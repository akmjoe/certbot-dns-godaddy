"""
This module defines a certbot plugin to automate the process of completing a
``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and subsequently
removing, TXT records using the GoDaddy Domains API v3.
"""

import logging
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import requests
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_API_URL = 'https://api.godaddy.com/v3/domains'
DEFAULT_TTL = 600
MIN_TTL = 600  # GoDaddy rejects TTLs below 600 seconds
MAX_TTL = 86400


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for GoDaddy

    This Authenticator uses the GoDaddy API v3 to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using GoDaddy for DNS).')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self._client: Optional[_GoDaddyClient] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='GoDaddy credentials INI file.')
        add('ttl', type=int, default=DEFAULT_TTL,
            help=f'TTL of the TXT record ({MIN_TTL}-{MAX_TTL} seconds).')

    def more_info(self) -> str:
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using the GoDaddy API v3.')

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'GoDaddy credentials INI file',
            {'pat': 'Personal Access Token (PAT) for the GoDaddy API'},
        )

    def _perform(self, domain: str, validation_name: str,
                 validation: str) -> None:
        self._get_client().add_txt_record(domain, validation_name,
                                          validation, self._get_ttl())

    def _cleanup(self, domain: str, validation_name: str,
                 validation: str) -> None:
        self._get_client().del_txt_record(domain, validation_name, validation)

    def _get_ttl(self) -> int:
        ttl = int(self.conf('ttl') or DEFAULT_TTL)
        if not MIN_TTL <= ttl <= MAX_TTL:
            raise errors.PluginError(
                f'--{self.dest("ttl").replace("_", "-")} must be between '
                f'{MIN_TTL} and {MAX_TTL} seconds (got {ttl}).')
        return ttl

    def _get_client(self) -> '_GoDaddyClient':
        if self._client is None:
            if not self.credentials:  # pragma: no cover
                raise errors.Error('Plugin has not been prepared.')
            api_url = self.credentials.conf('api_url') or DEFAULT_API_URL
            self._client = _GoDaddyClient(self.credentials.conf('pat'),
                                          api_url)
        return self._client


class _GoDaddyClient:
    """Minimal client for the GoDaddy Domains API v3 DNS record endpoints."""

    def __init__(self, token: str, api_url: str = DEFAULT_API_URL) -> None:
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'User-Agent': 'certbot-dns-godaddy',
        })
        self._zones: Dict[str, str] = {}

    def add_txt_record(self, domain: str, record_name: str,
                       record_content: str, record_ttl: int) -> None:
        zone = self._find_zone(domain)
        name = _relative_name(record_name, zone)
        logger.debug('Creating TXT record %s in zone %s', name, zone)
        response = self._request(
            'POST', f'/zones/{quote(zone)}/dns-records',
            json={'type': 'TXT', 'name': name, 'data': record_content,
                  'ttl': record_ttl})
        if response.status_code not in (200, 201):
            raise errors.PluginError(
                f'Error adding TXT record {record_name}: '
                f'{_describe_error(response)}')
        logger.debug('Successfully added TXT record %s', record_name)

    def del_txt_record(self, domain: str, record_name: str,
                       record_content: str) -> None:
        try:
            zone = self._find_zone(domain)
            name = _relative_name(record_name, zone)
            records = self._list_txt_records(zone, name)
        except errors.PluginError as e:
            logger.warning('Unable to look up TXT record %s for cleanup: %s',
                           record_name, e)
            return

        matches = [r for r in records
                   if _unquote_txt(r.get('data', '')) == record_content]
        if not matches:
            logger.warning('No TXT record %s with the expected value found; '
                           'nothing to clean up.', record_name)
        for record in matches:
            record_id = record.get('recordId')
            if not record_id:
                continue
            response = self._request(
                'DELETE',
                f'/zones/{quote(zone)}/dns-records/{quote(record_id, safe="")}')
            if response.status_code in (200, 204, 404):
                logger.debug('Deleted TXT record %s (%s)', record_name,
                             record_id)
            else:
                logger.warning('Error deleting TXT record %s: %s',
                               record_name, _describe_error(response))

    def _find_zone(self, domain: str) -> str:
        """Find the GoDaddy zone that hosts ``domain``."""
        if domain in self._zones:
            return self._zones[domain]

        last_error = ''
        for guess in dns_common.base_domain_name_guesses(_to_ascii(domain)):
            response = self._request(
                'GET', f'/zones/{quote(guess)}/dns-records',
                params={'type': 'SOA', 'pageSize': 1})
            if response.status_code == 200:
                logger.debug('Found zone %s for domain %s', guess, domain)
                self._zones[domain] = guess
                return guess
            if response.status_code == 401:
                raise errors.PluginError(
                    'GoDaddy rejected the Personal Access Token: '
                    f'{_describe_error(response)}')
            if response.status_code in (400, 403, 404, 422):
                # Not a zone in this account; try the next candidate.
                last_error = f'{guess}: {_describe_error(response)}'
                continue
            raise errors.PluginError(
                f'Error looking up zone {guess}: '
                f'{_describe_error(response)}')

        raise errors.PluginError(
            f'Unable to find a GoDaddy DNS zone for {domain}. Make sure the '
            'domain is managed by GoDaddy DNS and the token can access it. '
            f'(Last response: {last_error})')

    def _list_txt_records(self, zone: str, name: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        page = 1
        while True:
            response = self._request(
                'GET', f'/zones/{quote(zone)}/dns-records',
                params={'type': 'TXT', 'name': name, 'page': page,
                        'pageSize': 100})
            if response.status_code != 200:
                raise errors.PluginError(
                    f'Error listing TXT records for {name}.{zone}: '
                    f'{_describe_error(response)}')
            body = response.json()
            records.extend(body.get('items') or [])
            has_next = any(link.get('rel') == 'next'
                           for link in body.get('links') or [])
            if not has_next:
                return records
            page += 1

    def _request(self, method: str, path: str, **kwargs: Any
                 ) -> requests.Response:
        url = self.api_url + path
        try:
            return self.session.request(method, url, timeout=30, **kwargs)
        except requests.RequestException as e:
            raise errors.PluginError(
                f'Error communicating with the GoDaddy API: {e}') from e


def _to_ascii(name: str) -> str:
    """Lower-case ``name`` and convert it to punycode (A-label) form."""
    name = name.lower().rstrip('.').replace('*.', '')
    try:
        return name.encode('idna').decode('ascii')
    except UnicodeError:
        return name


def _relative_name(record_name: str, zone: str) -> str:
    """Convert a fully-qualified record name to one relative to ``zone``."""
    record_name = _to_ascii(record_name)
    if record_name == zone:
        return '@'
    suffix = '.' + zone
    if record_name.endswith(suffix):
        return record_name[:-len(suffix)]
    raise errors.PluginError(
        f'Record {record_name} is not inside zone {zone}.')


def _unquote_txt(data: str) -> str:
    if len(data) >= 2 and data[0] == data[-1] == '"':
        return data[1:-1]
    return data


def _describe_error(response: requests.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f'HTTP {response.status_code}: {response.text[:200]}'
    if isinstance(body, dict):
        message = body.get('message') or body.get('name') or body
        details = body.get('details')
        if details:
            return f'HTTP {response.status_code}: {message} ({details})'
        return f'HTTP {response.status_code}: {message}'
    return f'HTTP {response.status_code}: {body}'
