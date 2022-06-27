from typing import Any, Callable, Optional
import json
import logging
import random
import requests
import string

from certbot.configuration import NamespaceConfig
from certbot.errors import PluginError
from certbot.plugins.dns_common import DNSAuthenticator, CredentialsConfiguration

logger = logging.getLogger(__name__)


class _HostpointClient(object):
    LOGIN_URL = "https://admin.hostpoint.ch/customer/Auth/Login"

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.client = _HostpointHttpClient()

    def add_txt_record(self, domain: str, record_name: str, record_content: str, record_ttl: int) -> None:
        logger.debug("Adding TXT record to domain {}, {}={}, TTL={}".format(
            domain, record_name, record_content, record_ttl))
        self._login()
        tx = _DnsTransaction(self.client, domain)
        tx.begin()
        existing_record_idx = tx.find_txt_record_index(
            record_name, record_content)
        if existing_record_idx is not None:
            tx.update_txt_record(existing_record_idx,
                                 record_content, record_ttl)
        else:
            tx.add_txt_record(record_name, record_content, record_ttl)
        tx.commit()

    def delete_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        self._login()
        tx = _DnsTransaction(self.client, domain)
        tx.begin()
        existing_record_idx = tx.find_txt_record_index(
            record_name, record_content)
        if existing_record_idx is not None:
            tx.delete_txt_record(existing_record_idx)
            tx.commit()
        else:
            logger.debug(
                "No TXT record for %s with value %s was found, not deleting", record_name, record_content)

    def _login(self) -> None:
        if self.client.session:
            return

        logger.debug("Populating initial cookies")
        self.client.session = requests.Session()
        resp = self.client.session.get(_HostpointClient.LOGIN_URL)
        if resp.status_code != 200:
            raise PluginError(
                "Failed to populate initial cookies: login page returned HTTP error {}".format(resp.status_code))

        logger.debug("Logging in")
        self.client.csrf_post(_HostpointClient.LOGIN_URL, data={
            'username': self.username,
            'password': self.password,
            'locale': 'en_US',
            'cloud_office_host': '',
            'csrf_token': self.client.get_csrf_token(),
            '_action_login': '',
            'g_main_locale': 'en_US',
        })


class _HostpointHttpClient(object):
    CSRF_TOKEN_COOKIE = "csrf_token-customer"
    CSRF_TOKEN_HEADER = "x-csrf-token"

    def __init__(self) -> None:
        self.session: Optional[requests.Session] = None

    def csrf_post(self, *args: Any, **kwargs: Any) -> requests.Response:
        if not self.session:
            raise PluginError("Session was not set when performing CSRF POST")
        self.session.headers.update(
            {_HostpointHttpClient.CSRF_TOKEN_HEADER: self.get_csrf_token()})
        resp = self.session.post(*args, **kwargs)
        if resp.status_code != 200:
            raise PluginError(
                "Failed to make API call: returned HTTP error {}".format(resp.status_code))
        return resp

    def get_csrf_token(self) -> str:
        if not self.session:
            raise PluginError("Session was not set when getting CSRF token")
        csrf_token = self.session.cookies.get(  # type: ignore[no-untyped-call]
            _HostpointHttpClient.CSRF_TOKEN_COOKIE)
        if not isinstance(csrf_token, str):
            raise PluginError("CSRF token was not set")
        return csrf_token


class _DnsTransaction:
    EDIT_URL_TEMPLATE = "https://admin.hostpoint.ch/customer/Domains/Dns/Edit?name={}"

    def __init__(self, client: _HostpointHttpClient, domain: str) -> None:
        self.client = client
        self.domain = domain
        self.edit_url = _DnsTransaction.EDIT_URL_TEMPLATE.format(domain)
        self.records: list[dict[str, Any]] = []
        self.version: int = 0
        self.deleted_records: list[dict[str, Any]] = []

    def begin(self) -> None:
        logger.debug("Populating initial data")
        resp = self.client.csrf_post(self.edit_url, data={
            '_action_get_records': '1',
        })
        logger.debug(resp.text)
        try:
            j: dict[str, Any] = resp.json()
            self.records = j['records']
            self.version = j['snapshot']['version']
            logger.debug("%d records, version %d",
                         len(self.records), self.version)
        except (json.JSONDecodeError, KeyError) as e:
            raise PluginError(
                "Malformed DNS record populate response: {}".format(str(e)))

    def find_txt_record_index(self, record_name: str, record_content: str) -> Optional[int]:
        for i, record in enumerate(self.records):
            if record["type"] == "TXT" and record["full_name"] == record_name and record["content"] == f"\"{record_content}\"":
                return i
        return None

    def add_txt_record(self, record_name: str, record_content: str, record_ttl: int) -> None:
        subpart = record_name.removesuffix('.' + self.domain)
        id = ''.join(random.choice(string.ascii_lowercase) for _ in range(9))
        self.records.append({
            "ipv6address_public": None,
            "hostname": None,
            "weight": None,
            "ca": None,
            "ipaddress_public": None,
            "_is_hosting_relevant": False,
            "tag": None,
            "full_name": record_name,
            "ttl": record_ttl,
            "destination": None,
            "port": None,
            "content": record_content,
            "_is_editable": True,
            "subpart": subpart,
            "_is_deletable": True,
            "id": id,
            "priority": None,
            "_is_modifiable": True,
            "content_tokens": {
                "text": record_content,
                "type": "TXT",
                "manual_ttl": "",
                "subpart": subpart,
                "ttl": record_ttl
            },
            "ip_address_flag": None,
            "cpu_type": None,
            "content_wrapped": "False",
            "_is_hidden_from_customer": False,
            "flag": None,
            "prio": None,
            "ip_address": None,
            "target": None,
            "manual_type": None,
            "name": None,
            "type": "TXT",
            "manual_ttl": "",
            "content_strip_prio": record_content,
            "os": None,
            "_added": True
        })

    def update_txt_record(self, idx: int, record_content: str, record_ttl: int) -> None:
        self.records[idx].update({
            "content": record_content,
            "content_strip_prio": record_content,
            "ttl": str(record_ttl),
            "_changed": True
        })
        self.records[idx]["content_tokens"].update({
            "text": record_content,
            "ttl": str(record_ttl),
        })

    def delete_txt_record(self, idx: int) -> None:
        self.deleted_records.append(self.records[idx])
        del self.records[idx]

    def commit(self) -> None:
        logger.debug("Committing data")
        resp = self.client.csrf_post(self.edit_url, data={
            "records": json.dumps(self.records),
            "deletedRecords": json.dumps(self.deleted_records),
            "options": json.dumps({
                "changes_name": "certbot automated DNS change",
                "changes_name_hidden": "certbot automated DNS change",
                "exec_type": "exec_type_now",
                "execute_date": "",
            }),
            "contactOptions": "{}",
            "version": str(self.version),
            "_action_save_records": "1",
        })
        try:
            j = resp.json()
            if 'success' not in j or j['success'] != True:
                err = j['error'] if 'error' in j else "unknown API error"
                raise PluginError("Failed to commit data: {}".format(err))
        except json.JSONDecodeError as e:
            raise PluginError(
                "Malformed DNS record commit response: {}".format(e.msg))


class Authenticator(DNSAuthenticator):
    CONF_USERNAME = "username"
    CONF_PASSWORD = "password"
    CONF_DOMAIN = "domain"

    description = "Obtain certificates using a DNS TXT record (if you are using Hostpoint for DNS)."
    ttl = 300

    def __init__(self, config: NamespaceConfig, name: str) -> None:
        super().__init__(config, name)
        self.credentials: Optional[CredentialsConfiguration] = None
        self.hostpoint_client: Optional[_HostpointClient] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:  # type: ignore[override]
        super(DNSAuthenticator, cls).add_parser_arguments(add)
        add("credentials", help="Hostpoint credentials INI file.")

    def more_info(self) -> str:
        return "This plugin configure a DNS TXT record to respond to a dns-01 challenge using the Hostpoint API"

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials("credentials", "Hostpoint credentials INI file", {
            Authenticator.CONF_USERNAME: "Username for the Hostpoint account.",
            Authenticator.CONF_PASSWORD: "Password for the Hostpoint account.",
            Authenticator.CONF_DOMAIN: "Domain to use on the Hostpoint account.",
        })

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_hostpoint_client().add_txt_record(
            domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_hostpoint_client().delete_txt_record(
            domain, validation_name, validation)

    def _get_hostpoint_client(self) -> _HostpointClient:
        if not self.hostpoint_client:
            assert(self.credentials)
            self.hostpoint_client = _HostpointClient(self.credentials.conf(
                Authenticator.CONF_USERNAME), self.credentials.conf(Authenticator.CONF_PASSWORD))
        return self.hostpoint_client
