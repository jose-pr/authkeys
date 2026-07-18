"""LDAP source: derive SSH keys from X.509 certificates stored in a directory.

Each matching entry's ``cert_attr`` values are parsed as DER certificates; the
public key is serialized to OpenSSH format. An optional ``cert_filter`` callable
``(username, cert) -> bool | str`` can drop a certificate or supply a comment.

Requires the optional ``ldap`` extra (``pip install authkeys[ldap]``:
``ldap3`` + ``cryptography``).
"""

from configparser import SectionProxy
from pathlib import Path
from typing import Callable, Iterable, Optional, Union

from .. import AuthkeysSource, utils

# (username, cert) -> False to drop, str for a comment, True/None for default
CertFilter = Callable[[str, "object"], "Union[bool, str]"]


def only_auth_keys(username: str, cert) -> bool:
    """Default filter: keep certs whose KeyUsage permits digital signature."""
    from cryptography import x509

    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return True
    return not usage or usage.value.digital_signature


class LdapAuthorizedKeys(AuthkeysSource):
    def __init__(self, conf: SectionProxy, globals) -> None:
        self.tls_cert = conf.get("tls_cert", "/etc/pki/tls/certs/server.crt")
        self.tls_key = conf.get("tls_key", "/etc/pki/tls/private/server.key")
        self.server = conf.get("server", None)
        self.basedn = conf.get("basedn", "")
        self.cert_attr = conf.get("cert_attr", "userCertificate")
        self.username_attr = conf.get("username_attr", "uid")
        cert_filter: "Optional[Union[str, CertFilter]]" = conf.get("cert_filter", None)
        if isinstance(cert_filter, str):
            cert_filter = utils.import_module_object(cert_filter)
        self.cert_filter = cert_filter

    def _search_filter(self, username: str) -> str:
        """Build the LDAP search filter with the username properly escaped.

        The username may be attacker-controlled (e.g. via ``authkeys serve``),
        so it must be escaped to prevent LDAP filter injection such as
        ``*)(uid=*`` matching unintended entries.
        """
        from ldap3.utils.conv import escape_filter_chars

        return f"({self.username_attr}={escape_filter_chars(username)})"

    def authorized_keys(self, username: str) -> Iterable[str]:
        import ldap3
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization.ssh import (
            serialize_ssh_public_key,
        )

        if (
            not self.server
            or not Path(self.tls_key).exists()
            or not Path(self.tls_cert).exists()
        ):
            raise RuntimeError("LDAP source is missing required configuration")

        tls = ldap3.Tls(self.tls_key, self.tls_cert)
        server = ldap3.Server(self.server, use_ssl=True, tls=tls)
        conn = ldap3.Connection(server=server, auto_bind=True)
        try:
            found = conn.search(
                self.basedn,
                self._search_filter(username),
                attributes=[self.cert_attr],
            )
            if not found or not conn.response:
                return
            for raw in conn.response[0]["raw_attributes"][self.cert_attr]:
                cert = x509.load_der_x509_certificate(raw)
                comment: "Union[bool, str, None]" = None
                if self.cert_filter:
                    comment = self.cert_filter(username, cert)
                    if comment is False:
                        continue
                if comment is None or isinstance(comment, bool):
                    comment = f"{username}({cert.subject.rfc4514_string()})"
                key = serialize_ssh_public_key(cert.public_key()).decode()
                yield f"{key} {comment}"
        finally:
            conn.unbind()
