"""LDAP source: derive SSH keys from X.509 certificates stored in a directory.

Each matching entry's ``cert_attr`` values are parsed as DER certificates; the
public key is serialized to OpenSSH format. A ``cert_filter`` callable
``(username, cert) -> bool | str`` drops a certificate or supplies a comment; it
defaults to :func:`only_auth_keys`, and ``cert_filter = none`` keeps every one.

Requires the optional ``ldap`` extra (``pip install authkeys[ldap]``:
``ldap3`` + ``cryptography``).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Union

from duho import logging

from .. import KeySource, utils
from ..config import typed
from ..exceptions import ConfigError, SourceError

LOGGER = logging.getLogger("authkeys.sources.ldap")

# (username, cert) -> False to drop, str for a comment, True/None for default
CertFilter = Callable[[str, "object"], "Union[bool, str]"]


# LDAP result codes that mean "searched, and this is the answer": success and
# noSuchObject (RFC 4511, Appendix A). Anything else is a failed search.
_SEARCH_ANSWERED = (0, 32)


def _validity(cert):
    # cryptography 42 added the timezone-aware properties.
    before = getattr(cert, "not_valid_before_utc", None)
    after = getattr(cert, "not_valid_after_utc", None)
    if before is None:
        before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def only_auth_keys(username: str, cert) -> bool:
    """Default filter: keep only certificates that are login credentials.

    A certificate is kept when it is within its validity period, is not
    self-signed, its KeyUsage (when present) permits digital signature, and its
    ExtendedKeyUsage (when present) includes clientAuth or anyExtendedKeyUsage.
    Directories also hold encryption, e-mail and recovery certificates in the
    same attribute; those must not become SSH keys.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    before, after = _validity(cert)
    if not before <= datetime.now(timezone.utc) <= after:
        return False
    if cert.issuer == cert.subject:
        return False
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.digital_signature:
        return False
    try:
        purposes = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        purposes = None
    if purposes is not None and not (
        ExtendedKeyUsageOID.CLIENT_AUTH in purposes
        or ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in purposes
    ):
        return False
    return True


class LDAPSource(KeySource):
    """Keys derived from X.509 certificates stored in an LDAP directory."""

    options = frozenset(
        {
            "server",
            "basedn",
            "cert_attr",
            "username_attr",
            "tls_cert",
            "tls_key",
            "tls_verify",
            "timeout",
            "cert_filter",
        }
    )

    def __init__(self, options: Mapping[str, Any], globals: dict) -> None:
        where = "ldap source"
        # tls_cert/tls_key are the *client* mutual-TLS credentials (not server
        # verification). Server verification is controlled by tls_verify below.
        self.tls_cert = typed(
            options, "tls_cert", str, "/etc/pki/tls/certs/server.crt", where
        )
        self.tls_key = typed(
            options, "tls_key", str, "/etc/pki/tls/private/server.key", where
        )
        # tls_verify: 'none' (insecure opt-out), 'system'/unset (verify against the
        # OS trust store), or a path (file -> CA bundle, dir -> CA directory).
        # Default is to VERIFY -- an unverified LDAPS channel decides who logs in.
        self.tls_verify = typed(options, "tls_verify", str, None, where)
        self.timeout = float(typed(options, "timeout", (int, float), 10.0, where))
        self.server = typed(options, "server", str, None, where)
        # ldap3 lets an ldap:// URL override use_ssl, which would send the search
        # (and so the answer that decides who logs in) in clear text.
        if self.server and self.server.strip().lower().startswith("ldap://"):
            raise ConfigError(
                "ldap source 'server' must be an ldaps:// URL or a host name, "
                "not ldap://"
            )
        self.basedn = typed(options, "basedn", str, "", where)
        self.cert_attr = typed(options, "cert_attr", str, "userCertificate", where)
        self.username_attr = typed(options, "username_attr", str, "uid", where)
        # Default only_auth_keys; "none" keeps every certificate in the attribute.
        cert_filter: "Optional[Union[str, CertFilter]]" = typed(
            options, "cert_filter", str, None, where
        )
        if cert_filter is None:
            cert_filter = only_auth_keys
        elif cert_filter.strip().lower() == "none":
            cert_filter = None
        else:
            cert_filter = utils.import_module_object(cert_filter)
        self.cert_filter = cert_filter

    def _tls_kwargs(self) -> dict:
        """Map ``tls_verify`` to ``ldap3.Tls`` verification kwargs.

        - ``none``            -> CERT_NONE (insecure; warns)
        - ``system`` / unset  -> CERT_REQUIRED, OS trust store (no CA file)
        - a file path         -> CERT_REQUIRED + ``ca_certs_file``
        - a directory path    -> CERT_REQUIRED + ``ca_certs_path``
        """
        import ssl

        value = (self.tls_verify or "system").strip()
        if value.lower() == "none":
            LOGGER.warning(
                "LDAP tls_verify=none: server certificate verification is "
                "DISABLED. The channel that authorizes SSH logins is unverified."
            )
            return {"validate": ssl.CERT_NONE}
        if value.lower() == "system":
            return {"validate": ssl.CERT_REQUIRED}
        path = Path(value)
        if path.is_dir():
            return {"validate": ssl.CERT_REQUIRED, "ca_certs_path": str(path)}
        return {"validate": ssl.CERT_REQUIRED, "ca_certs_file": str(path)}

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
            raise ConfigError(
                "the ldap source needs a server and existing tls_cert/tls_key files"
            )

        tls = ldap3.Tls(self.tls_key, self.tls_cert, **self._tls_kwargs())
        server = ldap3.Server(
            self.server, use_ssl=True, tls=tls, connect_timeout=self.timeout
        )
        # receive_timeout bounds the search so a black-holed server can't hang
        # the resolve path (and, in `serve`, other requests behind it).
        conn = ldap3.Connection(
            server=server, auto_bind=True, receive_timeout=self.timeout
        )
        try:
            conn.search(
                self.basedn,
                self._search_filter(username),
                attributes=[self.cert_attr],
            )
            # search() is False both for "no match" and for a refused search; only
            # the result code tells them apart, and a refusal must reach the
            # resolver's error path instead of being cached as "no keys".
            result = conn.result.get("result")
            if result not in _SEARCH_ANSWERED:
                raise SourceError(
                    f"LDAP search failed: {conn.result.get('description')} ({result})"
                )
            # Search references (referrals) sit in the same list as entries.
            entries = [
                r for r in (conn.response or []) if r.get("type") == "searchResEntry"
            ]
            if not entries:
                return
            if len(entries) > 1:
                raise SourceError(
                    f"LDAP search for {username!r} matched {len(entries)} entries"
                )
            for raw in entries[0]["raw_attributes"].get(self.cert_attr, []):
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
