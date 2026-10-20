"""The two LDAP clients behind the ldap source: python-ldap and ldap3.

Each one answers ``certificates(search_filter) -> list[bytes]`` (DER values of
the certificate attribute of the one matching entry) and raises
:class:`~authkeys.exceptions.SourceError` when the server refuses the bind or the
search, or when more than one entry matches.
"""

import math
import os
import ssl
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from duho import logging

from ..exceptions import ConfigError, SourceError

LOGGER = logging.getLogger("authkeys.sources.ldap")

# Result codes that answer a search: success and noSuchObject (RFC 4511, Appendix A).
SEARCH_ANSWERED = (0, 32)

# Below this SASL security strength a Kerberos session is neither signed nor sealed.
MIN_SSF = 56


@dataclass
class LDAPSettings:
    url: str  # ldaps://host[:port] or ldap://host[:port]
    starttls: bool
    basedn: str
    attribute: str
    auth: str  # gssapi | simple | external | anonymous
    keytab: Optional[str]
    principal: Optional[str]
    bind_dn: Optional[str]
    password_env: Optional[str]
    tls_verify: Optional[str]  # None/"system", "none", a file or a directory
    tls_cert: Optional[str]
    tls_key: Optional[str]
    timeout: float
    ssl_context: "Optional[ssl.SSLContext]" = None

    @property
    def tls(self) -> bool:
        return self.url.lower().startswith("ldaps://") or self.starttls

    def password(self) -> str:
        value = os.environ.get(self.password_env or "", "")
        if not value:
            raise SourceError(
                f"LDAP simple bind: the variable {self.password_env!r} is unset or empty"
            )
        return value


def _values(attributes: Dict[str, Any], name: str) -> List[bytes]:
    # A server may name the attribute with an option ("userCertificate;binary"),
    # in any case; ldap3 may also return the plain name, empty.
    wanted = name.split(";", 1)[0].lower()
    found: List[bytes] = []
    for key, values in attributes.items():
        if key.split(";", 1)[0].lower() == wanted:
            found.extend(v for v in values if isinstance(v, (bytes, bytearray)))
    return found


def _one_entry(entries: List[Dict[str, Any]], what: str) -> Optional[Dict[str, Any]]:
    if not entries:
        return None
    if len(entries) > 1:
        raise SourceError(f"LDAP search for {what} matched {len(entries)} entries")
    return entries[0]


def use_machine_keytab(keytab: Optional[str]) -> None:
    """Point MIT Kerberos at ``keytab`` for initiator credentials.

    Only when ``KRB5_CLIENT_KTNAME`` is unset and the file is readable: a process
    that cannot read the host keytab gets its credentials from gssproxy or the
    default cache instead.
    """
    if keytab and "KRB5_CLIENT_KTNAME" not in os.environ and os.access(keytab, os.R_OK):
        os.environ["KRB5_CLIENT_KTNAME"] = keytab


def tls_context(settings: LDAPSettings) -> ssl.SSLContext:
    """The client TLS context for ``settings``: the caller's, else one built with
    sslcontext from ``tls_verify``, ``tls_cert`` and ``tls_key``."""
    if settings.ssl_context is not None:
        return settings.ssl_context
    import sslcontext

    options: Dict[str, Any] = {}
    verify = (settings.tls_verify or "system").strip()
    if verify.lower() == "none":
        LOGGER.warning(
            "LDAP tls_verify=none: server certificate verification is DISABLED. "
            "The channel that authorizes SSH logins is unverified."
        )
        options["verify"] = False
    elif verify.lower() != "system":
        options["capath" if os.path.isdir(verify) else "cafile"] = verify
    if settings.tls_cert:
        options["certificate"] = settings.tls_cert
        options["key"] = settings.tls_key
    return sslcontext.create_context(**options)


class LDAP3Client:
    """The ldap3 (2.10.2rc4 or later) client."""

    name = "ldap3"

    def __init__(self, settings: LDAPSettings) -> None:
        import ldap3

        if not hasattr(ldap3, "ENCRYPT"):
            raise ConfigError(
                "the ldap source needs ldap3 2.10.2rc4 or later (session security)"
            )
        if settings.auth == "gssapi":
            try:
                if os.name == "nt":
                    import winkerberos  # noqa: F401
                else:
                    import gssapi  # noqa: F401
            except ImportError:
                raise ConfigError(
                    "Kerberos with the ldap3 client needs gssapi (POSIX) or winkerberos "
                    "(Windows): pip install authkeys[kerberos]"
                ) from None
        if settings.principal and os.name != "posix":
            raise ConfigError(
                "ldap source: 'principal' needs POSIX Kerberos; on Windows the "
                "process's own credentials are used"
            )
        self.settings = settings

    def certificates(self, search_filter: str) -> List[bytes]:
        import ldap3

        s = self.settings
        tls = _ContextTls(tls_context(s)) if s.tls else None
        # ldap3 packs its timeouts as whole seconds.
        seconds = max(1, math.ceil(s.timeout))
        server = ldap3.Server(
            s.url,
            use_ssl=s.url.lower().startswith("ldaps://"),
            tls=tls,
            connect_timeout=seconds,
            # No schema read: on open() it would run before the bind, outside the
            # Kerberos security layer the server requires.
            get_info=ldap3.NONE,
        )
        options: Dict[str, Any] = {}
        if s.auth == "gssapi":
            options.update(authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)
            if not s.tls:
                options["session_security"] = ldap3.ENCRYPT
            if s.principal:
                options["user"] = s.principal
                if s.keytab:
                    options["cred_store"] = {"client_keytab": s.keytab}
        elif s.auth == "simple":
            options.update(
                authentication=ldap3.SIMPLE, user=s.bind_dn, password=s.password()
            )
        elif s.auth == "external":
            # An empty authorization id: the server derives it from the certificate.
            options.update(
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.EXTERNAL,
                sasl_credentials="",
            )
        # Referrals are not followed: following one rebuilds a plain Tls from file
        # paths, losing the context, and an answer comes from this server only.
        conn = ldap3.Connection(
            server, auto_referrals=False, receive_timeout=seconds, **options
        )
        try:
            conn.open()
            if s.starttls and not conn.start_tls():
                raise SourceError(
                    f"LDAP StartTLS failed: {conn.result.get('description')}"
                )
            if not conn.bind():
                raise SourceError(f"LDAP bind failed: {conn.result.get('description')}")
            conn.search(s.basedn, search_filter, attributes=[s.attribute])
            result = conn.result.get("result")
            if result not in SEARCH_ANSWERED:
                raise SourceError(
                    f"LDAP search failed: {conn.result.get('description')} ({result})"
                )
            entries = [
                r for r in (conn.response or []) if r.get("type") == "searchResEntry"
            ]
            entry = _one_entry(entries, search_filter)
            return _values(entry["raw_attributes"], s.attribute) if entry else []
        finally:
            try:
                conn.unbind()
            except Exception:
                pass


def _context_tls_class():
    import ldap3

    class ContextTls(ldap3.Tls):
        """ldap3's ``Tls`` that wraps the socket with a given ``SSLContext``.

        ldap3's own ``Tls`` builds a context from file paths and turns host-name
        checking off; this one uses the context as given, host-name check included.
        """

        def __init__(self, context: ssl.SSLContext) -> None:
            super().__init__(validate=context.verify_mode)
            self.context = context

        def wrap_socket(self, connection, do_handshake=False):
            sock = self.context.wrap_socket(
                connection.socket,
                server_side=False,
                do_handshake_on_connect=do_handshake,
                server_hostname=connection.server.host,
            )
            # Read for channel binding (tls-server-end-point) by ldap3's SASL code.
            self.peer_certificate = sock.getpeercert(binary_form=True)
            connection.socket = sock

    return ContextTls


def _ContextTls(context: ssl.SSLContext):
    return _context_tls_class()(context)


class PythonLDAPClient:
    """The python-ldap (libldap, Cyrus SASL) client."""

    name = "python-ldap"

    def __init__(self, settings: LDAPSettings) -> None:
        import ldap  # noqa: F401

        if settings.ssl_context is not None:
            raise ConfigError(
                "python-ldap does its TLS in libldap and cannot take an SSLContext; "
                'use client = "ldap3"'
            )
        if settings.principal:
            raise ConfigError(
                "ldap source: 'principal' needs client = \"ldap3\"; python-ldap uses "
                "the keytab's first principal"
            )
        self.settings = settings

    def _tls_options(self, conn) -> None:
        import ldap

        s = self.settings
        verify = (s.tls_verify or "system").strip()
        if verify.lower() == "none":
            LOGGER.warning(
                "LDAP tls_verify=none: server certificate verification is DISABLED. "
                "The channel that authorizes SSH logins is unverified."
            )
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        else:
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            if verify.lower() != "system":
                option = (
                    ldap.OPT_X_TLS_CACERTDIR
                    if os.path.isdir(verify)
                    else ldap.OPT_X_TLS_CACERTFILE
                )
                conn.set_option(option, verify)
        if s.tls_cert:
            conn.set_option(ldap.OPT_X_TLS_CERTFILE, s.tls_cert)
            conn.set_option(ldap.OPT_X_TLS_KEYFILE, s.tls_key or s.tls_cert)
        # Settings above apply to a new TLS context only.
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

    def certificates(self, search_filter: str) -> List[bytes]:
        import ldap
        import ldap.sasl

        s = self.settings
        conn = ldap.initialize(s.url)
        try:
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, s.timeout)
            conn.set_option(ldap.OPT_TIMEOUT, s.timeout)
            if s.tls:
                self._tls_options(conn)
            if s.starttls:
                conn.start_tls_s()
            if s.auth == "gssapi":
                if not s.tls:
                    conn.set_option(ldap.OPT_X_SASL_SSF_MIN, MIN_SSF)
                conn.sasl_interactive_bind_s("", ldap.sasl.gssapi())
            elif s.auth == "simple":
                conn.simple_bind_s(s.bind_dn, s.password())
            elif s.auth == "external":
                conn.sasl_interactive_bind_s("", ldap.sasl.external())
            res = conn.search_ext_s(
                s.basedn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                [s.attribute],
                timeout=s.timeout,
            )
        except ldap.NO_SUCH_OBJECT:
            return []
        except ldap.LDAPError as e:
            info = e.args[0] if e.args and isinstance(e.args[0], dict) else {}
            raise SourceError(
                f"LDAP {type(e).__name__}: {info.get('desc', '')} {info.get('info', '')}".strip()
            ) from None
        finally:
            try:
                conn.unbind_s()
            except Exception:
                pass
        # Search references come back with no DN.
        entries = [{"dn": dn, "attributes": attrs} for dn, attrs in res if dn]
        entry = _one_entry(entries, search_filter)
        return _values(entry["attributes"], s.attribute) if entry else []


def make_client(settings: LDAPSettings, choice: str):
    """The client ``choice`` names: ``python-ldap``, ``ldap3`` or ``auto`` (python-ldap
    when it imports and no ``ssl_context`` or ``principal`` asks for ldap3)."""
    if choice not in ("auto", "python-ldap", "ldap3"):
        raise ConfigError(
            f"ldap source: client must be auto, python-ldap or ldap3, not {choice!r}"
        )
    if choice == "python-ldap":
        return PythonLDAPClient(settings)
    if choice == "ldap3":
        return LDAP3Client(settings)
    wants_ldap3 = settings.ssl_context is not None or bool(settings.principal)
    if not wants_ldap3:
        try:
            return PythonLDAPClient(settings)
        except ImportError:
            pass
    try:
        return LDAP3Client(settings)
    except ImportError:
        raise ConfigError(
            "the ldap source needs python-ldap or ldap3: pip install authkeys[ldap]"
        ) from None
