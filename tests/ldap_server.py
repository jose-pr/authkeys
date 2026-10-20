"""A private OpenLDAP server for the LDAP tests (POSIX hosts with slapd installed).

``start(root)`` writes a CA, a server and a client certificate, a ``slapd.conf``
and a small directory under ``root``, then runs ``slapd`` on two free loopback
ports (``ldap://`` and ``ldaps://``). The directory, under ``dc=ak,dc=test``:

- ``uid=alice``: two certificates, a CA-issued client-auth one (kept by the
  default filter) and a self-signed one (dropped);
- ``uid=bob``: no certificate;
- two entries with ``cn=twin`` (an ambiguous match).

Anonymous reads are allowed; ``cn=admin,dc=ak,dc=test`` / ``ROOT_PASSWORD`` binds.
"""

import base64
import datetime
import ipaddress
import os
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

ROOT_DN = "cn=admin,dc=ak,dc=test"
ROOT_PASSWORD = "s3cret-admin"
BASE_DN = "dc=ak,dc=test"
SCHEMA_DIRS = ("/etc/openldap/schema", "/etc/ldap/schema")


@dataclass
class LDAPServer:
    ldap_url: str
    ldaps_url: str
    ca: str
    other_ca: str
    client_cert: str
    client_key: str
    pid: int
    root: Path

    def stop(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        for _ in range(50):
            try:
                os.kill(self.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)


def available() -> "str | None":
    """Why the server cannot run here, or None when it can."""
    if os.name != "posix":
        return "slapd tests run on POSIX only"
    if not (shutil.which("slapd") or Path("/usr/sbin/slapd").exists()):
        return "slapd not found"
    if not any(Path(d, "inetorgperson.schema").exists() for d in SCHEMA_DIRS):
        return "OpenLDAP schemas not found"
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return "cryptography is not installed"
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _pki(root: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def make(name, issuer=None, *, ca=False, san=None, eku=None):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        signer_key, signer_name = issuer or (key, subject)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(signer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    signer_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=not ca,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san), critical=False
            )
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return key, builder.sign(signer_key, hashes.SHA256())

    def write(stem, key, cert):
        (root / f"{stem}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        (root / f"{stem}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    ca_key, ca = make("AK Test CA", ca=True)
    write("ca", ca_key, ca)
    server = make(
        "localhost",
        (ca_key, ca.subject),
        san=[
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    write("server", *server)
    client = make(
        "key-client", (ca_key, ca.subject), eku=[ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    write("client", *client)
    write("other", *make("Other CA", ca=True))
    alice_good = make(
        "alice", (ca_key, ca.subject), eku=[ExtendedKeyUsageOID.CLIENT_AUTH]
    )[1]
    alice_self = make("alice-efs")[1]
    der = serialization.Encoding.DER
    return [alice_good.public_bytes(der), alice_self.public_bytes(der)]


def start(root: Path) -> LDAPServer:
    """Configure and start slapd under ``root``; raises RuntimeError if it fails."""
    root.mkdir(parents=True, exist_ok=True)
    alice_certs = _pki(root)
    schema = next(d for d in SCHEMA_DIRS if Path(d, "inetorgperson.schema").exists())
    (root / "db").mkdir(exist_ok=True)
    (root / "slapd.conf").write_text(f"""include {schema}/core.schema
include {schema}/cosine.schema
include {schema}/inetorgperson.schema
pidfile {root}/slapd.pid
argsfile {root}/slapd.args
TLSCACertificateFile {root}/ca.pem
TLSCertificateFile {root}/server.pem
TLSCertificateKeyFile {root}/server.key
TLSVerifyClient allow
database mdb
maxsize 10485760
suffix "{BASE_DN}"
rootdn "{ROOT_DN}"
rootpw {ROOT_PASSWORD}
directory {root}/db
""")
    certs = "".join(
        f"userCertificate;binary:: {base64.b64encode(c).decode()}\n"
        for c in alice_certs
    )
    (root / "data.ldif").write_text(f"""dn: {BASE_DN}
objectClass: dcObject
objectClass: organization
o: ak
dc: ak

dn: uid=alice,{BASE_DN}
objectClass: inetOrgPerson
uid: alice
cn: alice
sn: alice
{certs}
dn: uid=bob,{BASE_DN}
objectClass: inetOrgPerson
uid: bob
cn: bob
sn: bob

dn: uid=twin1,{BASE_DN}
objectClass: inetOrgPerson
uid: twin1
cn: twin
sn: twin

dn: uid=twin2,{BASE_DN}
objectClass: inetOrgPerson
uid: twin2
cn: twin
sn: twin
""")
    slapd = shutil.which("slapd") or "/usr/sbin/slapd"
    slapadd = shutil.which("slapadd") or "/usr/sbin/slapadd"
    subprocess.run(
        [slapadd, "-f", str(root / "slapd.conf"), "-l", str(root / "data.ldif")],
        check=True,
        capture_output=True,
    )
    ldap_port, ldaps_port = _free_port(), _free_port()
    ldap_url = f"ldap://127.0.0.1:{ldap_port}"
    ldaps_url = f"ldaps://127.0.0.1:{ldaps_port}"
    subprocess.run(
        [slapd, "-f", str(root / "slapd.conf"), "-h", f"{ldap_url}/ {ldaps_url}/"],
        check=True,
        capture_output=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ldaps_port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("slapd did not start listening")
    pid = int((root / "slapd.pid").read_text().strip())
    return LDAPServer(
        ldap_url=ldap_url,
        ldaps_url=ldaps_url,
        ca=str(root / "ca.pem"),
        other_ca=str(root / "other.pem"),
        client_cert=str(root / "client.pem"),
        client_key=str(root / "client.key"),
        pid=pid,
        root=root,
    )
