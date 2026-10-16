"""Explicit self-signed node TLS bootstrap. Verify its fingerprint out of band."""
import hashlib
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def certificate(directory, hostname):
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / 'tls.crt', directory / 'tls.key'
    if cert.exists() != key.exists():
        raise ValueError('TLS bootstrap incomplete; restore both certificate and key or explicitly replace both')
    if not cert.exists():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            name = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            name = x509.DNSName(hostname.encode('idna').decode('ascii'))
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        value = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
                 .not_valid_after(now+timedelta(days=365)).add_extension(x509.SubjectAlternativeName([name]), critical=False)
                 .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(private, hashes.SHA256()))
        # Exclusive creation prevents accidental replacement of a previously pinned identity.
        for path, raw in ((key, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                          (cert, value.public_bytes(serialization.Encoding.PEM))):
            fd = os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw);handle.flush();os.fsync(handle.fileno())
    loaded = x509.load_pem_x509_certificate(cert.read_bytes())
    fingerprint = hashlib.sha256(loaded.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert,key,fingerprint
