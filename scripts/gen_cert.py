# scripts/gen_cert.py
"""
Generates an entity (server or client) certificate signed by our root CA.
Usage:
    python scripts/gen_cert.py server server.local
    python scripts/gen_cert.py client client.local
"""

import os, sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT_DIR = "certs"
os.makedirs(OUT_DIR, exist_ok=True)

if len(sys.argv) < 3:
    print("Usage: python scripts/gen_cert.py <entity_name> <common_name>")
    sys.exit(1)

entity = sys.argv[1]
common_name = sys.argv[2]

CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")

# Load CA key and cert
with open(CA_KEY_PATH, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
with open(CA_CERT_PATH, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Generate entity key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_path = os.path.join(OUT_DIR, f"{entity}.key.pem")
cert_path = os.path.join(OUT_DIR, f"{entity}.cert.pem")

with open(key_path, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Build CSR and sign with CA
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    )
    .sign(key, hashes.SHA256())
)

cert = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
    .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 year
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("✅ Certificate generated:")
print(f"  Key : {key_path}")
print(f"  Cert: {cert_path}")
