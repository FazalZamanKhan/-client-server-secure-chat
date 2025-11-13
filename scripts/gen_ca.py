# scripts/gen_ca.py
"""
Generates a root Certificate Authority (CA) key and self-signed certificate.
Stores them in certs/ca.key.pem and certs/ca.cert.pem.
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT_DIR = "certs"
os.makedirs(OUT_DIR, exist_ok=True)

CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")

# 1️⃣ Generate 2048-bit RSA private key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2️⃣ Build the CA certificate subject/issuer (self-signed)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
    x509.NameAttribute(NameOID.COMMON_NAME, "MyLocalRootCA"),
])

# 3️⃣ Create and sign the certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

# 4️⃣ Write files
with open(CA_KEY_PATH, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open(CA_CERT_PATH, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("✅ Root CA generated:")
print(f"  Key : {CA_KEY_PATH}")
print(f"  Cert: {CA_CERT_PATH}")
