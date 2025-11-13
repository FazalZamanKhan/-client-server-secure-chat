# helpers/cert_utils.py
"""
Certificate load/verify helpers.
"""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_pem(path: str):
    with open(path, "rb") as f:
        return f.read()

def load_cert(cert_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_bytes)

def verify_certificate(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Returns True if:
      - issuer == CA subject
      - valid date range
      - signature verifies with CA public key
    """
    try:
        if cert.issuer != ca_cert.subject:
            return False
        now = datetime.datetime.utcnow()
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            return False
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print("[!] Cert verify failed:", e)
        return False
