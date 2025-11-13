# tools/verify_receipt.py
# Usage:
#   python tools/verify_receipt.py transcripts/server_transcript.log receipt.json certs/server.cert.pem
import sys, base64
from hashlib import sha256
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

if len(sys.argv) < 4:
    print("Usage: python tools/verify_receipt.py <transcript.log> <receipt.json> <signer_cert.pem>")
    sys.exit(1)

import json
tn, rn, certp = sys.argv[1], sys.argv[2], sys.argv[3]

with open(tn, "rb") as f:
    lines = f.read()
calc = sha256(lines).hexdigest()

with open(rn, "r") as f:
    receipt = json.load(f)
print("Transcript computed sha256:", calc)
print("Receipt contains sha256:      ", receipt.get("transcript_sha256"))

if calc != receipt.get("transcript_sha256"):
    print("[!] Transcript hash mismatch! Transcript was modified.")
else:
    print("[+] Transcript hash matches.")

sig_b64 = receipt.get("sig")
sig = base64.b64decode(sig_b64)

with open(certp, "rb") as f:
    cert_p = f.read()

pub = x509.load_pem_x509_certificate(cert_p).public_key()
try:
    pub.verify(sig, calc.encode(), asym_padding.PKCS1v15(), hashes.SHA256())
    print("[+] Receipt signature verified.")
except Exception as e:
    print("[!] Receipt signature verification FAILED:", e)
