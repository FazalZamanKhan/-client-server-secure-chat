import os
import time
import base64
from hashlib import sha256
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---- PKCS7 pad/unpad and AES-CBC encrypt/decrypt ----
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padder = sym_padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
    unpadder = sym_padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_encrypt_cbc(key: bytes, plaintext: bytes) -> (bytes, bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return iv, ct

def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)

# ---- DH parameter + key helpers (classical DH) ----
def generate_dh_parameters(key_size: int = 2048):
    """
    Returns (p:int, g:int, parameter_obj)
    parameter_obj is cryptography DHParameters instance required to create private keys.
    """
    params = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
    pn = params.parameter_numbers()
    return pn.p, pn.g, params

def generate_dh_private_key_from_params(params):
    return params.generate_private_key()

def dh_public_int_from_private(priv_key):
    return priv_key.public_key().public_numbers().y

def load_peer_public_key_from_int(y_int: int, p_int: int, g_int: int):
    params = dh.DHParameterNumbers(p_int, g_int).parameters(backend=default_backend())
    pub_numbers = dh.DHPublicNumbers(y_int, params.parameter_numbers())
    return pub_numbers.public_key(backend=default_backend())

def compute_dh_shared_secret_bytes(priv_key, peer_pub_key):
    """
    Returns raw shared secret bytes (as returned by .exchange()).
    We'll hash this blob and take first 16 bytes for AES-128 key.
    """
    return priv_key.exchange(peer_pub_key)

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    h = sha256(shared_bytes).digest()
    return h[:16]

# ---- simple base64 helpers used for JSON transport ----
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

# ---- RSA sign / verify helpers (kept for later phases) ----
def rsa_sign(private_key_pem: bytes, data: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    return priv.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())

def rsa_verify(public_key_pem: bytes, signature: bytes, data: bytes) -> bool:
    pub = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    pub.verify(signature, data, asym_padding.PKCS1v15(), hashes.SHA256())
    return True

# ---- DH parameter object from p and g (for client) ----
def dh_parameter_obj_from_p_g(p_int: int, g_int: int):
    return dh.DHParameterNumbers(p_int, g_int).parameters(backend=default_backend())




    # ---- Fingerprint & transcript helpers ----
from hashlib import sha256

def cert_fingerprint(cert_pem: bytes) -> str:
    cert_bytes = b"".join(line for line in cert_pem.splitlines() if not line.startswith(b"-----"))
    return sha256(cert_bytes).hexdigest()[:16]  # short fingerprint

def current_unix_ms() -> int:
    import time
    return int(time.time() * 1000)
