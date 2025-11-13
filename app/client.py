"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket, json, base64, os
import secrets
from helpers.cert_utils import load_pem, load_cert, verify_certificate

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
CERTS_DIR = "certs"

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR, "ca.cert.pem")))
    my_cert_pem = load_pem(os.path.join(CERTS_DIR, "client.cert.pem"))
    my_key_pem = load_pem(os.path.join(CERTS_DIR, "client.key.pem"))
    my_cert = load_cert(my_cert_pem)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))

    # Step 1: send hello with our cert and nonce
    nonce = secrets.token_bytes(16)
    hello = {
        "type": "hello",
        "cert": base64.b64encode(my_cert_pem).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }
    s.send(json.dumps(hello).encode())

    # Step 2: receive server hello_ack
    data = s.recv(4096).decode()
    msg = json.loads(data)
    if msg.get("type") != "hello_ack":
        print("[!] Invalid response")
        return

    server_cert_b64 = msg["cert"]
    server_nonce = base64.b64decode(msg["nonce"])
    server_cert = load_cert(base64.b64decode(server_cert_b64))

    if verify_certificate(server_cert, ca_cert):
        print("[+] Server cert verified OK")
        print(f"[+] Nonce received: {server_nonce.hex()}")
    else:
        print("[!] BAD SERVER CERT")

    s.close()

if __name__ == "__main__":
    main()
