"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket, json, base64, os
import secrets
from helpers.cert_utils import load_pem, load_cert, verify_certificate

HOST = "0.0.0.0"
PORT = 9000
CERTS_DIR = "certs"

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR, "ca.cert.pem")))
    my_cert_pem = load_pem(os.path.join(CERTS_DIR, "server.cert.pem"))
    my_key_pem = load_pem(os.path.join(CERTS_DIR, "server.key.pem"))
    my_cert = load_cert(my_cert_pem)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[+] Server listening on {HOST}:{PORT}")

    conn, addr = srv.accept()
    print(f"[+] Connection from {addr}")

    # Step 1: receive client's hello
    data = conn.recv(4096).decode()
    msg = json.loads(data)
    if msg.get("type") != "hello":
        conn.close()
        return

    client_cert_b64 = msg["cert"]
    client_nonce = base64.b64decode(msg["nonce"])

    client_cert = load_cert(base64.b64decode(client_cert_b64))
    if verify_certificate(client_cert, ca_cert):
        print("[+] Client cert verified OK")
    else:
        print("[!] BAD CLIENT CERT, closing")
        conn.close()
        return

    # Step 2: send our hello back
    server_nonce = secrets.token_bytes(16)
    reply = {
        "type": "hello_ack",
        "cert": base64.b64encode(my_cert_pem).decode(),
        "nonce": base64.b64encode(server_nonce).decode(),
    }
    conn.send(json.dumps(reply).encode())

    print(f"[+] Handshake done with {client_cert.subject.rfc4514_string()}")
    conn.close()

if __name__ == "__main__":
    main()
