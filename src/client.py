import socket
import json
import os
import base64
import getpass
from helpers.cert_utils import load_pem, load_cert, verify_certificate
from helpers import crypto
from dotenv import load_dotenv

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9000"))
CERTS_DIR = os.getenv("CERTS_DIR", "certs")

def send_json(conn, obj):
    conn.sendall(json.dumps(obj).encode() + b"\n")

def recv_json(rfile):
    line = rfile.readline()
    if not line:
        return None
    return json.loads(line.decode())

def prompt_register():
    print("=== Register ===")
    email = input("email: ").strip()
    username = input("username: ").strip()
    pwd = getpass.getpass("password: ").encode()
    return {"type":"register","email":email,"username":username,"pwd": base64.b64encode(pwd).decode()}

def prompt_login():
    print("=== Login ===")
    email = input("email: ").strip()
    pwd = getpass.getpass("password: ").encode()
    return {"type":"login","email":email,"pwd": base64.b64encode(pwd).decode()}

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR, "ca.cert.pem")))
    my_cert_pem = load_pem(os.path.join(CERTS_DIR, "client.cert.pem"))
    my_cert = load_cert(my_cert_pem)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    rfile = s.makefile("rb")

    # 1) send hello
    nonce = os.urandom(16)
    send_json(s, {"type":"hello", "cert": base64.b64encode(my_cert_pem).decode(), "nonce": base64.b64encode(nonce).decode()})

    # 2) receive hello_ack
    msg = recv_json(rfile)
    if not msg or msg.get("type") != "hello_ack":
        print("bad handshake")
        s.close()
        return
    server_cert = load_cert(base64.b64decode(msg["cert"]))
    if not verify_certificate(server_cert, ca_cert):
        print("server cert not valid")
        s.close()
        return
    print("[+] Server cert verified OK")

    # 3) receive dh_params from server
    msg = recv_json(rfile)
    if not msg or msg.get("type") != "dh_params":
        print("missing dh params")
        s.close()
        return
    p_int = int(msg["p"], 16)
    g_int = int(msg["g"], 16)
    server_pub_y = int(msg["server_pub"], 16)

    # create client private key from params and send client_pub
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    params_obj = dh.DHParameterNumbers(p_int, g_int).parameters(backend=default_backend())
    client_priv = params_obj.generate_private_key()
    client_pub_y = crypto.dh_public_int_from_private(client_priv)
    send_json(s, {"type":"dh_client_pub", "client_pub": hex(client_pub_y)})

    # compute shared
    peer_pub_key = crypto.load_peer_public_key_from_int(server_pub_y, p_int, g_int)
    shared = crypto.compute_dh_shared_secret_bytes(client_priv, peer_pub_key)
    aes_tmp = crypto.derive_aes_key_from_shared(shared)
    print("[+] Ephemeral DH complete. Temporary AES key derived.")

    # choose action: register or login
    action = input("action (register/login): ").strip().lower()
    if action == "register":
        payload = prompt_register()
    else:
        payload = prompt_login()

    # encrypt payload and send
    iv, ct = crypto.aes_encrypt_cbc(aes_tmp, json.dumps(payload).encode())
    send_json(s, {"type":"enc", "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()})

    # receive encrypted response
    resp_msg = recv_json(rfile)
    if not resp_msg or resp_msg.get("type") != "enc":
        print("No encrypted response")
        s.close()
        return
    iv2 = base64.b64decode(resp_msg["iv"])
    ct2 = base64.b64decode(resp_msg["ct"])
    pt2 = crypto.aes_decrypt_cbc(aes_tmp, iv2, ct2)
    resp = json.loads(pt2.decode())
    print("Server response:", resp)

    s.close()

if __name__ == "__main__":
    main()
