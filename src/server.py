import socket
import json
import os
import base64
import secrets
import pymysql
from dotenv import load_dotenv
from helpers.cert_utils import load_pem, load_cert, verify_certificate
from helpers import crypto
from hashlib import sha256
import hmac
import time

load_dotenv()

HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "9000"))
CERTS_DIR = os.getenv("CERTS_DIR", "certs")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "securechat_user")
DB_PASS = os.getenv("DB_PASS", "secure_password_here")
DB_NAME = os.getenv("DB_NAME", "securechat")

def connect_db():
    return pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME, autocommit=True)

# simple newline-delimited JSON framing
def send_json(conn, obj):
    data = json.dumps(obj).encode() + b"\n"
    conn.sendall(data)

def recv_json(rfile):
    line = rfile.readline()
    if not line:
        return None
    return json.loads(line.decode())

def handle_register(db_conn, email, username, password_bytes):
    # server generates salt, stores hex(sha256(salt||pwd))
    salt = secrets.token_bytes(16)
    h = sha256(salt + password_bytes).hexdigest()
    with db_conn.cursor() as cur:
        cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                    (email, username, salt, h))
    return True, "registered"

def handle_login(db_conn, email, password_bytes):
    with db_conn.cursor() as cur:
        cur.execute("SELECT id, salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
    if not row:
        return False, "no such user"
    _, salt, stored_hash = row
    recomputed = sha256(salt + password_bytes).hexdigest()
    if hmac.compare_digest(recomputed, stored_hash):
        return True, "ok"
    else:
        return False, "invalid credentials"

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR, "ca.cert.pem")))
    my_cert_pem = load_pem(os.path.join(CERTS_DIR, "server.cert.pem"))
    my_key_pem = load_pem(os.path.join(CERTS_DIR, "server.key.pem"))
    my_cert = load_cert(my_cert_pem)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[+] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = srv.accept()
        print(f"[+] Connection from {addr}")
        rfile = conn.makefile("rb")
        try:
            # 1) receive hello
            msg = recv_json(rfile)
            if not msg or msg.get("type") != "hello":
                conn.close()
                continue
            client_cert_b64 = msg["cert"]
            client_nonce = base64.b64decode(msg["nonce"])
            client_cert = load_cert(base64.b64decode(client_cert_b64))
            if not verify_certificate(client_cert, ca_cert):
                print("[!] BAD CLIENT CERT, closing")
                send_json(conn, {"type":"error","msg":"bad cert"})
                conn.close()
                continue
            print("[+] Client cert verified OK")

            # 2) reply with server cert + nonce
            server_nonce = secrets.token_bytes(16)
            reply = {
                "type": "hello_ack",
                "cert": base64.b64encode(my_cert_pem).decode(),
                "nonce": base64.b64encode(server_nonce).decode()
            }
            send_json(conn, reply)

            # 3) Perform ephemeral DH: server creates params and its private key
            p_int, g_int, params = crypto.generate_dh_parameters(2048)
            server_priv = crypto.generate_dh_private_key_from_params(params)
            server_pub_y = crypto.dh_public_int_from_private(server_priv)

            # send DH params and server public (hex strings)
            send_json(conn, {
                "type": "dh_params",
                "p": hex(p_int),
                "g": hex(g_int),
                "server_pub": hex(server_pub_y)
            })

            # receive client public
            msg = recv_json(rfile)
            if not msg or msg.get("type") != "dh_client_pub":
                print("[!] DH client pub missing")
                conn.close()
                continue
            client_pub_y = int(msg["client_pub"], 16)
            # build peer public key object
            peer_pub_key = crypto.load_peer_public_key_from_int(client_pub_y, p_int, g_int)
            shared = crypto.compute_dh_shared_secret_bytes(server_priv, peer_pub_key)
            aes_tmp = crypto.derive_aes_key_from_shared(shared)
            print("[+] Ephemeral DH complete. Temporary AES key derived.")

            # Now accept encrypted commands using AES-CBC (iv + ct fields)
            db_conn = connect_db()
            while True:
                enc_msg = recv_json(rfile)
                if enc_msg is None:
                    break
                if enc_msg.get("type") != "enc":
                    send_json(conn, {"type":"error","msg":"expected enc"})
                    continue
                iv = base64.b64decode(enc_msg["iv"])
                ct = base64.b64decode(enc_msg["ct"])
                try:
                    pt = crypto.aes_decrypt_cbc(aes_tmp, iv, ct)
                except Exception as e:
                    send_json(conn, {"type":"error","msg":"decrypt failed"})
                    continue
                payload = json.loads(pt.decode())
                if payload.get("type") == "register":
                    email = payload["email"]
                    username = payload["username"]
                    pwd_b64 = payload["pwd"]
                    pwd = base64.b64decode(pwd_b64)
                    ok, msgtxt = handle_register(db_conn, email, username, pwd)
                    resp = {"status":"ok" if ok else "error", "msg":msgtxt}
                elif payload.get("type") == "login":
                    email = payload["email"]
                    pwd_b64 = payload["pwd"]
                    pwd = base64.b64decode(pwd_b64)
                    ok, msgtxt = handle_login(db_conn, email, pwd)
                    resp = {"status":"ok" if ok else "error", "msg":msgtxt}
                else:
                    resp = {"status":"error","msg":"unknown cmd"}

                # encrypt response
                iv2, ct2 = crypto.aes_encrypt_cbc(aes_tmp, json.dumps(resp).encode())
                send_json(conn, {"type":"enc", "iv": base64.b64encode(iv2).decode(), "ct": base64.b64encode(ct2).decode()})

        except Exception as ex:
            print("[!] Exception:", ex)
        finally:
            try:
                conn.close()
            except:
                pass

if __name__ == "__main__":
    main()
