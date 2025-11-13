# src/server_chat.py
import socket, json, base64, os, secrets, time
from helpers import crypto
from helpers.cert_utils import load_pem, load_cert, verify_certificate

CERTS_DIR = os.getenv("CERTS_DIR", "certs")
HOST, PORT = "0.0.0.0", 9100
TRANSCRIPT_PATH = "transcripts/server_transcript.log"

def send_json(conn, obj):
    conn.sendall(json.dumps(obj).encode() + b"\n")

def recv_json(rfile):
    line = rfile.readline()
    if not line:
        return None
    return json.loads(line.decode())

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR,"ca.cert.pem")))
    my_cert_pem = load_pem(os.path.join(CERTS_DIR,"server.cert.pem"))
    my_key_pem  = load_pem(os.path.join(CERTS_DIR,"server.key.pem"))
    my_cert     = load_cert(my_cert_pem)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[+] Chat server listening on {PORT}")

    conn, addr = srv.accept()
    print(f"[+] Chat from {addr}")
    rfile = conn.makefile("rb")

    # 1️⃣  Mutual cert exchange
    msg = recv_json(rfile)
    client_cert = load_cert(base64.b64decode(msg["cert"]))
    if not verify_certificate(client_cert, ca_cert):
        print("[!] Bad client cert"); conn.close(); return
    send_json(conn, {"type":"cert","cert":base64.b64encode(my_cert_pem).decode()})
    print("[+] Certs verified.")

    # 2️⃣  Session DH key exchange
    p,g,params = crypto.generate_dh_parameters()
    priv = crypto.generate_dh_private_key_from_params(params)
    y = crypto.dh_public_int_from_private(priv)
    send_json(conn, {"type":"dh_params","p":hex(p),"g":hex(g),"y":hex(y)})
    msg = recv_json(rfile)
    y_peer = int(msg["y"],16)
    peer_pub = crypto.load_peer_public_key_from_int(y_peer,p,g)
    shared = crypto.compute_dh_shared_secret_bytes(priv,peer_pub)
    K = crypto.derive_aes_key_from_shared(shared)
    print("[+] Session AES key established.")

    # 3️⃣  Chat loop
    last_seq = 0
    open(TRANSCRIPT_PATH,"w").close()
    while True:
        msg = recv_json(rfile)
        if not msg: break
        if msg.get("type")=="msg":
            seq,ts,iv,ct,sig = msg["seqno"],msg["ts"],base64.b64decode(msg["iv"]),base64.b64decode(msg["ct"]),base64.b64decode(msg["sig"])
            # Seqno monotonicity / replay protection
            if int(seq) <= last_seq:
                print(f"[!] REPLAY or OOO seq: {seq} <= last_seq {last_seq} - rejecting")
                send_json(conn, {"type":"error", "msg":"replay/sequence error"})
                continue
            last_seq = int(seq)
            # verify signature
            h = crypto.sha256(str(seq).encode()+str(ts).encode()+msg["ct"].encode()).digest()
            try:
                crypto.rsa_verify(client_cert.public_key().public_bytes(
                    crypto.serialization.Encoding.PEM,
                    crypto.serialization.PublicFormat.SubjectPublicKeyInfo),
                    sig,h)
                pt = crypto.aes_decrypt_cbc(K,iv,base64.b64decode(msg["ct"]))
                print(f"[client#{seq}] {pt.decode()}")
                # log transcript
                with open(TRANSCRIPT_PATH,"a") as f:
                    f.write(f"{seq}|{ts}|{msg['ct']}|{base64.b64encode(sig).decode()}|{crypto.cert_fingerprint(client_cert.public_bytes(crypto.serialization.Encoding.PEM))}\n")
            except Exception:
                print("[!] Signature verification failed")
        elif msg.get("type")=="bye":
            break

    # 4️⃣  Compute session receipt
    with open(TRANSCRIPT_PATH,"rb") as f:
        transcript_bytes = f.read()
    thash = crypto.sha256(transcript_bytes).hexdigest()
    sig = crypto.rsa_sign(my_key_pem, thash.encode())
    receipt = {
        "type": "receipt",
        "transcript_sha256": thash,
        "sig": base64.b64encode(sig).decode()
    }
    send_json(conn, receipt)
    print("[+] Session receipt sent.")
    conn.close()

if __name__=="__main__":
    main()
