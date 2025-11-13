# src/client_chat.py
import socket, json, base64, os, time
from helpers import crypto
from helpers.cert_utils import load_pem, load_cert, verify_certificate

CERTS_DIR = os.getenv("CERTS_DIR","certs")
SERVER_HOST, SERVER_PORT = "127.0.0.1", 9100
TRANSCRIPT_PATH = "transcripts/client_transcript.log"

def send_json(conn,obj): conn.sendall(json.dumps(obj).encode()+b"\n")
def recv_json(rfile):
    line=rfile.readline()
    if not line: return None
    return json.loads(line.decode())

def main():
    ca_cert = load_cert(load_pem(os.path.join(CERTS_DIR,"ca.cert.pem")))
    my_cert_pem=load_pem(os.path.join(CERTS_DIR,"client.cert.pem"))
    my_key_pem=load_pem(os.path.join(CERTS_DIR,"client.key.pem"))
    my_cert=load_cert(my_cert_pem)

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((SERVER_HOST,SERVER_PORT))
    rfile=s.makefile("rb")

    # 1️⃣ Send our cert
    send_json(s,{"type":"cert","cert":base64.b64encode(my_cert_pem).decode()})
    msg=recv_json(rfile)
    server_cert=load_cert(base64.b64decode(msg["cert"]))
    if not verify_certificate(server_cert,ca_cert):
        print("Bad server cert"); return
    print("[+] Certs verified.")

    # 2️⃣ Session DH
    msg=recv_json(rfile)
    p,g,y_server=int(msg["p"],16),int(msg["g"],16),int(msg["y"],16)
    from cryptography.hazmat.primitives.asymmetric import dh
    params=dh.DHParameterNumbers(p,g).parameters()
    priv=params.generate_private_key()
    y_client=crypto.dh_public_int_from_private(priv)
    send_json(s,{"type":"dh_pub","y":hex(y_client)})
    peer_pub=crypto.load_peer_public_key_from_int(y_server,p,g)
    shared=crypto.compute_dh_shared_secret_bytes(priv,peer_pub)
    K=crypto.derive_aes_key_from_shared(shared)
    print("[+] Session AES key established.")

    # 3️⃣ Chat loop
    seq=1
    open(TRANSCRIPT_PATH,"w").close()
    while True:
        msg_txt=input("You> ")
        if msg_txt.lower() in ["bye","exit"]: send_json(s,{"type":"bye"}); break
        ts=crypto.current_unix_ms()
        iv,ct=crypto.aes_encrypt_cbc(K,msg_txt.encode())
        ct_b64=base64.b64encode(ct).decode()
        h=crypto.sha256(str(seq).encode()+str(ts).encode()+ct_b64.encode()).digest()
        sig=crypto.rsa_sign(my_key_pem,h)
        packet={"type":"msg","seqno":seq,"ts":ts,"iv":base64.b64encode(iv).decode(),
                "ct":ct_b64,"sig":base64.b64encode(sig).decode()}
        send_json(s,packet)
        with open(TRANSCRIPT_PATH,"a") as f:
            f.write(f"{seq}|{ts}|{ct_b64}|{base64.b64encode(sig).decode()}|{crypto.cert_fingerprint(server_cert.public_bytes(crypto.serialization.Encoding.PEM))}\n")
        seq+=1

    # 4️⃣ Receive receipt
    msg=recv_json(rfile)
    print("[Server receipt]",msg)
    s.close()

if __name__=="__main__":
    main()
