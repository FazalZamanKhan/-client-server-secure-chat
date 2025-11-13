# tools/tamper_send.py
# Usage: python tools/tamper_send.py original_packet.json
import socket, sys, json, base64

if len(sys.argv) < 2:
    print("Usage: python tools/tamper_send.py original_packet.json")
    sys.exit(1)

fn = sys.argv[1]
with open(fn, "r") as f:
    pkt = json.load(f)

if pkt.get("type") != "msg":
    print("packet must be of type 'msg'")
    sys.exit(1)

# decode ct, flip one byte, re-encode
ct_b64 = pkt["ct"]
ct = bytearray(base64.b64decode(ct_b64))
# flip a byte in middle (tamper)
if len(ct) > 5:
    ct[5] = (ct[5] + 1) % 256
else:
    ct[0] = (ct[0] + 1) % 256
pkt["ct"] = base64.b64encode(bytes(ct)).decode()

# keep original sig (so signature no longer matches)
HOST = "127.0.0.1"
PORT = 9100
s = socket.socket()
s.connect((HOST, PORT))
s.sendall(json.dumps(pkt).encode() + b"\n")
print("Tampered packet sent. Waiting for server reply (5s)...")
s.settimeout(5.0)
try:
    resp = s.recv(4096)
    print("Server:", resp.decode(errors="ignore"))
except Exception as e:
    print("No reply or timeout:", e)
s.close()
