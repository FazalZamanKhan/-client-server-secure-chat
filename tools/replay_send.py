# tools/replay_send.py
# Usage: python tools/replay_send.py replay_packet.json
import socket, sys, json

if len(sys.argv) < 2:
    print("Usage: python tools/replay_send.py replay_packet.json")
    sys.exit(1)

packet_fn = sys.argv[1]
with open(packet_fn, "r") as f:
    obj = json.load(f)

HOST = "127.0.0.1"
PORT = 9100

s = socket.socket()
s.connect((HOST, PORT))
# send as newline-delimited JSON
s.sendall(json.dumps(obj).encode() + b"\n")
print("Sent replay packet, waiting for server response (5s)...")
s.settimeout(5.0)
try:
    resp = s.recv(4096)
    print("Server:", resp.decode(errors="ignore"))
except Exception as e:
    print("No reply or timeout:", e)
s.close()
