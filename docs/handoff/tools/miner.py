#!/usr/bin/env python3
# Minimal stratum v1 test miner (scrypt / sha256d) for regtest end-to-end tests.
import socket, json, hashlib, struct, sys, time, binascii
host, port, user, algo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
nshares = int(sys.argv[5]) if len(sys.argv) > 5 else 5
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def powhash(h):
    if algo == 'scrypt': return hashlib.scrypt(h, salt=h, n=1024, r=1, p=1, dklen=32)
    return dsha(h)
s = socket.create_connection((host, port)); f = s.makefile('rw')
def send(m): f.write(json.dumps(m) + "\n"); f.flush()
send({"id":1,"method":"mining.subscribe","params":["testminer/1.0"]})
send({"id":2,"method":"mining.authorize","params":[user,"c=LTC"]})
en1 = None; en2size = 4; job = None; diff = 1; msgs = 0
while job is None or en1 is None:
    m = json.loads(f.readline()); msgs += 1
    if m.get("id") == 1: en1, en2size = m["result"][1], m["result"][2]
    elif m.get("id") == 2: print("authorize:", m.get("result"), m.get("error"))
    elif m.get("method") == "mining.set_difficulty": diff = m["params"][0]
    elif m.get("method") == "mining.notify": job = m["params"]
jid, prev, cb1, cb2, branches, ver, nbits, ntime, clean = job[:9]
print("job", jid, "diff", diff, "branches", len(branches))
en2 = "00" * en2size
cb = binascii.unhexlify(cb1 + en1 + en2 + cb2)
root = dsha(cb)
for b in branches: root = dsha(root + binascii.unhexlify(b))
prev_le = b"".join(binascii.unhexlify(prev)[i:i+4][::-1] for i in range(0, 32, 4))
hdr0 = binascii.unhexlify(ver)[::-1] + prev_le[::-1][::-1] + root + binascii.unhexlify(ntime)[::-1] + binascii.unhexlify(nbits)[::-1]
# stratum prevhash is word-swapped big endian; convert to header byte order
prev_hdr = b"".join(binascii.unhexlify(prev)[i:i+4][::-1] for i in range(0, 32, 4))
hdr0 = binascii.unhexlify(ver)[::-1] + prev_hdr + root + binascii.unhexlify(ntime)[::-1] + binascii.unhexlify(nbits)[::-1]
sent = 0; nonce = 0
while sent < nshares:
    nonce += 1
    h = powhash(hdr0 + struct.pack("<I", nonce))
    if int.from_bytes(h, "little") > (1 << 256) // 64: continue
    send({"id":10+sent,"method":"mining.submit","params":[user, jid, en2, ntime, "%08x" % nonce]})
    while True:
        m = json.loads(f.readline())
        if m.get("id") == 10+sent:
            print("submit nonce", nonce, "->", m.get("result"), m.get("error")); break
    sent += 1
    time.sleep(0.2)
