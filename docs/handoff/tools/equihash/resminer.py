#!/usr/bin/env python3
# Test miner of the resistance-miner stratum dialect (Bitcoin stratum + 10th notify param
# hashFinalSaplingRoot, 140 byte header, 4 byte nonce at offset 108), yespowerRES.
# usage: resminer.py host port user nshares
import socket, json, hashlib, struct, sys, time, ctypes, os, select
host, port, user, nshares = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libyesres.so'))
def yp(h):
    o = ctypes.create_string_buffer(32); lib.yespowerRES_hash(h, o, len(h)); return o.raw
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def wswap(hexs):  # stratum word swapped (each 4 byte word reversed)
    b = bytes.fromhex(hexs); return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))
s = socket.create_connection((host, port)); rbuf = b""
def send(m): s.sendall((json.dumps(m) + "\n").encode())
def readline(block=True):
    global rbuf
    while b"\n" not in rbuf:
        if not block and not select.select([s], [], [], 0)[0]: return None
        d = s.recv(65536)
        if not d: raise SystemExit("closed")
        rbuf += d
    l, rbuf = rbuf.split(b"\n", 1); return l
send({"id": 1, "method": "mining.subscribe", "params": ["resminer/1.0"]})
send({"id": 2, "method": "mining.authorize", "params": [user, "x"]})
en1 = None; diff = None; job = None
def handle(m):
    global en1, en2size, diff, job
    if m.get("id") == 1: en1, en2size = m["result"][1], m["result"][2]; print("subscribe", m["result"])
    elif m.get("id") == 2: print("authorize", m.get("result"), m.get("error"))
    elif m.get("method") == "mining.set_difficulty": diff = m["params"][0]; print("diff", diff)
    elif m.get("method") == "mining.notify": job = m["params"]; print("notify", job[0], "params", len(job))
while en1 is None or diff is None or job is None: handle(json.loads(readline()))
sent = acc = 0; n2 = 0; sid = 100
while sent < nshares:
    while True:
        l = readline(False)
        if l is None: break
        handle(json.loads(l))
    jid, prev, cb1, cb2, branches, ver, nbits, ntime, clean, root = job[:10]
    n2 += 1; en2 = "%08x" % n2
    cb = bytes.fromhex(cb1 + en1 + en2 + cb2)
    mr = dsha(cb)
    for b in branches: mr = dsha(mr + bytes.fromhex(b))
    hdr0 = bytes.fromhex(ver)[::-1] + wswap(prev) + mr + wswap(root) + bytes.fromhex(ntime)[::-1] + bytes.fromhex(nbits)[::-1]
    target = int((0xffff << 208) * 65536 / diff)  # cpuminer diff/65536
    for nonce in range(0, 400):
        hdr = hdr0 + struct.pack(">I", nonce) + bytes(28)   # be32enc(n) as resistance-miner
        h = int.from_bytes(yp(hdr), 'little')
        if h > target: continue
        send({"id": sid, "method": "mining.submit", "params": [user, jid, en2, ntime, struct.pack("<I", nonce).hex()]})
        while True:
            m = json.loads(readline())
            if m.get("id") == sid: break
            handle(m)
        print("submit job %s en2 %s nonce %d hash %064x -> %s %s" % (jid, en2, nonce, h, m.get("result"), m.get("error")))
        sid += 1; sent += 1; acc += bool(m.get("result"))
        break
print("sent", sent, "accepted", acc)
