#!/usr/bin/env python3
# ZIP-301 test miner (Equihash, small regtest parameters) for the yiimp equihash stratum.
# usage: zipminer.py host port user n k pers nshares [--prefix|--noprefix] [--bad]
import socket, json, hashlib, struct, sys, time, ctypes, os
host, port, user = sys.argv[1], int(sys.argv[2]), sys.argv[3]
n, k, pers, nshares = int(sys.argv[4]), int(sys.argv[5]), sys.argv[6], int(sys.argv[7])
noprefix = '--noprefix' in sys.argv
lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libeqsolve.so'))
c = n // (k + 1); solsize = (1 << k) * (c + 1) // 8
def compact(x): return bytes([x]) if x < 253 else b'\xfd' + struct.pack('<H', x)
def solve(inp):
    out = ctypes.create_string_buffer(solsize * 8)
    cnt = lib.eq_solve(n, k, pers.encode(), inp, len(inp), out, 8)
    return [out.raw[i*solsize:(i+1)*solsize] for i in range(cnt)]
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

import select
s = socket.create_connection((host, port)); rbuf = b""
def send(m): s.sendall((json.dumps(m) + "\n").encode())
def readline(block=True):
    global rbuf
    while b"\n" not in rbuf:
        if not block and not select.select([s], [], [], 0)[0]: return None
        d = s.recv(65536)
        if not d: raise SystemExit("connection closed")
        rbuf += d
    line, rbuf = rbuf.split(b"\n", 1)
    return line
send({"id": 1, "method": "mining.subscribe", "params": ["zipminer/1.0", None, host, str(port)]})
send({"id": 2, "method": "mining.authorize", "params": [user, "x"]})
nonce1 = None; target = None; job = None
pending = []
def handle(m):
    global nonce1, target, job
    if m.get("id") == 1:
        print("subscribe ->", m.get("result"), m.get("error")); nonce1 = m["result"][1]
    elif m.get("id") == 2: print("authorize ->", m.get("result"), m.get("error"))
    elif m.get("method") == "mining.set_target":
        target = int(m["params"][0], 16); print("set_target", m["params"][0])
    elif m.get("method") == "mining.notify":
        job = m["params"]; print("notify", job[0], "clean", job[7])
    elif m.get("id") is not None and m.get("id") >= 100:
        pending.append(m)
    else:
        print("msg", m)
def poll():
    while True:
        line = readline(False)
        if line is None: return
        handle(json.loads(line))
while nonce1 is None or target is None or job is None:
    handle(json.loads(readline()))
sent = 0; accepted = 0; n2 = 0; sid = 100; blocks = 0
t0 = time.time()
while sent < nshares:
    poll()
    jid, ver, prev, merkle, reserved, ntime, bits, clean = job[:8]
    n2 += 1
    nonce2 = n2.to_bytes(32 - len(nonce1)//2, 'little').hex()
    hdr = bytes.fromhex(ver + prev + merkle + reserved + ntime + bits + nonce1 + nonce2)
    assert len(hdr) == 140
    for sol in solve(hdr):
        blk = hdr + compact(solsize) + sol
        h = int.from_bytes(dsha(blk)[::-1], 'big')
        if h > target: continue
        solhex = sol.hex() if noprefix else (compact(solsize) + sol).hex()
        if '--bad' in sys.argv and sent % 2 == 1:
            # a corrupted solution whose block hash still meets the share target
            for i in range(1, 10000):
                b = bytearray(sol); b[i % solsize] ^= (i // solsize) + 1
                if int.from_bytes(dsha(hdr + compact(solsize) + bytes(b))[::-1], 'big') <= target: break
            solhex = (compact(solsize) + bytes(b)).hex()
        if '--dup' in sys.argv and sent % 3 == 2:
            send({"id": 99, "method": "mining.submit", "params": [user, jid, ntime, nonce2, solhex]})
        send({"id": sid, "method": "mining.submit", "params": [user, jid, ntime, nonce2, solhex]})
        while True:
            m = json.loads(readline())
            if m.get("id") == sid: break
            handle(m)
        print("submit job %s nonce2 %s.. hash %064x -> %s %s" % (jid, nonce2[:8], h, m.get("result"), m.get("error")))
        sid += 1; sent += 1
        if m.get("result"): accepted += 1
        if sent >= nshares: break
        time.sleep(0.3)
print("sent", sent, "accepted", accepted, "time %.1fs" % (time.time() - t0))
