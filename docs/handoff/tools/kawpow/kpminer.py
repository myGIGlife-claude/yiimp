#!/usr/bin/env python3
# Minimal KawPoW-family stratum test miner (kawpowminer protocol), CPU light hashing through
# libkp.so (the stratum's own progpow code).
# usage: kpminer.py host port user algo nshares [lib]
import socket, json, sys, time, ctypes, os
host, port, user, algo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
nshares = int(sys.argv[5]) if len(sys.argv) > 5 else 5
blocks_only = len(sys.argv) > 6 and sys.argv[6] == 'blocks'
lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '..', 'libkp.so'))
lib.progpow_find_variant.restype = ctypes.c_void_p
lib.progpow_find_variant.argtypes = [ctypes.c_char_p]
lib.progpow_hash.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
lib.progpow_seed_hash.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
v = lib.progpow_find_variant(algo.encode())
assert v, "unknown algo"

s = socket.create_connection((host, port))
rbuf = b''
def send(m): s.sendall((json.dumps(m) + "\n").encode())
def readline():
    # one reader for the whole script (blocking)
    global rbuf
    while b'\n' not in rbuf:
        s.setblocking(True)
        d = s.recv(65536)
        if not d: raise SystemExit("closed")
        rbuf += d
    line, rbuf = rbuf.split(b'\n', 1)
    return line
send({"id": 1, "method": "mining.subscribe", "params": ["kpminer/1.0"]})
send({"id": 2, "method": "mining.authorize", "params": [user, "x"]})
nonce1 = None; job = None; target = None
def handle(m):
    global nonce1, job, target
    if m.get("id") == 1:
        print("subscribe:", m.get("result"), m.get("error")); nonce1 = m["result"][1]
    elif m.get("id") == 2: print("authorize:", m.get("result"), m.get("error"))
    elif m.get("method") == "mining.set_target": target = m["params"][0]; print("set_target", target)
    elif m.get("method") == "mining.notify": job = m["params"]; print("notify", job)
    else: return False
    return True
while job is None or nonce1 is None or target is None:
    handle(json.loads(readline()))

def poll():
    global rbuf
    s.setblocking(False)
    try:
        d = s.recv(65536)
        if not d: raise SystemExit("closed")
        rbuf += d
    except BlockingIOError:
        pass
    s.setblocking(True)
    while b'\n' in rbuf:
        line, rbuf = rbuf.split(b'\n', 1)
        m = json.loads(line)
        if not handle(m): print("recv", m)

sent = 0; accepted = 0
nonce = int(nonce1, 16) << (64 - 4 * len(nonce1))
while sent < nshares:
    poll()
    jid, header, seed, jtarget, clean, height, bits = job
    # the seed hash must be the one of the epoch of this height
    sd = ctypes.create_string_buffer(32); lib.progpow_seed_hash(v, height, sd)
    assert sd.raw.hex() == seed, ("seed mismatch", sd.raw.hex(), seed)
    mix = ctypes.create_string_buffer(32); fin = ctypes.create_string_buffer(32)
    nonce += 1
    lib.progpow_hash(v, height, bytes.fromhex(header), nonce, mix, fin)
    if fin.raw.hex() > jtarget: continue
    if blocks_only:
        b = int(bits, 16); bt = (b & 0xffffff) << (8 * ((b >> 24) - 3))
        if int(fin.raw.hex(), 16) > bt: continue
    send({"id": 100 + sent, "method": "mining.submit",
          "params": [user, jid, "0x%016x" % nonce, "0x" + header, "0x" + mix.raw.hex()]})
    while True:
        m = json.loads(readline())
        if handle(m): continue
        if m.get("id") == 100 + sent:
            print("submit height %d nonce %016x hash %s -> %s %s" % (height, nonce, fin.raw.hex(), m.get("result"), m.get("error")))
            if m.get("result"): accepted += 1
            break
        print("recv", m)
    sent += 1
    time.sleep(0.5)
    poll()
# a few bad shares: wrong mix, wrong nonce prefix, duplicate
jid, header, seed, jtarget, clean, height, bits = job
tests = [("bad mix", "0x%016x" % (nonce + 12345), "0x" + "00" * 32),
         ("bad prefix", "0x%016x" % ((nonce ^ (0xffff << 48)) + 1), "0x" + mix.raw.hex()),
         ("duplicate", "0x%016x" % nonce, "0x" + mix.raw.hex())]
for i, (name, n, mx) in enumerate(tests):
    send({"id": 500 + i, "method": "mining.submit", "params": [user, jid, n, "0x" + header, mx]})
    while True:
        m = json.loads(readline())
        if handle(m): continue
        if m.get("id") == 500 + i: print("%s -> %s %s" % (name, m.get("result"), m.get("error"))); break
print("accepted %d/%d" % (accepted, sent))
