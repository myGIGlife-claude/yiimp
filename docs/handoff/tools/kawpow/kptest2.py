#!/usr/bin/env python3
# negative tests: low difficulty share, duplicate share, stale header hash
import socket, json, sys, ctypes, os
host, port, user, algo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '..', 'libkp.so'))
lib.progpow_find_variant.restype = ctypes.c_void_p; lib.progpow_find_variant.argtypes = [ctypes.c_char_p]
lib.progpow_hash.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
v = lib.progpow_find_variant(algo.encode())
s = socket.create_connection((host, port)); f = s.makefile('rw')
def send(m): f.write(json.dumps(m) + "\n"); f.flush()
send({"id": 1, "method": "mining.subscribe", "params": ["kptest/1.0"]})
send({"id": 2, "method": "mining.authorize", "params": [user, sys.argv[5]]})
nonce1 = job = target = None
while job is None or nonce1 is None:
    m = json.loads(f.readline())
    if m.get("id") == 1: nonce1 = m["result"][1]
    elif m.get("method") == "mining.set_target": target = m["params"][0]; print("set_target", target)
    elif m.get("method") == "mining.notify": job = m["params"]
jid, header, seed, jtarget, clean, height, bits = job
print("job target", jtarget)
def submit(i, n, hdr, mix):
    send({"id": i, "method": "mining.submit", "params": [user, jid, "0x%016x" % n, "0x" + hdr, "0x" + mix]})
    while True:
        m = json.loads(f.readline())
        if m.get("id") == i: return m.get("result"), m.get("error")
nonce = int(nonce1, 16) << 48
mix = ctypes.create_string_buffer(32); fin = ctypes.create_string_buffer(32)
while True:
    nonce += 1
    lib.progpow_hash(v, height, bytes.fromhex(header), nonce, mix, fin)
    if fin.raw.hex() > "7fffff" + "0" * 58: break
print("low diff (hash %s):" % fin.raw.hex()[:16], submit(10, nonce, header, mix.raw.hex()))
print("stale header:", submit(11, nonce, "11" * 32, mix.raw.hex()))
print("share again (duplicate):", submit(12, nonce, header, mix.raw.hex()))
while True:
    nonce += 1
    lib.progpow_hash(v, height, bytes.fromhex(header), nonce, mix, fin)
    if fin.raw.hex() <= "7fffff" + "0" * 58: break
print("block (hash %s):" % fin.raw.hex()[:16], submit(13, nonce, header, mix.raw.hex()))
print("duplicate:", submit(14, nonce, header, mix.raw.hex()))
