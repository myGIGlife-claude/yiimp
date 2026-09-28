#!/usr/bin/env python3
# Stratum v1 test miner for ghostrider / mike / minotaurx / flex (hashes from our libalgos objects)
# usage: cpuminer.py host port user algo nblocks_or_shares [target_shift]
import faulthandler; faulthandler.dump_traceback_later(3000, exit=True)
import select, socket, json, hashlib, struct, sys, time, binascii, ctypes, os
host, port, user, algo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
nshares = int(sys.argv[5]) if len(sys.argv) > 5 else 5
blockonly = len(sys.argv) > 6 and sys.argv[6] == 'blocks'
lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libpow.so'))
fn = {'ghostrider': lib.ghostrider_hash, 'mike': lib.mike_hash, 'minotaurx': lib.minotaurx_hash, 'flex': lib.flex_hash}[algo]
def powhash(h):
    b = ctypes.create_string_buffer(64); fn(h, b, len(h)); return b.raw[:32]
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def sha3d(b): return hashlib.sha3_256(hashlib.sha3_256(b).digest()).digest()
cbhash = sha3d if algo == 'flex' else dsha
s = socket.create_connection((host, port)); f = s.makefile('rw')
def send(m): f.write(json.dumps(m) + "\n"); f.flush()
send({"id":1,"method":"mining.subscribe","params":["testminer/1.0"]})
send({"id":2,"method":"mining.authorize","params":[user,"x"]})
en1 = None; en2size = 4; job = None; diff = 1
def readmsg():
    global en1, en2size, job, diff
    m = json.loads(f.readline())
    if m.get("id") == 1: en1, en2size = m["result"][1], m["result"][2]
    elif m.get("id") == 2: print("authorize:", m.get("result"), m.get("error"))
    elif m.get("method") == "mining.set_difficulty": diff = m["params"][0]
    elif m.get("method") == "mining.notify": job = m["params"]
    return m
while job is None or en1 is None: readmsg()
sent = 0; ok = 0; nonce = 0; cur = None; en2i = 0
mult = {'ghostrider': 0x10000, 'mike': 0x10000}.get(algo, 1)
while sent < nshares:
    if cur is not job:
        cur = job; en2i += 1
        jid, prev, cb1, cb2, branches, ver, nbits, ntime, clean = job[:9]
        en2 = ("%0" + str(2*en2size) + "x") % en2i
        cb = binascii.unhexlify(cb1 + en1 + en2 + cb2)
        root = cbhash(cb)
        for b in branches: root = dsha(root + binascii.unhexlify(b))
        prev_hdr = b"".join(binascii.unhexlify(prev)[i:i+4][::-1] for i in range(0, 32, 4))
        hdr0 = binascii.unhexlify(ver)[::-1] + prev_hdr + root + binascii.unhexlify(ntime)[::-1] + binascii.unhexlify(nbits)[::-1]
        # share target (yiimp: 0x0000ffff * 2^208 * mult / diff)
        target = int((0x0000ffff << 208) * mult / diff) // 2
        if blockonly:
            nb = int(nbits, 16); btarget = (nb & 0xffffff) << (8 * ((nb >> 24) - 3))
            target = min(target, btarget)
        print("job", jid, "ver", ver, "diff", diff, "branches", len(branches), flush=True)
    nonce += 1
    h = powhash(hdr0 + struct.pack("<I", nonce))
    if int.from_bytes(h, "little") > target:
        while select.select([s], [], [], 0)[0]: readmsg()
        continue
    send({"id":10+sent,"method":"mining.submit","params":[user, jid, en2, ntime, "%08x" % nonce]})
    while True:
        m = readmsg()
        if m.get("id") == 10+sent:
            print("submit nonce", nonce, "hash", h[::-1].hex(), "->", m.get("result"), m.get("error"), flush=True)
            ok += 1 if m.get("result") else 0
            break
    sent += 1
print("accepted shares", ok, "/", sent)
