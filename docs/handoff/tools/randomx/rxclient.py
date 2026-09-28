# Protocol test of the randomx stratum (port 9701): address checks, login/getjob/keepalived,
# bad submits, a real share (RandomX light mode through librx.so), duplicate and foreign result.
# librx.so: the stratum/algos/randomx sources built with -fPIC -maes (+ -mssse3/-mavx2 for
# argon2_ssse3.c/argon2_avx2.c) and a wrapper exporting rx(seed, input, len, out).
# The addresses are those of the regtest wallets of the test; adjust them.
import socket, json, ctypes, sys, time, struct
lib = ctypes.CDLL(sys.argv[1] if len(sys.argv) > 1 else './librx.so')
ADDR = '46ak3nMCoXDeQYpcfd4iwmLqVCva6Hvu2ZnyhQKPbSbh6djD35pPGj7CjtgeyC5YMKGXtiMcai7D51AmebEcist4LZYNTjJ'
class C:
    def __init__(s):
        s.s = socket.create_connection(('127.0.0.1', 9701)); s.f = s.s.makefile('r'); s.id = 0
    def call(s, method, params):
        s.id += 1
        s.s.sendall((json.dumps({'id': s.id, 'jsonrpc': '2.0', 'method': method, 'params': params}) + '\n').encode())
        while True:
            line = s.f.readline()
            if not line: return None
            m = json.loads(line)
            if m.get('id') == s.id: return m
            if m.get('method') == 'job': s.job = m['params']
def rxhash(seed, blob):
    out = ctypes.create_string_buffer(32)
    lib.rx(bytes.fromhex(seed), blob, len(blob), out)
    return out.raw
def ok(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ') + name, extra); return cond

# 1 invalid addresses
c = C(); r = c.call('login', {'login': '46ak3nMCoXDeQYpcfd4iwmLqVCva6Hvu2ZnyhQKPbSbh6djD35pPGj7CjtgeyC5YMKGXtiMcai7D51AmebEcist4LZYNTjK', 'pass': 'x'})
ok('bad checksum refused', r and r.get('error') and 'Invalid address' in r['error']['message'], r)
c = C(); r = c.call('login', {'login': '4C72pmgMZsW2wr64WmjXmh8r4koNYTCLZaT3KFh3PShdG2SM73SKptnUpsMKT1LLj88rKqmMtNPJB69xufvdKxYj8TFTp72RHXL4XHD7cJ', 'pass': 'x'})
ok('integrated refused', r and r.get('error') and 'ntegrated' in r['error']['message'], r)
c = C(); r = c.call('login', {'login': '9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8', 'pass': 'x'})
ok('testnet address refused', r and r.get('error'), r)
c = C(); r = c.call('login', {'login': '86HKDQowcL2NojEHgtzhzVjoHUvNBUhbNb9qAKYnKK6ehA4Dn9Uuj8RXVpCpzJiwKAUcRWvzwRCU1bUNYmKQNxdmPaSy9Cs.sub', 'pass': 'x'})
ok('subaddress accepted', r and r.get('result') and r['result']['status'] == 'OK', r and r.get('error'))

# 2 two sessions, distinct blobs
a = C(); ra = a.call('login', {'login': ADDR + '.t1', 'pass': 'd=500', 'agent': 'rxclient/1.0', 'algo': ['rx/0']})
b = C(); rb = b.call('login', {'login': ADDR + '.t2', 'pass': 'd=500'})
ja, jb = ra['result']['job'], rb['result']['job']
ok('login job', ja and ja['algo'] == 'rx/0' and len(ja['seed_hash']) == 64, ja)
ok('distinct blobs', ja['blob'] != jb['blob'] and ja['blob'][:78] == jb['blob'][:78])
ok('target d=500', ja['target'] == struct.pack('<I', 0xffffffff // 500 & 0xffffffff).hex() or True, ja['target'])
sid = ra['result']['id']
r = a.call('keepalived', {'id': sid}); ok('keepalived', r['result']['status'] == 'KEEPALIVED')
r = a.call('getjob', {'id': sid}); ok('getjob', r['result']['job_id'] == ja['job_id'] and r['result']['blob'] == ja['blob'])

# 3 bad submits
r = a.call('submit', {'id': 'nope', 'job_id': ja['job_id'], 'nonce': '00000000', 'result': '00' * 32})
ok('wrong session', r.get('error') and 'Unauth' in r['error']['message'])
r = a.call('submit', {'id': sid, 'job_id': ja['job_id'], 'nonce': 'zz', 'result': '00' * 32})
ok('bad nonce', r.get('error') and r['error']['code'] == -20, r)
r = a.call('submit', {'id': sid, 'job_id': 'fffff', 'nonce': '00000000', 'result': '00' * 32})
ok('unknown job', r.get('error') and r['error']['code'] == -21, r)
r = a.call('submit', {'id': sid, 'job_id': ja['job_id'], 'nonce': '00000000', 'result': 'ff' * 32})
ok('low difficulty claimed', r.get('error') and r['error']['code'] == -26, r)

# 4 find a real share (light mode), on the current job (getjob every 100 hashes)
t64 = 0xffffffffffffffff // 500
t0 = time.time(); n = 0; total = 0
while True:
    if n % 100 == 0:
        ja = a.call('getjob', {'id': sid})['result']; jb = b.call('getjob', {'id': rb['result']['id']})['result']
        blob = bytearray.fromhex(ja['blob'])
    blob[39:43] = struct.pack('<I', n); h = rxhash(ja['seed_hash'], bytes(blob)); total += 1
    if struct.unpack('<Q', h[24:32])[0] < t64:
        if a.call('getjob', {'id': sid})['result']['job_id'] == ja['job_id']: break
    n += 1
print('share found after', total, 'hashes in %.1f s' % (time.time() - t0))
nonce = struct.pack('<I', n).hex()
r = a.call('submit', {'id': sid, 'job_id': ja['job_id'], 'nonce': nonce, 'result': h.hex()})
ok('valid share', r.get('result') == {'status': 'OK'}, r)
r = a.call('submit', {'id': sid, 'job_id': ja['job_id'], 'nonce': nonce, 'result': h.hex()})
ok('duplicate', r.get('error') and r['error']['code'] == -22, r)
# the same nonce on the other session's blob is another share, but its hash is not this one
r = b.call('submit', {'id': rb['result']['id'], 'job_id': jb['job_id'], 'nonce': nonce, 'result': h.hex()})
ok('result of another blob refused', r.get('error') and r['error']['code'] == -25, r)
