#!/usr/bin/env python3
# fetch block headers from a mainnet node over P2P (through the CONNECT proxy)
# usage: p2phdr.py host port magichex protover locatorhash(display hex) [count]
import socket, struct, hashlib, sys, time, os, random
host, port, magic, pver, loc = sys.argv[1], int(sys.argv[2]), bytes.fromhex(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, payload):
    return magic + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(payload)) + dsha(payload)[:4] + payload
def varint(n):
    if n < 0xfd: return bytes([n])
    return b'\xfd' + struct.pack('<H', n)
s = socket.create_connection(("127.0.0.1", 36289), timeout=30)
s.send(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
r = b''
while b'\r\n\r\n' not in r: r += s.recv(1)
addr = b'\0'*8 + b'\0'*10 + b'\xff\xff' + b'\0'*4 + b'\0\0'
ver = struct.pack('<iQq', pver, 0, int(time.time())) + addr + addr + struct.pack('<Q', random.getrandbits(64)) + b'\x00' + struct.pack('<i', 0) + b'\x00'
s.send(msg('version', ver))
buf = b''
def readmsg():
    global buf
    while True:
        while len(buf) < 24:
            d = s.recv(65536)
            if not d: raise SystemExit('closed')
            buf += d
        ln = struct.unpack('<I', buf[16:20])[0]
        while len(buf) < 24 + ln:
            d = s.recv(65536)
            if not d: raise SystemExit('closed')
            buf += d
        cmd = buf[4:16].rstrip(b'\0').decode(); pl = buf[24:24+ln]; buf = buf[24+ln:]
        return cmd, pl
sent = False
while True:
    cmd, pl = readmsg()
    sys.stderr.write('got %s %d\n' % (cmd, len(pl)))
    if cmd == 'version': s.send(msg('verack', b''))
    elif cmd == 'ping': s.send(msg('pong', pl))
    if cmd in ('verack',) and not sent:
        gh = struct.pack('<I', pver) + varint(1) + bytes.fromhex(loc)[::-1] + b'\0'*32
        s.send(msg('getheaders', gh)); sent = True
    if cmd == 'headers':
        n = pl[0]; off = 1
        if n == 0xfd: n = struct.unpack('<H', pl[1:3])[0]; off = 3
        sz = (len(pl) - off) // n
        sys.stderr.write('%d headers of %d bytes (incl txcount)\n' % (n, sz))
        for i in range(n):
            print(pl[off + i*sz: off + i*sz + sz - 1].hex())
        break
