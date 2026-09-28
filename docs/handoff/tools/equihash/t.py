import ctypes, sys, time
sys.path.insert(0,'../eqkat')
from eqref import verify
lib=ctypes.CDLL('./libeqsolve.so')
def solve(n,k,pers,inp,maxs=8):
    c=n//(k+1); sz=(1<<k)*(c+1)//8
    out=ctypes.create_string_buffer(sz*maxs)
    cnt=lib.eq_solve(n,k,pers.encode(),inp,len(inp),out,maxs)
    return [out.raw[i*sz:(i+1)*sz] for i in range(cnt)]
for (n,k) in [(48,5),(96,5)]:
    tot=0; ok=0; t=time.time()
    for nonce in range(10):
        inp=bytes(108)+nonce.to_bytes(32,'little')
        for s in solve(n,k,'ZcashPoW',inp):
            tot+=1; ok+=verify(n,k,'ZcashPoW',inp,s)
    print(n,k,'solutions',tot,'valid',ok,'time',time.time()-t)
