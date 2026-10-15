# Independent transcript and ring-equation check, using integer arithmetic.
# This intentionally does not call Beldex's prover, verifier, or hash routine.
import sys
from collections import defaultdict
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P
MASK = 2**64 - 1
RC = [0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,
      0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,
      0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,
      0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
def rol(x,n): return ((x << n) | (x >> (64-n))) & MASK

def keccak256(data):
    padded = bytearray(data) + b'\x01'
    padded.extend(bytes((-len(padded)) % 136))
    padded[-1] |= 0x80
    a = [0] * 25
    for off in range(0, len(padded), 136):
        for i in range(17): a[i] ^= int.from_bytes(padded[off+8*i:off+8*i+8], 'little')
        for rc in RC:
            c = [a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
            d = [c[(x-1)%5]^rol(c[(x+1)%5],1) for x in range(5)]
            b = [0] * 25
            for x in range(5):
                for y in range(5): b[y+5*((2*x+3*y)%5)] = rol(a[x+5*y]^d[x],ROT[x][y])
            for x in range(5):
                for y in range(5): a[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            a[0] ^= rc
    return b''.join(x.to_bytes(8,'little') for x in a)[:32]

assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
def decode(data):
    bits = int.from_bytes(data,'little'); y = bits & (2**255-1)
    x2 = (y*y-1)*pow(D*y*y+1,-1,P)%P
    x = pow(x2,(P+3)//8,P)
    if x*x%P != x2: x = x*pow(2,(P-1)//4,P)%P
    assert x*x%P == x2
    if (x & 1) != bits >> 255: x = P-x
    return x,y

def add(a,b):
    x,y=a; u,v=b; d=D*x*u*y*v%P
    return ((x*v+y*u)*pow(1+d,-1,P)%P,(y*v+x*u)*pow(1-d,-1,P)%P)
def mul(a,n):
    result=(0,1)
    while n:
        if n & 1: result=add(result,a)
        a=add(a,a); n >>= 1
    return result

def read(path):
    fields=defaultdict(list)
    for line in open(path):
        name,sep,value=line.strip().partition('=')
        if sep and name in {'context','ring','target','X','A','B','Pk','f','y','z','challenge'}:
            fields[name].append(bytes.fromhex(value))
    return fields

def check(fields, legacy=False):
    def one(k): return fields[k][0]
    transcript = b'' if legacy else b'BELDEX_BGE_V1'
    transcript += one('context') + b''.join(fields['ring'])
    if not legacy: transcript += one('target')
    transcript += one('A') + one('B') + b''.join(fields['Pk'])
    challenge = int.from_bytes(keccak256(transcript),'little') % L
    print('challenge=' + challenge.to_bytes(32,'little').hex())
    if 'challenge' in fields: assert challenge.to_bytes(32,'little') == one('challenge')
    m = len(fields['Pk'])
    f = [int.from_bytes(v,'little') for v in fields['f']]
    rows = [[(challenge-sum(f[j*3:j*3+3]))%L] + f[j*3:j*3+3] for j in range(m)]
    result = (0,1)
    for i in range(4**m):
        coeff=1
        for j in range(m): coeff = coeff*rows[j][(i//4**j)%4]%L
        result=add(result,mul(decode(fields['ring'][min(i,len(fields['ring'])-1)]),coeff))
    for j,pk in enumerate(fields['Pk']): result=add(result,mul(decode(pk),(-8*pow(challenge,j,L))%L))
    result=add(result,mul(decode(one('target')),(-pow(challenge,m,L))%L))
    result=add(result,mul(decode(one('X')),int.from_bytes(one('z'),'little')))
    assert result == (0,1), 'BGE ring equation failed'
    print('ring equation verified')

if __name__ == '__main__': check(read(sys.argv[1]), '--legacy' in sys.argv)
