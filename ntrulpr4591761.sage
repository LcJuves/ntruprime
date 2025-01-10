p = 761; q61 = 765; q = 6*q61+1; w = 250
Zx.<x> = ZZ[]; R.<xp> = Zx.quotient(x^p-x-1)
Fq = GF(q); Fqx.<xq> = Fq[]; Rq.<xqp> = Fqx.quotient(x^p-x-1)
F3 = GF(3); F3x.<x3> = F3[]; R3.<x3p> = F3x.quotient(x^p-x-1)

import hashlib
def hash(s): h = hashlib.sha512(); h.update(s); return h.digest()

import itertools
def concat(lists): return list(itertools.chain.from_iterable(lists))

def nicelift(u):
  return lift(u + q//2) - q//2

def nicemod3(u): # r in {0,1,-1} with u-r in {...,-3,0,3,...}
  return u - 3*round(u/3)

def int2str(u,bytes):
  return ''.join(chr((u//256^i)%256) for i in range(bytes))

def str2int(s):
  return sum(ord(s[i])*256^i for i in range(len(s)))

def seq2str(u,radix,batch,bytes): # radix^batch <= 256^bytes
  return ''.join(int2str(sum(u[i+t]*radix^t for t in range(batch)),bytes)
                 for i in range(0,len(u),batch))

def str2seq(s,radix,batch,bytes):
  u = [str2int(s[i:i+bytes]) for i in range(0,len(s),bytes)]
  return concat([(u[i]//radix^j)%radix for j in range(batch)] for i in range(len(u)))

def encodeZx(m): # assumes coefficients in range {-1,0,1}
  m = [m[i]+1 for i in range(p)] + [0]*(-p % 4)
  return seq2str(m,4,4,1)

def decodeZx(mstr):
  m = str2seq(mstr,4,4,1)
  return Zx([m[i]-1 for i in range(p)])

def encoderoundedRq(c):
  c = [q61 + nicelift(c[i]/3) for i in range(p)] + [0]*(-p % 6)
  return seq2str(c,1536,3,4)[:1015]

def decoderoundedRq(cstr):
  c = str2seq(cstr,1536,3,4)
  if max(c) > q61*2: raise Exception("c out of range")
  return 3*Rq([c[i]-q61 for i in range(p)])

def roundRq(h):
  e = Zx([-nicemod3(nicelift(h[i])) for i in range(p)])
  return Rq(e) + h

from Crypto.Cipher import AES
from Crypto.Util import Counter
def stream32(k): # k |-> p random elements of [0,2^32-1]
  s = AES.new(k,AES.MODE_CTR,counter=Counter.new(128,initial_value=0))
  c = s.encrypt('\0'*(4*p))
  return str2seq(c,2^32,1,4)

def seededRq(k): # Rq element from cipher seed
  G = stream32(k)
  G = [(Gi % q) - 3*q61 for Gi in G]
  return Rq(G)

def seededRsmall(k): # R element with w coeffs +-1 from cipher seed
  G = stream32(k)
  L = [G[i] & (-2) for i in range(w)]
  L += [(G[i+w] & (-3)) | 1 for i in range(p-w)]
  L.sort()
  L = [(L[i]%4)-1 for i in range(p)]
  return Zx(L)

def randomR():
  return seededRsmall(os.urandom(32))

def keygen():
  K = os.urandom(32)
  G = seededRq(K)
  a = randomR()
  aG = G * Rq(a)
  A = roundRq(aG)
  pk = K + encoderoundedRq(A)
  sk = encodeZx(a) + pk
  return pk,sk

def Right(C):
  C = str2seq(C,16,2,1)
  return [287*Ci - 2007 for Ci in C]

def Top(C):
  C = [round(((nicelift(Ci) + 2156) * 114) / 2^15) for Ci in C]
  return seq2str(C,16,2,1)

def hide(pk,r):
  K,A = pk[:32],decoderoundedRq(pk[32:])
  G = seededRq(K)

  k12 = hash(r)
  k1,k2 = k12[:32],k12[32:]

  b = seededRsmall(k1)
  bG = G * Rq(b)
  bA = A * Rq(b)
  B = roundRq(bG)

  rbits = str2seq(r,2,8,1)
  C = [bA[i] + 3*q61*rbits[i] for i in range(256)]

  k34 = hash(k2)
  k3,k4 = k34[:32],k34[32:]
  return k3 + encoderoundedRq(B) + Top(C),k4

def encapsulate(pk):
  return hide(pk,os.urandom(32))

def decapsulate(cstr,sk):
  a,pk = decodeZx(sk[:191]),sk[191:]
  B,C = decoderoundedRq(cstr[32:1047]),Right(cstr[1047:])

  aB = B * Rq(a)
  C = [C[i] - aB[i] + 4*w+1 for i in range(256)]
  rbits = [-(nicelift(Ci) >> 30) for Ci in C]
  r = seq2str(rbits,2,8,1)

  check,k = hide(pk,r)
  if check != cstr: return False
  return k
  
for keys in range(5):
  pk,sk = keygen()
  for ciphertexts in range(5):
    c,k = encapsulate(pk)
    assert decapsulate(c,sk) == k

print len(pk),'bytes in public key'
print len(sk),'bytes in secret key'
print len(c),'bytes in ciphertext'
print len(k),'bytes in shared secret'
