#!/usr/bin/env sage
"""
weave (UMDCTF 2026)
취약점: 모든 cipher piece(warp, bolt, pegs, knot, shuttle, fibers)를 다 노출.
- loom_{j,i} = pegs[i]^(q^j) → Moore matrix → Gabidulin code 생성행렬
- warp = knot * loom * shuttle^-1, bolt = secret*warp + frays
- frays는 F_q-rank ≤ 5 의 rank-metric error
- y = bolt * shuttle = (secret*knot)*loom + (frays*shuttle)
  frays*shuttle 의 F_q-rank ≤ 5 * FIBER_D=3 = 15 ≤ floor((40-8)/2)=16 → decodable
- Gabidulin 디코딩 → secret*knot 복구 → /knot → secret → SHA256 → AES-GCM key
"""

import json
from sage.all import *

with open('output.json') as f:
    data = json.load(f)

Q = int(data['spec']['q'])
M = int(data['spec']['m'])
N = int(data['spec']['n'])
K = int(data['spec']['k'])

R = PolynomialRing(GF(Q), 'x')
MODPOLY = R(data['spec']['modulus'])
assert MODPOLY.is_irreducible()

Fq = GF(Q)
Fqm = GF(Q**M, 'a', modulus=MODPOLY)

def unpack_elem(val):
    v = int(val)
    cs = [(v >> i) & 1 for i in range(M)]
    return Fqm(cs)

def unpack_vec(arr):
    return [unpack_elem(v) for v in arr]

def unpack_mat(arr):
    return [unpack_vec(row) for row in arr]

pegs    = unpack_vec(data['loom']['pegs'])
knot    = Matrix(Fqm, unpack_mat(data['loom']['knot']))
shuttle = Matrix(Fqm, unpack_mat(data['loom']['shuttle']))
fibers  = unpack_vec(data['loom']['fibers'])
warp    = Matrix(Fqm, unpack_mat(data['warp']))
bolt    = vector(Fqm, unpack_vec(data['bolt']))

print('[*] reconstruct loom (Moore matrix from pegs)')
loom = Matrix(Fqm, K, N, lambda j, i: pegs[i] ** (Q**j))

print('[*] verify warp = knot * loom * shuttle^-1')
assert knot * loom * shuttle.inverse() == warp

print('[*] y = bolt * shuttle  (Gabidulin codeword + rank<=15 error)')
y = bolt * shuttle

print('[*] build Gabidulin code with evaluation_points=pegs')
C = codes.GabidulinCode(Fqm, N, K, sub_field=Fq, evaluation_points=pegs)
D = C.decoder()
print('[*] decoder:', D)

print('[*] decode')
codeword = D.decode_to_code(y)

print('[*] error rank:', (vector(Fqm, y) - vector(Fqm, codeword)).column().rank())  # for sanity if helpers exist

print('[*] solve secret_prime * loom = codeword')
secret_prime = loom.solve_left(vector(Fqm, codeword))
secret = secret_prime * knot.inverse()

print('[*] secret recovered, length =', len(secret))

def pack_elem(e):
    cs = list(e.polynomial())
    cs = [int(c) for c in cs] + [0] * (M - len(cs))
    val = 0
    for i, c in enumerate(cs):
        val |= c << i
    return val

secret_bytes = b''.join(int(pack_elem(e)).to_bytes((M+7)//8, 'big') for e in secret)
print('SECRET_BYTES:', secret_bytes.hex())

iv   = data['vault']['iv']
body = data['vault']['body']
tag  = data['vault']['tag']
print('VAULT_IV:', iv)
print('VAULT_BODY:', body)
print('VAULT_TAG:', tag)
