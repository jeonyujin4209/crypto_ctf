"""
GGH-like / NTRU-like lattice attack.

Encryption: e = r*h + m (mod q)
Where h = g * f^-1 (mod q), f and g are small (~ sqrt(q/2))

We know q, h, e. We need to find m.
We have: e = r*h + m (mod q)
=> f*e = f*r*h + f*m (mod q)
=> f*e = r*g + f*m (mod q)  (since f*h = g mod q)

Since f, g, r, m are all small (~sqrt(q)), f*m and r*g are small relative to q.
So f*e mod q = r*g + f*m (holds over integers, no wraparound).

The lattice approach: consider the lattice spanned by rows of:
| q  0 |
| h  1 |

A short vector in this lattice is (g, -f) because:
  -f * h + 1*g = g - f*h = g - g (mod q) ... but we need integer relation.
  Actually: (g, f) lies close to a lattice point.

Better: The lattice L = {(x,y) : x = y*h (mod q)}
Basis: v1 = (q, 0), v2 = (h, 1)

Gaussian reduction finds short vectors. One short vector will be (g, f) or similar.
Then: a = f*e mod q, m = a * f^-1 mod g = a/f mod g.
"""
from sympy import mod_inverse

def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def gaussian_reduction(v1, v2):
    while True:
        if dot(v2, v2) < dot(v1, v1):
            v1, v2 = v2, v1
        m = round(dot(v1, v2) / dot(v1, v1))
        if m == 0:
            return v1, v2
        v2 = [v2[i] - m * v1[i] for i in range(len(v1))]

q = 7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257
h = 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800
e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

# Lattice basis
v1 = [q, 0]
v2 = [h, 1]

# Gaussian reduction to find short vectors
u1, u2 = gaussian_reduction(v1, v2)

# One of u1, u2 should give us (g, f) or (-g, -f)
# Try both
for sv in [u1, u2]:
    f_candidate = abs(sv[1])
    g_candidate = abs(sv[0])
    if f_candidate == 0:
        continue
    try:
        # Decrypt: a = f*e mod q, then m = a * f^-1 mod g
        a = (f_candidate * e) % q
        f_inv_g = mod_inverse(f_candidate, g_candidate)
        m = (a * f_inv_g) % g_candidate
        # Try to decode as bytes
        flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        if b'crypto' in flag:
            print(flag.decode())
            break
    except:
        pass
