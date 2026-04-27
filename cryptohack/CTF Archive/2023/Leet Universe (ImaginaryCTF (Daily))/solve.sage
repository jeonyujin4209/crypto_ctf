# Leet Universe (ImaginaryCTF Round 40, 2023/11)
#
# Vulnerability: Server computes g = gcd(x^13+37, (x+42)^13+42) for input x,
# then prints flag[:g]. The two polynomials are coprime over Q, so gcd | Res.
# The resultant R is a 912-bit integer with no small factors — factoring is
# infeasible. But we don't need to factor R!
#
# Trick: Run polynomial Euclidean over Zmod(R)[x]. In Sage, polynomial mod
# in a quotient ring of a non-field may stall on a low-degree polynomial
# whose leading coefficient is non-invertible mod R. The remaining linear
# polynomial ff = a*x + b (mod R) has the simultaneous root x = -b/a (mod R).
# This x is a common root of f, g modulo R, so R | gcd(f(x), g(x)) ⇒ gcd >= R.

x = polygen(ZZ)
f = x**13 + 37
g = (x + 42) ** 13 + 42
v = abs(ZZ(f.resultant(g)))
print("v bits:", v.nbits())

R = Zmod(v)
ff = f.change_ring(R)
gg = g.change_ring(R)
while gg:
    ff, gg = gg, ff % gg

print("ff:", ff)
print("ff degree:", ff.degree())

x_int = ZZ(-ff[0] / ff[1])
print("x =", x_int)

from math import gcd
fv = x_int**13 + 37
gv = (x_int + 42) ** 13 + 42
g_val = gcd(int(fv), int(gv))
print("gcd:", g_val)
print("gcd bits:", ZZ(g_val).nbits())

# Connect to server with this x
import socket

def solve_remote(host, port):
    s = socket.create_connection((host, port), timeout=20)
    f = s.makefile('rwb', 0)
    prompt = f.read(4)  # "x = "
    print("prompt:", prompt)
    f.write((str(x_int) + "\n").encode())
    out = f.read()
    print("server output:", out)
    s.close()

import sys
if len(sys.argv) > 1 and sys.argv[1] == "remote":
    solve_remote("archive.cryptohack.org", 3721)
