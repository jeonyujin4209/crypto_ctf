"""Micro Transmissions — Pohlig-Hellman on smooth curve order.

Why BSGS (my earlier attempt) was the wrong tool:
The private key is 64 bits, so bounded BSGS needs 2^32 ≈ 4e9 ops — minutes
to hours. But the curve order factors into small primes; Sage's
`discrete_log` auto-detects and uses Pohlig-Hellman, solving in seconds.
"""
from hashlib import sha1

p  = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a  = 1
b  = 4
ax = 87360200456784002948566700858113190957688355783112995047798140117594305287669
bx = 6082896373499126624029343293750138460137531774473450341235217699497602895121
iv = bytes.fromhex("ceb34a8c174d77136455971f08641cc5")
ct = bytes.fromhex("b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453")

E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]

order = E.order()
print(f"[*] curve order = {order}")
print(f"[*] factorization: {factor(order)}")
print(f"[*] E.gens() count: {len(E.gens())}")
print(f"[*] G.order() = {G.order()}")
print(f"[*] G.order() == curve order? {G.order() == order}")

B = E.lift_x(GF(p)(bx))
A = E.lift_x(GF(p)(ax))
print(f"[*] A.order() = {A.order()}")
print(f"[*] A.order() divides N: {order % A.order() == 0}")
print(f"[*] A.order() == N? {A.order() == order}")

# Let Sage do the full PH itself. It's smart enough to handle smooth orders.
print(f"[*] Calling Sage's discrete_log(A, G, ord=order, operation='+') ...")
import time
t0 = time.time()

# Try both lifts
for A_try in [A, -A]:
    try:
        n_a = int(discrete_log(A_try, G, ord=G.order(), operation='+'))
    except Exception as ex:
        print(f"  failed: {ex}")
        continue
    dt = time.time() - t0
    print(f"[+] n_a = {n_a}  ({dt:.1f}s, bits={n_a.bit_length()})")
    # Reduce modulo 2^64 in case discrete_log gave a larger value
    for n_cand in [n_a, n_a % (2^64)]:
        if n_cand * G == A:
            shared = int((n_cand * B).xy()[0])
            print(f"[+] shared x = {shared}")
            print(f"[+] SHA1 key hex = {sha1(str(shared).encode('ascii')).hexdigest()}")
            exit()
    print(f"[!] Even after mod 2^64, no match")
