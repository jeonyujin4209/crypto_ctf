"""
Micro Transmissions — Pohlig-Hellman on smooth curve order.
Prints shared_x so Python can decrypt separately.
"""
p = 99061670249353652702595159229088680425828208953931838069069584252923270946291
E = EllipticCurve(GF(p), [1, 4])
G = E(43190960452218023575787899214023014938926631792651638044680168600989609069200,
      20971936269255296908588589778128791635639992476076894152303569022736123671173)
A = E.lift_x(87360200456784002948566700858113190957688355783112995047798140117594305287669)
B = E.lift_x(6082896373499126624029343293750138460137531774473450341235217699497602895121)

order = G.order()
print(f"[*] G.order() factored: {factor(order)}", flush=True)

max_n = 2^64 - 1
results, moduli, mul = [], [], 1
for prime, exp in factor(order):
    pe = prime^exp
    e = order // pe
    G_sub = G * e
    A_sub = A * e
    d = discrete_log(A_sub, G_sub, ord=pe, operation='+')
    print(f"  l={prime}^{exp}: dlog={d}", flush=True)
    results.append(d)
    moduli.append(pe)
    mul *= pe
    if mul > max_n:
        break

n_A = crt(results, moduli)
print(f"[+] n_A = {n_A}", flush=True)

# Verify
if n_A * G == A:
    print("[+] Verified: n_A * G == A", flush=True)
else:
    print("[!] Verify failed", flush=True)

# Compute shared x for both lifts
for B_try in [B, -B]:
    sx = int((n_A * B_try)[0])
    print(f"SHARED_X={sx}", flush=True)
