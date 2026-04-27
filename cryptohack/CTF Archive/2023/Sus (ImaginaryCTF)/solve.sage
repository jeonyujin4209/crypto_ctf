"""
Sus (ImaginaryCTF 2023) - Solver

Vulnerability:
  n = p * q * r, with q = sus(p, 3) = 1 + p + p^2 = (p^3 - 1) / (p - 1).
  The order of F_{p^3}* is p^3 - 1 = (p-1)*q. So q divides |F_{p^3}*|.
  Since n = p*q*r is divisible by q, raising any element of F_{p^3} to the
  power n gives an element whose order divides (p-1) -> the result lies in F_p
  (the constant subfield), not the full F_{p^3}.

Attack (Pollard p-1 in cubic extension, a.k.a. F_{p^k} Pollard):
  Work in the ring R = (Z/nZ)[x] / (f(x)) for a random monic cubic f.
  With overwhelming probability f is irreducible mod p, so R mod p is F_{p^3}.
  Pick a random g in R. Compute h = g^n in R.
    - Reducing mod p: h_p = g_p^n in F_{p^3}, but n ≡ 0 (mod q), and the
      F_p-part of F_{p^3}* has order p-1; so h_p is in F_p, meaning the x-
      and x^2-coefficients of h are ≡ 0 (mod p).
  Therefore p | gcd(coef_of_x(h), n) and p | gcd(coef_of_x^2(h), n).

  This is "Pollard p-1 / Williams p+1 in a higher-degree extension field"
  (credit: maple3142).

Once p is recovered: q = 1 + p + p^2, r = n / (p*q), and standard RSA decrypt.
"""
from sage.all import *
import os

n = 1125214074953003550338693571791155006090796212726975350140792193817691133917160305053542782925680862373280169090301712046464465620409850385467397784321453675396878680853302837289474127359729865584385059201707775238870232263306676727868754652536541637937452062469058451096996211856806586253080405693761350527787379604466148473842686716964601958192702845072731564672276539223958840687948377362736246683236421110649264777630992389514349446404208015326249112846962181797559349629761850980006919766121844428696162839329082145670839314341690501211334703611464066066160436143122967781441535203415038656670887399283874866947000313980542931425158634358276922283935422468847585940180566157146439137197351555650475378438394062212134921921469936079889107953354092227029819250669352732749370070996858744765757449980454966317942024199049138183043402199967786003097786359894608611331234652313102498596516590920508269648305903583314189707679
e = 65537
c = 27126515219921985451218320201366564737456358918573497792847882486241545924393718080635287342203823068993908455514036540227753141033250259348250042460824265354495259080135197893797181975792914836927018186710682244471711855070708553557141164725366015684184788037988219652565179002870519189669615988416860357430127767472945833762628172190228773085208896682176968903038031026206396635685564975604545616032008575709303331751883115339943537730056794403071865003610653521994963115230275035006559472462643936356750299150351321395319301955415098283861947785178475071537482868994223452727527403307442567556712365701010481560424826125138571692894677625407372483041209738234171713326474989489802947311918341152810838321622423351767716922856007838074781678539986694993211304216853828611394630793531337147512240710591162375077547224679647786450310708451590432452046103209161611561606066902404405369379357958777252744114825323084960942810

print(f"[*] n bits: {ZZ(n).nbits()}")

R = Zmod(n)["x"]
x = R.gen()

p = None
for trial in range(50):
    # Random monic cubic. With overwhelming prob irreducible mod p.
    a = ZZ.random_element(0, n)
    b = ZZ.random_element(0, n)
    cc = ZZ.random_element(0, n)
    f = x**3 + a*x**2 + b*x + cc
    Q = R.quotient(f)
    g = Q.random_element()
    h = g**n
    coefs = list(h.lift())
    # h.lift() returns a polynomial in R; coefs is list of length up to 3 in Z/nZ
    # x^1 and x^2 coefficients should be ≡ 0 mod p
    if len(coefs) >= 2:
        c1 = ZZ(coefs[1])
        d = gcd(c1, n)
        if 1 < d < n:
            print(f"[+] gcd hit on trial {trial}: {d}")
            # Could be p, or p*q etc. Check.
            p_cand = d
            # We expect p ~ 512 bits
            if ZZ(p_cand).nbits() == 512 and is_prime(p_cand):
                p = p_cand
                break
            # Otherwise try x^2 coef
    if len(coefs) >= 3:
        c2 = ZZ(coefs[2])
        d = gcd(c2, n)
        if 1 < d < n:
            print(f"[+] gcd hit (c2) on trial {trial}: {d}")
            p_cand = d
            if ZZ(p_cand).nbits() == 512 and is_prime(p_cand):
                p = p_cand
                break

if p is None:
    raise SystemExit("[-] failed to recover p")

q = 1 + p + p**2
assert is_prime(q)
assert n % (p * q) == 0
r = n // (p * q)
assert is_prime(r)

print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] r = {r}")

phi = (p - 1) * (q - 1) * (r - 1)
d = inverse_mod(e, phi)
m = power_mod(c, d, n)
flag = ZZ(m).to_bytes((ZZ(m).nbits() + 7) // 8, "big")
print(f"[+] flag = {flag}")
