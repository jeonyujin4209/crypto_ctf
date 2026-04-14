---
name: castryck-decru-sidh-attack
description: SIDH/SIKE에서 phiA_P3/phiA_Q3(Alice 3-torsion images) 주어지면 Castryck-Decru로 Alice 비밀 isogeny 복구
type: skill
---

# Castryck-Decru SIDH Attack

## When to use
- SIDH/SIKE challenge where Alice's or Bob's public key is given
- Problem provides `phiA_P3`, `phiA_Q3` (images of 3-torsion basis under Alice's isogeny)
- Goal: recover the other party's private key

## Key insight
The CD attack recovers Bob's private scalar `sB` from Alice's public key.
After recovery: `K = phiA_P3 + sB * phiA_Q3`, then a 3^eb-isogeny gives the shared curve.

## Attack overview
1. **Gluing step**: Construct (2,2)-isogeny from E0 × EB to a product of two curves
2. **Push-forward**: Track images of Alice's torsion points through the (2,2)-isogeny chain
3. **Retrieve sB**: Solve for the scalar bit-by-bit (like a meet-in-the-middle DL)

## Critical: two_i endomorphism for j=1728 curve

The `generate_distortion_map()` helper from SIDH repos assumes curve `y²=x³+6x²+x`,
not the standard j=1728 curve `y²=x³+x`. **Don't use it for the base curve E0: y²=x³+x.**

### Correct construction for E0: y²=x³+x (j=1728)

```sage
# phi: 2-isogeny at x=0 kernel point
phi = E0.isogeny(E0(0, 0))
E1 = phi.codomain()  # E1 has j=1728 too (isomorphic)

# Find automorphism iota on E1 with iota^2 = -id
# For j=1728, automorphism group has order 4: {±1, ±iota} where iota^2=-1
for aut in E1.automorphisms():
    M = aut.rational_maps()
    # iota satisfies: aut(aut(P)) == -P for all P
    # Equivalently, the matrix [a,b;c,d] satisfies M^2 = -I
    test_P = E1.random_point()
    if aut(aut(test_P)) == -test_P:
        iota = aut
        break

# two_i = phi.dual ∘ iota ∘ phi  (endomorphism of degree 4 acting as [2i])
two_i = phi.post_compose(iota).post_compose(phi.dual())
```

### Alternative: direct formula for y²=x³+x

The endomorphism [i]: (x,y) → (-x, i*y) where i²=-1 in GF(p²).
`[2i] = [2] ∘ [i]`

```sage
# If F.<ii> = GF(p^2, modulus=[1,0,1]):
# [i]: (x,y) -> (-x, ii*y)
# [2i] = composition
```

## Recovering the shared secret

```sage
# After CD attack recovers sB:
sB = <recovered_value>

K = phiA_P3 + sB * phiA_Q3
E_shared = EA.isogeny(K, algorithm="factored").codomain()
shared_secret = E_shared.j_invariant()

key = SHA256.new(data=str(shared_secret).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
```

## SIDH parameters

```
p = f * 2^ea * 3^eb - 1
Alice's secret: sA in [0, 2^ea)  → kernel K_A = P2 + sA*Q2 (2-torsion)
Bob's secret:   sB in [0, 3^eb)  → kernel K_B = P3 + sB*Q3 (3-torsion)
```

## CryptoHack challenge setup (Breaking SIDH)

```
f=45, ea=117, eb=73
p = 45 * 2^117 * 3^73 - 1
EA = phiA_P3.curve()  (Alice's public curve)
Given: phiA_P3, phiA_Q3 (images of 3-torsion basis under Alice's isogeny phi_A)
```

## Reference
- Castryck, Decru (2022): "An efficient key recovery attack on SIDH"
- `cryptohack/Isogenies/Road to SIDH/Breaking SIDH/solve.sage`

## Challenges
- CryptoHack: Breaking SIDH (250pts) — `crypto{welcome_to_the_future_of_isogenies}`
