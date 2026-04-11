import json
proof.all(False)

p = 37 * 2^64 * lcm(range(1, 256)) - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [0, 1])

with open("output.txt") as f:
    ct = json.load(f)

item = ct[0]
x = F(item["P"]["x"][0]) + F(item["P"]["x"][1]) * i
y = F(item["P"]["y"][0]) + F(item["P"]["y"][1]) * i
# Test on original E0 (y^2 = x^3 + 1)
print(f"y^2 == x^3+1 ? {y^2 == x^3 + 1}")
# Phi goes to some NEW curve, not E0! The image phi(P), phi(Q) is on the codomain.
# So we need to find the codomain curve. For Weil pairing we don't need the curve
# equation if we just use the image points — but the EllipticCurve constructor
# requires the points to be on a known curve.
# Alternative: compute Weil pairing WITHOUT constructing points on E.
# E.weil_pairing(P, Q, n) requires P, Q on E.
# But we could construct E_new satisfying the point equation.
# Actually since each ciphertext entry has a DIFFERENT codomain, we'd need to
# compute the short Weierstrass for each. Reconstruct from two points:
#   y1^2 = x1^3 + a*x1 + b1
#   y2^2 = x2^3 + a*x2 + b2
# 2 unknowns (a, b), 2 equations → solve.
x1, y1 = x, y
x2 = F(item["Q"]["x"][0]) + F(item["Q"]["x"][1]) * i
y2 = F(item["Q"]["y"][0]) + F(item["Q"]["y"][1]) * i
# y1^2 - y2^2 = x1^3 - x2^3 + a*(x1 - x2)
# a = (y1^2 - y2^2 - x1^3 + x2^3) / (x1 - x2)
a_coef = (y1^2 - y2^2 - x1^3 + x2^3) / (x1 - x2)
b_coef = y1^2 - x1^3 - a_coef * x1
print(f"codomain a = {a_coef}")
print(f"codomain b = {b_coef}")
E_new = EllipticCurve(F, [a_coef, b_coef])
P_new = E_new(x1, y1)
Q_new = E_new(x2, y2)
print(f"constructed P_new = {P_new}")
print(f"E_new order: {E_new.order()}")
