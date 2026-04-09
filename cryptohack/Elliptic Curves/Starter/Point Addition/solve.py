p = 9739
a = 497
b = 1768

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None  # point at infinity
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

P = (493, 5564)
Q = (1539, 4742)
R = (4403, 5202)

S = point_add(P, P)
S = point_add(S, Q)
S = point_add(S, R)
print(S)
