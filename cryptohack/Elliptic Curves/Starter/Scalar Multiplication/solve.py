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
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(n, P):
    R = None
    Q = P
    while n > 0:
        if n & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        n >>= 1
    return R

P = (2339, 2213)
Q = scalar_mult(7863, P)
print(Q)
