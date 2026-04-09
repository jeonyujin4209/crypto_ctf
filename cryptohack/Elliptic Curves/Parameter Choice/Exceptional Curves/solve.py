from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

p = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77
a = 0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42
b = 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece

Gx = 3034712809375537908102988750113382444008758539448972750581525810900634243392172703684905257490982543775233630011707375189041302436945106395617312498769005
Gy = 4986645098582616415690074082237817624424333339074969364527548107042876175480894132576399611027847402879885574130125050842710052291870268101817275410204850
Ax = 4748198372895404866752111766626421927481971519483471383813044005699388317650395315193922226704604937454742608233124831870493636003725200307683939875286865
Ay = 2421873309002279841021791369884483308051497215798017509805302041102468310636822060707350789776065212606890489706597369526562336256272258544226688832663757
Bx = 0x7f0489e4efe6905f039476db54f9b6eac654c780342169155344abc5ac90167adc6b8dabacec643cbe420abffe9760cbc3e8a2b508d24779461c19b20e242a38
By = 0xdd04134e747354e5b9618d8cb3f60e03a74a709d4956641b234daa8a65d43df34e18d00a59c070801178d198e8905ef670118c15b0906d3a00a662d3a2736bf

p2 = p * p

def hensel_lift(px, py):
    f = px**3 + a*px + b - py**2
    assert f % p == 0
    t = (f // p) * pow(2*py, -1, p) % p
    return (px, (py + t*p) % p2)

# Projective coordinates [X:Y:Z] for E: Y^2*Z = X^3 + a*X*Z^2 + b*Z^3
def proj_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    X1, Y1, Z1 = P1
    X2, Y2, Z2 = P2

    U1 = (Y2 * Z1) % p2
    U2 = (Y1 * Z2) % p2
    V1 = (X2 * Z1) % p2
    V2 = (X1 * Z2) % p2

    if (V1 - V2) % p2 == 0:
        if (U1 - U2) % p2 != 0:
            return None  # Inverse points
        # Doubling
        return proj_dbl(P1)

    U = (U1 - U2) % p2
    V = (V1 - V2) % p2
    Vsq = V * V % p2
    Vcb = Vsq * V % p2
    W = Z1 * Z2 % p2
    A_ = (U * U * W - Vcb - 2 * Vsq * V2) % p2

    X3 = V * A_ % p2
    Y3 = (U * (Vsq * V2 - A_) - Vcb * U2) % p2
    Z3 = Vcb * W % p2

    return (X3 % p2, Y3 % p2, Z3 % p2)

def proj_dbl(P1):
    if P1 is None: return None
    X, Y, Z = P1
    if Y % p2 == 0: return None

    W_ = (a * Z * Z + 3 * X * X) % p2
    S_ = Y * Z % p2
    B_ = X * Y * S_ % p2
    H_ = (W_ * W_ - 8 * B_) % p2

    X3 = 2 * H_ * S_ % p2
    Y3 = (W_ * (4 * B_ - H_) - 8 * Y * Y * S_ * S_) % p2
    Z3 = 8 * S_ * S_ * S_ % p2

    return (X3 % p2, Y3 % p2, Z3 % p2)

def proj_mul(P, n):
    if n == 0: return None
    R = None
    Q = P
    while n > 0:
        if n & 1:
            R = proj_add(R, Q)
        Q = proj_dbl(Q)
        n >>= 1
    return R

def padic_log(pt):
    """
    Compute the p-adic elliptic logarithm of a point in E1(Z/p^2Z).
    The point is given in projective coords [X:Y:Z].
    For a point in E1, its reduction mod p is [0:1:0] (the identity).
    The formal group parameter is t = X/Y (note: for the formal group,
    we use t = -x/y = -(X/Z)/(Y/Z) = -X/Y... but in projective coords
    at the identity [0:1:0], we have t = X/Y or Z/Y as the uniformizer).

    Actually, for the formal group of E at the identity [0:1:0]:
    - Local parameter: t = -x/y = -X/Y (in affine x=X/Z, y=Y/Z)
    - But near infinity, t = X/Y is a local parameter too

    The p-adic log is: t_P = -X_P/Y_P mod p^2 (in projective)
    Since the point is in E1, t_P should have v_p(t_P) >= 1.
    We return t_P / p mod p (so a value in Z/pZ that represents the log).
    """
    X, Y, Z = pt
    # Compute -X * Y^(-1) mod p^2
    # Y should be nonzero mod p (since the point reduces to [0:1:0])
    t = (-X * pow(Y, -1, p2)) % p2
    # t should be divisible by p
    assert t % p == 0, f"t mod p = {t % p}, expected 0"
    return (t // p) % p

# Run Smart's attack
Pl = hensel_lift(Gx, Gy)
Ql = hensel_lift(Ax, Ay)

Pp = (Pl[0], Pl[1], 1)
Qp = (Ql[0], Ql[1], 1)

print("Computing p * P_lift...")
pP = proj_mul(Pp, p)
print("Computing p * Q_lift...")
pQ = proj_mul(Qp, p)

print(f"pP is None: {pP is None}")
print(f"pQ is None: {pQ is None}")

if pP is not None and pQ is not None:
    # Check that pP reduces to identity mod p: X ≡ 0, Z ≡ 0 mod p
    XP, YP, ZP = pP
    XQ, YQ, ZQ = pQ
    print(f"pP: X mod p = {XP % p}, Y mod p = {YP % p}, Z mod p = {ZP % p}")
    print(f"pQ: X mod p = {XQ % p}, Y mod p = {YQ % p}, Z mod p = {ZQ % p}")

    # For the identity [0:1:0], we need X ≡ 0 and Z ≡ 0 mod p, Y ≢ 0 mod p
    # But in our projective representation, the point might not be normalized.
    # Check if the point is "at infinity mod p":
    # In projective coords, [X:Y:Z] ~ [0:1:0] mod p iff X ≡ 0, Z ≡ 0 mod p (and Y ≢ 0)
    # OR [X:Y:Z] ~ [0:Y:0] mod p for some Y.

    # The formal group log: for a point near [0:1:0], the local parameter is
    # u = X/Y (or equivalently z = Z/Y). Then x = u/z, y = 1/z in the formal group.
    # The formal logarithm of the formal group is:
    # log_F(t) = t + c2*t^2 + c3*t^3 + ...
    # To first order, log_F(t) ≈ t.
    # Since we're working mod p^2 and t has valuation ≥ 1, t^2 has valuation ≥ 2,
    # so log_F(t) ≡ t mod p^2. Perfect.

    # t = -x/y for affine point (x,y). In projective: t = -X/Y * (Z/Z) but wait...
    # If affine x = X/Z, y = Y/Z, then -x/y = -(X/Z)/(Y/Z) = -X/Y.
    # So t = -X/Y.

    # But we need to check: for pP = [XP:YP:ZP], is X/Y well-defined mod p^2?
    # Y must be invertible mod p^2, which requires Y ≢ 0 mod p.

    if YP % p != 0:
        logP = padic_log(pP)
        logQ = padic_log(pQ)
        print(f"log(pP)/p = {logP}")
        print(f"log(pQ)/p = {logQ}")
        n_a = logQ * pow(logP, -1, p) % p
    else:
        print("Y is 0 mod p, need different approach")
        # Maybe Z/Y is the right parameter, or we need to normalize
        # Try: the point [X:Y:Z] can be renormalized. If Z ≡ 0 mod p and
        # X ≡ 0 mod p, then we can divide all by p: [X/p : Y/p : Z/p]
        # but that changes the projective point.
        # Actually we can just use Z/Y as the parameter instead.
        # For the formal group at [0:1:0], we can use w = Z/Y as parameter.
        # Then the log is still approximately w to first order.

        # Or: use u = X/Z as parameter if Z ≢ 0 mod p
        if ZP % p != 0:
            tP = (-XP * pow(ZP, -1, p2)) % p2
            tQ = (-XQ * pow(ZQ, -1, p2)) % p2
            # Hmm, but X/Z is the x-coordinate, not the formal group parameter.
            pass

        # Let me try a completely different approach.
        # Instead of -X/Y, try X*Z / Y^2 or similar.
        # Actually, let's just try all reasonable combinations.
        print("Trying alternative log formulas...")

        # Method 2: use affine coordinates. If pP is not at infinity (in Z/p^2Z),
        # it has finite affine coordinates. Convert and compute -x/y.
        if ZP % p2 != 0:
            try:
                invZ = pow(ZP, -1, p2)
                xP = XP * invZ % p2
                yP = YP * invZ % p2
                tP = (-xP * pow(yP, -1, p2)) % p2

                invZ = pow(ZQ, -1, p2)
                xQ = XQ * invZ % p2
                yQ = YQ * invZ % p2
                tQ = (-xQ * pow(yQ, -1, p2)) % p2

                print(f"tP = {tP}, tP mod p = {tP % p}")
                print(f"tQ = {tQ}, tQ mod p = {tQ % p}")

                if tP % p == 0 and tQ % p == 0:
                    logP = (tP // p) % p
                    logQ = (tQ // p) % p
                    n_a = logQ * pow(logP, -1, p) % p
                else:
                    n_a = tQ * pow(tP, -1, p) % p
            except ValueError:
                print("Inversion failed in affine conversion")
                n_a = None
        else:
            n_a = None

elif pP is None and pQ is not None:
    # Shouldn't happen for anomalous curve
    print("pP = O but pQ != O - unexpected")
    n_a = None
elif pP is not None and pQ is None:
    n_a = 0
else:
    # Both None - degenerate
    print("Both pP and pQ are identity")
    n_a = None

if n_a is not None:
    print(f"\nn_a = {n_a}")

    # Verify
    def ec_add(P1, P2):
        if P1 is None: return P2
        if P2 is None: return P1
        x1, y1 = P1; x2, y2 = P2
        if (x1 - x2) % p == 0:
            if (y1 + y2) % p == 0: return None
            lam = (3*x1*x1 + a) * pow(2*y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam*lam - x1 - x2) % p
        y3 = (lam*(x1 - x3) - y1) % p
        return (x3, y3)

    def ec_mul(P, n):
        if n == 0: return None
        R = None; Q = P
        while n > 0:
            if n & 1: R = ec_add(R, Q)
            Q = ec_add(Q, Q)
            n >>= 1
        return R

    check = ec_mul((Gx, Gy), n_a)
    ok = (check == (Ax, Ay))
    print(f"Verify: {ok}")

    if not ok:
        # Try p - n_a
        n_a2 = p - n_a
        check2 = ec_mul((Gx, Gy), n_a2)
        ok2 = (check2 == (Ax, Ay))
        print(f"Verify p-n_a: {ok2}")
        if ok2:
            n_a = n_a2
            ok = True

    if ok:
        S = ec_mul((Bx, By), n_a)
        shared = S[0]
        sha1 = hashlib.sha1()
        sha1.update(str(shared).encode('ascii'))
        key = sha1.digest()[:16]
        iv = bytes.fromhex('719700b2470525781cc844db1febd994')
        ct = bytes.fromhex('335470f413c225b705db2e930b9d460d3947b3836059fb890b044e46cbb343f0')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        flag = unpad(cipher.decrypt(ct), 16)
        print(f"Flag: {flag.decode()}")
    else:
        print("Both n_a and p-n_a failed verification")
