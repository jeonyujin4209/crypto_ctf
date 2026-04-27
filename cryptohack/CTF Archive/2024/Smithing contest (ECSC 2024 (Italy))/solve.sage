#!/usr/bin/env sage
"""
Smithing contest (ECSC 2024) — IBS verification protocol forgery.

Vulnerability:
    The pairing-based interactive identity-based signature (IBS) verification
    in `smithing.sage` lets the prover (signer) supply (R, S, t, r) such that
    the verifier's two equations hold for ANY x, y chosen by the verifier,
    using only PUBLIC data (no admin secret needed).

    Setting R = Q (= P_G1*s in G1) and S = Qid_admin + H(m) * Qid_user, the
    verification reduces to:
        Eq0:  e(Q, Qid_user)^(x*H(m))  =  r^(H(m)/y)
        Eq1:  r^(1/y) * t^x * e(P_G1, Qid_admin)^x  =  e(2Q, P_G2)^x

    Both are satisfied by:
        r = e(C, Qid_user)        -> r^(1/y) = e(Q, Qid_user)^x
        t = e(2Q, P_G2) / ( e(Q, Qid_user) * e(P_G1, Qid_admin) )

    Qid_admin = H0('admin') is publicly computable.
"""
from random import SystemRandom
from hashlib import sha256
from json import loads, dumps
import socket, sys, os, traceback

# ----------------- BN curve from challenge -----------------
class BN:
    def __init__(self):
        self.p      = 239019556058548081539763731767358519973
        self.Fp     = GF(self.p)
        self.b      = 11
        self.EFp    = EllipticCurve(self.Fp, [0, self.b])
        self.O_EFp  = self.EFp([0, 1, 0])
        self.G1     = self.EFp((1, 133660577740454676305948404600566797994))
        self.t      = self.EFp.trace_of_frobenius()
        self.n      = self.EFp.order()
        self.k      = 12
        self.bits   = ZZ(self.p).nbits()
        self.bytes  = ceil(self.bits/8)

        Fp2 = GF(self.p^2, name='a', modulus=[1,0,1] if False else None)
        # Use the same construction as challenge to ensure same a and same Fp2
        Fp2_R = GF(self.p)['x']
        # Sage's default GF(p^2) picks irreducible poly automatically; the
        # challenge uses Fp2.<a> = GF(p^2). Same default.
        Fp2.<a> = GF(self.p^2)
        self.Fp2 = Fp2
        self.eps = 50853858759521010453592688907791911225*a + 156893423039651253351316307339945502422
        self.EFp2   = EllipticCurve(self.Fp2, [0, self.b/self.eps])
        self.O_EFp2 = self.EFp2([0, 1, 0])
        self.G2     = self.EFp2((100774561144590475569157120930767342387*a + 218728496724280042701446122970647661523, 115367896606755692925113233629944781384*a + 211093354487559124632805793736258741445))
        self.h      = self.EFp2.order()//self.n

        Fp2u.<u>    = self.Fp2[]
        Fp12.<z>    = (u^6 - self.eps).root_field()
        self.Fp2u   = Fp2u
        self.Fp12   = Fp12
        self.z      = z
        self.EFp12  = EllipticCurve(self.Fp12, [0, self.b])

    def phi(self, P):
        Px, Py = P.xy()
        return self.EFp12(self.z^2 * Px, self.z^3 * Py)

    def e(self, P, Q):
        return self.EFp12(P).ate_pairing(self.phi(Q), self.n, self.k, self.t, self.p)

def H_msg(curve, x):
    return int.from_bytes(sha256(x).digest()[:curve.bytes], 'big') % curve.p

def H0(curve, uid):
    x0 = int.from_bytes(sha256(uid.encode()).digest(), 'big') % curve.p
    while 1:
        x0 += 1
        try:
            P = curve.h * curve.EFp2.lift_x(x0)
            if P != curve.O_EFp2 and curve.n * P == curve.O_EFp2:
                return P
        except Exception:
            continue

def intify(L): return list(map(int, L))
def strify(L): return list(map(str, L))


def main(host, port, uname='attacker'):
    print(f'[*] Connecting to {host}:{port}')
    curve = BN()
    print('[*] Local curve loaded')

    s = socket.create_connection((host, port), timeout=120)
    f = s.makefile('rwb', buffering=0)

    def recv_line():
        line = f.readline()
        return line.decode(errors='replace')

    def recv_until(token):
        buf = b''
        while token.encode() not in buf:
            ch = f.read(1)
            if not ch:
                break
            buf += ch
        return buf.decode(errors='replace')

    def send_line(s_text):
        print(f'[>] {s_text}')
        f.write((s_text + '\n').encode())

    # First: read banner / params
    banner = recv_line()
    print('[<]', banner.rstrip())
    params_line = recv_line()
    print('[<]', params_line.rstrip())
    params = loads(params_line)
    blank = recv_line()  # blank line
    print('[<]', blank.rstrip())

    # username prompt
    pre = recv_until('tell me your username:')
    print('[<]', pre.rstrip())
    send_line(uname)

    # private key dump
    line_pk1 = recv_line(); print('[<]', line_pk1.rstrip())
    line_pk2 = recv_line(); print('[<]', line_pk2.rstrip())
    line_pk3 = recv_line(); print('[<]', line_pk3.rstrip())

    # parse public params
    P_G1 = curve.EFp(params['P_G1'])
    Q    = curve.EFp(params['Q'])
    P_G2_xy = params['P_G2']  # strings
    P_G2 = curve.EFp2([curve.Fp2(P_G2_xy[0]), curve.Fp2(P_G2_xy[1])])

    print('[*] Parsed P_G1, Q, P_G2')

    # Compute Qid_admin and Qid_user (uname)
    Qid_admin = H0(curve, 'admin')
    Qid_user  = H0(curve, uname)
    print('[*] Computed Qid_admin, Qid_user')

    # Build the target message
    target = f'I, the eternal Admin, keeper of all secrets, hereby decree that you, {uname}, are worthy to glimpse my deepest and most ancient secret: the flag.'
    Hm = H_msg(curve, target.encode())

    # R = Q, S = Qid_admin + H(m) * Qid_user
    R = Q
    S = Qid_admin + Hm * Qid_user
    R_xy = intify(R.xy())
    S_xy = strify(S.xy())
    print('[*] R, S prepared')

    # signature prompt
    pre = recv_until('give me a signature to verify:')
    print('[<]', pre.rstrip())
    send_line(dumps([R_xy, S_xy]))

    pre = recv_until('what message corresponds to this signature?')
    print('[<]', pre.rstrip())
    send_line(target)

    pre = recv_until('who signed it?')
    print('[<]', pre.rstrip())
    send_line('admin')

    # Now receive C
    C_line = recv_line()
    print('[<]', C_line.rstrip())
    # Format: "C = [\"<x>\", \"<y>\"]" but the server uses dumps(admin.verify())
    # For verifier step 0, C is intify, so it's [int, int]
    # The line is: "C = [12345, 67890]"
    prefix = 'C = '
    idx = C_line.find(prefix)
    C_json = C_line[idx + len(prefix):].strip()
    C = loads(C_json)
    print('[*] Received C =', C)

    C_pt = curve.EFp(C)

    # Compute r = e(C, Qid_user), t = e(2Q, P_G2) / (e(Q, Qid_user) * e(P_G1, Qid_admin))
    print('[*] Computing pairings (this may take a while)...')
    r_val = curve.e(C_pt, Qid_user)
    print('    r computed')
    e_2Q_PG2 = curve.e(2*Q, P_G2)
    print('    e(2Q, P_G2) computed')
    e_Q_QidU = curve.e(Q, Qid_user)
    print('    e(Q, Qid_user) computed')
    e_PG1_QidA = curve.e(P_G1, Qid_admin)
    print('    e(P_G1, Qid_admin) computed')
    t_val = e_2Q_PG2 / (e_Q_QidU * e_PG1_QidA)
    print('[*] t, r computed')

    # Send t, r
    pre = recv_until('t, r?')
    print('[<]', pre.rstrip())
    send_line(dumps([str(t_val), str(r_val)]))

    # Read remaining
    while True:
        try:
            line = recv_line()
            if not line:
                break
            print('[<]', line.rstrip())
        except Exception as exc:
            print('[!]', exc)
            break

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 25469
    uname = sys.argv[3] if len(sys.argv) > 3 else 'attacker'
    main(host, port, uname)
