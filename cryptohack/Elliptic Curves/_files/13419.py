from os import urandom
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse
from hashlib import sha256

from utils import listener

FLAG = b"crypto{????????????????????????????????????}"

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")
Curve = namedtuple("Curve", "p a b G")
# The point at infinity (origin for the group law).
O = "Origin"

# NIST P-256
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = Point(
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
P_256 = Curve(p, a, b, G)


def point_inverse(P, C):
    if P == O:
        return P
    return Point(P.x, -P.y % C.p)


def point_addition(P, Q, C):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P, C):
        return O
    else:
        if P == Q:
            lam = (3 * P.x**2 + C.a) * inverse(2 * P.y, C.p)
            lam %= C.p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), C.p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % C.p
    Ry = (lam * (P.x - Rx) - P.y) % C.p
    R = Point(Rx, Ry)
    return R


def double_and_add(P, n, C):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q, C)
        Q = point_addition(Q, Q, C)
        n = n // 2
    return R


class Server:
    def __init__(self, curve):
        self.C = curve
        self.s = int.from_bytes(urandom(32), byteorder="little")
        self.P = double_and_add(self.C.G, self.s, self.C)

    def ecdh_kex(self, Q, ciphersuite):
        if ciphersuite != "ECDHE_P256_WITH_AES_128":
            raise Exception("Ciphersuite not supported.")
        shared_point = double_and_add(Q, self.s, self.C)
        self.shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

    def send_msg(self, pt):
        iv = urandom(16)
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(pt, 16))


class Challenge:
    def __init__(self):
        self.S = Server(P_256)
        client_secret_key = int.from_bytes(urandom(32), byteorder="little")
        client_public_key = double_and_add(self.S.C.G, client_secret_key, self.S.C)
        self.S.ecdh_kex(client_public_key, "ECDHE_P256_WITH_AES_128")
        self.before_input = (
            f"Eavesdropping...\n"
            f"client initiating key agreement :\n"
            f"client->server : {client_public_key}\n"
            f"server->client : {self.S.P}\n"
            f"server->client : {self.S.send_msg(FLAG).hex()}\n"
        )

    def challenge(self, your_input):
        if your_input["option"] == "start_key_exchange":
            if "Qx" not in your_input or "Qy" not in your_input:
                return {"msg": "No public key provided."}
            if "ciphersuite" not in your_input:
                return {"msg": "No ciphersuite provided"}
            try:
                Q = Point(int(your_input["Qx"], 16), int(your_input["Qy"], 16))
                self.S.ecdh_kex(Q, your_input["ciphersuite"])
            except:
                return {"msg": "An error occured, please provide valid inputs."}
            return {"msg": "Key exchange proceeded successfully."}

        if your_input["option"] == "get_test_message":
            return {"msg": self.S.send_msg(b"SERVER_TEST_MESSAGE").hex()}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13419)
