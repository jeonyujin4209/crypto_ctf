from py_ecc.optimized_bn128 import G1, G2, multiply, pairing, is_on_curve, b, FQ
from hashlib import sha256
import os
from utils import listener

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
FLAG = b"crypto{???????????????????????????????????????????????????}"

def poly(power, x):
    return (pow(x,power+7,p) - pow(x,3,p)) % p # (x**(power+7)-x**3) % p

def inverse(u, v):
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1

def hash_to_curve(h, G):
    return multiply(G,h)

class Challenge:
    def __init__(self):
        self.before_input = "Welcome! Have fun with this strange implementation...\n"
        self.x = int(os.urandom(192//8).hex(), 16)
        self.z = 17

    def BLS(self, hsh,  G):
        h = int(sha256(FLAG).hexdigest(),16)
        H = hash_to_curve(h, G2)
        print(G)
        if not is_on_curve(G, b):
            return False
        received_H = hash_to_curve(hsh, G2)
        xH = multiply(H, self.x)
        xG = multiply(G, self.x)
        xzH = multiply(xH, self.z)
        xzG = multiply(xG, self.z)
        l = pairing(xzH, G1)
        r = pairing(received_H, xzG)
        return l == r

    def set_internal_z(self, z):
        z = inverse(poly(z, self.x), p)
        if (self.x*z) % p == 1:
            raise Exception("Wtf?")
        self.z = z

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "set_internal_z":
            try:
                new_z = int(your_input["z"],16)
                if not 0 < new_z < p:
                    return {"error": "this is a mandatory: 0 < z < p"}
                self.set_internal_z(new_z)
            except Exception as e:
                return {"error": str(e)}
            return {"msg": "Internal z changed!"}

        elif your_input["option"] == "do_proof":
            try:
                G = your_input["G"].replace("(","").replace(")","").strip().split(",")
                G = (FQ(int(G[0])), FQ(int(G[1])), FQ(int(G[2])))
                hsh =  int(your_input["hsh"], 16)
                if self.BLS(hsh, G):
                    return {"msg":FLAG.decode()}
                else:
                    return {"msg": "you failed!"}
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                return {"error": str(e)}
        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13415)

