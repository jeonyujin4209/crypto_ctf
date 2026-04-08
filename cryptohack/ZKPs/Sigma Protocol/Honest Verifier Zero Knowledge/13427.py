import os
import random
from Crypto.Util.number import bytes_to_long
from utils import listener

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

FLAG = b"crypto{?????????????????????????????}"

padded_flag = FLAG + os.urandom(q.bit_length() // 8 - len(FLAG) - 1)
flag = bytes_to_long(padded_flag)

y = pow(g,flag,p)

assert (y%p) >= 1
assert pow(y, q, p) == 1


class Challenge:
    def __init__(self):
        self.before_input = f"Send me a transcript for my given `e` proving that you know the flag `w` such that y = g^w mod p\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            self.e = random.randint(0,2**511)
            
            self.state = "PROVE"
            return {"e": self.e, "y": y, "message": "send me your transcript"}

        elif self.state == "PROVE":
            self.a = msg["a"]
            self.z = msg["z"]

            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,self.z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG.decode(), "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13427)
