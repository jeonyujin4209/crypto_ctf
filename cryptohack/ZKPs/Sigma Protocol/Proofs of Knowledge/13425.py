import random
from utils import listener


FLAG = "crypto{????????????????????????}"

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2


# w,y for the relation `g^w = y mod P` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,P)
w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5

assert (y%p) >= 1
assert pow(y, q, p) == 1

class Challenge:
    def __init__(self):
        self.before_input = "Prove to me that you know an w such that g^w = y mod p. Send me a = g^r mod p for some random r in range(q)\n"
        self.state = "CHALLENGE"

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            # Prover sends a randomly sampled `A` value from Z_p* to verifier
            self.a = msg["a"]
            if (self.a%p) < 1 or pow(self.a, q, p) != 1:
                self.exit = True
                return {"error": "Invalid value"}

            # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
            self.e = random.randint(0,2**511)
            self.state = "PROVE"
            return {"e": self.e, "message": "send me z = r + e*w mod q"}
        elif self.state == "PROVE":
            # Prover sends z = r + e*w mod q to the Verifier
            z = msg["z"]

            self.exit = True

            # Verifier checks g^z = A*h^e mod p
            if pow(g,z,p) == (self.a*pow(y,self.e,p)) % p:
                return {"flag": FLAG, "message": "You convinced me you know an `w` such that g^w = y mod p!"}
            else:
                return {"error": "something went wrong :("}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13425)
