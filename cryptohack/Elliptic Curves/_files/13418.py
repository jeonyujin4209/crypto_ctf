import os
from Crypto.Util.number import inverse
from utils import listener


FLAG = "crypto{???????????????????????????????}"
LIMIT = 1
TIMEOUT = 60

# Parameters
modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
a = -3
b = 2697448053935541741976221051345108825177671050689533270507
order = 4782850957738000717885060297297408935631027604045525430677


def dbl(P1):
    X1, Z1 = P1

    XX = X1**2 % modulus
    ZZ = Z1**2 % modulus
    A = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % modulus
    aZZ = a * ZZ % modulus
    X3 = ((XX - aZZ) ** 2 - 2 * b * A * ZZ) % modulus
    Z3 = (A * (XX + aZZ) + 4 * b * ZZ**2) % modulus

    return (X3, Z3)


def diffadd(P1, P2, x0):
    X1, Z1 = P1
    X2, Z2 = P2

    X1Z2 = X1 * Z2 % modulus
    X2Z1 = X2 * Z1 % modulus
    Z1Z2 = Z1 * Z2 % modulus
    T = (X1Z2 + X2Z1) * (X1 * X2 + a * Z1Z2) % modulus
    Z3 = (X1Z2 - X2Z1) ** 2 % modulus
    X3 = (2 * T + 4 * b * Z1Z2**2 - x0 * Z3) % modulus

    return (X3, Z3)


def swap(bit, P1, P2):
    if bit == 1:
        P1, P2 = P2, P1
    return P1, P2


def scalarmult(scalar, x0):
    R0 = (x0, 1)
    R1 = dbl(R0)
    n = scalar.bit_length()
    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0)
        R0 = dbl(R0)
        pbit = bit

    if bit:
        R0 = R1

    return R0[0] * inverse(R0[1], modulus) % modulus


class Challenge:
    def __init__(self):
        self.before_input = f"Welcome!\nYou can submit only {LIMIT} elliptic curve point (x coordinate only).\nYou have {TIMEOUT} seconds to submit the private key in decimal format.\n"
        self.timeout_secs = TIMEOUT
        self.privkey = privkey = int.from_bytes(os.urandom(24), "big")
        self.privkey = min(privkey % order, (order - privkey) % order)
        self.attempts_remaining = 1

    def challenge(self, your_input):
        if "option" not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input["option"] == "get_pubkey":
            if self.attempts_remaining == 0:
                return {
                    "error": "You cannot submit a point anymore. Now, please submit the private key."
                }

            x0 = int(your_input["x0"])
            pubkey = scalarmult(self.privkey, x0)
            self.attempts_remaining -= 1
            return {"pubkey": pubkey}

        elif your_input["option"] == "get_flag":
            guess = your_input["privkey"]
            if guess % order == self.privkey:
                return {
                    "message": "Congratulations, you found my private key.",
                    "flag": FLAG,
                }
            else:
                return {"error": "Sorry, this is not my private key."}
        else:
            return {"error": "You must send an option to this server"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13418)
