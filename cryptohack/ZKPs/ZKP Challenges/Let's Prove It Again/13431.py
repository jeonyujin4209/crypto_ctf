#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import hashlib
import random
import os
import string
from utils import listener

def add_random_nonprintable(byte_str):
    index = random.randint(0, len(byte_str))
    non_printable_byte = random.randint(0, 255)
    while chr(non_printable_byte) in string.printable:
        non_printable_byte = random.randint(0, 255)
    return byte_str[:index] + bytes([non_printable_byte]) + byte_str[index:]

def xor(a, b):
     assert len(a) == len(b)
     return bytes(x ^ y for x, y in zip(a, b))

def xor_nonce(byte_str, nonce):
    start = byte_str[:7]
    end = byte_str[-1:]
    middle = byte_str[7:-1]
    return start + xor(middle, nonce) + bytes(end)


FLAG = b"crypto{??????????????????????????????}"
BITS = 2 << 9
g = 2
max_turns = 4
assert len(FLAG) == 38

class Challenge:
    def __init__(self):
        global FLAG
        self.nonce = os.urandom(31)
        self.refresh()
        self.before_input = f"This server is made to share proofs...\nThat is the nonce for this instance: {self.nonce.hex()}\n"
        self.your_turn = 1
        self.v = self.R.getrandbits(BITS >> 1)
        self.turn = 0
        self.FLAG = bytes_to_long(
            xor_nonce(add_random_nonprintable(FLAG), self.nonce)
        )

    def getPrime(self, N):
        while True:
            number = self.R.getrandbits(N) | 1
            if isPrime(number, randfunc=lambda x: long_to_bytes(self.R.getrandbits(x))):
                break
        return number

    def refresh(self, seed=None):
        self.seed = os.urandom(8) if seed == None else seed
        self.R = random.Random(self.nonce + self.seed)

    def fiatShamir(self):
        p = self.getPrime(BITS)
        y = pow(g, self.FLAG, p)
        self.refresh()
        t = pow(g, self.v, p)
        c = bytes_to_long(
            hashlib.sha3_256(
                long_to_bytes(t ^ y ^ g ^ self.R.randint(2, BITS))
            ).digest()
        )
        r = (self.v - c * self.FLAG) % (p - 1)
        assert t == (pow(g, r, p) * pow(y, c, p)) % p  # the proof
        return (t, r), (g, y)

    def challenge(self, your_input):
        if self.turn >= max_turns:
            return {"error": "You can leave this instance, we've enough spoke"}

        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "refresh" and self.your_turn < 2:
            return {
                "error": "It's the server's turn! It's a conversation between you and the server, not a monologue :p"
            }

        elif your_input["option"] == "get_proof":
            (t, r), (g, y) = self.fiatShamir()
            self.your_turn += 1
            self.turn += 1
            return {"t": t, "r": r, "g": g, "y": y}

        elif your_input["option"] == "refresh" and self.your_turn >= 2:
            if not "seed" in your_input:
                return {"error": "You need to send a seed"}
            try:
                seed = bytes.fromhex(your_input["seed"])
            except ValueError:
                return {"error": "seed must be an hexadecimal value"}
            self.your_turn = 0
            self.refresh(seed)
            return {"msg": "seed refreshed succesfully!"}
        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13431)
