"""
Pure-Python port of 13411.py so we can test the solver locally without Sage.
Logic is a faithful translation of the Sage version.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools"))
from utils import listener  # noqa: E402

FLAG = b"crypto{local_test_flag_not_real}"
n = 64
p = 257
q = 0x10001

S = [random.randrange(q) for _ in range(n)]


def encrypt(m: int):
    A = [random.randrange(q) for _ in range(n)]
    b = (sum(a * s for a, s in zip(A, S)) + m) % q
    return A, b


class Challenge:
    def __init__(self):
        self.before_input = "Would you like to encrypt your own message, or see an encryption of a character in the flag?\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {'error': 'You must specify an option'}

        if your_input['option'] == 'get_flag':
            if "index" not in your_input:
                return {"error": "You must provide an index"}
            index = int(your_input["index"])
            if index < 0 or index >= len(FLAG):
                return {"error": f"index must be between 0 and {len(FLAG) - 1}"}
            A, b = encrypt(FLAG[index])
            return {"A": str(list(A)), "b": str(int(b))}

        elif your_input['option'] == 'encrypt':
            if "message" not in your_input:
                return {"error": "You must provide a message"}
            message = int(your_input["message"])
            if message < 0 or message >= p:
                return {"error": f"message must be between 0 and {p - 1}"}
            A, b = encrypt(message)
            return {"A": str(list(A)), "b": str(int(b))}

        return {'error': 'Unknown action'}


import builtins
builtins.Challenge = Challenge
listener.start_server(port=13411)
