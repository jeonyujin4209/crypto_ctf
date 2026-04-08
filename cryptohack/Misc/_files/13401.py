import numpy as np
import random
import re
from Crypto.Util.number import isPrime
from utils import listener


FLAG = "crypto{??????????????????}"
SCHNEIER_FACTS = [
    "Bruce Schneier can write a recursive program that proves the Riemann Hypothesis. In Malbolge.",
    "The halting problem doesn't apply to Bruce Schneier. Loops terminate when he tells them to.",
    "Bruce Schneier knows Chuck Norris' private key.",
    "Bruce Schneier reads the 'Voynich Manuscript' as a bedtime story.",
    "Bruce Schneier never gets a speeding ticket because the camera manufacturers don't want to have to show him their source code in court.",
    "Hashes collide because they're swerving to avoid Bruce Schneier.",
    "Bruce Schneier has a set of SSH Bump Keys.",
    "Bruce Schneier can read captchas.",
    "Bruce Schneier is the root of all certificates.",
    "To describe the difficulty of cracking Bruce Schneier's cryptosystem, mathematicians use the term 'NP-Awesome'.",
]


def check(password):
    if not re.fullmatch(r"\w*", password, flags=re.ASCII):
        return "Password contains invalid characters."
    if not re.search(r"\d", password):
        return "Password should have at least one digit."
    if not re.search(r"[A-Z]", password):
        return "Password should have at least one upper case letter."
    if not re.search(r"[a-z]", password):
        return "Password should have at least one lower case letter."

    array = np.array(list(map(ord, password)))
    if isPrime(int(array.sum())) and array.sum() == array.prod():
        return FLAG
    else:
        return f"Wrong password, sum was {array.sum()} and product was {array.prod()}"


class Challenge():
    def __init__(self):
        self.before_input = f"{random.choice(SCHNEIER_FACTS)}\n"

    def challenge(self, message):
        if not "password" in message:
            self.exit = True
            return {"error": "Please send Bruce's password to the server."}

        password = message["password"]
        return {"msg": check(password)}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13401)
