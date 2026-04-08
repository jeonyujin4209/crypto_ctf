import numpy as np
import random
import re
from Crypto.Util.number import isPrime
from utils import listener


FLAG = "crypto{????????????????????????????????????????}"
SCHNEIER_FACTS = [
    "If Bruce Schneier had designed the Caesar cipher, Caesar would still be alive today.",
    "It is impossible to hide information from Bruce Schneier. Not even by destroying it.",
    "Bruce Schneier can fill a knapsack in constant time without exceeding the weight.",
    "Bruce Schneier writes his books and essays by generating random alphanumeric text of an appropriate length and then decrypting it.",
    "When Bruce Schneier observes a quantum particle, it remains in the same state until he has finished observing it.",
    "Bruce Schneier knows Alice and Bob's shared secret.",
    "The last cryptologist who questioned Bruce Schneier was found floating face down in his own entropy pool.",
    "Bruce Schneier's house is in a Galois Field.",
    "Bruce Schneier is in the middle of the man-in-the-middle.",
    "When Bruce Schneier wears a security badge, he's authenticating the badge.",
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
    if isPrime(int(array.sum())) and isPrime(int(array.prod())):
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
listener.start_server(port=13400)
