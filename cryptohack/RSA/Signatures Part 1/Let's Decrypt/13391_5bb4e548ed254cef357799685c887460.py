#!/usr/bin/env python3

"""
Let's Decrypt
If you can prove you own CryptoHack.org, then you get access to one of our secrets.

Connect at socket.cryptohack.org 13391

Challenge files:
  - 13391.py
"""


import re
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener
from pkcs1 import emsa_pkcs1_v15
# from params import N, E, D

FLAG = "crypto{?????????????????????????????????}"

MSG = 'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG.encode(), 256)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)


class Challenge():
    def __init__(self):
        self.before_input = "This server validates domain ownership with RSA signatures. Present your message and public key, and if the signature matches ours, you must own the domain.\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_signature':
            return {
                "N": hex(N),
                "e": hex(E),
                "signature": hex(SIGNATURE)
            }

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            n = int(your_input['N'], 16)
            e = int(your_input['e'], 16)

            digest = emsa_pkcs1_v15.encode(msg.encode(), 256)
            calculated_digest = pow(SIGNATURE, e, n)

            if bytes_to_long(digest) == calculated_digest:
                r = re.match(r'^I am Mallory.*own CryptoHack.org$', msg)
                if r:
                    return {"msg": f"Congratulations, here's a secret: {FLAG}"}
                else:
                    return {"msg": f"Ownership verified."}
            else:
                return {"error": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13391)
