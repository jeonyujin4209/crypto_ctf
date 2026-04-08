import os
import json
import signal
from utils import listener

FLAG = "crypto{???????????????????????????????????????????????????????????}"
LIMIT = 2500
TIMEOUT = 15


class StreamCipher:
    def __init__(self, key, skip=-1):
        assert len(key) == 128, "Error: the key must be of exactly 128 bits."
        self._s = key
        self._t = [0, 1, 2, 7]
        self._p = [0, 16, 32, 64, 96, 127]
        self._f = [[0, 1, 2, 3], [0, 1, 2, 4, 5], [0, 1, 2, 5], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 3, 5], [0, 1, 3], [0, 1, 4], [0, 1, 5], [0, 2, 3, 4, 5], [
            0, 2, 3], [0, 3, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 5], [1, 2], [1, 3, 5], [1, 3], [1, 4], [1], [2, 4, 5], [2, 4], [2], [3, 4], [4, 5], [4], [5]]
        self._b = 1
        if skip == -1:
            skip = 2 * len(key)
        for _ in range(skip):
            self._clock()

    def _prod(self, L):
        p = 1
        for x in L:
            p *= x
        return p

    def _sum(self, L):
        s = 0
        for x in L:
            s ^= x
        return s

    def _clock(self):
        x = [self._s[p] for p in self._p]
        self._s = self._s[1:] + [self._sum(self._s[p] for p in self._t)]
        return self._b ^ self._sum(self._prod(x[v] for v in m) for m in self._f)

    def encrypt(self, data):
        c = []
        for p in data:
            b = 0
            for _ in range(8):
                b = (b << 1) | self._clock()
            c += [p ^ b]
        return bytes(c)


class Challenge:
    def __init__(self):
        self.before_input = f"Hello stranger! You have {TIMEOUT} seconds to solve this crypto task! Good luck :-)\n"
        self.timeout_secs = TIMEOUT
        self.max_payload_size = 5500 # send up to 5500 bytes per message (CH default is 1024 bytes)
        self.key = int.from_bytes(os.urandom(16), "big")
        self.ciphered = 0
        self.sc = StreamCipher(list(map(int, list(f"{self.key:0128b}"))))

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'encrypt':
            if 'plaintext' in your_input:
                plaintext = bytes.fromhex(your_input["plaintext"])
            else:
                return {"error": "You need to send a plaintext (hex encoded)."}

            if (self.ciphered + len(plaintext)) <= LIMIT:
                ciphertext = self.sc.encrypt(plaintext)
                self.ciphered += len(plaintext)
                return {"ciphertext": ciphertext.hex()}
            else:
                return {"error": f"You cannot encrypt more than {LIMIT - self.ciphered} bytes."}

        elif your_input['option'] == 'get_flag':
            try:
                assert 'key' in your_input
                key = int(your_input["key"])
            except:
                return {"error": "You need to send the key as an integer."}

            if key == self.key:
                return {"flag": FLAG}
            else:
                return {"error": "This is not the correct key."}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13404)
