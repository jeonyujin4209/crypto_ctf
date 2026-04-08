from Crypto.Util.number import bytes_to_long

# SECRET_T = [?, ?, ?, ?]
FLAG = b"crypto{????????????????????????????????????????}"
assert len(FLAG) == 48

class LFSR:
    def __init__(self):
        self._s = list(map(int, list("{:0384b}".format(bytes_to_long(FLAG)))))
        for _ in range(16 * len(FLAG)):
            self._clock()

    def _clock(self):
        b = self._s[0]
        c = 0
        for t in SECRET_T: c ^= self._s[t]
        self._s = self._s[1:] + [c]
        return b

    def stream(self, length):
        return [self._clock() for _ in range(length)]

c = LFSR()
stream = c.stream(2048)
print("".join(map(str, stream)))
