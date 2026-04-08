import random
import json

FLAG = b"crypto{?????????????????????????????????????????}"


def keygen(secret, q, erange=range(2)):
    n, m = len(secret), len(secret) ** 2
    A = Matrix(GF(q), m, n, lambda i, j: randint(0, q - 1))
    e = vector(random.choices(erange, k=m), GF(q))
    b = (A * secret) + e
    return A, b, e


flag_int = int.from_bytes(FLAG, "big")
q = 0x10001
secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

secret_key = vector(GF(q), secret_key)
A, b, e = keygen(secret_key, q)

with open("output.txt", "w") as f:
    json.dump({"A": str(list(A)), "b": str(b)}, f)
