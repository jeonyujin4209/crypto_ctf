from py_ecc.optimized_bn128 import G1, G2, multiply, pairing
import os

FLAG = b"crypto{?????????????????}"

def gen_test(is_true):
    x = int(os.urandom(8).hex(), 16)
    y = int(os.urandom(8).hex(), 16)
    bias = 1 if is_true else int(os.urandom(2).hex(), 16)
    xG = multiply(G1, x)
    yG = multiply(G2, y)
    zG = pairing(yG, multiply(xG, bias))
    return xG, yG, zG

challenges = []

for bit in bin(int(FLAG.hex(),16))[2:]:
    xG, yG, zG = gen_test(int(bit))
    challenges.append([xG, yG, zG])

with open("output.txt", "w") as f:
    for chal in challenges:
        # Note: in your solution script, you can read each line by calling eval() on it
        f.write(str(chal))
        f.write("\n")
