"""
Each line of output.txt is [xG, yG, zG] where xG in G1, yG in G2, zG in GT.
Reconstruct bit: the encoded "is_true" is 1 iff pairing(yG, xG) == zG.
That is, zG = e(yG, multiply(xG, bias)); bias=1 iff is_true.
bit is 1 if pairing(yG, xG) == zG, else 0.
"""
from py_ecc.optimized_bn128 import G1, G2, pairing
from py_ecc.optimized_bn128 import FQ, FQ2, FQ12

# The script saved the tuples via str(). multiply returns an (x, y, z) optimized projective.
# In the saved form:
#   xG: (FQ_int, FQ_int, FQ_int)       -> 3-tuple of ints
#   yG: ((FQ2_c0, FQ2_c1), (...), (...)) -> 3-tuple of 2-tuples of ints
#   zG: FQ12 -> tuple of 12 ints
# We need to reconstruct the py_ecc projective points.

def parse_g1(t):
    return (FQ(t[0]), FQ(t[1]), FQ(t[2]))

def parse_g2(t):
    return (FQ2(list(t[0])), FQ2(list(t[1])), FQ2(list(t[2])))

def parse_gt(t):
    return FQ12(list(t))

lines = open("output.txt").read().strip().split("\n")
bits = []
for i, line in enumerate(lines):
    chal = eval(line)
    xG_raw, yG_raw, zG_raw = chal
    xG = parse_g1(xG_raw)
    yG = parse_g2(yG_raw)
    zG = parse_gt(zG_raw)
    # Compare pairing(yG, xG) with zG.
    p_val = pairing(yG, xG)
    bit = 1 if p_val == zG else 0
    bits.append(bit)
    if i % 20 == 0:
        print(f"{i}/{len(lines)}")

bitstr = "".join(str(b) for b in bits)
print("bits:", bitstr)

# The flag was encoded as bin(int(FLAG.hex(),16))[2:], so recover it directly
# (it may have a leading 0 stripped, and length is len(FLAG)*8 - leading_zeros).
# FLAG = b"crypto{?????????????}" -- 21 chars -> 168 bits -> would be 168 bits,
# but python bin() strips leading zeros. Let's infer FLAG length.
n = len(bits)
print(f"n = {n}")
val = int(bitstr, 2)
# Try various byte lengths
for nbytes in range(n // 8, n // 8 + 3):
    try:
        out = val.to_bytes(nbytes, "big")
        print(f"{nbytes} bytes: {out}")
    except Exception:
        pass
