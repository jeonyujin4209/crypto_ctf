from hashlib import sha256

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)

with open('output.txt') as f:
    lines = f.readlines()

bits = []
for line in lines:
    chal = eval(line.strip())
    a, b, c, d, root = [bytes.fromhex(h) for h in chal]
    left = merge_nodes(a, b)
    right = merge_nodes(c, d)
    computed_root = merge_nodes(left, right)
    bits.append('1' if computed_root == root else '0')

n = int(''.join(bits), 2)
print(n.to_bytes((n.bit_length() + 7) // 8, 'big').decode())
# crypto{U_are_R3ady_For_S4plins_ch4lls}
