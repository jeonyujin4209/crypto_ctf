from Crypto.Util.number import long_to_bytes

stream_str = open('output.txt').read().strip()
stream = [int(c) for c in stream_str]

# Berlekamp-Massey to find minimal polynomial
def berlekamp_massey(s):
    n = len(s)
    C, B = [1], [1]
    L, m = 0, 1
    for i in range(n):
        d = s[i]
        for j in range(1, len(C)):
            d ^= C[j] & s[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            shift = [0] * m + B
            while len(shift) < len(C): shift.append(0)
            while len(C) < len(shift): C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            L, B, m = i + 1 - L, T, 1
        else:
            shift = [0] * m + B
            while len(shift) < len(C): shift.append(0)
            while len(C) < len(shift): C.append(0)
            C = [C[j] ^ shift[j] for j in range(len(C))]
            m += 1
    return L, C

L, C = berlekamp_massey(stream)
taps = [i for i in range(1, len(C)) if C[i] == 1]
# Taps: [368, 369, 378, 384] -> SECRET_T = [0, 6, 15, 16]

# Reverse recurrence: a[n] = a[n+384] ^ a[n+16] ^ a[n+15] ^ a[n+6]
a = {}
for i in range(2048):
    a[768 + i] = stream[i]

for n in range(767, -1, -1):
    a[n] = a[n+384] ^ a[n+16] ^ a[n+15] ^ a[n+6]

initial_bits = [a[i] for i in range(384)]
flag_int = int(''.join(str(b) for b in initial_bits), 2)
print(long_to_bytes(flag_int))
# crypto{minimal_polynomial_in_an_arbitrary_field}
