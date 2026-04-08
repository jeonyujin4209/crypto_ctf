# x ≡ 2 mod 5
# x ≡ 3 mod 11
# x ≡ 5 mod 17
# Find x mod 935 (= 5 * 11 * 17)

from functools import reduce

def crt(remainders, moduli):
    N = reduce(lambda a, b: a * b, moduli)
    x = 0
    for a_i, n_i in zip(remainders, moduli):
        N_i = N // n_i
        x += a_i * N_i * pow(N_i, -1, n_i)
    return x % N

print(crt([2, 3, 5], [5, 11, 17]))
# Answer: 872
