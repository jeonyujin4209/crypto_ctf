#!/usr/bin/env python3
# Fermat's little theorem: a^(p-1) ≡ 1 (mod p), p prime
# 273246787654^65536 mod 65537 = 1 (since 65537 is prime, exponent = p-1)
print(pow(273246787654, 65536, 65537))
# 1
