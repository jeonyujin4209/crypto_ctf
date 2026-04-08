# RSA Backdoor Viability (80 pts)

**Approach:** Primes are generated with CM structure: p = (427*s^2 + 1)/4. This means 4p-1 = 427*s^2, giving the discriminant D = -427. Factor n using the Hilbert class polynomial for D = -427, or look up n on factordb.

**Flag:** `crypto{I_want_to_Break_Square-free_4p-1}`
