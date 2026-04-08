# Fast Primes (60 pts)

**Approach:** p is generated as k*primorial(40) + pow(e, a, M), resulting in only ~256-bit primes. With n at ~511 bits, it is trivially factorable using standard tools (e.g., yafu, msieve, or even Python's sympy).

**Flag:** `crypto{p00R_3570n14}`
