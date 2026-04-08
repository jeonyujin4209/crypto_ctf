# Ron was Wrong, Whit is Right (80 pts)

**Approach:** Multiple RSA public keys share common prime factors due to poor randomness. Compute pairwise GCD across all moduli to find shared primes, then factor the vulnerable keys and decrypt.

**Flag:** `crypto{3ucl1d_w0uld_b3_pr0ud}`
