# Crossed Wires (50 pts)

**Approach:** Same N with different public exponents. Given your own private key d, recover phi(N) = (e*d - 1) / k. Then compute each friend's private key and decrypt the message in reverse order.

**Flag:** `crypto{3ncrypt_y0ur_s3cr3t_w1th_y0ur_fr1end5_publ1c_k3y}`
