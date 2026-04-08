# Endless Emails (40 pts)

**Approach:** e = 3 with the same message encrypted under 7 different moduli. Apply Hastad's broadcast attack: CRT on 3 ciphertexts to get m^3, then take the cube root.

**Flag:** `crypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}`
