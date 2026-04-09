"""
Jeff's LFSR - Correlation attack on Geffe generator.
Phase 1: Brute-force LFSR2 (23 bits) with correlation to output (~75% match for correct key)
Phase 2: Brute-force LFSR1 (27 bits) same way
Phase 3: For correct (LFSR1, LFSR2) pair, solve GF(2) linear system for LFSR0

Found: key0=0b1110011111111101011, key1=72267956, key2=876548
Full key: 534932540467088023556
"""
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

output_list = [1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1]

key = 534932540467088023556

sha1 = hashlib.sha1()
sha1.update(str(key).encode('ascii'))
aes_key = sha1.digest()[:16]
iv = bytes.fromhex('310c55961f7e45891022668eea77f805')
ct = bytes.fromhex('2aa92761b36a4aad9a578d6cd7a62c52ba0709cb560c0ecff33a09e4af43bff0a1c865023bf28b387df91d6319f0e103d39dda88a88c14cfcec94c8ad02a6fb3152a4466c1a184f69184349e576d8950cac0a5b58bf30e67e5269883596a33a6')
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
print(pt)
# crypto{Geffe_generator_is_a_textbook_example_to_show_correlation_attacks_on_LFSR}
