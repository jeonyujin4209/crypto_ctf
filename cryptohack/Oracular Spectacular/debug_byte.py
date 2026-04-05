"""Debug: investigate why per-byte accuracy is so low."""

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom
import math
import os
import sys

rng_local = SystemRandom()
HEX_LIST = [ord(c) for c in '0123456789abcdef']

class LocalChallenge:
    def __init__(self):
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return (iv + ct).hex()

    def check_padding(self, ct_hex):
        ct = bytes.fromhex(ct_hex)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
        except ValueError:
            good = False
        else:
            good = True
        self.query_count += 1
        return good ^ (rng_local.random() > 0.4)


def test_single_byte():
    """Test byte 15 (simplest - padding 0x01) with lots of detail."""
    ch = LocalChallenge()
    ct_hex = ch.get_ct()
    ct_b = bytes.fromhex(ct_hex)
    iv = list(ct_b[:16])
    c1 = list(ct_b[16:32])
    c2 = list(ct_b[32:48])

    # True intermediate for block 2
    cipher_ecb = AES.new(ch.key, AES.MODE_ECB)
    true_inter = list(cipher_ecb.decrypt(bytes(c2)))

    pos = 15
    pad = 1  # 16 - 15

    # For pos=15, pad=1, we need m[15] = cand ^ 1
    # Valid padding 0x01 means last byte of decrypted = 0x01
    # AES_decrypt(c2)[15] ^ m[15] = 0x01
    # true_inter[15] ^ m[15] = 0x01
    # m[15] = true_inter[15] ^ 0x01
    # We set m[15] = cand ^ pad = cand ^ 1
    # So cand ^ 1 = true_inter[15] ^ 1 when cand = true_inter[15]

    # But wait - there are OTHER valid paddings!
    # If m makes the last byte 0x01, that's valid.
    # But also if m makes the last TWO bytes 0x02 0x02, that's valid too!
    # And 0x03 0x03 0x03, etc.
    # Since bytes 0..14 of m are RANDOM, these other paddings can occur!

    # THIS IS THE PROBLEM! Random prefix bytes can create valid padding by accident!

    # For padding 0x01: only last byte matters. Valid iff decrypted[15] = 0x01.
    # This happens for exactly ONE value of m[15] (= true_inter[15] ^ 0x01).
    # Other m[15] values: decrypted[15] != 0x01.
    # But could decrypted end in 0x02 0x02? Only if decrypted[14] = 0x02 AND decrypted[15] = 0x02.
    # decrypted[14] = true_inter[14] ^ m[14], where m[14] is random.
    # P(decrypted[14] = 0x02) = 1/256.
    # So P(wrong candidate gives valid padding) ≈ 1/256 + 1/256^2 + ... ≈ 1/256 per wrong candidate.

    # With noisy oracle at 0.4/0.6:
    # Correct candidate: P(True) = 0.4 (valid padding, True with prob 0.4)
    # Wrong candidate: P(True) = 0.6 * (1/256) * flip + ...
    # Actually: P(valid padding | wrong cand) ≈ 1/256 for the 0x02 case
    # So P(True | wrong) = P(valid)*P(True|valid) + P(invalid)*P(True|invalid)
    #                     = (1/256)*0.4 + (255/256)*0.6 ≈ 0.5992
    # vs P(True | correct) = 1*0.4 + 0*0.6 = 0.4

    # So the signal is 0.4 vs ~0.6. Good.

    # Wait, but for pos < 15, we set bytes pos+1..15 to inter[k] ^ pad.
    # If inter[k] is WRONG (not the true intermediate), then the decrypted bytes
    # at positions k for k>pos won't be pad. So the padding will NEVER be valid
    # regardless of what we put at position pos!

    # THIS IS THE CASCADE PROBLEM FROM A DIFFERENT ANGLE.
    # If any inter[k] for k>pos is wrong, then for ALL candidates at pos,
    # the padding is invalid (bytes k won't be pad). So we get P(True)=0.6 for ALL.
    # We can't distinguish them!

    # In the "no cascade" test above, I used true intermediates. So this shouldn't
    # be the issue there. Let me check the code more carefully.

    print(f"True intermediate byte 15: {true_inter[15]}")
    print(f"c1[15] = {c1[15]}")
    print(f"Plaintext byte 15: {true_inter[15] ^ c1[15]} = '{chr(true_inter[15] ^ c1[15])}'")

    # Test all 16 candidates for byte 15 with many queries
    cands = [c1[15] ^ h for h in HEX_LIST]
    print(f"\nTrue candidate (inter[15]): {true_inter[15]}")
    print(f"Candidates: {cands}")
    print(f"True candidate in list: {true_inter[15] in cands}")

    for i, cand in enumerate(cands):
        n_true = 0
        n_total = 100
        for _ in range(n_total):
            m = bytearray(os.urandom(16))
            m[15] = cand ^ 1  # pad = 1
            ct_mod = (bytes(m) + bytes(c2)).hex()
            r = ch.check_padding(ct_mod)
            n_true += int(r)
        frac = n_true / n_total
        marker = " <-- TRUE" if cand == true_inter[15] else ""
        hex_char = chr(cand ^ c1[15])
        print(f"  cand={cand:3d} (pt='{hex_char}'): True={n_true:3d}/{n_total} = {frac:.2f}{marker}")


test_single_byte()
