"""
Paper Plane - IGE Padding Oracle Attack

IGE Mode Decrypt:
  Block 0: inter0 = AES_dec(C0 XOR m0), P0 = inter0 XOR c0
  Block 1: inter1 = AES_dec(C1 XOR P0),  P1 = inter1 XOR C0

Padding is checked on the FULL plaintext (P0 || P1).
Only P1 matters for PKCS7 validation (last block).

Key insight: we can attack block 1 (last block) by manipulating C0.
When we modify C0:
  - Block 0 decryption changes (different XOR output)
  - Block 1: inter1 = AES_dec(C1 XOR P0') where P0' is the new block0 plaintext

This is complex because P0' depends on C0' too.

SIMPLER APPROACH:
Send only 1 block as ciphertext, with crafted m0/c0.
For a single block, the plaintext IS the last block, so PKCS7 is checked directly.

We want to find: inter = AES_dec(original_C0 XOR original_m0)
So we send: ciphertext=original_C0, m0=original_m0, vary c0
This gives: pt = inter XOR c0_test
When pt has valid PKCS7 -> oracle returns true.

But block 0 plaintext is like "crypto{some_tex" (not padded)
So most c0_test values won't give valid padding.
Only when c0_test makes pt end with 0x01 (or other valid pad).

The debug showed guess=0x0f valid for byte 15 with all other c0 bytes = 0x00.
This means: inter[15] XOR 0x0f = pad_value, and bytes 0-14 are inter[k] XOR 0x00 = inter[k]
For PKCS7 to be valid with these values, inter[0:15] must also match.

Actually, pad_value = inter[15] XOR 0x0f. If pad_value is large (e.g. 16),
then ALL bytes must equal 16. Unlikely.

More likely: inter[15] XOR 0x0f = some small pad value N, and
inter[16-N:15] XOR 0x00 all equal N too.

Let me just trust the first valid guess and work from there.
"""
import requests
import sys

BASE = "https://aes.cryptohack.org/paper_plane"

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def oracle(ct_hex, m0_hex, c0_hex):
    r = requests.get(f"{BASE}/send_msg/{ct_hex}/{m0_hex}/{c0_hex}/")
    return "msg" in r.json()

def find_pad_value(block, m0, guess_byte15):
    """Determine the actual pad value when c0[15]=guess gives valid padding"""
    # Send with c0 = [0]*14 + [guess]
    # pt = inter XOR c0, so pt[0:15] = inter[0:15], pt[15] = inter[15] ^ guess
    # PKCS7 pad value = pt[15]
    # If pad value is N, then pt[16-N:16] must all be N

    # Test: flip byte (15-1)=14. If still valid, pad >= 2
    for pad_test in range(1, 17):
        idx = 16 - pad_test - 1  # byte just before the pad
        if idx < 0:
            return pad_test  # pad = 16 (all bytes are padding)
        test_c0 = bytearray(16)
        test_c0[15] = guess_byte15
        test_c0[idx] ^= 1  # flip a byte just outside the pad region
        if not oracle(block.hex(), m0.hex(), bytes(test_c0).hex()):
            # Flipping this byte broke it -> this byte was part of pad
            continue
        else:
            # Flipping this byte didn't break it -> this byte is NOT part of pad
            return pad_test
    return 16

def attack_block(block, m0, c0):
    intermediate = bytearray(16)

    # Step 1: Find valid guess for byte 15
    print("  Finding byte 15...")
    valid_guesses = []
    for guess in range(256):
        test_c0 = bytearray(16)
        test_c0[15] = guess
        if oracle(block.hex(), m0.hex(), bytes(test_c0).hex()):
            valid_guesses.append(guess)

    print(f"  Valid guesses for byte 15: {[hex(g) for g in valid_guesses]}")

    if not valid_guesses:
        print("  [!] No valid guess for byte 15!")
        return None

    # For each valid guess, determine pad value
    for guess in valid_guesses:
        pad_val = find_pad_value(block, m0, guess)
        print(f"  guess=0x{guess:02x}, pad_value={pad_val}")

        # intermediate[15] = guess ^ pad_val
        intermediate[15] = guess ^ pad_val

        # If pad_val > 1, we also know more intermediate bytes
        if pad_val > 1:
            for k in range(16 - pad_val, 15):
                # pt[k] = inter[k] XOR 0 = inter[k] = pad_val
                intermediate[k] = pad_val  # since c0_test[k] was 0

        # Now continue with remaining bytes
        success = True
        for pos in range(16 - pad_val - 1, -1, -1):
            target_pad = 16 - pos
            test_c0 = bytearray(16)
            for k in range(pos + 1, 16):
                test_c0[k] = intermediate[k] ^ target_pad

            found = False
            for g in range(256):
                test_c0[pos] = g
                if oracle(block.hex(), m0.hex(), bytes(test_c0).hex()):
                    intermediate[pos] = g ^ target_pad
                    found = True
                    sys.stdout.write(f"\r  [{16-pos}/16] byte {pos} = 0x{intermediate[pos]:02x}")
                    sys.stdout.flush()
                    break

            if not found:
                print(f"\n  [!] Failed at byte {pos}, trying next guess")
                success = False
                break

        if success:
            plaintext = xor(bytes(intermediate), c0)
            return plaintext

    return None

def solve():
    print("[*] Getting encrypted flag...")
    r = requests.get(f"{BASE}/encrypt_flag/")
    data = r.json()
    ct = bytes.fromhex(data["ciphertext"])
    m0 = bytes.fromhex(data["m0"])
    c0 = bytes.fromhex(data["c0"])

    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    print(f"[*] {len(blocks)} blocks to decrypt")

    flag = b""
    prev_m = m0
    prev_c = c0

    for i, block in enumerate(blocks):
        print(f"\n[*] Block {i+1}/{len(blocks)}...")
        pt = attack_block(block, prev_m, prev_c)
        if pt:
            flag += pt
            print(f"\n  => {pt}")
            prev_m = pt
            prev_c = block
        else:
            print("\n[!] Attack failed")
            break

    if flag:
        try:
            pad_len = flag[-1]
            if 1 <= pad_len <= 16 and all(flag[-j] == pad_len for j in range(1, pad_len + 1)):
                flag = flag[:-pad_len]
        except:
            pass

    print(f"\n[+] Flag: {flag.decode(errors='replace')}")

if __name__ == "__main__":
    solve()
