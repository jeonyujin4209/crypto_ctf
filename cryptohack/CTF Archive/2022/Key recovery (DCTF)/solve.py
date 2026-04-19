"""
Key recovery (DCTF) — differential attack exploiting S-box DDT anomaly.

Vulnerability: DDT[0xbe][0xeb] = 172/256 (random max ~8-16). Per preserves
nibble-parity (P_box: even→even, odd→odd; P_nib swaps 0xb↔0xe), giving iterative
trail: per(all_0xbe) = all_0xeb, per(all_0xeb) = all_0xbe.

With input diff = 0xbe*16, each ct byte has small past cone (5-12 S-boxes).
1500 chosen-plaintext pairs (3000 encrypts, at budget) recover all 4 round keys
byte-by-byte via counting (y5 diff == 0xbe). Peel K3 → K2 → K1 → K0=master K.

Robustness: top-1 K3 fails ~25% of the time; single-byte-swap retry → 100%.
"""
import os as _os, sys, re
from hashlib import sha512
from itertools import product
from telnetlib import Telnet

sys.stdout.reconfigure(line_buffering=True)

BS, R = 16, 3
S_box = [80, 12, 233, 22, 60, 179, 30, 32, 112, 114, 174, 83, 207, 107, 33, 237, 37, 121, 161, 50, 54, 57, 77, 59, 152, 53, 52, 204, 70, 104, 163, 68, 196, 189, 17, 211, 178, 220, 92, 137, 78, 29, 96, 103, 239, 213, 108, 109, 111, 113, 90, 162, 21, 120, 23, 157, 123, 195, 186, 205, 132, 236, 232, 145, 248, 85, 134, 135, 139, 140, 102, 144, 249, 147, 181, 130, 194, 154, 175, 183, 219, 28, 66, 202, 91, 116, 142, 106, 9, 188, 203, 117, 206, 208, 151, 242, 82, 14, 210, 217, 20, 221, 227, 10, 99, 156, 160, 241, 67, 126, 65, 45, 231, 191, 46, 71, 58, 245, 24, 235, 218, 253, 61, 64, 79, 192, 8, 63, 3, 122, 35, 7, 81, 38, 201, 40, 252, 118, 254, 133, 177, 73, 34, 13, 180, 76, 4, 62, 15, 110, 165, 246, 100, 98, 89, 55, 250, 56, 47, 86, 72, 143, 173, 131, 223, 39, 115, 222, 166, 1, 148, 16, 74, 51, 200, 146, 95, 6, 36, 128, 69, 184, 155, 153, 31, 216, 215, 88, 2, 240, 187, 11, 167, 212, 164, 43, 214, 171, 49, 244, 243, 0, 209, 44, 197, 172, 251, 84, 170, 198, 168, 149, 75, 26, 136, 119, 230, 225, 255, 42, 228, 125, 185, 229, 124, 25, 93, 224, 5, 158, 226, 87, 101, 129, 176, 159, 169, 193, 48, 247, 234, 182, 41, 238, 94, 105, 18, 97, 141, 199, 150, 127, 138, 27, 19, 190]
S_box_inv = [201, 169, 188, 128, 146, 228, 177, 131, 126, 88, 103, 191, 1, 143, 97, 148, 171, 34, 246, 254, 100, 52, 3, 54, 118, 225, 213, 253, 81, 41, 6, 184, 7, 14, 142, 130, 178, 16, 133, 165, 135, 242, 219, 195, 203, 111, 114, 158, 238, 198, 19, 173, 26, 25, 20, 155, 157, 21, 116, 23, 4, 122, 147, 127, 123, 110, 82, 108, 31, 180, 28, 115, 160, 141, 172, 212, 145, 22, 40, 124, 0, 132, 96, 11, 207, 65, 159, 231, 187, 154, 50, 84, 38, 226, 244, 176, 42, 247, 153, 104, 152, 232, 70, 43, 29, 245, 87, 13, 46, 47, 149, 48, 8, 49, 9, 166, 85, 91, 137, 215, 53, 17, 129, 56, 224, 221, 109, 251, 179, 233, 75, 163, 60, 139, 66, 67, 214, 39, 252, 68, 69, 248, 86, 161, 71, 63, 175, 73, 170, 211, 250, 94, 24, 183, 77, 182, 105, 55, 229, 235, 106, 18, 51, 30, 194, 150, 168, 192, 210, 236, 208, 197, 205, 162, 10, 78, 234, 140, 36, 5, 144, 74, 241, 79, 181, 222, 58, 190, 89, 33, 255, 113, 125, 237, 76, 57, 32, 204, 209, 249, 174, 134, 83, 90, 27, 59, 92, 12, 93, 202, 98, 35, 193, 45, 196, 186, 185, 99, 120, 80, 37, 101, 167, 164, 227, 217, 230, 102, 220, 223, 216, 112, 62, 2, 240, 119, 61, 15, 243, 44, 189, 107, 95, 200, 199, 117, 151, 239, 64, 72, 156, 206, 136, 121, 138, 218]
P_nib = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
P_box = [24, 19, 12, 25, 0, 9, 6, 31, 26, 11, 28, 5, 14, 13, 20, 15, 18, 21, 10, 27, 4, 1, 22, 3, 8, 17, 16, 29, 2, 23, 30, 7]
P_box_inv = [4, 21, 28, 23, 20, 11, 6, 31, 24, 5, 18, 9, 2, 13, 12, 15, 26, 25, 16, 1, 14, 17, 22, 29, 0, 3, 8, 19, 10, 27, 30, 7]

def xor(a, b): return bytes(x^y for x, y in zip(a, b))
def byte_to_nib(x):
    out = []
    for b in x:
        out.append(b // 16); out.append(b % 16)
    return out
def nib_to_byte(x): return bytes([x[i]*16 + x[i+1] for i in range(0, len(x), 2)])
def per(x):
    n = byte_to_nib(x); return nib_to_byte([P_nib[n[P_box[i]]] for i in range(32)])
def per_inv(x):
    n = byte_to_nib(x); return nib_to_byte([P_nib[n[P_box_inv[i]]] for i in range(32)])
def key_schedule(k):
    k = k + sha512(k).digest()
    return [k[i:i+BS] for i in range(0, (R+1)*BS, BS)]
def block_full(x, keys):
    for r in range(R):
        x = bytes(S_box[a] for a in x); x = xor(x, keys[r]); x = per(x)
    x = bytes(S_box[a] for a in x); x = xor(x, keys[R])
    return x

DIFF = bytes([0xbe]*16)

def connect():
    tn = Telnet('archive.cryptohack.org', 44134, timeout=30)
    tn.read_until(b"> ", timeout=10)
    return tn

def encrypt_pt(tn, pt):
    tn.write(b"1\n" + pt.hex().encode() + b"\n")
    tn.read_until(b"hex format:\n", timeout=10)
    line = tn.read_until(b"\n", timeout=10).decode()
    # Match "Here you go:  <hex>"
    m = re.search(r'([0-9a-f]{32})', line)
    if not m:
        raise RuntimeError(f"Bad response: {line!r}")
    tn.read_until(b"> ", timeout=10)
    return bytes.fromhex(m.group(1))

def submit_key(tn, K):
    tn.write(b"3\n" + K.hex().encode() + b"\n")
    return tn.read_until(b"\n", timeout=10).decode() + tn.read_until(b"\n", timeout=10).decode()

def try_derive_K0(K3, pairs):
    pre_y4 = []
    for pt1, pt2, ct1, ct2 in pairs:
        y5_1 = bytes(S_box_inv[ct1[i] ^ K3[i]] for i in range(16))
        y5_2 = bytes(S_box_inv[ct2[i] ^ K3[i]] for i in range(16))
        pre_y4.append((pt1, pt2, per_inv(y5_1), per_inv(y5_2)))

    K2 = bytearray(16)
    for i in range(16):
        cnts = [0]*256
        for g in range(256):
            for _, _, p1, p2 in pre_y4:
                if (S_box_inv[p1[i] ^ g] ^ S_box_inv[p2[i] ^ g]) == 0xbe: cnts[g] += 1
        K2[i] = max(range(256), key=lambda g: cnts[g])
    K2 = bytes(K2)

    pre_y2 = []
    for pt1, pt2, p1, p2 in pre_y4:
        y3_1 = bytes(S_box_inv[p1[i] ^ K2[i]] for i in range(16))
        y3_2 = bytes(S_box_inv[p2[i] ^ K2[i]] for i in range(16))
        pre_y2.append((pt1, pt2, per_inv(y3_1), per_inv(y3_2)))

    K1 = bytearray(16)
    for i in range(16):
        cnts = [0]*256
        for g in range(256):
            for _, _, q1, q2 in pre_y2:
                if (S_box_inv[q1[i] ^ g] ^ S_box_inv[q2[i] ^ g]) == 0xbe: cnts[g] += 1
        K1[i] = max(range(256), key=lambda g: cnts[g])
    K1 = bytes(K1)

    pt1, _, q1, _ = pre_y2[0]
    y2_1 = bytes(q1[i] ^ K1[i] for i in range(16))
    y1_1 = bytes(S_box_inv[b] for b in y2_1)
    py = per_inv(y1_1)
    return bytes(py[i] ^ S_box[pt1[i]] for i in range(16))

def verify_K0(K0, pt, ct):
    return block_full(pt, key_schedule(K0)) == ct

def main():
    N = 1500
    print(f"Connecting to archive.cryptohack.org:44134 ...", flush=True)
    tn = connect()
    print(f"Collecting {N} pairs ({2*N} encrypts) ...", flush=True)
    pairs = []
    for j in range(N):
        pt1 = _os.urandom(16)
        pt2 = bytes(a ^ b for a, b in zip(pt1, DIFF))
        ct1 = encrypt_pt(tn, pt1)
        ct2 = encrypt_pt(tn, pt2)
        pairs.append((pt1, pt2, ct1, ct2))
        if (j+1) % 100 == 0:
            print(f"  {j+1}/{N}", flush=True)

    known_pt, known_ct = pairs[0][0], pairs[0][2]

    # K3 top-5 per byte
    print("Recovering K3 (top-5 per byte)...", flush=True)
    K3_tops = []
    for i in range(16):
        cnts = [0]*256
        for g in range(256):
            for _, _, ct1, ct2 in pairs:
                if (S_box_inv[ct1[i] ^ g] ^ S_box_inv[ct2[i] ^ g]) == 0xbe:
                    cnts[g] += 1
        K3_tops.append(sorted(range(256), key=lambda x: -cnts[x])[:5])

    K3 = bytes(t[0] for t in K3_tops)
    print(f"Top-1 K3: {K3.hex()}", flush=True)
    K0 = try_derive_K0(K3, pairs)
    if verify_K0(K0, known_pt, known_ct):
        print(f"Recovered K (top-1): {K0.hex()}", flush=True)
    else:
        print("Top-1 failed. Trying single-byte swaps...", flush=True)
        K0 = None
        for i in range(16):
            for alt in range(1, 5):
                K3_try = bytearray(K3); K3_try[i] = K3_tops[i][alt]; K3_try = bytes(K3_try)
                K0_try = try_derive_K0(K3_try, pairs)
                if verify_K0(K0_try, known_pt, known_ct):
                    K0 = K0_try
                    print(f"  Swap byte {i} -> top-{alt+1}. K = {K0.hex()}", flush=True)
                    break
            if K0: break

        if not K0:
            print("Single-swap failed. Trying 2-byte swaps...", flush=True)
            done = False
            for i1 in range(16):
                if done: break
                for i2 in range(i1+1, 16):
                    if done: break
                    for a1, a2 in product(range(1, 3), range(1, 3)):
                        K3_try = bytearray(K3); K3_try[i1] = K3_tops[i1][a1]; K3_try[i2] = K3_tops[i2][a2]
                        K0_try = try_derive_K0(bytes(K3_try), pairs)
                        if verify_K0(K0_try, known_pt, known_ct):
                            K0 = K0_try
                            print(f"  2-swap bytes {i1},{i2}. K = {K0.hex()}", flush=True)
                            done = True; break

        if not K0:
            print("Attack failed!", flush=True)
            return

    print("Submitting K to server...", flush=True)
    resp = submit_key(tn, K0)
    print("Server response:", flush=True)
    print(resp, flush=True)

if __name__ == "__main__":
    main()
