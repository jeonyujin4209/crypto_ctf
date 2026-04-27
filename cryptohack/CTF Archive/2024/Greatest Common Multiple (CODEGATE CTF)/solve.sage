"""
Greatest Common Multiple (CODEGATE CTF 2024).

Vulnerability:
- AES-GCM with FIXED key+nonce across many tag queries (nonce reuse).
- Server lets us issue tag/u1/u2 commands; final win = predict tag of empty
  message (= S = E_K(J0)).
- Although AAD/PT contents are random and unknown to us, every 12-byte gen()
  block leaves 32 BITS of zero-padding inside its 16-byte GHASH block. That
  zero-padding is what makes the polynomial system over GF(2) solvable.

Attack outline (Soon Haari's writeup, https://soon.haari.me/gcm/):
1) Recover y = H = E_K(0):
   Issue ~150 alternating (u1, tag). Between consecutive tags, exactly one of
   {ad, ct} block was replaced (the other 50% chance is the same slot, then we
   just discard - random sample lands on the right setup).
   For each consecutive XOR diff D = tag_i XOR tag_{i+1}:
       D = (delta) * y^k for k in {2,3,4,5}
   delta = c1 - c2 has known 32 zero bits in upper half (12-byte plaintext
   padded to 16). Multiplying D * y^{-k} * a^{-32} yields (c1 - c2)/a^32 which
   should also have its top 32 bits = 0 IF k was correct. Each pair gives 32
   GF(2) equations on coefficients of y^{-k}. Random 5-tuples -> 160 eqs in
   128 vars. Two roots survive: y^{-2} and y^{-3} (since u1 only changes one
   slot, k either 2 or 3, but appears as 4 or 5 too via squaring? Actually we
   solve for y^{-2}; both kernel solutions are y^{-2} and y^{-3} due to slot
   ambiguity, picking the right one via y^{-3} == y^{-2}^(3/2)).

2) Recover s = S:
   Build long messages by repeated u2 (slot bit random). After u1 reset to
   12-byte, do (u2, tag)*N. Each u2 either appends to ad or ct (random).
   The first 6 u2's let us detect the slot pattern via tag-diff polynomial
   nullpad signatures (which exponent k normalises to <96 bits). Once we
   know the prefix, brute-force only the trailing few bits, set up linear
   system over GF(2) for unknowns (ad bits, ct bits, s bits). 12 tags >
   320 vars -> kernel small, enumerate.

3) Predict empty tag = length_block(0,0)*y + s = 0*y + s ... actually
   tag = sum of poly. Empty AAD/CT, len_block all zero -> tag = 0 + S.
   But chall.py calls digest() on fresh cipher = empty AAD + empty CT,
   so tag = S directly (length block contribution = 0 * y + s_pad).
   Send hex(S) to win.
"""

from Crypto.Cipher import AES
from pwn import remote, xor
import os, random, hashlib, sys
from itertools import product
from time import time

# ---------------- GF(2^128) helpers (mirror writeup) ----------------
F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)
mod_int = 2^128 + 2^7 + 2^2 + 2 + 1

def bytes_to_n(b):
    v = int.from_bytes(nullpad(b), 'big')
    # Bit-reverse to match GHASH bit order
    return int(f"{v:0128b}"[::-1], 2)

def bytes_to_poly(b):
    return F.from_integer(bytes_to_n(b))

def poly_to_n(p):
    v = p.to_integer()
    return int(f"{v:0128b}"[::-1], 2)

def poly_to_bytes(p):
    return poly_to_n(p).to_bytes(16, 'big')

def length_block(lad, lct):
    return int(lad * 8).to_bytes(8, 'big') + int(lct * 8).to_bytes(8, 'big')

def nullpad(msg):
    return bytes(msg) + b'\x00' * (-len(msg) % 16)


# ---------------- I/O helpers ----------------
def tag_cmd():
    io.sendline(b"tag")
    io.recvuntil(b"tag: ")
    return bytes.fromhex(io.recvline().decode())

# ---------------- PoW (multiprocess) ----------------
from multiprocessing import Pool, cpu_count

def _pow_search(args):
    start, end, nonce, target = args
    for n in range(start, end):
        if hashlib.md5(str(n).encode() + nonce).digest() == target:
            return n
    return None

def solve_PoW():
    io.recvuntil(b"b'")
    nonce = io.recvuntil(b"'")[:-1]
    io.recvuntil(b" = ")
    hsh = bytes.fromhex(io.recvline()[:-1].decode())
    print(f"[*] PoW nonce={nonce!r} target={hsh.hex()}", flush=True)

    workers = max(1, cpu_count())
    max_n = 2**26
    chunk = max_n // workers + 1
    args = [(i*chunk, min((i+1)*chunk, max_n), nonce, hsh) for i in range(workers)]
    pst = time()
    with Pool(workers) as p:
        for r in p.imap_unordered(_pow_search, args):
            if r is not None:
                p.terminate()
                print(f"[*] PoW n={r} ({time()-pst:.1f}s)", flush=True)
                io.sendlineafter(b"): ", str(r).encode())
                return
    raise RuntimeError("PoW failed")


# ---------------- Step 1: recover y ----------------
def solve1():
    cur = tag_cmd()
    dats = []
    num_dat = 150
    io.sendlines([b"u1", b"tag"] * num_dat)
    for _ in range(num_dat):
        io.recvuntil(b"tag: ")
        new = bytes.fromhex(io.recvline().decode())
        dat = xor(new, cur)
        cur = new

        dat_n = bytes_to_n(dat)
        basis = [dat_n]
        for i in range(127):
            basis.append(basis[-1] << 1)
            if basis[-1] & (1 << 128):
                basis[-1] ^^= mod_int

        vecs = []
        for i in range(32):
            vecs.append(vector(GF(2), [basis[j] >> (i + 96) for j in range(128)]))
        dats.append(vecs)

    found = set()
    tries = 0
    while True:
        tries += 1
        if tries > 5000:
            return None
        idxs = random.sample(range(num_dat), 5)
        M = []
        for idx in idxs:
            M += dats[idx]
        M = Matrix(M)
        basis = M.right_kernel().basis()
        if len(basis) == 1:
            res = F([int(t) for t in basis[0]])
            found.add(res)
            if len(found) == 2:
                break

    f1, f2 = list(found)
    y = 1 / f1.sqrt()
    if y^(-3) == f2:
        return y
    y = 1 / f2.sqrt()
    if y^(-3) == f1:
        return y
    return None


# ---------------- Step 2: recover s and ct/ad ----------------
def solve2(y):
    cnt = 0
    # Precompute pre_mat[exp]: 128x128 GF(2) Matrix where col k = bit_decomp(y^exp * a^k)
    pre_mat = []
    for exp in range(20):
        cols = [list(y^exp * a^i) for i in range(128)]
        M_pre = Matrix(GF(2), 128, 128)
        for k in range(128):
            for j in range(128):
                M_pre[j, k] = cols[k][j]
        pre_mat.append(M_pre)

    while True:
        cnt += 1
        print(f"[solve2] try {cnt}", flush=True)
        # Reset all values to 12 bytes via 50 u1's
        io.sendlines([b"u1"] * 50)

        io.sendline(b"tag")
        io.sendlines([b"u2", b"tag"] * 6)

        tags = []
        for _ in range(7):
            io.recvuntil(b"tag: ")
            tags.append(bytes.fromhex(io.recvline().decode()))

        c1, c2 = True, True

        f = bytes_to_poly(xor(tags[2], tags[3])) + (bytes_to_poly(length_block(12, 36)) + bytes_to_poly(length_block(12, 48))) * y
        f /= y^2 * a^32
        f = f.to_integer()
        if f >> 96 != 0:
            c1 = False

        f = bytes_to_poly(xor(tags[5], tags[6])) + (bytes_to_poly(length_block(36, 48)) + bytes_to_poly(length_block(48, 48))) * y
        f /= y^5 * a^32
        f = f.to_integer()
        if f >> 96 != 0:
            c1 = False

        f = bytes_to_poly(xor(tags[2], tags[3])) + (bytes_to_poly(length_block(36, 12)) + bytes_to_poly(length_block(48, 12))) * y
        f /= y^3 * a^32
        f = f.to_integer()
        if f >> 96 != 0:
            c2 = False

        f = bytes_to_poly(xor(tags[5], tags[6])) + (bytes_to_poly(length_block(48, 36)) + bytes_to_poly(length_block(48, 48))) * y
        f /= y^2 * a^32
        f = f.to_integer()
        if f >> 96 != 0:
            c2 = False

        assert (c1 and c2) == False

        if c1:
            base_it = [1, 1, 1, 0, 0, 0]
        elif c2:
            base_it = [0, 0, 0, 1, 1, 1]
        else:
            continue

        tag_n = 12
        io.sendlines([b"u2", b"tag"] * (tag_n - 7))
        for _ in range(tag_n - 7):
            io.recvuntil(b"tag: ")
            tags.append(bytes.fromhex(io.recvline().decode()))

        tags = [bytes_to_poly(t) for t in tags]
        assert len(tags) == tag_n

        valid_its = []
        for it in range(2^(tag_n - 7)):
            ad_l = 96
            ct_l = 96
            it_full = base_it + [(it >> i) & 1 for i in range(tag_n - 4)]
            ad_tot = ad_l + 96 * ((tag_n - 1) - sum(it_full))
            ct_tot = ct_l + 96 * sum(it_full)

            M = Matrix(GF(2), tag_n * 128, (ad_tot + ct_tot + 128))
            r = []

            for bl in range(tag_n):
                if bl > 0:
                    cur = it_full[bl - 1]
                    if cur == 0:
                        ad_l += 96
                    else:
                        ct_l += 96

                res = tags[bl] + bytes_to_poly(length_block(ad_l // 8, ct_l // 8)) * y
                r += list(res)

                ad_b = (ad_l + 127) // 128
                ct_b = (ct_l + 127) // 128

                # Vectorized AD-block assignment.
                row_lo = bl * 128
                row_hi = row_lo + 128
                for c in range(ad_b):
                    col_lo = c * 128
                    col_hi = min((c + 1) * 128, ad_l)
                    width = col_hi - col_lo
                    exp_c = 1 + ad_b + ct_b - c
                    if width == 128:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c]
                    else:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c][:, :width]

                for c in range(ct_b):
                    col_lo = ad_tot + c * 128
                    col_hi = ad_tot + min((c + 1) * 128, ct_l)
                    width = col_hi - col_lo
                    exp_c = 1 + ct_b - c
                    if width == 128:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c]
                    else:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c][:, :width]

                M[row_lo:row_hi, ad_tot + ct_tot:ad_tot + ct_tot + 128] = identity_matrix(GF(2), 128)

            r = vector(GF(2), r)

            try:
                res = M.solve_right(r)
            except ValueError:
                continue

            # Rank-only check: kernel basis is expensive, defer to final pick.
            l = M.ncols() - M.rank()
            if l > 10:
                continue
            valid_its.append((it, l, res, M, ad_tot, ct_tot))

        if not valid_its:
            continue

        # Pick smallest kernel
        valid_its.sort(key=lambda t: t[1])
        it_best, l, res, M_best, ad_tot, ct_tot = valid_its[0]
        basis = M_best.right_kernel().basis()
        print(f"[solve2] best it={it_best} kernel={l}", flush=True)

        cands = []
        for itt in product(range(2), repeat=l):
            v = res
            for i, b in enumerate(itt):
                v += b * basis[i]
            vs = [v[:ad_tot], v[ad_tot:ad_tot + ct_tot], v[ad_tot + ct_tot:]]
            for idx in range(3):
                vv = list(vs[idx])
                v_bytes = b""
                for i in range(0, len(vv), 128):
                    block = [int(t) for t in vv[i:i + 128]]
                    v_bytes += poly_to_bytes(F(block))[:len(block) // 8]
                vs[idx] = v_bytes
            cands.append(vs)
        return cands

# ---------------- Step 3: forge tag for empty AAD+CT ----------------
def solve3(y, cands):
    io.sendline(b"")  # exit loop

    # Empty AAD, empty CT: blocks = [length_block(0,0)=zeros, s].
    # Reversed enumeration: s*y^0 + L*y^1 = s + 0 = s.
    # Try only the FIRST candidate (one shot per connection).
    cand = cands[0]
    s = cand[2]
    l = length_block(0, 0)
    blocks = [l, s]
    tag = F(0)
    for exp, block in enumerate(blocks[::-1]):
        tag += y^exp * bytes_to_poly(block)
    tag_bytes = poly_to_bytes(tag)
    io.sendlineafter(b"tag: ", bytes.hex(tag_bytes).encode())

    try:
        # The flag is printed after correct guess; receive remaining
        data = io.recvall(timeout=4)
    except Exception:
        data = b""
    text = data.decode(errors="replace").strip()
    # Strip ANSI escape codes (server colorizes the flag)
    import re
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    print(f"[solve3] response: {clean!r}", flush=True)
    if clean and ("{" in clean and "}" in clean) and not clean.lower().startswith("nope"):
        m = re.search(r"[A-Za-z_][A-Za-z0-9_]*\{[^}]+\}", clean)
        if m:
            return m.group(0)
        return clean
    return None


def main():
    global io
    HOST = os.environ.get("CHAL_HOST", "archive.cryptohack.org")
    PORT = int(os.environ.get("CHAL_PORT", "2762"))

    while True:
        st = time()
        try:
            io = remote(HOST, PORT)
        except Exception as e:
            print(f"connect fail: {e}", flush=True)
            continue

        try:
            solve_PoW()
            print(f"[*] PoW done at {time()-st:.1f}s", flush=True)

            y = solve1()
            if y is None:
                print("[!] solve1 failed", flush=True)
                io.close()
                continue
            print(f"[*] y recovered at {time()-st:.1f}s", flush=True)

            cands = solve2(y)
            if cands is None:
                io.close()
                continue
            print(f"[*] cands at {time()-st:.1f}s, count={len(cands)}", flush=True)

            flag = solve3(y, cands)
            io.close()
            if flag:
                print(f"\n=== FLAG === {flag}", flush=True)
                return
        except Exception as e:
            print(f"[!] error: {e}", flush=True)
            try: io.close()
            except: pass
            continue


if __name__ == "__main__":
    main()
