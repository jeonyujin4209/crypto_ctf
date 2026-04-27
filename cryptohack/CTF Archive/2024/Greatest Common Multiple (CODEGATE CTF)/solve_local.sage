"""Local test driver - skips PoW, runs against chall_local.py via process()."""

from Crypto.Cipher import AES
from pwn import process, xor
import os, random, hashlib, sys
from itertools import product
from time import time

F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)
mod_int = 2^128 + 2^7 + 2^2 + 2 + 1

def bytes_to_n(b):
    v = int.from_bytes(nullpad(b), 'big')
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

def tag_cmd():
    io.sendlineafter(b"> ", b"tag")
    io.recvuntil(b"tag: ")
    return bytes.fromhex(io.recvline().decode())

def solve1():
    cur = tag_cmd()
    dats = []
    num_dat = 150
    for _ in range(num_dat):
        io.sendlineafter(b"> ", b"u1")
    for _ in range(num_dat):
        io.sendlineafter(b"> ", b"tag")
        io.recvuntil(b"tag: ")
        new_tag = bytes.fromhex(io.recvline().decode())
        # need alternation - this above is wrong order
        pass
    # Re-do with proper interleaving
    return None

# Simplified: re-do via batched send
def solve1_v2():
    cur = tag_cmd()
    dats = []
    num_dat = 150
    cmds = []
    for _ in range(num_dat):
        cmds += [b"u1", b"tag"]
    io.sendlines(cmds)

    for _ in range(num_dat):
        io.recvuntil(b"tag: ")
        new_tag = bytes.fromhex(io.recvline().decode())
        dat = xor(new_tag, cur)
        cur = new_tag

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

def solve2(y):
    cnt = 0
    # Precompute pre_mat[exp]: 128x128 GF(2) Matrix with col k = bit_decomp(y^exp * a^k)
    pre_mat = []
    for exp in range(20):
        cols = [list(y^exp * a^i) for i in range(128)]
        # Build matrix where row j col k = bit j of (y^exp * a^k)
        M_pre = Matrix(GF(2), 128, 128)
        for k in range(128):
            for j in range(128):
                M_pre[j, k] = cols[k][j]
        pre_mat.append(M_pre)

    while True:
        cnt += 1
        print(f"[solve2] try {cnt}", flush=True)
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
        if f.to_integer() >> 96 != 0:
            c1 = False

        f = bytes_to_poly(xor(tags[5], tags[6])) + (bytes_to_poly(length_block(36, 48)) + bytes_to_poly(length_block(48, 48))) * y
        f /= y^5 * a^32
        if f.to_integer() >> 96 != 0:
            c1 = False

        f = bytes_to_poly(xor(tags[2], tags[3])) + (bytes_to_poly(length_block(36, 12)) + bytes_to_poly(length_block(48, 12))) * y
        f /= y^3 * a^32
        if f.to_integer() >> 96 != 0:
            c2 = False

        f = bytes_to_poly(xor(tags[5], tags[6])) + (bytes_to_poly(length_block(48, 36)) + bytes_to_poly(length_block(48, 48))) * y
        f /= y^2 * a^32
        if f.to_integer() >> 96 != 0:
            c2 = False

        if c1 and c2:
            continue
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
                # For column block c (cols c*128..(c+1)*128-1, but last partial),
                # exp(c) = (2 + ad_b + ct_b) - 1 - c = 1 + ad_b + ct_b - c
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

                # Vectorized CT-block assignment. exp(c) = 1 + ct_b - c
                for c in range(ct_b):
                    col_lo = ad_tot + c * 128
                    col_hi = ad_tot + min((c + 1) * 128, ct_l)
                    width = col_hi - col_lo
                    exp_c = 1 + ct_b - c
                    if width == 128:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c]
                    else:
                        M[row_lo:row_hi, col_lo:col_hi] = pre_mat[exp_c][:, :width]

                # Identity block for S
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

def solve3(y, cands):
    io.sendline(b"")  # exit loop
    # Read DBG_S from chall_local (skip any leftover "> " prompt)
    io.recvuntil(b"DBG_S: ")
    dbg_line = io.recvline(timeout=3).decode().strip()
    print(f"[solve3] DBG_S: {dbg_line}", flush=True)
    actual_s_hex = dbg_line

    # Find the cand whose s matches actual
    matching_idx = -1
    for i, cand in enumerate(cands):
        s_hex = cand[2].hex()
        if s_hex == actual_s_hex:
            matching_idx = i
            print(f"[solve3] cand[{i}] matches actual S", flush=True)
            break

    if matching_idx == -1:
        print(f"[solve3] NO cand matched actual S! algorithm failed", flush=True)
        # Send dummy
        io.sendlineafter(b"tag: ", b"00")
        try:
            print(io.recvall(timeout=3).decode(errors="replace"))
        except Exception:
            pass
        return None

    cand = cands[matching_idx]
    s = cand[2]
    l = length_block(0, 0)
    blocks = [l, s]
    tag = F(0)
    for exp, block in enumerate(blocks[::-1]):
        tag += y^exp * bytes_to_poly(block)
    tag_bytes = poly_to_bytes(tag)
    io.sendlineafter(b"tag: ", bytes.hex(tag_bytes).encode())
    try:
        data = io.recvall(timeout=3).decode(errors="replace").strip()
    except Exception:
        data = ""
    print(f"[solve3] response: {data!r}", flush=True)
    if "{" in data and "}" in data:
        import re
        m = re.search(r"[A-Za-z_][A-Za-z0-9_]*\{[^}]+\}", data)
        if m:
            return m.group(0)
        return data
    return None

def main():
    global io
    st = time()
    io = process(["python3", "chall_local.py"])
    y = solve1_v2()
    if y is None:
        print("solve1 failed")
        return
    print(f"y={y} at {time()-st:.1f}s", flush=True)
    cands = solve2(y)
    if cands is None:
        print("solve2 failed")
        return
    print(f"got {len(cands)} cands at {time()-st:.1f}s", flush=True)
    flag = solve3(y, cands)
    print(f"FLAG: {flag}")

if __name__ == "__main__":
    main()
