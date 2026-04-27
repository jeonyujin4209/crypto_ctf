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
    pre = []
    for exp in range(20):
        pre.append([list(y^exp * a^i) for i in range(128)])

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

                exp = 2 + ad_b + ct_b
                for i in range(ad_l):
                    if i % 128 == 0:
                        exp -= 1
                    for j in range(128):
                        M[bl * 128 + j, i] = pre[exp][i % 128][j]

                exp = 2 + ct_b
                for i in range(ct_l):
                    if i % 128 == 0:
                        exp -= 1
                    for j in range(128):
                        M[bl * 128 + j, i + ad_tot] = pre[exp][i % 128][j]

                for i in range(128):
                    M[bl * 128 + i, i + ad_tot + ct_tot] = 1

            r = vector(GF(2), r)
            try:
                res = M.solve_right(r)
            except ValueError:
                continue

            basis = M.right_kernel().basis()
            l = len(basis)
            if l > 10:
                continue

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
            print(f"[solve2] kernel={l} cands={len(cands)}", flush=True)
            return cands

def solve3(y, cands):
    io.sendline(b"")  # exit loop

    for cand in cands:
        s = cand[2]
        l = length_block(0, 0)
        blocks = [l, s]
        tag = F(0)
        for exp, block in enumerate(blocks[::-1]):
            tag += y^exp * bytes_to_poly(block)
        tag_bytes = poly_to_bytes(tag)
        io.sendlineafter(b"tag: ", bytes.hex(tag_bytes).encode())

        try:
            line = io.recvline(timeout=3)
        except Exception:
            line = b""
        text = line.decode(errors="replace").strip()
        print(f"[solve3] response: {text!r}", flush=True)
        if "{" in text and "}" in text:
            return text
        # Only one chance in real challenge - but for test only one s works
        return None
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
