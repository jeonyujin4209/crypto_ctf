#!/usr/bin/env python3
"""
Sign In Please, Again (HKCERT CTF 2021)
SHA256 length extension via extended pbox + salt-embedded padding.

Attack overview:
  1. pbox has no length check (set(pbox)==set(range(21)) allows repeats)
     → can create arbitrary-length permuted output → multi-block SHA256
  2. salt bytes chosen to replicate SHA256 padding (0x80 + zeros + length)
     inside block 1 → h_target hash = intermediate SHA256 state
  3. Length extension: use h_target as IV for block 2 containing unknown bytes
  4. Recover password byte-by-byte via precomputed mapper

Budget: 16 (h_targets) + 16 (h_lookups) + 16 (pw bytes) + 1 (auth) = 49/50
"""

from pwn import *
import base64
import binascii
import hashlib
import itertools
from hash import SHA256

HOST = "archive.cryptohack.org"
PORT = 60192


def connect():
    r = remote(HOST, PORT)
    return r


def solve_pow(challenge):
    i = 0
    while True:
        i += 1
        res = i.to_bytes(8, "big")
        if hashlib.sha256(challenge + res).digest().startswith(b"\x00\x00\x00"):
            return res


def spy(r, pbox, salt):
    r.sendlineafter(b"\xf0\x9f\xa4\x96 ", "\U0001f575\ufe0f")
    r.sendlineafter(b"\xf0\x9f\x98\xb5 ", str(pbox))
    r.sendlineafter(b"\xf0\x9f\xa7\x82 ", base64.b64encode(salt))
    r.recvuntil(b"\xf0\x9f\x94\x91 ")
    return binascii.unhexlify(r.recvline().strip())


def auth(r, password):
    r.sendlineafter(b"\xf0\x9f\xa4\x96 ", "\U0001f5a5\ufe0f")
    r.recvuntil(b"\xf0\x9f\x98\xb5 ")
    pbox = eval(r.recvline())
    r.recvuntil(b"\xf0\x9f\xa7\x82 ")
    salt = base64.b64decode(r.recvline())
    # Server checks all 256 pepper values, just use pepper=0
    permutated_password = password + salt + b"\x00"
    permutated_password = bytes([permutated_password[pbox[i]] for i in range(len(pbox))])
    hashed_password = hashlib.sha256(permutated_password).hexdigest()
    r.sendlineafter(b"\xf0\x9f\x94\x91 ", hashed_password)


def recover_pepper(h_targets, h_lookups):
    """
    Length extension: h_target = SHA256(pw + 0000 + pepper) for unknown pepper.
    h_lookup[i] = SHA256(pw + 0000 + i + padding || pepper_random) where block 1 = padded(pw+0000+i).
    If pepper == i for some h_target, then h_target = intermediate state after block 1.
    Try all (h_target, i) and check if SHA256_extend(h_target, [i] + padding) matches h_lookup[i].
    """
    for h in h_targets:
        for i in range(256):
            s = SHA256(h)
            # Block 2: [pepper_candidate] + SHA256 padding for 65-byte total message
            # Length = 65 * 8 = 520 = 0x0208
            s.feed(bytes([i]) + b"\x80" + b"\x00" * 60 + b"\x02\x08")
            h_final = s.digest()
            if h_final in h_lookups:
                return bytes([h_lookups.index(h_final)]), h
    return None


def attempt():
    r = connect()

    # PoW
    r.recvuntil(b"\xf0\x9f\x94\xa7 ")
    challenge = base64.b64decode(r.recvline())
    log.info("Solving PoW...")
    r.sendlineafter(b"\xf0\x9f\x94\xa9 ", base64.b64encode(solve_pow(challenge)))

    # Phase 1: Collect h_targets (16 calls)
    # Identity pbox, salt=0000 → SHA256(pw + 0000 + random_pepper)
    # Each is a single-block SHA256 (21 bytes + padding = 64 bytes)
    log.info("Phase 1: collecting h_targets (16 spy calls)")
    h_targets = set()
    for _ in range(16):
        h_targets.add(spy(r, list(range(21)), b"\x00" * 4))

    # Phase 2: Collect h_lookups (16 calls)
    # Extended pbox (65 elements) + salt embedding SHA256 padding
    # salt = [0x00, i, 0x80, 0xA8]
    # Block 1 (64 bytes): pw(16) + 0000(4) + i(1) + 0x80(1) + 0x00(41) + 0xA8(1)
    # = padded SHA256 input for 21-byte message when pepper==i
    # Block 2 (1 byte): random pepper → determines final hash
    log.info("Phase 2: collecting h_lookups (16 spy calls)")
    pbox_ext = (
        list(range(16))           # pw[0..15]
        + [0x10] * 4              # salt[0] * 4 = 0x00 * 4
        + [0x11]                  # salt[1] = i
        + [0x12]                  # salt[2] = 0x80
        + [0x10] * 41             # salt[0] * 41 = 0x00 * 41
        + [0x13]                  # salt[3] = 0xA8
        + [0x14]                  # pepper (random)
    )
    assert len(pbox_ext) == 65

    h_lookups = []
    for i in range(16):
        h_lookups.append(spy(r, pbox_ext, bytes([0, i, 0x80, 0xa8])))

    # Phase 3 (offline): Recover one pepper via length extension
    log.info("Phase 3: recovering pepper via length extension")
    h_lookups_set = set(h_lookups)
    res = recover_pepper(h_targets, h_lookups)
    if res is None:
        log.warning("Pepper not recovered, retrying (~35% failure rate)")
        r.close()
        return False

    pepper, h_target = res
    log.success(f"Recovered pepper: {pepper.hex()}, h_target: {h_target.hex()}")

    # Phase 4 (offline): Build mapper for (base64_char, pepper_byte) → hash
    # Extended pbox will place pw[i] in block 2 position 0, pepper in position 1
    # Block 2 padding: 0x80 + 0x00*59 + 0x0210 (66*8=528=0x210)
    log.info("Phase 4: building mapper (64 * 256 = 16384 entries)")
    charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    mapper = {}
    for ch in charset:
        for p in range(256):
            s = SHA256(h_target)
            s.feed(bytes([ch, p]) + b"\x80" + b"\x00" * 59 + b"\x02\x10")
            mapper[s.digest()] = bytes([ch])

    # Phase 5: Recover password byte-by-byte (16 calls)
    # pbox places known pepper at byte 20, pw[i] at byte 64, random pepper at byte 65
    log.info("Phase 5: recovering password (16 spy calls)")
    pbox_recover = (
        list(range(16))           # pw[0..15]
        + [0x10] * 4              # salt[0] * 4 = 0x00 * 4
        + [0x11]                  # salt[1] = known pepper
        + [0x12]                  # salt[2] = 0x80
        + [0x10] * 41             # salt[0] * 41 = 0x00 * 41
        + [0x13]                  # salt[3] = 0xA8
        # byte 64: pw[i] (varies per call)
        # byte 65: pepper (random)
    )
    # Will append [i, 0x14] at the end for each byte position

    password = b""
    for i in range(16):
        pbox_i = pbox_recover + [i, 0x14]
        assert len(pbox_i) == 66
        h = spy(r, pbox_i, b"\x00" + pepper + b"\x80\xa8")
        pw_byte = mapper.get(h)
        assert pw_byte is not None, f"Password byte {i} not found in mapper!"
        password += pw_byte
        log.info(f"  pw[{i}] = {pw_byte}")

    log.success(f"Recovered password: {password}")

    # Phase 6: Auth (1 call)
    log.info("Phase 6: authenticating")
    auth(r, password)
    flag_line = r.recvline()
    log.success(f"Flag: {flag_line.strip().decode()}")
    r.close()
    return True


def main():
    attempt_num = 0
    while True:
        attempt_num += 1
        log.info(f"=== Attempt {attempt_num} ===")
        if attempt():
            break


if __name__ == "__main__":
    main()
