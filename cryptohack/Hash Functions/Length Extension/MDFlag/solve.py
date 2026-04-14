"""
MDFlag (Hash Functions / Length Extension) — POC solver

Server (13407.py) accepts {"option": "message", "data": <hex>} where len(data)
must be >= len(FLAG), and returns {"hash": md5(data XOR cycle(FLAG)).hexdigest()}.

Goal: leak FLAG. There is no get_flag option — we have to read it out byte-by-
byte from the hash oracle.

Attack overview
---------------
Pick L1 = 183. We chose this because:
  * L1 mod 64 = 55  →  pad(L1) is the *minimum* MD5 padding length, 9 bytes
  * L1 mod 46 = 45  →  cycle(FLAG)[L1 .. L1+9] indexes
                       FLAG[45], FLAG[0], FLAG[1], ..., FLAG[7]
                       i.e. one unknown (FLAG[7]) and eight knowns

Then:

  Step 0  Send data1 = b"\\x00" * L1.
          salted1 = cycle(FLAG)[0..L1] (we don't know it),
          but the server returns h1 = md5(salted1).

  Step 1  Recover FLAG[7] with 256 queries.
          Construct, for each guess g in 0..255,
            data2[0..L1]   = b"\\x00" * L1
            data2[L1..L1+9] = pad(L1) XOR (b"}crypto{" || bytes([g]))
          If g == FLAG[7] then salted2[L1..L1+9] = pad(L1), so the entire
          message hashed by the server is exactly salted1 || pad(L1), and the
          server's md5 equals length_extend(h1, L1, b"")  — a hash we can
          compute offline. Whichever g matches reveals FLAG[7].

  Step 2  Recover FLAG[8..44] with 1 query each.
          Now that we know FLAG[7], we can correctly construct
          data2[L1..L1+9] = pad(L1) XOR cycle(FLAG)[L1..L1+9] for *real*.
          Append one extra byte data2[L1+9] = 0; then
            salted2[L1+9] = 0 XOR FLAG[(L1+9) mod 46]
                          = FLAG[8]   (since (L1+9) mod 46 = 192 mod 46 = 8)
          The server returns md5(salted1 || pad(L1) || FLAG[8]).
          Offline, predict 256 candidates length_extend(h1, L1, bytes([g]))
          and pick the matching one.
          Append two extra bytes for FLAG[9], etc.

The same script, with HOST = "socket.cryptohack.org", retrieves the real flag.
Total queries: ~256 (FLAG[7]) + 38 (FLAG[8..44]) ≈ 295.
"""

import json
import socket
import sys
from pathlib import Path

# Make tools/ importable
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "lib"))
from md5_ext import md5_continue, md5_pad  # noqa: E402

HOST = "socket.cryptohack.org"
PORT = 13407
TIMEOUT = 30


def open_session():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # consume "Enter data\n"
    return sock, f


def query(f, data: bytes) -> str:
    f.write((json.dumps({"option": "message", "data": data.hex()}) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    resp = json.loads(line.decode())
    if "hash" not in resp:
        raise RuntimeError(f"unexpected response: {resp}")
    return resp["hash"]


def main() -> None:
    # FLAG length is known for this CryptoHack challenge. The previous
    # binary-search probe proved flaky because the server drops the socket
    # on short-data error responses and rate-limits rapid reconnects.
    flag_len = 46
    sock, f = open_session()
    try:
        print(f"[+] FLAG length = {flag_len} (hardcoded)")

        L1 = 183
        assert L1 % 64 == 55, "L1 must give the 9-byte minimum MD5 pad"
        assert L1 % flag_len == flag_len - 1, "L1 must align cycle so window starts at FLAG[-1]"

        # Step 0: get h1 = md5(cycle(FLAG)[:L1])
        h1 = query(f, b"\x00" * L1)
        print(f"[+] h1 = {h1}")

        pad_L1 = md5_pad(L1)
        assert len(pad_L1) == 9
        # cycle(FLAG)[L1..L1+9] indexes FLAG[45,0,1,2,3,4,5,6,7]
        known_window_prefix = b"}crypto{"  # FLAG[45], FLAG[0..6]
        assert len(known_window_prefix) == 8

        # Step 1: brute-force FLAG[7] (256 queries)
        h_target = md5_continue(h1, L1, b"")  # md5(salted1 || pad(L1))
        flag7 = None
        for g in range(256):
            data2 = bytearray(b"\x00" * L1)
            cycle_window = known_window_prefix + bytes([g])  # 9 bytes
            data2.extend(bytes(pad_L1[i] ^ cycle_window[i] for i in range(9)))
            assert len(data2) == L1 + 9
            h_resp = query(f, bytes(data2))
            if h_resp == h_target:
                flag7 = g
                break
        if flag7 is None:
            raise RuntimeError("FLAG[7] not found")
        print(f"[+] FLAG[7] = {flag7!r} ({chr(flag7)!r})")

        # Step 2: leak FLAG[8..44] (1 query each)
        flag = bytearray(b"crypto{" + bytes([flag7]))   # known so far: FLAG[0..8)
        # We extend the data2 with bytes whose corresponding salted bytes are
        # FLAG[8], FLAG[9], ... etc.
        # Position L1 + 9 + i in data2 corresponds to cycle index L1 + 9 + i,
        # which is FLAG[(L1 + 9 + i) mod flag_len] = FLAG[8 + i].
        for k in range(8, flag_len - 1):  # learn FLAG[8] .. FLAG[44]
            i = k - 8  # 0-based extension byte index
            data2 = bytearray(b"\x00" * L1)
            cycle_window = b"}" + flag[:8]  # FLAG[45], FLAG[0..7]
            assert len(cycle_window) == 9
            data2.extend(bytes(pad_L1[j] ^ cycle_window[j] for j in range(9)))
            # extension bytes at positions L1+9..L1+9+i+1
            # set them to FLAG[8..8+i] XOR cycle (i.e. salted = FLAG bytes themselves...
            # easier: use the *salted* byte we want, then XOR with the FLAG byte we know).
            for j in range(i):
                data2.append(flag[8 + j] ^ flag[8 + j])  # = 0 (any constant works,
                                                          # but this matches the prediction
                                                          # if we set salted-style below)
            # last extension byte: data2[...] = 0, salted = FLAG[8 + i]
            data2.append(0x00)

            h_resp = query(f, bytes(data2))

            # Build the predicted extension as it appears in `salted2[L1+9..]`.
            # salted2[L1 + 9 + j] = data2[L1 + 9 + j] XOR FLAG[(L1 + 9 + j) mod flag_len]
            #                     = data2[L1 + 9 + j] XOR FLAG[8 + j]
            # For j in 0..i-1 we set data2[L1+9+j] = 0 (after the change below), so
            #     salted2[L1+9+j] = FLAG[8 + j]   (which we know)
            # For j == i we set data2[L1+9+j] = 0 too, so salted2[L1+9+j] = FLAG[8+i],
            # which we want to leak.
            # ⇒ Try every g for FLAG[8+i] in the offline prediction.

            # NOTE: above I set data2[L1+9+j] = flag[8+j] XOR flag[8+j] = 0 for j<i.
            # That's actually 0, same as the last byte. So salted2[L1+9..L1+9+i+1] is
            # FLAG[8..8+i+1] -- 8 bytes we know plus the unknown one.
            known_ext_prefix = bytes(flag[8 : 8 + i])  # i bytes we already know
            found = None
            for g in range(256):
                ext = known_ext_prefix + bytes([g])
                if md5_continue(h1, L1, ext) == h_resp:
                    found = g
                    break
            if found is None:
                raise RuntimeError(f"FLAG[{k}] not found")
            flag.append(found)
            print(f"[+] FLAG[{k}] = {found!r} ({chr(found) if 32 <= found < 127 else '?'!r})  partial = {bytes(flag).decode(errors='replace')}")

        # Append the known last byte
        flag.append(ord("}"))
        print()
        print("FLAG:", bytes(flag).decode(errors="replace"))
    finally:
        sock.close()


if __name__ == "__main__":
    main()
