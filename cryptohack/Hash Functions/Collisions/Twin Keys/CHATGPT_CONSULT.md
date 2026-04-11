# Twin Keys — Consultation Request

I'm stuck on CryptoHack's **Twin Keys** (100pts, Hash Functions / Collisions)
at `socket.cryptohack.org 13397`. I've done a thorough analysis and all roads
seem to lead to running HashClash chosen-prefix collision (CPC) which is
taking hours. I want a sanity check: am I missing a shortcut, or is this
genuinely the intended ~hours-on-GPU workload for 100 points?

## 1. Server source (`13397.py`)

```python
import os
import random
from Crypto.Hash import MD5
from utils import listener


KEY_START = b"CryptoHack Secure Safe"       # 22 bytes, fixed
FLAG      = b"crypto{????????????????????????}"


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


class SecureSafe:
    def __init__(self):
        self.magic1 = os.urandom(16)        # fresh per connection
        self.magic2 = os.urandom(16)        # fresh per connection
        self.keys = {}

    def insert_key(self, key):
        if len(self.keys) >= 2:
            return {"error": "All keyholes are already occupied"}
        if key in self.keys:
            return {"error": "This key is already inserted"}

        self.keys[key] = 0
        if key.startswith(KEY_START):
            self.keys[key] = 1

        return {"msg": "Key inserted"}

    def unlock(self):
        if len(self.keys) < 2:
            return {"error": "Missing keys"}
        if sum(self.keys.values()) != 1:
            return {"error": "Invalid keys"}

        hashes = []
        for k in self.keys.keys():
            hashes.append(MD5.new(k).digest())

        # "Encrypting the hashes with secure quad-grade XOR encryption"
        # "Using different randomized magic numbers to prevent the hashes
        #  from ever being equal"
        h1 = hashes[0]
        h2 = hashes[1]
        for i in range(2, 2 ** (random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)

        assert h1 != bytes(bytearray(16))

        if h1 == h2:
            return {"msg": f"The safe clicks and the door opens. "
                           f"Amongst its secrets you find a flag: {FLAG}"}
        return {"error": "The keys does not match"}


class Challenge:
    def __init__(self):
        self.securesafe = SecureSafe()
        self.before_input = "Can you help find our lost keys to unlock the safe?\n"

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}
        elif your_input["option"] == "insert_key":
            # note: due to listener, key intentionally limited to 1024 bytes
            key = bytes.fromhex(your_input["key"])
            return self.securesafe.insert_key(key)
        elif your_input["option"] == "unlock":
            return self.securesafe.unlock()
        else:
            return {"error": "Invalid option"}
```

Client protocol (JSON over TCP via CryptoHack's generic listener):

```json
{"option": "insert_key", "key": "<hex>"}        // insert key (1st or 2nd slot)
{"option": "unlock"}                            // finalize
```

Exactly 2 distinct keys can be inserted per connection. Each key goes
through `bytes.fromhex(...)` so it's arbitrary bytes, 1024-byte cap.

## 2. What I've verified

### 2a. The XOR "scrambler" is the identity function for every N this challenge can pick

The loop body simplifies algebraically (I double-checked by running the
exact code in Python on 100k random inputs):

```
new_h1 = magic1 ^ h1       # the nested xor collapses
new_h2 = magic2 ^ h2       # same
```

So each iteration is `(h1, h2) ↦ (h1 ^ m1, h2 ^ m2)`. After two iterations
we're back to `(h1, h2)` (magic XORs cancel). Therefore after any **even
number of iterations** the scrambler is the identity.

The loop count is `len(range(2, 2**k))` where `k = random.randint(2, 10)`,
so it takes one of the values `{2, 6, 14, 30, 62, 126, 254, 510, 1022}` —
**all even**, always. Empirically verified in Python for 100k random
`k` samples: every count is even.

**Conclusion**: after the scrambler, `h1 = MD5(k1)` and `h2 = MD5(k2)`,
no matter what `magic1, magic2` are. The comment in the source says the
magics "prevent the hashes from ever being equal", but that's the bug —
they don't. The author intended a non-trivial scrambler that masks
collisions, but wrote an involution.

### 2b. Win condition

```
sum(keys.values()) == 1           ⟺ exactly one key starts with KEY_START
h1 == h2 (after scrambler)        ⟺ MD5(k1) == MD5(k2)
h1 != 16 zero bytes               ⟺ trivially true (no MD5 preimage to 0)
```

So we need **two distinct byte strings k1, k2 such that one starts with
`"CryptoHack Secure Safe"` (22 bytes), the other doesn't, and
`MD5(k1) == MD5(k2)`**.

This is textbook **MD5 chosen-prefix collision** (CPC): prefix1 must
literally be `KEY_START`, prefix2 can be anything not starting with
`KEY_START`.

### 2c. Sanity checks I've already eliminated

| Idea | Verdict |
|---|---|
| Insert the same key twice | Blocked by `if key in self.keys`. Bytes equality is byte-for-byte — no Python quirk helps. |
| Make both keys hash to all-zero (exploit the `assert`) | Needs MD5 preimage → infeasible. |
| Exploit `sum` on dict values | Values are always literal `0` or `1`. Can't inject other types. |
| JSON-parsing / listener bug | `bytes.fromhex` on a string, result always plain bytes. |
| `random.randint` returning odd N, making the scrambler non-identity | All `2^k - 2` for `k ≥ 2` are even. |
| `random` module predictability | Even if we predicted N, N-parity doesn't matter (always even). |
| Length-extension / Wang IPC pair | An IPC gives two messages with *identical* prefix — both keys would either start with KEY_START or neither would. Fails the `sum == 1` check. |
| `key.startswith` quirks, Unicode hex, bytes subclassing via JSON | None of these work — `bytes.fromhex` always returns plain `bytes`. |

Nothing non-CPC survives.

## 3. What I've tried to actually solve it

### 3a. Infrastructure
- Windows 11 host, RTX 4060 Ti, Docker Desktop + WSL2, GPU passthrough
  confirmed (`docker run --gpus all nvidia/cuda:… nvidia-smi` works).
- Built Marc Stevens' HashClash from source with `--with-cuda=/usr/local/cuda`;
  `ldd md5_birthdaysearch | grep cuda` shows `libcudart.so.12` linked in.
- Also downloaded **`hashclash-static-release-v1.2b`** (what the SHCTF 2026
  hash3 writeup points at — that contest had a sibling challenge derived
  from Twin Keys) and run its binaries inside `nvidia/cuda:11.4.3-runtime-ubuntu18.04`.
- Had to patch `--trange VALUE` → `--trange=VALUE` in `poc_no.sh` / `cpc.sh`
  because the static-release binaries' Boost program_options was ambiguously
  matching `--trange` onto `--tstep` otherwise.

Both HashClash variants (my CUDA build from source, and the upstream static
release) exhibit identical behaviour on our prefixes.

### 3b. `poc_no.sh` (HashClash's "single-bit differential" IPC)

This is what the SHCTF hash3 writeup uses with `prefix="SHCTF2025ISFUNNY"`.
It produces two 128-byte colliding messages that differ in exactly two bytes
(the `--diffm2 9` differential puts the flip at byte 9 of each 64-byte MD5
block). For the hash3 challenge this is perfect because hash3 only requires
"first 16 bytes of m1 ≠ first 16 bytes of m2" and alphanumeric.

I tried `poc_no.sh` with our 22-byte `prefix.bin = "CryptoHack Secure Safe"`:

- Output was two 128-byte `collision1.bin` / `collision2.bin` with matching
  MD5 ✅
- Diffs at byte 9 (`k` ↔ `l`) and byte 73 ✅
- But the outputs' first 22 bytes are `b"CryptoHack Secure Sa\xf2\xce"` and
  `b"CryptoHacl Secure Sa\xf2\xce"` — **the prefix is only preserved up to
  byte 19; bytes 20–21 are random bytes from the collision search**.

Why: with a 22-byte prefix, MD5 is still in the first 64-byte block when
the differential path starts, and the collision-block search only fixes
bit-level constraints at specific positions. Bytes 20–21 (part of word
`m_5`) aren't constrained by the `--diffm2 9` path, so they get whatever
fastcoll's search produces.

Consequence: for `poc_no.sh` output to start with the full 22-byte
KEY_START we'd need bytes 20–21 to randomly equal `b"fe"`. That's
`1 / 65536` per run, and each run costs several minutes → expected ~hours
to days → not practical.

I tried both 20-byte and 21-byte prefix variants; same problem, just at a
different boundary.

### 3c. `cpc.sh` (proper chosen-prefix collision)

First mistake: passing 22-byte prefix files. The birthday search prints
`IHV1 == IHV2 == 0123456789abcdeffedcba9876543210` — i.e. the *standard*
MD5 init IV — because MD5 hasn't processed a full 64-byte block yet. So
effectively it's doing IPC from the init state, not a real CPC; the
"chosen prefix" is ignored.

Fix: pad to 64 bytes so MD5 actually processes a block and emits a real
non-trivial IHV:

```
p1 = b"CryptoHack Secure Safe" + b"\x00" * 42     # 64 bytes, starts with KEY_START
p2 = b"cryptoHack Secure Safe" + b"\x00" * 42     # 64 bytes, NOT KEY_START
```

With this, the birthday search correctly prints two different IHVs and a
real CPC run begins. The on-disk `file1.bin` after the birthday phase is
`p1 + (64-byte birthday block)` = 128 bytes — the prefix **is** preserved
verbatim at the start. Subsequent NC blocks get concatenated onto that.
So once `file1.bin.coll` and `file2.bin.coll` exist, my k1 and k2 would
begin with `p1` and `p2` respectively and satisfy the Twin Keys `startswith`
constraint.

The issue is runtime.

- `Detecting worklevel...: 32` (mid-range)
- First NC-block step ("step 0") `connect` phase is currently at
  `best path p ≈ 0.028` but the `collfind` loop has been running for
  ~45 min and only finds collision candidates very slowly
  (`79353 1`, `88860 2`, `189044 4`, `262144 5`, `698143 8` — i.e. 8
  best paths in ~700k iterations; prior runs needed 30+ best paths to
  produce an actual NC-block collision)
- The script's auto-killer retries step 0 after 4500s if `step0/killed`
  never appears — my `cpc.sh` timeout tuning matches the static release's
  defaults
- `cpc.sh` expects up to 7 total NC blocks per CPC. If each one takes
  around the same time, we're looking at ~4–8 hours total even with the
  RTX 4060 Ti + 12 CPU threads (the birthday search is GPU-accelerated
  but the differential-path connect / collision-find phases are CPU-bound)

Prior runs I've tried:
- 22-byte prefixes (broken, fell back to IPC-from-init)
- 22-byte `p2 = "CryptoHack Secure Saf!"` (bad worklevel, no collision in 90+ min)
- 64-byte prefix with `p2` differing only at byte 0 (`C` → `c`) — currently
  still in step 0 after ~1h

Each CPC run has high **per-seed variance**: the first run (the broken
one, which happened to do IPC-from-init with effective empty prefix)
finished step 0 in ~22 min; the "correct" 64-byte CPC runs I've launched
have all been much slower.

## 4. Comparison to the SHCTF 2026 hash3 writeup

[Chinese writeup on gm7.org / mp.weixin.qq.com](https://mp.weixin.qq.com/s/C3_3_gA7uoR666f_-2NJgA)
explicitly says hash3 is "derived from (题目来源: Cryptohack Twin Keys)"
but the server checks are different:

```python
# hash3
if len(apple1) <= 16 or len(apple2) <= 16:  ...
if not all(ch in table for ch in apple1[:16]) or ...:  ...
if apple1[:16] == apple2[:16]:  ...
if hash_apple1 != hash_apple2:  ...
```

hash3 only requires "first 16 bytes ≠ and both alphanumeric" + MD5 match.
That's satisfied by `poc_no.sh` output when the prefix is any 16-byte
alphanumeric string (like `"SHCTF2025ISFUNNY"`) — the byte-9 single-bit
flip is `'I' → 'J'`, both alphanumeric, done in minutes.

**Twin Keys' check is stricter**: `k1.startswith(b"CryptoHack Secure Safe")`
with a fixed 22-byte literal. The hash3 solving recipe doesn't transfer —
`poc_no.sh` can't force the full 22 bytes of both outputs to match a fixed
value, and `cpc.sh` is the only HashClash script that supports a true
chosen-prefix workflow.

## 5. Questions I'd like sanity-checked

1. **Is there a non-HashClash trick for Twin Keys that I'm missing?**
   Any cryptographic or implementation weakness I didn't catch? (The
   scrambler analysis especially — is the identity conclusion correct, or
   am I missing a parity case?)

2. **If HashClash CPC is the only path, is multi-hour runtime considered
   normal for a 100pt challenge?** Or are there tuning knobs (e.g.,
   different `--maxblocks`, `--pathtyperange`, `--hybridbits`, or different
   prefix2 choices) that make the common case much faster than what I'm
   seeing?

3. **Is there a canonical writeup / known-good `cpc.sh` invocation for
   Twin Keys specifically?** Ideally with rough wall-clock numbers so I can
   calibrate expectations.

4. **Is 64 bytes the right padded-prefix length, or should I pad to 128
   bytes (two full MD5 blocks)?** Does a longer prefix ever make the
   birthday search easier in practice?

5. **Any favour to different prefix2 choices** (one-bit flip vs letter
   case vs whole-byte change vs totally different ASCII) that's known to
   give easier differential paths?

Tool info:
- HashClash: `cr-marcstevens/hashclash` at commit tip of master, built
  with CUDA 12.6; also static-release `v1.2b`.
- GPU: RTX 4060 Ti (Ada, 8 GB VRAM).
- CPU: 12-thread modern laptop-class.

Thanks in advance.
