# infra/ — CryptoHack CTF environment reproduction

A complete recipe for rebuilding this repo's solver environment on a fresh machine.

## Python

- **Version**: 3.12.10 (64-bit)
- **Location (current host)**: `C:\Users\UserK\AppData\Local\Programs\Python\Python312\`
- Any 3.12.x works. Lower limit 3.10 untested; 3.13 may break `python-flint` wheels.

## Install — pure Python (pip) side

```bash
pip install -r infra/requirements.txt
```

Covers **everything in `cryptohack/**/solve*.py` and `tools/*.py`** except
problems explicitly marked *(SageMath 필요)* in the root `README.md`.

### Package-by-package breakdown

See `requirements.txt` — each line has a popularity count and a one-line
justification so you can verify what's used where.

### Windows-specific notes

- `gmpy2`, `python-flint`, `galois` all ship pre-built wheels for CPython
  3.12 x64 on Windows — no MSVC toolchain required.
- `pwntools` on Windows has limitations (no ptrace, some pty features) but
  the socket/remote functionality used by every CryptoHack solver works.
- `scapy` needs WinPcap/Npcap for live capture, **but** all solvers here
  only read `.pcap` files (`rdpcap`), which works without any driver.

### Reproducibility check

After install, verify with:

```bash
python -c "import Crypto, numpy, pwn, sympy, requests, scapy, cryptography, \
gmpy2, PIL, galois, mpmath, flint, ecdsa, py_ecc, owiener, pkcs1, primefac; \
print('all imports ok')"
```

## Heavy-lifting sidecars (Docker)

### SageMath — `infra/sagemath.md`

Full Sage environment for curve arithmetic, BKZ, isogenies, extension-
field DLPs, etc. Pulled as the prebuilt `sagemath/sagemath:latest`
Docker image (~4.8 GB). Use via `bash infra/sage-run.sh <script.sage>`.

See `infra/sagemath.md` for the install + usage patterns, including
the Python-collects-then-Sage-computes hybrid pattern we use
throughout the repo.

### HashClash — `infra/hashclash.md`

Marc Stevens' MD5 collision toolkit (fastcoll for IPCs, fastcpc.sh for
chosen-prefix collisions). Built as a custom Docker image via
`infra/Dockerfile.hashclash` with **CUDA acceleration** — an NVIDIA GPU
cuts a full CPC from ~4-8 hours down to ~30-60 minutes.

See `infra/hashclash.md` for build + GPU passthrough instructions.

### PARI/GP standalone (lightweight alternative)

For finite-field DLP only (no curves, no isogenies, no lattices), a 12
MB standalone `gp64-*.exe` Windows binary is enough and avoids the ~5
GB Sage image. Download:

```bash
curl -o "$HOME/AppData/Local/Temp/pari/gp.exe" \
    https://pari.math.u-bordeaux.fr/pub/pari/windows/gp64-2-17-3.exe
```

Set `default(parisize, 4000000000);` at the top of any `.gp` script
that uses `fflog` — the 8 MB default stack overflows on extension
fields. See `cryptohack/Diffie-Hellman/Misc/The Matrix Revolutions/`
(`dlp.gp` + `solve.py`) for a worked example.

### fastcoll (lightweight MD5 IPC)

For **identical-prefix** MD5 collisions (seconds, no GPU):

```bash
curl -sL https://marc-stevens.nl/research/hashclash/fastcoll_v1.0.0.5.exe.zip \
    -o /tmp/fastcoll.zip
unzip /tmp/fastcoll.zip -d ~/AppData/Local/Temp/fastcoll/
```

See `cryptohack/Hash Functions/Collisions/PriMeD5/` for a solver that
loops fastcoll until one side of the collision is prime and the other
composite.

## What each category needs

| Category | Python | Sage | HashClash | PARI standalone |
|---|---|---|---|---|
| Introduction, General, Symmetric, Mathematics, RSA | ✅ | | | |
| Diffie-Hellman | ✅ | | | ✅ (Matrix Revolutions GF(2^89) DLP) |
| Elliptic Curves | ✅ | ✅ (Smooth Criminal, Micro Transmissions) | | |
| Hash Functions | ✅ | | ✅ (Twin Keys CPC) | |
| Crypto on the Web | ✅ | | | |
| Lattices | ✅ | ✅ (harder BKZ) | | |
| Isogenies | | ✅ (all remaining) | | |
| ZKPs | ✅ | | | |
| Misc | ✅ | | | |

## Local helper modules (`tools/`)

The `tools/` folder contains hand-rolled modules that are **NOT on PyPI**:

- `tools/fast_lll.py` — Pure-Python LLL + Babai nearest-plane (fallback when
  Sage's `LLL()` isn't available). Used by some lattice solvers.
- `tools/md5_ext.py` — MD5 length-extension / internal-state helpers
  (length-extension category).
- `tools/trunc_lcg.py` — Truncated LCG seed recovery via LLL (PRNG category).
- `tools/utils/` — Miscellaneous shared helpers (e.g., socket protocol
  parsers used by multiple servers).

These are imported as `from tools.fast_lll import ...` etc., so running
solvers requires being at the **repo root** (so `tools/` is on `sys.path`)
or having `PYTHONPATH=.` set.

## Directory layout

```
infra/
├── README.md            ← this file
├── requirements.txt     ← pip freeze (audited, not full freeze)
├── Dockerfile           ← minimal Sage wrapper image (optional)
├── sage-run.sh          ← thin wrapper to run Sage scripts via Docker
└── verify.sh            ← "does my env work?" smoke test
```

## Not covered by this infra

- Browser-based / live TLS query challenges (`Secure Protocols`, `Saying Hello`)
- GPU-accelerated compute (not currently needed)
- Heavy factoring tools like CADO-NFS / msieve (not currently needed)
