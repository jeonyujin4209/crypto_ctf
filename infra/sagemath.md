# SageMath via Docker — setup & usage patterns

SageMath is packaged as a Docker image — `sagemath/sagemath:latest`
(~4.8 GB on disk, SageMath 10.8, 2025-12-18 at time of writing). This
is the recommended way to run Sage on Windows without a full WSL2
distribution or native port.

## Pull

```bash
docker pull sagemath/sagemath:latest
```

One-shot verification (should print the Sage banner):

```bash
docker run --rm sagemath/sagemath sage --version
```

## Running a Sage script

From git-bash on Windows:

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
    -v "C:\\Users\\UserK\\Documents\\hackerone\\program\\crypto_ctf:/work" \
    -w "/work/path/to/problem/dir" \
    sagemath/sagemath sage script.sage
```

**Critical**: `MSYS_NO_PATHCONV=1` is required — without it, git-bash
rewrites `/work/...` into `C:/Program Files/Git/work/...` and Docker
fails with "invalid working directory". Same gotcha applies to every
Docker invocation from git-bash with an absolute Unix-style path in
`-w`.

## Wrapper script

`infra/sage-run.sh` handles the path conversion and the repo-root mount
for you:

```bash
bash infra/sage-run.sh path/to/script.sage
bash infra/sage-run.sh sage       # interactive REPL
bash infra/sage-run.sh shell      # bash shell in container
bash infra/sage-run.sh -c 'print(factor(42))'   # inline expression
```

The working directory inside the container is `/work`, which maps to
the repo root on the host. Relative paths in your Sage script resolve
against the repo root.

## Pattern: Sage + Python hybrid solvers

When a CryptoHack problem needs one Sage-only computation (curve order,
discrete log in an extension field, LLL/BKZ with larger dimensions) but
the rest is best done in Python:

1. Write a tiny `*.sage` script that does **only** the Sage-required
   step and writes the result to a plain text file (e.g., `order.txt`)
2. Run it once via `sage-run.sh` → Sage writes the file
3. Python `solve.py` reads the file and handles the rest (network I/O,
   crypto primitives, decryption)

This keeps the Sage dependency minimal, avoids the slow startup cost of
the Docker container on every run, and keeps the solver code in Python
which is easier to debug.

### Concrete examples in this repo

- **Smooth Criminal** (EC) — `order.sage` computes `E.order()` and
  `factor(...)`, writes `order.txt`. `solve.py` reads `order.txt` and
  runs Pohlig-Hellman + BSGS in pure Python.
- **Noise Cheap** (LWE2) — `collect.py` pulls samples from the server
  and saves `samples.json`. `solve.sage` does the BKZ + CVP and prints
  the flag.

## What Sage unblocks

Several categories in the repo root `README.md` are marked
*(SageMath 필요)*:

- Elliptic Curves: Smooth Criminal (done), Micro Transmissions (TODO)
- Isogenies: Road to SIDH (5), Road to CSIDH (5), Isogeny Challenges (7)
- Lattices: harder BKZ problems
- Misc: various

Essentially every problem that requires `EllipticCurve(...)`,
`discrete_log(...)` in an extension field, `BKZ(...)`, or isogeny
operations becomes solvable once the Sage image is present.

## Lightweight alternative: PARI/GP standalone

For **finite-field DLPs only** (no curves, no isogenies, no lattices),
a 12 MB standalone `gp64-*.exe` from
<https://pari.math.u-bordeaux.fr/pub/pari/windows/> is enough and
avoids the ~5 GB Sage image.

Download + install:

```bash
curl -o "$HOME/AppData/Local/Temp/pari/gp.exe" \
    https://pari.math.u-bordeaux.fr/pub/pari/windows/gp64-2-17-3.exe
```

Invoke as a subprocess with the stack size bumped (needed for extension
field ops that would otherwise overflow the 8 MB default):

```python
subprocess.run(
    [GP, "-q", "script.gp"],
    capture_output=True,
    text=True,
)
```

Your `.gp` script should start with:

```gp
default(parisize, 4000000000);
```

**Concrete example**: The Matrix Revolutions solver
(`cryptohack/Diffie-Hellman/Misc/The Matrix Revolutions/`) uses
`dlp.gp` + `solve.py` to reduce a GF(2^89) discrete log via PARI's
`fflog` — finishes in seconds where pure-Python Pollard rho would take
years.
