#!/usr/bin/env bash
# Smoke test: verify the solver environment is complete on the current host.
# Run from the repo root: bash infra/verify.sh

set -e

echo "=== Python ==="
python --version

echo
echo "=== pip packages ==="
python - <<'PY'
mods = [
    ("Crypto",       "pycryptodome"),
    ("numpy",        "numpy"),
    ("pwn",          "pwntools"),
    ("sympy",        "sympy"),
    ("requests",     "requests"),
    ("scapy",        "scapy"),
    ("cryptography", "cryptography"),
    ("gmpy2",        "gmpy2"),
    ("PIL",          "Pillow"),
    ("galois",       "galois"),
    ("mpmath",       "mpmath"),
    ("flint",        "python-flint"),
    ("ecdsa",        "ecdsa"),
    ("py_ecc",       "py-ecc"),
    ("owiener",      "owiener"),
    ("pkcs1",        "pkcs1"),
    ("primefac",     "primefac"),
]
import importlib
fail = 0
for mod, pkg in mods:
    try:
        importlib.import_module(mod)
        print(f"  ok     {pkg:15s} ({mod})")
    except ImportError as e:
        print(f"  MISS   {pkg:15s} ({mod}) — {e}")
        fail += 1
if fail:
    print(f"\n{fail} package(s) missing — run: pip install -r infra/requirements.txt")
    raise SystemExit(1)
PY

echo
echo "=== repo-local helpers ==="
python - <<'PY'
import sys, os
sys.path.insert(0, os.getcwd())
for mod in ("tools.fast_lll", "tools.md5_ext", "tools.trunc_lcg"):
    try:
        __import__(mod)
        print(f"  ok     {mod}")
    except Exception as e:
        print(f"  FAIL   {mod} — {e}")
        raise SystemExit(1)
PY

echo
echo "=== PARI/GP standalone (optional) ==="
GP="${GP_EXE:-$HOME/AppData/Local/Temp/pari/gp.exe}"
if [ -x "$GP" ]; then
    echo "  ok     $GP"
    # Small znlog sanity test (discrete log in Z/(2^61-1)*)
    echo 'p=2^61-1; print(znlog(Mod(3,p)^12345, Mod(3,p)))' | "$GP" -q || true
else
    echo "  -      PARI gp.exe not found (only needed for some extension-field DLPs)"
fi

echo
echo "=== sagemath Docker image (optional) ==="
if command -v docker >/dev/null 2>&1; then
    if docker image inspect sagemath/sagemath >/dev/null 2>&1; then
        echo "  ok     sagemath/sagemath image present"
    else
        echo "  -      sagemath image not pulled (docker pull sagemath/sagemath)"
    fi
else
    echo "  -      docker not available"
fi

echo
echo "=== OK ==="
