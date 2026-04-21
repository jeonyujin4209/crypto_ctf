"""Solve Unbalanced (ICC Athens 2022).

Challenge:
  N = p*q, 1024-bit. p = 256-bit, q = 768-bit (UNBALANCED: β_p = 0.25).
  d = 300-bit prime with d > N^0.292 (just above balanced Boneh-Durfee boundary).
  e = pow(d, -1, phi(N)). c = flag^e mod N.

Attack (maple3142):
  Use 3-variable polynomial f(x, y, z) = 1 + x(N+1-y-z), roots (k, p, q).
  Critical: do NOT collapse to bivariate via q=N/p; keep 3 variables and
  substitute y*z = N INSIDE the polynomial ring via `poly_sub`, which
  reduces every mixed y^a*z^b monomial to N^min * pure-y or pure-z power.

  This gives tight Coppersmith bound that IMPROVES with more unbalanced
  primes (β smaller → attack easier). Flag confirms: "unbalanced primes
  only make things worse".

LLL lattice ~66x66, solved in ~22s at m=t=5.
"""
import os
import subprocess
import sys
import time


HERE = os.path.dirname(os.path.abspath(__file__))


def run_sage(timeout=600):
    wdir = HERE.replace("D:", "/d").replace("\\", "/")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{wdir}:/work", "-w", "/work",
        "sagemath/sagemath:latest", "sage", "solve.sage",
    ]
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    sys.stderr.write(res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"sage failed (rc={res.returncode})")
    return res.stdout.strip()


def main():
    t0 = time.time()
    out = run_sage()
    print(f"[+] done in {time.time() - t0:.1f}s", file=sys.stderr)
    print(out)


if __name__ == "__main__":
    main()
