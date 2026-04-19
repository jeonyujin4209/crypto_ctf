"""
Functional (ICC Athens 2022) end-to-end solver.

Delegates the heavy Sage computation (BM + Jordan-block ITERS recovery +
matrix-exp for S3 + Kitamasa for j(ITERS)) to `solve.sage` running inside the
sagemath/sagemath Docker image, then does the final AES-ECB decryption in
Python (Sage docker lacks pycryptodome).

See solve.sage for attack details.
"""
import os, hashlib, subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HERE = os.path.dirname(os.path.abspath(__file__))
wd = HERE.replace('\\', '/')
mount = f'/{wd[0].lower()}{wd[2:]}'  # '/d/...'

env = os.environ.copy()
env['MSYS_NO_PATHCONV'] = '1'
cmd = ['docker', 'run', '--rm', '-v', f'{mount}:/work', '-w', '/work',
       'sagemath/sagemath:latest', 'sage', 'solve.sage']
print(f"Running Sage in Docker...")
res = subprocess.run(cmd, env=env, cwd=HERE, capture_output=True, text=True)
print(res.stdout)
if res.returncode != 0:
    print("STDERR:", res.stderr)
    raise SystemExit(res.returncode)

with open(os.path.join(HERE, 'j_iters.txt')) as f:
    j_iters = int(f.read().strip())

with open(os.path.join(HERE, 'output.txt')) as f:
    ct_hex = f.read().strip().split('\n')[-1].strip()
ct = bytes.fromhex(ct_hex)

key = hashlib.sha256(str(j_iters).encode()).digest()
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
print(f"flag = {flag.decode()}")
