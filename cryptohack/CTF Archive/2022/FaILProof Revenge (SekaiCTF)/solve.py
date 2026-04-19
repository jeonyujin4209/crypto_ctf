"""
FaILProof Revenge (SekaiCTF 2022) solver.

차이점 (original vs Revenge)
---------------------------
- sha256 → sha512 (hash 64B), pubkey 길이 = 64*4 = 256 (256-bit → 512-bit)
- segment_len = len(pubkey) // 32 = 8 (32 → 8 byte/block)
- block layout (64B): urandom(24) || msg(8) || urandom(32)
  → 메시지 바이트는 int의 bits 256..319 (MSB-first → to_bytes(64,'big')[24:32])
- encrypt: for each block_int, [popcount(A_i & block_int) for A_i in pub] (256 값)

취약점
------
여전히 `happiness == popcount`, 그리고 `popcount(A_i & x) = Σ_j A_{i,j} b_j`.
256개 Z-linear 등식 on 512 binary vars. ratio 1/2로 원래와 동일.
Information theoretically unique (각 등식 ~7 bit info → 1792 bit ≫ 512).
Random binary matrix에서 ILP가 유일해 반환.

풀이
----
pulp+CBC binary ILP per block (~0.85 s/block).
"""
import hashlib
import pulp
from pwn import remote

HOST, PORT = 'archive.cryptohack.org', 36813
N_BITS = 512
M_EQS = 256
SEG_LEN = 8


def gen_pubkey(secret_bytes):
    state = hashlib.sha512(secret_bytes).digest()
    pub = []
    for _ in range(M_EQS):
        pub.append(int.from_bytes(state, 'big'))
        state = hashlib.sha512(state).digest()
    return pub


def solve_block(A_bits, c):
    prob = pulp.LpProblem("block", pulp.LpMinimize)
    x = [pulp.LpVariable(f"x{j}", cat='Binary') for j in range(N_BITS)]
    prob += 0
    for i in range(M_EQS):
        idx = [j for j in range(N_BITS) if A_bits[i][j]]
        prob += pulp.lpSum(x[j] for j in idx) == c[i]
    prob.solve(pulp.PULP_CBC_CMD(msg=0))
    status = pulp.LpStatus[prob.status]
    assert status == 'Optimal', f"status {status}"
    b = [int(round(x[j].value())) for j in range(N_BITS)]
    return sum(b[j] << j for j in range(N_BITS))


def main():
    io = remote(HOST, PORT)
    secret_hex = io.recvline().strip().decode()
    enc_line = io.recvline().strip().decode()
    io.close()
    print(f"secret = {secret_hex}")
    secret = bytes.fromhex(secret_hex)
    enc = eval(enc_line, {"__builtins__": {}}, {})
    print(f"blocks = {len(enc)}")

    A = gen_pubkey(secret)
    A_bits = [[(A[i] >> j) & 1 for j in range(N_BITS)] for i in range(M_EQS)]

    out = b''
    for idx, c in enumerate(enc):
        assert len(c) == M_EQS
        block_int = solve_block(A_bits, c)
        padded = block_int.to_bytes(64, 'big')
        msg = padded[24:32]
        print(f"block {idx}: {msg!r}")
        out += msg
    out = out.rstrip(b'\x00')
    print("=" * 40)
    print(out)


if __name__ == '__main__':
    main()
