"""
FaILProof (SekaiCTF 2022) solver.

취약점
------
- 서버가 비밀 secret을 출력해준다 → pubkey A를 재구성 가능.
- gen_pubkey: sha256 chain으로 128개의 256-bit 정수 A_i 생성.
- encrypt: 메시지를 32-byte 블록(256-bit B)으로 쪼개고 각 블록마다
  [happiness(A_i AND B) for A_i in A] 출력.
- happiness(x) = x - sum(x>>i for i in 1..bit_length-1)
               = popcount(x)  (증명: Σ floor(x/2^i) = x - popcount(x))

따라서 각 블록에 대해 128개 선형 방정식
     Σ_j A_bits[i][j] · b_j = c_i   (정수, 0 ≤ b_j ≤ 1)
를 얻는다. 256 이진 미지수, 128 제약 → 무작위 A에 대해 해는 유일.

풀이
----
Binary ILP (pulp + CBC). 블록당 ~0.2 s.
"""
import hashlib
import pulp
from pwn import remote

HOST, PORT = 'archive.cryptohack.org', 42351
N_BITS = 256
M_EQS = 128


def gen_pubkey(secret_bytes):
    state = hashlib.sha256(secret_bytes).digest()
    pub = []
    for _ in range(M_EQS):
        pub.append(int.from_bytes(state, 'big'))
        state = hashlib.sha256(state).digest()
    return pub


def solve_block(A_bits, c):
    prob = pulp.LpProblem("block", pulp.LpMinimize)
    x = [pulp.LpVariable(f"x{j}", cat='Binary') for j in range(N_BITS)]
    prob += 0
    for i in range(M_EQS):
        idx = [j for j in range(N_BITS) if A_bits[i][j]]
        prob += pulp.lpSum(x[j] for j in idx) == c[i]
    prob.solve(pulp.PULP_CBC_CMD(msg=0))
    assert pulp.LpStatus[prob.status] == 'Optimal', f"ILP status {pulp.LpStatus[prob.status]}"
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
        B = solve_block(A_bits, c)
        chunk = B.to_bytes(32, 'big')
        print(f"block {idx}: {chunk!r}")
        out += chunk
    # Strip null padding
    out = out.rstrip(b'\x00')
    print("=" * 40)
    print(out)


if __name__ == '__main__':
    main()
