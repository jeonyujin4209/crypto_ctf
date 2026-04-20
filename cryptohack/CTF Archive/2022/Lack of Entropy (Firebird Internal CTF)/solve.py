"""
q = int(gmpy2.digits(p, 3)): q의 십진수 digit = p의 3진수 digit (모두 {0,1,2}).
Attack: MSB부터 digit d∈{0,1,2} 탐색. 나머지 remainder bound로 pruning.
  r = n - p_high*q_high, UB = p_high*q_rem_max + q_high*p_rem_max + cross
  (all remaining digits=2일 때 최대) → 각 step에서 유효 digit이 1개뿐 → O(L) 탐색.
"""

import gmpy2
from Crypto.Util.number import long_to_bytes

n = gmpy2.mpz(12189464288007059657184858632825479990912616419482466046617619319388181010121359489739982536798361842485210016303524715395474637570227926791570158634811951043352789232959763417380155972853016696908995809240738171081946517881643416715486249)
e = 65537
c = gmpy2.mpz(10093874086170276546167955043813453195412484673031739173390677430603113063707524122014352886564777373620029541666833142412009063988439640569778321681605225404251519582850624600712844557011512775502356036366115295154408488005375252950048742)


def try_solve(L):
    pow3  = [gmpy2.mpz(3) ** i for i in range(L + 1)]
    pow10 = [gmpy2.mpz(10) ** i for i in range(L + 1)]

    # DFS: (pos, p_high, q_high)
    # pos: 다음에 채울 digit 위치 (L-1부터 0까지)
    stack = [(L - 1, gmpy2.mpz(0), gmpy2.mpz(0))]

    while stack:
        pos, p_h, q_h = stack.pop()

        for d in (2, 1, 0):
            if pos == L - 1 and d == 0:
                continue  # 최상위 digit은 0 불가

            new_p = p_h + d * pow3[pos]
            new_q = q_h + d * pow10[pos]
            new_r = n - new_p * new_q

            if new_r < 0:
                continue

            if pos == 0:
                if new_r == 0:
                    return int(new_p), int(new_q)
            else:
                # 나머지 digit이 모두 2일 때의 최대 p_rem, q_rem
                p_rem_max = pow3[pos] - 1
                q_rem_max = 2 * (pow10[pos] - 1) // 9
                UB = new_p * q_rem_max + new_q * p_rem_max + p_rem_max * q_rem_max
                if new_r <= UB:
                    stack.append((pos - 1, new_p, new_q))

    return None, None


# n ∈ [3^{L-1}*10^{L-1}, 3^L*10^L) = [30^{L-1}, 30^L) 에서 L 추정
import math
L_est = int(math.log(int(n)) / math.log(30)) + 1

print(f"Estimated L = {L_est}")

for L in range(L_est - 2, L_est + 3):
    print(f"Trying L={L} ...")
    result = try_solve(L)
    if result and result[0] is not None:
        p, q = result
        assert p * q == n
        print(f"p = {p}")
        print(f"q = {q}")
        phi = (p - 1) * (q - 1)
        d_rsa = int(gmpy2.invert(e, phi))
        m = pow(int(c), d_rsa, int(n))
        print(long_to_bytes(m))
        break
