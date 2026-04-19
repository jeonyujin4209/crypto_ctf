---
name: dlog-unknown-modulus-gcd-recovery
description: h = pow(g, M, p) with (g, p) hidden but M attacker-controlled (via message prefix structure). Force consecutive exponents M, M+1, M+2, M+3 by single-byte edits; then h2^2 - h1*h3 ≡ 0 mod p (= g^(2M+2) twice). GCD of 2-3 such relations recovers p exactly.
type: attack
---

# Recover Hidden Prime `p` from `g^M mod p` via Consecutive-Exponent GCD

## 유형
Black-box keyed hash / commitment / "MAC" of form:
```
H(m) = pow(g, prefix_encode(m), p)      # (g, p) secret, p ~ 256-bit prime
```
where `prefix_encode` is a deterministic injection that the attacker can nudge by small known offsets. Classic pattern:
```
prefix_encode(m) = int.from_bytes(FIXED_PREFIX + m, 'big')
                 = PRE_INT * 256^|m| + int(m)
```

## 왜 안전해 보이나
- `p`, `g` 비공개 → 결과 `H(m)`만 하위 채널로 관찰 가능
- `g^M mod p`의 결과는 `p`에 대한 정보를 직접 drop하지 않는 것처럼 보임
- DLP 관점에서 `p` 자체 복구는 **trivial하게 보이지 않음**
- 출력이 단순히 32-byte truncated도 OK (bit-length만 맞으면 됨)

## 공격 핵심
공격자는 `m`을 선택하므로, **M의 값**은 `(PRE, |m|, int(m))` 함수로 완전히 공지된다. 두 메시지 `m_a`, `m_b`가 **길이 같고 마지막 바이트만 다르게** 만들면:

```
M_b - M_a = int(m_b) - int(m_a)   # 1, 2, 3, ... 가능
```

`M_{i+1} = M_i + 1`로 4개 준비:
```
h_i = g^(M_1 + i)  mod p,   i = 0,1,2,3
```

Then `g^(M_1+1) * g^(M_1+1) = g^(M_1) * g^(M_1+2)`, so
```
h_2^2 ≡ h_1 * h_3   (mod p)
h_3^2 ≡ h_2 * h_4   (mod p)
h_2 * h_3 ≡ h_1 * h_4   (mod p)
```

각 관계식에서 LHS - RHS는 **일반 정수 산술**로 계산 가능 (결과 ~2^512). 전부 `p`의 배수.

```python
X = h2*h2 - h1*h3    # = k_X * p
Y = h3*h3 - h2*h4    # = k_Y * p
Z = h2*h3 - h1*h4    # = k_Z * p
p_guess = gcd(gcd(X, Y), Z)
```

`gcd(k_X, k_Y, k_Z) = 1`일 확률이 압도적이므로 `p_guess = p * (small)` 정도. 작은 소수 (2,3,5,7,...)를 trial-division으로 제거 후 `is_prime` 확인.

## g 복구
```
g ≡ h_{i+1} * h_i^{-1}  (mod p)   (since M_{i+1} = M_i + 1)
```
한 번 `p`가 알려지면 modular inverse 즉시 가능.

```python
g = (h2 * pow(h1, -1, p)) % p
assert pow(g, M1, p) == h1
```

## 쿼리 예산
| queries | relations | GCD |
|---|---|---|
| 2 | 0 | 불가 (한 개 값만으로 `p` 판별 불가) |
| 3 | 1 (`h_2^2 - h_1 h_3`) | GCD 한 개 → 큰 `k` 나옴. 512-bit factoring 필요 |
| 4 | **3** relations | **GCD 하나로 `p * O(1)`** → 실전 권장 |
| 5 | 6 | safety margin |

**4 queries로 확정** — 남은 쿼리는 실제 공격(충돌, flag)에 사용.

## 충돌 단계 (p 알 때)
`H(m) ≡ H(target) (mod p)` → `M(m) ≡ M(target) (mod ord(g))`. `ord(g) | p-1`.

구하기 가장 단순한 접근:
- `M(m) ≡ M(target) (mod p-1)` 조건을 만족하는 `m`을 Kannan/LLL knapsack 으로 검색
- 알파벳 제한 (e.g. [a-z]) → `y_i ∈ [-12, 13]` centered coefficient
- Lattice dim `L+2`, L은 메시지 길이. 적절한 L (≈ log_26(N) * 1.1 정도, 260-bit N이면 L=60) + BKZ block_size=20 조합이 실전에서 바로 풂

## 실전 팁
- **prefix의 역할**: `PRE * 256^L` 부분은 known constant offset — `E = (M_target - PRE*256^L - shift_sum) mod N` 로 흡수
- **BKZ sign 뒤집힘**: Kannan 표준 형태는 target=`-t` 임 (`lwe-kannan-embedding-sign-trap`). LLL 출력 row의 마지막 좌표가 ±K 둘 다 나옴 → 양쪽 부호 전부 시도
- **Sage에서 `sys.exit(0)` 주의**: preparser가 exit code를 0으로 클린하게 전달 안 함 → `raise SystemExit(0)` 쓰거나 stdout `RESULT:` 라인으로 통신
- **Windows/docker 경로**: `D:\foo` → `/d/foo` 변환 필요. `MSYS_NO_PATHCONV=1` 환경변수로 git-bash 자동변환 억제

## 적용 가능
- RSA / DLP with unknown modulus 가 아닌 **prefix-encoded 메시지**의 group-exponentiation hash
- Schnorr-like commitment `g^r mod p` with attacker-influenced `r`
- 연속 정수 exponent를 강제할 수 있는 곳이면 어디든 (예: counter-based HMAC alternatives)

## 적용 불가
- Exponent `M`이 비결정적 (server-added randomness, nonce)
- 출력이 **hash of pow** (e.g. `SHA256(pow(g, M, p))`) — 정수 관계식 잃음
- 같은 `p`에 대해 **쿼리당 g 재샘플링** — relation이 `g`가 섞여서 단순한 형태 아님

## 출처
- CryptoHack CTF Archive 2022: C0ll1d3r (Firebird Internal CTF, MystizConnect)
  - 256-bit random `p`, 256-bit `g`, prefix `SECUREHASH_`, 5 queries
  - 4 queries로 `p`, `g` 복구 → LLL로 충돌 메시지 → 5번째 쿼리로 flag
  - Flag: `firebird{wh3n_1n_d0ub7_u5e_latt111c3_r3duc71110n_4lg0r111thm}`
