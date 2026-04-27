# Skills

AI가 삽질했거나 직접 쓴 패턴 정리. frontmatter `type` 기준으로 분류.

---

## 🔐 공격 기법 (Attack Recipes)

재사용 가능한 암호 공격 레시피.

- [aes-component-disable-key-recovery](attack/aes-component-disable-key-recovery.md) — AES 개별 컴포넌트(ARK/SB/SR/MC) 비활성화 시 각각의 약점으로 key 복구
- [arora-ge-binary-lwe](attack/arora-ge-binary-lwe.md) — Binary/bounded error LWE는 격자 대신 다항식 linearization → 가우스 소거
- [castryck-decru-sidh-attack](attack/castryck-decru-sidh-attack.md) — SIDH에서 3-torsion images 주어지면 Castryck-Decru로 비밀 isogeny 복구
- [coppersmith-approx-factor](attack/coppersmith-approx-factor.md) — `floor(D*sqrt(p))` 힌트에서 오류 ≈ 2*sqrt(p)/D; `small_roots(beta=0.5)`로 정확한 p 복구
- [csidh-genus-theory-ddh](attack/csidh-genus-theory-ddh.md) — CSIDH DDH: genus theory로 j-invariant의 isogeny class 판단, DH vs random 구별
- [fischlin-wi-distinguisher](attack/fischlin-wi-distinguisher.md) — Fischlin OR proof에서 RO hit count로 b=0/1 구별. count>1이면 b=1 확실
- [gaussian-int-padic-dlp](attack/gaussian-int-padic-dlp.md) — Z[i]/(p^2)* DLP에서 norm map + Paillier log로 p-파트 O(1); k bound < order면 partial PH만 써도 충분
- [partial-pohlig-hellman-bounded-key](attack/partial-pohlig-hellman-bounded-key.md) — k가 order보다 작으면 큰 factor 몇 개만 풀고 CRT + small brute force
- [groth16-rerandomization](attack/groth16-rerandomization.md) — Groth16 (A,B,C)에서 λ 재랜덤화 → (λ⁻¹A, λB, C)도 valid. 크레딧 파밍 가능
- [hamiltonicity-online-fs-grinding](attack/hamiltonicity-online-fs-grinding.md) — Online FS면 A 랜덤 재시도로 challenge=0 강제 가능 (Batch FS Ham2와 대비)
- [hastad-small-message-broadcast](attack/hastad-small-message-broadcast.md) — RSA e가 크더라도 m이 작으면 e개 미만 ciphertext로 Hastad broadcast attack 가능
- [hnp-biased-ecdsa-nonce](attack/hnp-biased-ecdsa-nonce.md) — Biased ECDSA nonce → Boneh-Venkatesan 격자. Sage 없으면 pure-Python LLL fallback
- [ecdsa-nonce-xor-d-hash-bit-lattice](attack/ecdsa-nonce-xor-d-hash-bit-lattice.md) — nonce k = d XOR z (d 비밀키, z 해시)이면 signature congruence가 d_i 비트에 linear mod q → Kannan embedding + LLL로 d 복구. AND/OR 등 다른 bitwise도 동일 프레임
- [isogeny-claw-mitm](attack/isogeny-claw-mitm.md) — 2^e-isogeny E1→E2를 MITM claw-finding으로 복구. DFS 양방향 + j-invariant 고정점 매칭
- [jwt-algorithm-confusion](attack/jwt-algorithm-confusion.md) — JWT RS256→HS256 algorithm confusion: RS256 공개키를 HMAC secret으로 서명 위조
- [matrix-dh-repeated-root-local-ring](attack/matrix-dh-repeated-root-local-ring.md) — Matrix DH에서 min_poly 중복근이면 DLP 없이 SECRET = λ·b/a로 즉시 복구
- [known-prng-game-graph-dp](attack/known-prng-game-graph-dp.md) — PRNG state 알면 미래 스트림 결정론 → graph DP로 최적 hit/stand 시퀀스 탐색. greedy(54%) vs DP(64%) 차이 결정적
- [mt-state-partial-leak-z3](attack/mt-state-partial-leak-z3.md) — random.random() 연속 624 floats → Z3 getnext() 큐 모델로 MT state 복원 (2 twist cycle = unique)
- [numpy-mt-32bit-seed-brute](attack/numpy-mt-32bit-seed-brute.md) — numpy.random.seed(32-bit)는 state[0]=seed. 첫 bytes(16) → untemper 후 numba로 2^32 brute ~3분
- [partial-precompute-short-password-mac](attack/partial-precompute-short-password-mac.md) — 짧은 pw hash-MAC challenge-response에서 chal_c 고정 + pw 1/N subset 정밀타격, reconnect N번까지
- [noisy-oracle-statistical-approach](attack/noisy-oracle-statistical-approach.md) — 노이즈 오라클에서 Sequential Halving 실패; Adaptive Top-2로 해결
- [patarin-linearization-mi-mq](attack/patarin-linearization-mi-mq.md) — MI(Matsumoto-Imai) 다변수 이차 공개키 → Patarin bilinear relation으로 선형화 복호
- [pohlig-hellman-ecdlp](attack/pohlig-hellman-ecdlp.md) — Smooth/small order ECDLP → Pohlig-Hellman. BSGS 전에 `factor(E.order())` 필수
- [prange-isd-xor-keystream-recovery](attack/prange-isd-xor-keystream-recovery.md) — n개 AES-CTR XOR 구조 + known-plaintext → syndrome decoding(Prange ISD)으로 키스트림 복구
- [rsa-last-byte-oracle-binary-search](attack/rsa-last-byte-oracle-binary-search.md) — last byte == 0x2e oracle에서 s ≡ 0x81 overflow 감지 → binary search로 m 복구
- [rsa-msb-byte-oracle-manger-variant](attack/rsa-msb-byte-oracle-manger-variant.md) — `hex(m).startswith("0x67")` MSB byte oracle: 양방향 Manger 변종. 다양한 i(lift count) + clean lift + 양쪽 boundary로 hit ⟺ m ∈ [hit_lo, hit_hi). 단일 cut binary search는 정수 산술 stall
- [sbox-invariant-subspace-birthday](attack/sbox-invariant-subspace-birthday.md) — SBOX invariant subspace(특정 비트=0 보존) + bit-index 보존 permute → 유효 capacity 축소, birthday 가능
- [sha256-length-extension-via-oracle](attack/sha256-length-extension-via-oracle.md) — Hash oracle에서 제어 바이트로 SHA256 padding 재현 → output을 intermediate state로 length extension
- [singular-curve-mapping](attack/singular-curve-mapping.md) — ECDLP 전 discriminant 체크. Singular 곡선은 F_p*/F_p+ 로 매핑해 DLP 해결
- [custom-hash-xor-finalization-noop](attack/custom-hash-xor-finalization-noop.md) — 커스텀 해시 finalization이 고정 입력으로 짝수번 XOR하면 no-op → 라운드 충돌로 환원
- [mmh3-seed-independent-differential-collision](attack/mmh3-seed-independent-differential-collision.md) — MurmurHash3_x86_32 모든 seed 동시 collision: 2-block trail (block1 diff `0x00040000` → ROTL13 → bit-31, `*5+c`가 top-bit XOR diff 보존; block2 diff `0x80000000`가 cancel). 8byte+공통suffix → bloom filter add/check 우회
- [ed25519-magic-malleability-and-identity-key](attack/ed25519-magic-malleability-and-identity-key.md) — Warner의 `python-ed25519` (SUPERCOP ref10): (1) S+L malleability — 같은 R, 다른 S로 검증, (2) identity verifying key + R=identity + S=0으로 임의 메시지 universal 위조. RFC 8032 검사들이 다 빠져 있음
- [base-conversion-shared-digit-rsa-factoring](attack/base-conversion-shared-digit-rsa-factoring.md) — `q=int(digits(p,k))` 구조: p의 k진 digit = q의 10진 digit → MSB-first greedy digit search로 O(L) 인수분해
- [dlog-unknown-modulus-gcd-recovery](attack/dlog-unknown-modulus-gcd-recovery.md) — `pow(g, M, p)` with hidden p: 연속 정수 M_i로 `h2²≡h1h3 mod p` 관계식 → GCD로 p 복구
- [mod-p-plus-mod-q-prf-hnp](attack/mod-p-plus-mod-q-prf-hnp.md) — `(prod%p + prod%q) % p` weak PRF에서 p >> q면 wrap 무시 → `<k,h> ≡ out - r_q (mod p)` HNP 격자 BKZ
- [weak-prf-fourier-magnitude-distinguisher](attack/weak-prf-fourier-magnitude-distinguisher.md) — marginal uniform처럼 보이는 PRF를 `|F_k|²` Fourier magnitude로 구별. Chi-square보다 강력
- [output-filter-arora-ge-degree-reduction](attack/output-filter-arora-ge-degree-reduction.md) — PRF output class마다 annihilator 차수 다르면, 낮은 차수 output만 필터해 Arora-Ge → 모노미얼 수 20×+ 감소
- [paillier-homomorphic-carry-oracle](attack/paillier-homomorphic-carry-oracle.md) — Paillier 가법 준동형 + PKCS padding oracle: all-carry delta로 separator carry 유발 → has_zero_byte 핑거프린트
- [popcount-hidden-bit-shifts](attack/popcount-hidden-bit-shifts.md) — `x - Σ floor(x/2^i) = popcount(x)`. 비트 쉬프트 합 위장 → popcount → AND-popcount는 Z-linear on bits
- [recurrence-jordan-block-no-dlp](attack/recurrence-jordan-block-no-dlp.md) — BM char poly에 중복 인수 (g(x))^k 있으면 companion에 Jordan block → M^n이 n의 polynomial → DLP 없이 n 복구
- [spn-sbox-ddt-anomaly-iterative-diff](attack/spn-sbox-ddt-anomaly-iterative-diff.md) — Custom SPN에서 S-box DDT 이상치 + parity-preserving permutation → iterative differential trail로 per-byte key 복구, round peeling으로 master K까지
- [crt-rsa-kp-kq-reduction-mod-e](attack/crt-rsa-kp-kq-reduction-mod-e.md) — CRT-RSA에서 k_p ≡ -(p-1)^-1 mod e. p mod e iterate만 해도 (k_p, k_q) 유일 → e^2 → e로 검색 축소
- [permuted-digits-hs-branch-prune](attack/permuted-digits-hs-branch-prune.md) — d_p, d_q hex digit permutation = σ에 선형. CRT 항등식 mod 16^(d+1) LSB-first backtrack (Heninger-Shacham style)
- [nested-lcg-rsa-base-q-layered-recovery](attack/nested-lcg-rsa-base-q-layered-recovery.md) — `p = L3·q² + L2·q + L1` with 공격자 제어 LCG1: (a,x,b)=(1,1,1)로 roll index 주입 → n mod q에서 index 복구 → n mod q²로 LCG2 다항식 → Coppersmith
- [unbalanced-rsa-trivariate-bd-yz-substitution](attack/unbalanced-rsa-trivariate-bd-yz-substitution.md) — Unbalanced RSA (p=N^β, β<0.5) with small d: 3-variable BD `1+x(N+1-y-z)` + `poly_sub(y*z, N)`로 quotient ring에서 정확 제약 처리. Bivariate 큐빅 reduction은 bound에 걸려 실패; trivariate는 unbalanced 심할수록 쉬워짐
- [loidreau-shuttle-rank-inflate-gabidulin](attack/loidreau-shuttle-rank-inflate-gabidulin.md) — Loidreau PKE `G' = S·G_Gab·P⁻¹` (P 엔트리 ∈ λ-dim F_q-subspace) → 우측 P-곱으로 distortion 제거, error rank가 t→t·λ로 팽창해도 ≤⌊(n-k)/2⌋면 Sage Gao decoder 일발

---

## ⚠️ AI 실수 패턴 (Reasoning Failures)

한 번 틀린 접근법 — 같은 실수 반복 방지용.

- [cryptohack-listener-quirks](failures/cryptohack-listener-quirks.md) — `no_prompt=True` 자동 flush; 전이 메시지는 전이를 유발한 라운드에 붙는다
- [cryptohack-pkcs1-sha1-default](failures/cryptohack-pkcs1-sha1-default.md) — CryptoHack pkcs1 라이브러리는 SHA-1 기본. SHA-256 가정 금지
- [ec-check-smoothness-before-bsgs](failures/ec-check-smoothness-before-bsgs.md) — Small secret ECDLP면 BSGS 전에 반드시 `factor(E.order())`. Smooth → PH 초단위 해결
- [hand-rolled-inverse-edge-cases](failures/hand-rolled-inverse-edge-cases.md) — 챌린지 inline GCD에서 `inverse(0, p)`는 raise 대신 0 반환 → identity element bypass
- [ige-mode-dual-iv-attack](failures/ige-mode-dual-iv-attack.md) — IGE dual IV(m0/c0) 중 어느 쪽을 변조할지 혼동
- [invalid-curve-attack-alternative-b](failures/invalid-curve-attack-alternative-b.md) — ECDH point-on-curve 미검증 시 다른 b' 곡선 스캔 → smooth order PH+CRT로 비밀 복구. **Crash gotchas**: q=2(y=0 doubling) + d≡0 mod q(INF.to_bytes) 둘 다 connection 죽임. 큰 q부터, M>n에서 stop, 죽으면 reconnect
- [kitamasa-base-case-threshold](failures/kitamasa-base-case-threshold.md) — Kitamasa order L = base-case threshold T (NOT recurrence max-shift). T > max-shift면 off-by-one 함정 (naive sanity도 같이 틀려서 "match=True"로 속임)
- [isogeny-degree-leak-via-weil-pairing](failures/isogeny-degree-leak-via-weil-pairing.md) — 비밀이 isogeny 차수에 인코딩되고 phi(P)/phi(Q) 공개 → Weil pairing으로 degree leak
- [lwe-kannan-embedding-sign-trap](failures/lwe-kannan-embedding-sign-trap.md) — Kannan은 lattice point closest to **−t** 탐색. embed row에 +target 넣으면 BKZ 성공해도 검증 50% 실패
- [padding-oracle-byte15-edge-case](failures/padding-oracle-byte15-edge-case.md) — pad_value를 1로 가정하면 실패, 동적 판별 필요
- [premature-dlp-infeasibility](failures/premature-dlp-infeasibility.md) — 127비트 DLP를 Pollard rho로 계산해 "불가능"이라 단정 금지. PARI는 index calculus 씀
- [ph-smooth-prime-must-exceed-modulus](failures/ph-smooth-prime-must-exceed-modulus.md) — Static-key DH MITM에서 PH용 smooth prime은 p_orig보다 커야 b가 truncation 없이 복구됨
- [sage-isogeny-dual-builtin](failures/sage-isogeny-dual-builtin.md) — Isogeny dual은 Sage `.dual()` 쓰기. copypasta dual()은 Aut(E) 임의 선택으로 틀린 sigma-class에 빠짐
- [normalize-unknown-sizes-before-lattice](failures/normalize-unknown-sizes-before-lattice.md) — 힌트 방정식 small unknown 여러 개 → dominant known으로 나눠서 크기 분석 먼저. O(1)짜리는 격자서 제외
- [oracle-model-simulation-mismatch](failures/oracle-model-simulation-mismatch.md) — 오라클 시뮬레이션에서 파라미터 범위별 case 누락. mixed zone에서 no-carry=항상😀 무시 → 36% unique. 범위 제한으로 case 제거
- [schnorr-nonce-reuse-over-different-moduli](failures/schnorr-nonce-reuse-over-different-moduli.md) — Schnorr nonce v 재사용이 서로 다른 소수 p_i 하에서도 유효. c*w>v면 정확히 1번 wrap → 정수 등식
- [sympy-discrete-log-pk-oom](failures/sympy-discrete-log-pk-oom.md) — sympy discrete_log은 p^k에서 OOM. Hensel lifting으로 분해
- [thread-race-slow-the-thread](failures/thread-race-slow-the-thread.md) — background thread validation은 race 말고 worker inner loop를 팽창시켜 일부러 느리게 만들어라
- [tls12-extended-master-secret](failures/tls12-extended-master-secret.md) — TLS 1.2 InvalidTag면 즉시 EMS extension(0x17) 의심. master_secret 유도식 변경됨
- [unbalanced-rsa-small-d-boundary](failures/unbalanced-rsa-small-d-boundary.md) — Unbalanced RSA (β=0.25) with d ≈ N^0.293: CF/BD 실패, 큐빅 polynomial은 asymptotic 경계 (`(2/3)logX+logY < (4/9)logE`) 바로 위라 basic JM 실패. Maitra-Sarkar 또는 Herrmann-May sublattice 필요
- [binary-search-d-top-resolution-stall](failures/binary-search-d-top-resolution-stall.md) — RSA d=top binary search는 mid²/A 정수 산술 한계로 (b-a) ≈ 2·mid²/A에서 stall. m << n + tight initial 케이스. 단일 boundary cut 안 됨 → 양방향 Manger 변종

---

## 🔧 툴 & 메타 (Tool / Meta)

환경 quirk 및 범용 문제 접근 체크리스트.

- [local-first-debugging](tools/local-first-debugging.md) — 서버에서 디버깅하면 비효율. 로컬 시뮬레이션 먼저
- [sage-dlp-fp-feasibility](tools/sage-dlp-fp-feasibility.md) — 128-bit F_p* DLP는 Sage `discrete_log`로 수 분 내 해결 (PARI znlog index calculus)
- [direct-prime-power-construction](tools/direct-prime-power-construction.md) — N=p^k 필요하면 smooth 검색 말고 `getPrime(bits)**k` 직접
- [sage-gf-large-fp2-construction](tools/sage-gf-large-fp2-construction.md) — 큰 p에서 `GF((p,2),...)` → GAP order 에러. `GF(p^2,'i',modulus=[1,0,1])`로 바꿀 것
- [sage-preparser-xor-trap](tools/sage-preparser-xor-trap.md) — `.sage` 파일에서 `^`는 XOR 아닌 거듭제곱. Sage XOR은 `^^`
- [try-first-principle](tools/try-first-principle.md) ⭐⭐ — AI 1위 실수: 이론만으로 infeasible 판정. 생각을 실험으로 전환하는 범용 원칙
- [stuck-checklist-5-questions](tools/stuck-checklist-5-questions.md) ⭐ — "복잡 → skip" 전 6문 체크 (Q0: 실측 근거 / 분해 / dir(obj) / 제목 공격명 / 두 번째 약점 / github 구현)
- [cascade-not-all-at-once](tools/cascade-not-all-at-once.md) ⭐ — AI 자주 빠지는 함정: 한 번에 다 풀려 함. A→B→C 단계적 cascade로 분해. 각 단계 산출물이 다음 단계 input
- [z3-bitblast-sat-for-crypto](tools/z3-bitblast-sat-for-crypto.md) — Z3 bitvector 곱셈+XOR 문제에서 `Then('simplify','bit-blast','sat')`로 극적 속도 향상
- [sage-script-exit-returncode](tools/sage-script-exit-returncode.md) — `.sage`에서 `sys.exit(N)`은 preparser와 충돌 → `raise SystemExit(N)` + stdout `RESULT:` 마커로 통신
- [docker-windows-path-mount](tools/docker-windows-path-mount.md) — Python subprocess로 docker 호출 시 Windows path 수동 변환 (`D:\foo` → `/d/foo`) + `MSYS_NO_PATHCONV=1`
- [binary-ilp-pulp-cbc](tools/binary-ilp-pulp-cbc.md) — 0/1 변수 + 정수 선형 등식 시스템: `pulp + CBC` binary ILP가 LLL embedding 대안. n=256, m=128 → 0.2s
