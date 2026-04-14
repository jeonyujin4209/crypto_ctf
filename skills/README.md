# Skills

AI가 삽질했거나 직접 쓴 패턴 정리. frontmatter `type` 기준으로 분류.

---

## 🔐 공격 기법 (Attack Recipes)

재사용 가능한 암호 공격 레시피.

- [arora-ge-binary-lwe](attack/arora-ge-binary-lwe.md) — Binary/bounded error LWE는 격자 대신 다항식 linearization → 가우스 소거
- [castryck-decru-sidh-attack](attack/castryck-decru-sidh-attack.md) — SIDH에서 3-torsion images 주어지면 Castryck-Decru로 비밀 isogeny 복구
- [coppersmith-approx-factor](attack/coppersmith-approx-factor.md) — `floor(D*sqrt(p))` 힌트에서 오류 ≈ 2*sqrt(p)/D; `small_roots(beta=0.5)`로 정확한 p 복구
- [csidh-genus-theory-ddh](attack/csidh-genus-theory-ddh.md) — CSIDH DDH: genus theory로 j-invariant의 isogeny class 판단, DH vs random 구별
- [fischlin-wi-distinguisher](attack/fischlin-wi-distinguisher.md) — Fischlin OR proof에서 RO hit count로 b=0/1 구별. count>1이면 b=1 확실
- [gaussian-int-padic-dlp](attack/gaussian-int-padic-dlp.md) — Z[i]/(p^2)* DLP에서 p-파트 Hensel lifting으로 선형 해결 (BSGS 불가)
- [groth16-rerandomization](attack/groth16-rerandomization.md) — Groth16 (A,B,C)에서 λ 재랜덤화 → (λ⁻¹A, λB, C)도 valid. 크레딧 파밍 가능
- [hamiltonicity-online-fs-grinding](attack/hamiltonicity-online-fs-grinding.md) — Online FS면 A 랜덤 재시도로 challenge=0 강제 가능 (Batch FS Ham2와 대비)
- [hnp-biased-ecdsa-nonce](attack/hnp-biased-ecdsa-nonce.md) — Biased ECDSA nonce → Boneh-Venkatesan 격자. Sage 없으면 pure-Python LLL fallback
- [isogeny-claw-mitm](attack/isogeny-claw-mitm.md) — 2^e-isogeny E1→E2를 MITM claw-finding으로 복구. DFS 양방향 + j-invariant 고정점 매칭
- [jwt-algorithm-confusion](attack/jwt-algorithm-confusion.md) — JWT RS256→HS256 algorithm confusion: RS256 공개키를 HMAC secret으로 서명 위조
- [matrix-dh-repeated-root-local-ring](attack/matrix-dh-repeated-root-local-ring.md) — Matrix DH에서 min_poly 중복근이면 DLP 없이 SECRET = λ·b/a로 즉시 복구
- [noisy-oracle-statistical-approach](attack/noisy-oracle-statistical-approach.md) — 노이즈 오라클에서 Sequential Halving 실패; Adaptive Top-2로 해결
- [pohlig-hellman-ecdlp](attack/pohlig-hellman-ecdlp.md) — Smooth/small order ECDLP → Pohlig-Hellman. BSGS 전에 `factor(E.order())` 필수
- [rsa-last-byte-oracle-binary-search](attack/rsa-last-byte-oracle-binary-search.md) — last byte == 0x2e oracle에서 s ≡ 0x81 overflow 감지 → binary search로 m 복구
- [singular-curve-mapping](attack/singular-curve-mapping.md) — ECDLP 전 discriminant 체크. Singular 곡선은 F_p*/F_p+ 로 매핑해 DLP 해결

---

## ⚠️ AI 실수 패턴 (Reasoning Failures)

한 번 틀린 접근법 — 같은 실수 반복 방지용.

- [cryptohack-listener-quirks](failures/cryptohack-listener-quirks.md) — `no_prompt=True` 자동 flush; 전이 메시지는 전이를 유발한 라운드에 붙는다
- [ec-check-smoothness-before-bsgs](failures/ec-check-smoothness-before-bsgs.md) — Small secret ECDLP면 BSGS 전에 반드시 `factor(E.order())`. Smooth → PH 초단위 해결
- [hand-rolled-inverse-edge-cases](failures/hand-rolled-inverse-edge-cases.md) — 챌린지 inline GCD에서 `inverse(0, p)`는 raise 대신 0 반환 → identity element bypass
- [ige-mode-dual-iv-attack](failures/ige-mode-dual-iv-attack.md) — IGE dual IV(m0/c0) 중 어느 쪽을 변조할지 혼동
- [invalid-curve-attack-alternative-b](failures/invalid-curve-attack-alternative-b.md) — ECDH point-on-curve 미검증 시 다른 b' 곡선 스캔 → smooth order PH+CRT로 비밀 복구
- [isogeny-degree-leak-via-weil-pairing](failures/isogeny-degree-leak-via-weil-pairing.md) — 비밀이 isogeny 차수에 인코딩되고 phi(P)/phi(Q) 공개 → Weil pairing으로 degree leak
- [lwe-kannan-embedding-sign-trap](failures/lwe-kannan-embedding-sign-trap.md) — Kannan은 lattice point closest to **−t** 탐색. embed row에 +target 넣으면 BKZ 성공해도 검증 50% 실패
- [padding-oracle-byte15-edge-case](failures/padding-oracle-byte15-edge-case.md) — pad_value를 1로 가정하면 실패, 동적 판별 필요
- [ph-smooth-prime-must-exceed-modulus](failures/ph-smooth-prime-must-exceed-modulus.md) — Static-key DH MITM에서 PH용 smooth prime은 p_orig보다 커야 b가 truncation 없이 복구됨
- [sage-isogeny-dual-builtin](failures/sage-isogeny-dual-builtin.md) — Isogeny dual은 Sage `.dual()` 쓰기. copypasta dual()은 Aut(E) 임의 선택으로 틀린 sigma-class에 빠짐
- [schnorr-nonce-reuse-over-different-moduli](failures/schnorr-nonce-reuse-over-different-moduli.md) — Schnorr nonce v 재사용이 서로 다른 소수 p_i 하에서도 유효. c*w>v면 정확히 1번 wrap → 정수 등식
- [thread-race-slow-the-thread](failures/thread-race-slow-the-thread.md) — background thread validation은 race 말고 worker inner loop를 팽창시켜 일부러 느리게 만들어라
- [tls12-extended-master-secret](failures/tls12-extended-master-secret.md) — TLS 1.2 InvalidTag면 즉시 EMS extension(0x17) 의심. master_secret 유도식 변경됨

---

## 🔧 툴 & 메타 (Tool / Meta)

환경 quirk 및 범용 문제 접근 체크리스트.

- [local-first-debugging](tools/local-first-debugging.md) — 서버에서 디버깅하면 비효율. 로컬 시뮬레이션 먼저
- [sage-gf-large-fp2-construction](tools/sage-gf-large-fp2-construction.md) — 큰 p에서 `GF((p,2),...)` → GAP order 에러. `GF(p^2,'i',modulus=[1,0,1])`로 바꿀 것
- [sage-preparser-xor-trap](tools/sage-preparser-xor-trap.md) — `.sage` 파일에서 `^`는 XOR 아닌 거듭제곱. Sage XOR은 `^^`
- [stuck-checklist-5-questions](tools/stuck-checklist-5-questions.md) ⭐ — "복잡 → skip" 전 5문 체크: 분해 / dir(obj) / 제목 공격명 / 두 번째 약점 / github 구현
