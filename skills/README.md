# AI Failure Skills

AI가 바로 못 풀고 삽질한 패턴만 정리. 기본적으로 풀 수 있는 건 생략.

## 목록

- [padding-oracle-byte15-edge-case](padding-oracle-byte15-edge-case.md) — pad_value를 1로 가정하면 실패, 동적 판별 필요
- [noisy-oracle-statistical-approach](noisy-oracle-statistical-approach.md) — 노이즈 오라클에서 Sequential Halving 실패, Adaptive Top-2로 해결
- [ige-mode-dual-iv-attack](ige-mode-dual-iv-attack.md) — IGE의 dual IV(m0/c0) 중 어떤 걸 변조할지 혼동
- [local-first-debugging](local-first-debugging.md) — 서버에서 디버깅하면 비효율, 로컬 시뮬레이션 먼저
- [singular-curve-mapping](singular-curve-mapping.md) — ECDLP 전 discriminant 체크. Singular 곡선은 F_p*/F_p+로 매핑 가능
- [hnp-biased-ecdsa-nonce](hnp-biased-ecdsa-nonce.md) — Biased ECDSA nonce → Boneh-Venkatesan 격자. Sage 없을 때 pure-Python LLL fallback
- [tls12-extended-master-secret](tls12-extended-master-secret.md) — TLS 1.2 InvalidTag면 즉시 EMS extension(0x17) 의심. master_secret 유도식 변경
- [arora-ge-binary-lwe](arora-ge-binary-lwe.md) — Binary/bounded error LWE는 격자 말고 다항식 linearization으로 가우스 소거
- [ph-smooth-prime-must-exceed-modulus](ph-smooth-prime-must-exceed-modulus.md) — Static-key DH MITM에서 Pohlig-Hellman용 smooth prime은 p_orig보다 커야 b가 truncation 없이 복구됨
- [matrix-dh-repeated-root-local-ring](matrix-dh-repeated-root-local-ring.md) — Matrix DH에서 min_poly가 중복근을 가지면 DLP 전혀 없이 SECRET = λ·b/a로 즉시 복구. DLP 접근 전에 squarefree 검사 필수
- [lwe-kannan-embedding-sign-trap](lwe-kannan-embedding-sign-trap.md) — Kannan은 lattice point closest to **−t** 를 찾음. Embed row에 +target 대신 −target 넣으면 BKZ는 성공하지만 검증 50% 실패. 부호 한 번 더 의심
- [cryptohack-listener-quirks](cryptohack-listener-quirks.md) — `no_prompt=True`는 접속 시 첫 응답까지 자동 flush. "new croupier" 같은 전이 메시지는 전이를 **유발한** 라운드에 붙는다 (다음 라운드 아님)
- [thread-race-slow-the-thread](thread-race-slow-the-thread.md) — 서버가 background thread로 validation하면 그냥 race 돌리지 말고 **worker의 inner loop를 팽창시켜** 일부러 느리게 만들어라 (`wanted_nodes = {"1": 10^8}`)
- [sage-preparser-xor-trap](sage-preparser-xor-trap.md) — `.sage` 파일에서 `^`는 XOR이 아니라 거듭제곱 (`**`)이다. Sage XOR은 `^^`. X-only ladder 포팅하면 k=1은 맞고 k=2부터 틀리면 이거 의심
- [hand-rolled-inverse-edge-cases](hand-rolled-inverse-edge-cases.md) — 챌린지가 inline extended-GCD로 만든 `inverse(0, p)`는 **raise 안 하고 0을 반환**. `if (x*z) % p == 1: raise` 가드가 z=0을 통과시켜서 identity element bypass 가능
- [schnorr-nonce-reuse-over-different-moduli](schnorr-nonce-reuse-over-different-moduli.md) — Schnorr `v` 재사용이 **서로 다른 소수 p_i** 하에서도 쓸만함. `c*w > v`면 mod가 정확히 한 번만 `+(p_i-1)` wrap 하므로 정수 등식으로 풀린다
- [sage-gf-large-fp2-construction](sage-gf-large-fp2-construction.md) — 큰 p에 대해 `GF((p, 2), ...)`는 GAP `order must be at most 65536` 에러. `GF(p^2, 'i', modulus=[1,0,1])`로 바꿀 것
- [isogeny-degree-leak-via-weil-pairing](isogeny-degree-leak-via-weil-pairing.md) — 비밀이 isogeny의 **차수**에 인코딩되고 `phi(P), phi(Q)`가 공개되면 `e(phi(P),phi(Q)) = e(P,Q)^{deg}`로 한 방 leak
- [ec-check-smoothness-before-bsgs](ec-check-smoothness-before-bsgs.md) — "Small secret ECDLP"면 BSGS 가기 전에 **반드시 `factor(E.order())`**. Smooth면 Sage `discrete_log`가 자동 PH로 초단위 해결 (Micro Transmissions에서 놓친 교훈)
- [invalid-curve-attack-alternative-b](invalid-curve-attack-alternative-b.md) — ECDH 서버가 point-on-curve 체크 안 하면 **다른 `b'` 곡선들**을 스캔해서 smooth-order 것들 찾고 PH+CRT로 비밀 복구. 트위스트 한 개만이 아니라 여러 곡선 조합 가능 (Checkpoint)
- [sage-isogeny-dual-builtin](sage-isogeny-dual-builtin.md) — Isogeny의 dual이 필요할 때 **Sage 내장 `.dual()` 메서드 쓰기**. 교재의 `dual()` 함수를 copypasta하면 `isomorphism_to()`가 Aut(E) 중 하나를 임의로 골라서 틀린 sigma-class에 빠짐. j=0/1728 곡선은 특히 위험 (Dual Masters)
- [stuck-checklist-5-questions](stuck-checklist-5-questions.md) ⭐ — "복잡 → skip" 누를 때마다 무조건 통과시킬 5개 질문: (1) 3-6단계 분해했나 (2) `dir(obj)` 돌렸나 (3) 제목에서 공격명 뽑았나 (4) 첫 약점 말고 두 번째 약점도 봤나 (5) github에 구현 찾았나. 이번 세션 6개 skip이 전부 이 5개 중 하나 실패였음
- [fischlin-wi-distinguisher](fischlin-wi-distinguisher.md) — Fischlin OR proof에서 RO hit count로 b=0/1 구별. count>1이면 b=1 확실, count==1이면 b=0 추정(73%)
- [groth16-rerandomization](groth16-rerandomization.md) — Groth16 (A,B,C)에서 λ 쓰면 (λ⁻¹A, λB, C)도 valid. 다른 proof ID로 크레딧 파밍 가능. arkworks 직렬화는 LE + 0x3F 마스크
- [hamiltonicity-online-fs-grinding](hamiltonicity-online-fs-grinding.md) — Online FS(1라운드씩 challenge 계산)면 A 랜덤 재시도로 challenge=0 강제 가능. Batch FS(Ham 2)와 대비
