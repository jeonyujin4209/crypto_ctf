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
