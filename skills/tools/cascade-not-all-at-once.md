---
name: cascade-not-all-at-once
description: 어려운 문제에서 AI가 자주 빠지는 함정 - "A, B, C 다 동시에 풀려고" 시도하다가 무한 루프. 실제로는 A→B→C 단계적 cascade가 답. 매 단계의 산출물을 다음 단계 input으로
type: tool
---

## 사용자가 알려준 패턴

> "AI는 다 알려고 해서 계속 무한 루프 돌아서 분석 시도 → 당연히 실패. 알고 보니 A를 알면 B를 알고, B를 알면 C를 유추할 수 있고 거기서 해답이 있었어"

문제 풀이가 막혔을 때 자문:
1. 풀려고 하는 게 너무 큼? 한 번에 다 풀려고 하나?
2. 부분 정보로 시작할 수 있는 단계가 있나?
3. 그 부분 정보가 다음 단계의 input이 되나?

## UMDCTF 2026 no-brainrot-allowed 사례

처음에 "Bleichenbacher로 m 전체를 한 번에 복구"만 시도 → m << n + 정수 산술 한계로 fundamental stall. 5+ 시간 소비.

사용자 hint 후 cascade로 재정리:
- **A**: cluster info (sequential s 검색에서 첫 hit) → flag length K=103 추정
- **B**: K + binary search to stall → 17 bytes "UMDCTF{thank_you_" 복구
- **C**: 양방향 Manger 변종 + ASCII tighten → 나머지 94 bytes 복구

각 단계가 다음 단계의 prerequisite. K 모르면 [m_low, m_high] 못 잡음. 17 bytes 모르면 ASCII tighten 효과 없음.

## 일반 적용

매 단계의 **산출물(output)이 다음 단계의 입력(input)** 인지 확인:

```
A → output_A → B(input=output_A) → output_B → C(input=output_B) → output_C = answer
```

만약 한 단계가 너무 어렵다면, 그 단계 자체를 sub-cascade로 분해:
```
A → B → [C₁ → C₂ → C₃] → answer
```

## CTF에서 자주 나오는 cascade 예시

- **RSA factoring**: hint → factor 1개 → 다른 factor → d → decrypt
- **ECDLP**: order factoring → Pohlig-Hellman per factor → CRT → 최종 d
- **Padding oracle**: oracle에서 1 bit → block → message
- **AES**: known plaintext → key bits → 다음 round → 전체 key
- **이번 문제**: cluster → length → prefix → byte-by-byte (or 양방향 narrow) → flag

## 막혔을 때 체크

```
[ ] 지금 한 번에 풀려고 하는 unknown의 크기는?
[ ] 그 unknown에서 partial info를 빼낼 sub-method가 있나?
[ ] 그 partial info를 활용해 unknown 크기를 줄이는 method가 있나?
[ ] 줄어든 unknown은 다른 method로 풀 수 있나?
```

만약 모든 답이 "아니오"면 진짜 막힌 것. 답이 "예/모르겠다"면 단계 분해 시도.

## 위험: Pseudo-cascade

cascade인 척하지만 각 단계가 독립인 경우 (실제 정보 흐름 X). 예: 작은 K부터 큰 K까지 try → 각 K가 독립 시행, cascade 아님.

진짜 cascade: 단계 N의 산출물이 단계 N+1의 input으로 명시적으로 사용됨.

## 관련

- `tools/stuck-checklist-5-questions`: 막힐 때 체크리스트 (이게 더 일반적)
- `tools/try-first-principle`: 이론보다 실측. cascade의 각 단계도 실측 검증 필요.
