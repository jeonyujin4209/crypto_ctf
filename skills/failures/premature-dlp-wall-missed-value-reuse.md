---
name: premature-dlp-wall-missed-value-reuse
description: Collision/forgery 시 "특정 값을 만들려면 DLP" 결론에서 멈추지 말 것. 그 값이 *이미 시스템 안에서 자유롭게 쓸 수 있는 형태로 존재*할 수 있음
type: failure
---

# Premature DLP-wall — missed value reuse

## 실패 패턴

세션 2에서 Hamiltonicity 2의 hash collision 시도 중:

> A_b의 cycle commit (commit-to-1) 이 fm_a의 specific 309-char window와 일치해야 함.
> c_b = h1 * h2^{r_b} ≡ N (mod P) 에서 r_b를 N으로부터 derive ⇒ DLP-hard.
> → "boundary shift collision은 DLP 필요. 진짜 trick은 더 영리함." 그리고 멈춤.

→ 다음 세션에서 발견: **A_a 자체가 G의 1-position 5개에 대해 commit-to-1을 이미 들고 있음**. 그걸 A_b의 cycle position에 *그대로 복사*하면 됨. DLP 일절 불필요. free cell 길이만 조정해서 character offset 정렬.

## 일반화

Hash/commitment collision을 만들 때 "특정 값 X가 필요"라는 결론에 도달하면:
- ❌ 즉시 "X를 만들려면 inversion/DLP 필요 → 안 됨" 결론 짓고 다른 attack 찾기
- ✅ Self-question: **"이 값 X와 동일한 (또는 활용 가능한) 무언가가 이 protocol 안에 *이미 존재*하나?"**

존재하는 경우 흔한 패턴:
- Honest prover가 어차피 보낼 commitment 중 하나
- 다른 라운드/세션에서 만든 commitment
- 공개 파라미터에 들어 있는 값
- 같은 메시지 m에 대한 *다른 r*의 commit (r 자유롭게 고를 수 있으니 동일 가능)

## 적용 체크리스트

DLP/inversion 벽 만났을 때 1분만 자문:

1. **이 값을 *처음부터 만들어야* 하는가?** Honest 흐름에서 나오는 값과 동일한가?
2. **목표 값의 *형태*는 무엇인가?** "commit-to-m for some r" 인가, 아니면 "specific bit pattern"인가? 전자라면 **임의 r 선택 가능**.
3. **재사용 가능한 *위치*가 있는가?** Protocol 입력으로 같은 값을 여러 cell에 넣을 수 있는가? Format에 제약 (alignment, length) 있는가? 그 제약을 *우리가 다른 free 변수로* 흡수할 수 있는가?
4. **두 결과가 같은 hash가 되는 다른 방법은?** 값 자체가 같지 않더라도, *다른 위치에 같은 substring*만 있으면 OK일 때가 있음 (str-join 분리자 무 등).

## 교훈

DLP는 보통 "값 → 지수" 방향. 그런데 *값을 우리가 자유롭게 고를 수 있다면* 지수를 먼저 고르고 값은 따라 나오게 하면 됨. 이게 가능한지 보는 게 첫 단계.

## 관련
- `attack/hash-strjoin-no-separator-prover-collision` — Ham2의 풀이 (이 실패 다음에 나옴)
- `tools/try-first-principle` — 추론 대신 실측
- `failures/premature-dlp-infeasibility` — DLP 자체의 feasibility 오판 (다른 결)
