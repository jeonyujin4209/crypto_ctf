# The Good, The Pad, The Ugly
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 100 pts
- **카테고리**: AES, CBC, Padding Oracle
- **technique**: noisy_padding_oracle, statistical_voting

## 문제 요약
패딩 오라클에 노이즈: `result = good | (random > 0.4)`
- False → 확실히 bad padding
- True → 60% 노이즈 또는 진짜 good

12000 쿼리 제한.

## 실패한 접근과 원인

### 1차 시도: 클래식 패딩 오라클 + hex 검증 없음
- 노이즈로 인해 wrong candidate가 True를 반환 → 잘못된 바이트 선택
- 결과: 비ASCII 바이트 복호화 → UnicodeDecodeError

### 2차 시도: hex 검증 추가 + 4 samples 확인
- hex char 필터로 후보를 16개로 줄임
- 1차 쿼리에서 True인 후보만 3회 추가 확인
- **문제**: good padding은 항상 True인데, bad도 60% True → 확인 단계에서 bad가 통과
- 결과: 12000 쿼리 초과 또는 잘못된 메시지

### 실패 원인 핵심
- `good | (random > 0.4)` 에서 **True는 정보가 없음** (good이든 bad이든 True 가능)
- **False만 신뢰 가능** (False = bad padding 확정, 단 40% 확률로만 발생)
- True 기반 확인은 노이즈와 구분 불가

## 성공한 풀이
**투표 방식**: 각 후보에 동일 samples, **False 횟수**로 판별
- good padding → False **0회** (good | noise = 항상 True)
- bad padding → False **~40%** (noise가 0.4 이하일 때)

평문이 hex 문자(16종)임을 이용해 후보를 16개로 제한.
각 후보에 10 samples, **False 횟수가 가장 적은 후보 = correct**:
- correct: 0 False (절대 False 안 나옴)
- wrong: 평균 4 False (10 × 0.4)

**확실한 구분**: correct는 0, wrong은 ~4. 겹칠 확률 거의 없음.

16 × 10 × 32 = 5120 쿼리. 예산 내.

## 교훈
- 노이즈 오라클에서는 "True/False 중 어느 쪽이 **확정적 정보**인가"를 먼저 파악
- `good | noise`: True는 쓸모없고, **False가 확정** → False 횟수 기반 투표
- 후보 공간 축소(256→16)가 쿼리 예산 절약의 핵심

## 플래그
`crypto{even_a_faulty_oracle_leaks_all_information}`
