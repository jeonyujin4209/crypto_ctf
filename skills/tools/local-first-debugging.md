---
name: local-first-debugging
description: 서버 디버깅 전 반드시 로컬 재현 먼저. 서버 loop은 느리고 중간 상태 관찰 불가능
type: feedback
---

# 원칙: 서버 전에 로컬에서 먼저 검증

## 유형
디버깅 전략 (모든 서버 기반 CTF 문제)

## 문제 상황
서버에 수천 회 요청을 보내면서 디버깅하면 시간 낭비 + rate limit 위험.

## 왜 못 풀었나 (A)
Paper Plane에서 패딩 오라클 로직의 edge case(byte 15)를 서버에 직접 요청하면서 디버깅. 256 x 3 = 768회 요청으로 문제를 파악하는 데 수십 분 소요.

Oracular Spectacular에서도 전략 비교를 서버에서 직접 했다면 12,000 쿼리 제한에 걸려서 테스트조차 불가능했을 것.

## 어떻게 해결했나 (B)
**로컬 시뮬레이션을 먼저 작성**:

```python
# 로컬 오라클 시뮬레이터
class LocalOracle:
    def __init__(self):
        self.key = os.urandom(16)
        self.flag = b"crypto{test_flag_here}"
    
    def encrypt(self):
        # 서버와 동일한 암호화
        ...
    
    def oracle(self, ct, m0, c0):
        # 서버와 동일한 복호화 + 패딩 검증
        ...
```

로컬에서:
1. edge case 재현 (byte 15 문제)
2. 로직 수정 후 즉시 검증 (요청 0회)
3. 확신이 생긴 후 서버에 실행

## 적용 범위
- 패딩 오라클 (서버 요청이 느린 경우)
- 노이즈 오라클 (수천 회 시도 필요)
- rate limit이 있는 모든 서버 문제
- 전략 비교/튜닝이 필요한 경우

## 체크리스트
1. 서버 코드가 주어지면 → 로컬 복제본 먼저 만들기
2. 로컬에서 solver가 100% 성공하는지 확인
3. edge case (빈 입력, 경계값, 랜덤 키 여러 개) 테스트
4. 확인 후 서버에 실행

## 출처
- CryptoHack: Paper Plane, Oracular Spectacular
