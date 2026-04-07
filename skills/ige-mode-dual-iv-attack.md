# IGE 모드: Dual IV(m0/c0) 공격 전략

## 유형
AES-IGE (Infinite Garble Extension) 모드 공격

## 문제 상황
IGE는 CBC와 달리 IV가 2개(m0, c0)이다. 패딩 오라클 공격 시 어떤 값을 고정하고 어떤 값을 변조해야 하는지 혼란.

## 왜 못 풀었나 (A)
CBC 패딩 오라클과 동일하게 접근했다. CBC는 IV 하나만 변조하면 되지만, IGE는:
```
intermediate = AES_dec(block XOR m0)
plaintext = intermediate XOR c0
```
m0가 AES 입력에 영향, c0가 출력에 영향. 처음에 둘 다 동시에 바꾸거나, 잘못된 쪽을 변조해서 AES 입력 자체가 바뀌어 공격이 성립 안 됨.

## 어떻게 해결했나 (B)
**m0 고정, c0만 변조** 전략:
```
send_msg(target_block, m0=원본, c0=변조)
→ intermediate = AES_dec(block XOR m0)  ← m0 고정이므로 항상 동일
→ plaintext = intermediate XOR c0_test  ← c0 변조로 제어
```
이러면 CBC에서 IV를 변조하는 것과 정확히 동일한 구조가 된다.

### 다중 블록 처리
블록 i의 복호화에 필요한 m_prev, c_prev:
- m_prev = 이전 블록의 **평문** (블록 i-1 복호화 결과)
- c_prev = 이전 블록의 **암호문** (알려진 값)

→ 블록 0부터 순서대로 복호화하면, 이전 평문을 알게 되므로 다음 블록 공격 가능.

## 적용 범위
- AES-IGE 패딩 오라클
- Telegram MTProto 1.0 (IGE 사용)
- Dual IV 구조의 커스텀 암호 모드

## 출처
- CryptoHack: Paper Plane (120pts, Authenticated Encryption)
