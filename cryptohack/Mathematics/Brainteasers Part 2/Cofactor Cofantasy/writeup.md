# Cofactor Cofantasy

- **Category**: Brainteasers Part 2
- **Points**: 150
- **Status**: 미해결 (소켓 챌린지, 서버 접속 필요)
- **Server**: socket.cryptohack.org:13398

## Challenge

N은 safe prime의 곱, g가 주어짐. get_bit(i) 호출 시:
- FLAG의 비트 i가 1이면: pow(g, randint(2, phi-1), N) 반환 (g의 거듭제곱 = QR subgroup 원소)
- FLAG의 비트 i가 0이면: randint(1, N-1) 반환 (랜덤)

## Approach

N과 phi가 주어지므로 p, q를 복구 가능: p+q = N-phi+1, p*q = N.

g^r mod N은 항상 이차잉여(QR). 랜덤 값은 약 3/4 확률로 비QR.
각 비트에 대해 여러 번 쿼리하여:
- 모든 값이 QR이면 비트 = 1
- 비QR 값이 하나라도 있으면 비트 = 0

Legendre(value, p) * Legendre(value, q)로 QR 판별.

서버 접속 가능 환경에서 구현 예정.
