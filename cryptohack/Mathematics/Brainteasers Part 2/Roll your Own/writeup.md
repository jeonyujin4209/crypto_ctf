# Roll your Own

- **Category**: Brainteasers Part 2
- **Points**: 125
- **Status**: 미해결 (소켓 챌린지, 서버 접속 필요)
- **Server**: socket.cryptohack.org:13403

## Challenge

서버가 512비트 소수 q와 비밀 x를 생성. 우리가 g, n을 보내면 (pow(g,q,n)==1 검증),
서버가 h = pow(g, x, n)을 반환. x를 맞추면 플래그.

## Approach

핵심: g, n을 자유롭게 선택 가능. DLP가 쉬운 구조를 만들어야 함.

1. n = q*k + 1인 소수 찾기 (k가 smooth)
2. g를 order q인 원소로 설정
3. Pohlig-Hellman으로 x mod (작은 인수들) 구하기
4. 충분한 정보로 x 복구

또는: n을 smooth order를 가진 합성수로 설정하여 CRT로 분해.

서버 접속 가능 환경에서 구현 예정.
