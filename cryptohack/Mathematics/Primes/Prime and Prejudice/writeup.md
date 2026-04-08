# Prime and Prejudice

- **Category**: Primes
- **Points**: 200
- **Status**: 미해결 (소켓 챌린지, 서버 접속 필요)
- **Server**: socket.cryptohack.org:13385

## Challenge

a와 p를 보내면:
- p: 601~900 비트, Miller-Rabin(p, 64) 통과 필요
- x = pow(a, p-1, p)
- FLAG[:x] 반환

소수 p이면 페르마 소정리로 x=1, FLAG의 첫 글자만 반환.

## Approach

합성수 p가 Miller-Rabin을 통과하면서 pow(a, p-1, p)가 큰 값이 되도록 해야 함.

1. 모든 base < 64인 소수에 대한 strong pseudoprime 찾기
2. 적절한 a 선택으로 pow(a, p-1, p) >= len(FLAG)

Carmichael number 기반 접근 또는 known strong pseudoprime 구성.

서버 접속 가능 환경에서 구현 예정.
