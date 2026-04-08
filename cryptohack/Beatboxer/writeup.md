# Beatboxer

- **Category**: Symmetric Ciphers / Linear Cryptanalysis
- **Points**: 150
- **Server**: `socket.cryptohack.org:13406`

## Challenge

커스텀 S-box를 사용하는 AES 구현이 주어진다. ECB 모드로 동작하며:

- `encrypt_message`: 16바이트 메시지 1회만 암호화 가능
- `encrypt_flag`: 플래그를 PKCS7 패딩 후 ECB 암호화하여 반환

## Vulnerability

커스텀 S-box가 **아핀(affine)** 함수이다:

```
sbox[x] = L(x) ^ 0x2a    (L은 GF(2)^8 위의 선형 함수)
```

검증: 모든 a, b에 대해 `sbox[a ^ b] == sbox[a] ^ sbox[b] ^ sbox[0]` 성립.

표준 AES의 S-box는 비선형(GF(2^8)에서의 역원 + 아핀 변환)이라 선형 공격에 저항하지만,
이 S-box는 순수 아핀이므로 **AES 전체가 아핀 함수**가 된다:

```
E(x) = M * x + c    (GF(2)^128 위의 아핀 변환)
```

핵심: **M은 키와 무관**하다. 키는 상수 c에만 영향을 준다.

## Attack

1. **M 계산 (로컬)**: 아무 키로 AES 인스턴스를 만들어 128개 기저 벡터를 암호화
   - `c_local = E_local(0)`
   - `M의 j번째 열 = E_local(e_j) ^ c_local`
   - GF(2) 가우스 소거법으로 M^(-1) 계산

2. **서버에서**:
   - 영벡터 암호화: `c_server = E_server(0)` (1회 사용)
   - 플래그 암호화: `enc_flag = E_server(flag_blocks)`

3. **복호화**:
   ```
   flag_block = M^(-1) * (enc_flag_block ^ c_server)
   ```

## Usage

```bash
python solve.py
```

서버 연결이 안 될 경우 `solve.py`의 `USE_LOCAL = True`로 변경하여 로컬 테스트 가능.
