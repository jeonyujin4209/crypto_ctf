# Forbidden Fruit

- **Category**: Symmetric Ciphers (AES-GCM)
- **URL**: https://aes.cryptohack.org/forbidden_fruit
- **Flag**: `crypto{https://github.com/attr-encrypted/encryptor/pull/22}`

## Challenge

AES-GCM 암호화/복호화 오라클이 주어진다.

- `encrypt(plaintext)`: 고정된 IV로 암호화. `flag`이 포함된 평문은 태그 없이 ciphertext만 반환.
- `decrypt(nonce, ciphertext, tag, associated_data)`: 인증 통과 후, `give me the flag`이 포함되면 플래그 반환.

## Vulnerability

`encrypt`가 **매번 동일한 nonce(IV)**를 사용한다. GCM에서 nonce 재사용은 인증키 H를 노출시켜 태그 위조가 가능해지는 치명적 취약점이다.

## GCM Tag 구조

1블록 AD(A), 1블록 ciphertext(C)인 경우:

```
Tag = A*H^3 + C*H^2 + L*H + S
```

- H: GHASH 인증키 (= AES_K(0))
- L: 길이 블록 (len(AD) || len(CT))
- S: 암호화 마스크 (= AES_K(J0)), nonce가 같으면 동일

## Attack

같은 nonce로 두 평문을 암호화하면 A, L, S가 모두 동일하므로:

```
Tag2 ^ Tag3 = (C2 ^ C3) * H^2
```

여기서 H^2를 복구할 수 있다.

1. 알려진 평문 2개 암호화 -> C2, Tag2, C3, Tag3 획득
2. `H^2 = (Tag2 ^ Tag3) * inverse(C2 ^ C3)` in GF(2^128)
3. `"give me the flag"` 암호화 -> C_target 획득 (태그는 차단됨)
4. 태그 위조: `Forged_Tag = Tag2 ^ (C_target ^ C2) * H^2`
5. 위조 태그로 decrypt 호출 -> 플래그 획득
