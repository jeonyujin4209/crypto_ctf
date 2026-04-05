# Crypto CTF - CryptoHack Writeups

## Introduction

### Encoding
| # | 문제 | pts | technique | 플래그 |
|---|------|-----|-----------|--------|
| 1 | [ASCII](cryptohack/ASCII/) | 5 | `chr()` 변환 | `crypto{ASCII_pr1nt4bl3}` |
| 2 | [Hex](cryptohack/Hex/) | 5 | `bytes.fromhex()` | `crypto{You_will_be_working_with_hex_strings_a_lot}` |
| 3 | [Base64](cryptohack/Base64/) | 10 | hex→bytes→base64 | `crypto/Base+64+Encoding+is+Web+Safe/` |
| 4 | [Bytes and Big Integers](cryptohack/Bytes%20and%20Big%20Integers/) | 10 | `int.to_bytes()` / `long_to_bytes()` | `crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}` |
| 5 | [Encoding Challenge](cryptohack/Encoding%20Challenge/) | 40 | 다중 인코딩 자동 디코딩 + pwntools | `crypto{3nc0d3_d3c0d3_3nc0d3}` |

### XOR
| # | 문제 | pts | technique | 플래그 |
|---|------|-----|-----------|--------|
| 1 | [XOR Starter](cryptohack/XOR%20Starter/) | 10 | single-byte XOR | `crypto{aloha}` |
| 2 | [XOR Properties](cryptohack/XOR%20Properties/) | 15 | XOR 교환/결합/자기역원 성질 | `crypto{x0r_i5_ass0c1at1v3}` |
| 3 | [Favourite byte](cryptohack/Favourite%20byte/) | 20 | single-byte XOR brute force (256) | `crypto{0x10_15_my_f4v0ur173_by7e}` |
| 4 | [You either know XOR you don't](cryptohack/You%20either%20know%20XOR%20you%20dont/) | 30 | known plaintext + repeating-key XOR | `crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}` |
| 5 | [Lemur XOR](cryptohack/Lemur%20XOR/) | 40 | 이미지 XOR (A⊕K ^ B⊕K = A⊕B) | `crypto{X0Rly_n0t!}` |

### Mathematics
| # | 문제 | pts | technique | 답 |
|---|------|-----|-----------|-----|
| 1 | [Greatest Common Divisor](cryptohack/Greatest%20Common%20Divisor/) | 15 | 유클리드 알고리즘 | `1512` |
| 2 | [Extended GCD](cryptohack/Extended%20GCD/) | 20 | 확장 유클리드 → 모듈러 역원 | `-8404` |
| 3 | [Modular Arithmetic 1](cryptohack/Modular%20Arithmetic%201/) | 20 | 모듈러 나머지 연산 | `4` |
| 4 | [Modular Arithmetic 2](cryptohack/Modular%20Arithmetic%202/) | 20 | 페르마 소정리 a^(p-1)≡1 mod p | `1` |
| 5 | [Modular Inverting](cryptohack/Modular%20Inverting/) | 25 | 모듈러 역원 `pow(a,-1,p)` | `9` |

### Data Formats
| # | 문제 | pts | technique | 답/플래그 |
|---|------|-----|-----------|-----------|
| 1 | [Privacy-Enhanced Mail](cryptohack/Privacy-Enhanced%20Mail/) | 25 | PEM 파싱, `RSA.importKey()` | d값 (큰 정수) |
| 2 | [CERTainly not](cryptohack/CERTainly%20not/) | 30 | DER x509 인증서 파싱 | n값 (큰 정수) |
| 3 | [SSH Keys](cryptohack/SSH%20Keys/) | 35 | ssh-rsa 공개키 바이너리 파싱 | n값 (큰 정수) |
| 4 | [Transparency](cryptohack/Transparency/) | 50 | Certificate Transparency (crt.sh) | `crypto{thx_redpwn_for_inspiration}` |

### Symmetric Ciphers (AES)
| # | 문제 | pts | technique | 플래그 |
|---|------|-----|-----------|--------|
| 1 | [Keyed Permutations](cryptohack/Keyed%20Permutations/) | 5 | AES 이론 (bijection) | `crypto{bijection}` |
| 2 | [Resisting Bruteforce](cryptohack/Resisting%20Bruteforce/) | 10 | AES 이론 (biclique attack) | `crypto{biclique}` |
| 3 | [Structure of AES](cryptohack/Structure%20of%20AES/) | 15 | matrix2bytes 변환 | `crypto{inmatrix}` |
| 4 | [Round Keys](cryptohack/Round%20Keys/) | 20 | AddRoundKey (XOR) | `crypto{r0undk3y}` |
| 5 | [Confusion through Substitution](cryptohack/Confusion%20through%20Substitution/) | 25 | SubBytes (inv_s_box) | `crypto{l1n34rly}` |
| 6 | [Diffusion through Permutation](cryptohack/Diffusion%20through%20Permutation/) | 30 | inv_shift_rows + inv_mix_columns | `crypto{d1ffUs3R}` |
| 7 | [Bringing It All Together](cryptohack/Bringing%20It%20All%20Together/) | 50 | AES-128 전체 복호화 | `crypto{MYAES128}` |
| 8 | [Modes of Operation Starter](cryptohack/Modes%20of%20Operation%20Starter/) | 15 | ECB decrypt oracle | `crypto{bl0ck_c1ph3r5_4r3_f457_!}` |
| 9 | [Passwords as Keys](cryptohack/Passwords%20as%20Keys/) | 50 | dictionary attack (md5) | `crypto{k3y5__r__n07__p455w0rdz?}` |
| 10 | [ECB CBC WTF](cryptohack/ECB%20CBC%20WTF/) | 55 | CBC→ECB 수동 복호화 | `crypto{3cb_5uck5_4v01d_17_!!!!!}` |
| 11 | [ECB Oracle](cryptohack/ECB%20Oracle/) | 60 | byte-at-a-time ECB | `crypto{p3n6u1n5_h473_3cb}` |
| 12 | [Flipping Cookie](cryptohack/Flipping%20Cookie/) | 60 | CBC bit-flipping | `crypto{4u7h3n71c4710n_15_3553n714l}` |
| 13 | [Lazy CBC](cryptohack/Lazy%20CBC/) | 60 | IV=KEY 키 추출 | `crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}` |
| 14 | [Triple DES](cryptohack/Triple%20DES/) | 60 | DES weak key 자기역원 | `crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}` |
| 15 | [Symmetry](cryptohack/Symmetry/) | 50 | OFB encrypt=decrypt | `crypto{0fb_15_5ymm37r1c4l_!!!11!}` |
| 16 | [Bean Counter](cryptohack/Bean%20Counter/) | 60 | CTR 카운터 버그 + known PNG header | `crypto{hex_bytes_beans}` |
| 17 | [CTRIME](cryptohack/CTRIME/) | 70 | CRIME 압축 오라클 | `crypto{CRIME_571ll_p4y5}` |
| 18 | [Logon Zero](cryptohack/Logon%20Zero/) | 80 | CFB-8 Zerologon (CVE-2020-1472) | `crypto{Zerologon_Windows_CVE-2020-1472}` |
| 19 | [Stream of Consciousness](cryptohack/Stream%20of%20Consciousness/) | 80 | CTR nonce 재사용 many-time pad | `crypto{k3y57r34m_r3u53_15_f474l}` |
| 20 | [Dancing Queen](cryptohack/Dancing%20Queen/) | 120 | ChaCha20 역연산 (addition 누락) | `crypto{M1x1n6_r0und5_4r3_1nv3r71bl3!}` |
| 21 | [Oh SNAP](cryptohack/Oh%20SNAP/) | 120 | RC4 FMS 공격 | `crypto{w1R3d_equ1v4l3nt_pr1v4cy?!}` |
| 22 | [Pad Thai](cryptohack/Pad%20Thai/) | 80 | 클래식 패딩 오라클 | `crypto{if_you_ask_enough_times_you_usually_get_what_you_want}` |
| 23 | [The Good The Pad The Ugly](cryptohack/The%20Good%20The%20Pad%20The%20Ugly/) | 100 | 노이즈 패딩 오라클 (OR) | `crypto{even_a_faulty_oracle_leaks_all_information}` |
| 24 | [Oracular Spectacular](cryptohack/Oracular%20Spectacular/) | 150 | 노이즈 패딩 오라클 (XOR) | 진행 중 |

### General
| # | 문제 | pts | technique | 플래그 |
|---|------|-----|-----------|--------|
| 1 | [Great Snakes](cryptohack/Great%20Sankes/) | 3 | Python XOR 실행 | `crypto{z3n_0f_pyth0n}` |
| 2 | [Network Attacks](cryptohack/Network%20Attacks/) | 5 | pwntools JSON socket | `crypto{sh0pp1ng_f0r_fl4g5}` |

---

## 통계
- **총 문제**: 45개 (1개 진행 중)
- **총 점수**: 1875 pts
- **카테고리**: Encoding(5), XOR(5), Mathematics(5), Data Formats(4), AES(24), General(2)
