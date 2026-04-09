# Crypto CTF - CryptoHack Writeups

## Progress Overview

| Category | Progress | Status |
|----------|----------|--------|
| Introduction | 3 / 3 | ✅ |
| General | 19 / 19 | ✅ |
| Symmetric Ciphers | 27 / 27 | ✅ |
| Mathematics | 15 / 15 | ✅ |
| RSA | 29 / 29 | ✅ |
| Diffie-Hellman | 9 / 14 | 🔨 |
| Elliptic Curves | 14 / 23 | 🔨 |
| Hash Functions | 5 / 14 | 🔨 |
| Crypto on the Web | 7 / 17 | 🔨 |
| Lattices | 12 / 18 | 🔨 |
| Isogenies | 6 / 23 | 🔨 |
| ZKPs | 2 / 17 | 🔨 |
| Misc | 5 / 14 | 🔨 |
| CTF Archive | 0 / 75 | ⬜ |

**총 점수**: 1875+ pts (+ 신규 풀이 ~1500pts)

---

## Introduction (3/3) ✅

- [x] Great Snakes — 3pts — Python XOR 실행 — `crypto{z3n_0f_pyth0n}`
- [x] Network Attacks — 5pts — pwntools JSON socket — `crypto{sh0pp1ng_f0r_fl4g5}`
- [x] Finding Flags — 2pts

## General (19/19) ✅

### Encoding
- [x] ASCII — 5pts — `chr()` 변환
- [x] Hex — 5pts — `bytes.fromhex()`
- [x] Base64 — 10pts — hex→bytes→base64
- [x] Bytes and Big Integers — 10pts — `int.to_bytes()` / `long_to_bytes()`
- [x] Encoding Challenge — 40pts — 다중 인코딩 자동 디코딩 + pwntools

### XOR
- [x] XOR Starter — 10pts — single-byte XOR
- [x] XOR Properties — 15pts — XOR 교환/결합/자기역원 성질
- [x] Favourite byte — 20pts — single-byte XOR brute force (256)
- [x] You either know XOR you don't — 30pts — known plaintext + repeating-key XOR
- [x] Lemur XOR — 40pts — 이미지 XOR

### Mathematics
- [x] Greatest Common Divisor — 15pts — 유클리드 알고리즘
- [x] Extended GCD — 20pts — 확장 유클리드 → 모듈러 역원
- [x] Modular Arithmetic 1 — 20pts — 모듈러 나머지 연산
- [x] Modular Arithmetic 2 — 20pts — 페르마 소정리
- [x] Modular Inverting — 25pts — `pow(a,-1,p)`

### Data Formats
- [x] Privacy-Enhanced Mail — 25pts — PEM 파싱
- [x] CERTainly not — 30pts — DER x509 인증서 파싱
- [x] SSH Keys — 35pts — ssh-rsa 공개키 바이너리 파싱
- [x] Transparency — 50pts — Certificate Transparency (crt.sh)

## Symmetric Ciphers (27/27) ✅

### How AES Works
- [x] Keyed Permutations — 5pts
- [x] Resisting Bruteforce — 10pts
- [x] Structure of AES — 15pts
- [x] Round Keys — 20pts
- [x] Confusion through Substitution — 25pts
- [x] Diffusion through Permutation — 30pts
- [x] Bringing It All Together — 50pts

### Symmetric Starter
- [x] Modes of Operation Starter — 15pts
- [x] Passwords as Keys — 50pts

### Block Ciphers 1
- [x] ECB CBC WTF — 55pts
- [x] ECB Oracle — 60pts
- [x] Flipping Cookie — 60pts
- [x] Lazy CBC — 60pts
- [x] Triple DES — 60pts

### Stream Ciphers
- [x] Symmetry — 50pts
- [x] Bean Counter — 60pts
- [x] CTRIME — 70pts
- [x] Logon Zero — 80pts
- [x] Stream of Consciousness — 80pts
- [x] Dancing Queen — 120pts
- [x] Oh SNAP — 120pts

### Padding Attacks
- [x] Pad Thai — 80pts
- [x] The Good The Pad The Ugly — 100pts
- [x] Oracular Spectacular — 150pts

### Authenticated Encryption
- [x] Forbidden Fruit
- [x] Paper Plane

### Linear Cryptanalysis
- [x] Beatboxer

## Mathematics (15/15) ✅

### Modular Math
- [x] Chinese Remainder Theorem
- [x] Quadratic Residues
- [x] Legendre Symbol
- [x] Modular Square Root

### Brainteasers Part 1
- [x] Successive Powers
- [x] Adrien's Signs
- [x] Modular Binomials
- [x] Broken RSA
- [x] No Way Back Home

### Brainteasers Part 2
- [x] Unencryptable
- [x] Ellipse Curve Cryptography
- [x] Roll your Own
- [x] Real Eisenstein
- [x] Cofactor Cofantasy

### Primes
- [x] Prime and Prejudice

## RSA (29/29) ✅

### Starter
- [x] RSA Signatures
- [x] Public Keys
- [x] Euler's Totient
- [x] Modular Exponentiation
- [x] Private Keys
- [x] RSA Decryption

### Primes Part 1
- [x] Factoring
- [x] Manyprime
- [x] Monoprime
- [x] Square Eyes
- [x] Inferius Prime

### Primes Part 2
- [x] Marin's Secrets
- [x] Ron was Wrong, Whit is Right
- [x] Fast Primes
- [x] RSA Backdoor Viability
- [x] Infinite Descent

### Public exponent
- [x] Salty
- [x] Modulus Inutilis
- [x] Everything is Big
- [x] Crossed Wires
- [x] Everything is Still Big
- [x] Endless Emails

### Signatures Part 1
- [x] Signing Server
- [x] Let's Decrypt
- [x] Blinding Light

### Signatures Part 2
- [x] Let's Decrypt Again
- [x] Vote for Pedro

### PADDING
- [x] Bespoke Padding
- [x] Null or Never

## Diffie-Hellman (9/14) 🔨

### Starter ✅
- [x] Working with Fields — 10pts
- [x] Generators of Groups — 20pts
- [x] Computing Public Values — 25pts
- [x] Computing Shared Secrets — 30pts
- [x] Deriving Symmetric Keys — 40pts

### Man In The Middle (2/3)
- [x] Parameter Injection — 60pts
- [x] Export-grade
- [ ] Static Client *(server)*

### Group Theory (0/2)
- [ ] Additive *(server)*
- [ ] Static Client 2 *(server)*

### Misc (2/4)
- [x] Script Kiddie — `crypto{b3_c4r3ful_w1th_y0ur_n0tati0n}`
- [x] The Matrix — `crypto{there_is_no_spoon_66eff188}`
- [ ] The Matrix Reloaded *(SageMath 필요)*
- [ ] The Matrix Revolutions *(SageMath 필요)*

## Elliptic Curves (14/23) 🔨

### Background ✅
- [x] Background Reading — 5pts — `abelian`

### Starter ✅
- [x] Point Negation — 10pts — `(8045, 2803)`
- [x] Point Addition — 30pts — `(4215, 2162)`
- [x] Scalar Multiplication — 35pts — `(9467, 2742)`
- [x] Curves and Logs — 40pts — `crypto{80e5212754a824d3a4aed185ace4f9cac0f908bf}`
- [x] Efficient Exchange — 50pts — `crypto{3ff1c1ent_k3y_3xch4ng3}`

### Parameter Choice (3/5)
- [ ] Smooth Criminal — 60pts *(SageMath 필요: curve order)*
- [x] Exceptional Curves — 100pts — `crypto{H3ns3l_lift3d_my_fl4g!}` (Smart's attack)
- [ ] Micro Transmissions — 120pts *(SageMath 필요: BSGS)*
- [x] Elliptic Nodes — 150pts — `crypto{s1ngul4r_s1mplif1c4t1on}` (singular curve)
- [x] Moving Problems — 150pts — `crypto{MOV_attack_on_non_supersingular_curves}`

### Parameter Choice 2 (1/5)
- [ ] A Twisted Mind — 80pts *(server)*
- [ ] An Exceptional Twisted Mind — 125pts *(server)*
- [ ] Checkpoint — 150pts *(server)*
- [ ] An Evil Twisted Mind — 175pts *(server)*
- [x] Real Curve Crypto — 200pts — `crypto{real_fields_arent_finite}` (PSLQ + real elliptic log)

### Edwards Curves ✅
- [x] Edwards Goes Degenerate — 100pts — `crypto{degenerates_will_never_keep_a_secret}`

### Side Channels ✅
- [x] Montgomery's Ladder — 40pts — Curve25519 ladder
- [x] Double and Broken — 50pts — `crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}`

### Signatures (1/4)
- [ ] Digestive — 60pts *(web server)*
- [ ] ProSign 3 — 100pts *(server)*
- [ ] Curveball — 100pts *(server)*
- [x] No Random, No Bias — 120pts — `crypto{3mbrac3_r4nd0mn3ss}` (HNP/lattice attack)

## Hash Functions (5/14) 🔨

### Probability ✅
- [x] Jack's Birthday Hash — `1420`
- [x] Jack's Birthday Confusion — `76`

### Collisions (0/5)
- [ ] No Difference *(server)*
- [ ] Collider *(server)*
- [ ] Hash Stuffing *(server)*
- [ ] Twin Keys *(server)*
- [ ] PriMeD5 *(server)*

### Pre-image attacks (0/2)
- [ ] Mixed Up *(server)*
- [ ] Invariant *(server)*

### Length Extension (0/2)
- [ ] MD0 *(server)*
- [ ] MDFlag *(server)*

### Hash-based Cryptography ✅
- [x] Merkle Trees — `crypto{U_are_R3ady_For_S4plins_ch4lls}`
- [x] WOTS Up — `ECSC{h4sh1ng_ch41n_r34ct1on_ff_}`
- [x] WOTS Up 2 — `ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}`

## Crypto on the Web (7/17) 🔨

### JSON Web Tokens (2/7)
- [x] Token Appreciation — `crypto{jwt_contents_can_be_easily_viewed}`
- [x] JWT Sessions — theory: `Authorization`
- [ ] No Way JOSE *(web server)*
- [ ] JWT Secrets *(web server)*
- [ ] RSA or HMAC *(web server)*
- [ ] RSA or HMAC Part 2 *(web server)*
- [ ] JSON in JSON *(web server)*

### TLS Part 1 The Protocol (5/7)
- [ ] Secure Protocols *(live cert query)*
- [ ] Saying Hello *(live TLS query)*
- [x] TLS Handshake — `crypto{67c6bf8ffda56fcb359fba7f0149f85422223cf021ab1a0af701de5dd2091498}`
- [x] Sharks on the Wire — `15` (pcap analysis)
- [x] Decrypting TLS 1.2 — `crypto{weaknesses_of_non_ephemeral_key_exchange}`
- [x] Decrypting TLS 1.3 — `crypto{export_SSLKEYLOGFILE}`
- [x] Authenticated Handshake — `crypto{b51d7b5fb12aa3d692140d8f1f80732610e99411ca0f6d928b0f60570cbc778e672457a729d7cf3b58bc174f00dc5d30}`

### Cloud (0/3)
- [ ] Megalomaniac 1 *(server)*
- [ ] Megalomaniac 2 *(server)*
- [ ] Megalomaniac 3 *(server)*

## Lattices (12/18) 🔨

### Lattices ✅
- [x] Vectors — `702`
- [x] Size and Basis — `9.0`
- [x] What's a Lattice — `255`
- [x] Gram Schmidt — `0.91611`
- [x] Gaussian Reduction — `7410790865146821`
- [x] Find the Lattice — `crypto{Gauss_lattice_attack!}`
- [x] Backpack Cryptography — `crypto{my_kn4ps4ck_1s_l1ghtw31ght}` (LLL)

### Learning With Errors 1 ✅
- [x] LWE Background — `Oded Regev`
- [x] LWE Intro — `Gaussian Elimination`
- [x] LWE Low Bits Message — `147`
- [x] LWE High Bits Message — `201`
- [x] From Private to Public Key LWE — `1568`

### Learning With Errors 2 (2/6)
- [ ] Noise Free *(server)*
- [ ] Noise Cheap *(server)*
- [x] Bounded Noise — `crypto{linearised_polynomials_for_bounded_errors}` (Arora-Ge)
- [x] Nativity — `crypto{flavortext-flag-coprime-regev-yadda-yadda}`
- [ ] Missing Modulus *(server)*
- [ ] Too Many Errors *(server)*

## Isogenies (6/23) 🔨

### Introduction ✅
- [x] Introduction to Isogenies — `crypto{65537}`

### Starter ✅
- [x] Montgomery Curves — `crypto{723347356}` (twist pair)
- [x] The j-invariant — `crypto{127}`
- [x] Image Point Arithmetic — `crypto{37097}`
- [x] Where's the Supersingular Curve — `crypto{170141183460469230846243588177825628225}`
- [x] DLOG on the Surface — `crypto{now_try_writing_a_function_for_fast_torsion_basis_generation!}`

### Road to SIDH (0/5) *(SageMath 필요)*
- [ ] Two Isogenies
- [ ] Three Isogenies
- [ ] Composite Isogenies
- [ ] SIDH Key Exchange
- [ ] Breaking SIDH

### Road to CSIDH (0/5) *(SageMath 필요)*
- [ ] Special Isogenies
- [ ] Prime Power Isogenies
- [ ] Secret Exponents
- [ ] CSIDH Key Exchange
- [ ] Twisted CSIDH Isogenies

### Isogeny Challenges (0/7) *(대부분 SageMath 필요)*
- [ ] What's My Kernel
- [ ] Better than Linear
- [ ] Meet me in the Claw
- [ ] André Encoding
- [ ] Dual Masters
- [ ] Abelian SIDH
- [ ] A True Genus *(SageMath: CSIDH)*

## ZKPs (2/17) 🔨

### Sigma Protocol (1/11)
- [x] ZKP Introduction — `crypto{1985}`
- [ ] Proofs of Knowledge *(server)*
- [ ] Honest Verifier Zero Knowledge *(server)*
- [ ] Special Soundness *(server)*
- [ ] Non-Interactive *(server)*
- [ ] Too Honest *(server)*
- [ ] Fischlin Transform *(server)*
- [ ] OR Proof *(server)*
- [ ] Hamiltonicity 1 *(server)*
- [ ] Hamiltonicity 2 *(server)*
- [ ] Ticket Maestro *(server)*

### ZKP Challenges (1/6)
- [ ] Let's Prove It *(server)*
- [ ] Let's Prove It Again *(server)*
- [ ] Couples *(server)*
- [ ] Mister Saplin's Preview *(server)*
- [ ] Mister Saplins The Prover *(server)*
- [x] Pairing-Based Cryptography — `crypto{Pa1rings_R_Str0ng}`

## Misc (5/14) 🔨

### ElGamal ✅
- [x] Bit by Bit — `crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}` (Legendre symbol)

### LFSR (2/3)
- [ ] LFSR Destroyer *(server)*
- [x] Jeff's LFSR — `crypto{Geffe_generator_is_a_textbook_example_to_show_correlation_attacks_on_LFSR}`
- [x] L-Win — `crypto{minimal_polynomial_in_an_arbitrary_field}` (Berlekamp-Massey)

### One Time Pad (0/2)
- [ ] No Leaks *(server)*
- [ ] Gotta Go Fast *(server)*

### PRNGs (1/4)
- [ ] Lo-Hi Card Game *(server)*
- [ ] Nothing Up My Sleeve *(server)*
- [x] RSA vs RNG — `crypto{pseudorandom_shamir_adleman}` (LCG Hensel lift)
- [ ] Trust Games *(server)*

### Password Complexity (0/2)
- [ ] Bruce Schneier's Password *(server)*
- [ ] Bruce Schneier's Password Part 2 *(server)*

### Secret Sharing Schemes (1/2)
- [ ] Toshi's Treasure *(server)*
- [x] Armory — `crypto{fr46m3n73d_b4ckup_vuln?}` (deterministic Shamir)

## CTF Archive (0/75) ⬜

*See `cryptohack/CTF Archive/` for challenge files (2020-2025)*
