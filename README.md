# Crypto CTF - CryptoHack Writeups

## Progress Overview

| Category | Progress | Status |
|----------|----------|--------|
| Introduction | 3 / 3 | ✅ |
| General | 19 / 19 | ✅ |
| Symmetric Ciphers | 27 / 27 | ✅ |
| Mathematics | 15 / 15 | ✅ |
| RSA | 29 / 29 | ✅ |
| Diffie-Hellman | 14 / 14 | ✅ |
| Elliptic Curves | 20 / 23 | 🔨 |
| Hash Functions | 13 / 14 | 🔨 |
| Crypto on the Web | 14 / 17 | 🔨 |
| Lattices | 18 / 18 | ✅ |
| Isogenies | 23 / 23 | ✅ |
| ZKPs | 16 / 17 | 🔨 |
| Misc | 12 / 14 | 🔨 |
| CTF Archive | 17 / 75 | 🔨 |

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

## Diffie-Hellman (14/14) ✅

### Starter ✅
- [x] Working with Fields — 10pts
- [x] Generators of Groups — 20pts
- [x] Computing Public Values — 25pts
- [x] Computing Shared Secrets — 30pts
- [x] Deriving Symmetric Keys — 40pts

### Man In The Middle ✅
- [x] Parameter Injection — 60pts
- [x] Export-grade
- [x] Static Client — smooth prime > p_orig 필수 (Pohlig-Hellman truncation)

### Group Theory ✅
- [x] Additive — `crypto{cycl1c_6r0up_und3r_4dd1710n?}` (additive DLP = a = A·g⁻¹)
- [x] Static Client 2 — `crypto{uns4f3_pr1m3_sm4ll_oRd3r}` (smooth-prime PH; Bob rejects A=2)

### Misc ✅
- [x] Script Kiddie — `crypto{b3_c4r3ful_w1th_y0ur_n0tati0n}`
- [x] The Matrix — `crypto{there_is_no_spoon_66eff188}`
- [x] The Matrix Reloaded — `crypto{the_oracle_told_me_about_you_91e019ff}` (repeated-root local-ring trick: SECRET = λ·b/a)
- [x] The Matrix Revolutions — `crypto{we_are_looking_for_the_keymaker_478415c4}` (min poly factors GF(2^61)·GF(2^89), DLPs via PARI fflog + CRT)

## Elliptic Curves (14/23) 🔨

### Background ✅
- [x] Background Reading — 5pts — `abelian`

### Starter ✅
- [x] Point Negation — 10pts — `(8045, 2803)`
- [x] Point Addition — 30pts — `(4215, 2162)`
- [x] Scalar Multiplication — 35pts — `(9467, 2742)`
- [x] Curves and Logs — 40pts — `crypto{80e5212754a824d3a4aed185ace4f9cac0f908bf}`
- [x] Efficient Exchange — 50pts — `crypto{3ff1c1ent_k3y_3xch4ng3}`

### Parameter Choice (5/5) ✅
- [x] Smooth Criminal — 60pts — `crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}` (Sage curve-order → smooth → PH+BSGS)
- [x] Exceptional Curves — 100pts — `crypto{H3ns3l_lift3d_my_fl4g!}` (Smart's attack)
- [x] Micro Transmissions — 120pts — `crypto{d0nt_l3t_n_b3_t00_sm4ll}` (Pohlig-Hellman, smooth curve order, nbits=64)
- [x] Elliptic Nodes — 150pts — `crypto{s1ngul4r_s1mplif1c4t1on}` (singular curve)
- [x] Moving Problems — 150pts — `crypto{MOV_attack_on_non_supersingular_curves}`

### Parameter Choice 2 (2/5)
- [x] A Twisted Mind — 80pts — `crypto{tw1st_s3curity_of_x_0nly_ladder}` (X-only ladder twist attack, PH over curve N_smooth + twist Np_smooth)
- [ ] An Exceptional Twisted Mind — 125pts *(Z/p² Smart-style lift, modulus = secp256k1_prime²)*
- [ ] Checkpoint — 150pts *(invalid curve attack on ECDH-AES)*
- [ ] An Evil Twisted Mind — 175pts *(384-bit composite modulus, needs factoring)*
- [x] Real Curve Crypto — 200pts — `crypto{real_fields_arent_finite}` (PSLQ + real elliptic log)

### Edwards Curves ✅
- [x] Edwards Goes Degenerate — 100pts — `crypto{degenerates_will_never_keep_a_secret}`

### Side Channels ✅
- [x] Montgomery's Ladder — 40pts — Curve25519 ladder
- [x] Double and Broken — 50pts — `crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}`

### Signatures ✅
- [x] Digestive — 60pts — `crypto{thanx_for_ctf_inspiration_https://mastodon.social/@filippo/109360453402691894}` (24-byte digest truncation + duplicate JSON "admin" key)
- [x] ProSign 3 — 100pts — `crypto{ECDSA_700_345y_70_5cr3wup}` (ECDSA tiny nonce recovery)
- [x] Curveball — 100pts — `crypto{Curveballing_Microsoft_CVE-2020-0601}` (CVE-2020-0601 explicit-params attack)
- [x] No Random, No Bias — 120pts — `crypto{3mbrac3_r4nd0mn3ss}` (HNP/lattice attack)

## Hash Functions (13/14) 🔨

### Probability ✅
- [x] Jack's Birthday Hash — `1420`
- [x] Jack's Birthday Confusion — `76`

### Collisions (4/5) — Twin Keys only remaining
- [x] No Difference — `crypto{n0_d1ff_n0_pr0bl3m}` (2-block differential via SBOX 0xdf-symmetry)
- [x] Collider — `crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}` (Wang MD5 collision pair)
- [x] Hash Stuffing — `crypto{Always_add_padding_even_if_its_a_whole_block!!!}` (non-injective padding)
- [ ] Twin Keys *(server — HashClash CPC, GPU build running)*
- [x] PriMeD5 — `crypto{MD5_5uck5_p4rt_tw0}` (fastcoll loop → prime/composite MD5 collision)

### Pre-image attacks ✅
- [x] Mixed Up — `crypto{y0u_c4n7_m1x_3v3ry7h1n6_1n_l1f3}`
- [x] Invariant — `crypto{preimages_of_the_all_zero_output}` (2-block hash-zero search)

### Length Extension ✅
- [x] MD0 — `crypto{l3ngth_3xT3nd3r}` (MD5 length extension forgery)
- [x] MDFlag — flag byte-by-byte leak via MD5 length extension

### Hash-based Cryptography ✅
- [x] Merkle Trees — `crypto{U_are_R3ady_For_S4plins_ch4lls}`
- [x] WOTS Up — `ECSC{h4sh1ng_ch41n_r34ct1on_ff_}`
- [x] WOTS Up 2 — `ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}`

## Crypto on the Web (14/17) 🔨

### JSON Web Tokens (7/7) ✅
- [x] Token Appreciation — `crypto{jwt_contents_can_be_easily_viewed}`
- [x] JWT Sessions — theory: `Authorization`
- [x] No Way JOSE — `crypto{The_Cryptographic_Doom_Principle}` (alg:none bypass)
- [x] JWT Secrets — `crypto{jwt_secret_keys_must_be_protected}` (weak default secret `"secret"`)
- [x] RSA or HMAC — `crypto{Doom_Principle_Strikes_Again}` (HS256/RS256 key confusion via PEM-as-HMAC-secret)
- [x] RSA or HMAC Part 2 — `crypto{thanks_silentsignal_for_inspiration}` (gmpy2 N recovery from RS256 sigs + PKCS1 PEM forge)
- [x] JSON in JSON — `crypto{https://owasp.org/www-community/Injection_Theory}` (username JSON injection → duplicate admin key)

### TLS Part 1 The Protocol (7/7) ✅
- [x] Secure Protocols — (cert download)
- [x] Saying Hello — `ECDHE-RSA-AES256-GCM-SHA384` (openssl s_client -tls1_2)
- [x] TLS Handshake — `crypto{67c6bf8ffda56fcb359fba7f0149f85422223cf021ab1a0af701de5dd2091498}`
- [x] Sharks on the Wire — `15` (pcap analysis)
- [x] Decrypting TLS 1.2 — `crypto{weaknesses_of_non_ephemeral_key_exchange}`
- [x] Decrypting TLS 1.3 — `crypto{export_SSLKEYLOGFILE}`
- [x] Authenticated Handshake — `crypto{b51d7b5fb12aa3d692140d8f1f80732610e99411ca0f6d928b0f60570cbc778e672457a729d7cf3b58bc174f00dc5d30}`

### Cloud (0/3)
- [ ] Megalomaniac 1 *(server)*
- [ ] Megalomaniac 2 *(server)*
- [ ] Megalomaniac 3 *(server)*

## Lattices (18/18) ✅

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

### Learning With Errors 2 (6/6) ✅
- [x] Noise Free — `crypto{linear_algebra_is_useful}` (Gaussian elim over GF(q))
- [x] Noise Cheap — `crypto{LLL_is_also_very_useful!}` (short-secret Kannan embedding + BKZ)
- [x] Bounded Noise — `crypto{linearised_polynomials_for_bounded_errors}` (Arora-Ge linearization, binary noise → degree-2 system over GF(q))
- [x] Nativity — `crypto{flavortext-flag-coprime-regev-yadda-yadda}` (GF(2) reduction: pk last row ≡ s@A mod 2)
- [x] Missing Modulus — `crypto{learning-is-easy-over-the-real-numbers}` (integer linalg, noise ≪ matrix scale)
- [x] Too Many Errors — `crypto{f4ult_4ttack5_0n_lw3}` (reset+majority vote → 1-coord fault recovery)

## Isogenies (23/23) ✅

### Introduction ✅
- [x] Introduction to Isogenies — `crypto{65537}`

### Starter ✅
- [x] Montgomery Curves — `crypto{723347356}` (twist pair)
- [x] The j-invariant — `crypto{127}`
- [x] Image Point Arithmetic — `crypto{37097}`
- [x] Where's the Supersingular Curve — `crypto{170141183460469230846243588177825628225}`
- [x] DLOG on the Surface — `crypto{now_try_writing_a_function_for_fast_torsion_basis_generation!}`

### Road to SIDH (5/5) ✅
- [x] Two Isogenies — `crypto{287496}` (Sage E.isogeny(K))
- [x] Three Isogenies — `crypto{96392670793}`
- [x] Composite Isogenies — `crypto{249510360818*i + 292990704480}` (chain 13 three-isogenies)
- [x] SIDH Key Exchange — `crypto{congratulations_you_are_an_isogenist!}`
- [x] Breaking SIDH — `crypto{welcome_to_the_future_of_isogenies}` (Castryck-Decru attack: sB=39990433064274301814750584859416466)

### Road to CSIDH ✅
- [x] Special Isogenies — `crypto{199}` (Montgomery A of 5-isogeny codomain)
- [x] Prime Power Isogenies — `crypto{27}` (7-isogeny graph cycle length)
- [x] Secret Exponents — `crypto{404}` (CSIDH with [2,3,4] vector)
- [x] CSIDH Key Exchange — `crypto{post_quantum_NIKE_isogenies_just_do_it}` (twist trick: negative step = positive on twist, A → -A)
- [x] Twisted CSIDH Isogenies — `crypto{261}` (backward step on 3-isogeny graph)

### Isogeny Challenges (7/7) ✅
- [x] What's My Kernel — `crypto{whoops_this_was_just_a_dlog}` (P_b=P_a bug → direct DL)
- [x] Better than Linear — `crypto{48495725269*i + 91493879515}` (large-prime factored isogeny)
- [x] Meet me in the Claw — `crypto{clawing_our_way_to_victory}` (MITM on 2-isogeny graph via Φ2 modular polynomial)
- [x] André Encoding — `crypto{weil_pairings_and_isogenies_are_best_friends}` (Weil pairing degree leak)
- [x] Dual Masters — `crypto{but_I_only_gave_one_point?!}` (phi_hat.dual() from Sage built-in, then DL like What's My Kernel)
- [x] Abelian SIDH — `crypto{wait_I_thought_this_was_the_post_quantum_section}` (phi_hat∘phi = [deg])
- [x] A True Genus — `crypto{Gauss_knew_how_to_break_CSIDH???}` (CSIDH genus character χ: δ(base,EA)==δ(EB,EC) → bit=1)

## ZKPs (16/17) 🔨

### Sigma Protocol (10/11)
- [x] ZKP Introduction — `crypto{1985}`
- [x] Proofs of Knowledge — `crypto{sigma_protocol_complete!}` (honest Schnorr w leaked in source)
- [x] Honest Verifier Zero Knowledge — `crypto{so_honest_very_zero_knowledge}` (Schnorr simulator)
- [x] Special Soundness — `crypto{specially_sound_sigmas}` (nonce reuse → witness extract)
- [x] Non-Interactive — `crypto{shvzk_and_ss_to_nizk}` (Fiat-Shamir honest prover, w hardcoded)
- [x] Too Honest — `crypto{2_hon3st_to_b3_tru3}` (unreduced z + uncapped e → w = z // huge_e)
- [x] Fischlin Transform *(CTF Archive)* (WI distinguisher via RO hit count)
- [x] OR Proof — `crypto{sigma_protocols_compose!}` (archive.cryptohack.org:11840 — OR proof completeness + special-soundness witness extraction + SHVZK simulation)
- [x] Hamiltonicity 1 *(CTF Archive)* (online FS: grind A until challenge=0)
- [ ] Hamiltonicity 2 *(CTF Archive)*
- [x] Ticket Maestro *(server)* (Groth16 rerandomization → replay with new proof ID)

### ZKP Challenges (6/6) ✅
- [x] Let's Prove It — `crypto{HNP_1s_a_b3aut1ful_Pr0blem_no?}` (c=H² → c*FLAG~2^824>>v~2^512 → only ~1 FLAG candidate per known-p proof)
- [x] Let's Prove It Again — `crypto{CRT_1s_m4gic_for_cryptanalysis}` (Schnorr nonce reuse with v fixed across different primes; integer equation + bruteforce R.randint)
- [x] Couples — `crypto{don_t_let_useless_param_and_edge_cases_in_your_code}` (BLS verifier bypass: set_internal_z(p-5) via Fermat → inverse(0,p)=0 → z=0 → trivial pairing)
- [x] Mister Saplin's Preview — `crypto{M3rkle_tree_AND_race_condition_AND_replay_attack___that's_too_much}` (thread-race TOCTOU)
- [x] Mister Saplins The Prover — `crypto{M3rkle_Trees__funny_if_U_can_replay_atk}` (negative index -1 → nodes[1][0]; leaf3-7 = FLAG-only → same across connections; 5 connections collect right subtree, 6th brute-forces secret[16] 256 ways)
- [x] Pairing-Based Cryptography — `crypto{Pa1rings_R_Str0ng}`

## Misc (12/14) 🔨

### ElGamal ✅
- [x] Bit by Bit — `crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}` (Legendre symbol)

### LFSR (2/3)
- [ ] LFSR Destroyer *(server, skipped — algebraic attack)*
- [x] Jeff's LFSR — `crypto{Geffe_generator_is_a_textbook_example_to_show_correlation_attacks_on_LFSR}`
- [x] L-Win — `crypto{minimal_polynomial_in_an_arbitrary_field}` (Berlekamp-Massey)

### One Time Pad ✅
- [x] No Leaks — `crypto{unr4nd0m_07p}` (rejection sampling → missing-byte-per-position is flag byte)
- [x] Gotta Go Fast — `crypto{t00_f4st_t00_furi0u5}` (time-based OTP, ±30s brute window)

### PRNGs ✅
- [x] Lo-Hi Card Game — `crypto{shuffl3_tr4ck1n6_i5_1t_l3g4l?}` (LCG recovery from base-52 card stream, 3 states → A,B)
- [x] Nothing Up My Sleeve — `crypto{No_Str1ngs_Att4ch3d}` (Dual EC DRBG backdoor, player Q := P)
- [x] RSA vs RNG — `crypto{pseudorandom_shamir_adleman}` (LCG Hensel lift)
- [x] Trust Games — `crypto{L4ttice_C0mpl1ant_G4m3}` (truncated LCG + LLL)

### Password Complexity (1/2)
- [x] Bruce Schneier's Password — `crypto{https://www.schneierfacts.com/facts/1341}` (numpy int64 overflow → prime product)
- [ ] Bruce Schneier's Password Part 2 *(skipped — needs MITM over 2^64 for sum==prod constraint)*

### Secret Sharing Schemes ✅
- [x] Toshi's Treasure — `crypto{shoulda_used_verifiable_secret_sharing}` (adaptive fake share in 5-of-6 SSSS via Lagrange linearity)
- [x] Armory — `crypto{fr46m3n73d_b4ckup_vuln?}` (deterministic Shamir)

## CTF Archive (17/75) 🔨

### 2020 (4/?)
- [x] 1337crypt (DownUnderCTF) — `DUCTF{wh0_N33ds_pr3cIsi0n_wh3n_y0u_h4v3_c0pp3rsmiths_M3thod}` (Coppersmith p recovery from sqrt hint, GM decryption)
- [x] Calm Down (HKCERT CTF) — `hkcert20{c4lm_d0wn_4nd_s0lv3_th3_ch4llen9e}` (RSA last-byte oracle 0x81 fixed-point binary search)
- [x] 2020 (TETCTF) (MT19937 prediction via index 1396/1792)
- [x] Sign in Please (HKCERT CTF) (SHA-256 length extension + pbox rainbow table)

### 2021 (7/?)
- [x] 1337crypt v2 (DownUnderCTF) — `DUCTF{mantissa_in_crypto??_n0_th4nks!!}` (3×3 LLL on normalized hint2 to recover d, then p)
- [x] 1n_jection (Zh3r0 CTF V2) — `zh3r0{wh0_th0ugh7_b1j3c710n5_fr0m_n^k_t0_n_c0uld_b3_s00000_c0000000l!}` (inverse Cantor pairing)
- [x] A Joke Cipher (HKCERT CTF) — `hkcert21{th1s_i5_wh4t_w3_c4ll3d_sn4k3o1l_crypt0sy5t3m}` (Nagaty shared key = (yA·yB)² mod p)
- [x] Key Backup Service 2 (HKCERT CTF) — `hkcert21{y0u_d0nt_n33d_p41rw15e_9cd_1f_y0u_c4n_d0_i7_1n_b4tch}` (ord(G)=2²⁵ birthday + GCD prime)
- [x] Twist and Shout (Zh3r0 CTF V2) — `zh3r0{7h3_fu7ur3_m1gh7_b3_c4p71v471ng_bu7_n0w_y0u_kn0w_h0w_t0_l00k_a7_7h3_p457}` (MT19937 untemper + reverse in-place twist → state bytes)
- [x] Unimplemented (TETCTF) — `TetCTF{c0unt1ng_1s_n0t_4lw4ys_34sy-vina:*100*48012023578024#}` (Gaussian integer RSA lambda)
- [x] Unevaluated (TETCTF) — `TetCTF{h0m0m0rph1sm_1s_0ur_fr13nd-mobi:*100*231199111007#}` (Z[i]/p² DLP: norm map + Paillier log mod p + Sage F_p* DLP mod q + partial PH)
- [x] import numpy as MT (Zh3r0 CTF V2) — `zh3r0{wh0_th0ugh7_7h3_m3r53nn3_7w1573r_w45_5o_pr3d1c74bl3?c3rt41nly_n0t_m47454n0}` (numpy MT 32-bit seed brute force: state[0]=seed, numba parallel ~3min/round)

### 2022 (3/?)
- [x] Authenticator (Firebird Internal CTF) — `firebird{y0u_d0n7_n33d_t0_pr3c0mpu73_3very7h1n9_4nyw4y}` (blake3 challenge-response with 6-char unique alnum pw: partial precompute 1/62 subset w/ fixed chal_c → reconnect ~62 times)
- [x] C0ll1d3r (Firebird Internal CTF) — `firebird{wh3n_1n_d0ub7_u5e_latt111c3_r3duc71110n_4lg0r111thm}` (hidden p: 연속 exponent h2²-h1h3=kp → gcd로 p 복구; LLL knapsack Kannan embedding으로 소문자 충돌 찾기)
- [x] Dark Arts (CODEGATE CTF) — `CODEGATE{I_told_you_building_secure_PRFs_is_hard_:(}` (4-stage "mod p + mod q" weak PRF: unit-vector distinguisher → Fourier |F_2|² bias → quadratic Arora-Ge linearization on GF(5) → HNP BKZ lattice)
- [x] FaILProof (SekaiCTF) — `SEKAI{w3ll_1_gu355_y0u_c4n_4lw4y5_4sk_f0r_m0r3_3qu4t10n5_wh3n_n0_0n3s_l00k1ng}` (happiness(x)=x-Σ(x>>i)는 popcount 위장. 서버가 secret 공개 → A 재구성, 블록당 128개 Z-linear 등식 on 256 binary unknowns → pulp+CBC ILP 0.2 s/block)
- [x] FaILProof Revenge (SekaiCTF) — `SEKAI{b00l3n5_4r3_my5t3r10u5_1n_th31r_0wn_ch33ky_w4y5}` (sha512 chain, 256 pubkey 512-bit, block=24rand∥8msg∥32rand. 블록당 256 Z-linear 등식 on 512 binary unknowns → pulp+CBC ILP 0.85 s/block; 랜덤 패딩은 linear-on-bits 암호에 무용)
