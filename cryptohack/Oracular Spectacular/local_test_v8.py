"""
Multi-CT pooled approach: Use many CTs, pool observations across CTs for same plaintext byte.

For each byte position:
1. Query each candidate on each CT (one query per candidate per CT)
2. Pool all observations: for hex char h, count True and False across all CTs
3. Pick h with lowest True rate (closest to 0.4)
4. Set intermediates for all CTs based on consensus

This pools N observations per candidate (one per CT).
Budget per byte = 16 × N (one query per candidate per CT).
Total budget = 32 × 16 × N = 512N.
For N=23: total = 11776 < 12000.

Per candidate: N=23 queries.
E[score|valid] = 23 × 0.2 = 4.6
std = sqrt(23 × 0.96) = 4.70

P(one wrong > correct) = Phi(-(2×4.6)/(4.70×sqrt(2))) = Phi(-1.38) = 8.4%
P(any of 15 > correct) = 1-(1-0.084)^15 = 73.6%
Per byte accuracy: ~26%. Terrible!

So pure uniform pooling with 23 queries per candidate is BAD (26%).

Better: use adaptive pooling.
Phase 1: Screen with M CTs (1 query per cand per CT = 16M queries per byte)
Phase 2: Focus remaining CTs on top 2 candidates

With 23 CTs:
Screen: use 3 CTs for screening = 48 queries. Each cand gets 3 observations.
Focus: use 20 CTs, each queries only top 2 = 40 queries per byte.
Total per byte: 48 + 40 = 88. For 32 bytes: 2816. Way under budget!

We have room for many more CTs. With budget B=375 per byte:
Screen: S CTs × 16 candidates = 16S queries
Focus: F CTs × 2 candidates = 2F queries
Total: 16S + 2F = 375
Each top-2 candidate gets S + F observations.

Maximize S+F subject to 16S + 2F ≤ 375 and S ≥ 2.
F = (375 - 16S) / 2
S + F = S + 187.5 - 8S = 187.5 - 7S

To maximize: minimize S. S=2: total = 187.5 - 14 = 173.5 observations per top-2 cand.
But the screening with only 2 queries is unreliable.

Let S=5: total = 187.5 - 35 = 152.5. Screening: 5 queries per cand. Better.

Let me think about this differently. Each CT provides ONE observation for ONE candidate.
If we focus CT_k on candidate h, CT_k tells us: is h the correct plaintext byte?

We need enough CTs for screening (testing all 16 cands) plus enough for confirming top candidates.

Actually this is exactly the same as the single-CT adaptive approach! Each oracle call is independent, and whether it comes from the same CT or different CTs doesn't matter (they're all testing "is this candidate correct?").

The only difference: different CTs have different target blocks and intermediates, so the query construction differs. But the oracle response distribution is the same: P(True)=0.4 for correct, P(True)=0.6 for incorrect.

Wait, there IS a subtle difference. With a SINGLE CT, all 16 candidates are tested against the same target block. The noise is independent across queries. With MULTIPLE CTs, each candidate is tested against a different target block per CT. Still independent.

So the per-byte accuracy should be the same whether we use 1 CT with 375 queries or 23 CTs with ~16 queries each. The total number of observations per candidate is what matters.

This means multi-CT provides NO advantage over single-CT for per-byte accuracy! The ONLY advantage is breaking cascade (by using consensus to set intermediates).

But we showed that multi-CT consensus with 3 CTs at 125 each gives ~55% per-byte → ~68% with consensus. While single CT at 375 gives 85% per-byte. 85% > 68%, so single CT is better.

The fundamental trade-off: splitting budget across CTs reduces per-byte accuracy (because adaptive top-2 is super-linear in budget), but consensus prevents cascade.

Given that single CT already achieves 0.25% success rate (cascade included), and consensus approaches give worse per-byte accuracy, **the single CT approach is the best we can do**.

0.25% success rate means we need ~400 attempts. Let's just build the remote solver with retry logic.

Actually wait, let me try to increase the budget efficiency. The issue is 375 queries per byte.
What if the plaintext has padding? The message is `urandom(16).hex()` = 32 ASCII characters.
That's exactly 32 bytes = 2 AES blocks. There's NO padding block!

Wait, actually: AES.new(MODE_CBC).encrypt(message.encode("ascii")). The message is 32 bytes.
AES block = 16 bytes. 32/16 = 2 blocks exactly. But the encrypt() method for CBC requires
the input to be a multiple of block size. In PyCryptodome, encrypt() doesn't add padding by
itself. The check_padding function calls unpad(pt, 16) on the decrypted text.

For a 32-byte message (2 blocks), the decrypted text is also 32 bytes. unpad expects
PKCS#7 padding. The last byte of the decrypted text tells the padding length. For 32-byte
message with no padding added during encryption, the last byte is just the last char of the
message.encode("ascii"), which is a hex character (0x30-0x39, 0x61-0x66). unpad would try
to interpret this as padding length and strip that many bytes.

Wait, this is important! The message is 32 bytes with NO padding. When the server encrypts
with `cipher.encrypt(self.message.encode("ascii"))`, if the message is exactly 32 bytes,
PyCryptodome's encrypt in CBC mode requires the input to be a multiple of 16 and does NOT
add padding. So the ciphertext is 32 bytes = 2 blocks.

When we test padding with check_padding: it decrypts 32 bytes to 32 bytes, then calls
unpad(pt, 16). unpad looks at the last byte, say it's 0x61 ('a' = 97). It would try to
remove 97 bytes of padding... from a 32-byte string... which would fail. So good = False
for any normal decryption.

Wait, but the LAST block (c2) when decrypted gives the second 16 bytes of the message.
When we modify the previous block (c1 → m), we change the decryption of c2.
decrypt(c2) ^ m gives us a controlled 16-byte block. We're testing if THIS block has
valid padding. So the 16-byte block has valid padding if the last byte is 1 (and only 1),
or last 2 bytes are 2, etc.

So the padding oracle is on a SINGLE 16-byte block, not the full 32-byte message. That's
standard. The server decrypts only the submitted ciphertext (which we control).

Actually, looking at check_padding more carefully:
  ct = bytes.fromhex(ct)
  iv, ct = ct[:16], ct[16:]

So it expects our submitted ct_hex to be 32+ bytes hex. It splits into iv (16 bytes) and
ct (remaining). For our attack, we send 32 hex bytes (16 bytes) as modified prev block and
16 bytes target block = 32 bytes total.

Wait, that's 32 bytes = 64 hex chars. iv = first 16 bytes, ct = remaining 16 bytes.
Then decrypt(ct) with IV = iv, getting 16 bytes plaintext. Then unpad on 16 bytes.

For the standard attack: our "modified prev block" IS the IV, and "target block" IS the ct.
So we send (modified_iv + target_block) as ct_hex. The server uses first 16 bytes as IV,
decrypts the next 16 bytes, and checks padding on the result.

This is all correct. Now, when attacking block 1 (c1), we modify the IV. When attacking
block 2 (c2), we modify c1.

But wait: the server does `ct = bytes.fromhex(ct); iv, ct = ct[:16], ct[16:]`.
If we send more than 32 bytes, the extra is included in ct. So:
- For block 2 attack: we could send (modified_c1 + c2) = 32 bytes.
  Server: iv = modified_c1, ct = c2. Decrypts c2 with AES-CBC using iv=modified_c1.
  This is equivalent to: AES_ECB_decrypt(c2) XOR modified_c1. Correct.

- For block 1 attack: we send (modified_iv + c1) = 32 bytes.
  Server: iv = modified_iv, ct = c1. Decrypts c1 with AES-CBC using iv=modified_iv.
  This is: AES_ECB_decrypt(c1) XOR modified_iv. Correct.

OK, the oracle behavior is as expected. Now, there's another subtlety: when we attack
block 2, byte position 15 means we want the last byte of AES_ECB_decrypt(c2) XOR m[15] = 1
for pad=1. For the CORRECT candidate, the padding is exactly \x01, and unpad accepts it.

For wrong candidates with pad=1: the last byte is not 1. unpad looks at last byte (some
other value, say 3), checks if last 3 bytes are all 3. They're random, so almost certainly
not → invalid padding. P(false positive) ≈ 1/256 for the "\x02\x02" case. Very rare.

All checks out. The algorithm is correct. The 0.25% success rate is what we have.

Let me now focus on building the actual remote solver.
"""
print("This file is just analysis notes. Run local_test_v3.py for actual testing.")
