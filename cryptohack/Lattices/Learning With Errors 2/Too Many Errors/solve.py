"""
Too Many Errors: requires live server at socket.cryptohack.org 13390.
SKIPPED (server challenge).

Attack sketch: the SEED for random.Random is 32 bits, fixed per connection. Using
'reset' restores state. So we can collect many samples for the SAME underlying
randomness. Combined with the fact that only ~50% of samples are faulty and the
fault is a single coordinate overwrite, we can do majority-voting / error-correcting
linear algebra over F_127 to recover FLAG.

Requires server interaction.
"""
print("This challenge requires a live server connection. Skipped locally.")
