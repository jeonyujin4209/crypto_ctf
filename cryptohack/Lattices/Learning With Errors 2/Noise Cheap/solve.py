"""
Noise Cheap: requires live server at socket.cryptohack.org 13413.
SKIPPED (server challenge).

Intended attack: the noise is e in {-1, 0, 1} and m + p*e with p=257.
Reduce each encryption mod p to remove noise: (A.S + m + p*e) mod p = (A.S + m) mod p.
Solve linear system over F_p to recover S mod p (64+ queries), then decrypt.
"""
print("This challenge requires a live server connection. Skipped locally.")
