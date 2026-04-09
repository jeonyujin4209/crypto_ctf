"""
Noise Free: requires live server at socket.cryptohack.org 13411.
No local data to attack. SKIPPED (server challenge).

Intended attack: since there's no noise, each "encrypt" query gives
    b = A . S + m  (mod q)
for known m and random A. With 64+ queries we can solve the linear system
for S exactly, then decrypt flag char-by-char.
"""
print("This challenge requires a live server connection. Skipped locally.")
