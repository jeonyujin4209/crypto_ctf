p = 29
ints = [14, 6, 11]

for x in ints:
    for a in range(1, p):
        if (a * a) % p == x:
            print(f"QR: {x}, smaller root: {min(a, p - a)}")
            break
# Answer: 8
