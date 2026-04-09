import hashlib

PRIME = 77793805322526801978326005188088213205424384389488111175220421173086192558047

# We have one share: (x1, y1)
x1 = 105622578433921694608307153620094961853014843078655463551374559727541051964080
y1 = 25953768581962402292961757951905849014581503184926092726593265745485300657424

# coefs[1] = sha256(FLAG) as bytes -> int = x1 (given as evaluation point)
# coefs[2] = sha256(coefs[1]) as bytes -> int
c1 = x1
c2 = int.from_bytes(hashlib.sha256(x1.to_bytes(32, 'big')).digest(), 'big')

# y1 = s + c1*x1 + c2*x1^2 mod PRIME
s = (y1 - c1*x1 - c2*x1*x1) % PRIME
flag = s.to_bytes((s.bit_length()+7)//8, 'big')
print(flag)
# crypto{fr46m3n73d_b4ckup_vuln?}
