# Generators of Groups (20pts)
# Find smallest primitive element g of F_p where p = 28151
# g is primitive if ord(g) = p-1

p = 28151

def is_primitive(g, p):
    """Check if g is a primitive root mod p"""
    # ord(g) must be p-1
    # Check that g^((p-1)/q) != 1 for all prime factors q of p-1
    from sympy import factorint
    factors = factorint(p - 1)
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

for g in range(2, p):
    if is_primitive(g, p):
        print(g)
        break
