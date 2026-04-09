# j-invariant of y^2 = x^3 + a x + b is:
#   j = 1728 * 4a^3 / (4a^3 + 27b^2)
# over F_163.

p = 163
a = 145
b = 49

num = 1728 * (4 * a**3)
den = (4 * a**3 + 27 * b**2) % p
j = (num * pow(den, -1, p)) % p
print(f"j = {j}")
print(f"crypto{{{j}}}")
