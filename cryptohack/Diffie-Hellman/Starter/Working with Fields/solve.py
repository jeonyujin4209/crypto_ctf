# Working with Fields (10pts)
# Find d = g^(-1) mod 991 such that g*d mod 991 = 1
# g = 209, p = 991

p = 991
g = 209
d = pow(g, -1, p)
print(d)  # answer is a number
