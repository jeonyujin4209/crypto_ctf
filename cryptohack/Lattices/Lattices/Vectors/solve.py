import numpy as np

v = np.array([2, 6, 3])
w = np.array([1, 0, 0])
u = np.array([7, 7, 2])

# 3*(2*v - w) . 2*u
# inner product of 3*(2v - w) and 2u
a = 2*v - w       # (3, 12, 6)
b = 3 * a          # (9, 36, 18)
c = 2 * u          # (14, 14, 4)
result = np.dot(b, c)
print(result)
