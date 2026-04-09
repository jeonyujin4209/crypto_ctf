import numpy as np

v1 = [6, 2, -3]
v2 = [5, 1, 4]
v3 = [2, 7, 1]

A = np.array([v1, v2, v3])
vol = abs(round(np.linalg.det(A)))
print(vol)
