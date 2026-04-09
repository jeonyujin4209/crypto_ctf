import math

v = (4, 6, 2, 5)
size_squared = sum(x*x for x in v)
size = math.sqrt(size_squared)
print(size)
