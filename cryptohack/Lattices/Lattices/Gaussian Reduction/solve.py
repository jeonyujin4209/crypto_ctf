def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def gaussian_reduction(v1, v2):
    while True:
        if dot(v2, v2) < dot(v1, v1):
            v1, v2 = v2, v1
        m = round(dot(v1, v2) / dot(v1, v1))
        if m == 0:
            return v1, v2
        v2 = [v2[i] - m * v1[i] for i in range(len(v1))]

v = [846835985, 9834798552]
u = [87502093, 123094980]

v1, v2 = gaussian_reduction(v, u)
print(dot(v1, v2))
