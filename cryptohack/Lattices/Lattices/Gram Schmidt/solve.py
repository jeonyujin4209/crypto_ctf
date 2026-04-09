from fractions import Fraction

def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def norm_sq(a):
    return dot(a, a)

def gram_schmidt(basis):
    u = []
    for i, vi in enumerate(basis):
        ui = list(vi)
        for j in range(i):
            mu = Fraction(dot(vi, u[j]), norm_sq(u[j]))
            ui = [ui[k] - mu * u[j][k] for k in range(len(ui))]
        u.append(ui)
    return u

v1 = [Fraction(4), Fraction(1), Fraction(3), Fraction(-1)]
v2 = [Fraction(2), Fraction(1), Fraction(-3), Fraction(4)]
v3 = [Fraction(1), Fraction(0), Fraction(-2), Fraction(7)]
v4 = [Fraction(6), Fraction(2), Fraction(9), Fraction(-5)]

basis = [v1, v2, v3, v4]
orthogonal = gram_schmidt(basis)

u4 = orthogonal[3]
# Second component of u4, to 5 significant figures
val = float(u4[1])
print(f"{val:.5g}")
