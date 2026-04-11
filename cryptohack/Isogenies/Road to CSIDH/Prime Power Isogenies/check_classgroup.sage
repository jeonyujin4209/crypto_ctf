p = 419
K.<a> = QuadraticField(-p)
print("class number:", K.class_number())
Cl = K.class_group()
print("class group:", Cl)
# Find prime ideal above 7
for P, e in K.factor(7):
    print("prime above 7:", P, "order:", P.gen(0) if hasattr(P, 'gen') else None)
    I = Cl(P)
    print("class of ideal:", I, "order:", I.order())
