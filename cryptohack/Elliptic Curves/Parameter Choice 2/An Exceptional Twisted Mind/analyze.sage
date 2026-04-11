N = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813
print("N bits:", N.nbits())
print("order bits:", order.nbits())
print("is N prime:", is_prime(N))
if not is_prime(N):
    print("N factors:", factor(N))
print()
print("is order prime:", is_prime(order))
if not is_prime(order):
    print("order factors:", factor(order))
print()
# Maybe N = order^2?
print("N - order^2 =", N - order^2)
print("N - order*(order+something)?")
# Try order+something
# Try N = order * (order + c)
c = N // order - order
print("c =", c)
print("order*(order + c) =", order * (order + c))
print("diff =", N - order*(order + c))
