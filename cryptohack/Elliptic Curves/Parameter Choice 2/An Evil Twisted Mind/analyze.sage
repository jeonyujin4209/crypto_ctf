modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
order = 4782850957738000717885060297297408935631027604045525430677
a = -3
b = 2697448053935541741976221051345108825177671050689533270507

print("modulus bits:", modulus.nbits())
print("order   bits:", order.nbits())
print()
print("is modulus prime:", is_prime(modulus))
if not is_prime(modulus):
    print("modulus factors:", factor(modulus))
print()
print("is order prime:", is_prime(order))
if not is_prime(order):
    print("order factors:", factor(order))

# Check if modulus - 1 has structure
print()
print("modulus == order^2?", modulus == order^2)
print("modulus // order =", modulus // order)
print("modulus mod order =", modulus % order)
