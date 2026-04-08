# Secret Exponents (60pts)
## Road to CSIDH

## Description
In the CSIDH key exchange, a private key is a list of integers as long as the number of odd primes dividing (p+1)(p+1)(p+1). This data represents an exponent vector [e0,e1,e2,...,ek][e_0, e_1, e_2, ..., e_k][e0​,e1​,e2​,...,ek​] which dictates the path of Alice and Bob's secret isogenies.Before implementing CSIDH let us begin by computing an isogeny with the secret vector [2,3,4][2,3,4][2,3,4] from the starting curveE0:y2=x3+xmod  419E_0 : y^{2} = x^{3} + x \mod 419E0​:y2=x3+xmod419The flag for this challenge is the Montgomery coefficient A of the codomain.Essentially what this challenge is asking you to do is compute an isogeny of degree n=32⋅53⋅74n = 3^{2} \cdot 5^{3} \cdot 7^{4}n=32⋅53⋅74. You will need this code again throughout this section, think about how to write this efficiently so you can generalise it to other vectors and other characteristics!
