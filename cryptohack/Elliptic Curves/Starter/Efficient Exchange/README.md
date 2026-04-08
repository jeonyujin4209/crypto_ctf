# Efficient Exchange (50pts)
## Starter

## Description
Alice and Bob are looking at the Elliptic Curve Discrete Logarithm Problem and thinking about the data they send.They want to try and keep their data transfer as efficient as possible and realise that sending both the xxx and yyy coordinate of their public key isn't necessary.As long as Alice and Bob agree on the curve parameters, there are only ever two possible values of yyy for a given xxx.In fact, given either of the values of yyy permissible from the value xxx they receive, the xxx coordinate of their shared secret will be the same. For these challenges, we have used a prime p≡3mod  4p \equiv 3 \mod 4p≡3mod4, which will help you find yyy from y2y^{2}y2.Using the curve, prime and generator: E:Y2=X3+497X+1768mod  9739,G:(1804,5368)E: Y^{2} = X^{3} + 497 X + 1768 \mod 9739, \quad G: (1804,5368)E:Y2=X3+497X+1768mod9739,G:(1804,5368) Calculate the shared secret after Alice sends you x(QA)=4726x(Q_A) = 4726x(QA​)=4726, with your secret integer nB=6534n_B = 6534nB​=6534.Use the decrypt.py file to decode the flag {'iv': 'cd9da9f1c60925922377ea952afc212c', 'encrypted_flag': 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'} You can specify which of the two possible values your public yyy coordinate has taken by sending only one bit. Try and think about how you could do this. How are the two yyy values related to each other?Challenge files:  - decrypt.py

## Files
- `decrypt.py`
