# RSA or HMAC? (35pts)
## JSON Web Tokens

There's another issue caused by allowing attackers to specify their own algorithms but not carefully validating them. Attackers can mix and match the algorithms that are used to sign and verify data. When one of these is a symmetric algorithm and one is an asymmetric algorithm, this creates a beauti
