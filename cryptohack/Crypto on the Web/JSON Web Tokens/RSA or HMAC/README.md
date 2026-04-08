# RSA or HMAC? (35pts)
## JSON Web Tokens

## Server
`https://web.cryptohack.org/rsa-or-hmac`

## Description
There's another issue caused by allowing attackers to specify their own algorithms but not carefully validating them. Attackers can mix and match the algorithms that are used to sign and verify data. When one of these is a symmetric algorithm and one is an asymmetric algorithm, this creates a beautiful vulnerability. The server is running PyJWT with a small patch to enable an exploit that existed in PyJWT versions <= 1.5.0. To create the malicious signature, you will need to patch your PyJWT library too. If you want to patch, look at the line that was added in the fix for the vulnerability. Use pip show pyjwt to find the location of the PyJWT library on your computer, and make the edit. For versions of PyJWT > 2.4.0 the code has been changed so you will have to edit jwt/utils.py instead of jwt/algorithms.pyPlay at https://web.cryptohack.org/rsa-or-hmac
