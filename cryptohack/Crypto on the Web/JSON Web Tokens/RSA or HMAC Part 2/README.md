# RSA or HMAC? Part 2 (100pts)
## JSON Web Tokens

## Server
`https://web.cryptohack.org/rsa-or-hmac-2`

## Description
It is possible to abuse JWT public keys without the public key being public? This challenge takes RSA or HMAC one step further, and now both a deeper knowledge of RSA maths and data formatting is involved. It's more realistic than the first part as web apps usually won't have a route disclosing their public key.If you are attempting to implement the solution yourself (which is recommended over using a public script!), but the signature is not validating, take care that your formatting is 100% correct. We've added to the source the commands used to generate the private and public keys.The server is running PyJWT with a small patch, the same as the previous challenge. Check the notes from the previous challenge.Play at https://web.cryptohack.org/rsa-or-hmac-2
