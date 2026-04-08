# JWT Secrets (25pts)
## JSON Web Tokens

## Server
`https://web.cryptohack.org/jwt-secrets`

## Description
The most common signing algorithms used in JWTs are HS256 and RS256. The first is a symmetric signing scheme using a HMAC with the SHA256 hash function. The second is an asymmetric signing scheme based on RSA.A lot of guides on the internet recommend using HS256 as it's more straightforward. The secret key used to sign a token is the same as the key used to verify it.However, if the signing secret key is compromised, an attacker can sign arbitrary tokens and forge sessions of other users, potentially causing total compromise of a webapp. HS256 makes the secret key harder to secure than an asymmetric keypair, as the key must be available on all servers that verify HS256 tokens (unless better infrastructure with a separate token verifying service is in place, which usually isn't the case). In contrast, with the asymmetric scheme of RS256, the signing key can be better protected while the verifying key is distributed freely. Even worse, developers sometimes use a default or weak HS256 secret key.Here is a snippet of source code with one function to create a session and another function to authorise a session and check for admin permissions. But there's a strange comment about the secret key. What are you going to do?Play at https://web.cryptohack.org/jwt-secrets
