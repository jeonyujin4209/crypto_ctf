# No Way JOSE (20pts)
## JSON Web Tokens

## Server
`https://web.cryptohack.org/no-way-jose`

## Description
Let's look at JWT algorithms. The first part of a JWT is the JOSE header, and when you decode it, looks like this: {"typ":"JWT","alg":"HS256"} This tells the server it's a JWT and which algorithm to use to verify it. Can you see the issue here? The server has to process this untrusted input before it is actually able to verify the integrity of the token! In ideal cryptographic protocols, you verify messages you receive before performing any further operations on them, otherwise in Moxie Marlinspike's words, "it will somehow inevitably lead to doom".The "none" algorithm in JWTs is a case in point. The link below takes you to a page where you can interact with a broken session API, which emulates a vulnerability that existed in a lot of JWT libraries. Use it to bypass authorisation and get the flag.Play at https://web.cryptohack.org/no-way-jose
