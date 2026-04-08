# Too Honest (50pts)
## Sigma Protocol

## Server
`socket.cryptohack.org 13429`

## Description
Recall that we only proved Schnorr's protocol to be SHVZK, and while this was enough to make maliciously secure NIZK's, this leaves the question of "what could happen if V isn't honest?"This challenge is an implementation of Girault's identification protocol for proving knowledge of a witness for a DLOG relation, but modulo some composite NNN instead of a prime. You are the verifier, and the prover will show that they know the flag using an interactive Σ\SigmaΣ-Protocol. Extract the flag by selecting a malicious eee.Note that proving something to be a Σ\SigmaΣ-Protocol only makes it secure against an "honest" verifier. If we want to use a protocol in a setting where the verifier can't be trusted to be honest, you can either make the proof non-interactive, or convert the SHVZK protocol into a maliciously secure ZK protocol, (there exist generic transformations which generally add another round of interaction.)Connect at socket.cryptohack.org 13429Challenge files:  - 13429.pyChallenge contributed by oberon

## Files
- `13429.py`
