# Toshi's Treasure (150pts)
## Secret Sharing Schemes

## Server
`socket.cryptohack.org 13384`

## Description
You are hyperreality and you are playing an online treasure hunt with your team mpeg, codecrafting, RichGirlOnLSD and pogo.There's one million dollars in a Bitcoin wallet - which nobody yet knows the address for - awaiting the first team to gain 5 of 6 SSSS shares and combine them to a private key. Each member of your team has found one share and you're ready to do the key ceremony to unlock the prize.The SSSS implementation is simply the example code on Wikipedia, with the 13th Mersenne prime. The server will tell you your share in the first message. You've all agreed to split the million dollars equally, however in a final moment of greed you decide you want it all for yourself!Here's your evil plan:  1. Disrupt the first combination by submitting a fake share. The others assume a mistake was made and try again.  2. This time, submit a fake share such that the combined secret is a private key for a wallet that you own containing just $1k. This will confuse your teammates and make them think they have been cheated by the game creators, not you.  3. Unlock the real wallet and use the funds to escape to an island nation where nobody will ever be able to find you.Connect at socket.cryptohack.org 13384Challenge files:  - hyper_privkey.txt

## Files
- `hyper_privkey.txt`
