import os
import random
from Crypto.Util.number import bytes_to_long
from utils import listener

# RSA group (2024 bits)
# p,q are both strong primes (i.e. of the form 2x+1 for x prime)

#p = REDACTED
#q = REDACTED
#N = p * q
N = 63506177426384102189597350894327047299059434133653566917776601666605133716653510828029111986956978773016660313963972378811186153674164948861199369871734498221215139927864142313488277305751745855210473314367642273303159704466900274761354992859789827863358153922459760984397971477173435625199596782211170294424560686178858124003120741008270927463303483018910205943877584647744143454984243979284973117132536957364157878132874844783228762221620863204335896952103079109039534346621267709606103312376393511653638269034043434410564414042523141936372609708140474052147124354400977541403247799192906955295291389109531010594317

FLAG = b"crypto{???????????????????}"

g = 2

k1 = 512
k2 = 128
S = 2**k1
R = 2**(2*k2+k1)

padded_flag = FLAG + os.urandom(S.bit_length() // 8 - len(FLAG) - 2)
flag = bytes_to_long(padded_flag)

y = pow(g,-flag,N)


class Challenge:
    def __init__(self):
        self.before_input = f"I will prove to you that I know flag `w` such that y = g^-w mod N\n"
        self.state = "CHALLENGE"
        self.no_prompt = True

    def challenge(self, msg):
        if self.state == "CHALLENGE":
            # Prover sends a randomly sampled `A` value to verifier
            self.r = random.randint(0,R)
            self.a = pow(g,self.r,N)

            self.state = "PROVE"
            return {"y": y, "a": self.a, "message": "Send a random e in range 0 <= e < 2^{k2}"}

        elif self.state == "PROVE":
            # Verifier sends a random challenge sampled from Z_{2^k2}
            self.e = msg["e"]

            # Prover sends z = r + e*w mod q to the Verifier
            self.z = (self.r + self.e*flag)

            self.exit = True 
            return {"z": self.z, "message": "I hope you're convinced I know the flag now. Goodbye :)"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13429)

