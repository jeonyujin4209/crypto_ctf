import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

FLAG = b"crypto{??????????????????????????}"

# Base field
ea = 35
eb = 29
p = 2**ea * 3**eb - 1
F.<i> = GF(p**2, modulus=[1,0,1])

# Public parameters
E0 = EllipticCurve(F, [1, 0])
P2 = E0(1956194174015565770794336*i + 1761758151759977040301838,  2069089015584979134622338*i + 203179590296749797202321)
Q2 = E0(2307879706216488835068177*i + 525239361975369850140518,  1834477572646982833868802*i + 733730165545948547648966)
P3 = E0(2162781291023757368295120*i + 1542032609308508307064948,  1130418491160933565948899*i + 904285233345649302734471)
Q3 = E0(365294178628988623980343*i + 1867216057142335172490873,  2141125983272329025279178*i + 1860108401614981479394873)

# Alice's public key
EAa = 2336060373130772918448023*i+63223462935813026254900
EAb = 202739861418983960259548*i+525917254309082638166498
EA = EllipticCurve(F, [EAa, EAb]) 
phiA_P3 = None # Missing!!
phiA_Q3 = None # Missing!!

# Bob's secret
sB = 495832856

def encrypt_flag(shared_secret):
    key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))

    return iv.hex(), ct.hex()

iv = '9a030e6824e7ec5d66b3443920ea76cb'
ct = '7f11a2ca0359cc5f3a81d5039643b1208ac7eb17f8bd42600d1f67e474cd664dcb8624c94175e167acfe856f48be34bd'
