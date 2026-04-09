import re
from Crypto.Util.number import long_to_bytes

q = 117477667918738952579183719876352811442282667176975299658506388983916794266542270944999203435163206062215810775822922421123910464455461286519153688505926472313006014806485076205663018026742480181999336912300022514436004673587192018846621666145334296696433207116469994110066128730623149834083870252895489152123

# Legendre(2, q) = -1, Legendre(256, q) = 1, g is QR so s is always QR
# bit=0: me = 2*padding (Legendre=-1), bit=1: me = 4*padding (Legendre=1)
# c2 = s*me, Legendre(c2) = Legendre(me)

with open('output.txt') as f:
    text = f.read()

c2_values = re.findall(r'c2=(0x[0-9a-f]+)', text)

bits = []
for c2_hex in c2_values:
    c2 = int(c2_hex, 16)
    leg = pow(c2, (q-1)//2, q)
    bits.append('1' if leg == 1 else '0')

# Bits are from LSB to MSB
m = int(''.join(reversed(bits)), 2)
print(long_to_bytes(m))
# crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}
