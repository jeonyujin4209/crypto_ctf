"""
Breaking SIDH - Castryck-Decru Attack
Bob's private key recovered via CD attack: sB = 39990433064274301814750584859416466
Compute shared secret: K = phiA_P3 + sB*phiA_Q3, then iso from EA
"""
import subprocess, sys
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pycryptodome"], check=True)

from Crypto.Hash import SHA256
from Crypto.Cipher import AES

f, ea, eb = 45, 117, 73
p = f * 2**ea * 3**eb - 1
F.<i> = GF(p**2, modulus=[1,0,1])

E0 = EllipticCurve(F, [1,0])

phiA_P3 = EllipticCurve(F, [
    341962904043010047547037514847227313183414494665183661406956171643838238*i+466221816892334489710400228219157166377700467211697103422573316531708902,
    145050307288456998377054421680667611887270583594997309677606837459597101*i+356616269078165763297060128562598654455817286639025312561154777133108454
])(
    180748165080544728482273627011017446820851964671689844940751613607027042*i + 386399657558539814871631131488087670882259175999167407491042206165954470,
    327787397151786462956783797299341040567085054575313609836298710436619785*i + 196105866987178697015232911678783180764030519956520455354300809913687633
)

phiA_Q3 = phiA_P3.curve()(
    258847568494100760477286708131798122974987254057932346978697593107825530*i + 38490496870779580975180675248455270468746617165569920252532162902409675,
    306358844762893197793766376830898073944594560219460755063030400129179690*i + 182510704835708623157232097040016637690000728438765134566515343181898854
)

EA = phiA_P3.curve()

iv = bytes.fromhex('f45273daf12b8234bd41607d8b517913')
ct = bytes.fromhex('65917ae4d3de3ba753d50bab78992b2239cb189493807fcc3da8d058da1eda7d993c041d0ecb09089808d759a982f087')

# Bob's recovered private key (from Castryck-Decru attack)
sB = 39990433064274301814750584859416466

print(f"[*] Computing kernel point K = phiA_P3 + {sB} * phiA_Q3 ...")
K = phiA_P3 + sB * phiA_Q3
print(f"[*] K order check: K should have order 3^{eb} = {3**eb}")
print(f"[*] Computing 3^{eb}-isogeny from EA with kernel K ...")

E_shared = EA.isogeny(K, algorithm="factored").codomain()
shared_secret = E_shared.j_invariant()
print(f"[+] shared_secret (j-invariant) = {shared_secret}")

key = SHA256.new(data=str(shared_secret).encode()).digest()
print(f"[*] AES key (SHA256, 32 bytes)")

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
print(f"[+] FLAG: {flag}")
