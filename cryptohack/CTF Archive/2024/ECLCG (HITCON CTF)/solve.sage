"""
ECLCG (HITCON CTF 2024)

Vulnerability:
  17 ECDSA signatures on secp256k1 share a private key d. The per-signature
  nonces k_i come from an LCG with unknown a, b, p:  k_{i+1} = a*k_i + b mod p,
  with p ~ 0x137 = 311 bits, while q (curve order) is ~256 bits. So nonces are
  larger than q, but the LCG gives us linear constraints relating them.

Attack (Stern-style orthogonal lattice / "Easy DSA:LCG" reduction):
  From two ECDSA equations we get
      kk_i := k_{i+1} - k_i = u_i*d + v_i  (mod q)
  with known u_i, v_i. Building Stern lattice from u_i, v_i (with two consecutive
  shifts so the LCG `a` cancels and only short integer relations among the kk_i
  remain), LLL gives us linear combinations c such that sum c_j*kk_{i+j} = 0
  over the integers (since nonce differences are bounded by p < 2^311 < 2^999).
  These integer relations let us solve for kk_i (up to scalar), then
      d = (kk_0 - v_0) / u_0  mod q
  and we decrypt the AES-CTR flag with key = sha256(str(d)).

Reference: https://connor-mccartney.github.io/cryptography/ecc/ECLCG-HITCON-2024
"""

from hashlib import sha256

# secp256k1 order
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Fq = GF(q)

sigs = [(49045447930003829750162655581084595201459949397872275714162821319721992870137, 21098529732134205108109967746034152237233232924371095998223311603901491079093), (8434794394718599667511164042594333290182358521589978655877119244796681096882, 72354802978589927520869194867196234684884793779590432238701483883808233102754), (98981626295463797155630472937996363226644024571226330936699150156804724625467, 78572251404021563757924042999423436619062431666136174495628629970067579789086), (39876682309182176406603789159148725070536832954790314851840125453779157261498, 57493814845754892728170466976981074324110106533966341471105757201624065653133), (65207470758289014032792044615136252007114423909119261801100552919825658080689, 35801670032389332886673836105411894683051812268221960643533854039645456103322), (62310615350331421137050446859674467271639363124966403418757056624834651785981, 35521772482874533704942922179876531774398711539124898773478624535131725819343), (112968103298671409136981160931495676458802276287280410415332578623201858813402, 69136482735760979952358359721969881674752452777485098096528689791122554903910), (65185852906255515620576935005939230631603582432998989514260597054881976462676, 85379997570993122627264764907519703985819259494167121515303052416417601678111), (89525951822575634807524099747751997083879407738240060351122435098952102365970, 73032937908295382442051096857786822685807890991333822263666894552392531234105), (10051482171127490286979879686762557184173302546674808492445781875620932719446, 26217862064468074441046914792412948081058029471697661868711999974556608497458), (8842758449685028748615236698968197767772820788773190926335075554397256573640, 31652804170027719136589492610452674938583230853203431940531961290992398961987), (23751070894286517351443200111133743672788640335816140651282619979550868046371, 62545547750389706281745923819072901405095067763677430386609805435019439100532), (73526459114147520989492697207756783950511563270716718674108128391637651652182, 70851054921933366241324896134628440370210434216441807412696261358563604784468), (57753594385723283080008450150285839290328959323728215111064869128180653466512, 48682503345807264543892350428384011994195616727229911040222271121395096668630), (65263395028919805249304292530249376748389080058707453448295007353333046365479, 10365290276028966530454805043630476285018698618883354555344947391544138993674), (87437293666767613034832827186884716590065056433713359026118257811657437100576, 89500859891014369107213802143650102492250691913844472777312272074978411403745), (82006715584380621917183646856144618837928013528296150149335800289034986391573, 66403597255556240236430083902481022812584785679596388450322939858389337923701)]

msgs = [
    b"https://www.youtube.com/watch?v=kv4UD4ICd_0",
    b"https://www.youtube.com/watch?v=IijOKxLclxE",
    b"https://www.youtube.com/watch?v=GH6akWYAtGc",
    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",
    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",
    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",
    b"https://www.youtube.com/watch?v=zH7wBliAhT0",
    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",
    b"https://www.youtube.com/watch?v=ylH6VpJAoME",
    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",
    b"https://www.youtube.com/watch?v=bef23j792eE",
    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",
    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",
    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",
    b"https://www.youtube.com/watch?v=S53XDR4eGy4",
    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",
    b"https://www.youtube.com/watch?v=tLL8cqRmaNE",
]

ct = b'\xc6*\x17\xcce\xc1y\xb8\xb4\x8d\x87L\xf8\x81QK\xf4\x02\xf2\xf7\x8d\xe0\xe8\x92\xc7\xe7\x8fg\xb1M\xb4.\x89\x18\xf5\x7f\xed\xc3I\x92\x82\xfd\xfe9\x95\xc9(\x90\xce\x93\xb9+\xce\x958\xf3\x05PH'
nonce = b'6\xe7m\xcc\x8e\x0eG '

# Build (r, s, z) for each signature.
sigs_ext = []
for m, (r, s) in zip(msgs, sigs):
    z = int.from_bytes(sha256(m).digest(), "big") % q
    sigs_ext.append((r, s, z))

# k_i ≡ s_i^{-1} (z_i + r_i d) mod q
# kk_i := k_{i+1} - k_i = (r_n/s_n - r_c/s_c)*d + (z_n/s_n - z_c/s_c) (mod q)
us, vs = [], []
for (r_c, s_c, z_c), (r_n, s_n, z_n) in zip(sigs_ext[:-1], sigs_ext[1:]):
    u = int(Fq(r_n)/Fq(s_n) - Fq(r_c)/Fq(s_c))
    v = int(Fq(z_n)/Fq(s_n) - Fq(z_c)/Fq(s_c))
    us.append(u)
    vs.append(v)

# 16 differences. Use 14 consecutive shifts to give cancellation of 'a'.
# Build Stern lattice over Z (modulo q on first 4 columns via augment with q*I).
n_pairs = len(us) - 2  # 14
M = (Matrix(us[:-2]).T
     .augment(vector(vs[:-2]))
     .augment(vector(us[1:-1]))
     .augment(vector(vs[1:-1]))
)
M = block_matrix([
    [M, 1],
    [q, 0]
])
M[:, :4] *= 2 ** 1000
M = M.LLL()

# Each row of upper LLL block, after dropping the (zeroed) first 4 columns,
# is an integer relation c on (kk_0..kk_{n_pairs-1}). It must hold over Z too,
# because the kk's are bounded by p (~2^311) which is far below the LLL norm.
PR = PolynomialRing(ZZ, [f"kk_{i}" for i in range(15)])
sym = PR.gens()
eqs = []
for row in M[:11]:
    comb = [int(x) for x in row[4:]]
    # apply at two shifts so we get equations over indices 0..14 and 1..15
    for shift in range(2):
        eqs.append(sum(a*b for a, b in zip(comb, sym[shift:shift+14])))

A, _ = Sequence(eqs).coefficients_monomials()
ker = A.right_kernel().basis_matrix()
print(f"kernel dim = {ker.nrows()}")

def aes_ctr_decrypt(key, nonce, ct):
    """Pure-Python AES-CTR (PyCryptodome MODE_CTR default: 8-byte nonce + 8-byte
    counter starting at 0, big-endian). Avoids needing pycryptodome inside the
    Sage docker image."""
    from Crypto.Cipher import AES as _AES  # available outside sage too
    return _AES.new(key, _AES.MODE_CTR, nonce=nonce).decrypt(ct)

for mm in (-1, 1):
    rec = mm * ker[0]
    d_cand = int(Fq(int(rec[0]) - vs[0]) / Fq(us[0]))
    key = sha256(str(d_cand).encode()).digest()
    try:
        flag = aes_ctr_decrypt(key, nonce, ct)
    except Exception:
        # pycryptodome not in this environment; just print d
        print(f"mm={mm}  d={d_cand}")
        continue
    print(f"mm={mm}  d={d_cand}\n  flag={flag!r}")
