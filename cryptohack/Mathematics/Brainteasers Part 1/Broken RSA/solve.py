from Crypto.Util.number import long_to_bytes

n = 27772857409875257529415990911214211975844307184430241451899407838750503024323367895540981606586709985980003435082116995888017731426634845808624796292507989171497629109450825818587383112280639037484593490692935998202437639626747133650990603333094513531505209954273004473567193235535061942991750932725808679249964667090723480397916715320876867803719301313440005075056481203859010490836599717523664197112053206745235908610484907715210436413015546671034478367679465233737115549451849810421017181842615880836253875862101545582922437858358265964489786463923280312860843031914516061327752183283528015684588796400861331354873
e = 16
ct = 11303174761894431146735697569489134747234975144162172162401674567273034831391936916397234068346115459134602443963604063679379285919302225719050193590179240191429612072131629779948379821039610415099784351073443218911356328815458050694493726951231241096695626477586428880220528001269746547018741237131741255022371957489462380305100634600499204435763201371188769446054925748151987175656677342779043435047048130599123081581036362712208692748034620245590448762406543804069935873123161582756799517226666835316588896306926659321054276507714414876684738121421124177324568084533020088172040422767194971217814466953837590498718

# n is PRIME! (confirmed via factordb)
# So we need 16th root of ct mod n (a prime)
# e = 16 = 2^4, take 4 successive square roots

def sqrt_mod(a, p):
    """All square roots of a mod p using Tonelli-Shanks."""
    a = a % p
    if a == 0:
        return [0]
    if pow(a, (p - 1) // 2, p) != 1:
        return []  # not a QR
    if p % 4 == 3:
        r = pow(a, (p + 1) // 4, p)
        return [r, p - r]
    # Tonelli-Shanks
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while True:
        if t == 1:
            return [r % p, (p - r) % p]
        i, tmp = 1, (t * t) % p
        while tmp != 1:
            tmp = (tmp * tmp) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, (b * b) % p, (t * b * b) % p, (r * b) % p

# Take 4 successive square roots (16 = 2^4)
roots = [ct]
for step in range(4):
    new_roots = []
    for r in roots:
        new_roots.extend(sqrt_mod(r, n))
    roots = list(set(new_roots))
    print(f"Step {step+1}: {len(roots)} roots")

# Check all roots for valid plaintext
for m in roots:
    pt = long_to_bytes(m)
    if b'crypto{' in pt:
        print(f"FLAG: {pt.decode()}")
    # Also check n - m (negative root)
    pt2 = long_to_bytes(n - m)
    if b'crypto{' in pt2:
        print(f"FLAG: {pt2.decode()}")

# Also try all roots for printable ASCII
for m in roots:
    pt = long_to_bytes(m)
    try:
        text = pt.decode('ascii')
        if text.isprintable():
            print(f"Printable: {text}")
    except:
        pass

# Flag: crypto{m0dul4r_squ4r3_r00t}
