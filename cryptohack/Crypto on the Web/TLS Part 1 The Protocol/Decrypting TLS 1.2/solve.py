"""
Decrypt TLS 1.2 RSA-keyed connection (TLS_RSA_WITH_AES_256_GCM_SHA384).
"""
from scapy.all import rdpcap, IP, TCP, Raw
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib
import struct

# --- Load private key ---
with open("privkey.pem", "rb") as f:
    privkey = load_pem_private_key(f.read(), password=None)

# --- Read pcap and reassemble TCP streams ---
packets = rdpcap("tls2.cryptohack.org.pcapng")

# Find IPs - server is tls2.cryptohack.org
# Find by looking at port 443
client_ip = None
server_ip = None
for p in packets:
    if IP in p and TCP in p:
        if p[TCP].dport == 443:
            client_ip = p[IP].src
            server_ip = p[IP].dst
            break

print(f"Client: {client_ip}, Server: {server_ip}")

# Reassemble TCP streams. Use sequence numbers for correct ordering.
def reassemble(packets, src, dst):
    segs = {}  # seq -> data
    isn = None
    for p in packets:
        if IP in p and TCP in p and p[IP].src == src and p[IP].dst == dst and Raw in p:
            seq = p[TCP].seq
            data = bytes(p[Raw].load)
            if data:
                segs[seq] = data
                if isn is None or seq < isn:
                    isn = seq
    if not segs:
        return b""
    # Order by seq
    out = bytearray()
    sorted_seqs = sorted(segs.keys())
    cur = sorted_seqs[0]
    pos = {s: segs[s] for s in sorted_seqs}
    while pos:
        if cur in pos:
            data = pos.pop(cur)
            out += data
            cur += len(data)
        else:
            # gap?
            nxt = min(pos.keys())
            cur = nxt
    return bytes(out)

c2s = reassemble(packets, client_ip, server_ip)
s2c = reassemble(packets, server_ip, client_ip)
print(f"C2S bytes: {len(c2s)}, S2C bytes: {len(s2c)}")

# --- Parse TLS records ---
def parse_records(data):
    i = 0
    out = []
    while i + 5 <= len(data):
        ctype = data[i]
        ver = (data[i+1], data[i+2])
        ln = int.from_bytes(data[i+3:i+5], "big")
        body = data[i+5:i+5+ln]
        if len(body) < ln:
            break
        out.append((ctype, ver, body))
        i += 5 + ln
    return out

c_records = parse_records(c2s)
s_records = parse_records(s2c)
print(f"Client records: {len(c_records)}, Server records: {len(s_records)}")
for r in c_records[:6]:
    print("C:", r[0], len(r[2]))
for r in s_records[:6]:
    print("S:", r[0], len(r[2]))

# --- Extract handshake messages ---
def extract_handshake(records):
    """Concatenate handshake records, then split into individual messages."""
    buf = b""
    for ctype, ver, body in records:
        if ctype == 22:  # handshake
            buf += body
    msgs = []
    i = 0
    while i + 4 <= len(buf):
        htype = buf[i]
        hlen = int.from_bytes(buf[i+1:i+4], "big")
        body = buf[i+4:i+4+hlen]
        msgs.append((htype, body, buf[i:i+4+hlen]))  # also raw for transcript
        i += 4 + hlen
    return msgs

c_hs = extract_handshake(c_records)
s_hs = extract_handshake(s_records)

print("Client handshake msgs:", [(t, len(b)) for t, b, _ in c_hs])
print("Server handshake msgs:", [(t, len(b)) for t, b, _ in s_hs])

# --- ClientHello: type 1 ---
client_hello = next(b for t, b, _ in c_hs if t == 1)
# legacy_version (2) + random (32) + session_id_len (1) + ...
client_random = client_hello[2:34]
print("client_random:", client_random.hex())

# --- ServerHello: type 2 ---
server_hello = next(b for t, b, _ in s_hs if t == 2)
server_random = server_hello[2:34]
print("server_random:", server_random.hex())

# --- ClientKeyExchange: type 16 ---
cke = next(b for t, b, _ in c_hs if t == 16)
# For RSA: 2-byte length + encrypted premaster
enc_pms_len = int.from_bytes(cke[0:2], "big")
enc_pms = cke[2:2+enc_pms_len]
print("enc_pms len:", enc_pms_len)

# --- RSA decrypt to get premaster secret ---
pms = privkey.decrypt(enc_pms, padding.PKCS1v15())
print("premaster secret:", pms.hex())

# --- TLS 1.2 PRF using SHA-384 (since cipher is ..._SHA384) ---
def P_hash(secret, seed, hash_fn, length):
    out = b""
    A = seed
    while len(out) < length:
        A = hmac.new(secret, A, hash_fn).digest()
        out += hmac.new(secret, A + seed, hash_fn).digest()
    return out[:length]

def PRF(secret, label, seed, length):
    return P_hash(secret, label + seed, hashlib.sha384, length)

# Server agreed extended_master_secret extension (0x17), so use:
#   master_secret = PRF(pms, "extended master secret", session_hash, 48)
# session_hash = SHA-384(all handshake messages up to and including ClientKeyExchange)
# Build the transcript from raw handshake bytes (concatenated, no record headers)
hs_so_far = b""
for t, body, raw in c_hs + s_hs:
    pass  # ignore - need ordered

# Reconstruct ordered handshake messages by re-walking records in chronological order
# Combine and split records by side; we need them in true wire order across both sides.
# Build (timestamp, side, record) by iterating packets again.
ordered_hs = []
# Collect (seq_in_stream, side, raw_handshake_msgs)
# Simpler: use combined order based on TCP sequence isn't helpful here.
# Actually the order is: ClientHello, ServerHello, Certificate, [ServerKeyExchange], [CertReq], ServerHelloDone, [ClientCert], ClientKeyExchange, [CertVerify], [ChangeCipherSpec], Finished
# So we know the canonical order:
# Client side handshake msgs (in c_hs order): ClientHello, ClientKeyExchange, ...(Finished encrypted)
# Server side: ServerHello, Certificate, [ServerKeyExchange], ServerHelloDone, ...(Finished encrypted)
# We want everything up to and including ClientKeyExchange.

# Order: ClientHello, ServerHello, Certificate, ServerHelloDone (server msgs in s_hs order),
#        then ClientKeyExchange (next client msg)
client_pre_hs = []  # raw bytes of (type+len+body) for plaintext msgs from client
for t, body, raw in c_hs:
    if t in (1, 11, 12, 14, 15, 16):  # ClientHello..ClientKeyExchange
        client_pre_hs.append((t, raw))
server_pre_hs = []
for t, body, raw in s_hs:
    if t in (2, 11, 12, 13, 14):  # ServerHello, Certificate, ServerKeyExchange, CertReq, ServerHelloDone
        server_pre_hs.append((t, raw))

# Build canonical order
canonical = []
ch_msg = next(raw for t, raw in client_pre_hs if t == 1)
canonical.append(ch_msg)
for t, raw in server_pre_hs:
    canonical.append(raw)
cke_msg = next(raw for t, raw in client_pre_hs if t == 16)
canonical.append(cke_msg)

session_hash = hashlib.sha384(b"".join(canonical)).digest()
print("session_hash:", session_hash.hex())

# master_secret with EMS
master_secret = PRF(pms, b"extended master secret", session_hash, 48)
print("master_secret (EMS):", master_secret.hex())

# Key block: for AES-256-GCM with AEAD: no MAC keys.
# key_block = PRF(master_secret, "key expansion", server_random + client_random, ...)
# For AES_256_GCM_SHA384: enc_key_length = 32, fixed_iv_length = 4, mac_key_length = 0
key_block_len = 2 * 32 + 2 * 4
key_block = PRF(master_secret, b"key expansion", server_random + client_random, key_block_len)
client_write_key = key_block[0:32]
server_write_key = key_block[32:64]
client_write_iv = key_block[64:68]  # implicit IV (salt)
server_write_iv = key_block[68:72]
print("client_write_key:", client_write_key.hex())
print("server_write_key:", server_write_key.hex())

# --- Now decrypt ApplicationData records ---
# Each record: type=23, version, length, then body
# For TLS_RSA_WITH_AES_256_GCM_SHA384 (RFC 5288):
#   GenericAEADCipher: explicit_nonce (8 bytes) + ciphertext + tag (16 bytes)
#   nonce = client_write_iv || explicit_nonce  (12 bytes total)
#   AAD = seq_num (8) + content_type (1) + version (2) + length_of_plaintext (2)

def decrypt_records(records, write_key, write_iv, start_seq=0):
    aesgcm = AESGCM(write_key)
    seq = start_seq
    out = []
    for ctype, ver, body in records:
        if ctype == 23:  # ApplicationData
            explicit_nonce = body[:8]
            ct_and_tag = body[8:]
            nonce = write_iv + explicit_nonce
            plaintext_len = len(ct_and_tag) - 16
            aad = struct.pack(">Q", seq) + bytes([ctype]) + bytes([ver[0], ver[1]]) + struct.pack(">H", plaintext_len)
            try:
                pt = aesgcm.decrypt(nonce, ct_and_tag, aad)
                out.append((ctype, pt))
            except Exception as e:
                out.append((ctype, f"DECRYPT_FAIL_t23: {type(e).__name__} {e}".encode()))
            seq += 1
        elif ctype == 20:  # ChangeCipherSpec - doesn't increment seq
            pass
        elif ctype == 22:  # Handshake (Finished is encrypted as appdata typically in 1.2 - but uses same seq)
            # In TLS 1.2 GCM, the Finished message is in a Handshake record but encrypted via the AEAD wrapper
            # Actually no - in TLS 1.2 the Finished message comes WRAPPED in a handshake record but is itself
            # encrypted. The Finished is sent as a Handshake content type (22) but encrypted. Actually no -
            # in TLS 1.2 with GCM, after ChangeCipherSpec, all subsequent records are encrypted. The Finished
            # appears in a Handshake (type 22) record but the body is encrypted.
            explicit_nonce = body[:8]
            ct_and_tag = body[8:]
            nonce = write_iv + explicit_nonce
            plaintext_len = len(ct_and_tag) - 16
            aad = struct.pack(">Q", seq) + bytes([ctype]) + bytes([ver[0], ver[1]]) + struct.pack(">H", plaintext_len)
            try:
                pt = aesgcm.decrypt(nonce, ct_and_tag, aad)
                out.append((ctype, pt))
            except Exception as e:
                out.append((ctype, f"DECRYPT_FAIL_t22: {type(e).__name__} {e}".encode()))
            seq += 1
    return out

# We need to start decryption AFTER the ChangeCipherSpec record on each side.
# Find index of CCS in client and server records.
def split_after_ccs(records):
    out = []
    seen = False
    for r in records:
        if seen:
            out.append(r)
        if r[0] == 20:
            seen = True
    return out

c_after = split_after_ccs(c_records)
s_after = split_after_ccs(s_records)

print("\n=== Client encrypted records ===")
c_dec = decrypt_records(c_after, client_write_key, client_write_iv)
for ctype, pt in c_dec:
    print(f"  type={ctype} len={len(pt)} preview={pt[:80]!r}")

print("\n=== Server encrypted records ===")
s_dec = decrypt_records(s_after, server_write_key, server_write_iv)
for ctype, pt in s_dec:
    print(f"  type={ctype} len={len(pt)} preview={pt[:200]!r}")

# Look for flag
all_decrypted = b"".join(pt for _, pt in c_dec + s_dec)
import re
m = re.search(rb"crypto\{[^}]+\}", all_decrypted)
if m:
    print("\nFLAG:", m.group().decode())
else:
    print("\nNo crypto{} flag found yet. Full decrypted server data:")
    full_s = b"".join(pt for ctype, pt in s_dec if ctype == 23)
    print(full_s)
