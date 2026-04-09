"""
Compute the client Finished verify_data for TLS 1.3.
We need the unencrypted handshake messages:
  ClientHello, ServerHello, EncryptedExtensions,
  Certificate, CertificateVerify, server Finished

ClientHello and ServerHello are plaintext in the pcap.
The other server messages are encrypted with SERVER_HANDSHAKE_TRAFFIC_SECRET.
Decrypt them, then compute:
  finished_key = HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", Hash.length)
  verify_data = HMAC(finished_key, Transcript-Hash(handshake context...server Finished))
"""
import hmac
import hashlib
import struct
from math import ceil
from scapy.all import rdpcap, IP, TCP, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HASH_ALG = hashlib.sha384
HASH_LEN = HASH_ALG().digest_size

# --- Read keylog ---
keys = {}
with open("keylogfile.txt") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 3:
            keys[parts[0]] = bytes.fromhex(parts[2])

s_hs_secret = keys["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
c_hs_secret = keys["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]

# --- Parse pcap ---
packets = rdpcap("no-finished-tls3.cryptohack.org.pcapng")

client_ip = None
server_ip = None
for p in packets:
    if IP in p and TCP in p and p[TCP].dport == 443:
        client_ip = p[IP].src
        server_ip = p[IP].dst
        break

def reassemble(packets, src, dst):
    segs = {}
    for p in packets:
        if IP in p and TCP in p and p[IP].src == src and p[IP].dst == dst and Raw in p:
            seq = p[TCP].seq
            data = bytes(p[Raw].load)
            if data:
                segs[seq] = data
    if not segs:
        return b""
    out = bytearray()
    cur = min(segs.keys())
    pos = dict(segs)
    while pos:
        if cur in pos:
            d = pos.pop(cur); out += d; cur += len(d)
        else:
            cur = min(pos.keys())
    return bytes(out)

c2s = reassemble(packets, client_ip, server_ip)
s2c = reassemble(packets, server_ip, client_ip)

def parse_records(data):
    out = []
    i = 0
    while i + 5 <= len(data):
        ctype = data[i]; ver = (data[i+1], data[i+2])
        ln = int.from_bytes(data[i+3:i+5], "big")
        out.append((ctype, ver, data[i+5:i+5+ln]))
        i += 5 + ln
    return out

c_records = parse_records(c2s)
s_records = parse_records(s2c)

# --- HKDF ---
def HKDF_expand(prk, info, length, alg):
    hl = alg().digest_size
    n = (length + hl - 1) // hl
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), alg).digest()
        okm += t
    return okm[:length]

def HKDF_expand_label(secret, label, context, length, alg):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    return HKDF_expand(secret, info, length, alg)

# Cipher suite is TLS_AES_256_GCM_SHA384 (0x1302) per the script using HASH_ALG=sha384
key_len = 32

def derive(secret):
    k = HKDF_expand_label(secret, b"key", b"", key_len, HASH_ALG)
    iv = HKDF_expand_label(secret, b"iv", b"", 12, HASH_ALG)
    return k, iv

s_hs_key, s_hs_iv = derive(s_hs_secret)

# --- Find ClientHello and ServerHello (plaintext records) ---
def find_handshake_msg(records, htype):
    for ctype, ver, body in records:
        if ctype == 22:
            j = 0
            while j + 4 <= len(body):
                ht = body[j]; hl = int.from_bytes(body[j+1:j+4], "big")
                msg = body[j:j+4+hl]
                if ht == htype:
                    return msg
                j += 4 + hl
    return None

client_hello_msg = find_handshake_msg(c_records, 1)
server_hello_msg = find_handshake_msg(s_records, 2)
print("ClientHello len:", len(client_hello_msg))
print("ServerHello len:", len(server_hello_msg))

# --- Decrypt server-side encrypted handshake records (after CCS) ---
def tls13_decrypt_records(records, key, iv):
    aesgcm = AESGCM(key)
    seq = 0
    out = []
    for ctype, ver, body in records:
        if ctype == 23:
            nonce = bytearray(iv)
            sb = struct.pack(">Q", seq)
            for i in range(8):
                nonce[12 - 8 + i] ^= sb[i]
            aad = bytes([ctype, ver[0], ver[1]]) + struct.pack(">H", len(body))
            try:
                pt = aesgcm.decrypt(bytes(nonce), body, aad)
            except Exception as e:
                out.append(("ERR", str(e)))
                seq += 1
                continue
            j = len(pt) - 1
            while j >= 0 and pt[j] == 0:
                j -= 1
            inner_type = pt[j]
            inner = pt[:j]
            out.append((inner_type, inner))
            seq += 1
        elif ctype == 20:
            pass
    return out

# Server records: [22 (ServerHello), 20 (CCS), 23..., 23...]
# We only need to decrypt records AFTER ServerHello (the encrypted ones).
# Actually only encrypted records (ctype=23) are decrypted by the function above.
server_dec = tls13_decrypt_records(s_records, s_hs_key, s_hs_iv)
print("Server decrypted inner messages:")
for t, p in server_dec:
    print(" ", t, len(p) if isinstance(p, (bytes, bytearray)) else p)

# Concatenate inner handshake messages (type 22) into a single buffer, then split.
encrypted_handshake_buf = b""
for t, p in server_dec:
    if t == 22:
        encrypted_handshake_buf += p

# Split into individual handshake messages
def split_hs(buf):
    msgs = []
    i = 0
    while i + 4 <= len(buf):
        ht = buf[i]
        hl = int.from_bytes(buf[i+1:i+4], "big")
        msg = buf[i:i+4+hl]
        msgs.append((ht, msg))
        i += 4 + hl
    return msgs

server_hs_msgs = split_hs(encrypted_handshake_buf)
print("Server encrypted handshake messages:", [(t, len(m)) for t, m in server_hs_msgs])

# Identify EncryptedExtensions(8), Certificate(11), CertificateVerify(15), Finished(20)
ee = next(m for t, m in server_hs_msgs if t == 8)
cert = next(m for t, m in server_hs_msgs if t == 11)
cv = next(m for t, m in server_hs_msgs if t == 15)
fin = next(m for t, m in server_hs_msgs if t == 20)

print("EE:", len(ee), "Cert:", len(cert), "CV:", len(cv), "Fin:", len(fin))

# --- Compute finished_key for client ---
finished_key = HKDF_expand_label(c_hs_secret, b"finished", b"", HASH_LEN, HASH_ALG)

# --- Compute transcript hash and verify_data ---
transcript = client_hello_msg + server_hello_msg + ee + cert + cv + fin
transcript_hash = HASH_ALG(transcript).digest()
print("Transcript hash:", transcript_hash.hex())

verify_data = hmac.new(finished_key, transcript_hash, HASH_ALG).digest()
print("verify_data (hex):", verify_data.hex())
print("Flag: crypto{" + verify_data.hex() + "}")
