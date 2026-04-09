"""
Decrypt TLS 1.3 traffic using key log file (CLIENT/SERVER_TRAFFIC_SECRET_0).
TLS 1.3 records use AEAD with keys derived via HKDF-Expand-Label from the
traffic secret.
"""
from scapy.all import rdpcap, IP, TCP, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib
import struct
import re

# --- Parse keylog ---
keys = {}
with open("keylogfile.txt") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 3:
            label, cr, secret = parts
            keys[label] = (bytes.fromhex(cr), bytes.fromhex(secret))

print("Keylog labels:", list(keys.keys()))

# --- Read pcap ---
packets = rdpcap("tls3.cryptohack.org.pcapng")

client_ip = None
server_ip = None
for p in packets:
    if IP in p and TCP in p and p[TCP].dport == 443:
        client_ip = p[IP].src
        server_ip = p[IP].dst
        break
print("Client:", client_ip, "Server:", server_ip)

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
    sorted_seqs = sorted(segs.keys())
    cur = sorted_seqs[0]
    pos = dict(segs)
    while pos:
        if cur in pos:
            data = pos.pop(cur)
            out += data
            cur += len(data)
        else:
            cur = min(pos.keys())
    return bytes(out)

c2s = reassemble(packets, client_ip, server_ip)
s2c = reassemble(packets, server_ip, client_ip)

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
print("Client records:", [(r[0], len(r[2])) for r in c_records])
print("Server records:", [(r[0], len(r[2])) for r in s_records])

# --- HKDF ---
def HKDF_expand(prk, info, length, hash_alg):
    hash_len = hash_alg().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_alg).digest()
        okm += t
    return okm[:length]

def HKDF_expand_label(secret, label, context, length, hash_alg):
    full_label = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return HKDF_expand(secret, info, length, hash_alg)

# --- Derive AEAD keys from traffic secrets ---
# Cipher suite is determined by ServerHello. Find it.
def get_cipher_suite():
    # ServerHello in s_records[0]: type=22 then handshake type 2
    for ctype, ver, body in s_records:
        if ctype == 22:
            # parse first handshake msg
            j = 0
            while j + 4 <= len(body):
                ht = body[j]
                hl = int.from_bytes(body[j+1:j+4], "big")
                hb = body[j+4:j+4+hl]
                if ht == 2:
                    # ServerHello: legacy_ver(2) + random(32) + sid_len(1)+sid + cs(2) + comp(1) + ext...
                    p = 34
                    sl = hb[p]; p += 1 + sl
                    cs = hb[p:p+2]
                    return cs
                j += 4 + hl
    return None

cs = get_cipher_suite()
print("cipher suite:", cs.hex() if cs else None)

# Map: 0x1301 = TLS_AES_128_GCM_SHA256, 0x1302 = TLS_AES_256_GCM_SHA384, 0x1303 = TLS_CHACHA20_POLY1305_SHA256
suite_map = {
    b"\x13\x01": ("AES128GCM", hashlib.sha256, 16),
    b"\x13\x02": ("AES256GCM", hashlib.sha384, 32),
    b"\x13\x03": ("CHACHA20", hashlib.sha256, 32),
}
suite_name, hash_alg, key_len = suite_map[cs]
print("Using:", suite_name)

def derive_key_iv(secret):
    key = HKDF_expand_label(secret, b"key", b"", key_len, hash_alg)
    iv  = HKDF_expand_label(secret, b"iv", b"", 12, hash_alg)
    return key, iv

# Note: Each direction has TWO secrets:
# - {C,S}_HANDSHAKE_TRAFFIC_SECRET (for handshake records after ServerHello)
# - {C,S}_TRAFFIC_SECRET_0 (for application data after Finished)
# We need to switch between them.

c_hs_secret = keys["CLIENT_HANDSHAKE_TRAFFIC_SECRET"][1]
s_hs_secret = keys["SERVER_HANDSHAKE_TRAFFIC_SECRET"][1]
c_app_secret = keys["CLIENT_TRAFFIC_SECRET_0"][1]
s_app_secret = keys["SERVER_TRAFFIC_SECRET_0"][1]

c_hs_key, c_hs_iv = derive_key_iv(c_hs_secret)
s_hs_key, s_hs_iv = derive_key_iv(s_hs_secret)
c_app_key, c_app_iv = derive_key_iv(c_app_secret)
s_app_key, s_app_iv = derive_key_iv(s_app_secret)

# --- AEAD decrypt for TLS 1.3 ---
def tls13_decrypt(records, hs_key, hs_iv, app_key, app_iv):
    """
    TLS 1.3 records: outer type is always 23 (application_data) for encrypted records.
    AAD = full record header (5 bytes).
    nonce = iv XOR seq (right-aligned).
    Plaintext = inner_content || inner_type (last byte) || optional padding (zeros)
    """
    seq = 0
    finished_seen = False
    cur_key = hs_key
    cur_iv = hs_iv
    aesgcm = AESGCM(cur_key)
    out = []
    for ctype, ver, body in records:
        if ctype == 23:  # encrypted application data wrapper
            # Build nonce
            nonce = bytearray(cur_iv)
            seq_bytes = struct.pack(">Q", seq)
            for i in range(8):
                nonce[12 - 8 + i] ^= seq_bytes[i]
            aad = bytes([ctype, ver[0], ver[1]]) + struct.pack(">H", len(body))
            try:
                pt = aesgcm.decrypt(bytes(nonce), body, aad)
            except Exception as e:
                out.append(("ERR", str(e), seq))
                seq += 1
                continue
            # Strip trailing zeros (padding) and last byte = inner type
            j = len(pt) - 1
            while j >= 0 and pt[j] == 0:
                j -= 1
            inner_type = pt[j]
            inner = pt[:j]
            out.append((inner_type, inner, seq))
            seq += 1
            # If we just decrypted a Finished (handshake type 20) on this stream,
            # switch to application keys and reset seq for app data.
            if inner_type == 22 and len(inner) >= 1 and inner[0] == 20 and not finished_seen:
                finished_seen = True
                cur_key = app_key
                cur_iv = app_iv
                aesgcm = AESGCM(cur_key)
                seq = 0
        elif ctype == 20:
            # ChangeCipherSpec - ignore in 1.3
            pass
        else:
            out.append(("PLAIN", (ctype, body), seq))
    return out

print("\n=== Server stream ===")
s_dec = tls13_decrypt(s_records, s_hs_key, s_hs_iv, s_app_key, s_app_iv)
for t, payload, seq in s_dec:
    if isinstance(payload, bytes):
        print(f"  seq={seq} type={t} len={len(payload)} preview={payload[:80]!r}")
    else:
        print(f"  seq={seq} type={t} payload={payload}")

print("\n=== Client stream ===")
c_dec = tls13_decrypt(c_records, c_hs_key, c_hs_iv, c_app_key, c_app_iv)
for t, payload, seq in c_dec:
    if isinstance(payload, bytes):
        print(f"  seq={seq} type={t} len={len(payload)} preview={payload[:80]!r}")

# Look for flag
all_pt = b""
for t, p, _ in s_dec + c_dec:
    if isinstance(p, bytes):
        all_pt += p
m = re.search(rb"crypto\{[^}]+\}", all_pt)
if m:
    print("\nFLAG:", m.group().decode())
else:
    # Try printing app data only from server
    print("\nServer app data dump:")
    for t, p, seq in s_dec:
        if t == 23 and isinstance(p, bytes):
            print(p)
