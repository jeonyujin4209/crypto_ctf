"""
Cipher Mode Picker (HKCERT CTF 2021)

Key insight: CFB-128 with zero plaintext produces the same ciphertext as
the OFB keystream. Because:
  CFB: c_i = E(c_{i-1}) XOR p_i,  c_{-1} = IV
  OFB: c_i = s_i XOR p_i,  s_i = E(s_{i-1}),  s_{-1} = IV

With p_i = 0 for all i:
  CFB: c_0 = E(IV), c_1 = E(c_0) = E(E(IV)), ...  (same recurrence as OFB keystream)

Attack (2 queries):
  1. cfb data <80 zero bytes>  → OFB keystream
  2. ofb flag                  → flag XOR OFB keystream
  XOR (1) and (2)              → flag
"""
import socket

HOST = 'archive.cryptohack.org'
PORT = 2951

def recvuntil(s, delim=b'\n'):
    buf = b''
    while not buf.endswith(delim):
        buf += s.recv(1)
    return buf

def query(s, cmd):
    s.sendall((cmd + '\n').encode())
    return recvuntil(s).decode().strip()

with socket.create_connection((HOST, PORT)) as sock:
    zeros_hex = '00' * 80

    # Step 1: CFB with 80 zero bytes → OFB keystream
    prompt = recvuntil(sock, b'> ')
    cfb_resp = query(sock, f'cfb data {zeros_hex}')
    keystream = bytes.fromhex(cfb_resp)
    print(f"keystream: {keystream.hex()}")

    # Step 2: OFB flag → keystream XOR flag
    prompt = recvuntil(sock, b'> ')
    ofb_resp = query(sock, 'ofb flag')
    ct = bytes.fromhex(ofb_resp)
    print(f"ofb_flag:  {ct.hex()}")

    flag_bytes = bytes(a ^ b for a, b in zip(ct, keystream))
    print("Flag:", flag_bytes.decode())
