#!/usr/bin/env python3

ct = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

# Known plaintext: flag starts with "crypto{"
known = b"crypto{"
key_fragment = bytes(ct[i] ^ known[i] for i in range(len(known)))
# key_fragment = b"myXORke" -> full key = "myXORkey"
key = b"myXORkey"

result = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
print(result.decode())
# crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}
