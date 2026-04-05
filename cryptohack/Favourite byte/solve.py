#!/usr/bin/env python3

data = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for key in range(256):
    result = bytes(b ^ key for b in data)
    if b"crypto{" in result:
        print(f"Key: {hex(key)}")
        print(result.decode())
        break
# Key: 0x10
# crypto{0x10_15_my_f4v0ur173_by7e}
