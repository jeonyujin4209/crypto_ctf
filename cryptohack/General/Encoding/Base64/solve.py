#!/usr/bin/env python3

import base64

hex_str = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
raw_bytes = bytes.fromhex(hex_str)
print(base64.b64encode(raw_bytes).decode())
# crypto/Base+64+Encoding+is+Web+Safe/
