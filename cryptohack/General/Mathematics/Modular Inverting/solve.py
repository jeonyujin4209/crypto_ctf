#!/usr/bin/env python3
# 3 * d ≡ 1 (mod 13)
# By Fermat's little theorem: d = 3^(13-2) mod 13 = 3^11 mod 13
# Or simply: pow(3, -1, 13)
print(pow(3, -1, 13))
# 9  (because 3*9 = 27 = 2*13 + 1)
