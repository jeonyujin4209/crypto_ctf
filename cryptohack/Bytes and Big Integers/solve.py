#!/usr/bin/env python3

n = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
print(n.to_bytes((n.bit_length() + 7) // 8, 'big').decode())
# crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}
