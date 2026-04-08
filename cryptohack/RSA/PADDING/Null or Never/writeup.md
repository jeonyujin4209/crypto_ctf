# Null or Never

## Challenge

RSA with e=3. The flag is padded with null bytes to 100 bytes:
```python
m_padded = FLAG + b'\x00' * (100 - len(FLAG))
c = m_padded^3 mod n
```

Given: n (1024-bit), e=3, c.

## Attack

Since `m_padded = FLAG_int * 256^pad_len`, we have:
```
c = (FLAG_int * 256^pad_len)^3 mod n
c = FLAG_int^3 * 256^(3*pad_len) mod n
```

Therefore:
```
FLAG_int^3 = c * inverse(256^(3*pad_len), n) mod n
```

If `FLAG_int^3 < n` (i.e., the flag is short enough that cubing doesn't wrap around n), we can simply take the integer cube root.

For flag_len <= 42 bytes: `FLAG_int^3 < 2^(42*8*3) = 2^1008 < n` (1024 bits), so this works.

For longer flags: iterate over `FLAG_int^3 = c * inv(256^(3k), n) + j*n` for small j values.

### Steps:
1. For each candidate flag length (20-80):
   - Compute `shift_inv = inverse(256^(3*pad_len), n)`
   - Compute `flag_cubed = c * shift_inv mod n`
   - Take integer cube root (using gmpy2.iroot)
   - Check if result decodes to `crypto{...}`

## Flag
`crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}`
