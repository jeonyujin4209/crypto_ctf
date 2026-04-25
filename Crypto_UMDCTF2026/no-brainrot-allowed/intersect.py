"""
Maintain [a, b) AND know that m ∈ S (ASCII pattern).

After every query update, set:
  a := min(S ∩ [a, b))
  b := max(S ∩ [a, b)) + 1

These can be computed efficiently from the byte representation of a and b.

Specifically, given any value v, find:
  - smallest s ∈ S with s >= v: walk from MSB. For each byte position, if v_byte fits
    the pattern, keep it; if v_byte > max_allowed, increment higher byte and set this
    and all lower to min; if v_byte < min_allowed, set this byte to min and all lower to min.
  - largest s ∈ S with s < V (similarly).
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes


def byte_range(i, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi):
    """For position i in flag, return (min, max) byte values allowed."""
    if i < len(prefix_bytes):
        return prefix_bytes[i], prefix_bytes[i]
    if i == n_bytes - 1:
        return suffix_byte, suffix_byte
    return content_lo, content_hi


def smallest_in_S_ge(v, n_bytes, prefix_bytes, suffix_byte, content_lo=0x20, content_hi=0x7e):
    """Smallest x in S with x >= v. Returns None if none."""
    v_bytes = v.to_bytes(n_bytes, 'big')
    # Build greedily from MSB
    out = bytearray(n_bytes)
    # We try to follow v_bytes as closely as possible while fitting pattern, going up if needed.
    # Strategy: scan MSB to LSB:
    #   - try out[i] = v[i] if it fits range. Then continue with "==" mode (must match v from this point or go higher).
    #   - if v[i] < lo: set out[i] = lo, fill rest with min, done (now > v, so > v).
    #   - if v[i] > hi: backtrack (need to increment a previous byte).
    # We'll implement via recursion / explicit backtracking.
    
    # State: ge_mode (still tracking == v from MSB)
    # When ge_mode is True, we must satisfy out[i:] >= v[i:].
    # When ge_mode is False, we can use min for all remaining.
    
    def helper(i, ge_mode):
        if i == n_bytes:
            return bytearray()  # empty tail, valid
        lo, hi = byte_range(i, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
        if ge_mode:
            # must have out[i:] >= v[i:] in lex
            if v_bytes[i] > hi:
                return None  # can't reach v[i] with allowed bytes; backtrack
            if v_bytes[i] < lo:
                # set out[i] = lo, rest = mins (since out[i] > v[i])
                tail = bytearray()
                for j in range(i+1, n_bytes):
                    lj, _ = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                    tail.append(lj)
                return bytearray([lo]) + tail
            # try out[i] = v[i] with ge_mode=True first
            if lo <= v_bytes[i] <= hi:
                rec = helper(i+1, True)
                if rec is not None:
                    return bytearray([v_bytes[i]]) + rec
            # else try larger byte
            for c in range(max(v_bytes[i]+1, lo), hi+1):
                tail = bytearray()
                for j in range(i+1, n_bytes):
                    lj, _ = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                    tail.append(lj)
                return bytearray([c]) + tail
            return None
        else:
            # any value in [lo, hi]; pick min for smallest result
            tail = bytearray()
            for j in range(i, n_bytes):
                lj, _ = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                tail.append(lj)
            return tail
    
    res = helper(0, True)
    if res is None: return None
    return int.from_bytes(res, 'big')


def largest_in_S_lt(v, n_bytes, prefix_bytes, suffix_byte, content_lo=0x20, content_hi=0x7e):
    """Largest x in S with x < v. Returns None if none."""
    v_bytes = v.to_bytes(n_bytes, 'big')
    
    def helper(i, lt_mode):
        if i == n_bytes:
            if lt_mode:
                return None  # we needed strict <, but ended in equal → not < v
            return bytearray()
        lo, hi = byte_range(i, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
        if lt_mode:
            # must have out[i:] < v[i:] in lex
            if v_bytes[i] < lo:
                return None  # can't go below v[i] with allowed bytes; backtrack
            if v_bytes[i] > hi:
                # set out[i] = hi, rest = max
                tail = bytearray()
                for j in range(i+1, n_bytes):
                    _, hj = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                    tail.append(hj)
                return bytearray([hi]) + tail
            # try out[i] = v[i] with lt_mode=True (must satisfy in tail)
            if lo <= v_bytes[i] <= hi:
                rec = helper(i+1, True)
                if rec is not None:
                    return bytearray([v_bytes[i]]) + rec
            # else try smaller byte (but >= lo)
            c = min(v_bytes[i] - 1, hi)
            if c >= lo:
                tail = bytearray()
                for j in range(i+1, n_bytes):
                    _, hj = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                    tail.append(hj)
                return bytearray([c]) + tail
            return None
        else:
            # any value in [lo, hi]; pick max
            tail = bytearray()
            for j in range(i, n_bytes):
                _, hj = byte_range(j, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
                tail.append(hj)
            return tail
    
    res = helper(0, True)
    if res is None: return None
    return int.from_bytes(res, 'big')


def intersect_with_S(a, b, n_bytes, prefix_bytes, suffix_byte, content_lo=0x20, content_hi=0x7e):
    """Compute (a', b') = ([a, b) ∩ S) bounding interval. Returns None if empty."""
    new_a = smallest_in_S_ge(a, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
    if new_a is None or new_a >= b: return None
    new_b_minus_1 = largest_in_S_lt(b, n_bytes, prefix_bytes, suffix_byte, content_lo, content_hi)
    if new_b_minus_1 is None or new_b_minus_1 < new_a: return None
    return (new_a, new_b_minus_1 + 1)


# Test
if __name__ == "__main__":
    flag_len = 111
    prefix = b"UMDCTF{"
    suffix = 0x7d
    
    # test 1: full unknown
    a = bytes_to_long(prefix + b"\x00" * 103 + b"}")
    b = bytes_to_long(prefix + b"\xff" * 103 + b"}") + 1
    new_a, new_b = intersect_with_S(a, b, flag_len, prefix, suffix)
    print(f"test 1: a={a:x}...")
    print(f"  expected min m = prefix + '\\x20'*103 + '}}'")
    expected_min = bytes_to_long(prefix + b"\x20" * 103 + b"}")
    expected_max = bytes_to_long(prefix + b"\x7e" * 103 + b"}")
    print(f"  new_a == expected? {new_a == expected_min}")
    print(f"  new_b - 1 == expected? {new_b - 1 == expected_max}")
    print(f"  width: 2^{(new_b - new_a).bit_length()-1}")
    
    # test 2: arbitrary [a, b) where some bytes outside ASCII
    real = bytes_to_long(b"UMDCTF{abcdefghijklmnop" + b"x" * (111 - 24) + b"}")
    a = real - 100  
    b = real + 100
    print(f"\ntest 2: small range around real flag")
    print(f"  width: {b - a}")
    res = intersect_with_S(a, b, flag_len, prefix, suffix)
    if res:
        new_a, new_b = res
        print(f"  intersect width: {new_b - new_a}")
        # both real and real+1 etc should be in S, since real is itself a valid flag
        assert new_a <= real < new_b
    else:
        print("  empty?!")
    
    # test 3: edge case
    # narrow [a, b) that contains no S element
    a = bytes_to_long(prefix + b"\x10" * 103 + b"}")
    b = bytes_to_long(prefix + b"\x1f" * 103 + b"}") + 1
    res = intersect_with_S(a, b, flag_len, prefix, suffix)
    print(f"\ntest 3: range entirely below 0x20: {res}")
    
    # test 4: range that should include some valid m's
    a = bytes_to_long(prefix + b"\x10" * 103 + b"}")
    b = bytes_to_long(prefix + b"\x30" * 103 + b"}") + 1
    res = intersect_with_S(a, b, flag_len, prefix, suffix)
    if res:
        new_a, new_b = res
        # min in S >= a: byte 0 of content can't be 0x10, so smallest is byte 0 = 0x20, rest min
        print(f"\ntest 4: range partly valid")
        print(f"  new_a as bytes: {long_to_bytes(new_a)[:30]}")
        print(f"  new_b - 1 as bytes: {long_to_bytes(new_b - 1)[:30]}")
