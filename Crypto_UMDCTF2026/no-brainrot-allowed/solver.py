"""
Server solver. Plug in real n, ct from server.

Manger-style attack with:
  - track [mmin, mmax)
  - each step: find f s.t. f*[mmin, mmax) lifted mod n straddles A=0x67·16^254
  - oracle response halves
  - ASCII-tighten after each step
  
Also batches queries to server to save round-trip.
We BATCH by speculatively trying multiple candidate f values per round,
each corresponding to a different (i, df) tuple. After getting batch results,
we walk through and apply update for the FIRST one that actually narrows.

But for first version, single-query-per-round is simpler and only ~686 queries total.
With batch_oracle of 25 per round, we'd need ceil(686/25)=28 round-trips. Already great.

Let me start with the single-query-per-round version.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from intersect import intersect_with_S
from Crypto.Util.number import bytes_to_long, long_to_bytes

A_TOP = 0x67 * 16**254
B_TOP = 0x68 * 16**254
DELTA = B_TOP - A_TOP


def find_query(mmin, mmax, n, sample_i_count=500):
    """Find f that straddles A_TOP boundary cleanly inside f*[mmin, mmax) mod n."""
    width = mmax - mmin
    if width < 2: return None
    target_m = mmin + width // 2
    if target_m == 0: return None
    f_max = (n - 1) // width
    if f_max < 2: return None
    
    i_max = (f_max * mmax) // n + 1
    if i_max > sample_i_count:
        stride = max(1, i_max // sample_i_count)
        i_list = list(range(0, i_max + 1, stride))[:sample_i_count]
    else:
        i_list = list(range(0, i_max + 1))
    
    best = None
    for i in i_list:
        f_target = (i * n + A_TOP) // target_m
        for df in (0, 1, -1, 2, -2, 3, -3):
            f = f_target + df
            if not (2 <= f <= f_max): continue
            v_lo = f * mmin
            v_hi = f * mmax
            if not (i * n <= v_lo and v_hi <= (i + 1) * n):
                continue
            target_A = i * n + A_TOP
            target_B = i * n + B_TOP
            if not (v_lo <= target_A < v_hi):
                continue
            m_A = (target_A + f - 1) // f
            if target_B < v_hi:
                m_B_inside = (target_B + f - 1) // f
                hit_lo = max(m_A, mmin)
                hit_hi = min(m_B_inside, mmax)
            else:
                hit_lo = max(m_A, mmin)
                hit_hi = mmax
            if hit_lo >= hit_hi: continue
            hit_width = hit_hi - hit_lo
            bal = abs(2 * hit_width - width)
            if best is None or bal < best[0]:
                best = (bal, f, i, hit_lo, hit_hi)
    return best


def solve(n, e, ct, oracle_fn, K=103,
          prefix=b"UMDCTF{", suffix_byte=0x7d, log_progress=True):
    """
    Recover m given:
      n, e, ct = pow(m, e, n)
      oracle_fn(c) -> bool: hex(pow(c,d,n)).startswith('0x67')
      K = content length (between {})
    Returns recovered m (int) or None.
    """
    flag_len = len(prefix) + K + 1  # prefix + content + suffix
    a = bytes_to_long(prefix + b"\x20" * K + bytes([suffix_byte]))
    b = bytes_to_long(prefix + b"\x7e" * K + bytes([suffix_byte])) + 1
    
    if log_progress:
        print(f"[solve] flag_len={flag_len}, K={K}, start width 2^{(b-a).bit_length()-1}")
    
    step = 0
    last_w_log = (b - a).bit_length()
    queries_total = 0
    import time
    t0 = time.time()
    
    while b - a > 1:
        step += 1
        if step > 5000:
            if log_progress: print("max steps reached")
            break
        res = find_query(a, b, n)
        if res is None:
            if log_progress: print(f"  step {step}: no candidate, w 2^{(b-a).bit_length()-1}")
            break
        bal, f, i, hit_lo, hit_hi = res
        c = ct * pow(f, e, n) % n
        is_hit = oracle_fn(c)
        queries_total += 1
        if is_hit:
            new_a, new_b = hit_lo, hit_hi
        else:
            if (hit_lo - a) >= (b - hit_hi):
                new_a, new_b = a, hit_lo
            else:
                new_a, new_b = hit_hi, b
        # Sanity: new bounds should be subset of [a, b)
        new_a = max(new_a, a)
        new_b = min(new_b, b)
        if new_a >= new_b:
            if log_progress: print(f"  step {step}: empty after update?!"); 
            break
        # ASCII tighten
        tightened = intersect_with_S(new_a, new_b, flag_len, prefix, suffix_byte)
        if tightened is None:
            if log_progress: print(f"  step {step}: ASCII intersect empty")
            break
        new_a, new_b = tightened
        if (new_a, new_b) == (a, b):
            if log_progress: print(f"  step {step}: no progress, w 2^{(b-a).bit_length()-1}")
            break
        a, b = new_a, new_b
        cur_w = max(0, (b - a).bit_length())
        if log_progress and (last_w_log - cur_w >= 30 or step % 100 == 0 or cur_w < 30):
            print(f"  step {step}: w 2^{cur_w}, q={queries_total}, t={time.time()-t0:.1f}s")
            last_w_log = cur_w
    
    if b - a == 1:
        return a, queries_total
    else:
        if log_progress:
            print(f"[solve] failed; final w={b-a}, q={queries_total}")
        return None, queries_total


# Local test
if __name__ == "__main__":
    from Crypto.Util.number import getPrime
    import random
    
    def setup(seed, bits=1024):
        random.seed(seed)
        while True:
            p = getPrime(bits // 2); q = getPrime(bits // 2)
            n = p*q
            if n.bit_length() != bits-1: continue
            if hex(n)[2] in '789abcdef': break
        e = 65537; d = pow(e, -1, (p-1)*(q-1))
        return n, e, d
    
    seed = 0xC0FFEE
    n, e, d = setup(seed)
    random.seed(seed)
    content = bytes(random.randrange(33, 127) for _ in range(103))
    flag = b"UMDCTF{" + content + b"}"
    m = bytes_to_long(flag)
    ct = pow(m, e, n)
    
    print(f"Target flag: {flag}")
    
    queries_count = [0]
    def oracle_fn(c):
        queries_count[0] += 1
        return hex(pow(c, d, n)).startswith("0x67")
    
    result, q = solve(n, e, ct, oracle_fn, K=103)
    print(f"\nResult: {long_to_bytes(result) if result else None}")
    print(f"Queries: {q}, success: {result == m}")
