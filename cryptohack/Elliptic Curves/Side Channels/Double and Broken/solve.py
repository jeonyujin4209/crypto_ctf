"""
Double and Broken — recover secp256k1 private key from side-channel traces
of a right-to-left double-and-add implementation.

Each of the 50 traces has 359 power samples, one per scalar-bit iteration
(i = 0 ... 358 from LSB). A sample corresponds to a doubling plus an
optional add (when bit_i = 1). Averaging across the 50 traces gives two
clearly-separated clusters (gap of ~33 between means), so a single threshold
recovers every bit of the scalar `d`.

Because the loop is right-to-left, sample index i maps directly to bit i
of d. The scalar is the flag bytes_to_long, so reconstructing d gives us
the flag.
"""

import json
import statistics
from Crypto.Util.number import long_to_bytes

with open('collected_data.txt') as f:
    traces = json.load(f)

assert len(traces) == 50
assert all(len(t) == 359 for t in traces)

# Average each sample position across the 50 repetitions
means = [statistics.mean(t[i] for t in traces) for i in range(359)]

# Find the gap separating the two clusters
sorted_means = sorted(means)
best = max(
    ((sorted_means[i + 1] - sorted_means[i], (sorted_means[i] + sorted_means[i + 1]) / 2)
     for i in range(len(sorted_means) - 1)),
    key=lambda x: x[0],
)
threshold = best[1]

# High mean -> double+add -> bit 1; low -> double only -> bit 0
bits = [1 if m > threshold else 0 for m in means]

# Right-to-left algorithm: sample index i corresponds to bit i of d.
d = 0
for i, b in enumerate(bits):
    if b:
        d |= 1 << i

flag = long_to_bytes(d)
print('d =', hex(d))
print('flag:', flag.decode())
