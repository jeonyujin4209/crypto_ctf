"""Test adaptive top-3 vs top-2 at budget 375, simulation only."""

import random
import math

LOG_P = math.log(0.4/0.6)

def sim(budget, top_k=2, screen_q=2, n_trials=200000):
    correct = 0
    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        used = 0

        for idx in range(16):
            for _ in range(screen_q):
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                llr[idx] += LOG_P if r else -LOG_P
                used += 1

        while used < budget:
            sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
            for t in sorted_idx[:top_k]:
                if used >= budget:
                    break
                p = 0.4 if t == true_idx else 0.6
                r = random.random() < p
                llr[t] += LOG_P if r else -LOG_P
                used += 1

        best = max(range(16), key=lambda i: llr[i])
        if best == true_idx:
            correct += 1
    return correct / n_trials

print(f"Budget=375:")
for top_k in [2, 3, 4]:
    for sq in [2, 3, 4]:
        acc = sim(375, top_k, sq)
        print(f"  top-{top_k} sq={sq}: {100*acc:.2f}% -> P(32)={100*acc**32:.4f}%")
