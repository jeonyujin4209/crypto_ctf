"""Fine-tune the number of CTs and screening queries."""

import random
import math


def simulate_consensus_v2(budget_per_ct, n_cts, screen_q, n_trials=100000):
    """Multi-CT consensus with configurable screen queries."""
    correct = 0
    log_p = math.log(0.4/0.6)

    for _ in range(n_trials):
        true_idx = 0
        votes = [0] * 16

        for ct in range(n_cts):
            llr = [0.0] * 16
            used = 0

            sq = min(screen_q, budget_per_ct // 16)
            for idx in range(16):
                for _ in range(sq):
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    llr[idx] += log_p if result else -log_p
                    used += 1

            while used < budget_per_ct:
                sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
                for target in sorted_idx[:2]:
                    if used >= budget_per_ct:
                        break
                    p = 0.4 if target == true_idx else 0.6
                    result = random.random() < p
                    llr[target] += log_p if result else -log_p
                    used += 1

            best = max(range(16), key=lambda i: llr[i])
            votes[best] += 1

        final = max(range(16), key=lambda i: votes[i])
        if final == true_idx:
            correct += 1

    return correct / n_trials


total = 375

print("N_CTs  Budget  Screen  Accuracy  P(32)")
for n_cts in [3, 5, 7, 9, 11, 13, 15, 17, 21, 25]:
    b = total // n_cts
    if b < 20:
        continue
    for sq in [2, 3]:
        if sq * 16 > b:
            sq = 1
        acc = simulate_consensus_v2(b, n_cts, sq)
        print(f"  {n_cts:2d}     {b:3d}      {sq}     {100*acc:.1f}%    {100*acc**32:.2f}%")
