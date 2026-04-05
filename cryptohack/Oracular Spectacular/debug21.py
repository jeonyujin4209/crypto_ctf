"""Verify: simulation vs reality for 3-CT consensus."""

import random
import math

LOG_P = math.log(0.4/0.6)


def sim_single_ct(budget, screen_q=2, top_k=2):
    """Simulate single CT best-arm identification."""
    true_idx = 0
    llr = [0.0] * 16
    used = 0

    sq = min(screen_q, budget // 16)
    for idx in range(16):
        for _ in range(sq):
            if used >= budget:
                break
            p = 0.4 if idx == true_idx else 0.6
            result = random.random() < p
            llr[idx] += LOG_P if result else -LOG_P
            used += 1

    while used < budget:
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for target_idx in sorted_idx[:top_k]:
            if used >= budget:
                break
            p = 0.4 if target_idx == true_idx else 0.6
            result = random.random() < p
            llr[target_idx] += LOG_P if result else -LOG_P
            used += 1

    best = max(range(16), key=lambda i: llr[i])
    return best == true_idx


def sim_consensus(budget_per_ct, n_cts, screen_q=2, top_k=2):
    """Simulate N-CT consensus."""
    true_idx = 0
    from collections import Counter
    votes = Counter()

    for _ in range(n_cts):
        llr = [0.0] * 16
        used = 0

        sq = min(screen_q, budget_per_ct // 16)
        for idx in range(16):
            for _ in range(sq):
                if used >= budget_per_ct:
                    break
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                llr[idx] += LOG_P if result else -LOG_P
                used += 1

        while used < budget_per_ct:
            sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
            for target_idx in sorted_idx[:top_k]:
                if used >= budget_per_ct:
                    break
                p = 0.4 if target_idx == true_idx else 0.6
                result = random.random() < p
                llr[target_idx] += LOG_P if result else -LOG_P
                used += 1

        best = max(range(16), key=lambda i: llr[i])
        votes[best] += 1

    final = votes.most_common(1)[0][0]
    return final == true_idx


# Run
n_trials = 100000

print("Single CT:")
for b in [125, 187, 250, 375]:
    correct = sum(sim_single_ct(b) for _ in range(n_trials))
    acc = correct / n_trials
    print(f"  Budget={b}: {100*acc:.1f}% → P(32)={100*acc**32:.3f}%")

print("\nConsensus:")
for n_cts in [3, 5, 7, 9, 11, 15, 21]:
    b = 375 // n_cts
    if b < 16:
        continue
    correct = sum(sim_consensus(b, n_cts) for _ in range(n_trials))
    acc = correct / n_trials
    print(f"  {n_cts} CTs × {b} = {n_cts*b}: {100*acc:.1f}% → P(32)={100*acc**32:.3f}%")

# What about POOLING across CTs: instead of voting, use ALL queries as if from same CT
print("\nPooled (as if single CT with combined budget):")
for n_cts in [3, 5, 7]:
    b_total = (375 // n_cts) * n_cts
    correct = sum(sim_single_ct(b_total) for _ in range(n_trials))
    acc = correct / n_trials
    print(f"  Budget={b_total}: {100*acc:.1f}% → P(32)={100*acc**32:.3f}%")
