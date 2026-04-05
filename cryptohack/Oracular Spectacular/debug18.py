"""
Test LLR aggregation across CTs instead of voting.
For each CT, instead of picking best candidate, maintain LLR scores for all 16 hex chars.
Then sum LLR across CTs and pick the hex char with highest total LLR.
"""

import random
import math


def simulate_llr_aggregate(budget_per_ct, n_cts, screen_q=2, n_trials=100000):
    """
    For each CT: screen all 16, then focus on top-2 (adaptive).
    After all CTs done, aggregate LLR scores across CTs for each hex char candidate.
    Pick the one with highest total LLR.
    """
    correct = 0
    log_p = math.log(0.4/0.6)

    for _ in range(n_trials):
        true_idx = 0
        # Accumulate LLR across all CTs
        total_llr = [0.0] * 16

        for ct in range(n_cts):
            llr = [0.0] * 16
            used = 0

            # Screen
            sq = min(screen_q, max(1, budget_per_ct // 16))
            for idx in range(16):
                for _ in range(sq):
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    llr[idx] += log_p if result else -log_p
                    used += 1

            # Adaptive top-2
            while used < budget_per_ct:
                sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
                for target in sorted_idx[:2]:
                    if used >= budget_per_ct:
                        break
                    p = 0.4 if target == true_idx else 0.6
                    result = random.random() < p
                    llr[target] += log_p if result else -log_p
                    used += 1

            # Add to total LLR
            for idx in range(16):
                total_llr[idx] += llr[idx]

        final = max(range(16), key=lambda i: total_llr[i])
        if final == true_idx:
            correct += 1

    return correct / n_trials


def simulate_vote(budget_per_ct, n_cts, screen_q=2, n_trials=100000):
    """Standard majority vote."""
    correct = 0
    log_p = math.log(0.4/0.6)

    for _ in range(n_trials):
        true_idx = 0
        votes = [0] * 16

        for ct in range(n_cts):
            llr = [0.0] * 16
            used = 0

            sq = min(screen_q, max(1, budget_per_ct // 16))
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
print("Method      N_CTs  Budget  Accuracy  P(32)")

for n_cts in [1, 3, 5, 7, 9, 11, 15, 21, 31]:
    b = total // n_cts
    if b < 16:  # need at least 1 query per candidate
        continue
    sq = min(2, b // 16)
    if sq < 1:
        sq = 1

    acc_vote = simulate_vote(b, n_cts, sq)
    acc_llr = simulate_llr_aggregate(b, n_cts, sq)
    print(f"  Vote     {n_cts:2d}     {b:3d}     {100*acc_vote:.1f}%    {100*acc_vote**32:.2f}%")
    print(f"  LLR-Agg  {n_cts:2d}     {b:3d}     {100*acc_llr:.1f}%    {100*acc_llr**32:.2f}%")
