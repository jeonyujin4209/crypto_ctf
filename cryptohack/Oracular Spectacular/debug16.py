"""Test adaptive top-2 at different budgets, and multi-CT consensus."""

import random
import math


def simulate_adaptive_top2(budget, n_trials=50000):
    """Adaptive: 3 queries each to screen, then focus on top 2."""
    correct = 0
    log_p = math.log(0.4/0.6)

    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        counts = [0] * 16
        used = 0

        # Screen: 3 queries per candidate = 48 queries
        screen_q = 3
        for idx in range(16):
            for _ in range(screen_q):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                llr[idx] += log_p if result else -log_p
                counts[idx] += 1
                used += 1

        # Adaptive: always query the top 2
        while used < budget:
            sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
            for target in sorted_idx[:2]:
                if used >= budget:
                    break
                p = 0.4 if target == true_idx else 0.6
                result = random.random() < p
                llr[target] += log_p if result else -log_p
                counts[target] += 1
                used += 1

        best = max(range(16), key=lambda i: llr[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_consensus(budget_per_ct, n_cts, n_trials=50000):
    """Multi-CT consensus: run adaptive on each CT, majority vote."""
    correct = 0
    log_p = math.log(0.4/0.6)

    for _ in range(n_trials):
        true_idx = 0
        votes = [0] * 16

        for ct in range(n_cts):
            llr = [0.0] * 16
            counts = [0] * 16
            used = 0

            screen_q = 3
            for idx in range(16):
                for _ in range(screen_q):
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    llr[idx] += log_p if result else -log_p
                    counts[idx] += 1
                    used += 1

            while used < budget_per_ct:
                sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
                for target in sorted_idx[:2]:
                    if used >= budget_per_ct:
                        break
                    p = 0.4 if target == true_idx else 0.6
                    result = random.random() < p
                    llr[target] += log_p if result else -log_p
                    counts[target] += 1
                    used += 1

            best = max(range(16), key=lambda i: llr[i])
            votes[best] += 1

        final = max(range(16), key=lambda i: votes[i])
        if final == true_idx:
            correct += 1

    return correct / n_trials


print("Adaptive Top-2:")
for b in [75, 100, 125, 150, 187, 250, 370]:
    acc = simulate_adaptive_top2(b)
    print(f"  Budget={b:3d}: {100*acc:.1f}% → P(32)={100*acc**32:.3f}%")

print("\nMulti-CT Consensus (Adaptive Top-2 each):")
total_budget = 375  # per byte total

for n_cts in [1, 3, 5, 7, 9, 11]:
    b_per_ct = total_budget // n_cts
    acc = simulate_consensus(b_per_ct, n_cts)
    print(f"  {n_cts} CTs × {b_per_ct} = {n_cts*b_per_ct}: {100*acc:.1f}% → P(32)={100*acc**32:.3f}%")
