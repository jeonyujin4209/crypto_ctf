"""Pure simulation: identify which of 16 biased coins has p=0.4 (rest have p=0.6)."""

import random
import numpy as np

def simulate_single(budget, n_trials=10000):
    """Simulate identifying the p=0.4 coin among 16 coins with p=0.6."""
    correct = 0

    for _ in range(n_trials):
        # 16 coins: coin 0 has p=0.4, rest have p=0.6
        true_idx = 0
        scores = [0] * 16
        used = 0
        active = list(range(16))

        # Sequential halving: b=10 per round
        b = 10
        for keep in [8, 4, 2]:
            for idx in active:
                for _ in range(b):
                    if used >= budget:
                        break
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    scores[idx] += (-1 if result else 1)
                    used += 1
            active.sort(key=lambda i: scores[i], reverse=True)
            active = active[:keep]

        # Final duel
        while used < budget:
            for idx in active:
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                scores[idx] += (-1 if result else 1)
                used += 1

        best = max(active, key=lambda i: scores[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


# Test different budgets
for budget in [100, 150, 200, 250, 300, 370, 500, 750, 1000]:
    acc = simulate_single(budget, 20000)
    p32 = acc**32
    print(f"Budget={budget:4d}: accuracy={100*acc:.1f}% → P(32 correct)={100*p32:.2f}%")
