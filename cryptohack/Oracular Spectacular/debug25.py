"""Test hybrid: sequential halving to top 4, then adaptive top 2."""

import random
import math

LOG_P = math.log(0.4/0.6)

def sim_hybrid(budget, n_trials=100000):
    """SeqHalf 16→4, then adaptive top-2."""
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        used = 0

        # Phase 1: screen 16→4 using sequential halving
        # Give 12 queries each to all 16 = 192 queries
        for idx in range(16):
            for _ in range(12):
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                llr[idx] += LOG_P if r else -LOG_P
                used += 1

        # Keep top 4
        active = sorted(range(16), key=lambda i: llr[i], reverse=True)[:4]

        # Phase 2: adaptive top-2 among these 4
        while used < budget:
            sorted_active = sorted(active, key=lambda i: llr[i], reverse=True)
            for t in sorted_active[:2]:
                if used >= budget:
                    break
                p = 0.4 if t == true_idx else 0.6
                r = random.random() < p
                llr[t] += LOG_P if r else -LOG_P
                used += 1

        best = max(active, key=lambda i: llr[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def sim_three_phase(budget, n_trials=100000):
    """Screen 16→8, then 8→2, then final duel."""
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        used = 0

        # Phase 1: 6 queries each for 16 = 96
        for idx in range(16):
            for _ in range(6):
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                llr[idx] += LOG_P if r else -LOG_P
                used += 1

        active = sorted(range(16), key=lambda i: llr[i], reverse=True)[:8]

        # Phase 2: 10 more queries each for 8 = 80
        for idx in active:
            for _ in range(10):
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                llr[idx] += LOG_P if r else -LOG_P
                used += 1

        active = sorted(active, key=lambda i: llr[i], reverse=True)[:2]

        # Phase 3: remaining budget between top 2
        while used < budget:
            for t in active:
                if used >= budget:
                    break
                p = 0.4 if t == true_idx else 0.6
                r = random.random() < p
                llr[t] += LOG_P if r else -LOG_P
                used += 1

        best = max(active, key=lambda i: llr[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def sim_adaptive_top2(budget, screen_q=2, n_trials=100000):
    """Standard adaptive top-2."""
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
            for t in sorted_idx[:2]:
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


budget = 375

print(f"Budget={budget}")
a1 = sim_adaptive_top2(budget, 2)
a2 = sim_hybrid(budget)
a3 = sim_three_phase(budget)

print(f"  Adaptive top-2 (sq=2):  {100*a1:.1f}% → {100*a1**32:.3f}%")
print(f"  Hybrid (12q→4, top2):   {100*a2:.1f}% → {100*a2**32:.3f}%")
print(f"  Three-phase (6→8,10→2): {100*a3:.1f}% → {100*a3**32:.3f}%")

# Try more configurations
for sq1, keep1, sq2, keep2 in [
    (8, 4, 0, 2),    # 8q*16=128 → top 4, remaining 247 for top 2 adaptive
    (10, 4, 0, 2),   # 10q*16=160 → top 4, remaining 215 for top 2
    (6, 8, 12, 2),   # 6q*16=96 → top 8, 12q*8=96 → top 2, remaining 183 for duel
    (8, 8, 12, 2),   # 8q*16=128 → top 8, 12q*8=96 → top 2, remaining 151
    (5, 4, 10, 2),   # 5q*16=80 → top 4, 10q*4=40 → top 2, remaining 255
]:
    def make_sim(s1=sq1, k1=keep1, s2=sq2, k2=keep2):
        def sim(n_trials=100000):
            correct = 0
            for _ in range(n_trials):
                true_idx = 0
                llr = [0.0] * 16
                used = 0
                active = list(range(16))

                # Phase 1
                for idx in active:
                    for _ in range(s1):
                        if used >= budget: break
                        p = 0.4 if idx == true_idx else 0.6
                        r = random.random() < p
                        llr[idx] += LOG_P if r else -LOG_P
                        used += 1
                active = sorted(active, key=lambda i: llr[i], reverse=True)[:k1]

                # Phase 2 (if any)
                if s2 > 0:
                    for idx in active:
                        for _ in range(s2):
                            if used >= budget: break
                            p = 0.4 if idx == true_idx else 0.6
                            r = random.random() < p
                            llr[idx] += LOG_P if r else -LOG_P
                            used += 1
                    active = sorted(active, key=lambda i: llr[i], reverse=True)[:k2]

                # Final: adaptive between remaining
                while used < budget:
                    sorted_a = sorted(active, key=lambda i: llr[i], reverse=True)
                    for t in sorted_a[:2]:
                        if used >= budget: break
                        p = 0.4 if t == true_idx else 0.6
                        r = random.random() < p
                        llr[t] += LOG_P if r else -LOG_P
                        used += 1

                best = max(active, key=lambda i: llr[i])
                if best == true_idx:
                    correct += 1
            return correct / n_trials
        return sim

    acc = make_sim()()
    print(f"  [{sq1}q*16→{keep1}, {sq2}q*{keep1}→{keep2}]: {100*acc:.1f}% → {100*acc**32:.3f}%")
