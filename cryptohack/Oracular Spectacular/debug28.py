"""Compare full Bayesian approach vs adaptive top-2 in simulation."""

import random
import math

LOG_P = math.log(0.4/0.6)
LV_T = math.log(0.4)
LV_F = math.log(0.6)
LI_T = math.log(0.6)
LI_F = math.log(0.4)

def sim_adaptive_top2(budget, n_trials=200000):
    correct = 0
    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        used = 0

        for idx in range(16):
            for _ in range(2):
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


def sim_bayesian_rr(budget, n_trials=200000):
    """Full Bayesian with round-robin queries over active set.
    Matches the existing solve.py's approach."""
    correct = 0
    for _ in range(n_trials):
        true_idx = 0
        log_p = [0.0] * 16
        active = list(range(16))
        used = 0

        # Phase 1: 5 rounds over 16 -> keep 8
        for _ in range(5):
            for idx in active:
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
                used += 1

        active = sorted(active, key=lambda i: log_p[i], reverse=True)[:8]

        # Phase 2: 6 rounds over 8 -> keep 4
        for _ in range(6):
            for idx in active:
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
                used += 1

        active = sorted(active, key=lambda i: log_p[i], reverse=True)[:4]

        # Phase 3: 35 rounds over 4 -> keep 2
        for _ in range(35):
            for idx in active:
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
                used += 1

        active = sorted(active, key=lambda i: log_p[i], reverse=True)[:2]

        # Phase 4: duel
        remaining = budget - used
        duel_rounds = max(1, remaining // 2)
        for _ in range(duel_rounds):
            for idx in active:
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
                used += 1

        best = max(active, key=lambda i: log_p[i])
        if best == true_idx:
            correct += 1
    return correct / n_trials


def sim_bayesian_adaptive(budget, n_trials=200000):
    """Bayesian update + adaptive top-2 querying (combines both approaches)."""
    correct = 0
    for _ in range(n_trials):
        true_idx = 0
        log_p = [0.0] * 16
        active = list(range(16))
        used = 0

        # Screen: 2 queries per candidate
        for idx in range(16):
            for _ in range(2):
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[idx] += LV_T
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_T
                else:
                    log_p[idx] += LV_F
                    for j in active:
                        if j != idx:
                            log_p[j] += LI_F
                used += 1

        # Adaptive top-2 with Bayesian update
        while used < budget:
            sorted_idx = sorted(active, key=lambda i: log_p[i], reverse=True)
            for t in sorted_idx[:2]:
                if used >= budget:
                    break
                p = 0.4 if t == true_idx else 0.6
                r = random.random() < p
                if r:
                    log_p[t] += LV_T
                    for j in active:
                        if j != t:
                            log_p[j] += LI_T
                else:
                    log_p[t] += LV_F
                    for j in active:
                        if j != t:
                            log_p[j] += LI_F
                used += 1

        best = max(active, key=lambda i: log_p[i])
        if best == true_idx:
            correct += 1
    return correct / n_trials


budget = 375
a1 = sim_adaptive_top2(budget)
a2 = sim_bayesian_rr(budget)
a3 = sim_bayesian_adaptive(budget)

print(f"Budget={budget}:")
print(f"  Adaptive top-2:        {100*a1:.2f}% -> P(32)={100*a1**32:.4f}%")
print(f"  Bayesian RR (solve.py):{100*a2:.2f}% -> P(32)={100*a2**32:.4f}%")
print(f"  Bayesian + adaptive:   {100*a3:.2f}% -> P(32)={100*a3**32:.4f}%")
