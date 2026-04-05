"""Compare ALL strategies at budget=375 with 100k trials."""

import random
import math

LOG_P = math.log(0.4/0.6)

def sim_uniform(budget):
    """Uniform allocation."""
    true_idx = 0
    scores = [0] * 16
    q_per = budget // 16
    for idx in range(16):
        for _ in range(q_per):
            p = 0.4 if idx == true_idx else 0.6
            r = random.random() < p
            scores[idx] += (-1 if r else 1)
    return max(range(16), key=lambda i: scores[i]) == true_idx


def sim_seqhalf(budget):
    """Sequential halving: 16→8→4→2→1."""
    true_idx = 0
    scores = [0] * 16
    active = list(range(16))
    used = 0

    n_rounds = 4
    keeps = [8, 4, 2, 1]

    for rnd in range(n_rounds):
        n_a = len(active)
        q_per = max(1, (budget // n_rounds) // n_a)

        for idx in active:
            for _ in range(q_per):
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                scores[idx] += (-1 if r else 1)
                used += 1

        active.sort(key=lambda i: scores[i], reverse=True)
        active = active[:keeps[rnd]]

    while used < budget:
        for idx in active:
            if used >= budget:
                break
            p = 0.4 if idx == true_idx else 0.6
            r = random.random() < p
            scores[idx] += (-1 if r else 1)
            used += 1

    return max(active, key=lambda i: scores[i]) == true_idx


def sim_adaptive_top2(budget, screen_q=2):
    """Adaptive top-2."""
    true_idx = 0
    llr = [0.0] * 16
    used = 0

    sq = min(screen_q, budget // 16)
    for idx in range(16):
        for _ in range(sq):
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

    return max(range(16), key=lambda i: llr[i]) == true_idx


def sim_adaptive_rescreen(budget, screen_q=2, rescreen_interval=30):
    """Adaptive with periodic re-screening."""
    true_idx = 0
    llr = [0.0] * 16
    counts = [0] * 16
    used = 0

    # Initial screen
    sq = min(screen_q, budget // 16)
    for idx in range(16):
        for _ in range(sq):
            p = 0.4 if idx == true_idx else 0.6
            r = random.random() < p
            llr[idx] += LOG_P if r else -LOG_P
            counts[idx] += 1
            used += 1

    last_rescreen = used

    while used < budget:
        # Re-screen periodically: give 1 query to every candidate
        if used - last_rescreen >= rescreen_interval:
            for idx in range(16):
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                r = random.random() < p
                llr[idx] += LOG_P if r else -LOG_P
                counts[idx] += 1
                used += 1
            last_rescreen = used

        # Focus on top 2
        sorted_idx = sorted(range(16), key=lambda i: llr[i], reverse=True)
        for t in sorted_idx[:2]:
            if used >= budget:
                break
            p = 0.4 if t == true_idx else 0.6
            r = random.random() < p
            llr[t] += LOG_P if r else -LOG_P
            counts[t] += 1
            used += 1

    return max(range(16), key=lambda i: llr[i]) == true_idx


def sim_track_all(budget):
    """Track and stop: round-robin with early termination for confident answers."""
    true_idx = 0
    llr = [0.0] * 16
    used = 0

    # Round-robin
    while used < budget:
        for idx in range(16):
            if used >= budget:
                break
            p = 0.4 if idx == true_idx else 0.6
            r = random.random() < p
            llr[idx] += LOG_P if r else -LOG_P
            used += 1

    return max(range(16), key=lambda i: llr[i]) == true_idx


def sim_successive_elim(budget):
    """Successive elimination: round-robin, eliminate candidates below threshold."""
    true_idx = 0
    llr = [0.0] * 16
    counts = [0] * 16
    used = 0
    active = set(range(16))

    while used < budget and len(active) > 1:
        for idx in list(active):
            if used >= budget or len(active) <= 1:
                break
            p = 0.4 if idx == true_idx else 0.6
            r = random.random() < p
            llr[idx] += LOG_P if r else -LOG_P
            counts[idx] += 1
            used += 1

        # Eliminate: remove candidates that are significantly worse than best
        if len(active) > 1:
            best_llr = max(llr[i] for i in active)
            min_count = min(counts[i] for i in active)
            # Threshold: sqrt(2 * log(K) * count) where K=16
            if min_count > 0:
                threshold = math.sqrt(2 * math.log(16) * min_count) * 0.5
                to_remove = {i for i in active if best_llr - llr[i] > threshold}
                active -= to_remove

    if len(active) == 1:
        return list(active)[0] == true_idx
    return max(active, key=lambda i: llr[i]) == true_idx


n_trials = 100000
budget = 375

print(f"Budget = {budget}, N_trials = {n_trials}")
print(f"{'Method':30s} {'Accuracy':>10s} {'P(32)':>10s}")

for name, func in [
    ("Uniform", lambda: sim_uniform(budget)),
    ("SeqHalf", lambda: sim_seqhalf(budget)),
    ("Adaptive Top-2 (sq=2)", lambda: sim_adaptive_top2(budget, 2)),
    ("Adaptive Top-2 (sq=3)", lambda: sim_adaptive_top2(budget, 3)),
    ("Adaptive Top-2 (sq=5)", lambda: sim_adaptive_top2(budget, 5)),
    ("Adaptive+Rescreen(30)", lambda: sim_adaptive_rescreen(budget, 2, 30)),
    ("Adaptive+Rescreen(50)", lambda: sim_adaptive_rescreen(budget, 2, 50)),
    ("Round-Robin", lambda: sim_track_all(budget)),
    ("Successive Elim", lambda: sim_successive_elim(budget)),
]:
    correct = sum(func() for _ in range(n_trials))
    acc = correct / n_trials
    print(f"  {name:30s} {100*acc:8.1f}%  {100*acc**32:8.3f}%")
