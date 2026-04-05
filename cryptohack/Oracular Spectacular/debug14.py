"""Test adaptive strategies for best-arm identification with 16 arms."""

import random


def simulate_seqhalf_adaptive(budget, n_trials=20000):
    """Sequential halving with budget split evenly across rounds."""
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        scores = [0] * 16
        used = 0
        active = list(range(16))

        # Rounds: 16→8→4→2→1
        # 4 rounds, each gets budget/4
        n_rounds = 4
        round_budget = budget // n_rounds
        keeps = [8, 4, 2, 1]

        for rnd in range(n_rounds):
            n_active = len(active)
            q_per = round_budget // n_active

            for idx in active:
                for _ in range(q_per):
                    if used >= budget:
                        break
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    scores[idx] += (-1 if result else 1)
                    used += 1

            active.sort(key=lambda i: scores[i], reverse=True)
            if rnd < n_rounds - 1:
                active = active[:keeps[rnd]]

        best = max(active, key=lambda i: scores[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_seqhalf_optimal(budget, n_trials=20000):
    """
    Optimal sequential halving: budget proportional to log2 at each round.
    Each round uses budget/(num_rounds) queries, split evenly among active.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        scores = [0] * 16
        used = 0
        active = list(range(16))

        # ceil(log2(16)) = 4 rounds
        # Budget per round = budget / 4
        # Round i: n_i active arms, each gets (budget/4)/n_i queries
        n_rounds = 4
        keeps = [8, 4, 2, 1]

        for rnd in range(n_rounds):
            n_active = len(active)
            round_b = budget // n_rounds
            q_per = max(1, round_b // n_active)

            for idx in active:
                for _ in range(q_per):
                    if used >= budget:
                        break
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    scores[idx] += (-1 if result else 1)
                    used += 1

            active.sort(key=lambda i: scores[i], reverse=True)
            active = active[:keeps[rnd]]

        if used < budget:
            for idx in active:
                while used < budget:
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    scores[idx] += (-1 if result else 1)
                    used += 1

        best = max(active, key=lambda i: scores[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_uniform_then_verify(budget, n_trials=20000):
    """
    Uniform allocation across all 16, pick top 1.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        scores = [0] * 16
        q_per = budget // 16

        for idx in range(16):
            for _ in range(q_per):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                scores[idx] += (-1 if result else 1)

        best = max(range(16), key=lambda i: scores[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_track_and_stop(budget, n_trials=20000):
    """
    Query each candidate one at a time, round-robin.
    After each round, check if a candidate has a significant lead.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        scores = [0] * 16
        used = 0

        while used < budget:
            for idx in range(16):
                if used >= budget:
                    break
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                scores[idx] += (-1 if result else 1)
                used += 1

        best = max(range(16), key=lambda i: scores[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_lucb(budget, n_trials=20000):
    """
    LUCB-style: maintain upper/lower confidence bounds.
    Always query the candidate with highest UCB and the one with lowest LCB among rest.
    Simplified version.
    """
    import math
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        scores = [0.0] * 16
        counts = [0] * 16
        used = 0

        # Initial: 2 queries each
        for idx in range(16):
            for _ in range(2):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                scores[idx] += (-1 if result else 1)
                counts[idx] += 1
                used += 1

        while used < budget:
            # Query the empirically best candidate
            means = [scores[i]/counts[i] if counts[i] > 0 else 0 for i in range(16)]
            best = max(range(16), key=lambda i: means[i])

            p = 0.4 if best == true_idx else 0.6
            result = random.random() < p
            scores[best] += (-1 if result else 1)
            counts[best] += 1
            used += 1

            if used >= budget:
                break

            # Query the second-best (challenger)
            challenger = max((i for i in range(16) if i != best), key=lambda i: means[i])
            p = 0.4 if challenger == true_idx else 0.6
            result = random.random() < p
            scores[challenger] += (-1 if result else 1)
            counts[challenger] += 1
            used += 1

        means = [scores[i]/counts[i] if counts[i] > 0 else 0 for i in range(16)]
        best = max(range(16), key=lambda i: means[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


print("Best-arm identification: 16 arms, target p=0.4, rest p=0.6")
print("="*70)

for budget in [200, 370, 500, 750]:
    print(f"\nBudget = {budget}:")
    a1 = simulate_uniform_then_verify(budget)
    a2 = simulate_seqhalf_adaptive(budget)
    a3 = simulate_lucb(budget)
    print(f"  Uniform:      {100*a1:.1f}%  →  P(32)={100*a1**32:.2f}%")
    print(f"  SeqHalf:      {100*a2:.1f}%  →  P(32)={100*a2**32:.2f}%")
    print(f"  LUCB:         {100*a3:.1f}%  →  P(32)={100*a3**32:.2f}%")
