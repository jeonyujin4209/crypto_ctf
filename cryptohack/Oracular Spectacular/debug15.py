"""Bayesian approach: maintain posterior over 16 candidates."""

import random
import math
import numpy as np


def simulate_bayesian(budget, n_trials=20000):
    """
    Bayesian best-arm identification.
    Maintain log-odds for each candidate being the "correct" one.
    Use uniform allocation for simplicity.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        # Log posterior ratios: start at 0 (uniform prior)
        log_odds = [0.0] * 16  # log P(correct) / P(wrong) for each candidate
        used = 0

        q_per = budget // 16
        for idx in range(16):
            for _ in range(q_per):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p

                # Update: if result=True
                # log_odds[idx] += log(P(True|idx correct) / P(True|idx wrong))
                # P(True|correct) = 0.4, P(True|wrong) = 0.6
                if result:
                    log_odds[idx] += math.log(0.4 / 0.6)  # negative
                else:
                    log_odds[idx] += math.log(0.6 / 0.4)  # positive

        best = max(range(16), key=lambda i: log_odds[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_bayesian_adaptive(budget, n_trials=20000):
    """
    Adaptive Bayesian: query the most uncertain candidate.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        log_odds = [0.0] * 16
        counts = [0] * 16
        used = 0

        # Initial: 3 queries per candidate
        for idx in range(16):
            for _ in range(3):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                if result:
                    log_odds[idx] += math.log(0.4 / 0.6)
                else:
                    log_odds[idx] += math.log(0.6 / 0.4)
                counts[idx] += 1
                used += 1

        # Adaptive phase: query the candidate that's closest to 0 (most uncertain)
        while used < budget:
            # Find the candidate closest to decision boundary
            # Actually, better: query top 2 candidates
            sorted_idx = sorted(range(16), key=lambda i: log_odds[i], reverse=True)
            # Query top candidate and runner-up
            for target in [sorted_idx[0], sorted_idx[1]]:
                if used >= budget:
                    break
                p = 0.4 if target == true_idx else 0.6
                result = random.random() < p
                if result:
                    log_odds[target] += math.log(0.4 / 0.6)
                else:
                    log_odds[target] += math.log(0.6 / 0.4)
                counts[target] += 1
                used += 1

        best = max(range(16), key=lambda i: log_odds[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_sequential_halving_bayesian(budget, n_trials=20000):
    """
    Combine: sequential halving for elimination, Bayesian scoring.
    Same as before but using log-likelihood ratio for ranking.
    """
    correct = 0

    for _ in range(n_trials):
        true_idx = 0
        log_odds = [0.0] * 16
        used = 0
        active = list(range(16))

        n_rounds = 4
        keeps = [8, 4, 2, 1]

        for rnd in range(n_rounds):
            n_active = len(active)
            q_per = max(1, (budget // n_rounds) // n_active)

            for idx in active:
                for _ in range(q_per):
                    if used >= budget:
                        break
                    p = 0.4 if idx == true_idx else 0.6
                    result = random.random() < p
                    if result:
                        log_odds[idx] += math.log(0.4 / 0.6)
                    else:
                        log_odds[idx] += math.log(0.6 / 0.4)
                    used += 1

            active.sort(key=lambda i: log_odds[i], reverse=True)
            active = active[:keeps[rnd]]

        # Final queries on winner
        while used < budget:
            idx = active[0]
            p = 0.4 if idx == true_idx else 0.6
            result = random.random() < p
            if result:
                log_odds[idx] += math.log(0.4 / 0.6)
            else:
                log_odds[idx] += math.log(0.6 / 0.4)
            used += 1

        best = max(active, key=lambda i: log_odds[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


def simulate_pure_bayesian_topk(budget, n_trials=20000):
    """
    Pure round-robin, then pick the one with highest log-odds.
    Same as uniform but uses LLR.
    """
    correct = 0
    log_p_ratio = math.log(0.4/0.6)  # -0.405

    for _ in range(n_trials):
        true_idx = 0
        llr = [0.0] * 16
        used = 0

        q_per = budget // 16
        for idx in range(16):
            for _ in range(q_per):
                p = 0.4 if idx == true_idx else 0.6
                result = random.random() < p
                llr[idx] += log_p_ratio if result else -log_p_ratio
                used += 1

        best = max(range(16), key=lambda i: llr[i])
        if best == true_idx:
            correct += 1

    return correct / n_trials


print("Comparison of algorithms:")
print("="*70)

for budget in [200, 370, 500, 750]:
    a1 = simulate_pure_bayesian_topk(budget)
    a2 = simulate_bayesian_adaptive(budget)
    a3 = simulate_sequential_halving_bayesian(budget)
    print(f"\nBudget={budget}:")
    print(f"  Uniform LLR:     {100*a1:.1f}% → P(32)={100*a1**32:.3f}%")
    print(f"  Adaptive Top2:   {100*a2:.1f}% → P(32)={100*a2**32:.3f}%")
    print(f"  SeqHalf+LLR:     {100*a3:.1f}% → P(32)={100*a3**32:.3f}%")
