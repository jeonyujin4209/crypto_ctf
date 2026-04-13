---
name: hamiltonicity-online-fs-grinding
description: Online Fiat-Shamir 시그마 프로토콜은 A 랜덤 재시도로 challenge=0 강제 가능. Batch FS에서는 불가
type: skill
---

# Hamiltonicity / Sigma Protocol — Online Fiat-Shamir Grinding

## When to use
- Multi-round sigma protocol converted to NIZK via Fiat-Shamir
- Server computes challenge ONLINE per round: `challenge_i = hash(A_i, FS_state_{i-1})[-1] & 1`
- You cannot produce a valid challenge=1 response (no Hamiltonian cycle / no witness)
- Goal: force challenge=0 every round

## The Vulnerability

When challenges are computed ONE AT A TIME (online FS), you can:
1. Try different random commitments A until the hash gives challenge=0
2. ~50% success rate per try → on average 2 tries per round

```python
while True:
    permutation = list(range(N))
    random.shuffle(permutation)
    G_perm = permute_graph(G, permutation)
    A, openings = commit_to_graph(G_perm)
    
    trial_state = hash_committed_graph(A, FS_state, comm_params)
    challenge = trial_state[-1] & 1
    
    if challenge == 0:
        break  # can answer this!

FS_state = trial_state
z = [permutation, openings]  # valid challenge=0 response
```

## Why it works

- challenge=0 response: reveal permutation + full NxN openings → always possible
- challenge=1 response: reveal Hamiltonian cycle → requires knowing one → skip
- With online FS, the hash for round i only depends on A_i and previous state → retrying A_i is undetectable

## z format (Pedersen commitment Hamiltonicity)

```python
# challenge=0: z = [permutation, openings]
#   permutation: list of N ints (perm indices)
#   openings: NxN list of [v, r] pairs

# challenge=1: z = [cycle_edges, r_vals]
#   cycle_edges: [[src,dst], ...] list of N edge pairs
#   r_vals: [r0, r1, ...] flat list of N integers (randomness for cycle edges)
```

## Contrast with Batch FS (Hamiltonicity 2)

- Batch FS: server collects ALL commitments first, then computes ALL challenges from final hash
- Cannot grind per-round: changing A_i affects ALL challenge bits simultaneously
- Requires a different attack (fixed-point search)

## Challenges
- CryptoHack Hamiltonicity 1 — `crypto{not_hashing_entire_statement_is_bad}`
