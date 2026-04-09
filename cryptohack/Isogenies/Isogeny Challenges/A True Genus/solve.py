"""
A True Genus: SKIPPED.

This challenge is CSIDH-based. The group action `action(pub, priv)` in source.sage
computes a long sequence of small-degree isogenies over supersingular curves with
the specific prime p = 2 * prod(primes(3,112)) * 139 - 1. Solving it requires
implementing CSIDH group action + class group discrete log (a "genus" / form-class
pairing attack is hinted at by the name "A True Genus"), which requires SageMath
and is not feasible in pure Python within this session.
"""
print("This challenge requires SageMath for CSIDH computations. Skipped.")
