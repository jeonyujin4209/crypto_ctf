# Generators of Groups (20pts)
## Starter

## Description
Every element of a finite field Fp\FpFp​ can be used to make a subgroup HHH under repeated action of multiplication. In other words, for an element ggg the subgroup H=⟨g⟩={g,g2,g3,…}H = \langle g \rangle = \{g, g^2, g^3, \ldots \}H=⟨g⟩={g,g2,g3,…}A primitive element of Fp\FpFp​ is an element whose subgroup H=Fp∗H = \Fp^*H=Fp∗​, i.e., every non-zero element of Fp\FpFp​, can be written as gnmod  pg^n \mod pgnmodp for some integer nnn. Because of this, primitive elements are sometimes called generators of the finite field.For the finite field with p=28151p = 28151p=28151 find the smallest element ggg which is a primitive element of Fp\FpFp​.This problem can be solved by brute-force, but there's also clever ways to speed up the calculation.
