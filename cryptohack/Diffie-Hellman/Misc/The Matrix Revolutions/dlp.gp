\\ DLP solver via PARI/GP for Matrix Revolutions
\\ Reads min_poly factors and target polys from input.gp, computes the
\\ discrete logs in GF(2^61) and GF(2^89), then writes A_priv to output.txt.

default(parisize, 4000000000);
read("input.gp");

\\ Build the field GF(2^d) using f_d as the modulus
\\ pari ffgen requires an irreducible polynomial; we use the factors directly.

f61m = Mod(f61, 2);
f89m = Mod(f89, 2);

print("Constructing GF(2^61)...");
F61 = ffgen(f61m, t);
print("Constructing GF(2^89)...");
F89 = ffgen(f89m, t);

\\ Reduce A_poly mod f61 → an element of GF(2^61)
print("Reducing A_poly mod f61...");
A_red61 = subst(Mod(A_poly, 2), x, F61);
print("A_red61 = ", A_red61);

print("Solving DLP in GF(2^61)...");
A_priv_mod_61 = fflog(A_red61, F61);
print("A_priv mod (2^61-1) = ", A_priv_mod_61);

print("Reducing A_poly mod f89...");
A_red89 = subst(Mod(A_poly, 2), x, F89);
print("A_red89 = ", A_red89);

print("Solving DLP in GF(2^89)...");
A_priv_mod_89 = fflog(A_red89, F89);
print("A_priv mod (2^89-1) = ", A_priv_mod_89);

\\ CRT
print("CRT...");
A_priv = chinese(Mod(A_priv_mod_61, 2^61 - 1), Mod(A_priv_mod_89, 2^89 - 1));
print("A_priv = ", lift(A_priv));

\\ Write to file (overwrite)
system("rm -f output.txt");
write("output.txt", lift(A_priv));
