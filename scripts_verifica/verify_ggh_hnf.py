"""Feasibility evidence for the GGH-HNF discarded-draw oblivious sampler.

This is the exploratory script that motivated the ggh_fo rewrite (the
maintained, assertive version of these checks lives in
tests/test_ggh_versions.py). It measures, against the planted keygen law
R = k*I + Uniform[-n, n-1] (k = n*ceil(sqrt(n)+1), the library's
GGH_private=True branch):

  T1. flint's .hnf() convention: row-style UPPER-triangular, diag > 0,
      above-diagonal entries reduced into [0, diag)
  T2. real HNF structure: diagonal almost all 1 with 1-3 nontrivial entries
      near the end; columns with diag 1 have all-zero off-diagonals
  T3. dense-column residues of REAL HNFs are ~uniform (chi-square), i.e. the
      sampler's exactly-uniform fill matches every cheap invariant
  T4. a vector reduced against an obliviously sampled H stays lattice-congruent
      (encryption functional against oblivious keys)
  T5. GGH_private=False is unusable: LLL(public HNF) is as good a decryption
      basis as the private one (public trapdoor)

Run from the MODULAROT root:  .venv/bin/python scripts_verifica/verify_ggh_hnf.py
"""
import math, random, sys
from flint import fmpz_mat, fmpq_mat

N, NKEYS = 40, 30


def keygen_R(n):
    l = n; k = l * math.ceil(math.sqrt(n) + 1)
    while True:
        R = fmpz_mat([[random.randint(-l, l - 1) for _ in range(n)] for _ in range(n)])
        for i in range(n):
            R[i, i] = int(R[i, i]) + k
        if R.det() != 0:
            return R


def sample_oblivious_hnf(n):
    """Discarded draw: keep only diag(HNF(R'')), fill reduced cells uniformly."""
    Hdd = keygen_R(n).hnf()
    diag = [int(Hdd[i, i]) for i in range(n)]
    H = fmpz_mat(n, n)
    for i in range(n):
        H[i, i] = diag[i]
        for k in range(i):
            if diag[i] > 1:
                H[k, i] = random.randrange(diag[i])
    return H


fails = []
def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not ok: fails.append(name)


# T1: flint HNF convention
H0, n0 = keygen_R(8).hnf(), 8
check("T1: flint HNF upper-triangular, diag>0, reduced into [0,diag)",
      all(int(H0[i, j]) == 0 for i in range(n0) for j in range(i))
      and all(int(H0[i, i]) > 0 for i in range(n0))
      and all(0 <= int(H0[k, i]) < int(H0[i, i]) for i in range(n0) for k in range(i)))

# T2/T3: structure + dense-column residue uniformity, real vs oblivious
def dense_residues(H, n, pool, thresh=1 << 20):
    for i in range(n):
        d = int(H[i, i])
        if d > thresh:
            for k in range(i):
                pool.append(int(H[k, i]) / d)

real_pool, obl_pool = [], []
zero_offdiag_ok, nontriv = True, []
for _ in range(NKEYS):
    H = keygen_R(N).hnf()
    nontriv.append(sum(1 for i in range(N) if int(H[i, i]) != 1))
    for i in range(N):
        if int(H[i, i]) == 1 and any(int(H[k, i]) for k in range(i)):
            zero_offdiag_ok = False
    dense_residues(H, N, real_pool)
    dense_residues(sample_oblivious_hnf(N), N, obl_pool)

check("T2: diag=1 columns have all-zero off-diagonals", zero_offdiag_ok)
print(f"     nontrivial diag entries per key: min={min(nontriv)} max={max(nontriv)}")

def chisq_uniform(pool, nb=16):
    exp = len(pool) / nb
    counts = [0] * nb
    for x in pool:
        counts[min(int(x * nb), nb - 1)] += 1
    return sum((c - exp) ** 2 / exp for c in counts)

c_r, c_o = chisq_uniform(real_pool), chisq_uniform(obl_pool)
check("T3: REAL dense-column residues ~ uniform (df=15, crit 37.7)",
      c_r < 37.7, f"chi2={c_r:.1f}, n={len(real_pool)}")
check("T3: OBLIV dense-column residues ~ uniform",
      c_o < 37.7, f"chi2={c_o:.1f}, n={len(obl_pool)}")

# T4: reduction against an oblivious H stays lattice-congruent
sys.path.insert(0, ".")
from modularot.custom_kems.ggh_fo import ggh_fo
Ho = sample_oblivious_hnf(N)
diag, cols = ggh_fo._hnf_to_diag_cols(Ho, N)
e = [random.randint(-3, 3) for _ in range(N)]
c = ggh_fo._reduce_mod_hnf(e, N, diag, cols)
diff = fmpq_mat(fmpz_mat([[a - b for a, b in zip(c, e)]]))
y = diff * fmpq_mat(Ho).inv()
check("T4: c - e in L(H_oblivious) and c in fundamental region",
      all(y[0, j].denom() == 1 for j in range(N))
      and all(0 <= c[i] < diag[i] for i in range(N)))

# T5: GGH_private=False -> public trapdoor
def min_gs_norm(B, n):
    A = [[float(B[i, j]) for j in range(n)] for i in range(n)]
    ortho = []
    for v in A:
        w = list(v)
        for q in ortho:
            mu = sum(a * b for a, b in zip(v, q)) / sum(x * x for x in q)
            w = [a - mu * b for a, b in zip(w, q)]
        ortho.append(w)
    return min(math.sqrt(sum(x * x for x in q)) for q in ortho)

M = fmpz_mat([[random.randint(-N, N - 1) for _ in range(N)] for _ in range(N)])
Rpriv = M.lll()
g_priv, g_atk = min_gs_norm(Rpriv, N), min_gs_norm(Rpriv.hnf().lll(), N)
check("T5: GGH_private=False has a PUBLIC trapdoor (attacker LLL(H) >= 0.5x private)",
      g_atk >= 0.5 * g_priv, f"attacker {g_atk:.1f} vs private {g_priv:.1f}")

print()
print("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}")
sys.exit(1 if fails else 0)
