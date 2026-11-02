"""Distinguishers against the OLD classic-GGH oblivious sampler (historical).

The removed `sample_oblivious_ggh` replaced B = U*R with a uniform matrix in
[-M, M], M = max|B|. This script re-measures why that was unsound: four
poly-time statistics separate real from oblivious keys with certainty.
The pk format itself (a trapdoor-defined basis) is what makes any such sampler
impossible; the project now ships the GGH-HNF variant instead
(tests/test_ggh_versions.py covers all three variants).

Run from the MODULAROT root:  .venv/bin/python scripts_verifica/verify_ggh_classic.py
Note: classic keygen with nguyen_fix needs dimension ~200 for sigma > 2.
"""
import math, secrets, statistics, struct, sys
from flint import fmpz_mat
from GGH_crypto import GGHCryptosystem

DIM, N_KEYS = 200, 5


def classic_pk_matrix(dim):
    """One classic keygen (as the old ggh_fo.gen did: nguyen_fix=True)."""
    ggh = GGHCryptosystem(dimension=dim, integer_sigma=True, nguyen_fix=True)
    return ggh.public_basis, int(ggh.sigma)


def uniform_like(B, n):
    """What the removed sampler produced: uniform entries in [-M, M]."""
    M = max(abs(int(B[i, j])) for i in range(n) for j in range(n)) or 1
    return fmpz_mat([[secrets.randbelow(2 * M + 1) - M for _ in range(n)]
                     for _ in range(n)])


def stats(B, n):
    ent = [int(B[i, j]) for i in range(n) for j in range(n)]
    M = max(abs(v) for v in ent)
    d = abs(int(B.det()))
    rows = [math.sqrt(sum(int(B[i, j]) ** 2 for j in range(n))) for i in range(n)]
    return dict(M=M,
                mean_abs=statistics.fmean(abs(v) for v in ent),
                frac_big=sum(1 for v in ent if abs(v) > M / 2) / len(ent),
                log2det=math.log2(d) if d else float("-inf"),
                rownorm=statistics.fmean(rows))


real_s, obl_s, sigmas = [], [], set()
for i in range(N_KEYS):
    B, sigma = classic_pk_matrix(DIM)
    sigmas.add(sigma)
    rs, os_ = stats(B, DIM), stats(uniform_like(B, DIM), DIM)
    real_s.append(rs); obl_s.append(os_)
    print(f"key {i}: REAL  mean|e|/M={rs['mean_abs']/rs['M']:.4f} "
          f"frac>M/2={rs['frac_big']:.4f} log2|det|={rs['log2det']:8.1f}")
    print(f"       OBLIV mean|e|/M={os_['mean_abs']/os_['M']:.4f} "
          f"frac>M/2={os_['frac_big']:.4f} log2|det|={os_['log2det']:8.1f}")

k = 4 * math.ceil(math.sqrt(DIM) + 1)
print(f"\nsigma across keys: {sigmas} | theory log2|det| = n*log2(k) = "
      f"{DIM * math.log2(k):.1f} bits (k={k})")

perfect = True
for name, key in [("mean|entry|", "mean_abs"), ("log2|det|", "log2det"),
                  ("row norm", "rownorm"), ("frac>M/2", "frac_big")]:
    rv = [s[key] for s in real_s]; ov = [s[key] for s in obl_s]
    sep = max(rv) < min(ov)
    perfect &= sep
    print(f"[{name:12s}] real [{min(rv):.3g}, {max(rv):.3g}] vs "
          f"oblivious [{min(ov):.3g}, {max(ov):.3g}] -> "
          f"{'PERFECT separation' if sep else 'overlap'}")

print("\nCONCLUSION: classic GGH pk format admits no oblivious sampler"
      if perfect else "\nUNEXPECTED: separation not perfect on this run")
sys.exit(0 if perfect else 1)
