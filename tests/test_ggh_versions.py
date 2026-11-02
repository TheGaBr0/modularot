"""
The three GGH variants, side by side — why only one of them can back the OT.

  V1  GGH classic (pk = basis B = U·R)          -> NO oblivious sampler exists:
      the pk is a *basis* whose distribution is defined by the trapdoor.
      log2|det B| = n·log2(k) exactly, while any trapdoor-free sample has a
      wildly different determinant; entry stats separate too. Demonstrated
      with perfect single-key separation below.

  V2  GGH-HNF, GGH_private=False               -> the KEM itself is void:
      the private basis is LLL(uniform matrix), but LLL is basis-independent
      at lattice level, so LLL(public HNF) hands ANYONE an equally good
      basis. Public trapdoor, no sender privacy possible.

  V3  GGH-HNF, GGH_private=True (modularot.custom_kems.ggh_fo)  -> sound:
      planted basis R = kI + E is a real secret; pk = HNF(L) is canonical, so
      it reveals only det/cokernel/reduced entries, all reproduced exactly by
      the discarded-draw oblivious sampler. Receiver privacy reduces to a
      planted-short-basis decisional assumption (unproven, but the same shape
      as M-LWE/NTRU — not provably false like V1).

Run:  python tests/test_ggh_versions.py       (~1-2 min)
"""

import math
import secrets
import statistics
import sys

from flint import fmpz_mat

from GGH_crypto import GGHCryptosystem, GGHHNFCryptosystem
from modularot.custom_kems.ggh_fo import ggh_fo
from modularot.oblivious_sampling import sample_oblivious_ggh_hnf
from modularot.kem_adapter.adapter import KEMAdapter
from modularot.ot_protocol import run_ot

FAILURES = []


def check(name: str, ok: bool, detail: str = ""):
    print(f"  {'✓ PASS' if ok else '✗ FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES.append(name)


def log2_abs_det(M: fmpz_mat) -> float:
    d = abs(int(M.det()))
    return math.log2(d) if d else float("-inf")


def matrix_stats(entries):
    M = max(abs(v) for v in entries)
    return {
        "M": M,
        "mean_abs": statistics.fmean(abs(v) for v in entries),
        "frac_big": sum(1 for v in entries if abs(v) > M / 2) / len(entries),
    }


def min_gs_norm(B: fmpz_mat, n: int) -> float:
    """Minimum Gram-Schmidt norm — the figure of merit of a decryption basis."""
    A = [[float(B[i, j]) for j in range(n)] for i in range(n)]
    ortho = []
    for v in A:
        w = list(v)
        for q in ortho:
            qq = sum(x * x for x in q)
            mu = sum(a * b for a, b in zip(v, q)) / qq
            w = [a - mu * b for a, b in zip(w, q)]
        ortho.append(w)
    return min(math.sqrt(sum(x * x for x in q)) for q in ortho)


# ═════ V1 — GGH classic: the basis format admits no oblivious sampler ═════════

def test_v1_classic_distinguishable(n=300):
    print("\n" + "=" * 78)
    print(f"V1  GGH classic (B = U·R, dim {n}): pk format unsound for oblivious sampling")
    print("=" * 78)

    k = 4 * math.ceil(math.sqrt(n) + 1)
    expected_bits = n * math.log2(k)

    ggh = GGHCryptosystem(dimension=n)          # classic keygen, B = U·R
    B = ggh.public_basis
    real_entries = [int(B[i, j]) for i in range(n) for j in range(n)]
    rs = matrix_stats(real_entries)
    real_det = log2_abs_det(B)

    # the best a trapdoor-free sampler can do in this format: uniform entries
    # with the same range (this is what the removed sample_oblivious_ggh did)
    M = rs["M"]
    fake_entries = [secrets.randbelow(2 * M + 1) - M for _ in range(n * n)]
    fake = fmpz_mat([[fake_entries[i * n + j] for j in range(n)] for i in range(n)])
    fs = matrix_stats(fake_entries)
    fake_det = log2_abs_det(fake)

    print(f"  log2|det|: real {real_det:.1f} (theory n·log2(k) = {expected_bits:.1f}) "
          f"vs uniform sample {fake_det:.1f}")
    print(f"  mean|entry|/M: real {rs['mean_abs']/M:.4f} vs uniform {fs['mean_abs']/M:.4f}")
    print(f"  frac(|entry|>M/2): real {rs['frac_big']:.4f} vs uniform {fs['frac_big']:.4f}")

    check("det invariant pins the real key (within 2 bits of n·log2 k)",
          abs(real_det - expected_bits) < 2)
    check("det separates real from sampled with huge margin",
          fake_det - real_det > n)          # thousands of bits apart in practice
    check("entry marginals separate too (frac>M/2: ~0 vs ~1/2)",
          rs["frac_big"] < 0.05 < 0.4 < fs["frac_big"])
    print("  -> a poly-time sender reads the choice bit with certainty: REFUSED.")


# ═════ V2 — GGH-HNF with GGH_private=False: public trapdoor ══════════════════

def test_v2_hnf_lll_public_trapdoor(n=300):
    print("\n" + "=" * 78)
    print(f"V2  GGH-HNF, GGH_private=False (dim {n}): the trapdoor is public")
    print("=" * 78)

    ggh = GGHHNFCryptosystem(dimension=n)       # private basis = LLL(uniform)
    R_priv = ggh.private_basis
    H_pub = ggh.public_basis

    g_priv = min_gs_norm(R_priv, n)
    g_atk = min_gs_norm(H_pub.lll(), n)         # anyone can do this to the pk

    print(f"  min Gram-Schmidt norm: private basis {g_priv:.1f} "
          f"vs attacker LLL(H_pub) {g_atk:.1f}")
    check("attacker basis decrypts as well as the private one (>= 0.5x quality)",
          g_atk >= 0.5 * g_priv, f"{g_atk:.1f} vs {g_priv:.1f}")
    print("  -> anyone decrypts both OT branches: no sender privacy. REFUSED.")


# ═════ V3 — GGH-HNF with GGH_private=True: the sound construction ════════════

def _hnf_pk_stats(pk: bytes):
    n, diag, cols, _ = ggh_fo._des_pk(pk)
    residues = [v / diag[i] for i in cols for v in cols[i] if diag[i] > (1 << 20)]
    log2det = sum(math.log2(d) for d in diag if d > 1)
    nontrivial = sum(1 for d in diag if d != 1)
    return log2det, nontrivial, residues


def _chi2_uniform(pool, nb=16):
    exp = len(pool) / nb
    counts = [0] * nb
    for x in pool:
        counts[min(int(x * nb), nb - 1)] += 1
    return sum((c - exp) ** 2 / exp for c in counts)


def test_v3_hnf_private_kem(n=300, rounds=10):
    print("\n" + "=" * 78)
    print(f"V3  GGH-HNF, GGH_private=True (dim {n}): KEM correctness + FO")
    print("=" * 78)

    pk, sk = ggh_fo.gen(dimension=n)
    ok = True
    for _ in range(rounds):
        ss_a, ct = ggh_fo.encaps(pk)
        ok &= ggh_fo.decaps(sk, ct) == ss_a
    check(f"KEM roundtrip x{rounds} (zero decryption failures by construction)", ok)

    ss_a, ct = ggh_fo.encaps(pk)
    bad = bytearray(ct)
    bad[len(bad) // 2] ^= 0x01
    r1, r2 = ggh_fo.decaps(sk, bytes(bad)), ggh_fo.decaps(sk, bytes(bad))
    check("tampered ct -> implicit rejection (ss differs from honest one)", r1 != ss_a)
    check("implicit rejection is deterministic", r1 == r2)
    check("truncated ct -> clean rejection, no crash",
          ggh_fo.decaps(sk, ct[:-3]) not in (ss_a, None))


def test_v3_oblivious_sampler(n=300, keys=10):
    print("\n" + "=" * 78)
    print(f"V3  GGH-HNF oblivious sampler ({keys} real vs {keys} oblivious keys, dim {n})")
    print("=" * 78)

    template_pk, _ = ggh_fo.gen(dimension=n)

    real, obl = [], []
    for _ in range(keys):
        real.append(_hnf_pk_stats(ggh_fo.gen(dimension=n)[0]))
        obl.append(_hnf_pk_stats(sample_oblivious_ggh_hnf(template_pk)))

    r_det = [x[0] for x in real]
    o_det = [x[0] for x in obl]
    r_res = [v for x in real for v in x[2]]
    o_res = [v for x in obl for v in x[2]]
    c_r, c_o = _chi2_uniform(r_res), _chi2_uniform(o_res)

    print(f"  log2(det): real [{min(r_det):.1f}, {max(r_det):.1f}] "
          f"vs oblivious [{min(o_det):.1f}, {max(o_det):.1f}]  (same law by construction)")
    print(f"  nontrivial diag entries: real {sorted(x[1] for x in real)} "
          f"vs oblivious {sorted(x[1] for x in obl)}")
    print(f"  dense-column residues chi2 (df=15, 99.9% crit 37.7): "
          f"real {c_r:.1f}, oblivious {c_o:.1f}  (n={len(r_res)}/{len(o_res)})")

    check("det ranges overlap (no det distinguisher, unlike V1)",
          min(o_det) <= max(r_det) and min(r_det) <= max(o_det))
    check("real dense-column residues consistent with uniform", c_r < 37.7, f"chi2={c_r:.1f}")
    check("oblivious dense-column residues consistent with uniform", c_o < 37.7, f"chi2={c_o:.1f}")

    ss, _ct = ggh_fo.encaps(sample_oblivious_ggh_hnf(template_pk))
    check("encaps accepts an oblivious pk", len(ss) == 32)


def test_v3_ot_end_to_end(n_dim=300):
    print("\n" + "=" * 78)
    print(f"V3  full 1-out-of-n OT over GGH_FO-{n_dim}")
    print("=" * 78)

    def factory():
        return KEMAdapter(
            gen=lambda: ggh_fo.gen(dimension=n_dim),
            encap=ggh_fo.encaps,
            decap=ggh_fo.decaps,
        )

    for n_branches, choice in ((2, 1), (4, 2)):
        r = run_ot(factory, sample_oblivious_ggh_hnf, f"GGH_FO-{n_dim}",
                   choice=choice, n=n_branches, check_security=True, verbose=False)
        check(f"1-out-of-{n_branches} OT correct (receiver gets m_{choice})", r["ok"])
        check(f"1-out-of-{n_branches} OT sender-private (other branches unreadable)",
              r["secure"])


if __name__ == "__main__":
    test_v1_classic_distinguishable()
    test_v2_hnf_lll_public_trapdoor()
    test_v3_hnf_private_kem()
    test_v3_oblivious_sampler()
    test_v3_ot_end_to_end()

    print("\n" + "=" * 78)
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}): " + "; ".join(FAILURES))
        sys.exit(1)
    print("ALL CHECKS PASSED — classic GGH refused, HNF+LLL refused, "
          "HNF+planted basis sound.")
