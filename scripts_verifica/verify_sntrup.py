"""Mathematical verification of the sntrup761 oblivious sampler.

Checks, against the NTRU Prime reference Decode (Bernstein et al., spec pseudocode)
and against real liboqs keys:
  A. Encode implementation == reference Encode (right inverse of reference Decode)
  B. Real liboqs pk decodes to p coefficients in [0, q) and re-encodes to the
     identical byte string  (=> the sampler uses the exact liboqs serialisation)
  C. Encode is injective and constant-length on [0,q)^p  (Decode∘Encode = id),
     so uniform coefficients => the exact pushforward distribution of a
     "uniform h" public key
  D. Oblivious pk: correct length, decodes in-range, accepted by liboqs encaps
  E. Coefficient marginals: chi-square sanity on both real and oblivious keys

Run from the MODULAROT root:  .venv/bin/python scripts_verifica/verify_sntrup.py
"""
import sys, os, secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modularot.oblivious_sampling import _ntruprime_encode, resolve_oqs
import oqs

P, Q = 761, 4591

# ---- reference Encode/Decode straight from the NTRU Prime spec --------------
def ref_Encode(R, M):
    if len(M) == 0: return []
    S = []
    if len(M) == 1:
        r, m = R[0], M[0]
        while m > 1:
            S += [r % 256]; r, m = r // 256, (m + 255) // 256
        return S
    R2, M2 = [], []
    for i in range(0, len(M) - 1, 2):
        m, r = M[i] * M[i + 1], R[i] + M[i] * R[i + 1]
        while m >= 16384:
            S += [r % 256]; r, m = r // 256, (m + 255) // 256
        R2 += [r]; M2 += [m]
    if len(M) & 1:
        R2 += [R[-1]]; M2 += [M[-1]]
    return S + ref_Encode(R2, M2)

def ref_Decode(S, M):
    if len(M) == 0: return []
    if len(M) == 1:
        return [sum(S[i] * 256**i for i in range(len(S))) % M[0]]
    k = 0; bottom, M2 = [], []
    for i in range(0, len(M) - 1, 2):
        m, r, t = M[i] * M[i + 1], 0, 1
        while m >= 16384:
            r, t, k, m = r + S[k] * t, t * 256, k + 1, (m + 255) // 256
        bottom += [(r, t)]; M2 += [m]
    if len(M) & 1: M2 += [M[-1]]
    R2 = ref_Decode(S[k:], M2)
    R = []
    for i in range(0, len(M) - 1, 2):
        r, t = bottom[i // 2]
        r += t * R2[i // 2]
        R += [r % M[i], (r // M[i]) % M[i + 1]]
    if len(M) & 1: R += [R2[-1]]
    return R

M = [Q] * P
fails = []

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  {detail}" if detail else ""))
    if not ok: fails.append(name)

# A. module Encode == reference Encode
for _ in range(20):
    R = [secrets.randbelow(Q) for _ in range(P)]
    if bytes(_ntruprime_encode(R, M)) != bytes(ref_Encode(R, M)):
        check("A: module Encode == spec Encode", False); break
else:
    check("A: module Encode == spec Encode (20 random vectors)", True)
check("A2: Encode agrees at all-max coefficients",
      bytes(_ntruprime_encode([Q - 1] * P, M)) == bytes(ref_Encode([Q - 1] * P, M)))
check("A3: Encode agrees at all-zero coefficients",
      bytes(_ntruprime_encode([0] * P, M)) == bytes(ref_Encode([0] * P, M)))

# B. real liboqs keys: decode in-range + perfect re-encode round trip
n_real, all_rt, all_range = 30, True, True
real_coeff_pool = []
for _ in range(n_real):
    with oqs.KeyEncapsulation("sntrup761") as kem:
        pk = kem.generate_keypair()
    coeffs = ref_Decode(list(pk), M)
    if any(not (0 <= c < Q) for c in coeffs): all_range = False
    if bytes(ref_Encode(coeffs, M)) != pk: all_rt = False
    real_coeff_pool.extend(coeffs)
check(f"B1: {n_real} real pks -> coefficients all in [0,{Q})", all_range)
check(f"B2: Encode(Decode(real_pk)) == real_pk for all {n_real}", all_rt)

# C. bijectivity onto image + constant length
lens, ok_bij = set(), True
for _ in range(200):
    R = [secrets.randbelow(Q) for _ in range(P)]
    S = ref_Encode(R, M)
    lens.add(len(S))
    if ref_Decode(S, M) != R: ok_bij = False
check("C1: Decode(Encode(R)) == R (200 random R)", ok_bij)
check("C2: constant encoded length", len(lens) == 1, f"len={lens}")
check("C3: encoded length == liboqs pk length", lens == {len(pk)}, f"{lens} vs {len(pk)}")

# D. oblivious keys: length, in-range decode, encaps accepts
sampler = resolve_oqs("sntrup761")
ok_len = ok_range = ok_encaps = True
ss_set, obl_pool = set(), []
for _ in range(15):
    opk = sampler(pk)
    if len(opk) != len(pk): ok_len = False
    oc = ref_Decode(list(opk), M)
    if any(not (0 <= c < Q) for c in oc): ok_range = False
    obl_pool.extend(oc)
    with oqs.KeyEncapsulation("sntrup761") as peer:
        ct, ss = peer.encap_secret(opk)
        ss_set.add(ss)
        if len(ss) == 0: ok_encaps = False
check("D1: oblivious pk length == real pk length", ok_len)
check("D2: oblivious pk decodes to coefficients in [0,q)", ok_range)
check("D3: liboqs encaps accepts oblivious pks (15/15)", ok_encaps)
check("D4: shared secrets all distinct", len(ss_set) == 15)

# E. chi-square on coefficient marginals (16 buckets, df=15, 99.9% crit 37.7)
def chisq(pool, nb=16):
    exp = len(pool) / nb
    counts = [0] * nb
    for c in pool: counts[c * nb // Q] += 1
    return sum((c - exp) ** 2 / exp for c in counts)

c_real, c_obl = chisq(real_coeff_pool), chisq(obl_pool)
check("E1: real-key coefficient marginals ~ uniform", c_real < 37.7, f"chi2={c_real:.1f}")
check("E2: oblivious coefficient marginals ~ uniform", c_obl < 37.7, f"chi2={c_obl:.1f}")

print()
print("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}")
sys.exit(1 if fails else 0)
