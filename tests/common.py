"""
Shared machinery for the sampler verification tests.

  * per-family extraction function ``phi``: what is pulled out of a public key
    before any statistical comparison, plus the matching ``Encode`` used for
    the Step 1 round-trip;
  * the four statistical steps:
      Step 1  structural round-trip           Encode(Decode(x)) == x
      Step 2  two-sample Kolmogorov-Smirnov    D_{n,m} vs 1.36*sqrt((n+m)/nm)
      Step 3  Pearson chi-square vs the uniform law (Wilson-Hilferty critical
              value for large degrees of freedom)
      Step 4  Shannon entropy + MCV min-entropy (NIST SP 800-90B)
  * a catalogue of the sampler instances under test.

No third-party stats dependency.
"""

import logging
import math
import os
import secrets
import statistics
import sys

logging.disable(logging.INFO)   # NTRU_FO logs keygen on the root logger

import oqs
from modularot.oblivious_sampling import (
    _byte_encode_12, resolve_oqs, sample_oblivious_ntru_fo,
    sample_oblivious_ggh_hnf,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

# palette
BLUE, RED, GREY, GREEN, ORANGE = "#4575b4", "#d73027", "#999999", "#1a9850", "#f46d43"


# ══════════════════════════════════════════════════════════════════════════════
#  Step 2 -- two-sample Kolmogorov-Smirnov
# ══════════════════════════════════════════════════════════════════════════════

def ks_two_sample(a, b, alpha=0.05, n_eff=None):
    """D_{n,m} = sup_x |F_n(x) - G_m(x)| and the decision rule
        reject H0 (F_real == F_obl)  iff  D_{n,m} > c(alpha) sqrt((n+m)/(nm)),
    with c(0.05) = 1.36. Returns a dict.

    ``n_eff`` overrides the sample size used for the threshold (not for D):
    for data drawn in correlated blocks -- one block per key -- the number of
    independent observations is the block count, not the value count."""
    c = {0.10: 1.224, 0.05: 1.358, 0.01: 1.628}[alpha]
    a = sorted(a)
    b = sorted(b)
    n, m = len(a), len(b)
    i = j = 0
    d = 0.0
    d_at = None
    while i < n and j < m:
        x = min(a[i], b[j])
        while i < n and a[i] <= x:
            i += 1
        while j < m and b[j] <= x:
            j += 1
        gap = abs(i / n - j / m)
        if gap > d:
            d, d_at = gap, x
    ne = me = n_eff if n_eff is not None else None
    thr = c * math.sqrt((n + m) / (n * m) if ne is None
                        else (ne + me) / (ne * me))
    return {
        "D": d, "D_at": d_at, "n": n, "m": m, "n_eff": n_eff,
        "threshold": thr, "c_alpha": c, "alpha": alpha,
        "reject": d > thr,
        "p_value": _ks_pvalue(d, n_eff or n, n_eff or m),
    }


def ks_repeated(a_pool, b_pool, n_ks, reps=9, alpha=0.05, n_eff=None):
    """KS applied to ``reps`` independent random subsamples of size ``n_ks``
    from each pool. Guards a single verdict against an unlucky split: the
    distributions differ only if a clear majority of the splits reject.
    Returns the median run plus the rejection fraction. ``n_eff`` is forwarded
    to ``ks_two_sample`` for block-correlated data."""
    # always draw a strict subsample so the `reps` splits actually vary
    cap = min(n_ks, int(0.85 * min(len(a_pool), len(b_pool))))
    runs = []
    for r in range(reps):
        a = _rand_subsample(a_pool, cap, seed=2 * r + 1)
        b = _rand_subsample(b_pool, cap, seed=2 * r + 2)
        runs.append(ks_two_sample(a, b, alpha, n_eff=n_eff))
    runs.sort(key=lambda x: x["D"])
    med = runs[len(runs) // 2]
    frac = sum(1 for x in runs if x["reject"]) / len(runs)
    med = dict(med)
    med["reject_fraction"] = frac
    med["reps"] = reps
    med["reject"] = frac > 0.5
    med["D_runs"] = [x["D"] for x in runs]
    return med


def _rand_subsample(seq, n, seed):
    if len(seq) <= n:
        return list(seq)
    rng = _lcg(seed ^ (len(seq) * 2654435761))
    idx = set()
    while len(idx) < n:
        idx.add(next(rng) % len(seq))
    return [seq[i] for i in idx]


def _lcg(state):
    state &= (1 << 64) - 1
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        yield state >> 11


def _ks_pvalue(D, n, m):
    ne = n * m / (n + m)
    t = (math.sqrt(ne) + 0.12 + 0.11 / math.sqrt(ne)) * D
    if t <= 0:
        return 1.0
    p = 2.0 * sum((-1) ** (k - 1) * math.exp(-2.0 * k * k * t * t)
                  for k in range(1, 101))
    return min(max(p, 0.0), 1.0)


def ecdf(values):
    xs = sorted(values)
    n = len(xs)
    return xs, [(i + 1) / n for i in range(n)]


# ══════════════════════════════════════════════════════════════════════════════
#  Step 3 -- Pearson chi-square goodness of fit vs the uniform law
# ══════════════════════════════════════════════════════════════════════════════

def wilson_hilferty_crit(df, alpha=0.05):
    """Critical value of chi^2_df at level ``alpha`` via the Wilson-Hilferty
    cube-root normal approximation, for degrees of freedom (3328, 8190, ...)
    that standard tables do not cover."""
    z = {0.10: 1.281552, 0.05: 1.644854, 0.01: 2.326348}[alpha]
    t = 1.0 - 2.0 / (9.0 * df) + z * math.sqrt(2.0 / (9.0 * df))
    return df * t ** 3


def _bucket(v, lo, hi, k):
    """Class index of ``v`` among ``k`` equal cells of [lo, hi). Integer path
    when the domain is integer and one value == one class (avoids the
    float-rounding off-by-one that would inflate chi^2)."""
    span = hi - lo
    if isinstance(lo, int) and isinstance(hi, int) and span == k:
        idx = v - lo
    else:
        idx = int((v - lo) * k / span)
    return min(max(idx, 0), k - 1)


def chi2_uniform_gof(values, lo, hi, k):
    """chi^2 = sum (O_i - E_i)^2 / E_i for ``k`` equal classes over [lo, hi)
    against the uniform reference E_i = N/k. Returns (chi2, df=k-1, N)."""
    n = len(values)
    exp = n / k
    counts = [0] * k
    for v in values:
        counts[_bucket(v, lo, hi, k)] += 1
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    return chi2, k - 1, n


def chi2_verdict(values, lo, hi, k, alpha=0.05):
    chi2, df, n = chi2_uniform_gof(values, lo, hi, k)
    crit = wilson_hilferty_crit(df, alpha)
    return {"chi2": chi2, "df": df, "n": n, "crit": crit,
            "reject": chi2 > crit, "alpha": alpha,
            "exp_per_class": n / k}


# ══════════════════════════════════════════════════════════════════════════════
#  Step 4 -- descriptive metrics: Shannon entropy and MCV min-entropy
# ══════════════════════════════════════════════════════════════════════════════

def _class_counts(values, lo, hi, k):
    counts = {}
    for v in values:
        idx = _bucket(v, lo, hi, k)
        counts[idx] = counts.get(idx, 0) + 1
    return counts, len(values)


def shannon_entropy(values, lo, hi, k):
    counts, n = _class_counts(values, lo, hi, k)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def min_entropy_mcv(values, lo, hi, k):
    """NIST SP 800-90B Most-Common-Value estimator:
        p_hat = max_i O_i / n ,
        p_upper = p_hat + 2.576 sqrt(p_hat (1 - p_hat) / (n - 1)) ,
        H_inf  = -log2( min(1, p_upper) ) .
    Also returns the plug-in value -log2(p_hat)."""
    counts, n = _class_counts(values, lo, hi, k)
    p_hat = max(counts.values()) / n
    p_up = min(1.0, p_hat + 2.576 * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    return {"H_inf_mcv": -math.log2(p_up),
            "H_inf_plugin": -math.log2(p_hat),
            "p_hat": p_hat, "max_bits": math.log2(k)}


def descriptive(values, lo, hi, k):
    return {
        "shannon": shannon_entropy(values, lo, hi, k),
        "shannon_max": math.log2(k),
        **min_entropy_mcv(values, lo, hi, k),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  per-family phi    +  matching Encode for Step 1
# ══════════════════════════════════════════════════════════════════════════════

_Q3329 = 3329


def _dec_q3329(pk):
    body = pk[:-32]
    out = []
    for i in range(0, len(body), 3):
        b0, b1, b2 = body[i], body[i + 1], body[i + 2]
        out.append(b0 | ((b1 & 0x0F) << 8))
        out.append((b1 >> 4) | (b2 << 4))
    return out


def _enc_q3329(pk):
    return _byte_encode_12([c % _Q3329 for c in _dec_q3329(pk)]) + pk[-32:]


def _dec_bitpacked(pk, n, qbits):
    out, bitpos = [], 0
    for _ in range(n - 1):
        c = 0
        for kk in range(qbits):
            c |= ((pk[bitpos // 8] >> (bitpos % 8)) & 1) << kk
            bitpos += 1
        out.append(c)
    return out


def _enc_bitpacked(pk, n, qbits):
    coeffs = _dec_bitpacked(pk, n, qbits)
    out = bytearray(len(pk))
    bitpos = 0
    for c in coeffs:
        for kk in range(qbits):
            if (c >> kk) & 1:
                out[bitpos // 8] |= 1 << (bitpos % 8)
            bitpos += 1
    return bytes(out)


def _dec_ntrufo(pk):
    return [int.from_bytes(pk[i:i + 4], "big") for i in range(0, len(pk), 4)]


def _enc_ntrufo(pk, q=8192):
    return b"".join((c % q).to_bytes(4, "big") for c in _dec_ntrufo(pk))


# NTRU Prime reference Encode/Decode (Bernstein et al.), as in verify_sntrup.py
def _np_encode(R, M):
    if len(M) == 0:
        return []
    S = []
    if len(M) == 1:
        r, m = R[0], M[0]
        while m > 1:
            S += [r % 256]
            r, m = r // 256, (m + 255) // 256
        return S
    R2, M2 = [], []
    for i in range(0, len(M) - 1, 2):
        m, r = M[i] * M[i + 1], R[i] + M[i] * R[i + 1]
        while m >= 16384:
            S += [r % 256]
            r, m = r // 256, (m + 255) // 256
        R2 += [r]
        M2 += [m]
    if len(M) & 1:
        R2 += [R[-1]]
        M2 += [M[-1]]
    return S + _np_encode(R2, M2)


def _np_decode(S, M):
    if len(M) == 0:
        return []
    if len(M) == 1:
        return [sum(S[i] * 256 ** i for i in range(len(S))) % M[0]]
    k, bottom, M2 = 0, [], []
    for i in range(0, len(M) - 1, 2):
        m, r, t = M[i] * M[i + 1], 0, 1
        while m >= 16384:
            r, t, k, m = r + S[k] * t, t * 256, k + 1, (m + 255) // 256
        bottom += [(r, t)]
        M2 += [m]
    if len(M) & 1:
        M2 += [M[-1]]
    R2 = _np_decode(S[k:], M2)
    R = []
    for i in range(0, len(M) - 1, 2):
        r, t = bottom[i // 2]
        r += t * R2[i // 2]
        R += [r % M[i], (r // M[i]) % M[i + 1]]
    if len(M) & 1:
        R += [R2[-1]]
    return R


# ══════════════════════════════════════════════════════════════════════════════
#  case catalogue
# ══════════════════════════════════════════════════════════════════════════════

class Case:
    """One concrete sampler instance under test. ``kind`` drives the analysis:
    'coeff' families feed phi -> list of coefficients over [lo, hi) with k
    classes; 'ggh' is handled specially (log2 det / HNF diagonal / residues)."""

    kind = "coeff"
    family = ""
    label = ""
    lo = 0
    hi = 256
    k = 256
    unit = "byte"

    def real_key(self):        raise NotImplementedError
    def sample(self, real):    raise NotImplementedError
    def encaps_ok(self, pk):   raise NotImplementedError
    def phi(self, pk):         raise NotImplementedError          # -> list
    def roundtrip_ok(self, real):  return True                    # Step 1
    def ot_entry(self):        return None                        # (factory, sampler)


class _Oqs(Case):
    def __init__(self, alg):
        self.alg = alg

    def real_key(self):
        with oqs.KeyEncapsulation(self.alg) as k:
            return k.generate_keypair()

    def sample(self, real):
        return resolve_oqs(self.alg)(real)

    def encaps_ok(self, pk):
        try:
            with oqs.KeyEncapsulation(self.alg) as k:
                ct, ss = k.encap_secret(pk)
            return len(ss) > 0
        except Exception:
            return False

    def ot_entry(self):
        from modularot.ot_protocol import _oqs_kem_factory
        return (_oqs_kem_factory(self.alg), resolve_oqs(self.alg))


class MLKEM(_Oqs):
    kind, family, unit = "coeff", "ML-KEM", "coefficient"
    label = "ML-KEM-768"
    lo, hi, k = 0, _Q3329, _Q3329

    def __init__(self):        super().__init__("ML-KEM-768")
    def phi(self, pk):         return [c % _Q3329 for c in _dec_q3329(pk)]
    def roundtrip_ok(self, r): return _enc_q3329(r) == r


class Frodo(_Oqs):
    kind, family, unit = "coeff", "FrodoKEM", "byte"
    label = "FrodoKEM-640-AES"
    lo, hi, k = 0, 256, 256

    def __init__(self):        super().__init__("FrodoKEM-640-AES")
    def phi(self, pk):         return list(pk)
    def roundtrip_ok(self, r): return True     # identity encoding


class NtruHps(_Oqs):
    kind, family, unit = "coeff", "NTRU-HPS", "coefficient"
    label = "NTRU-HPS-2048-509"
    _n, _q = 509, 2048
    lo, hi, k = 0, 2048, 2048

    def __init__(self):        super().__init__("NTRU-HPS-2048-509")
    def phi(self, pk):         return _dec_bitpacked(pk, self._n, 11)
    def roundtrip_ok(self, r): return _enc_bitpacked(r, self._n, 11) == r


class NtruHrss(_Oqs):
    kind, family, unit = "coeff", "NTRU-HRSS", "coefficient"
    label = "NTRU-HRSS-701"
    _n, _q = 701, 8192
    lo, hi, k = 0, 8192, 8192

    def __init__(self):        super().__init__("NTRU-HRSS-701")
    def phi(self, pk):         return _dec_bitpacked(pk, self._n, 13)
    def roundtrip_ok(self, r): return _enc_bitpacked(r, self._n, 13) == r


class Sntrup(_Oqs):
    kind, family, unit = "coeff", "sntrup761", "coefficient"
    label = "sntrup761"
    _P, _Q = 761, 4591
    lo, hi, k = 0, 4591, 4591

    def __init__(self):
        super().__init__("sntrup761")
        self._M = [self._Q] * self._P

    def phi(self, pk):         return _np_decode(list(pk), self._M)
    def roundtrip_ok(self, r):
        return bytes(_np_encode(_np_decode(list(r), self._M), self._M)) == r


class NtruFo(Case):
    kind, family, unit = "coeff", "NTRU_FO", "coefficient"
    label = "NTRU_FO-701"
    q = 8192
    lo, hi, k = 0, 8192, 8192

    def __init__(self):
        from modularot.custom_kems.ntru_fo.ntru_fo import NTRU_FO
        self._cls = NTRU_FO
        self._impl = NTRU_FO(N=701, p=3, q=self.q)

    def real_key(self):
        self._impl = self._cls(N=701, p=3, q=self.q)
        pk, _ = self._impl.generate_keys()
        return pk

    def sample(self, real):    return sample_oblivious_ntru_fo(real, q=self.q)

    def encaps_ok(self, pk):
        try:
            ss, _ = self._impl.encapsulate(pk)
            return len(ss) > 0
        except Exception:
            return False

    def phi(self, pk):         return _dec_ntrufo(pk)
    def roundtrip_ok(self, r): return _enc_ntrufo(r, self.q) == r

    def ot_entry(self):
        from modularot.cli import _ntrufo_entry
        _, factory, sampler = _ntrufo_entry(701)
        return (factory, sampler)


class GghFo(Case):
    kind, family, unit = "ggh", "GGH_FO", "residue"
    label = "GGH_FO-100"
    lo, hi, k = 0.0, 1.0, 16          # chi-square only on residues, df = 15

    def __init__(self, dim=100):
        from modularot.custom_kems.ggh_fo import ggh_fo
        self._m = ggh_fo
        self.dim = dim
        self.label = f"GGH_FO-{dim}"

    def real_key(self):        return self._m.gen(dimension=self.dim)[0]
    def sample(self, real):    return sample_oblivious_ggh_hnf(real)

    def encaps_ok(self, pk):
        try:
            ss, _ = self._m.encaps(pk)
            return len(ss) == 32
        except Exception:
            return False

    def roundtrip_ok(self, r):
        n, diag, cols, _ = self._m._des_pk(r)
        return self._m._ser_pk(n, diag, cols) == r

    def hnf_stats(self, pk):
        """phi for GGH: (log2|det L|, #non-trivial diagonal entries,
        residues of the dense columns)."""
        n, diag, cols, _ = self._m._des_pk(pk)
        log2det = sum(math.log2(d) for d in diag if d > 1)
        nontriv = sum(1 for d in diag if d != 1)
        res = [v / diag[i] for i in cols for v in cols[i] if diag[i] > (1 << 20)]
        return log2det, nontriv, res

    def phi(self, pk):         return self.hnf_stats(pk)[2]      # residues

    def ot_entry(self):
        from modularot.cli import _gghfo_entry
        _, factory, sampler = _gghfo_entry(self.dim)
        return (factory, sampler)


def all_cases(ggh_dim=100):
    return [MLKEM(), Frodo(), NtruHps(), NtruHrss(), Sntrup(), NtruFo(),
            GghFo(ggh_dim)]


# ══════════════════════════════════════════════════════════════════════════════
#  misc
# ══════════════════════════════════════════════════════════════════════════════

def ensure_out():
    os.makedirs(OUT, exist_ok=True)
    return OUT


def subsample(seq, n):
    if len(seq) <= n:
        return list(seq)
    step = len(seq) / n
    return [seq[int(i * step)] for i in range(n)]
