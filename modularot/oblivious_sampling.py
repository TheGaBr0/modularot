"""
Oblivious public-key sampling for the KEM-based OT (semi-honest, lattice KEMs).

This is the only KEM-aware module; the protocol in ot_protocol.py just calls
the sampler returned here.

An oblivious public key is a well-formed pk, distributed like a real one, whose
secret key nobody knows. The receiver supplies it for the non-chosen branch, so
the sender's shared secret there is pseudorandom to the receiver.

Requirements on a sampler:
  * sender privacy: nobody knows the secret key (no sampler runs KeyGen).
  * receiver privacy: real and oblivious pks must be indistinguishable, so the
    bytes must decode to the same coefficient distribution, in the same
    encoding. This rests on each scheme's decisional assumption (M-LWE, LWE,
    NTRU, NTRU Prime).

Sampling cannot be black-box over an arbitrary KEM (Gertner et al., FOCS 2000),
so each family has its own sampler; encodings were verified against liboqs
(Encode(Decode(real_pk)) == real_pk).

Coverage:
  * ML-KEM-{512,768,1024}, Kyber{512,768,1024} -> q=3329 ByteEncode_12
  * FrodoKEM / eFrodoKEM                        -> uniform bytes
  * NTRU-HPS / NTRU-HRSS                        -> bit-packed n-1 coefficients
  * sntrup761                                   -> NTRU Prime Encode, q prime
"""

import secrets


# ── structured lattice, prime modulus q = 3329 (ML-KEM, Kyber) ────────────────

_Q3329 = 3329


def _byte_encode_12(coeffs):
    """FIPS 203 ByteEncode_12: two 12-bit coefficients per three bytes."""
    out = bytearray()
    for i in range(0, len(coeffs), 2):
        d0, d1 = coeffs[i], coeffs[i + 1]
        out.append(d0 & 0xFF)
        out.append(((d0 >> 8) & 0x0F) | ((d1 & 0x0F) << 4))
        out.append((d1 >> 4) & 0xFF)
    return bytes(out)


def sample_oblivious_q3329(real_pk: bytes) -> bytes:
    """pk = ByteEncode_12(t) || rho, with t uniform in [0, q) (M-LWE) and a
    fresh seed rho. `real_pk` only gives the length, hence k."""
    if (len(real_pk) - 32) % 384 != 0:
        raise ValueError("not a q=3329 lattice public-key length")
    k = (len(real_pk) - 32) // 384
    coeffs = [secrets.randbelow(_Q3329) for _ in range(256 * k)]
    return _byte_encode_12(coeffs) + secrets.token_bytes(32)


# ── uniform bytes (LWE, power-of-two modulus) ─────────────────────────────────

def sample_oblivious_uniform_bytes(real_pk: bytes) -> bytes:
    """FrodoKEM: the pk is uniform under decisional LWE and has no range or
    padding constraint."""
    return secrets.token_bytes(len(real_pk))


# ── bit-packed n-1 coefficients, power-of-two modulus (NTRU-HPS / NTRU-HRSS) ──
#
# pk = h packed as (n-1) coefficients of log2(q) bits. Every bit pattern is a
# valid coefficient, so the sampler is uniform bytes with bits >= sig_bits
# zeroed. sig_bits == (n-1)*log2(q), verified against liboqs.
_NTRU_BITPACK = {
    "NTRU-HPS-2048-509":  5588,
    "NTRU-HPS-2048-677":  7436,
    "NTRU-HPS-4096-821":  9840,
    "NTRU-HPS-4096-1229": 14736,
    "NTRU-HRSS-701":      9100,
    "NTRU-HRSS-1373":     19208,
}


def _make_bitpacked_sampler(sig_bits: int):
    def sampler(real_pk: bytes) -> bytes:
        out = bytearray(secrets.token_bytes(len(real_pk)))
        full, rem = sig_bits // 8, sig_bits % 8
        if rem:
            out[full] &= 0xFF >> (8 - rem)   # keep low `rem` bits
            full += 1
        for i in range(full, len(out)):
            out[i] = 0                        # zero padding
        return bytes(out)
    return sampler


# ── NTRU Prime Encode of uniform coefficients (sntrup) ────────────────────────
#
# Uniform bytes do not decode to uniform in-range coefficients, so sample
# p coefficients in [0, q) and apply the mixed-radix Encode (matches liboqs).
_SNTRUP = {"sntrup761": (761, 4591)}


def _ntruprime_encode(R, M):
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
        m, r = M[i] * M[i + 1], R[i] + R[i + 1] * M[i]
        while m >= 16384:
            S += [r % 256]
            r, m = r // 256, (m + 255) // 256
        R2 += [r]
        M2 += [m]
    if len(M) & 1:
        R2 += [R[-1]]
        M2 += [M[-1]]
    return S + _ntruprime_encode(R2, M2)


def _make_ntruprime_sampler(p: int, q: int):
    M = [q] * p

    def sampler(real_pk: bytes) -> bytes:
        return bytes(_ntruprime_encode([secrets.randbelow(q) for _ in range(p)], M))
    return sampler


# ── NTRU_FO (custom, research-grade, N=701/p=3/q=8192 by default) ────────────
#
# Ring x^N - 1: pk = h = p*g*f^{-1} mod q, as N coefficients in [0, q), each
# in a 4-byte big-endian field (NTRU_FO._poly_to_bytes). Uniform bytes would set
# the high bits and be distinguishable, so sample each coefficient in [0, q).
# q is not recoverable from the key length and must match the instance.

def sample_oblivious_ntru_fo(real_pk: bytes, q: int = 8192) -> bytes:
    """Oblivious NTRU_FO public key; `q` must match the instance's modulus."""
    if len(real_pk) % 4 != 0:
        raise ValueError("not a 4-byte-per-coefficient NTRU_FO public key")
    n = len(real_pk) // 4
    return b"".join(secrets.randbelow(q).to_bytes(4, "big") for _ in range(n))


# ── GGH-HNF (custom library) ─────────────────────────────────────────────────
#
# Classic GGH (pk = basis B = U·R) is refused: det B, entry marginals and row
# norms separate real keys from any trapdoor-free sample, and no
# pseudorandomness assumption exists.
#
# The HNF variant (ggh_fo, GGH_private=True) publishes HNF(L), a canonical form
# revealing only det, the cokernel (HNF diagonal) and reduced column entries.
# Sampler ("discarded draw"):
#   1. draw once from the keygen law and keep only diag(HNF(R'')); R'' is
#      discarded, so nobody holds a short basis of the output;
#   2. fill the reduced entries (rows k < i of columns with d_i > 1)
#      uniformly in [0, d_i); columns with d_i = 1 are zero in any HNF.
# Indistinguishability rests on a planted-short-basis (uSVP-style) decisional
# assumption: unproven, but not known to be false.


def sample_oblivious_ggh_hnf(real_pk: bytes) -> bytes:
    """Oblivious GGH-HNF public key. Only the dimension header of `real_pk`
    is used; reusing its diagonal would correlate det/cokernel across branches."""
    # lazy import: flint/GGH_crypto are an optional extra
    import struct
    from .custom_kems.ggh_fo import ggh_fo

    (n,) = struct.unpack_from(">i", real_pk, 0)
    diag = ggh_fo.draw_lattice_diag(n)     # discarded draw
    cols = {
        i: [secrets.randbelow(diag[i]) for _ in range(i)]
        for i in range(n) if diag[i] > 1
    }
    return ggh_fo._ser_pk(n, diag, cols)


# ── dispatch ─────────────────────────────────────────────────────────────────

def resolve_oqs(alg: str):
    """Return `real_pk -> oblivious_pk` for a liboqs mechanism, or raise
    NotImplementedError if there is no sampler."""
    if alg.startswith("ML-KEM") or alg.startswith("Kyber"):
        return sample_oblivious_q3329
    if alg.startswith("FrodoKEM") or alg.startswith("eFrodoKEM"):
        return sample_oblivious_uniform_bytes
    if alg in _NTRU_BITPACK:
        return _make_bitpacked_sampler(_NTRU_BITPACK[alg])
    if alg in _SNTRUP:
        return _make_ntruprime_sampler(*_SNTRUP[alg])
    if alg.startswith("ntrulpr"):
        raise NotImplementedError(
            f"{alg}: NTRU Prime LPR uses the Rounded encoding (different moduli "
            "per limb); needs its own Encode wiring."
        )
    raise NotImplementedError(f"{alg!r}: no oblivious sampler")


def is_supported_oqs(alg: str) -> bool:
    try:
        resolve_oqs(alg)
        return True
    except NotImplementedError:
        return False
