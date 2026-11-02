"""GGH-HNF KEM with the Fujisaki-Okamoto transform. Educational, not quantum-safe."""

import functools
import hashlib
import math
import secrets
import struct
from typing import Dict, List, Optional, Tuple

from flint import fmpz_mat, fmpq_mat

from GGH_crypto import GGHHNFCryptosystem


# ── domain-separation tags ────────────────────────────────────────────────────

_TAG_KEY    = b"GGH-HNF-FO-KEY-V1\x00"
_TAG_REJECT = b"GGH-HNF-FO-REJECT-V1\x00"

_R_ENTRY = 8    # bytes per private-basis entry (|R[i,j]| << 2^63)
_MAX_TRIES = 25


# ── public parameters (functions of n only) ───────────────────────────────────

def sigma_e(n: int) -> int:
    """Public error magnitude; key-independent so nothing leaks about R."""
    return max(1, n // 2)


def keygen_k(n: int) -> int:
    """The library's GGH_private=True diagonal shift k = n*ceil(sqrt(n)+1)."""
    return n * math.ceil(math.sqrt(n) + 1)


# ── serialisation ─────────────────────────────────────────────────────────────

def _entry_width(d: int) -> int:
    """Fixed byte width for values in [0, d), d > 1."""
    return ((d - 1).bit_length() + 7) // 8


def _ser_pk(n: int, diag: List[int], cols: Dict[int, List[int]]) -> bytes:
    out = bytearray(struct.pack(">i", n))
    for d in diag:
        db = d.to_bytes((d.bit_length() + 7) // 8 or 1, "big")
        out += struct.pack(">H", len(db)) + db
    for i in range(n):
        if diag[i] > 1:
            w = _entry_width(diag[i])
            for v in cols[i]:
                out += v.to_bytes(w, "big")
    return bytes(out)


def _des_pk(buf: bytes) -> Tuple[int, List[int], Dict[int, List[int]], int]:
    """Parse a serialised pk (or the pk prefix of an sk).
    Returns (n, diag, cols, total_pk_length)."""
    (n,) = struct.unpack_from(">i", buf, 0)
    if not 1 <= n <= 1 << 20:
        raise ValueError("GGH-HNF pk: implausible dimension")
    off = 4
    diag = []
    for _ in range(n):
        (ln,) = struct.unpack_from(">H", buf, off)
        off += 2
        diag.append(int.from_bytes(buf[off:off + ln], "big"))
        off += ln
    cols: Dict[int, List[int]] = {}
    for i in range(n):
        if diag[i] > 1:
            w = _entry_width(diag[i])
            col = []
            for _ in range(i):
                col.append(int.from_bytes(buf[off:off + w], "big"))
                off += w
            cols[i] = col
    return n, diag, cols, off


def _ct_len(n: int, diag: List[int]) -> int:
    return sum(_entry_width(diag[i]) for i in range(n) if diag[i] > 1)


def _ser_ct(c: List[int], n: int, diag: List[int]) -> bytes:
    out = bytearray()
    for i in range(n):
        if diag[i] > 1:
            out += c[i].to_bytes(_entry_width(diag[i]), "big")
    return bytes(out)


def _des_ct(ct: bytes, n: int, diag: List[int]) -> Optional[List[int]]:
    if len(ct) != _ct_len(n, diag):
        return None
    c, off = [], 0
    for i in range(n):
        if diag[i] > 1:
            w = _entry_width(diag[i])
            v = int.from_bytes(ct[off:off + w], "big")
            if v >= diag[i]:
                return None      # outside the fundamental region: malformed
            c.append(v)
            off += w
        else:
            c.append(0)
    return c


def _ser_R(R: fmpz_mat, n: int) -> bytes:
    return b"".join(int(R[i, j]).to_bytes(_R_ENTRY, "big", signed=True)
                    for i in range(n) for j in range(n))


def _des_R(buf: bytes, off: int, n: int) -> fmpz_mat:
    return fmpz_mat([
        [int.from_bytes(buf[off + (i * n + j) * _R_ENTRY:
                             off + (i * n + j + 1) * _R_ENTRY], "big", signed=True)
         for j in range(n)]
        for i in range(n)
    ])


def _hnf_to_diag_cols(H: fmpz_mat, n: int) -> Tuple[List[int], Dict[int, List[int]]]:
    diag = [int(H[i, i]) for i in range(n)]
    cols = {i: [int(H[k, i]) for k in range(i)] for i in range(n) if diag[i] > 1}
    return diag, cols


# ── HNF arithmetic ────────────────────────────────────────────────────────────

def _reduce_mod_hnf(e: List[int], n: int, diag: List[int],
                    cols: Dict[int, List[int]]) -> List[int]:
    """Reduce a vector into the fundamental region of an upper-triangular HNF
    (flint's form): ascending sweep c -= floor(c_i / d_i) * row_i. The
    library's reduce_mod_B assumes a lower-triangular HNF, hence this copy.
    Result: c_i in [0, d_i), so c_i = 0 wherever d_i = 1."""
    c = list(e)
    dense = [i for i in range(n) if diag[i] > 1]
    for i in range(n):
        q = c[i] // diag[i]
        if q:
            c[i] -= q * diag[i]
            for j in dense:
                if j > i:
                    c[j] -= q * cols[j][i]
    return c


def _sigma_ok(R: fmpz_mat, n: int) -> bool:
    """Zero-failure condition for Babai rounding: for every j,
    2*sigma_e * sum_i |R^-1[i,j]| < 1 (column L1, as e is a row vector)."""
    s = sigma_e(n)
    Rinv = fmpq_mat(R).inv()
    for j in range(n):
        col = sum(abs(Rinv[i, j]) for i in range(n))
        if 2 * s * col >= 1:
            return False
    return True


# ── cryptographic helpers ─────────────────────────────────────────────────────

def _pack_signs(e: List[int]) -> bytes:
    """Pack sign(e_i) as bit i (LSB-first within each byte): the KEM coin m."""
    out = bytearray((len(e) + 7) // 8)
    for i, v in enumerate(e):
        if v > 0:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _h_key(m_bytes: bytes, ct: bytes) -> bytes:
    return hashlib.sha3_256(_TAG_KEY + m_bytes + ct).digest()


def _h_reject(reject_key: bytes, ct: bytes) -> bytes:
    return hashlib.sha3_256(_TAG_REJECT + reject_key + ct).digest()


# ── oblivious-sampling support ────────────────────────────────────────────────

def draw_lattice_diag(n: int, randint=None) -> List[int]:
    """One accepted keygen draw, returning only diag(HNF(R)). Follows the
    GGH_private=True law plus gen()'s rejection rules, so det and cokernel match
    keygen exactly; R itself is discarded and unrelated to the published key.
    `randint(a, b)` defaults to the crypto RNG."""
    if randint is None:
        rng = secrets.SystemRandom()
        randint = rng.randint
    k = keygen_k(n)
    for _ in range(_MAX_TRIES):
        R = fmpz_mat([[randint(-n, n - 1) for _ in range(n)] for _ in range(n)])
        for i in range(n):
            R[i, i] = int(R[i, i]) + k
        if R.det() == 0 or not _sigma_ok(R, n):
            continue
        H = R.hnf()
        diag = [int(H[i, i]) for i in range(n)]
        if all(d == 1 for d in diag):
            continue  # same rejection rule as gen()
        return diag
    raise ValueError(f"no accepted GGH-HNF draw in {_MAX_TRIES} tries (n={n} too small?)")


# ── KEM primitives ────────────────────────────────────────────────────────────

def gen(dimension: int = 200) -> Tuple[bytes, bytes]:
    """Generate (pk, sk) via GGH_private=True keygen, rejecting bases that fail
    the sigma bound."""
    n = dimension
    for _ in range(_MAX_TRIES):
        ggh = GGHHNFCryptosystem(dimension=n, GGH_private=True)
        R = ggh.private_basis
        if not _sigma_ok(R, n):
            continue
        H = ggh.public_basis  # already R.hnf()
        diag, cols = _hnf_to_diag_cols(H, n)
        if all(d == 1 for d in diag):
            continue  # det = +-1: nothing to hide in
        pk = _ser_pk(n, diag, cols)
        sk = pk + _ser_R(R, n) + secrets.token_bytes(32)
        return pk, sk
    raise ValueError(
        f"no sigma-accepted GGH-HNF key in {_MAX_TRIES} tries; "
        f"increase the dimension (sigma_max ~ 0.7*n must exceed n//2)."
    )


def encaps(pk: bytes) -> Tuple[bytes, bytes]:
    """Return (shared_secret, ciphertext)."""
    n, diag, cols, _ = _des_pk(pk)
    s = sigma_e(n)

    raw = secrets.token_bytes((n + 7) // 8)
    e = [s if (raw[i // 8] >> (i % 8)) & 1 else -s for i in range(n)]

    c = _reduce_mod_hnf(e, n, diag, cols)
    ct = _ser_ct(c, n, diag)
    return _h_key(_pack_signs(e), ct), ct


@functools.lru_cache(maxsize=16)
def _load_sk(sk: bytes) -> Tuple[int, List[int], Dict[int, List[int]],
                                 fmpz_mat, bytes]:
    """Parse an sk into (n, diag, cols, R, reject_key) (memoised)."""
    n, diag, cols, pk_len = _des_pk(sk)
    R = _des_R(sk, pk_len, n)
    reject_key = sk[pk_len + n * n * _R_ENTRY: pk_len + n * n * _R_ENTRY + 32]
    return n, diag, cols, R, reject_key


def decaps(sk: bytes, ct: bytes) -> bytes:
    """Return shared_secret (or the implicit-rejection value on failure)."""
    n, diag, cols, R, reject_key = _load_sk(sk)
    s = sigma_e(n)

    c = _des_ct(ct, n, diag)
    if c is None:
        return _h_reject(reject_key, ct)

    # Babai rounding: solve x R = c (cheaper than forming R^-1), then
    # e = c - round(x) R
    try:
        xt = fmpq_mat(R).transpose().solve(fmpq_mat(n, 1, [int(v) for v in c]))
        rounded = fmpz_mat([[round(xt[j, 0]) for j in range(n)]])
        closest = rounded * R
        e = [c[j] - int(closest[0, j]) for j in range(n)]
    except Exception:
        return _h_reject(reject_key, ct)

    # FO re-encryption check; accumulate both conditions before branching
    valid = 0
    for v in e:
        valid |= (abs(v) != s)
    c2 = _reduce_mod_hnf(e, n, diag, cols)
    for a, b in zip(c, c2):
        valid |= (a != b)

    if valid == 0:
        return _h_key(_pack_signs(e), ct)
    return _h_reject(reject_key, ct)
