import numpy as np
import logging
import hashlib
import secrets
import hmac
from typing import Tuple, Optional, List
from flint import nmod_poly, fmpz_poly
import os
import sys
import math
import time

log = logging.getLogger("ntru_fo")


def center_lift(poly, modulus):
    """Center lift coefficients to range [-(q-1)/2, (q-1)/2]."""
    half_mod = modulus // 2
    coeffs = poly.coeffs()
    centered = [((int(c) + half_mod) % modulus) - half_mod for c in coeffs]
    return fmpz_poly(centered)

def poly_mod_coeffs(poly, modulus):
    """Reduce polynomial coefficients modulo 'modulus'."""
    coeffs = [int(c) % modulus for c in poly.coeffs()]
    return fmpz_poly(coeffs)


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def is_2_power(n):
    return n != 0 and (n & (n - 1)) == 0


def random_poly_flint(length, d, neg_ones_diff=0):
    coeffs = np.random.permutation(
        np.concatenate((
            np.zeros(length - 2 * d - neg_ones_diff),
            np.ones(d),
            -np.ones(d + neg_ones_diff)
        ))
    )
    return fmpz_poly([int(x) for x in coeffs])


def invert_nmod_poly(f, R, p):
    """Inverse of f mod R over Z/pZ (p prime) via xgcd: s*f + t*R = g, so
    f^-1 = g^-1 * s. Raises if f is not invertible."""
    g, s, _ = f.xgcd(R)

    # f is invertible mod R iff gcd(f, R) is a nonzero constant.
    if g.degree() != 0:
        raise Exception("Polynomial is not invertible")
    const = int(g.coeffs()[0]) if g.length() > 0 else 0
    if const % p == 0:
        raise Exception("Polynomial is not invertible")

    # xgcd does not force g monic; invert g by Fermat
    const_inv = pow(const % p, p - 2, p)
    return (s * nmod_poly([const_inv], p)) % R


def invert_poly_flint(f_poly, R_poly, p):
    """Inverse of f_poly mod R_poly (x^N - 1) over Z_p, p prime or a power of 2."""

    if is_prime(p):
        log.debug(f"Inverting mod prime p={p}")

        f_mod = nmod_poly(f_poly.coeffs(), p)
        R_mod = nmod_poly(R_poly.coeffs(), p)

        inv = invert_nmod_poly(f_mod, R_mod, p)

        return fmpz_poly([int(c) for c in inv.coeffs()])

    elif is_2_power(p):
        log.debug(f"Inverting mod 2-power p={p}")

        e = p.bit_length() - 1  # p = 2^e

        # seed: inverse mod 2
        f_mod2 = nmod_poly(f_poly.coeffs(), 2)
        R_mod2 = nmod_poly(R_poly.coeffs(), 2)
        inv = invert_nmod_poly(f_mod2, R_mod2, 2)

        # Newton lift: inv' = inv*(2 - f*inv) mod R doubles the precision each step
        f_mod = nmod_poly([int(c) for c in f_poly.coeffs()], p)
        R_mod = nmod_poly([int(c) for c in R_poly.coeffs()], p)
        inv = nmod_poly([int(c) for c in inv.coeffs()], p)
        two = nmod_poly([2], p)

        prec = 1
        while prec < e:
            inv = (inv * (two - (f_mod * inv) % R_mod)) % R_mod
            prec *= 2

        return fmpz_poly([int(c) for c in inv.coeffs()])

    else:
        raise Exception(f"Cannot invert polynomial in Z_{p}")


class NTRU_FO:
    """
    Stable NTRU-FO-CCA2 KEM (research-grade).

    Fixes:
    - Proper invertibility rejection loop
    - Canonical polynomial ordering (no reversals)
    - SHAKE-based deterministic randomness
    - Implicit rejection
    """

    TAG_RANDOMNESS = b"NTRU-FO-RAND-V1"
    TAG_SESSION_KEY = b"NTRU-FO-KEY-V1"
    TAG_MESSAGE = b"NTRU-FO-MSG-V1"
    TAG_IMPLICIT_REJECT = b"NTRU-FO-REJECT-V1"

    def __init__(self, N: int = 701, p: int = 3, q: int = 8192):
        self.N = N
        self.p = p
        self.q = q
        self.sigma_bytes = 32

        coeffs = [0] * (N + 1)
        coeffs[0] = -1
        coeffs[N] = 1
        self.R_poly = fmpz_poly(coeffs)

        self.f_poly = None
        self.f_p_poly = None
        self.f_q_poly = None
        self.g_poly = None
        self.h_poly = None
        # placeholder until generate_keys(); keeps decapsulate() from crashing keyless
        self._implicit_reject_key = secrets.token_bytes(32)

        logging.info(f"NTRU-FO initialized (N={N}, p={p}, q={q})")

    # ============================================================
    # KEY GENERATION (FIXED)
    # ============================================================

    def generate_keys(self) -> Tuple[fmpz_poly, fmpz_poly]:
        logging.info("Generating keys...")
        start = time.perf_counter()

        while True:
            try:
                self.g_poly = random_poly_flint(self.N, self.N // 4)
                self.f_poly = random_poly_flint(
                    self.N, self.N // 3, neg_ones_diff=-1
                )

                self.f_p_poly = invert_poly_flint(
                    self.f_poly, self.R_poly, self.p
                )
                self.f_q_poly = invert_poly_flint(
                    self.f_poly, self.R_poly, self.q
                )

                if self.f_p_poly is None or self.f_q_poly is None:
                    continue

                # Verify inversion correctness
                test_p = poly_mod_coeffs(
                    (self.f_poly * self.f_p_poly) % self.R_poly,
                    self.p,
                )
                test_q = poly_mod_coeffs(
                    (self.f_poly * self.f_q_poly) % self.R_poly,
                    self.q,
                )

                if list(test_p.coeffs())[:1] != [1]:
                    continue
                if list(test_q.coeffs())[:1] != [1]:
                    continue

                break

            except Exception:
                continue

        p_f_q = poly_mod_coeffs(self.p * self.f_q_poly, self.q)
        h_tmp = poly_mod_coeffs(p_f_q * self.g_poly, self.q)
        self.h_poly = poly_mod_coeffs(h_tmp % self.R_poly, self.q)

        self._implicit_reject_key = self._derive_reject_key()

        logging.info(f"Keygen done in {time.perf_counter() - start:.4f}s")
        return self._poly_to_bytes(self.h_poly), b""  # sk stays internal

    # ============================================================
    # ENCAPSULATION
    # ============================================================

    def encapsulate(self, public_key=None):
        if public_key is None:
            public_key = self.h_poly
        elif isinstance(public_key, bytes):
            public_key = self._bytes_to_poly(public_key)

        message = np.array(
            [secrets.randbelow(self.p) for _ in range(self.N)]
        )

        sigma = secrets.token_bytes(self.sigma_bytes)
        m_bytes = self._encode_message(message)

        r_poly = self._hash_to_randomness(m_bytes, sigma)

        msg_poly = fmpz_poly([int(c) for c in message])

        c_poly = poly_mod_coeffs(
            (poly_mod_coeffs(r_poly * public_key, self.q) + msg_poly)
            % self.R_poly,
            self.q,
        )

        c_bytes = self._poly_to_bytes(c_poly)
        ciphertext = c_bytes + sigma

        session_key = self._hash_h(m_bytes, ciphertext)
        return session_key, ciphertext  # (shared_secret, ciphertext)

    # ============================================================
    # DECAPSULATION
    # ============================================================

    def decapsulate(self, sk, ciphertext: bytes) -> bytes:
        c_len = self.N * 4
        if len(ciphertext) != c_len + self.sigma_bytes:
            return self._implicit_rejection(ciphertext)

        c_bytes = ciphertext[:c_len]
        sigma = ciphertext[c_len:]

        try:
            c_poly = self._bytes_to_poly(c_bytes)
        except Exception:
            return self._implicit_rejection(ciphertext)

        try:
            decrypted = self._decrypt(c_poly)
        except Exception:
            return self._implicit_rejection(ciphertext)

        message = np.array(decrypted[: self.N])
        m_bytes = self._encode_message(message)

        r_prime = self._hash_to_randomness(m_bytes, sigma)

        msg_poly = fmpz_poly([int(c) for c in message])

        c_prime = poly_mod_coeffs(
            (poly_mod_coeffs(r_prime * self.h_poly, self.q) + msg_poly)
            % self.R_poly,
            self.q,
        )

        c_prime_bytes = self._poly_to_bytes(c_prime)

        if hmac.compare_digest(c_bytes, c_prime_bytes):
            return self._hash_h(m_bytes, ciphertext)
        else:
            return self._implicit_rejection(ciphertext)

    # ============================================================
    # INTERNALS
    # ============================================================

    def _decrypt(self, ciphertext_poly: fmpz_poly) -> List[int]:
        a = poly_mod_coeffs(self.f_poly * ciphertext_poly, self.q)
        a = poly_mod_coeffs(a % self.R_poly, self.q)
        a = center_lift(a, self.q)
        b = poly_mod_coeffs(a, self.p)

        result = poly_mod_coeffs(
            (self.f_p_poly * b) % self.R_poly, self.p
        )

        # .coeffs() drops trailing zeros; pad to N so m_bytes stays canonical
        coeffs = list(result.coeffs())
        return [int(coeffs[i]) if i < len(coeffs) else 0 for i in range(self.N)]

    def _hash_to_randomness(self, m_bytes: bytes, sigma: bytes):
        # digest(n) returns a prefix of the XOF stream, so longer draws stay
        # deterministic (the re-encryption check in decapsulate() needs this)
        shake = hashlib.shake_256()
        shake.update(self.TAG_RANDOMNESS + m_bytes + sigma)

        take = self.N * 2
        while True:
            buf = shake.digest(take)
            coeffs = []
            for b in buf:
                if b >= 255:  # reject 255 so 0..254 maps to {0,1,2} unbiased
                    continue
                v = b % 3
                coeffs.append(0 if v == 0 else (1 if v == 1 else -1))
                if len(coeffs) == self.N:
                    return fmpz_poly(coeffs)
            take *= 2  # practically unreachable

    def _encode_message(self, message: np.ndarray) -> bytes:
        out = bytearray(self.TAG_MESSAGE)
        for c in message:
            out.extend(int(c % self.p).to_bytes(2, "big"))
        return bytes(out)

    def _hash_h(self, m_bytes: bytes, data: bytes) -> bytes:
        return hashlib.sha3_256(self.TAG_SESSION_KEY + m_bytes + data).digest()

    def _derive_reject_key(self) -> bytes:
        return hashlib.sha3_256(
            self.TAG_IMPLICIT_REJECT + self._poly_to_bytes(self.f_poly)
        ).digest()

    def _implicit_rejection(self, ciphertext: bytes) -> bytes:
        return hashlib.sha3_256(
            self._implicit_reject_key + ciphertext
        ).digest()

    def _poly_to_bytes(self, poly: fmpz_poly) -> bytes:
        coeffs = list(poly.coeffs())
        out = bytearray()
        for i in range(self.N):
            c = int(coeffs[i]) if i < len(coeffs) else 0
            out.extend((c % self.q).to_bytes(4, "big"))
        return bytes(out)

    def _bytes_to_poly(self, data: bytes) -> fmpz_poly:
        if len(data) != self.N * 4:
            raise ValueError("Invalid polynomial encoding")
        coeffs = [
            int.from_bytes(data[i:i + 4], "big") % self.q
            for i in range(0, len(data), 4)
        ]
        return fmpz_poly(coeffs)
