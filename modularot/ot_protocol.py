"""
Modular KEM-based 1-out-of-n Oblivious Transfer (semi-honest secure).

Construction:
    1. Receiver(b) generates a real keypair for branch b and an oblivious
       public key (no one knows its secret key) for every other branch, and
       sends all n public keys.
    2. Sender encapsulates under each public key, AEAD-seals m_i with the
       shared secret, and sends all n ciphertexts and sealed blobs.
    3. Receiver decapsulates ct_b with sk_b and opens m_b. It has no secret
       for the other keys, so m_{i!=b} stays hidden.

Security (semi-honest):
    * Receiver privacy: the sender holds no secret key, so real and oblivious
      pks are indistinguishable and b is hidden.
    * Sender privacy: recovering ss_i without sk_i breaks the KEM (IND-CPA);
      a union bound over the n-1 hidden branches covers the receiver's whole
      view, since secrets for oblivious keys never exist.

Cost:
    * Receiver: 1 KeyGen + (n-1) oblivious samples + 1 Decaps. The samplers
      are pure Python, so they dominate for cheap-KeyGen KEMs (ML-KEM) and
      KeyGen dominates for FrodoKEM and NTRU.
    * Sender: n Encaps + n AEAD seals.
    * Bandwidth: n public keys one way, n (ct + sealed blob) the other.

The only KEM-specific operation, oblivious pk sampling, is injected as a
callable from `oblivious_sampling`. A black-box KEM cannot yield a
sender-private OT (GKMRV, FOCS 2000).
"""

from typing import List, Optional, Callable
import secrets
import hashlib
import time

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .kem_adapter.adapter import KEMAdapter
from .oblivious_sampling import resolve_oqs
import oqs


def _fmt_ns(ns: int) -> str:
    if ns < 1_000:
        return f"{ns} ns"
    elif ns < 1_000_000:
        return f"{ns / 1_000:.3f} µs"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    else:
        return f"{ns / 1_000_000_000:.3f} s"


def _print_step(label: str, ns: int) -> None:
    print(f"  {label:<48} {_fmt_ns(ns):>14}")


# ── key/nonce/AD derivation (binds session, branch, pk, label) ────────────────

def compute_pk_fingerprint(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()


def derive_key(shared_secret: bytes, session_id: bytes, branch: int, pk_fp: bytes) -> bytes:
    info = (b"MODULAROT\x00session:" + session_id + b"\x00branch:"
            + str(branch).encode("ascii") + b"\x00pk:" + pk_fp)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=session_id, info=info).derive(shared_secret)


def build_associated_data(session_id: bytes, branch: int, pk_fp: bytes, label: bytes) -> bytes:
    return (b"MODULAROT||session:" + session_id + b"||branch:"
            + str(branch).encode("ascii") + b"||pk:" + pk_fp + b"||label:" + label)


def derive_nonce(shared_secret: bytes, session_id: bytes, branch: int, pk_fp: bytes, label: bytes) -> bytes:
    info = (b"MODULAROT_nonce||session:" + session_id + b"||branch:"
            + str(branch).encode("ascii") + b"||pk:" + pk_fp + b"||label:" + label)
    return HKDF(algorithm=hashes.SHA256(), length=12, salt=session_id, info=info).derive(shared_secret)


def _label(branch: int) -> bytes:
    return f"message_{branch}".encode("ascii")


# ── OT parties ────────────────────────────────────────────────────────────────

class OTReceiver:
    """Holds the real keypair for the chosen branch only."""

    def __init__(self, choice: int, kem: KEMAdapter,
                 sample_oblivious_pk: Callable[[bytes], bytes], n: int = 2):
        if n < 2:
            raise ValueError("Need at least 2 branches")
        if not 0 <= choice < n:
            raise ValueError(f"Choice must be in [0, {n - 1}]")
        self.n = n
        self.choice = choice
        self.kem = kem
        self.sample_oblivious_pk = sample_oblivious_pk
        self._real_sk: Optional[bytes] = None
        self._pk: List[Optional[bytes]] = [None] * n  # pks as sent

    def request(self) -> List[bytes]:
        """Return n public keys: real at `choice`, oblivious elsewhere."""
        pk_real, self._real_sk = self.kem.Gen()
        self._pk = [pk_real if i == self.choice else self.sample_oblivious_pk(pk_real)
                    for i in range(self.n)]
        return list(self._pk)

    def finalize(self, cts: List[bytes], sealeds: List[bytes],
                 session_id: bytes) -> Optional[bytes]:
        b = self.choice
        pk_fp = compute_pk_fingerprint(self._pk[b])  # recompute, don't trust sender

        ss = self.kem.decaps(self._real_sk, cts[b])
        key = derive_key(ss, session_id, b, pk_fp)
        ad = build_associated_data(session_id, b, pk_fp, _label(b))
        nonce = derive_nonce(ss, session_id, b, pk_fp, _label(b))
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, sealeds[b], ad)
        except Exception as e:
            print(f"[Receiver] decryption failed: {e}")
            return None


class OTSender:
    """Encapsulates under each received pk; cannot tell real from oblivious."""

    def __init__(self, kem: KEMAdapter, messages: List[bytes]):
        if len(messages) < 2:
            raise ValueError("Need at least 2 messages")
        self.kem = kem
        self.messages = list(messages)
        self.session_id = secrets.token_bytes(32)

    def transfer(self, pks: List[bytes]):
        if len(pks) != len(self.messages):
            raise ValueError(f"Got {len(pks)} public keys for {len(self.messages)} messages")
        cts, sealeds = [], []
        for i, pk in enumerate(pks):
            ss, ct = self.kem.encaps(pk)
            cts.append(ct)
            sealeds.append(self._seal(ss, i, pk, self.messages[i]))
        return cts, sealeds, self.session_id

    def _seal(self, ss: bytes, branch: int, pk: bytes, msg: bytes) -> bytes:
        pk_fp = compute_pk_fingerprint(pk)
        key = derive_key(ss, self.session_id, branch, pk_fp)
        ad = build_associated_data(self.session_id, branch, pk_fp, _label(branch))
        nonce = derive_nonce(ss, self.session_id, branch, pk_fp, _label(branch))
        return ChaCha20Poly1305(key).encrypt(nonce, msg, ad)


# ── check: a curious receiver must not recover any m_{i != b} ─────────────────

def receiver_cannot_read_other(make_kem, receiver: OTReceiver,
                               cts, sealeds, session_id) -> bool:
    """Try to open every m_{i != b} with the keys the receiver has (a forged
    sk and its real sk_b), on fresh and on the receiver's own KEM instances.
    Return True iff every AEAD open fails."""
    _, forged_sk = make_kem().Gen()
    attempts = [(make_kem(), forged_sk),
                (make_kem(), receiver._real_sk),
                (receiver.kem, receiver._real_sk)]
    for other in range(receiver.n):
        if other == receiver.choice:
            continue
        pk_fp = compute_pk_fingerprint(receiver._pk[other])
        for kem, sk in attempts:
            try:
                ss_guess = kem.decaps(sk, cts[other])
            except Exception:
                continue  # decaps refused
            key = derive_key(ss_guess, session_id, other, pk_fp)
            ad = build_associated_data(session_id, other, pk_fp, _label(other))
            nonce = derive_nonce(ss_guess, session_id, other, pk_fp, _label(other))
            try:
                ChaCha20Poly1305(key).decrypt(nonce, sealeds[other], ad)
                return False  # sender privacy broken
            except Exception:
                continue
    return True


# ── runner ────────────────────────────────────────────────────────────────────

def run_ot(make_kem: Callable[[], KEMAdapter],
           sampler: Callable[[bytes], bytes],
           label: str, choice: int = 0, n: int = 2,
           messages: Optional[List[bytes]] = None,
           check_security: bool = True, verbose: bool = True) -> dict:
    if messages is None:
        messages = [f"Secret message {i} [{label}]".encode() for i in range(n)]
    elif len(messages) != n:
        raise ValueError(f"Got {len(messages)} messages for n={n}")

    total_start = time.perf_counter_ns()

    t0 = time.perf_counter_ns()
    receiver = OTReceiver(choice, make_kem(), sampler, n=n)
    sender = OTSender(make_kem(), messages)
    t_init = time.perf_counter_ns() - t0

    # Receiver -> Sender : [pk_0..pk_{n-1}]  [KeyGen x1 + oblivious sample x(n-1)]
    t0 = time.perf_counter_ns()
    pks = receiver.request()
    t_request = time.perf_counter_ns() - t0

    # Sender -> Receiver : ciphertexts + sealed messages  [Encaps xn + AEAD xn]
    t0 = time.perf_counter_ns()
    cts, sealeds, session_id = sender.transfer(pks)
    t_transfer = time.perf_counter_ns() - t0

    # Receiver opens chosen message  [Decaps x1 + AEAD open x1]
    t0 = time.perf_counter_ns()
    received = receiver.finalize(cts, sealeds, session_id)
    t_finalize = time.perf_counter_ns() - t0

    total_ns = time.perf_counter_ns() - total_start

    ok = received == messages[choice]
    secure = (receiver_cannot_read_other(make_kem, receiver, cts, sealeds, session_id)
              if check_security else None)

    pk_bw = sum(len(pk) for pk in pks)
    ct_bw = sum(len(ct) for ct in cts) + sum(len(s) for s in sealeds)

    if verbose:
        print(f"\nKEM: {label}  |  1-out-of-{n}  |  choice: {choice}")
        print(f"  {'─' * 64}")
        _print_step("Init (Receiver + Sender)", t_init)
        _print_step(f"Receiver.request (KeyGen x1 + obliv pk x{n - 1})", t_request)
        _print_step(f"Sender.transfer (Encaps x{n} + AEAD seal x{n})", t_transfer)
        _print_step("Receiver.finalize (Decaps x1 + AEAD open x1)", t_finalize)
        print(f"  {'─' * 64}")
        _print_step("TOTAL", total_ns)
        print()
        print(f"  Bandwidth R->S      : {pk_bw} B ({n} public keys)")
        print(f"  Bandwidth S->R      : {ct_bw} B ({n} ct + {n} sealed)")
        print(f"  Correct (gets m_b)  : {ok}")
        print(f"  Decrypted message   : {received!r}")
        if check_security:
            print(f"  Sender-private      : {secure}   (receiver cannot read any m_(i!=b))")

    return {"KEM": label, "n": n, "init": t_init, "request": t_request,
            "transfer": t_transfer, "finalize": t_finalize, "TOTAL": total_ns,
            "pk_bw": pk_bw, "ct_bw": ct_bw, "ok": ok, "secure": secure,
            "message": received}


def _oqs_kem_factory(kemalg: str) -> Callable[[], KEMAdapter]:
    def oqs_gen():
        kem = oqs.KeyEncapsulation(kemalg)
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        kem.free()
        return pk, sk

    def oqs_encap(pk):
        kem = oqs.KeyEncapsulation(kemalg)
        ct, ss = kem.encap_secret(pk)
        kem.free()
        return ss, ct

    def oqs_decap(sk, ct):
        kem = oqs.KeyEncapsulation(kemalg, secret_key=sk)
        ss = kem.decap_secret(ct)
        kem.free()
        return ss

    return lambda: KEMAdapter(gen=oqs_gen, encap=oqs_encap, decap=oqs_decap)


def demo_oqs_ot():
    print("=" * 72)
    print("Modular OT over enabled lattice liboqs KEMs (semi-honest, sender-private)")
    print("=" * 72)

    results, skipped = [], []
    for kemalg in oqs.get_enabled_kem_mechanisms():
        try:
            sampler = resolve_oqs(kemalg)
        except NotImplementedError as e:
            skipped.append((kemalg, str(e).split(":", 1)[-1].strip()))
            continue
        except KeyError:
            continue  # non-lattice: excluded

        # warmup: keep liboqs lazy init out of the timings
        _wu = oqs.KeyEncapsulation(kemalg)
        _wu_pk = _wu.generate_keypair()
        _wu_ct, _ = _wu.encap_secret(_wu_pk)
        _wu.decap_secret(_wu_ct)
        _wu.free()

        results.append(run_ot(_oqs_kem_factory(kemalg), sampler, kemalg, choice=0))

    kw = max((len(r["KEM"]) for r in results), default=14)
    header = (f"{'KEM':<{kw}}  {'Request':>12}  {'Transfer':>12}  {'Finalize':>12}  "
              f"{'TOTAL':>12}  OK  SEC")
    print(f"\n\n{'═' * len(header)}")
    print(f"BENCHMARK SUMMARY — {len(results)} supported / "
          f"{len(results) + len(skipped)} enabled")
    print(f"{'═' * len(header)}")
    print(header)
    print("─" * len(header))
    for r in results:
        print(f"{r['KEM']:<{kw}}  {_fmt_ns(r['request']):>12}  {_fmt_ns(r['transfer']):>12}  "
              f"{_fmt_ns(r['finalize']):>12}  {_fmt_ns(r['TOTAL']):>12}  "
              f"{'✓' if r['ok'] else '✗'}   {'✓' if r['secure'] else '✗'}")
    print("─" * len(header))
    if skipped:
        print(f"\nNOT SUPPORTED ({len(skipped)}) — refused rather than weaken security:")
        for alg, reason in skipped:
            print(f"  • {alg:<26} {reason}")


def demo_NTRU_ot():
    print("=" * 72)
    print("OT over NTRU_FO — NOT RUN")
    print("=" * 72)
    print("  Not wired in: NTRU_FO uses its own N=701 polynomial encoding, so it")
    print("  needs a dedicated oblivious sampler (see oblivious_sampling.py).")


if __name__ == "__main__":
    demo_oqs_ot()
    print()
    demo_NTRU_ot()
