"""
Component reuse (mix-and-match) tests.

Checks that an object produced for the triple (sid, i, pk_i) cannot be reused
in place of one expected for a different triple. Every key, nonce and
associated data is derived from (ss, sid, i, fp(pk_i), label_i) through HKDF
and ChaCha20-Poly1305 (ot_protocol.py: ``derive_key``,
``build_associated_data``, ``derive_nonce``), which is what makes the objects
non-interchangeable.

Scenarios (each must be REJECTED):
  S1  index mix-up: open the blob of message 0 as if it were message b, and
      the other way round;
  S2  ss/key paired with the wrong public key (pk_j, j != i);
  S3  cross-session reuse: blobs sealed in session A opened with the sid of
      session B;
  S4  two runs with the same (m_0, m_1) but different sid: the ciphertexts
      are not interchangeable;
  S5  reuse of ct_i in a new session: decapsulation yields a fresh ss, so the
      old blob does not open.
Positive control P0: the honest run opens m_b.

Output: tests/output/component_reuse_<kem-slug>.png (one per KEM)
        + component_reuse.json
"""

import argparse
import json
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from modularot.ot_protocol import (
    OTReceiver, OTSender, compute_pk_fingerprint, derive_key,
    build_associated_data, derive_nonce, _label, _oqs_kem_factory,
)
from modularot.oblivious_sampling import resolve_oqs

from common import ensure_out, OUT, GREEN, RED, GREY, BLUE, ORANGE

# S1/S3/S5 are accidental mismatches (index error, unintended reuse across
# sessions); S2/S4 need deliberate tampering and fall outside the semi-honest
# model (hardening).
_TAG = {"S1a": "accidental", "S1b": "accidental", "S3": "accidental",
        "S5": "accidental", "S2": "deliberate", "S4": "deliberate"}
_TAG_COLOR = {"accidental": BLUE, "deliberate": ORANGE}

# Short labels for the figure
_SHORT = {
    "P0": "Honest execution",
    "S1a": "Wrong index, right key",
    "S1b": "Wrong index and key",
    "S2": "Wrong public key",
    "S3": "Sid from another session",
    "S4": "Cross-session ciphertext swap",
    "S5": "KEM ciphertext reuse",
}


def _try_open(ss, sid, branch, pk_fp, blob):
    """Attempt an AEAD open with a derivation for (ss, sid, branch, pk_fp).
    Returns the plaintext on success, None on any failure."""
    try:
        key = derive_key(ss, sid, branch, pk_fp)
        ad = build_associated_data(sid, branch, pk_fp, _label(branch))
        nonce = derive_nonce(ss, sid, branch, pk_fp, _label(branch))
        return ChaCha20Poly1305(key).decrypt(nonce, blob, ad)
    except Exception:
        return None


def run_scenarios(factory, sampler, label, choice=1):
    m = [b"MESSAGE-0::" + label.encode(),
         b"MESSAGE-1::" + label.encode()]

    # ---- session A -------------------------------------------------------
    recv = OTReceiver(choice, factory(), sampler, n=2)
    pks = recv.request()
    sA = OTSender(factory(), m)
    ctsA, sealedsA, sidA = sA.transfer(pks)
    ssA_b = recv.kem.decaps(recv._real_sk, ctsA[choice])   # receiver's own ss
    fp = [compute_pk_fingerprint(p) for p in pks]
    other = 1 - choice

    # ---- session B: same messages, fresh sid ---------------------------
    recvB = OTReceiver(choice, factory(), sampler, n=2)
    pksB = recvB.request()
    sB = OTSender(factory(), m)
    ctsB, sealedsB, sidB = sB.transfer(pksB)

    R = []

    def rec(sid_, name, desc, opened, mechanism):
        R.append({"id": sid_, "name": name, "desc": desc,
                  "opened_a_message": opened is not None,
                  "rejected": opened is None, "mechanism": mechanism})

    # P0  honest path
    honest = recv.finalize(ctsA, sealedsA, sidA)
    R.append({"id": "P0", "name": "honest execution",
              "desc": f"finalize succeeds -> m_{choice}",
              "opened_a_message": honest == m[choice],
              "rejected": False, "mechanism": "--",
              "control_ok": honest == m[choice]})

    # S1  branch-index misuse (receiver holds ss for `choice` only)
    o = _try_open(ssA_b, sidA, choice, fp[other], sealedsA[other])
    rec("S1a", "index: blob of the other message, key of the chosen one",
        f"open sealed[{other}] with (ss_{choice}, i={choice}, pk_{choice})", o,
        "HKDF info + AEAD AD (ss and pk do not match)")
    o = _try_open(ssA_b, sidA, other, fp[other], sealedsA[other])
    rec("S1b", "index: blob and derivation of the other message",
        f"open sealed[{other}] with (ss_{choice}, i={other}, pk_{other})", o,
        "ss of the chosen message != ss_{}".format(other))

    # S2  ss/key bound to the wrong public key
    o = _try_open(ssA_b, sidA, choice, fp[other], sealedsA[choice])
    rec("S2", "cross-pk: fingerprint of pk_j, j != i",
        f"open sealed[{choice}] with fp(pk_{other}) instead of fp(pk_{choice})",
        o, "HKDF info + AEAD AD bind fp(pk_i)")

    # S3  cross-session: A's blobs opened under B's sid
    o = _try_open(ssA_b, sidB, choice, fp[choice], sealedsA[choice])
    rec("S3", "cross-session: blob of A, sid of B",
        "open sealed_A with sid_B", o, "HKDF salt+info and AEAD AD bind sid")

    # S4  same (m0,m1), different sid -> ciphertexts not interchangeable
    interchangeable = sealedsA[choice] == sealedsB[choice]
    o = recv.finalize(ctsA, sealedsB, sidA)   # A's ct/sid, B's sealed blobs
    R.append({"id": "S4", "name": "same messages, different sid",
              "desc": "sealed_A vs sealed_B with equal (m0,m1)",
              "opened_a_message": o == m[choice],
              "rejected": o != m[choice],
              "identical_ciphertexts": interchangeable,
              "mechanism": "nonce/key bound to sid -> distinct blobs"})

    # S5  reuse ct_i in a new session
    o = recvB.finalize(ctsA, sealedsA, sidA)  # B's receiver, A's transcript
    #    B decapsulated a different keypair -> ss differs -> AEAD fails
    R.append({"id": "S5", "name": "reuse of ct_i in a new session",
              "desc": "receiver B runs finalize on A's transcript",
              "opened_a_message": o == m[choice],
              "rejected": o != m[choice],
              "mechanism": "decaps with a different sk -> different ss"})

    all_rejected = all(r["rejected"] for r in R if r["id"] != "P0")
    control_ok = R[0]["opened_a_message"]
    return {"label": label, "choice": choice, "scenarios": R,
            "all_rejected": all_rejected, "control_ok": control_ok,
            "pass": all_rejected and control_ok}


# ══════════════════════════════════════════════════════════════════════════════

def render(res, path):
    """Render one KEM's scenario table: one row per scenario (id, type, short
    name, outcome). Drawn at 6.3in width so fonts keep their real size."""
    rows = res["scenarios"]
    n = len(rows)
    fig, ax = plt.subplots(figsize=(6.3, 0.85 + 0.46 * n))
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    ax.text(0.0, 0.975, f"{res['label']}  ·  $m_{res['choice']}$", fontsize=12,
            weight="bold", va="top", ha="left", transform=ax.transAxes)

    header_y = 0.895
    for x, label in ((0.0, "SCEN."), (0.115, "TYPE"),
                     (0.40, "WHAT IS TESTED"), (0.80, "OUTCOME")):
        ax.text(x, header_y, label, fontsize=7, weight="bold",
                color="#888", va="center", transform=ax.transAxes)
    ax.axhline(header_y - 0.05, color="#ccc", lw=0.8, xmax=1.0)

    top, bottom = header_y - 0.11, 0.02
    dy = (top - bottom) / n
    for i, r in enumerate(rows):
        y = top - i * dy - dy / 2
        if i % 2 == 1:
            ax.add_patch(plt.Rectangle((0.0, y - dy / 2), 1.0, dy,
                                       color="#f5f5f7", lw=0,
                                       transform=ax.transAxes, zorder=0))
        is_ctrl = r["id"] == "P0"
        good = r["opened_a_message"] if is_ctrl else r["rejected"]
        col = GREEN if good else RED
        ax.add_patch(plt.Rectangle((0.0, y - dy * 0.34), 0.01, dy * 0.68,
                                   color=col, transform=ax.transAxes,
                                   clip_on=False, zorder=1))

        ax.text(0.022, y, r["id"], fontsize=10, weight="bold",
                va="center", transform=ax.transAxes)

        tag = "control" if is_ctrl else _TAG.get(r["id"], "")
        if tag:
            tcol = GREY if is_ctrl else _TAG_COLOR[tag]
            ax.text(0.115, y, tag, fontsize=7.5, style="italic", color=tcol,
                    va="center", transform=ax.transAxes)

        ax.text(0.40, y, _SHORT.get(r["id"], r["name"]), fontsize=9,
                va="center", transform=ax.transAxes)

        verdict = ("opens $m_b$" if is_ctrl else "REJECTED") if good \
            else ("does NOT open" if is_ctrl else "OPENED (!)")
        ax.text(0.80, y, verdict, fontsize=8, va="center", ha="left",
                color="white", weight="bold", transform=ax.transAxes,
                bbox=dict(boxstyle="round,pad=0.3", facecolor=col,
                          edgecolor="none"))

    fig.tight_layout(rect=[0.01, 0.0, 0.99, 1.0])
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kems", nargs="+", default=["ML-KEM-768"])
    ap.add_argument("--with-ggh", action="store_true",
                    help="also run GGH_FO (shows KEM independence through KEMAdapter)")
    args = ap.parse_args()

    ensure_out()
    t0 = time.perf_counter()
    entries = [(k, _oqs_kem_factory(k), resolve_oqs(k)) for k in args.kems]
    if args.with_ggh:
        from modularot.cli import _gghfo_entry
        lab, fac, samp = _gghfo_entry(100)
        entries.append((lab, fac, samp))

    results = []
    for label, factory, sampler in entries:
        print(f"\n=== {label}")
        res = run_scenarios(factory, sampler, label)
        for r in res["scenarios"]:
            tag = "OK " if (r["opened_a_message"] if r["id"] == "P0"
                            else r["rejected"]) else "!! "
            print(f"  {tag}[{r['id']}] {r['name']}")
        print(f"  -> {'PASS' if res['pass'] else 'FAIL'}")
        results.append(res)

    slug = lambda s: s.lower().replace("_", "-")
    paths = []
    for res in results:
        p = f"{OUT}/component_reuse_{slug(res['label'])}.png"
        render(res, p)
        paths.append(p)

    with open(f"{OUT}/component_reuse.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nWrote {', '.join(paths)}  ({time.perf_counter() - t0:.1f}s)")


if __name__ == "__main__":
    main()
