"""
Sezione 6.4 -- Tentativi di estrazione di informazione nel modello semi-honest.

Due avversari passivi:

  Ricevente curioso  -- obiettivo: recuperare m_{1-b}. Non conoscendo
  sk_{1-b} (che per costruzione del campionatore oblivious non esiste), la
  mossa migliore e decapsulare ct_{i != b} con una chiave che possiede gia.
  ``receiver_cannot_read_other`` prova, per ogni i != b, sia una chiave
  fabbricata sia la vera sk_b del ricevente, su un'istanza di KEM fresca e su
  quella del ricevente; qui si riporta anche, in colonna separata, l'esito
  del solo tentativo con sk_b propria.

  Mittente curioso   -- obiettivo: apprendere b. La sua vista e la sola coppia
  (pk_0, pk_1); l'unica distinzione possibile e una differenza statistica fra
  chiave reale e chiave obliviosa, ovvero esattamente il problema dei test di
  Sezione 6.1. Qui si riportano gli esiti KS/verdetto per famiglia (letti da
  6.1_risultati.json se presente, altrimenti misurati velocemente) e si mostra
  che un test su singola chiave non separa i due gruppi.

Output: cap6_output/6.4_avversariale.png  +  6.4_avversariale.json
"""

import argparse
import json
import os
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from modularot.ot_protocol import (
    OTReceiver, OTSender, receiver_cannot_read_other, compute_pk_fingerprint,
    derive_key, build_associated_data, derive_nonce, _label, _oqs_kem_factory,
)
from modularot.oblivious_sampling import resolve_oqs

from cap6_common import (
    ensure_out, OUT, GREEN, RED, BLUE, GREY, all_cases, ks_two_sample,
    chi2_uniform_gof, wilson_hilferty_crit, subsample,
)


# ══════════════════════════════════════════════════════════════════════════════
#  ricevente curioso
# ══════════════════════════════════════════════════════════════════════════════

def diagnose_ntru_fo(samples=60):
    """Health of NTRU_FO._hash_to_randomness. The known failure mode:
    reading SHAKE with digest(1) in a loop re-reads the first byte, so r
    collapses to a constant polynomial (0, sum x^i, or its negation). With
    r = 0 the ciphertext c = r*h + m equals the plaintext and the FO
    re-encryption check stops binding the key -- any keypair decapsulates it.
    A correct XOF stream yields a fresh pseudorandom ternary r each time."""
    from modularot.custom_kems.ntru_fo.ntru_fo import NTRU_FO
    import secrets as _s
    impl = NTRU_FO(N=701, p=3, q=8192)
    impl.generate_keys()
    distinct = set()
    constant = zero = 0
    for _ in range(samples):
        r = impl._hash_to_randomness(_s.token_bytes(20), _s.token_bytes(32))
        cs = tuple(int(c) for c in r.coeffs())
        distinct.add(cs)
        if len(set(cs)) <= 1:
            constant += 1
        if not any(cs):
            zero += 1
    healthy = constant == 0 and len(distinct) == samples
    return {
        "samples": samples, "distinct_r": len(distinct),
        "constant_r_fraction": constant / samples,
        "zero_r_fraction": zero / samples, "healthy": healthy,
        "note": ("r pseudocasuale ternario, uno diverso per campione: sano"
                 if healthy else
                 "r degenere (forme costanti): la randomicita non lega"),
    }


def curious_receiver(factory, sampler, label, ns, reps):
    rows = []
    for n in ns:
        builtin_ok = 0
        own_sk_ok = 0
        for _ in range(reps):
            recv = OTReceiver(0, factory(), sampler, n=n)
            pks = recv.request()
            sender = OTSender(factory(), [f"m{i}".encode() for i in range(n)])
            cts, sealeds, sid = sender.transfer(pks)

            # (a) built-in adversary: fabricated secret key per non-chosen branch
            if receiver_cannot_read_other(factory, recv, cts, sealeds, sid):
                builtin_ok += 1

            # (b) extra: decapsulate ct_{i != b} with the receiver's OWN sk_b
            leaked = False
            for i in range(n):
                if i == recv.choice:
                    continue
                try:
                    ss = recv.kem.decaps(recv._real_sk, cts[i])
                except Exception:
                    continue
                fp = compute_pk_fingerprint(recv._pk[i])
                try:
                    key = derive_key(ss, sid, i, fp)
                    ad = build_associated_data(sid, i, fp, _label(i))
                    nonce = derive_nonce(ss, sid, i, fp, _label(i))
                    ChaCha20Poly1305(key).decrypt(nonce, sealeds[i], ad)
                    leaked = True
                except Exception:
                    pass
            if not leaked:
                own_sk_ok += 1
        rows.append({"n": n, "reps": reps,
                     "builtin_hidden": builtin_ok,
                     "own_sk_hidden": own_sk_ok,
                     "pass": builtin_ok == reps and own_sk_ok == reps})
    return {"label": label, "rows": rows,
            "pass": all(r["pass"] for r in rows)}


# ══════════════════════════════════════════════════════════════════════════════
#  mittente curioso  -- si riduce a Sezione 6.1
# ══════════════════════════════════════════════════════════════════════════════

def curious_sender(ggh_dim, keys, nks):
    """Per each family: the KS verdict from 6.1 (loaded or measured) plus a
    single-key chi^2 distribution (what the sender could compute from ONE pk),
    showing real and oblivious single-key statistics overlap."""
    loaded = {}
    p = f"{OUT}/6.1_risultati.json"
    if os.path.exists(p):
        for r in json.load(open(p)):
            loaded[r["family"]] = r

    out = []
    for case in all_cases(ggh_dim):
        nk = max(12, keys)
        reals = [case.real_key() for _ in range(nk)]
        obls = [case.sample(reals[i % len(reals)]) for i in range(nk)]
        if case.kind == "ggh":
            per_real = [case.hnf_stats(r)[2] for r in reals]
            per_obl = [case.hnf_stats(o)[2] for o in obls]
        else:
            per_real = [case.phi(r) for r in reals]
            per_obl = [case.phi(o) for o in obls]

        # single-key chi^2 vs uniform  (the sender's one-shot statistic)
        def sk_chi2(pools):
            vals = []
            for pk_vals in pools:
                if not pk_vals:
                    continue
                c, df, _ = chi2_uniform_gof(pk_vals, case.lo, case.hi, case.k)
                vals.append(c / df)          # normalised: ~1 under H0
            return vals
        chi_r, chi_o = sk_chi2(per_real), sk_chi2(per_obl)

        rec = loaded.get(case.family, {})
        ks = rec.get("passo2")
        if ks is None:
            a = subsample([v for r in per_real for v in r], nks)
            b = subsample([v for o in per_obl for v in o], nks)
            ks = ks_two_sample(a, b)
        out.append({
            "label": case.label, "family": case.family,
            "ks_D": ks["D"], "ks_threshold": ks["threshold"],
            "ks_reject": ks["reject"],
            "verdict_6_1": rec.get("verdict", "n.d."),
            "sk_chi2_real": chi_r, "sk_chi2_obl": chi_o,
            "sk_overlap": (min(chi_o) <= max(chi_r) and min(chi_r) <= max(chi_o))
            if chi_r and chi_o else True,
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  plotting
# ══════════════════════════════════════════════════════════════════════════════

def render(recv_res, send_res, path):
    fig = plt.figure(figsize=(15, 5.2 + 0.5 * len(recv_res)))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.05, 1.3])
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])

    fig.suptitle("Sezione 6.4  --  Tentativi di estrazione (modello "
                 "semi-honest)", fontsize=14, weight="bold", x=0.012,
                 ha="left", y=0.99)

    # -- ricevente curioso : matrix KEM x n ------------------------------
    ns = recv_res[0]["rows"] and [r["n"] for r in recv_res[0]["rows"]] or []
    ax1.set_title("Ricevente curioso -- $m_{1-b}$ resta nascosto?",
                  fontsize=11, loc="left", weight="bold")
    ax1.set_xlim(0, len(ns))
    ax1.set_ylim(0, len(recv_res) + 0.4)
    for i, rr in enumerate(recv_res):
        yy = len(recv_res) - 1 - i
        for j, row in enumerate(rr["rows"]):
            ax1.add_patch(plt.Rectangle((j + 0.06, yy + 0.12), 0.88, 0.76,
                          color=GREEN if row["pass"] else RED))
            ax1.text(j + 0.5, yy + 0.5,
                     f"{row['builtin_hidden']}/{row['own_sk_hidden']}",
                     ha="center", va="center", fontsize=7, color="white")
        ax1.text(-0.1, yy + 0.5, rr["label"], ha="right", va="center",
                 fontsize=8.5, color=RED if not rr["pass"] else "black")
    for j, n in enumerate(ns):
        ax1.text(j + 0.5, len(recv_res) + 0.05, f"n={n}", ha="center",
                 va="bottom", fontsize=8)
    ax1.set_xticks([]); ax1.set_yticks([])
    for sp in ax1.spines.values():
        sp.set_visible(False)
    failed = [r["label"] for r in recv_res if not r["pass"]]
    note = ("verde = ogni messaggio m_i con i != b resta nascosto.  cella = "
            "casi superati con chiave fabbricata / con sk_b propria.")
    diag = getattr(render, "_ntru_diag", None)
    if failed:
        note += (f"\nATTENZIONE: {', '.join(failed)} perde la privacy del "
                 "mittente: il ricevente apre gli altri messaggi m_i.")
        if diag and not diag["healthy"]:
            note += ("\nCausa: NTRU_FO._hash_to_randomness legge SHAKE con "
                     f"digest(1) in un loop -> r degenere "
                     f"({diag['zero_r_fraction']:.0%} dei casi r=0, "
                     "ciphertext = messaggio).")
    elif diag and diag["healthy"]:
        note += ("\nNTRU_FO._hash_to_randomness: r pseudocasuale ternario, "
                 f"distinto su tutti i {diag['samples']} campioni (dopo la "
                 "correzione della lettura XOF).")
    ax1.text(0, -0.9, note, fontsize=7.3, color="#555")

    # -- mittente curioso : KS D vs soglia ------------------------------
    labels = [s["label"] for s in send_res]
    D = [s["ks_D"] for s in send_res]
    thr = [s["ks_threshold"] for s in send_res]
    y = range(len(labels))
    ax2.barh([i + 0.15 for i in y], D, height=0.3, color=BLUE, label="$D_{n,m}$")
    ax2.barh([i - 0.15 for i in y], thr, height=0.3, color=GREY,
             label="soglia $c(0.05)\\sqrt{(n+m)/nm}$")
    ax2.set_yticks(list(y)); ax2.set_yticklabels(labels, fontsize=8)
    ax2.set_xlim(0, max(max(D), max(thr)) * 1.45)
    for i, s in enumerate(send_res):
        ax2.text(max(D[i], thr[i]) * 1.03, i,
                 "nessun vantaggio" if not s["ks_reject"] else "RIGETTA",
                 va="center", fontsize=7.5,
                 color=GREEN if not s["ks_reject"] else RED)
    ax2.set_title("Mittente curioso -- si riduce a Sezione 6.1\n"
                  "(distinguere pk reale da pk obliviosa)", fontsize=11,
                  loc="left", weight="bold")
    ax2.set_xlabel("statistica di Kolmogorov-Smirnov (test primario)",
                   fontsize=8)
    ax2.legend(fontsize=7.5, frameon=False, loc="lower right",
               bbox_to_anchor=(1.0, -0.16), ncol=2)
    ax2.invert_yaxis()

    fig.tight_layout(rect=[0, 0.05, 1, 0.93])
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--kems", nargs="+",
                    default=["ML-KEM-768", "FrodoKEM-640-AES", "NTRU-HRSS-701",
                             "sntrup761"])
    ap.add_argument("--ns", nargs="+", type=int, default=[2, 3, 4, 8])
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--ggh-dim", type=int, default=80)
    ap.add_argument("--sender-keys", type=int, default=60)
    args = ap.parse_args()
    if args.quick:
        args.ns, args.reps, args.sender_keys, args.ggh_dim = [2, 4], 4, 24, 60

    ensure_out()
    t0 = time.perf_counter()

    entries = [(k, _oqs_kem_factory(k), resolve_oqs(k)) for k in args.kems]
    try:
        from modularot.cli import _ntrufo_entry, _gghfo_entry
        entries.append(_ntrufo_entry(701))
        entries.append(_gghfo_entry(args.ggh_dim))
    except Exception as e:
        print(f"  (custom KEM esclusi: {e})")

    ntru_diag = diagnose_ntru_fo()
    render._ntru_diag = ntru_diag
    print(f"\n=== diagnosi NTRU_FO._hash_to_randomness: "
          f"{ntru_diag['distinct_r']}/{ntru_diag['samples']} r distinti, "
          f"costanti {ntru_diag['constant_r_fraction']:.0%}, "
          f"r=0 {ntru_diag['zero_r_fraction']:.0%}  -> "
          f"{'SANO' if ntru_diag['healthy'] else 'DEGENERE'}")

    recv_res = []
    for label, factory, sampler in entries:
        print(f"\n=== ricevente curioso: {label}")
        r = curious_receiver(factory, sampler, label, args.ns, args.reps)
        for row in r["rows"]:
            print(f"  n={row['n']}: builtin {row['builtin_hidden']}/{row['reps']}"
                  f", sk_b propria {row['own_sk_hidden']}/{row['reps']}  "
                  f"{'OK' if row['pass'] else 'FAIL'}")
        recv_res.append(r)

    print("\n=== mittente curioso (riduzione a Sezione 6.1)")
    send_res = curious_sender(args.ggh_dim, args.sender_keys, 8000)
    for s in send_res:
        print(f"  {s['label']}: KS D={s['ks_D']:.4f} soglia={s['ks_threshold']:.4f}"
              f" -> {'nessun vantaggio' if not s['ks_reject'] else 'RIGETTA'}"
              f"  (6.1: {s['verdict_6_1']})")

    render(recv_res, send_res, f"{OUT}/6.4_avversariale.png")
    with open(f"{OUT}/6.4_avversariale.json", "w") as f:
        json.dump({"ricevente_curioso": recv_res, "mittente_curioso": send_res,
                   "diagnosi_ntru_fo": ntru_diag}, f, indent=2, default=float)
    print(f"\nScritto {OUT}/6.4_avversariale.png  ({time.perf_counter() - t0:.1f}s)")


if __name__ == "__main__":
    main()
