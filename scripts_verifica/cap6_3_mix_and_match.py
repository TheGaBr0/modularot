"""
Sezione 6.3 -- L'attacco mix-and-match.

Riproduce i disallineamenti descritti nella sezione: il riuso di un oggetto
prodotto per la tripla $(\\text{sid}, i, pk_i)$ al posto di quello atteso per
una tripla diversa. Nel framework ogni chiave/nonce/AD e derivata da
$(\\mathit{ss}, \\text{sid}, i, \\mathrm{fp}(pk_i), \\text{label}_i)$ tramite HKDF
+ ChaCha20-Poly1305 (vedi ot_protocol.py: ``derive_key``,
``build_associated_data``, ``derive_nonce``). Il legame alla tripla e cio che
rende non intercambiabili gli oggetti.

Scenari verificati (ognuno deve essere RESPINTO):
  S1  errore di indicizzazione: aprire il blob del messaggio 0 come se fosse
      il messaggio b, e viceversa;
  S2  ss/chiave accoppiati alla chiave pubblica sbagliata ($pk_j$, $j\\ne i$);
  S3  riuso cross-sessione: blob sigillati della sessione A aperti con il
      sid della sessione B;
  S4  due esecuzioni con gli stessi $(m_0, m_1)$ ma sid diverso: i ciphertext
      NON sono intercambiabili;
  S5  riuso di $ct_i$ in una nuova sessione: la decapsulazione da un nuovo
      $ss$, quindi il vecchio blob non apre.
Controllo positivo P0: l'esecuzione onesta apre correttamente $m_b$.

Output: cap6_output/6.3_mix_and_match_<kem-slug>.png (uno per KEM)
        + 6.3_mix_and_match.json
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

from cap6_common import ensure_out, OUT, GREEN, RED, GREY, BLUE, ORANGE

# S1/S3/S5 sono disallineamenti accidentali (errore di indicizzazione, riuso
# involontario fra sessioni); S2/S4 richiedono una manomissione deliberata e
# ricadono fuori dal modello semi-honest (hardening). Vedi Sezione 6.3.
_TAG = {"S1a": "accidentale", "S1b": "accidentale", "S3": "accidentale",
        "S5": "accidentale", "S2": "deliberato", "S4": "deliberato"}
_TAG_COLOR = {"accidentale": BLUE, "deliberato": ORANGE}

# Etichette brevi per la figura: la spiegazione estesa di ogni scenario resta
# nell'elenco puntato del Capitolo 7, la figura deve solo essere leggibile a
# colpo d'occhio una volta stampata a larghezza pagina.
_SHORT = {
    "P0": "Esecuzione onesta",
    "S1a": "Indice sbagliato, chiave giusta",
    "S1b": "Indice e chiave sbagliati",
    "S2": "Chiave pubblica sbagliata",
    "S3": "Sid di un'altra sessione",
    "S4": "Ciphertext scambiati fra sessioni",
    "S5": "Riuso del ciphertext KEM",
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
    m = [b"MESSAGGIO-0::" + label.encode(),
         b"MESSAGGIO-1::" + label.encode()]

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
    R.append({"id": "P0", "name": "esecuzione onesta",
              "desc": f"finalize corretta -> m_{choice}",
              "opened_a_message": honest == m[choice],
              "rejected": False, "mechanism": "--",
              "control_ok": honest == m[choice]})

    # S1  branch-index misuse (receiver holds ss for `choice` only)
    o = _try_open(ssA_b, sidA, choice, fp[other], sealedsA[other])
    rec("S1a", "indice: blob di un altro messaggio, chiave di quello scelto",
        f"apri sealed[{other}] con (ss_{choice}, i={choice}, pk_{choice})", o,
        "HKDF info + AEAD AD (ss e pk non combaciano)")
    o = _try_open(ssA_b, sidA, other, fp[other], sealedsA[other])
    rec("S1b", "indice: blob e derivazione di un altro messaggio",
        f"apri sealed[{other}] con (ss_{choice}, i={other}, pk_{other})", o,
        "ss del messaggio scelto != ss_{}".format(other))

    # S2  ss/key bound to the wrong public key
    o = _try_open(ssA_b, sidA, choice, fp[other], sealedsA[choice])
    rec("S2", "cross-pk: fingerprint di pk_j, j != i",
        f"apri sealed[{choice}] con fp(pk_{other}) al posto di fp(pk_{choice})",
        o, "HKDF info + AEAD AD legano fp(pk_i)")

    # S3  cross-session: A's blobs opened under B's sid
    o = _try_open(ssA_b, sidB, choice, fp[choice], sealedsA[choice])
    rec("S3", "cross-sessione: blob di A, sid di B",
        "apri sealed_A con sid_B", o, "HKDF salt+info e AEAD AD legano sid")

    # S4  same (m0,m1), different sid -> ciphertexts not interchangeable
    interchangeable = sealedsA[choice] == sealedsB[choice]
    o = recv.finalize(ctsA, sealedsB, sidA)   # A's ct/sid, B's sealed blobs
    R.append({"id": "S4", "name": "stessi messaggi, sid diverso",
              "desc": "sealed_A vs sealed_B con (m0,m1) uguali",
              "opened_a_message": o == m[choice],
              "rejected": o != m[choice],
              "identical_ciphertexts": interchangeable,
              "mechanism": "nonce/chiave legati a sid -> blob distinti"})

    # S5  reuse ct_i in a new session
    o = recvB.finalize(ctsA, sealedsA, sidA)  # B's receiver, A's transcript
    #    B decapsulated a different keypair -> ss differs -> AEAD fails
    R.append({"id": "S5", "name": "riuso di ct_i in nuova sessione",
              "desc": "receiver B esegue finalize sul transcript di A",
              "opened_a_message": o == m[choice],
              "rejected": o != m[choice],
              "mechanism": "decaps con sk diversa -> ss diverso"})

    all_rejected = all(r["rejected"] for r in R if r["id"] != "P0")
    control_ok = R[0]["opened_a_message"]
    return {"label": label, "choice": choice, "scenarios": R,
            "all_rejected": all_rejected, "control_ok": control_ok,
            "pass": all_rejected and control_ok}


# ══════════════════════════════════════════════════════════════════════════════

def render(res, path):
    """Renders a single KEM's scenario table to its own figure/file: one
    row per scenario (id, tipo, nome breve, esito), niente altro -- la
    spiegazione estesa di ogni caso resta nel testo del capitolo. La figura
    e' disegnata alla stessa larghezza con cui finisce stampata
    (\\textwidth = 6in nella tesi), cosi' i font restano alla loro
    dimensione reale invece di rimpicciolirsi nello scalare l'immagine in
    pagina."""
    rows = res["scenarios"]
    n = len(rows)
    fig, ax = plt.subplots(figsize=(6.3, 0.85 + 0.46 * n))
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    ax.text(0.0, 0.975, f"{res['label']}  ·  $m_{res['choice']}$", fontsize=12,
            weight="bold", va="top", ha="left", transform=ax.transAxes)

    header_y = 0.895
    for x, label in ((0.0, "SCEN."), (0.115, "TIPO"),
                     (0.40, "COSA SI TESTA"), (0.80, "ESITO")):
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

        tag = "controllo" if is_ctrl else _TAG.get(r["id"], "")
        if tag:
            tcol = GREY if is_ctrl else _TAG_COLOR[tag]
            ax.text(0.115, y, tag, fontsize=7.5, style="italic", color=tcol,
                    va="center", transform=ax.transAxes)

        ax.text(0.40, y, _SHORT.get(r["id"], r["name"]), fontsize=9,
                va="center", transform=ax.transAxes)

        verdict = ("apre $m_b$" if is_ctrl else "RESPINTO") if good \
            else ("NON apre" if is_ctrl else "APERTO (!)")
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
                    help="include GGH_FO (dimostra l'indipendenza dal KEM "
                         "attraverso il KEMAdapter)")
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
        p = f"{OUT}/6.3_mix_and_match_{slug(res['label'])}.png"
        render(res, p)
        paths.append(p)

    with open(f"{OUT}/6.3_mix_and_match.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nScritti {', '.join(paths)}  ({time.perf_counter() - t0:.1f}s)")


if __name__ == "__main__":
    main()
