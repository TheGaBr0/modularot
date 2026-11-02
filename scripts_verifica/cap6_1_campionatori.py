"""
Sezione 6.1 -- Verifica della correttezza dei campionatori oblivious.

Executes, for every sampler of Table ``tab:phi-schemi``, the four steps of
Sezione 6.1 and renders one report figure per family plus a summary matrix, a
results JSON and a booktabs table ready for Capitolo 7.

  Passo 1  verifica strutturale     Encode(Decode(pk_reale)) == pk_reale
  Passo 2  test primario  KS        D_{n,m}  vs  1.36 sqrt((n+m)/nm)
  Passo 3  test secondario Pearson  chi^2 vs uniforme, reali E oblivious,
                                    soglia di Wilson-Hilferty
  Passo 4  metriche descrittive     entropia di Shannon, min-entropia MCV

Verdetto: il campionatore e ``rotto`` se Passo 1 fallisce, se Passo 2 rigetta
H0, oppure se al Passo 3 le sole chiavi oblivious rigettano l'adattamento
all'uniforme mentre le reali no. Altrimenti resta ``nessun distinguisher
trovato``.

Uso (dalla root di MODULAROT):
  .venv/bin/python scripts_verifica/cap6_1_campionatori.py
  .venv/bin/python scripts_verifica/cap6_1_campionatori.py --quick
  .venv/bin/python scripts_verifica/cap6_1_campionatori.py --only ML-KEM GGH_FO
"""

import argparse
import json
import math
import random
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cap6_common import (
    all_cases, ensure_out, subsample, ks_two_sample, ks_repeated, ecdf,
    chi2_verdict, descriptive, OUT, BLUE, RED, GREEN,
)

VERDICT_OK = "nessun distinguisher trovato"
VERDICT_BROKEN = "campionatore rotto"


# ══════════════════════════════════════════════════════════════════════════════
#  measurement
# ══════════════════════════════════════════════════════════════════════════════

def run_case(case, n_keys, n_ks):
    t0 = time.perf_counter()
    reals = [case.real_key() for _ in range(n_keys)]
    obls = [case.sample(reals[i % len(reals)]) for i in range(n_keys)]

    res = {"family": case.family, "label": case.label, "section": case.section,
           "kind": case.kind, "unit": case.unit, "n_keys": n_keys,
           "domain": [case.lo, case.hi], "k_classes": case.k}

    # ---- Passo 1: verifica strutturale ---------------------------------------
    mism = sum(0 if case.roundtrip_ok(r) else 1 for r in reals)
    enc_ok = sum(1 for o in obls if case.encaps_ok(o))
    res["passo1"] = {
        "name": "verifica strutturale  Encode(Decode(pk))==pk",
        "mismatch": mism, "checked": len(reals),
        "encaps_accept": enc_ok, "encaps_total": len(obls),
        "pass": mism == 0,
    }

    # ---- phi pools ---------------------------------------------------------
    #  GGH: ogni chiave contribuisce un blocco correlato di residui (una
    #  colonna densa della forma di Hermite). Il pool completo (~2e4) e usato
    #  per la statistica D del Passo 2 e per la figura; le osservazioni
    #  indipendenti sono pero ~n_keys, quindi la soglia del Passo 2 usa
    #  n_eff = n_keys e il Passo 3/4 lavorano su un residuo per chiave
    #  (estratto in modo deterministico).
    if case.kind == "ggh":
        rs = [case.hnf_stats(r) for r in reals]
        os_ = [case.hnf_stats(o) for o in obls]
        real_pool = [v for s in rs for v in s[2]]
        obl_pool = [v for s in os_ for v in s[2]]
        _rng = random.Random(0xC6)
        real_dec = [_rng.choice(s[2]) for s in rs if s[2]]
        obl_dec = [_rng.choice(s[2]) for s in os_ if s[2]]
        res["ggh_extra"] = {
            "log2det_real": [s[0] for s in rs],
            "log2det_obl": [s[0] for s in os_],
            "nontrivial_real": [s[1] for s in rs],
            "nontrivial_obl": [s[1] for s in os_],
            "n_indip": len(real_dec),
        }
    else:
        real_pool = [v for r in reals for v in case.phi(r)]
        obl_pool = [v for o in obls for v in case.phi(o)]
        real_dec, obl_dec = real_pool, obl_pool

    res["pool_size"] = [len(real_pool), len(obl_pool)]

    # ---- Passo 2: Kolmogorov-Smirnov -------------------------------------
    n_eff = n_keys if case.kind == "ggh" else None
    ks = ks_repeated(real_pool, obl_pool, n_ks, n_eff=n_eff)
    res["passo2"] = {"name": "test primario Kolmogorov-Smirnov", **ks,
                     "pass": not ks["reject"]}
    if case.kind == "ggh":
        res["passo2_log2det"] = ks_two_sample(res["ggh_extra"]["log2det_real"],
                                              res["ggh_extra"]["log2det_obl"])
        res["passo2_nontrivial"] = ks_two_sample(
            res["ggh_extra"]["nontrivial_real"],
            res["ggh_extra"]["nontrivial_obl"])

    # ---- Passo 3: Pearson chi-square -----------------------------------
    #  Il confronto significativo e fra i due VERDETTI (Sez. 6.1): "entrambi
    #  la rigettano di poco" resta un successo. Passo 3 segnala un problema
    #  solo se le chiavi oblivious rigettano in modo grossolano mentre le
    #  reali no (oltre ~5 deviazioni standard di rumore, sigma = sqrt(2 df)).
    cr = chi2_verdict(real_dec, case.lo, case.hi, case.k)
    co = chi2_verdict(obl_dec, case.lo, case.hi, case.k)
    noise = 5.0 * math.sqrt(2.0 * cr["df"])
    gross = co["reject"] and (not cr["reject"]) and (co["chi2"] - cr["chi2"] > noise)
    coherent = not gross
    res["passo3"] = {"name": "test secondario Pearson chi^2",
                     "real": cr, "obl": co, "noise_band": noise,
                     "coherent": coherent, "pass": coherent}

    # ---- Passo 4: metriche descrittive ---------------------------------
    #  Numeri descrittivi, non un test: si usa l'intero pool (stima migliore
    #  della legge marginale), anche per GGH.
    dr = descriptive(real_pool, case.lo, case.hi, case.k)
    do = descriptive(obl_pool, case.lo, case.hi, case.k)
    res["passo4"] = {"name": "metriche descrittive", "real": dr, "obl": do}

    # ---- verdetto -----------------------------------------------------
    #  Passo 1 e Passo 2 (primario) determinano l'esito; Passo 3 contribuisce
    #  solo con una discrepanza grossolana (vedi sopra).
    broken = (not res["passo1"]["pass"]) or res["passo2"]["reject"] or gross
    res["verdict"] = VERDICT_BROKEN if broken else VERDICT_OK
    res["_pools"] = (real_pool, obl_pool)
    res["_elapsed"] = time.perf_counter() - t0
    return res


# ══════════════════════════════════════════════════════════════════════════════
#  plotting -- one panel per Passo
# ══════════════════════════════════════════════════════════════════════════════

def _panel_passo2(ax, res):
    real_pool, obl_pool = res["_pools"]
    xs_r, ys_r = ecdf(subsample(real_pool, 4000))
    xs_o, ys_o = ecdf(subsample(obl_pool, 4000))
    ax.step(xs_r, ys_r, where="post", color=BLUE, lw=1.5, label="reali $F_n$")
    ax.step(xs_o, ys_o, where="post", color=RED, lw=1.5, label="oblivious $G_m$")
    ks = res["passo2"]
    if ks.get("D_at") is not None:
        ax.axvline(ks["D_at"], color="#333", ls="--", lw=1)
    verdict = "RIGETTA $H_0$" if ks["reject"] else "non rigetta $H_0$"
    ax.set_title(f"Passo 2 -- Kolmogorov-Smirnov: {verdict}", fontsize=12,
                 loc="left", weight="bold")
    ax.set_ylabel("frequenza cumulata", fontsize=10)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=10, frameon=False, loc="lower right")


def _panel_passo3(ax, res):
    cr, co = res["passo3"]["real"], res["passo3"]["obl"]
    coherent = res["passo3"]["coherent"]
    vals = [cr["chi2"], co["chi2"]]
    bars = ax.bar(["reali", "oblivious"], vals, color=[BLUE, RED], width=0.5,
                  alpha=0.85)
    top = max(vals + [cr["crit"]]) * 1.35
    ax.axhline(cr["crit"], color="#333", ls="--", lw=1.2)
    ax.text(0.98, 0.96, f"soglia Wilson-Hilferty = {cr['crit']:.0f}",
            transform=ax.transAxes, fontsize=9, va="top", ha="right",
            color="#333")
    for bmark, v in zip(bars, vals):
        cx = bmark.get_x() + bmark.get_width() / 2
        ax.text(cx, v / 2, f"{v:.0f}", ha="center", va="center", fontsize=12,
                color="white", weight="bold")
    verdict = "verdetti coerenti" if coherent else "verdetti DISCORDI"
    ax.set_title(f"Passo 3 -- $\\chi^2$ vs uniforme: {verdict}", fontsize=12,
                 loc="left", weight="bold")
    ax.tick_params(labelsize=9)
    ax.set_ylabel("$\\chi^2$", fontsize=10)
    ax.set_ylim(0, top)


def _panel_passo4(ax, res):
    dr, do = res["passo4"]["real"], res["passo4"]["obl"]
    groups = ["Shannon $H$", "min-entropia $H_\\infty$ (MCV)"]
    real = [dr["shannon"], dr["H_inf_mcv"]]
    obl = [do["shannon"], do["H_inf_mcv"]]
    x = range(len(groups))
    ax.bar([i - 0.16 for i in x], real, width=0.32, color=BLUE)
    ax.bar([i + 0.16 for i in x], obl, width=0.32, color=RED)
    top = dr["shannon_max"] * 1.18
    ax.axhline(dr["shannon_max"], color="#333", ls="--", lw=1)
    for i, (rv, ov) in enumerate(zip(real, obl)):
        ax.text(i - 0.16, rv + top * 0.012, f"{rv:.2f}", ha="center",
                va="bottom", fontsize=9, color=BLUE)
        ax.text(i + 0.16, ov + top * 0.012, f"{ov:.2f}", ha="center",
                va="bottom", fontsize=9, color=RED)
    ax.set_xticks(list(x))
    ax.set_xticklabels(groups, fontsize=10)
    ax.set_xlim(-0.55, len(groups) - 0.45)
    ax.set_title(f"Passo 4 -- entropia (blu reali, rosso oblivious; "
                 f"tratteggio: massimo $\\log_2 k = {dr['shannon_max']:.2f}$)",
                 fontsize=11, loc="left", weight="bold")
    ax.set_ylim(0, top)
    ax.tick_params(labelsize=9)
    ax.set_ylabel("bit", fontsize=10)


HEADER = True   # set False (--no-header) for figures embedded in the thesis,
                # where title and verdict belong in the LaTeX caption


def render_case(res, path):
    # 2 pannelli sopra (KS, chi^2), il terzo (metriche descrittive) sotto,
    # centrato: pannelli piu grandi e leggibili di una fila da tre.
    broken = res["verdict"] == VERDICT_BROKEN
    fig = plt.figure(figsize=(13, 7.8 if not HEADER else 8.5))
    gs = fig.add_gridspec(2, 4, hspace=0.30, wspace=0.7)
    ax_ks = fig.add_subplot(gs[0, 0:2])
    ax_chi = fig.add_subplot(gs[0, 2:4])
    ax_desc = fig.add_subplot(gs[1, 1:3])
    if HEADER:
        fig.suptitle(f"Sezione 6.1  --  {res['label']}  --  {res['family']}",
                     fontsize=15, weight="bold", x=0.06, ha="left", y=0.985)
        fig.text(0.06, 0.955,
                 f"$\\varphi(pk)$: {res['unit']} su $[{res['domain'][0]}, "
                 f"{res['domain'][1]})$   |   {res['pool_size'][0]} valori reali, "
                 f"{res['pool_size'][1]} oblivious ({res['n_keys']} chiavi per "
                 f"gruppo)   |   verdetto: {res['verdict'].upper()}",
                 fontsize=10, ha="left", va="top",
                 color=RED if broken else GREEN)
    _panel_passo2(ax_ks, res)
    _panel_passo3(ax_chi, res)
    _panel_passo4(ax_desc, res)
    fig.subplots_adjust(left=0.07, right=0.97, bottom=0.07,
                        top=0.92 if HEADER else 0.97)
    fig.savefig(path, dpi=140)
    plt.close(fig)


def render_summary(all_res, path):
    labels = ["Passo 2\nKS", "Passo 3\n$\\chi^2$", "verdetto"]
    fig, ax = plt.subplots(figsize=(2.0 * len(labels) + 3.5,
                                    0.7 * len(all_res) + 1.8))
    ax.set_xlim(0, len(labels))
    ax.set_ylim(0, len(all_res) + 0.6)
    for i, r in enumerate(all_res):
        yy = len(all_res) - 1 - i
        cells = [
            r["passo2"]["pass"], r["passo3"]["pass"],
            r["verdict"] == VERDICT_OK,
        ]
        for j, ok in enumerate(cells):
            ax.add_patch(plt.Rectangle((j + 0.06, yy + 0.12), 0.88, 0.76,
                                       color=GREEN if ok else RED))
        ax.text(-0.12, yy + 0.5, r["label"], ha="right", va="center", fontsize=9)
    for j, lab in enumerate(labels):
        ax.text(j + 0.5, len(all_res) + 0.08, lab, ha="center", va="bottom",
                fontsize=8)
    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Sezione 6.1 -- riepilogo verifica campionatori "
                 "(verde = supera / rosso = rigetta)", fontsize=11, weight="bold",
                 pad=26)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def write_latex_table(all_res, path):
    rows = []
    for r in all_res:
        ks = r["passo2"]
        cr, co = r["passo3"]["real"], r["passo3"]["obl"]
        d4r, d4o = r["passo4"]["real"], r["passo4"]["obl"]
        rows.append(
            f"{r['label'].replace('_', r'\_')} & {ks['D']:.4f} & "
            f"{ks['threshold']:.4f} & "
            f"{'sì' if ks['reject'] else 'no'} & "
            f"{cr['chi2']:.0f} / {co['chi2']:.0f} & {cr['crit']:.0f} & "
            f"{d4o['shannon']:.2f} & {d4o['H_inf_mcv']:.2f} & "
            f"{'rotto' if r['verdict'] == VERDICT_BROKEN else 'ok'} \\\\"
        )
    body = "\n".join(rows)
    tex = (
        "% generato da scripts_verifica/cap6_1_campionatori.py\n"
        "\\begin{table}[H]\n\\centering\\small\n"
        "\\begin{tabular}{@{}lrrcrrrrc@{}}\n\\toprule\n"
        "\\textbf{Schema} & $D_{n,m}$ & soglia & rig. & "
        "$\\chi^2$ r/o & crit & $H$ obl & $H_\\infty$ obl & esito \\\\\n"
        "\\midrule\n" + body + "\n\\bottomrule\n\\end{tabular}\n"
        "\\caption{Sezione~6.1: esito dei quattro passi per ciascun "
        "campionatore. $\\chi^2$ r/o = valore su chiavi reali / oblivious; "
        "soglia $\\chi^2$ di Wilson-Hilferty ad $\\alpha=0{,}05$.}\n"
        "\\label{tab:cap6-verifica-campionatori}\n\\end{table}\n"
    )
    with open(path, "w") as f:
        f.write(tex)


def json_safe(res):
    return {k: v for k, v in res.items() if not k.startswith("_")}


# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", nargs="+")
    ap.add_argument("--keys", type=int, default=200)
    ap.add_argument("--keys-custom", type=int, default=200)
    ap.add_argument("--keys-ggh", type=int, default=200)
    ap.add_argument("--nks", type=int, default=20000)
    ap.add_argument("--ggh-dim", type=int, default=100)
    ap.add_argument("--no-header", action="store_true",
                    help="omit the baked-in title/verdict (for thesis figures)")
    args = ap.parse_args()

    if args.no_header:
        globals()["HEADER"] = False
    if args.quick:
        args.keys, args.keys_custom, args.keys_ggh, args.nks = 60, 40, 20, 6000

    ensure_out()
    cases = all_cases(args.ggh_dim)
    if args.only:
        want = set(args.only)
        cases = [c for c in cases if c.family in want or c.label in want]

    all_res = []
    for case in cases:
        if case.family == "GGH_FO":
            nk = args.keys_ggh
        elif case.family == "NTRU_FO":
            nk = args.keys_custom
        else:
            nk = args.keys
        print(f"\n=== {case.label} ({case.family})  n_keys={nk}")
        try:
            res = run_case(case, nk, args.nks)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"  !! {case.label} fallito: {e}")
            continue
        p = f"{OUT}/6.1_{case.family}.png"
        render_case(res, p)
        with open(f"{OUT}/6.1_{case.family}.json", "w") as f:
            json.dump(json_safe(res), f, indent=2, default=float)
        all_res.append(res)
        print(f"  Passo1 {'OK' if res['passo1']['pass'] else 'FAIL'} | "
              f"Passo2 D={res['passo2']['D']:.4f} "
              f"({int(res['passo2']['reject_fraction'] * res['passo2']['reps'])}"
              f"/{res['passo2']['reps']} rigetti) "
              f"{'RIGETTA' if res['passo2']['reject'] else 'ok'} | "
              f"Passo3 r/o chi2 {res['passo3']['real']['chi2']:.0f}/"
              f"{res['passo3']['obl']['chi2']:.0f} "
              f"({'coerenti' if res['passo3']['coherent'] else 'DISCORDI'}) | "
              f"-> {res['verdict']}  ({res['_elapsed']:.1f}s)")

    if all_res:
        render_summary(all_res, f"{OUT}/6.1_riepilogo.png")
        write_latex_table(all_res, f"{OUT}/tabella_6.1.tex")
        with open(f"{OUT}/6.1_risultati.json", "w") as f:
            json.dump([json_safe(r) for r in all_res], f, indent=2, default=float)
        print(f"\nScritti {len(all_res)} report + riepilogo + tabella in {OUT}/")


if __name__ == "__main__":
    main()
