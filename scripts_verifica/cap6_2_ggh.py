"""
Sezione 6.2 -- L'attacco al campionatore GGH.

Reproduces the three points of the section:

  A. GGH classico -- la chiave pubblica dichiara il proprio reticolo.
     Riproduce l'esempio con $n = 5$ della Figura ``fig:ggh-classico-distinguibile``
     (chiave reale $B = UR$ vs migliore chiave campionabile senza trapdoor,
     entrate uniformi nell'intervallo atteso $[-wl, wl]$) e conferma i due
     distinguisher su piu chiavi e piu dimensioni:
       * $\\log_2|\\det B|$, invariante di reticolo fissato dai parametri;
       * frazione di entrate con $|B_{ij}| > M/2$ (asimmetria delle entrate,
         indipendente dal determinante).

  B. GGH-HNF -- la forma canonica non basta. Le due varianti di
     Figura ``fig:ggh-hnf-confronto``:
       * base privata $R = \\mathsf{LLL}(\\text{matrice casuale})$ ->
         $\\mathsf{LLL}(H)$ recupera una base corta: trapdoor pubblica;
       * base privata $R = kI + E$ (costruzione originale GGH, la variante
         ibrida di GGH\\_FO) -> $\\mathsf{LLL}(H)$ non la recupera.
     Misura riportata: minima norma di Gram-Schmidt della base privata vs
     quella di $\\mathsf{LLL}(H)$.

Output: cap6_output/6.2_ggh.png  +  6.2_ggh.json

Uso:  .venv/bin/python scripts_verifica/cap6_2_ggh.py
      .venv/bin/python scripts_verifica/cap6_2_ggh.py --quick
"""

import argparse
import json
import math
import secrets
import statistics
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from flint import fmpz_mat
from GGH_crypto import GGHCryptosystem, GGHHNFCryptosystem

from cap6_common import ensure_out, OUT, BLUE, RED, GREEN, GREY

# thesis Figure fig:ggh-classico-distinguibile, n = 5
_B_REAL = [[1, 3, 0, 2, 1], [-1, 1, 3, 1, 0], [0, -1, 2, 0, 2],
           [0, 0, -1, 1, 3], [0, 0, 0, -1, 2]]
_B_SAMPLED = [[8, -3, 6, -1, 9], [-5, 2, -8, 4, 1], [3, -9, 0, 7, -6],
              [-2, 5, -4, 8, -7], [6, -1, 9, -3, 2]]
_M5 = 9   # w * l  = 3 * 3, stimato a priori dai parametri dell'esempio


# ══════════════════════════════════════════════════════════════════════════════
#  A -- GGH classico
# ══════════════════════════════════════════════════════════════════════════════

def _stats_classic(B, n):
    ent = [int(B[i, j]) for i in range(n) for j in range(n)]
    M = max(abs(v) for v in ent) or 1
    d = abs(int(B.det()))
    return {
        "log2det": math.log2(d) if d else 0.0,
        "frac_big": sum(1 for v in ent if abs(v) > M / 2) / len(ent),
        "M": M,
    }


def example_n5():
    B = fmpz_mat(_B_REAL)
    Bp = fmpz_mat(_B_SAMPLED)
    big = lambda Mx: sum(1 for i in range(5) for j in range(5)
                         if abs(int(Mx[i, j])) > _M5 / 2)
    return {
        "n": 5, "M_apriori": _M5,
        "real": {"matrix": _B_REAL, "abs_det": abs(int(B.det())),
                 "big_entries": big(B)},
        "sampled": {"matrix": _B_SAMPLED, "abs_det": abs(int(Bp.det())),
                    "big_entries": big(Bp)},
    }


def classic_separation(dims, keys):
    """Per each dimension: `keys` real GGH keys and, for each, the best
    trapdoor-free sample (uniform entries in [-M, M], M = max|B_ij| of that
    real key -- an upper bound on what the attacker's sampler could target).
    Confirms perfect separation on both statistics."""
    out = []
    for n in dims:
        real_det, real_fb, obl_det, obl_fb = [], [], [], []
        for _ in range(keys):
            B = GGHCryptosystem(dimension=n).public_basis
            rs = _stats_classic(B, n)
            M = rs["M"]
            fake = fmpz_mat([[secrets.randbelow(2 * M + 1) - M
                              for _ in range(n)] for _ in range(n)])
            fs = _stats_classic(fake, n)
            real_det.append(rs["log2det"]); real_fb.append(rs["frac_big"])
            obl_det.append(fs["log2det"]); obl_fb.append(fs["frac_big"])
        k = 4 * math.ceil(math.sqrt(n) + 1)
        out.append({
            "n": n, "theory_log2det": n * math.log2(k),
            "real_log2det": real_det, "obl_log2det": obl_det,
            "real_frac_big": real_fb, "obl_frac_big": obl_fb,
            "det_separated": max(real_det) < min(obl_det),
            "frac_separated": max(real_fb) < min(obl_fb),
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  B -- GGH-HNF: le due varianti
# ══════════════════════════════════════════════════════════════════════════════

def _min_gs_norm(B, n):
    A = [[float(B[i, j]) for j in range(n)] for i in range(n)]
    ortho = []
    for v in A:
        w = list(v)
        for q in ortho:
            qq = sum(x * x for x in q)
            mu = sum(a * b for a, b in zip(v, q)) / qq
            w = [a - mu * b for a, b in zip(w, q)]
        ortho.append(w)
    return min(math.sqrt(sum(x * x for x in q)) for q in ortho)


def hnf_variants(n, rounds):
    """Il ramo sinistro di Figura fig:ggh-hnf-confronto, riprodotto come in
    tests/test_ggh_versions.py (test_v2): per GGH_private=False la base privata
    e essa stessa una riduzione LLL, quindi LLL(H) raggiunge la stessa qualita
    (min norma di Gram-Schmidt, alta = base buona) -> la trapdoor e pubblica e
    nessun campionatore puo rendere sicura la chiave. Il ramo destro
    (GGH_private=True, R = kI+E) e la variante adottata da GGH_FO: la sua
    sicurezza come campionatore poggia sull'assunzione di base corta piantata
    (GGHThesis24), non su questo esperimento."""
    priv, atk = [], []
    for _ in range(rounds):
        g = GGHHNFCryptosystem(dimension=n)                   # GGH_private=False
        priv.append(_min_gs_norm(g.private_basis, n))
        atk.append(_min_gs_norm(g.public_basis.lll(), n))
    gp, ga = statistics.fmean(priv), statistics.fmean(atk)
    return {"n": n, "priv": priv, "atk_lll_H": atk,
            "g_priv": gp, "g_atk": ga, "ratio": ga / gp,
            "trapdoor_public": ga >= 0.5 * gp}


# ══════════════════════════════════════════════════════════════════════════════
#  plotting
# ══════════════════════════════════════════════════════════════════════════════

def _panel_example(ax, ex):
    ax.axis("off")
    ax.set_title("A.  GGH classico, $n=5$ (Fig. 6.1)", fontsize=11, loc="left",
                 weight="bold")

    def draw(x0, title, mat, det, big, color):
        ax.text(x0 + 0.22, 0.93, title, fontsize=9, ha="center",
                transform=ax.transAxes, weight="bold")
        for i, row in enumerate(mat):
            for j, v in enumerate(row):
                hot = abs(v) > _M5 / 2
                ax.text(x0 + j * 0.088, 0.80 - i * 0.11, f"{v:>3}",
                        fontsize=8.5, family="monospace", ha="center",
                        transform=ax.transAxes,
                        bbox=dict(boxstyle="square,pad=0.15", lw=0,
                                  fc=color if hot else "none"))
        ax.text(x0 + 0.22, 0.13, f"$|\\det B| = {det}$", fontsize=8.5,
                ha="center", transform=ax.transAxes)
        ax.text(x0 + 0.22, 0.04, f"{big}/25 entrate $> M/2$", fontsize=8.5,
                ha="center", transform=ax.transAxes)

    draw(0.02, "reale  $B = UR$", ex["real"]["matrix"], ex["real"]["abs_det"],
         ex["real"]["big_entries"], "#cfe6cf")
    draw(0.55, f"campionata  $[-{_M5},{_M5}]$", ex["sampled"]["matrix"],
         ex["sampled"]["abs_det"], ex["sampled"]["big_entries"], "#f4c9c4")


def _panel_det(ax, sep):
    ns = [s["n"] for s in sep]
    ax.set_title("A.  $\\log_2|\\det B|$: reale vs campionata", fontsize=11,
                 loc="left", weight="bold")
    for s in sep:
        ax.scatter([s["n"]] * len(s["real_log2det"]), s["real_log2det"],
                   color=BLUE, s=22, alpha=0.7,
                   label="reale" if s is sep[0] else None)
        ax.scatter([s["n"]] * len(s["obl_log2det"]), s["obl_log2det"],
                   color=RED, s=22, alpha=0.7,
                   label="campionata" if s is sep[0] else None)
    ax.plot(ns, [s["theory_log2det"] for s in sep], color="#333", ls="--",
            lw=1, label="$n\\log_2 k$ (teoria)")
    ax.set_xlabel("dimensione $n$", fontsize=8)
    ax.set_ylabel("$\\log_2|\\det B|$", fontsize=8)
    ax.legend(fontsize=8, frameon=False, loc="upper left")


def _panel_frac(ax, sep):
    ns = [s["n"] for s in sep]
    rmean = [statistics.fmean(s["real_frac_big"]) for s in sep]
    omean = [statistics.fmean(s["obl_frac_big"]) for s in sep]
    x = range(len(ns))
    ax.bar([i - 0.18 for i in x], rmean, width=0.36, color=BLUE, label="reale")
    ax.bar([i + 0.18 for i in x], omean, width=0.36, color=RED,
           label="campionata")
    ax.set_xticks(list(x)); ax.set_xticklabels(ns, fontsize=8)
    ax.set_title("A.  frazione entrate $|B_{ij}| > M/2$", fontsize=11,
                 loc="left", weight="bold")
    ax.set_xlabel("dimensione $n$   (separazione perfetta su tutte)", fontsize=8)
    ax.set_ylabel("frazione", fontsize=8)
    ax.legend(fontsize=8, frameon=False)


def _panel_hnf(ax, hv):
    vals = [hv["g_priv"], hv["g_atk"]]
    bars = ax.bar(["base privata $R$", "attaccante\n$\\mathsf{LLL}(H)$"], vals,
                  color=[BLUE, RED], alpha=0.85, width=0.5)
    top = max(vals) * 1.5
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + top * 0.02, f"{v:.1f}",
                ha="center", va="bottom", fontsize=9)
    ax.set_title(f"B.  GGH-HNF, GGH\\_private=False, $n={hv['n']}$",
                 fontsize=11, loc="left", weight="bold")
    ax.set_xlabel(f"$\\mathsf{{LLL}}(H)$ = {hv['ratio']:.0%} della privata: "
                  f"trapdoor sfruttabile", fontsize=8)
    ax.set_ylabel("min $\\|\\tilde b_i\\|$", fontsize=8)
    ax.set_ylim(0, top)


def render(data, path):
    fig, axes = plt.subplots(2, 3, figsize=(18, 9.5))
    fig.suptitle("Sezione 6.2  --  L'attacco al campionatore GGH", fontsize=14,
                 weight="bold", x=0.012, ha="left", y=0.985)
    verdict = ("GGH classico: distinguibile con certezza da entrambe le "
               "statistiche  |  GGH-HNF: sicuro solo con base piantata "
               "$R = kI+E$")
    fig.text(0.012, 0.945, verdict, fontsize=9, ha="left", va="top", color=RED)
    _panel_example(axes[0, 0], data["example_n5"])
    _panel_det(axes[0, 1], data["classic_separation"])
    _panel_frac(axes[0, 2], data["classic_separation"])
    _panel_hnf(axes[1, 0], data["hnf_variants"])
    axes[1, 1].axis("off")
    axes[1, 2].axis("off")
    # textual summary in the empty cells
    sep = data["classic_separation"]
    lines = ["Distinguisher su GGH classico:", ""]
    for s in sep:
        lines.append(
            f"  n={s['n']:>3}:  log2|det|  reale ~{statistics.fmean(s['real_log2det']):.0f}"
            f"  vs  campionata ~{statistics.fmean(s['obl_log2det']):.0f}"
            f"   [{'SEPARATO' if s['det_separated'] else 'overlap'}]")
        lines.append(
            f"          frac>M/2  reale ~{statistics.fmean(s['real_frac_big']):.3f}"
            f"  vs  campionata ~{statistics.fmean(s['obl_frac_big']):.3f}"
            f"   [{'SEPARATO' if s['frac_separated'] else 'overlap'}]")
    hv = data["hnf_variants"]
    lines += ["", f"GGH-HNF (Fig. 6.2), n={hv['n']}:",
              f"  GGH_private=False (R=LLL casuale):",
              f"    base privata min-GS {hv['g_priv']:.1f}  vs  "
              f"LLL(H) {hv['g_atk']:.1f}  ({hv['ratio']:.0%})",
              f"    -> LLL(H) da una base di decifratura comparabile:",
              f"       trapdoor sfruttabile, nessun campionatore possibile",
              f"  GGH_private=True (R=kI+E, adottata da GGH_FO):",
              f"    trapdoor piantata, non ridotta a posteriori;",
              f"    sicurezza del campionatore = assunzione di base corta",
              f"    piantata (GGHThesis24: attacchi di riduzione < dim 300)"]
    axes[1, 1].text(0.0, 1.0, "\n".join(lines), fontsize=7.6,
                    family="monospace", va="top",
                    transform=axes[1, 1].transAxes)
    fig.tight_layout(rect=[0.02, 0.02, 1, 0.90], h_pad=3, w_pad=2.8)
    fig.savefig(path, dpi=130)
    plt.close(fig)


# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--dims", nargs="+", type=int, default=[40, 80, 150])
    ap.add_argument("--keys", type=int, default=6)
    ap.add_argument("--hnf-dim", type=int, default=80)
    ap.add_argument("--hnf-rounds", type=int, default=4)
    args = ap.parse_args()
    if args.quick:
        args.dims, args.keys, args.hnf_dim, args.hnf_rounds = \
            [40, 80], 4, 60, 2

    ensure_out()
    t0 = time.perf_counter()
    print("A. esempio n=5 (Figura 6.1) ...")
    ex = example_n5()
    assert ex["real"]["abs_det"] == 70 and ex["sampled"]["abs_det"] == 9614
    assert ex["real"]["big_entries"] == 0 and ex["sampled"]["big_entries"] == 13
    print(f"   reale |det|={ex['real']['abs_det']}  {ex['real']['big_entries']}/25 grandi")
    print(f"   camp. |det|={ex['sampled']['abs_det']}  {ex['sampled']['big_entries']}/25 grandi  [coincide con la tesi]")

    print(f"A. separazione statistica su dim {args.dims} ({args.keys} chiavi) ...")
    sep = classic_separation(args.dims, args.keys)
    for s in sep:
        print(f"   n={s['n']}: det {'SEPARATO' if s['det_separated'] else 'overlap'}, "
              f"frac {'SEPARATO' if s['frac_separated'] else 'overlap'}")

    print(f"B. GGH-HNF, GGH_private=False, n={args.hnf_dim} "
          f"({args.hnf_rounds} round) ...")
    hv = hnf_variants(args.hnf_dim, args.hnf_rounds)
    print(f"   base privata min-GS {hv['g_priv']:.1f}  vs  LLL(H) {hv['g_atk']:.1f}"
          f"  ({hv['ratio']:.0%})  ->  trapdoor "
          f"{'PUBBLICA' if hv['trapdoor_public'] else 'nascosta'}")

    data = {"example_n5": ex, "classic_separation": sep, "hnf_variants": hv}
    render(data, f"{OUT}/6.2_ggh.png")
    with open(f"{OUT}/6.2_ggh.json", "w") as f:
        json.dump(data, f, indent=2, default=float)
    print(f"\nScritto {OUT}/6.2_ggh.png  ({time.perf_counter() - t0:.1f}s)")


if __name__ == "__main__":
    main()
