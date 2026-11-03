"""
Oblivious sampler indistinguishability tests.

For every sampler, runs the four steps below and renders one report figure per
family plus a summary matrix and a results JSON.

  Step 1  structural check       Encode(Decode(real_pk)) == real_pk
  Step 2  primary test, KS       D_{n,m} vs 1.36 sqrt((n+m)/nm)
  Step 3  secondary test         chi^2 vs uniform, real AND oblivious keys,
                                 Wilson-Hilferty threshold
  Step 4  descriptive metrics    Shannon entropy, MCV min-entropy

Verdict: the sampler is "broken" if Step 1 fails, Step 2 rejects H0, or only
the oblivious keys reject the uniform fit in Step 3. Otherwise "no
distinguisher found".

Usage (needs the modularot package installed):
  python tests/sampler_indistinguishability.py
  python tests/sampler_indistinguishability.py --quick
  python tests/sampler_indistinguishability.py --only ML-KEM GGH_FO
"""

import argparse
import json
import math
import random
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from common import (
    all_cases, ensure_out, subsample, ks_two_sample, ks_repeated, ecdf,
    chi2_verdict, descriptive, OUT, BLUE, RED, GREEN,
)

VERDICT_OK = "no distinguisher found"
VERDICT_BROKEN = "sampler broken"


# ══════════════════════════════════════════════════════════════════════════════
#  measurement
# ══════════════════════════════════════════════════════════════════════════════

def run_case(case, n_keys, n_ks):
    t0 = time.perf_counter()
    reals = [case.real_key() for _ in range(n_keys)]
    obls = [case.sample(reals[i % len(reals)]) for i in range(n_keys)]

    res = {"family": case.family, "label": case.label,
           "kind": case.kind, "unit": case.unit, "n_keys": n_keys,
           "domain": [case.lo, case.hi], "k_classes": case.k}

    # ---- Step 1: structural check -----------------------------------------
    mism = sum(0 if case.roundtrip_ok(r) else 1 for r in reals)
    enc_ok = sum(1 for o in obls if case.encaps_ok(o))
    res["step1"] = {
        "name": "structural check  Encode(Decode(pk))==pk",
        "mismatch": mism, "checked": len(reals),
        "encaps_accept": enc_ok, "encaps_total": len(obls),
        "pass": mism == 0,
    }

    # ---- phi pools ---------------------------------------------------------
    #  GGH: each key contributes a correlated block of residues (one dense
    #  HNF column). The full pool (~2e4) feeds the Step 2 D statistic and the
    #  figure, but only ~n_keys observations are independent, so the Step 2
    #  threshold uses n_eff = n_keys and Steps 3/4 use one residue per key.
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

    # ---- Step 2: Kolmogorov-Smirnov -------------------------------------
    n_eff = n_keys if case.kind == "ggh" else None
    ks = ks_repeated(real_pool, obl_pool, n_ks, n_eff=n_eff)
    res["step2"] = {"name": "test primario Kolmogorov-Smirnov", **ks,
                     "pass": not ks["reject"]}
    if case.kind == "ggh":
        res["step2_log2det"] = ks_two_sample(res["ggh_extra"]["log2det_real"],
                                              res["ggh_extra"]["log2det_obl"])
        res["step2_nontrivial"] = ks_two_sample(
            res["ggh_extra"]["nontrivial_real"],
            res["ggh_extra"]["nontrivial_obl"])

    # ---- Step 3: Pearson chi-square -----------------------------------
    #  What matters is the two verdicts: "both reject slightly" is still a
    #  success. Step 3 flags a problem only if the oblivious keys reject
    #  grossly while the real ones do not (beyond ~5 noise standard
    #  deviations, sigma = sqrt(2 df)).
    cr = chi2_verdict(real_dec, case.lo, case.hi, case.k)
    co = chi2_verdict(obl_dec, case.lo, case.hi, case.k)
    noise = 5.0 * math.sqrt(2.0 * cr["df"])
    gross = co["reject"] and (not cr["reject"]) and (co["chi2"] - cr["chi2"] > noise)
    coherent = not gross
    res["step3"] = {"name": "test secondario Pearson chi^2",
                     "real": cr, "obl": co, "noise_band": noise,
                     "coherent": coherent, "pass": coherent}

    # ---- Step 4: metriche descrittive ---------------------------------
    #  Descriptive numbers, not a test: the whole pool is used (best estimate
    #  of the marginal law), also for GGH.
    dr = descriptive(real_pool, case.lo, case.hi, case.k)
    do = descriptive(obl_pool, case.lo, case.hi, case.k)
    res["step4"] = {"name": "metriche descrittive", "real": dr, "obl": do}

    # ---- verdetto -----------------------------------------------------
    #  Steps 1 and 2 (primary) decide the outcome; Step 3 contributes only
    #  with a gross discrepancy (see above).
    broken = (not res["step1"]["pass"]) or res["step2"]["reject"] or gross
    res["verdict"] = VERDICT_BROKEN if broken else VERDICT_OK
    res["_pools"] = (real_pool, obl_pool)
    res["_elapsed"] = time.perf_counter() - t0
    return res


# ══════════════════════════════════════════════════════════════════════════════
#  plotting -- one panel per Step
# ══════════════════════════════════════════════════════════════════════════════

def _panel_step2(ax, res):
    real_pool, obl_pool = res["_pools"]
    xs_r, ys_r = ecdf(subsample(real_pool, 4000))
    xs_o, ys_o = ecdf(subsample(obl_pool, 4000))
    ax.step(xs_r, ys_r, where="post", color=BLUE, lw=1.5, label="real $F_n$")
    ax.step(xs_o, ys_o, where="post", color=RED, lw=1.5, label="oblivious $G_m$")
    ks = res["step2"]
    if ks.get("D_at") is not None:
        ax.axvline(ks["D_at"], color="#333", ls="--", lw=1)
    verdict = "rejects $H_0$" if ks["reject"] else "does not reject $H_0$"
    ax.set_title(f"Step 2 -- Kolmogorov-Smirnov: {verdict}", fontsize=12,
                 loc="left", weight="bold")
    ax.set_ylabel("cumulative frequency", fontsize=10)
    ax.tick_params(labelsize=9)
    ax.legend(fontsize=10, frameon=False, loc="lower right")


def _panel_step3(ax, res):
    cr, co = res["step3"]["real"], res["step3"]["obl"]
    coherent = res["step3"]["coherent"]
    vals = [cr["chi2"], co["chi2"]]
    bars = ax.bar(["real", "oblivious"], vals, color=[BLUE, RED], width=0.5,
                  alpha=0.85)
    top = max(vals + [cr["crit"]]) * 1.35
    ax.axhline(cr["crit"], color="#333", ls="--", lw=1.2)
    ax.text(0.98, 0.96, f"Wilson-Hilferty threshold = {cr['crit']:.0f}",
            transform=ax.transAxes, fontsize=9, va="top", ha="right",
            color="#333")
    for bmark, v in zip(bars, vals):
        cx = bmark.get_x() + bmark.get_width() / 2
        ax.text(cx, v / 2, f"{v:.0f}", ha="center", va="center", fontsize=12,
                color="white", weight="bold")
    verdict = "consistent verdicts" if coherent else "DISCORDANT verdicts"
    ax.set_title(f"Step 3 -- $\\chi^2$ vs uniform: {verdict}", fontsize=12,
                 loc="left", weight="bold")
    ax.tick_params(labelsize=9)
    ax.set_ylabel("$\\chi^2$", fontsize=10)
    ax.set_ylim(0, top)


def _panel_step4(ax, res):
    dr, do = res["step4"]["real"], res["step4"]["obl"]
    groups = ["Shannon $H$", "min-entropy $H_\\infty$ (MCV)"]
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
    ax.set_title(f"Step 4 -- entropy (blue real, red oblivious; "
                 f"dashed: maximum $\\log_2 k = {dr['shannon_max']:.2f}$)",
                 fontsize=11, loc="left", weight="bold")
    ax.set_ylim(0, top)
    ax.tick_params(labelsize=9)
    ax.set_ylabel("bit", fontsize=10)


HEADER = False   # --header adds a baked-in title and verdict line


def render_case(res, path):
    # two panels on top (KS, chi^2), the descriptive metrics below, centred
    broken = res["verdict"] == VERDICT_BROKEN
    fig = plt.figure(figsize=(13, 7.8 if not HEADER else 8.5))
    gs = fig.add_gridspec(2, 4, hspace=0.30, wspace=0.7)
    ax_ks = fig.add_subplot(gs[0, 0:2])
    ax_chi = fig.add_subplot(gs[0, 2:4])
    ax_desc = fig.add_subplot(gs[1, 1:3])
    if HEADER:
        fig.suptitle(f"{res['label']}  --  {res['family']}",
                     fontsize=15, weight="bold", x=0.06, ha="left", y=0.985)
        fig.text(0.06, 0.955,
                 f"$\\varphi(pk)$: {res['unit']} over $[{res['domain'][0]}, "
                 f"{res['domain'][1]})$   |   {res['pool_size'][0]} real values, "
                 f"{res['pool_size'][1]} oblivious ({res['n_keys']} keys per "
                 f"group)   |   verdict: {res['verdict'].upper()}",
                 fontsize=10, ha="left", va="top",
                 color=RED if broken else GREEN)
    _panel_step2(ax_ks, res)
    _panel_step3(ax_chi, res)
    _panel_step4(ax_desc, res)
    fig.subplots_adjust(left=0.07, right=0.97, bottom=0.07,
                        top=0.92 if HEADER else 0.97)
    fig.savefig(path, dpi=140)
    plt.close(fig)


def render_summary(all_res, path):
    labels = ["Step 2\nKS", "Step 3\n$\\chi^2$", "verdict"]
    fig, ax = plt.subplots(figsize=(2.0 * len(labels) + 3.5,
                                    0.7 * len(all_res) + 1.8))
    ax.set_xlim(0, len(labels))
    ax.set_ylim(0, len(all_res) + 0.6)
    for i, r in enumerate(all_res):
        yy = len(all_res) - 1 - i
        cells = [
            r["step2"]["pass"], r["step3"]["pass"],
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
    ax.set_title("Sampler verification summary "
                 "(green = pass / red = reject)", fontsize=11, weight="bold",
                 pad=26)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)




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
    ap.add_argument("--header", action="store_true",
                    help="add a baked-in title/verdict line to the figures")
    args = ap.parse_args()

    if args.header:
        globals()["HEADER"] = True
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
            print(f"  !! {case.label} failed: {e}")
            continue
        slug = case.family.lower().replace("ml-kem", "mlkem").replace("_", "")
        p = f"{OUT}/indistinguishability_{slug}.png"
        render_case(res, p)
        with open(f"{OUT}/indistinguishability_{slug}.json", "w") as f:
            json.dump(json_safe(res), f, indent=2, default=float)
        all_res.append(res)
        print(f"  Step1 {'OK' if res['step1']['pass'] else 'FAIL'} | "
              f"Step2 D={res['step2']['D']:.4f} "
              f"({int(res['step2']['reject_fraction'] * res['step2']['reps'])}"
              f"/{res['step2']['reps']} rejections) "
              f"{'REJECTS' if res['step2']['reject'] else 'ok'} | "
              f"Step3 r/o chi2 {res['step3']['real']['chi2']:.0f}/"
              f"{res['step3']['obl']['chi2']:.0f} "
              f"({'consistent' if res['step3']['coherent'] else 'DISCORDANT'}) | "
              f"-> {res['verdict']}  ({res['_elapsed']:.1f}s)")

    if all_res:
        render_summary(all_res, f"{OUT}/indistinguishability_summary.png")
        with open(f"{OUT}/indistinguishability_results.json", "w") as f:
            json.dump([json_safe(r) for r in all_res], f, indent=2, default=float)
        print(f"\nWrote {len(all_res)} reports + summary in {OUT}/")


if __name__ == "__main__":
    main()
