"""
Comparative performance plots across KEMs.

Reads the CSVs written by `modularot bench` (default: tests/data/*.csv), picks
the most secure instance of each family and writes five figures:

  sampling_cost.png       real KeyGen vs oblivious sample
  time_per_phase.png      request/transfer/finalize at fixed n
  scalability.png         total time vs n, all families
  bandwidth.png           pk + ct bandwidth per family
  standard_vs_custom.png  total time vs bandwidth, standard vs custom

Usage:
  python tests/comparison_plots.py [csv ...] [--out DIR]
"""

import csv
import math
import argparse
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "output")


def _sig(value, sig=3):
    """Round to `sig` significant digits in plain decimal notation."""
    if value == 0:
        return "0"
    exponent = math.floor(math.log10(abs(value)))
    decimals = max(0, sig - 1 - exponent)
    s = f"{value:.{decimals}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def _fmt_time(value_ms, _pos=None):
    """Log-axis tick label for times, in readable units (us/ms/s)."""
    if value_ms <= 0:
        return ""
    if value_ms < 1:
        return f"{_sig(value_ms * 1000)} µs"
    if value_ms < 1000:
        return f"{_sig(value_ms)} ms"
    return f"{_sig(value_ms / 1000)} s"


def _fmt_bandwidth(value_kib, _pos=None):
    """Log-axis tick label for bandwidth, in KiB/MiB."""
    if value_kib <= 0:
        return ""
    if value_kib < 1024:
        return f"{_sig(value_kib)} KiB"
    return f"{_sig(value_kib / 1024)} MiB"


TIME_FORMATTER = FuncFormatter(_fmt_time)
BANDWIDTH_FORMATTER = FuncFormatter(_fmt_bandwidth)


def _use_time_axis(ax):
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(TIME_FORMATTER)
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="y", which="major", color="black", alpha=0.12, linewidth=0.6)


def _use_bandwidth_axis(ax, axis="y"):
    which_axis = ax.yaxis if axis == "y" else ax.xaxis
    which_axis.set_major_locator(LogLocator(base=10))
    which_axis.set_major_formatter(BANDWIDTH_FORMATTER)
    which_axis.set_minor_formatter(NullFormatter())
    ax.grid(axis=axis, which="major", color="black", alpha=0.12, linewidth=0.6)

# same palette as common.py, plus two tones for the non-standard KEMs
BLUE, RED, GREY, GREEN, ORANGE = "#4575b4", "#d73027", "#999999", "#1a9850", "#f46d43"
PURPLE, BROWN = "#762a83", "#b35806"

# (family prefix, colour, standardized scheme?)
FAMILIES = [
    ("ML-KEM", BLUE, True), ("FrodoKEM", ORANGE, True), ("NTRU-HPS", GREEN, True),
    ("NTRU-HRSS", RED, True), ("sntrup761", GREY, True),
    ("NTRU_FO", PURPLE, False), ("GGH_FO", BROWN, False),
]
COLOR, STANDARD = {}, set()   # filled by load() for the selected instances

SHORT = {}   # tick labels, filled by load()


def _family(kem):
    for prefix, color, standard in FAMILIES:
        if kem.startswith(prefix):
            return prefix, color, standard
    return None


def _security_key(kem):
    """Larger parameters -> more secure: compare the numbers in the name."""
    return tuple(int(x) for x in re.findall(r"\d+", kem))


def load(csv_paths):
    rows, seen = [], set()
    for path in csv_paths:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                row["kem"] = row["kem"].replace("GGH-FO", "GGH_FO")
                if (row["kem"], row["n"]) in seen:
                    continue
                seen.add((row["kem"], row["n"]))
                for k in ("n", "pk_bytes", "ct_bytes", "total_bytes"):
                    row[k] = int(row[k])
                for k in ("request_ms", "transfer_ms", "finalize_ms", "total_ms",
                          "keygen_ms", "obliv_sample_ms", "keygen_over_sample"):
                    row[k] = float(row[k])
                rows.append(row)
    present = []
    for prefix, color, standard in FAMILIES:
        names = {r["kem"] for r in rows if _family(r["kem"]) and _family(r["kem"])[0] == prefix}
        if not names:
            continue
        best = max(names, key=_security_key)
        present.append(best)
        COLOR[best] = color
        if standard:
            STANDARD.add(best)
        SHORT[best] = best if prefix == "sntrup761" else f"{prefix}\n{best[len(prefix) + 1:]}"
    return rows, present


def by_kem_n(rows, kem, n):
    for r in rows:
        if r["kem"] == kem and r["n"] == n:
            return r
    return None


def fig1_sampling_cost(rows, present, out):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(len(present))
    w = 0.35
    keygen = [next(r for r in rows if r["kem"] == k)["keygen_ms"] for k in present]
    sample = [next(r for r in rows if r["kem"] == k)["obliv_sample_ms"] for k in present]
    ax.bar(x - w / 2, keygen, w, label="Real KeyGen", color=GREY)
    ax.bar(x + w / 2, sample, w, label="Oblivious sample", color=BLUE)
    ax.set_yscale("log")
    _use_time_axis(ax)
    ax.set_ylabel("median time")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Cost of a real key versus an oblivious sample")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "sampling_cost.png"), dpi=150)
    plt.close(fig)


def fig2_time_per_phase(rows, present, out, n=32):
    # GGH is ~4 orders of magnitude above the others: grouped bars on a
    # log scale keep every family visible.
    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    x = np.arange(len(present))
    w = 0.26
    req = [by_kem_n(rows, k, n)["request_ms"] for k in present]
    tra = [by_kem_n(rows, k, n)["transfer_ms"] for k in present]
    fin = [by_kem_n(rows, k, n)["finalize_ms"] for k in present]
    ax.bar(x - w, req, w, label="request", color=BLUE)
    ax.bar(x, tra, w, label="transfer", color=ORANGE)
    ax.bar(x + w, fin, w, label="finalize", color=GREY)
    ax.set_yscale("log")
    _use_time_axis(ax)
    ax.set_ylabel(f"median time, $n={n}$")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title(f"Protocol time breakdown by phase ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "time_per_phase.png"), dpi=150)
    plt.close(fig)


def fig3_scalability(rows, present, out):
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ns = sorted(set(r["n"] for r in rows))
    for k in present:
        pts = [(n, by_kem_n(rows, k, n)) for n in ns]
        pts = [(n, r["total_ms"]) for n, r in pts if r]
        ns_k, ys = [n for n, _ in pts], [y for _, y in pts]
        style = "-o" if k in STANDARD else "--s"
        label = SHORT[k].replace("\n", " ")
        ax.plot(ns_k, ys, style, color=COLOR[k], label=label, ms=4, lw=1.4)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(ns)
    ax.set_xticklabels([str(n) for n in ns])
    _use_time_axis(ax)
    ax.set_xlabel("$n$ (number of messages)")
    ax.set_ylabel("median total time")
    ax.legend(frameon=False, fontsize=7.5, ncol=2, loc="center right")
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Scalability of total protocol time as $n$ varies")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "scalability.png"), dpi=150)
    plt.close(fig)


def fig4_bandwidth(rows, present, out, n=32):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(len(present))
    pk = [by_kem_n(rows, k, n)["pk_bytes"] / 1024 for k in present]
    ct = [by_kem_n(rows, k, n)["ct_bytes"] / 1024 for k in present]
    ax.bar(x - 0.2, pk, 0.4, label=r"receiver$\to$sender bandwidth (keys $pk_i$)", color=BLUE)
    ax.bar(x + 0.2, ct, 0.4, label=r"sender$\to$receiver bandwidth (ciphertexts $c_i$)", color=ORANGE)
    ax.set_yscale("log")
    ax.set_ylim(min(pk + ct) * 0.5, max(pk + ct) * 2)
    _use_bandwidth_axis(ax)
    ax.set_ylabel(f"total bandwidth, $n={n}$")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title(f"Total bandwidth of public keys and ciphertexts ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "bandwidth.png"), dpi=150)
    plt.close(fig)


def fig5_standard_vs_custom(rows, present, out, n=32):
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    # manual offsets to separate labels that would overlap
    # (NTRU-HPS and NTRU-HRSS land almost on the same point)
    offsets = {
        "NTRU-HPS-4096-1229": (6, -11),
        "NTRU-HRSS-1373": (6, 6),
    }
    for k in present:
        r = by_kem_n(rows, k, n)
        bw_kib = (r["pk_bytes"] + r["ct_bytes"]) / 1024
        marker = "o" if k in STANDARD else "^"
        ax.scatter(bw_kib, r["total_ms"], s=90, color=COLOR[k], marker=marker,
                   edgecolor="white", linewidth=0.6, zorder=3)
        ax.annotate(SHORT[k].replace("\n", " "), (bw_kib, r["total_ms"]),
                    textcoords="offset points", xytext=offsets.get(k, (6, 4)),
                    fontsize=7.5)
    ax.set_xscale("log")
    ax.set_yscale("log")
    _use_bandwidth_axis(ax, axis="x")
    _use_time_axis(ax)
    ax.set_xlabel(f"total bandwidth $pk+ct$, $n={n}$ (log scale)")
    ax.set_ylabel("median total time")
    ax.spines[["top", "right"]].set_visible(False)
    from matplotlib.lines import Line2D
    handles = [Line2D([0], [0], marker="o", color="w", markerfacecolor=GREY,
                       markersize=9, label="standardized scheme (liboqs)"),
               Line2D([0], [0], marker="^", color="w", markerfacecolor=GREY,
                       markersize=9, label="non-conventional scheme (custom)")]
    ax.legend(handles=handles, frameon=False, fontsize=8, loc="upper left")
    ax.set_title(f"Total cost versus bandwidth: standard and custom schemes ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "standard_vs_custom.png"), dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("csv", nargs="*", help="benchmark CSVs (default: tests/data/*.csv)")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    paths = args.csv or sorted(os.path.join(DATA, f) for f in os.listdir(DATA)
                               if f.endswith(".csv"))
    os.makedirs(args.out, exist_ok=True)
    rows, present = load(paths)
    print(f"KEMs selected from the CSVs: {present}")
    fig1_sampling_cost(rows, present, args.out)
    ns = {r["n"] for r in rows}
    n_fixed = 32 if 32 in ns else max(ns)   # branch count of the per-phase/bandwidth plots
    fig2_time_per_phase(rows, present, args.out, n=n_fixed)
    fig3_scalability(rows, present, args.out)
    fig4_bandwidth(rows, present, args.out, n=n_fixed)
    fig5_standard_vs_custom(rows, present, args.out, n=n_fixed)
    print(f"Figures written to {args.out}")

if __name__ == "__main__":
    main()
