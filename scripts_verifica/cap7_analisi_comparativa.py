"""
Sezione 7.4 -- Analisi prestazionale comparativa tra KEM.

Legge il CSV prodotto da `modularot bench` (istanza piu sicura per ciascuna
famiglia, si veda cap7_bench/bench_log.txt per il comando esatto) e produce
le cinque figure della sezione:

  fig1  cap7_costo_campionamento.png   KeyGen vs campione oblivious (n=1)
  fig2  cap7_tempi_per_fase.png        request/transfer/finalize a n fissato
  fig3  cap7_scalabilita_n.png         TOTAL vs n, tutte le famiglie
  fig4  cap7_occupazione_banda.png     banda pk + ct per famiglia
  fig5  cap7_standard_vs_custom.png    tempo totale vs banda, standard vs custom

Uso (dalla root di MODULAROT):
  .venv/bin/python scripts_verifica/cap7_analisi_comparativa.py <csv_path>
"""

import csv
import math
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

IMAGES = "/home/gabro/Desktop/Tesi LaTeX/images"


def _sig(value, sig=3):
    """Valore arrotondato a `sig` cifre significative, in notazione
    decimale semplice (mai scientifica, es. '1000' non '1e+03')."""
    if value == 0:
        return "0"
    exponent = math.floor(math.log10(abs(value)))
    decimals = max(0, sig - 1 - exponent)
    s = f"{value:.{decimals}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def _fmt_time(value_ms, _pos=None):
    """Tick label per assi logaritmici di tempo: unita' leggibile (us/ms/s)
    invece della sola potenza di dieci."""
    if value_ms <= 0:
        return ""
    if value_ms < 1:
        return f"{_sig(value_ms * 1000)} µs"
    if value_ms < 1000:
        return f"{_sig(value_ms)} ms"
    return f"{_sig(value_ms / 1000)} s"


def _fmt_bandwidth(value_kib, _pos=None):
    """Tick label per assi logaritmici di banda: KiB/MiB invece della sola
    potenza di dieci."""
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

# stessa palette del Capitolo 6 (cap6_common.BLUE/RED/GREY/GREEN/ORANGE),
# estesa con due tonalita per i KEM non convenzionali
BLUE, RED, GREY, GREEN, ORANGE = "#4575b4", "#d73027", "#999999", "#1a9850", "#f46d43"
PURPLE, BROWN = "#762a83", "#b35806"

COLOR = {
    "ML-KEM-1024": BLUE,
    "FrodoKEM-1344-AES": ORANGE,
    "NTRU-HPS-4096-1229": GREEN,
    "NTRU-HRSS-1373": RED,
    "sntrup761": GREY,
    "NTRU_FO-701": PURPLE,
    "GGH_FO-300": BROWN,
}
ORDER = list(COLOR.keys())
STANDARD = {"ML-KEM-1024", "FrodoKEM-1344-AES", "NTRU-HPS-4096-1229",
            "NTRU-HRSS-1373", "sntrup761"}
CUSTOM = {"NTRU_FO-701", "GGH_FO-300"}

SHORT = {
    "ML-KEM-1024": "ML-KEM\n1024",
    "FrodoKEM-1344-AES": "FrodoKEM\n1344-AES",
    "NTRU-HPS-4096-1229": "NTRU-HPS\n4096-1229",
    "NTRU-HRSS-1373": "NTRU-HRSS\n1373",
    "sntrup761": "sntrup761",
    "NTRU_FO-701": "NTRU_FO\n701",
    "GGH_FO-300": "GGH_FO\n300",
}


def load(csv_path):
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            for k in ("n", "pk_bytes", "ct_bytes", "total_bytes"):
                row[k] = int(row[k])
            for k in ("request_ms", "transfer_ms", "finalize_ms", "total_ms",
                      "keygen_ms", "obliv_sample_ms", "keygen_over_sample"):
                row[k] = float(row[k])
            rows.append(row)
    present = [k for k in ORDER if any(r["kem"] == k for r in rows)]
    return rows, present


def by_kem_n(rows, kem, n):
    for r in rows:
        if r["kem"] == kem and r["n"] == n:
            return r
    return None


def fig1_costo_campionamento(rows, present, out):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(len(present))
    w = 0.35
    keygen = [next(r for r in rows if r["kem"] == k)["keygen_ms"] for k in present]
    sample = [next(r for r in rows if r["kem"] == k)["obliv_sample_ms"] for k in present]
    ax.bar(x - w / 2, keygen, w, label="KeyGen reale", color=GREY)
    ax.bar(x + w / 2, sample, w, label="Campione oblivious", color=BLUE)
    ax.set_yscale("log")
    _use_time_axis(ax)
    ax.set_ylabel("tempo mediano")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Costo di una chiave reale rispetto a un campione oblivious")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cap7_costo_campionamento.png"), dpi=150)
    plt.close(fig)


def fig2_tempi_per_fase(rows, present, out, n=32):
    # GGH e ~4 ordini di grandezza sopra le altre famiglie: una barra
    # impilata in scala lineare la renderebbe l'unica visibile, quindi si
    # usano barre affiancate per fase in scala log.
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
    ax.set_ylabel(f"tempo mediano, $n={n}$")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title(f"Ripartizione del tempo di protocollo per fase ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cap7_tempi_per_fase.png"), dpi=150)
    plt.close(fig)


def fig3_scalabilita(rows, present, out):
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ns = sorted(set(r["n"] for r in rows))
    for k in present:
        ys = [by_kem_n(rows, k, n)["total_ms"] for n in ns]
        style = "-o" if k in STANDARD else "--s"
        label = SHORT[k].replace("\n", " ")
        ax.plot(ns, ys, style, color=COLOR[k], label=label, ms=4, lw=1.4)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(ns)
    ax.set_xticklabels([str(n) for n in ns])
    _use_time_axis(ax)
    ax.set_xlabel("$n$ (numero di messaggi)")
    ax.set_ylabel("tempo totale mediano")
    ax.legend(frameon=False, fontsize=7.5, ncol=2)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Scalabilita del tempo totale di protocollo al variare di $n$")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cap7_scalabilita_n.png"), dpi=150)
    plt.close(fig)


def fig4_occupazione_banda(rows, present, out, n=32):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(len(present))
    pk = [by_kem_n(rows, k, n)["pk_bytes"] / 1024 for k in present]
    ct = [by_kem_n(rows, k, n)["ct_bytes"] / 1024 for k in present]
    ax.bar(x - 0.2, pk, 0.4, label=r"banda ricevente$\to$mittente (chiavi $pk_i$)", color=BLUE)
    ax.bar(x + 0.2, ct, 0.4, label=r"banda mittente$\to$ricevente (ciphertext $c_i$)", color=ORANGE)
    ax.set_yscale("log")
    ax.set_ylim(min(pk + ct) * 0.5, max(pk + ct) * 2)
    _use_bandwidth_axis(ax)
    ax.set_ylabel(f"banda totale, $n={n}$")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[k] for k in present], fontsize=8)
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title(f"Banda complessiva di chiavi e ciphertext ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cap7_occupazione_banda.png"), dpi=150)
    plt.close(fig)


def fig5_standard_vs_custom(rows, present, out, n=32):
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    # piccoli scarti manuali per separare le etichette che altrimenti si
    # sovrappongono (NTRU-HPS e NTRU-HRSS cadono quasi nello stesso punto)
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
    ax.set_xlabel(f"banda totale $pk+ct$, $n={n}$ (scala log)")
    ax.set_ylabel("tempo totale mediano")
    ax.spines[["top", "right"]].set_visible(False)
    from matplotlib.lines import Line2D
    handles = [Line2D([0], [0], marker="o", color="w", markerfacecolor=GREY,
                       markersize=9, label="schema standardizzato (liboqs)"),
               Line2D([0], [0], marker="^", color="w", markerfacecolor=GREY,
                       markersize=9, label="schema non convenzionale (custom)")]
    ax.legend(handles=handles, frameon=False, fontsize=8, loc="upper left")
    ax.set_title(f"Costo totale rispetto alla banda: standard e custom a confronto ($n={n}$)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cap7_standard_vs_custom.png"), dpi=150)
    plt.close(fig)


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "ot_scaling_secure.csv"
    out = sys.argv[2] if len(sys.argv) > 2 else IMAGES
    os.makedirs(out, exist_ok=True)
    rows, present = load(csv_path)
    print(f"KEM presenti nel CSV: {present}")
    fig1_costo_campionamento(rows, present, out)
    fig2_tempi_per_fase(rows, present, out)
    fig3_scalabilita(rows, present, out)
    fig4_occupazione_banda(rows, present, out)
    fig5_standard_vs_custom(rows, present, out)
    print(f"Figure scritte in {out}")


if __name__ == "__main__":
    main()
