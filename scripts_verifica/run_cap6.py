"""
Esegue l'intera suite di verifica del Capitolo 6 e assembla un indice HTML.

  6.1  cap6_1_campionatori.py   -- verifica dei campionatori oblivious (4 passi)
  6.2  cap6_2_ggh.py            -- attacco al campionatore GGH
  6.3  cap6_3_mix_and_match.py  -- attacco mix-and-match
  6.4  cap6_4_avversariale.py   -- tentativi di estrazione (semi-honest)

Uso:  .venv/bin/python scripts_verifica/run_cap6.py            (completo)
      .venv/bin/python scripts_verifica/run_cap6.py --quick    (rapido)
"""

import argparse
import base64
import glob
import os
import runpy
import sys
import time

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "cap6_output")


def _run(mod, argv):
    sys.argv = [mod] + argv
    print(f"\n{'#' * 70}\n# {mod}  {' '.join(argv)}\n{'#' * 70}")
    runpy.run_path(os.path.join(HERE, mod), run_name="__main__")


def build_index():
    imgs = sorted(glob.glob(os.path.join(OUT, "6.*.png")))
    parts = [
        "<!doctype html><meta charset=utf-8><title>Capitolo 6 -- verifiche</title>",
        "<style>body{font:14px/1.6 system-ui,sans-serif;margin:2rem auto;"
        "max-width:1150px;padding:0 1rem}img{width:100%;border:1px solid #ddd;"
        "border-radius:6px;margin:.4rem 0 2.2rem}h1{font-size:1.5rem}"
        "h2{font-size:1.1rem;margin-top:2rem;border-top:1px solid #eee;"
        "padding-top:1rem}code{background:#f4f4f4;padding:.1em .3em}"
        "a{color:#4575b4}</style>",
        "<h1>Capitolo 6 &mdash; Verifica delle propriet&agrave; di sicurezza</h1>",
        "<p>Generato da <code>scripts_verifica/run_cap6.py</code>. "
        "Dati grezzi nei file <code>cap6_output/*.json</code>; tabella LaTeX "
        "in <code>cap6_output/tabella_6.1.tex</code>.</p>",
        "<p>" + " &nbsp;|&nbsp; ".join(
            f'<a href="#{os.path.basename(p)}">{os.path.basename(p)[:-4]}</a>'
            for p in imgs) + "</p>",
    ]
    titles = {
        "6.1": "6.1 &mdash; Verifica della correttezza dei campionatori oblivious",
        "6.2": "6.2 &mdash; L'attacco al campionatore GGH",
        "6.3": "6.3 &mdash; L'attacco mix-and-match",
        "6.4": "6.4 &mdash; Tentativi di estrazione (modello semi-honest)",
    }
    seen = set()
    for p in imgs:
        name = os.path.basename(p)
        sec = name[:3]
        if sec not in seen:
            parts.append(f'<h2 id="{sec}">{titles.get(sec, sec)}</h2>')
            seen.add(sec)
        with open(p, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        parts.append(f'<a id="{name}"></a><img alt="{name}" '
                     f'src="data:image/png;base64,{b64}">')
    with open(os.path.join(OUT, "index.html"), "w") as f:
        f.write("\n".join(parts))
    print(f"\nIndice: {OUT}/index.html  ({len(imgs)} figure)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--skip", nargs="+", default=[],
                    help="salta sezioni, es. --skip 6.2 6.3")
    args = ap.parse_args()
    q = ["--quick"] if args.quick else []

    t0 = time.perf_counter()
    plan = [
        ("6.1", "cap6_1_campionatori.py", q),
        ("6.2", "cap6_2_ggh.py", q),
        ("6.3", "cap6_3_mix_and_match.py", ["--with-ggh"]),
        ("6.4", "cap6_4_avversariale.py", q),
    ]
    for sec, mod, argv in plan:
        if sec in args.skip:
            print(f"(salto {sec})")
            continue
        try:
            _run(mod, argv)
        except SystemExit:
            pass
        except Exception:
            import traceback
            traceback.print_exc()
            print(f"!! {mod} interrotto")

    build_index()
    print(f"\nTotale: {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()
