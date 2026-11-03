"""
Regenerate every graph and CSV of the experimental results.

  1. benchmark   -> output/ot_scaling.csv        (`modularot bench`)
  2. samplers    -> output/indistinguishability_*.png/json
  3. reuse       -> output/component_reuse_*.png/json
  4. comparison  -> output/{sampling_cost,time_per_phase,scalability,
                           bandwidth,standard_vs_custom}.png

Needs the modularot package installed (release branch) with the custom-kems
extra. A full run is slow because of GGH_FO at dimension 300; use --quick for a
smoke test.

Usage:
  python tests/run_all.py [--quick]
"""

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "output")

FULL_KEMS = ["ML-KEM-1024", "FrodoKEM-1344-AES", "NTRU-HPS-4096-1229",
             "NTRU-HRSS-1373", "sntrup761"]


def run(*cmd):
    print("\n$", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="fewer KEMs, branch counts and keys; GGH_FO at dim 60")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    py, csv_path = sys.executable, os.path.join(OUT, "ot_scaling.csv")
    t0 = time.time()

    if args.quick:
        bench = ["--kems", "ML-KEM-768", "sntrup761", "--ns", "2", "4",
                 "--reps", "1", "--ggh-dim", "60"]
    else:
        bench = ["--kems", *FULL_KEMS, "--ns", "2", "4", "8", "16", "32",
                 "--reps", "5", "--ggh-dim", "300"]
    run(py, "-m", "modularot.cli", "bench", *bench, "--csv", csv_path)

    sampler = [py, os.path.join(HERE, "sampler_indistinguishability.py")]
    run(*sampler, *(["--quick"] if args.quick else []))
    run(py, os.path.join(HERE, "component_reuse.py"), "--with-ggh")
    run(py, os.path.join(HERE, "comparison_plots.py"), csv_path)
    print(f"\nDone in {time.time() - t0:.0f}s. Outputs in {OUT}")


if __name__ == "__main__":
    main()
