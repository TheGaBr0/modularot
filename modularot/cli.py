"""
Command-line interface for modularot: the modular KEM-based 1-out-of-n OT.

Subcommands:
  run        -- run one 1-out-of-n OT transfer (KEM, n, choice, messages).
  bench      -- per KEM and per n: request/transfer/finalize timing, bandwidth
                and KeyGen-vs-oblivious-sample cost. Console tables + CSV.
  list-kems  -- list the names usable with `run --kem` / `bench --kems`.

Usage (`modularot` entry point or `python -m modularot.cli`):
    modularot run                                   # ML-KEM-768, 1-out-of-2, placeholder messages
    modularot run --kem ML-KEM-768 --n 4 --choice 2
    modularot run --n 3 --message "a" --message "b" --message "c" --choice 1
    modularot run --kem GGH_FO --ggh-dim 200 --quiet --output secret.bin
    modularot list-kems
    modularot bench                                 # default KEM subset + NTRU_FO + GGH_FO
    modularot bench --all                           # every supported liboqs mechanism, + custom
    modularot bench --kems ML-KEM-768 sntrup761 --no-custom
    modularot bench --ns 2 4 8 16 32 --reps 5 --csv out.csv
"""

import argparse
import csv
import statistics
import sys
import time

import oqs

from .ot_protocol import run_ot, _oqs_kem_factory, _fmt_ns
from .oblivious_sampling import resolve_oqs, is_supported_oqs, sample_oblivious_ntru_fo
from .kem_adapter.adapter import KEMAdapter

# One per (family, security level): short run covering every encoding family.
DEFAULT_KEMS = [
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",        # structured, q=3329
    "FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES",  # unstructured LWE
    "NTRU-HPS-2048-509", "NTRU-HRSS-701",             # NTRU, bit-packed
    "sntrup761",                                      # NTRU Prime, mixed-radix
]

DEFAULT_NS = [2, 4, 8, 16, 32]

CUSTOM_KEM_NAMES = {"NTRU_FO", "GGH_FO"}


def _ntrufo_entry(N: int, q: int = 8192, p: int = 3):
    """(label, kem_factory, sampler) for NTRU_FO; each factory call builds an
    independent instance."""
    from .custom_kems.ntru_fo.ntru_fo import NTRU_FO

    def factory():
        impl = NTRU_FO(N=N, p=p, q=q)
        return KEMAdapter(gen=impl.generate_keys, encap=impl.encapsulate,
                          decap=impl.decapsulate)

    return (f"NTRU_FO-{N}", factory, lambda pk: sample_oblivious_ntru_fo(pk, q=q))


def _gghfo_entry(dimension: int):
    """(label, kem_factory, sampler) for GGH-HNF FO (GGH_private=True). Needs
    `pip install modularot[custom-kems]`; dimension=200 is teaching-scale.
    Classic GGH has no sound oblivious sampler."""
    from .custom_kems.ggh_fo import ggh_fo
    from .oblivious_sampling import sample_oblivious_ggh_hnf

    def factory():
        return KEMAdapter(
            gen=lambda: ggh_fo.gen(dimension=dimension),
            encap=ggh_fo.encaps,
            decap=ggh_fo.decaps,
        )

    return (f"GGH_FO-{dimension}", factory, sample_oblivious_ggh_hnf)


def _build_entry(kem: str, ntrufo_n: int, ggh_dim: int):
    """(label, kem_factory, sampler) for one KEM name -- custom or liboqs."""
    if kem == "NTRU_FO":
        try:
            return _ntrufo_entry(ntrufo_n)
        except Exception as e:
            raise SystemExit(f"cannot build NTRU_FO: {e}")
    if kem == "GGH_FO":
        try:
            return _gghfo_entry(ggh_dim)
        except Exception as e:
            raise SystemExit(
                f"cannot build GGH_FO (needs the GGH_crypto package): {e}")

    enabled = set(oqs.get_enabled_kem_mechanisms())
    if kem not in enabled:
        raise SystemExit(f"KEM '{kem}' not enabled in this liboqs build "
                          f"(see `modularot list-kems`)")
    if not is_supported_oqs(kem):
        raise SystemExit(f"KEM '{kem}' has no oblivious sampler, refused "
                          f"rather than weaken security")
    return (kem, _oqs_kem_factory(kem), resolve_oqs(kem))


def _median(xs):
    return int(statistics.median(xs))


def warmup(kem_factory) -> None:
    """Absorb lazy-init overhead outside the timed region."""
    kem = kem_factory()
    pk, sk = kem.Gen()
    ss, ct = kem.encaps(pk)
    kem.decaps(sk, ct)


def bench_sampler_vs_keygen(kem_factory, sampler, reps: int) -> dict:
    """Median cost of one real KeyGen vs one oblivious sample."""
    keygen_ns, sample_ns = [], []
    for _ in range(reps):
        kem = kem_factory()
        t0 = time.perf_counter_ns()
        pk, _sk = kem.Gen()
        keygen_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        sampler(pk)
        sample_ns.append(time.perf_counter_ns() - t0)
    return {"keygen": _median(keygen_ns), "sample": _median(sample_ns)}


def bench_cell(label: str, kem_factory, sampler, n: int, reps: int) -> dict:
    """Median timings over `reps` runs of a full 1-out-of-n OT session."""
    runs = []
    for r in range(reps):
        # security check on the first rep only
        runs.append(run_ot(kem_factory, sampler, label,
                           choice=0, n=n, check_security=(r == 0),
                           verbose=False))
    first = runs[0]
    return {
        "KEM": label, "n": n,
        "request": _median([r["request"] for r in runs]),
        "transfer": _median([r["transfer"] for r in runs]),
        "finalize": _median([r["finalize"] for r in runs]),
        "TOTAL": _median([r["TOTAL"] for r in runs]),
        "pk_bw": first["pk_bw"], "ct_bw": first["ct_bw"],
        "ok": all(r["ok"] for r in runs), "secure": first["secure"],
    }


# ── `run`: use the library from the command line ────────────────────────────

def cmd_run(args) -> None:
    label, factory, sampler = _build_entry(args.kem, args.ntrufo_n, args.ggh_dim)

    n = args.n
    if not 0 <= args.choice < n:
        raise SystemExit(f"--choice must be in [0, {n - 1}]")

    if args.message and args.message_file:
        raise SystemExit("use either --message or --message-file, not both")
    if args.message:
        if len(args.message) != n:
            raise SystemExit(
                f"need exactly {n} --message values (one per branch, in "
                f"order), got {len(args.message)}")
        messages = [m.encode() for m in args.message]
    elif args.message_file:
        if len(args.message_file) != n:
            raise SystemExit(
                f"need exactly {n} --message-file values (one per branch, "
                f"in order), got {len(args.message_file)}")
        messages = [open(p, "rb").read() for p in args.message_file]
    else:
        messages = None  # run_ot falls back to placeholder messages

    result = run_ot(factory, sampler, label, choice=args.choice, n=n,
                     messages=messages, check_security=not args.no_security_check,
                     verbose=not args.quiet)

    if args.quiet:
        sys.stdout.buffer.write(result["message"] or b"")

    if args.output:
        with open(args.output, "wb") as f:
            f.write(result["message"] or b"")
        if not args.quiet:
            print(f"Decrypted message written to {args.output}")

    if not result["ok"]:
        raise SystemExit(1)


# ── `list-kems` ───────────────────────────────────────────────────────────

def cmd_list_kems(args) -> None:
    enabled = sorted(a for a in oqs.get_enabled_kem_mechanisms() if is_supported_oqs(a))
    print(f"liboqs KEMs with an oblivious sampler ({len(enabled)}, usable with --kem/--kems):")
    for k in enabled:
        print(f"  {k}")
    print("\nCustom KEMs (need `pip install modularot[custom-kems]`):")
    print("  NTRU_FO      ring degree via --ntrufo-n (default 701)")
    print("  GGH_FO   dimension via --ggh-dim (default 200)")


# ── `bench`: scalability sweep ───────────────────────────────────────────────

def cmd_bench(args) -> None:
    enabled = set(oqs.get_enabled_kem_mechanisms())
    if args.all:
        kems = sorted(a for a in enabled if is_supported_oqs(a))
    else:
        kems = args.kems or DEFAULT_KEMS
        missing = [a for a in kems if a not in enabled]
        unsupported = [a for a in kems if a in enabled and not is_supported_oqs(a)]
        if missing:
            print(f"skipping (not enabled in this liboqs build): {', '.join(missing)}")
        if unsupported:
            print(f"skipping (no oblivious sampler): {', '.join(unsupported)}")
        kems = [a for a in kems if a in enabled and is_supported_oqs(a)]

    # (label, kem_factory, sampler) — oqs mechanisms plus the custom KEMs
    entries = [(alg, _oqs_kem_factory(alg), resolve_oqs(alg)) for alg in kems]

    if not args.no_custom:
        try:
            entries.append(_ntrufo_entry(args.ntrufo_n))
        except Exception as e:
            print(f"skipping NTRU_FO: {e}")
        try:
            entries.append(_gghfo_entry(args.ggh_dim))
        except Exception as e:
            print(f"skipping GGH_FO (needs the GGH_crypto package): {e}")

    if not entries:
        raise SystemExit("no benchmarkable KEMs selected")

    print(f"KEMs: {', '.join(label for label, _, _ in entries)}")
    print(f"n: {args.ns}   reps/cell: {args.reps}\n")

    # ── table 1: real KeyGen vs oblivious sample ──────────────────────────────
    print("═" * 78)
    print("KeyGen vs oblivious sample (median, one call)")
    print("═" * 78)
    print(f"{'KEM':<22} {'KeyGen':>14} {'ObliviousSample':>16} {'ratio':>9}")
    print("─" * 78)
    ratios = {}
    for label, factory, sampler in entries:
        warmup(factory)
        r = bench_sampler_vs_keygen(factory, sampler, args.reps)
        ratio = r["keygen"] / max(r["sample"], 1)
        ratios[label] = r
        print(f"{label:<22} {_fmt_ns(r['keygen']):>14} {_fmt_ns(r['sample']):>16} "
              f"{ratio:>8.1f}x")
    print("─" * 78)

    # ── table 2: full-session scaling over n ─────────────────────────────────
    rows = []
    for label, factory, sampler in entries:
        print(f"\n{'═' * 98}")
        print(f"{label} — 1-out-of-n scaling (medians of {args.reps} runs)")
        print(f"{'═' * 98}")
        print(f"{'n':>4} {'Request':>12} {'Transfer':>12} {'Finalize':>12} "
              f"{'TOTAL':>12} {'BW R->S':>12} {'BW S->R':>12}  OK SEC")
        print("─" * 98)
        for n in args.ns:
            cell = bench_cell(label, factory, sampler, n, args.reps)
            rows.append(cell)
            print(f"{n:>4} {_fmt_ns(cell['request']):>12} {_fmt_ns(cell['transfer']):>12} "
                  f"{_fmt_ns(cell['finalize']):>12} {_fmt_ns(cell['TOTAL']):>12} "
                  f"{cell['pk_bw']:>10} B {cell['ct_bw']:>10} B  "
                  f"{'✓' if cell['ok'] else '✗'}  {'✓' if cell['secure'] else '✗'}")
        print("─" * 98)

    # ── CSV for plots ─────────────────────────────────────────────────────────
    # units in the header, fixed-precision milliseconds
    fields = ["kem", "n",
              "request_ms", "transfer_ms", "finalize_ms", "total_ms",
              "pk_bytes", "ct_bytes", "total_bytes",
              "keygen_ms", "obliv_sample_ms", "keygen_over_sample",
              "ok", "secure"]

    def _ms(ns: int) -> float:
        return round(ns / 1e6, 4)

    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            r = ratios[row["KEM"]]
            w.writerow({
                "kem": row["KEM"], "n": row["n"],
                "request_ms": _ms(row["request"]),
                "transfer_ms": _ms(row["transfer"]),
                "finalize_ms": _ms(row["finalize"]),
                "total_ms": _ms(row["TOTAL"]),
                "pk_bytes": row["pk_bw"],
                "ct_bytes": row["ct_bw"],
                "total_bytes": row["pk_bw"] + row["ct_bw"],
                "keygen_ms": _ms(r["keygen"]),
                "obliv_sample_ms": _ms(r["sample"]),
                "keygen_over_sample": round(r["keygen"] / max(r["sample"], 1), 2),
                "ok": row["ok"], "secure": row["secure"],
            })
    print(f"\nCSV written to {args.csv} ({len(rows)} rows)")


# ── argument parsing / dispatch ──────────────────────────────────────────────

def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kem", default="ML-KEM-768",
                   help="KEM mechanism name, liboqs or custom (NTRU_FO, "
                        "GGH_FO); see `modularot list-kems` (default: ML-KEM-768)")
    p.add_argument("--n", type=int, default=2,
                   help="number of branches, 1-out-of-n (default: 2)")
    p.add_argument("--choice", type=int, default=0,
                   help="branch the receiver wants to learn (default: 0)")
    p.add_argument("--message", action="append", metavar="MSG",
                   help="sender's message for one branch (utf-8 text); pass "
                        "once per branch, in branch order (default: "
                        "placeholder demo messages)")
    p.add_argument("--message-file", action="append", metavar="PATH",
                   help="like --message but read raw bytes from a file; "
                        "pass once per branch, in branch order")
    p.add_argument("--output", metavar="PATH",
                   help="write the receiver's decrypted message to this "
                        "file (default: printed to stdout)")
    p.add_argument("--ggh-dim", type=int, metavar="DIM", default=200,
                   help="dimension for --kem GGH_FO (default: 200)")
    p.add_argument("--ntrufo-n", type=int, metavar="N", default=701,
                   help="ring degree for --kem NTRU_FO (default: 701)")
    p.add_argument("--no-security-check", action="store_true",
                   help="skip the adversarial curious-receiver check")
    p.add_argument("--quiet", action="store_true",
                   help="print nothing but the raw decrypted message bytes")


def _add_bench_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kems", nargs="+", default=None,
                   help="mechanisms to benchmark (default: representative subset)")
    p.add_argument("--all", action="store_true",
                   help="benchmark every supported enabled mechanism")
    p.add_argument("--ns", nargs="+", type=int, default=DEFAULT_NS,
                   help=f"branch counts (default: {DEFAULT_NS})")
    p.add_argument("--reps", type=int, default=5,
                   help="repetitions per cell, median reported (default: 5)")
    p.add_argument("--no-custom", action="store_true",
                   help="skip the custom NTRU_FO and GGH_FO KEMs (on by default)")
    p.add_argument("--ggh-dim", type=int, metavar="DIM", default=200,
                   help="dimension for the custom GGH_FO KEM (default: 200; "
                        "teaching-scale, needs the GGH_crypto package)")
    p.add_argument("--ntrufo-n", type=int, metavar="N", default=701,
                   help="ring degree for the custom NTRU_FO KEM (default: 701)")
    p.add_argument("--csv", default="ot_scaling.csv",
                   help="CSV output path (default: ot_scaling.csv)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="modularot",
        description="Modular KEM-based 1-out-of-n Oblivious Transfer (semi-honest)")
    sub = ap.add_subparsers(dest="command", required=True)

    rp = sub.add_parser("run", help="run one 1-out-of-n OT transfer")
    _add_run_args(rp)
    rp.set_defaults(func=cmd_run)

    bp = sub.add_parser("bench", help="scaling benchmark across KEMs and branch counts")
    _add_bench_args(bp)
    bp.set_defaults(func=cmd_bench)

    lp = sub.add_parser("list-kems", help="list KEM names usable with run/bench")
    lp.set_defaults(func=cmd_list_kems)

    return ap


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
