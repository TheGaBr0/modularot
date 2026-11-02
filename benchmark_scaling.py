"""
Thin compatibility shim: the benchmark now lives in modularot/cli.py and ships
as `modularot bench` once the package is installed (`pip install -e .`). This
file just keeps `python benchmark_scaling.py` working the same way it always
has, pointed at the `bench` subcommand.
"""

import sys

from modularot.cli import build_parser

if __name__ == "__main__":
    args = build_parser().parse_args(["bench"] + sys.argv[1:])
    args.func(args)
