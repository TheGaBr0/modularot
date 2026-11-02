# Project Overview
This project was developed as part of a 2-year master's degree program at the Università degli Studi di Milano (University of Milan), following a 3-year bachelor's. It provides a modular implementation of a semi-honest 1-out-of-*n* Oblivious Transfer (OT) built on Key Encapsulation Mechanisms (KEMs), together with an empirical analysis of how well the construction adapts to different post-quantum lattice families. The work does not claim a new protocol: it validates the modularity of the construction across heterogeneous KEMs (structured, unstructured, NTRU-based and GGH-based), measuring cost and bandwidth as the number of branches grows.

# modularot Python Package
The package itself (source code, `pyproject.toml`, installation and usage instructions) lives in the [release branch](https://github.com/TheGaBr0/modularot/tree/release). This branch contains the tests, benchmarks and thesis material built around it.

# Contents
- `tests/`: tests for the custom KEMs (`test_ntru_fo.py`) and for the three GGH variants (`test_ggh_versions.py`), which shows why the classic `B = U·R` public basis admits no sound oblivious sampler.
- `scripts_verifica/`: verification suite for the thesis (samplers, GGH variants, mix-and-match, adversarial tests, comparative analysis). See `scripts_verifica/README_cap6.md`.

# Running
Check out the `release` branch for the package, install it (see its README), then copy or check out the files from this branch next to it:
```
git worktree add ../modularot-release release
pip install "../modularot-release[custom-kems]"
python scripts_verifica/run_cap6.py --quick
```

# References and final notes
`scripts_verifica/` is written in Italian, as is the thesis.
