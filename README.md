# Project Overview
This project was developed as part of a 2-year master's degree program at the Università degli Studi di Milano (University of Milan), following a 3-year bachelor's. It provides a modular implementation of a semi-honest 1-out-of-*n* Oblivious Transfer (OT) built on Key Encapsulation Mechanisms (KEMs), together with an empirical analysis of how well the construction adapts to different post-quantum lattice families. Building on the oblivious public-key technique [1]-[5], the work proposes a new KEM-agnostic 1-out-of-*n* OT scheme in which sampling an oblivious key is the only KEM-specific step, injected as a callable. The scheme is validated across heterogeneous KEMs (structured, unstructured, NTRU-based and GGH-based), measuring indistinguishability, cost and bandwidth as the number of branches grows.

## Attribution
Oblivious public-key sampling is **not** a contribution of this work. Having the receiver publish a key for which it knows no secret key goes back to Even, Goldreich and Lempel [1] and Bellare and Micali [2]. Naor and Pinkas [3] use it to build OT from public-key encryption, Peikert, Vaikuntanathan and Waters [4] generalize it with dual-mode cryptosystems, and Masny and Rindal [5] formalize it for any two-message KEM, with post-quantum instantiations. Gertner et al. [6] show that some such non-black-box property is unavoidable: no OT reduces black-box to a KEM or an IND-CPA PKE. What this work adds is the generalization to *n* branches, concrete samplers for several lattice families (ML-KEM, FrodoKEM, NTRU-HPS/HRSS, sntrup761, NTRU_FO, GGH-HNF) and an empirical validation of the construction.

# modularot Python Package
The OT protocol never names a specific scheme. The only KEM-specific operation, sampling an *oblivious* public key (a well-formed key whose secret nobody holds), is injected as a callable. This is necessarily KEM-specific: a black-box KEM cannot yield a sender-private OT [6]. See Attribution above for the origin of the technique.

How it works:
1. The receiver generates a real keypair for the chosen branch and an oblivious public key for every other branch, then sends all *n* public keys.
2. The sender encapsulates under each key and seals message *i* with ChaCha20-Poly1305, keyed from the shared secret via HKDF.
3. The receiver decapsulates only the chosen branch. It holds no secret for the others, so those messages stay hidden.

The package is composed of:
- `ot_protocol.py` which implements `OTSender`, `OTReceiver` and `run_ot`, plus an adversarial check that a curious receiver cannot open any other branch.
- `oblivious_sampling.py` which contains the per-family oblivious samplers: ML-KEM / Kyber, FrodoKEM, NTRU-HPS / HRSS, sntrup761, and the custom NTRU_FO and GGH-HNF.
- `kem_adapter/` which defines the `KEM` interface and `KEMAdapter`, used to plug in any KEM.
- `custom_kems/` which contains two research-grade KEMs built from scratch with the Fujisaki-Okamoto transform: `NTRU_FO` and `GGH_FO`.
- `cli.py` which provides the `modularot` command (`run`, `bench`, `list-kems`).

GGH is supported in its HNF form (Micciancio's variant [7], via [GGH_crypto](https://github.com/TheGaBr0/GGH) with `GGH_private=True`) because it is the only GGH format whose public key admits a sound oblivious sampler. The classic `B = U·R` public basis is distinguishable from any trapdoor-free sample by its determinant alone.

# Installation
```
pip install .
```
This installs `cryptography` and `liboqs-python`. **liboqs-python needs the [liboqs](https://github.com/open-quantum-safe/liboqs) C library built and installed first**; it is not a plain PyPI wheel. Follow the liboqs build instructions, then install `liboqs-python` from PyPI or from a local checkout.

The custom KEMs (NTRU_FO, GGH_FO) are an optional extra with their own native dependency (`python-flint`, built on FLINT/GMP/MPFR):
```
pip install ".[custom-kems]"
```

# General Usage
As a library:
```python
from modularot import run_ot, oqs_kem_factory, resolve_oqs

result = run_ot(
    make_kem=oqs_kem_factory("ML-KEM-768"),
    sampler=resolve_oqs("ML-KEM-768"),
    label="ML-KEM-768",
    choice=1,   # branch the receiver wants
    n=4,        # 1-out-of-4
)
assert result["ok"]      # receiver got the message it asked for
assert result["secure"]  # receiver could not open any other branch
```
`OTSender`, `OTReceiver` and `KEMAdapter` are also exported: to support a KEM that is not in liboqs you only need to write its oblivious sampler (see `oblivious_sampling.py` for worked examples of distinct encodings).

As a program:
```
modularot run                                  # ML-KEM-768, 1-out-of-2
modularot run --n 3 --choice 1 --message "a" --message "b" --message "c"
modularot list-kems                            # names usable with --kem / --kems

modularot bench                                # default KEM subset + custom KEMs
modularot bench --kems ML-KEM-768 sntrup761 --no-custom
modularot bench --ns 2 4 8 16 32 --reps 5 --csv out.csv
```
`run` performs one real transfer. `bench` reports per-phase timing and bandwidth for each KEM across branch counts and writes a CSV.

Tests, benchmarks and thesis material live in the [main branch](https://github.com/TheGaBr0/modularot/tree/main).

# Scope and limits
Semi-honest security only. `resolve_oqs` raises `NotImplementedError` for lattice mechanisms whose encoding is not wired yet (e.g. `ntrulpr`). `is_supported_oqs(alg)` checks in advance. NTRU_FO and GGH_FO are educational/research code and are **not** quantum-safe or production-ready (GGH remains concretely attackable at any practical dimension).

An observed result: the cost of the oblivious sampler relative to a real KeyGen depends on the family. The samplers are pure Python, so for ML-KEM they are slower than liboqs's C KeyGen, while for FrodoKEM and NTRU the KeyGen dominates. Receiver cost grows linearly with *n*.

# References
[1] S. Even, O. Goldreich, A. Lempel. *A Randomized Protocol for Signing Contracts*. Communications of the ACM 28(6), 1985, pp. 637-647.
[2] M. Bellare, S. Micali. *Non-Interactive Oblivious Transfer and Applications*. CRYPTO '89, LNCS 435, 1989, pp. 547-557.
[3] M. Naor, B. Pinkas. *Efficient Oblivious Transfer Protocols*. SODA 2001, pp. 448-457.
[4] C. Peikert, V. Vaikuntanathan, B. Waters. *A Framework for Efficient and Composable Oblivious Transfer*. CRYPTO 2008, LNCS 5157, pp. 554-571.
[5] D. Masny, P. Rindal. *Endemic Oblivious Transfer*. ACM CCS 2019, pp. 309-326.
[6] Y. Gertner, S. Kannan, T. Malkin, O. Reingold, M. Viswanathan. *The Relationship between Public Key Encryption and Oblivious Transfer*. FOCS 2000, pp. 325-335.
[7] D. Micciancio. *Improving Lattice Based Cryptosystems Using the Hermite Normal Form*. 2001, pp. 126-145.
