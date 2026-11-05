# modularot
Modular KEM-based 1-out-of-*n* Oblivious Transfer (semi-honest). The protocol never names a specific KEM: the only KEM-specific step, sampling an *oblivious* public key (a well-formed key nobody holds the secret for), is passed in as a callable.

The receiver sends one real public key for its choice and oblivious keys for the other branches. The sender encapsulates under every key and seals each message with ChaCha20-Poly1305. The receiver can only open the chosen one.

Samplers are included for ML-KEM / Kyber, FrodoKEM, NTRU-HPS / HRSS and sntrup761 (via liboqs), plus two research KEMs, `NTRU_FO` and `GGH_FO`, built with the Fujisaki-Okamoto transform.

## Install
```
pip install modularot
```
Requires the [liboqs](https://github.com/open-quantum-safe/liboqs) C library, installed before `liboqs-python`. The custom KEMs need an extra (`python-flint`):
```
pip install "modularot[custom-kems]"
```

## Usage
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

Command line:
```
modularot run --kem ML-KEM-768 --n 3 --choice 1
modularot list-kems
modularot bench --ns 2 4 8 --csv out.csv
```

## Other KEMs
Wrap the KEM in a `KEMAdapter(gen, encap, decap)` (all on `bytes`; `encap` returns `(shared_secret, ciphertext)`) and write a sampler `real_pk -> oblivious_pk` that returns a key in the same encoding as a real one, without running key generation. Then pass both to `run_ot`.

## Limits
Semi-honest security only. `NTRU_FO` and `GGH_FO` are research code, not quantum-safe or production-ready.
