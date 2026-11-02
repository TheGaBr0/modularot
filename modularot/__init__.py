"""
modularot -- modular KEM-based 1-out-of-n Oblivious Transfer (semi-honest).

The protocol is KEM-agnostic; the only KEM-specific operation (sampling an
oblivious public key) is injected as a callable. See `ot_protocol` for the
construction and `oblivious_sampling` for the samplers.

Quick start (any liboqs lattice KEM)::

    from modularot import run_ot, oqs_kem_factory, resolve_oqs

    result = run_ot(
        make_kem=oqs_kem_factory("ML-KEM-768"),
        sampler=resolve_oqs("ML-KEM-768"),
        label="ML-KEM-768",
        choice=1,     # branch the receiver wants
        n=4,          # 1-out-of-4
    )
    assert result["ok"] and result["secure"]

`OTSender`, `OTReceiver` and `KEMAdapter` are exported for custom KEMs; see
`modularot.custom_kems` (NTRU_FO, GGH_FO) for examples.
"""

from .ot_protocol import (
    OTReceiver,
    OTSender,
    run_ot,
    receiver_cannot_read_other,
)
from .ot_protocol import _oqs_kem_factory as oqs_kem_factory
from .kem_adapter.adapter import KEM, KEMAdapter, KEMInfo
from .oblivious_sampling import resolve_oqs, is_supported_oqs

__version__ = "0.1.0"

__all__ = [
    "OTReceiver",
    "OTSender",
    "run_ot",
    "receiver_cannot_read_other",
    "oqs_kem_factory",
    "KEM",
    "KEMAdapter",
    "KEMInfo",
    "resolve_oqs",
    "is_supported_oqs",
    "__version__",
]
