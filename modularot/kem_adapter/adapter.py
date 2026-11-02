from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class KEMInfo:
    name: str
    is_quantum_safe: bool
    security_level: int   # classical security bits
    pk_bytes: int
    ct_bytes: int
    ss_bytes: int


class KEM(ABC):
    """Abstract Key Encapsulation Mechanism interface."""

    @property
    @abstractmethod
    def info(self) -> KEMInfo: ...

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    @abstractmethod
    def encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Return (shared_secret, ciphertext)."""

    @abstractmethod
    def decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        """Return shared_secret."""


class KEMAdapter(KEM):

    def __init__(self, gen, encap, decap, info: KEMInfo = None):
        self._gen   = gen
        self._encap = encap
        self._decap = decap
        self._info  = info or KEMInfo("generic", False, 0, 0, 0, 0)
        self.Gen    = gen
        self.encaps = encap
        self.decaps = decap

    @property
    def info(self) -> KEMInfo:
        return self._info

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self._gen()

    def encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        return self._encap(pk)

    def decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        return self._decap(sk, ct)
