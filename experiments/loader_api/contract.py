"""Small falsifiable contract models; no production imports or global limits.

Admission counts model inputs, not physical memory or a hard CPU/time bound.
"""
from dataclasses import dataclass, asdict
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True)
class BudgetDiagnostic:
    code: str
    phase: str
    dimension: str
    limit: int
    admitted: int
    attempted: int

    def to_dict(self):
        return asdict(self)


class BudgetExceeded(RuntimeError):
    # Must not be HeptaError/ValueError: unchanged() and metadata catches hide those.
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__(f'{diagnostic.dimension} budget exceeded during {diagnostic.phase}')


class Ledger:
    """Model for admission counters. Physical OS reads retain sentinel accounting.

    This model deliberately does not wrap #619's string exceptions or claim that
    every existing failure can already produce a structured diagnostic.
    """
    def __init__(self, limits):
        if any(type(v) is not int or v < 0 for v in limits.values()):
            raise ValueError('limits must be nonnegative integers')
        self.limits = MappingProxyType(dict(limits))
        self.counts = {name: 0 for name in limits}
        self.failure = None

    def check(self):
        if self.failure is not None:
            raise BudgetExceeded(self.failure)

    def charge(self, dimension, amount, *, phase):
        self.check()
        if dimension not in self.limits or type(amount) is not int or amount < 0:
            raise ValueError('invalid admission')
        attempted = self.counts[dimension] + amount
        if attempted > self.limits[dimension]:
            self.failure = BudgetDiagnostic('E_LOAD_BUDGET', phase, dimension,
                                            self.limits[dimension], self.counts[dimension], attempted)
            raise BudgetExceeded(self.failure)
        self.counts[dimension] = attempted


class OverlayRejected(ValueError):
    """Opt-in profile policy error, not a claim about legacy acceptance."""


def freeze_overrides(mapping, ledger, *, phase='admit'):
    """Freeze ordinary caller-owned dicts once, preserving aliases only if unique.

    Counts ALL entries/UTF-8 bytes, including unused paths. Per-source limits and
    filesystem/root validation still belong to graph reads. No native publication
    is authorized by this model. Dict/str subclasses are refused to avoid invoking
    user-defined iteration/encoding callbacks in this isolated profile.
    """
    ledger.check()
    if mapping is None:
        mapping = {}
    if type(mapping) is not dict:
        raise OverlayRejected('bounded profile requires an ordinary dict')
    frozen = {}
    for key, value in mapping.items():
        ledger.charge('override_entries', 1, phase=phase)
        if type(key) is not str or type(value) is not str:
            raise OverlayRejected('bounded profile requires string paths and text')
        # Each chunk is admitted before retaining its encoded bytes. A single
        # bounded temporary chunk exists before admission, not an unbounded encode.
        chunks = []
        for start in range(0, len(value), 1024):
            encoded = value[start:start + 1024].encode('utf-8')
            ledger.charge('override_bytes', len(encoded), phase=phase)
            chunks.append(encoded)
        path = str(Path(key).resolve())
        if path in frozen:
            raise OverlayRejected('multiple override keys resolve to one source')
        frozen[path] = b''.join(chunks)
    return MappingProxyType(frozen)
