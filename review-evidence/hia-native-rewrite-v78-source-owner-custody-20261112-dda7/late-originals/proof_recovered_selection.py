"""Capture proof-contract selection for one complete call or service lifetime."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import os

SELECTOR = 'HEPTA_HIA_PROOF_CONTRACT_MANIFEST'
_UNSCOPED = object()
_ACTIVE = ContextVar('hia_proof_contract_owner', default=_UNSCOPED)


def capture_proof_contract():
    """Fresh explicit admission; absence does not load an unused native ABI."""
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    from .hia_proof_contract_native import installed_proof_contract, NativeProofContractOwner
    admitted = installed_proof_contract(selected, capture_identity=True)
    return NativeProofContractOwner(admitted.image, checker_custody=admitted)


def selected_proof_contract():
    selected = _ACTIVE.get()
    return capture_proof_contract() if selected is _UNSCOPED else selected


@contextmanager
def proof_contract_scope(owner):
    """Keep both a held owner and a captured absence stable across callbacks."""
    if owner is not None:
        from .hia_proof_contract_native import NativeProofContractOwner
        if type(owner) is not NativeProofContractOwner:
            raise TypeError('proof-contract scope requires its actual held owner')
    token = _ACTIVE.set(owner)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def active_proof_contract():
    selected = _ACTIVE.get()
    return None if selected is _UNSCOPED else selected
