"""Explicit single-image ELF selection and its held checker capability."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256

from .hia_machine_elf_native import (
    SELECTOR, SOURCE, SCHEMA, NativeMachineElf, _admit_machine_elf)

_UNSELECTED = object()
_OWNER = ContextVar('hia_machine_elf_admitted_selection', default=_UNSELECTED)


@dataclass(frozen=True, eq=False)
class _Admission:
    owner: NativeMachineElf
    checker_owner: object


def _admit(path, namespace=None):
    owner, manifest_raw, source_raw = _admit_machine_elf(path)
    from .hia_checker_identity import hold_native_owner
    return _Admission(owner, hold_native_owner(SELECTOR, owner, manifest_raw, source_raw))


def captured_checker_owner():
    admitted = _OWNER.get()
    if admitted is _UNSELECTED:
        return False, None
    return True, None if admitted is None else admitted.checker_owner


def native_implementation_identity(namespace=None):
    admitted = _OWNER.get()
    if admitted is _UNSELECTED:
        # Outside a scope this is a new selection. A selected failure cannot
        # fall back to the reference policy or the machine-object bundle.
        import os
        path = os.environ.get(SELECTOR)
        admitted = _admit(path, namespace) if path else None
    if admitted is None:
        return b''
    current_source = sha256(SOURCE.read_bytes()).hexdigest()
    if current_source != admitted.owner.admitted_source_sha256:
        raise ValueError('native ELF selected source changed after admission')
    return (admitted.owner.admitted_source_sha256 + ':' +
            admitted.owner.image_sha256).encode('ascii')


def selected_elf_policy(namespace):
    from .hia_backend_family_selection import elf_family
    selected = elf_family._select(namespace)
    return selected.family, selected.owner


def native_elf_policy_scope(namespace):
    from .hia_backend_family_selection import elf_family
    return elf_family.scope(namespace)
