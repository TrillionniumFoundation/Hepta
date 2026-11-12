"""Application-layer assembly selection, preserving its original JSON provider."""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
import os
from .hia_front_selection import admit
from .hia_assembly_front_native import NativeAssemblyFront, SOURCE, SCHEMA, SELECTOR
from .hia_core_verification_selection import borrow_core_verification_scope

_UNSCOPED = object()
_OWNER = ContextVar('hia_assembly_front_captured_owner', default=_UNSCOPED)

def _selected_admission():
    value = _OWNER.get()
    if value is not _UNSCOPED:
        return value
    path = os.environ.get(SELECTOR)
    return admit(path, SOURCE, SCHEMA, SELECTOR, NativeAssemblyFront) if path else None

def installed_assembly_front(manifest_path):
    return admit(manifest_path, SOURCE, SCHEMA, SELECTOR, NativeAssemblyFront).owner

def captured_checker_owner():
    value = _OWNER.get()
    return (False, None) if value is _UNSCOPED else (True, None if value is None else value.checker_owner)

def active_assembly_front():
    value = _OWNER.get()
    return None if value is _UNSCOPED or value is None else value.owner

@contextmanager
def native_assembly_front_scope():
    captured = _selected_admission()
    previous = _OWNER.get()
    try:
        _OWNER.set(captured)
        with borrow_core_verification_scope():
            yield None if captured is None else captured.owner
    finally:
        _OWNER.set(previous)
