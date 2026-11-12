"""Core-only capture, with an optional no-I/O application lease.

The Core public entry has no assembly or program-tools dependency. A lease
holds the first actual Core selection, including None, without moving that
selection ahead of an application's original syntax/provider effects.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
import os
from .hia_front_selection import admit
from .hia_core_verification_native import NativeCoreVerification, SOURCE, SCHEMA, SELECTOR

_UNSCOPED = object()
_OWNER = ContextVar('hia_core_verification_captured_owner', default=_UNSCOPED)

def _fresh():
    path = os.environ.get(SELECTOR)
    return admit(path, SOURCE, SCHEMA, SELECTOR, NativeCoreVerification) if path else None

class _Lease:
    __slots__ = ('admission',)
    def __init__(self):
        self.admission = _UNSCOPED
    def resolve(self):
        if self.admission is _UNSCOPED:
            self.admission = _fresh()
        return self.admission

def _selected_admission():
    value = _OWNER.get()
    if type(value) is _Lease:
        return value.resolve()
    return _fresh() if value is _UNSCOPED else value

def installed_core_verification(manifest_path):
    return admit(manifest_path, SOURCE, SCHEMA, SELECTOR, NativeCoreVerification).owner

def captured_checker_owner():
    value = _OWNER.get()
    if value is _UNSCOPED:
        return False, None
    if type(value) is _Lease:
        value = value.resolve()
    return True, None if value is None else value.checker_owner

def active_core_verification():
    value = _OWNER.get()
    if type(value) is _Lease:
        value = value.admission
    return None if value is _UNSCOPED or value is None else value.owner

@contextmanager
def borrow_core_verification_scope():
    previous = _OWNER.get()
    if previous is not _UNSCOPED:
        yield
        return
    try:
        _OWNER.set(_Lease())
        yield
    finally:
        _OWNER.set(previous)

@contextmanager
def native_core_verification_scope():
    captured = _selected_admission()
    previous = _OWNER.get()
    try:
        _OWNER.set(captured)
        yield None if captured is None else captured.owner
    finally:
        _OWNER.set(previous)
