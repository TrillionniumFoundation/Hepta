"""Explicit selection between two complete borrowed-byte policy families.

The existing multi-image bundle and in-process scheduling route keeps its
selector. The independent single-image control keeps its distinct selector.
No manifest is probed to guess its family, and selected failures never fall
back to another owner. These functions own transport selection, not byte policy.
"""
from __future__ import annotations

from contextlib import contextmanager


def _requested_family():
    from .hia_byte_wrapper_selection import byte_wrapper_selection_requested
    from .hia_native_byte_abi_selection import native_byte_abi_selection_requested

    bundle = byte_wrapper_selection_requested()
    control = native_byte_abi_selection_requested()
    if bundle and control:
        raise ValueError('byte-wrapper bundle and native byte-ABI control cannot both be selected')
    if bundle:
        return 'bundle'
    if control:
        return 'control'
    return None


def selected_byte_policy(namespace):
    family = _requested_family()
    if family == 'bundle':
        from .hia_byte_wrapper_selection import selected_byte_wrapper
        owner = selected_byte_wrapper(namespace)
    elif family == 'control':
        from .hia_native_byte_abi_selection import selected_native_byte_abi
        owner = selected_native_byte_abi(namespace)
    else:
        return None, None
    if owner is None:
        raise ValueError('borrowed-byte policy selection changed during admission')
    return family, owner


@contextmanager
def native_byte_policy_scope(namespace):
    """Freeze both the selected family and the other family's absence."""
    from .hia_byte_wrapper_selection import native_byte_wrapper_scope
    from .hia_native_byte_abi_selection import _native_byte_abi_control_scope

    _requested_family()
    with native_byte_wrapper_scope(namespace):
        with _native_byte_abi_control_scope(namespace):
            _requested_family()
            yield
