"""Mechanical private storage for the HIA Code continuation ABI.

The buffer implementation is copied byte-for-byte from the pinned peer JSON
wire bridge. No JSON graph observer, traversal policy, selector or quota is
ported or selected by this module.
"""
from __future__ import annotations

import ctypes
import errno
import mmap
from types import FunctionType


def _code_call_names(cls):
    """Keep CPython's original public argument-binding diagnostics.

    This sets binding metadata only. The selected method bodies, images and
    class identity stay explicit; no retained method is called or copied.
    """
    for name, member in vars(cls).items():
        if type(member) is property:
            member = member.fget
        if type(member) is FunctionType:
            member.__qualname__ = 'Code.' + name
    return cls


def _private_zeroed_buffer(size):
    """Keep the complete ABI extent without eagerly touching unused pages.

    The ctypes view retains an exported memoryview of the private mapping.
    That reference owns the mapping for the full buffer lifetime, including
    observers that raise and callers that retain a buffer after its session.
    No explicit close may run while such an export is still alive.
    """
    try:
        mapped = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)
    except OSError as exc:
        if exc.errno == errno.ENOMEM:
            # The original physical allocator raises CPython's MemoryError
            # without introducing the failed mmap's OSError into its context.
            # It can also use already-reserved heap storage when mmap cannot.
            return ctypes.create_string_buffer(size)
        raise
    try:
        return (ctypes.c_char * size).from_buffer(mapped)
    finally:
        # A returned exported view owns the mapping.  If construction fails,
        # this helper's traceback must not retain an unexported mapping.
        mapped = None
