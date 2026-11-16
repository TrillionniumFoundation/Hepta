"""Bounded host scratch implementation of HIA's owned-byte VM memory writes.

Verified HIA controls ownership and bounds. This host-only implementation
preserves bytewise fill and memmove semantics without O(request_size) temporary
bytearrays. It does not replace LLVM's native memset/memmove or prove a global
process-memory budget (the Python VM and allocator still use memory).
"""
from __future__ import annotations

_CHUNK = 4096


def _range(buffer: bytearray, offset: int, count: int) -> None:
    if (type(buffer) is not bytearray or type(offset) is not int
            or type(count) is not int or offset < 0 or count < 0
            or offset > len(buffer) or count > len(buffer) - offset):
        raise ValueError("E_HIA_VM_RANGE: invalid owned-byte extent")


def fill_bytes(buffer: bytearray, offset: int, count: int, value: int) -> None:
    """Fill a validated byte range using at most one 4KiB byte pattern."""
    _range(buffer, offset, count)
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError("E_HIA_VM_VALUE: expected u8")
    if not count:
        return
    # Seed at most 4 KiB, then double the filled region using disjoint
    # memoryview-to-memoryview copies. No large Python bytes object is formed.
    seeded = min(count, _CHUNK)
    pattern = bytes((value,)) * seeded
    view = memoryview(buffer)
    view[offset:offset + seeded] = pattern
    filled = seeded
    while filled < count:
        width = min(filled, count - filled)
        view[offset + filled:offset + filled + width] = view[offset:offset + width]
        filled += width


def move_bytes(buffer: bytearray, destination: int, source: int, count: int) -> None:
    """Move overlapping ranges as-if via temporary, with <=4KiB scratch."""
    _range(buffer, destination, count)
    _range(buffer, source, count)
    if not count or destination == source:
        return
    view = memoryview(buffer)
    if destination + count <= source or source + count <= destination:
        # Non-overlapping native buffer assignment needs no byte snapshot.
        view[destination:destination + count] = view[source:source + count]
        return
    if source < destination < source + count:
        remaining = count
        while remaining:
            width = min(remaining, _CHUNK)
            start = remaining - width
            view[destination + start:destination + start + width] = bytes(
                view[source + start:source + start + width])
            remaining = start
    else:
        for start in range(0, count, _CHUNK):
            width = min(_CHUNK, count - start)
            view[destination + start:destination + start + width] = bytes(
                view[source + start:source + start + width])
