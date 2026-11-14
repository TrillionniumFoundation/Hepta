"""Bounded host scratch implementation of HIA's owned-byte VM memory writes.

Verified HIA controls ownership and bounds. With an explicit native selection,
HIA also owns exact-kind/range/value admission and every byte mutation here.
The original bounded-scratch bodies remain independent qualification references;
no selected native failure falls back to them. The complete VM and allocator
remain hosted and this does not establish a global process-memory budget.
"""
from __future__ import annotations

_CHUNK = 4096


def _range(buffer: bytearray, offset: int, count: int) -> None:
    if (type(buffer) is not bytearray or type(offset) is not int
            or type(count) is not int or offset < 0 or count < 0
            or offset > len(buffer) or count > len(buffer) - offset):
        raise ValueError("E_HIA_VM_RANGE: invalid owned-byte extent")


def _reference_fill_bytes(buffer: bytearray, offset: int, count: int, value: int) -> None:
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


def _reference_move_bytes(buffer: bytearray, destination: int, source: int, count: int) -> None:
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


def fill_bytes(buffer: bytearray, offset: int, count: int, value: int) -> None:
    """Use the selected HIA owner, or the unchanged independent reference."""
    from .hia_bounded_memory_native import selected_bounded_memory
    native = selected_bounded_memory()
    if native is None:
        return _reference_fill_bytes(buffer, offset, count, value)
    return native.fill_bytes(buffer, offset, count, value)


def move_bytes(buffer: bytearray, destination: int, source: int, count: int) -> None:
    """Use the selected HIA owner, with no selected fallback."""
    from .hia_bounded_memory_native import selected_bounded_memory
    native = selected_bounded_memory()
    if native is None:
        return _reference_move_bytes(buffer, destination, source, count)
    return native.move_bytes(buffer, destination, source, count)
