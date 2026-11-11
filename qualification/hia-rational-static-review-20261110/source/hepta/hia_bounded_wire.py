"""Strict, bounded UTF-8 text-to-wire admission for HIA evidence gates.

For immutable built-in str only: check exact UTF-8 byte length in ≤4096-codepoint
slices BEFORE allocating the complete encoded wire. Returned bytes, if admitted,
are always within the caller's declared maximum; this is not a JSON parser or a
source authentication/production authorization mechanism.
"""
from __future__ import annotations


class WireBudgetExceeded(ValueError):
    """UTF-8 evidence exceeds its configured upper byte bound."""


def checked_utf8_wire(text: str, max_bytes: int) -> bytes:
    if type(text) is not str or type(max_bytes) is not int or max_bytes < 0:
        raise TypeError("expected immutable built-in text and exact byte budget")
    if len(text) > max_bytes:
        raise WireBudgetExceeded("UTF-8 evidence exceeds wire byte budget")
    if text.isascii():
        return text.encode("ascii")
    count = 0
    for offset in range(0, len(text), 4096):
        count += len(text[offset:offset + 4096].encode("utf-8"))
        if count > max_bytes:
            raise WireBudgetExceeded("UTF-8 evidence exceeds wire byte budget")
    # The only complete encoded copy is made AFTER its exact size was admitted.
    return text.encode("utf-8")
