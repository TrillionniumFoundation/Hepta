"""Shared mechanical call frame for the exact HIA serde diagnostic facet."""
from __future__ import annotations

HELPERS = r'''
def typed_error(o:mutbuf, w:mutbuf, mode:u64, source:u64, size:u64, next:u64) -> u32:
    put(w, 0, next)
    put(w, 58720256, mode & 255)
    put(w, 58720264, mode >> 8)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, 58720256)
    put(o, 24, 8388608)
    put(o, 32, 4194304)
    put(o, 40, 46137344)
    return 26

def typed_failure(w:mutbuf, prefix:u64, prefix_size:u64) -> u32:
    size = get(w, 8)
    if size == 0 or size > 8388608 or get(w, 67616) != 58720256 or get(w, 67624) != size:
        return 0
    if prefix > length(w) or prefix_size > length(w) - prefix or prefix_size > 1048576:
        return 0
    target = 58720256 - prefix_size
    index = 0
    while index < prefix_size:
        store(w, target + index, byte(w, prefix + index))
        index = index + 1
    return diagnostic(w, target, prefix_size + size)
'''
