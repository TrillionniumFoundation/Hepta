"""Bounded exact-byte memoization for development evidence encoding only.

Every cache hit requires equality of all immutable bytes. No native event,
comparison, source check, ledger row or archived byte is omitted. Mutable
inputs are copied before caching. The cache owns at most 64 MiB / 32 items.
"""
from hashlib import sha256

MAX_BYTES = 64 << 20
MAX_ITEMS = 32
MIN_BYTES = 4096
_cache = []
_bytes = 0
_stats = dict(calls=0, hits=0, input_bytes=0, hashed_bytes=0,
              equality_comparisons=0, cached_bytes=0, cached_items=0)

def evidence_digest(raw):
    global _bytes
    raw = bytes(raw)
    size = len(raw)
    _stats['calls'] += 1
    _stats['input_bytes'] += size
    if MIN_BYTES <= size <= MAX_BYTES:
        for at in range(len(_cache) - 1, -1, -1):
            previous, identity = _cache[at]
            if len(previous) == size:
                _stats['equality_comparisons'] += 1
                if raw == previous:
                    _cache.append(_cache.pop(at))
                    _stats['hits'] += 1
                    return identity
    identity = sha256(raw).hexdigest()
    _stats['hashed_bytes'] += size
    if MIN_BYTES <= size <= MAX_BYTES:
        _cache.append((raw, identity))
        _bytes += size
        while len(_cache) > MAX_ITEMS or _bytes > MAX_BYTES:
            removed, _ = _cache.pop(0)
            _bytes -= len(removed)
        _stats['cached_bytes'] = _bytes
        _stats['cached_items'] = len(_cache)
    return identity

def evidence_cache_statistics():
    return dict(_stats)
