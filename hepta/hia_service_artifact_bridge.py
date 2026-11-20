"""Mechanical Artifact provider lookup and captured-file reads.

Both function bodies are retained byte-for-byte from their 972 owners. This
module performs no business graph, UUID, FFI initialization or GC operation.
"""
import os
import stat


def _global_value(namespace, builtins, name):
    """Resolve an original provider global with its bound builtins fallback."""
    try:
        value = namespace[name]
    except KeyError:
        pass
    else:
        return value
    try:
        value = builtins[name]
    except KeyError:
        pass
    else:
        return value
    raise NameError("name '" + name + "' is not defined", name=name)



def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb', buffering=8192) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('store-lifecycle input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('store-lifecycle input changed while being read')
    return raw
