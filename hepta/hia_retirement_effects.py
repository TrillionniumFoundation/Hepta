"""Fixed foreign I/O for retirement; this module owns no policy transitions.

The selected Linux open primitive records its kernel result in an already
retained slot before returning to the interpreter. A Python interruption can
therefore never turn a possibly successful open into an assumed absent fd.
The small os facade preserves the reference and existing fault-injection API
without changing the process-global os module.
"""
from __future__ import annotations

import ctypes
import errno
import os as _os

from .hia_json_preflight_native import NativeHiaJsonImage

# Independently assembled from tools/hia_retirement_open_syscalls.S. The source
# test requires byte identity; installation needs no assembler or tools tree.
OPEN_IMAGE = bytes.fromhex(
    '4989d049c700010000004889f24889fe48c7c79cffffff4531d2b8010100000f05'
    '4989400849c70002000000c3')
OPEN_SHA256 = '5d18ef084f37abc8582924dcf8376fa1e9d1de67de17d309617be9b3c34d5f7e'


class RetirementOpenPrimitive(NativeHiaJsonImage):
    def __init__(self):
        super().__init__(OPEN_IMAGE, OPEN_SHA256)

    def open(self, path, flags, result):
        if (not isinstance(result, ctypes.Array) or result._type_ is not ctypes.c_int64
                or len(result) != 2):
            raise ValueError('native retirement open requires its exact retained two-word slot')
        allowed = _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_NONBLOCK | _os.O_CLOEXEC
        if flags not in (allowed, allowed | _os.O_DIRECTORY):
            raise ValueError('native retirement open flags differ from the fixed read-only profile')
        encoded = _os.fsencode(path)
        if b'\0' in encoded:
            raise ValueError('embedded null byte')
        if tuple(result) != (0, 0):
            raise ValueError('native retirement open result slot was already used')
        pathname = ctypes.create_string_buffer(encoded)
        # The primitive uses only the first three SysV arguments. Its retained
        # result is written before this foreign call can resume Python dispatch.
        while True:
            self._entry(pathname, flags, result, 0, None, 0)
            stage, returned = result
            if stage != 2:
                raise RuntimeError('native retirement open has no recorded kernel result')
            if returned == -errno.EINTR:
                # Match os.open's interrupted-syscall behavior. Python signal
                # handlers can raise before this retry; the recorded negative
                # result then proves no descriptor was returned. A successful
                # or unconfirmed result is never retried.
                continue
            if returned < 0:
                raise OSError(-returned, _os.strerror(-returned), path)
            return returned


class _RetirementOS:
    def __getattr__(self, name):
        return getattr(_os, name)

    def open(self, path, flags, mode=0o777, *, dir_fd=None,
             _hia_result=None, _hia_primitive=None):
        if _hia_result is None and _hia_primitive is None:
            return _os.open(path, flags, mode, dir_fd=dir_fd)
        if _hia_result is None or _hia_primitive is None or mode != 0o777 or dir_fd is not None:
            raise ValueError('invalid native retirement open transport')
        return _hia_primitive.open(path, flags, _hia_result)


os = _RetirementOS()
