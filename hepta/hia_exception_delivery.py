"""Fixed CPython raised-exception transport, emitted by a selected HIA image.

This is an explicit hosted interpreter mechanism. It neither selects a policy
error nor repairs cause/context/notes in Python. One held-GIL machine call adds
the reference stolen by PyErr_SetRaisedException and sets the exact exception.
The owner decides when its foreign scopes may be released and grants delivery.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import mmap
import platform
import struct
import sys
import threading

EMIT_MAGIC = int.from_bytes(b'HIACTP01', 'little')
FRAME_MAGIC = int.from_bytes(b'HIACTE01', 'little')
EMIT_REQUEST = struct.pack('<8Q', EMIT_MAGIC, 0, 0, 0, 0, 0, 0, 0)
CODE_BYTES = 69
CODE_SHA256 = 'f2e2bd93e353f347940221d324ca6faf42957815c6ac410142a55d9a982163e8'


class ExceptionDeliveryUnavailable(RuntimeError):
    """The fixed interpreter mechanism has no confirmed transport outcome."""


def _address(buffer):
    return ctypes.addressof(ctypes.c_char.from_buffer(buffer))


class ExceptionDelivery:
    def __init__(self, code):
        self.mapping = None
        self._frames = {}
        self._lock = threading.RLock()
        self._cleanup = None
        self.closed = False
        if (sys.implementation.name != 'cpython' or sys.version_info[:2] < (3, 12)
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or ctypes.sizeof(ctypes.c_void_p) != 8):
            raise ExceptionDeliveryUnavailable('exception delivery requires CPython 3.12+ on Linux x86-64 LP64')
        if type(code) is not bytes or len(code) != CODE_BYTES or sha256(code).hexdigest() != CODE_SHA256:
            raise ExceptionDeliveryUnavailable('exception delivery bytes differ from the fixed HIA emitter')
        try:
            self._apis = (ctypes.pythonapi.Py_IncRef, ctypes.pythonapi.PyErr_SetRaisedException)
            self.api_addresses = tuple(ctypes.cast(fn, ctypes.c_void_p).value for fn in self._apis)
        except (AttributeError, TypeError) as error:
            raise ExceptionDeliveryUnavailable('current interpreter lacks the exact public delivery API') from error
        if any(type(address) is not int or not address for address in self.api_addresses):
            raise ExceptionDeliveryUnavailable('current interpreter API addresses are unavailable')
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        self._libc.mprotect.restype = ctypes.c_int
        try:
            self.mapping = mmap.mmap(-1, CODE_BYTES, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            self.mapping.write(code)
            self.code_address = _address(self.mapping)
            self._protect(self.code_address, CODE_BYTES, mmap.PROT_READ | mmap.PROT_EXEC)
            self._entry = ctypes.PYFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(self.code_address)
        except BaseException:
            if self.mapping is not None:
                try:
                    self.mapping.close()
                except BaseException as cleanup:
                    self._cleanup = ('constructor cleanup unconfirmed', type(cleanup).__name__)
                else:
                    self.mapping = None
            raise

    @classmethod
    def from_hia(cls, image):
        source = ctypes.create_string_buffer(EMIT_REQUEST, len(EMIT_REQUEST))
        output = ctypes.create_string_buffer(CODE_BYTES + 16)
        workspace = ctypes.create_string_buffer(b'\xb7' * 128, 128)
        ctypes.memset(ctypes.addressof(output) + CODE_BYTES, 0xa5, 16)
        count = image._entry(source, len(EMIT_REQUEST), output, CODE_BYTES, workspace, len(workspace))
        if (type(count) is not int or count != CODE_BYTES or source.raw != EMIT_REQUEST
                or output.raw[CODE_BYTES:] != b'\xa5' * 16 or workspace.raw != b'\xb7' * 128):
            raise ExceptionDeliveryUnavailable('selected HIA image did not emit the exact guarded delivery mechanism')
        return cls(output.raw[:CODE_BYTES])

    def _protect(self, address, length, protection):
        if self._libc.mprotect(address, length, protection):
            raise ExceptionDeliveryUnavailable('exception delivery memory protection failed')

    def deliver(self, error):
        if not issubclass(type(error), BaseException):
            raise TypeError('exception delivery requires an actual BaseException instance')
        token = object()
        held = {'mapping': None, 'cleanup': None}
        with self._lock:
            if self.closed:
                raise ExceptionDeliveryUnavailable('exception delivery is closed')
            # A shared image has one immutable RX mapping. Each independently
            # admitted caller gets its own retained frame, including reentry.
            # The lock is never held across the actual interpreter API call.
            self._frames[token] = held
        try:
            # The exception is borrowed only for this call. Its exact address
            # and the two admitted API addresses reside in a private R-only
            # frame while the interpreter acquires the new raised reference.
            held['mapping'] = mmap.mmap(-1, 32, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            held['mapping'].write(struct.pack('<4Q', FRAME_MAGIC, *self.api_addresses, id(error)))
            address = _address(held['mapping'])
            self._protect(address, 32, mmap.PROT_READ)
            self._entry(address)
            raise ExceptionDeliveryUnavailable('fixed delivery returned without the original raised exception')
        finally:
            # Do not retain error -> traceback -> this-local -> error. Never
            # clear caller scopes or rewrite the interpreter's exception chain.
            error = None
            try:
                if held['mapping'] is not None:
                    held['mapping'].close()
            except BaseException as cleanup:
                # An unconfirmed physical cleanup keeps this exact frame
                # strongly owned. It cannot be reused or silently discarded.
                held['cleanup'] = ('frame cleanup unconfirmed', type(cleanup).__name__)
            else:
                held['mapping'] = None
                with self._lock:
                    self._frames.pop(token)

    def close(self):
        with self._lock:
            if self._frames:
                raise ExceptionDeliveryUnavailable('cannot close active or unconfirmed delivery frames')
            # Closing permanently refuses new calls. An explicit subsequent
            # close may retire the same idempotent mmap after an interrupted
            # cleanup; it never re-delivers an exception or reuses a frame.
            self.closed = True
            if self.mapping is not None:
                self.mapping.close()
                self.mapping = None
