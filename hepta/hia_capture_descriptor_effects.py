"""Explicit raw Linux/x86-64 descriptor ABI candidate.

This interface is not an os module or stream facade. It does not silently
replace os.open/fdopen, retry EINTR, decode struct stat, or choose cleanup.
The HIA control adapter in this package still uses original hosted providers.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import os
import platform
import struct
from .hia_json_preflight_native import NativeHiaJsonImage
from .hia_native_delivery import DeliveryRecord

REQUEST_MAGIC = 0x3151504143464948
RESULT_MAGIC = 0x3152504143464948
OPENAT, FSTAT, READ, CLOSE = 1, 2, 3, 4
_RESULT_ARRAY = ctypes.c_char * 80

class DescriptorUnknown(RuntimeError):
    """Actual syscall delivery has no acknowledged outcome; never retry."""

class NativeCaptureDescriptor(NativeHiaJsonImage):
    """A separately admitted raw image, not a generic worker HIA helper."""
    def __init__(self, raw, digest, *, assembly_source, assembly_sha256):
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
            raise ValueError('raw descriptor ABI requires Linux x86-64')
        if type(assembly_source) is not bytes or sha256(assembly_source).hexdigest() != assembly_sha256:
            raise ValueError('descriptor source differs from fixed assembly input')
        super().__init__(raw, digest)
        self.assembly_sha256 = assembly_sha256

@dataclass(frozen=True)
class DescriptorOutcome:
    operation: int
    result: int
    payload: bytes
    state: bytes

def _handoff(record, extent):
    record.enter_native()
    return extent

class DescriptorInvocation:
    """Own one request/workspace before the actual syscall handoff.

A successful result is returned exactly once. Unknown delivery retains this
object through DeliveryRecord, including request, work receipt and raw fd.
There is no implicit close/finalizer or retry on either successful or unknown
open/close. Negative kernel results are confirmed ordinary raw outcomes.
    """
    def __init__(self, image, operation, fd, *, flags=0, mode=0, path=b'', count=0):
        if type(image) is not NativeCaptureDescriptor:
            raise TypeError('descriptor primitive requires an admitted exact image')
        if type(operation) is not int or operation not in (OPENAT, FSTAT, READ, CLOSE):
            raise ValueError('invalid descriptor operation')
        if type(fd) is not int or not -(1 << 31) <= fd < (1 << 31):
            raise ValueError('descriptor ABI requires a signed Linux int fd')
        if any(type(x) is not int for x in (flags, mode, count)):
            raise TypeError('raw descriptor integer fields must be exact int')
        if not 0 <= flags < (1 << 32) or not 0 <= mode < (1 << 32) or not 0 <= count < (1 << 63):
            raise ValueError('raw descriptor fields are outside the explicit ABI')
        if type(path) is not bytes or b'\0' in path:
            raise ValueError('raw pathname must be encoded bytes without NUL')
        if operation != OPENAT and (flags or mode or path):
            raise ValueError('non-open descriptor request has path fields')
        if operation != READ and count:
            raise ValueError('non-read descriptor request has a read extent')
        self.image, self.operation, self.fd = image, operation, fd
        self.identity = struct.unpack('<2Q', os.urandom(16))
        tail = path + b'\0' if operation == OPENAT else b''
        extent = 208 if operation == FSTAT else 64 + count if operation == READ else 64
        self.raw = struct.pack('<2Qq5Q', REQUEST_MAGIC, operation, fd,
                               flags if operation == OPENAT else count, mode,
                               len(tail), *self.identity) + tail
        # Variable request/workspace buffers use ctypes' array cache. Their
        # GC behavior requires independent qualification before any public
        # opt-in route; this raw primitive is not silently installed there.
        self.request = ctypes.create_string_buffer(self.raw + b'\xc9' * 16, len(self.raw) + 16)
        self.output = ctypes.create_string_buffer(80)
        ctypes.memmove(ctypes.addressof(self.output) + 64, b'\xa5' * 16, 16)
        self.workspace = ctypes.create_string_buffer(extent + 16)
        ctypes.memmove(ctypes.addressof(self.workspace) + extent, b'\xb7' * 16, 16)
        self.extent, self.used = extent, False
        self.record = DeliveryRecord(self)

    def finish(self):
        if self.used:
            raise DescriptorUnknown('descriptor invocation cannot be reused')
        self.used = True
        record = self.record
        try:
            record.check(DescriptorUnknown)
            code = self.image._entry(self.request, len(self.raw), self.output, 64,
                                     self.workspace, _handoff(record, self.extent))
            state = self.workspace.raw[:self.extent]
            result = struct.unpack('<4Qq3Q', self.output.raw[:64])
            words = struct.unpack('<2Qq5Q', state[:64])
            if (code != 64 or self.request.raw != self.raw + b'\xc9' * 16
                    or self.output.raw[64:] != b'\xa5' * 16
                    or self.workspace.raw[self.extent:] != b'\xb7' * 16
                    or result[:4] != (RESULT_MAGIC, 0, self.operation, 2)
                    or result[5:7] != self.identity or result[7] != 0
                    or words[:2] != (2, self.operation)
                    or words[2] != result[4] or words[3:5] != self.identity
                    or words[5:] != (0, 0, 0)):
                raise DescriptorUnknown('descriptor result is not a confirmed syscall receipt')
            if self.operation == READ and result[4] > self.extent - 64:
                raise DescriptorUnknown('read result exceeds borrowed output extent')
            outcome = DescriptorOutcome(self.operation, result[4], state[64:], state)
            record.check(DescriptorUnknown)
            record.confirmed(terminal=True)
            return outcome
        except BaseException as error:
            record.failed(error)
            raise
        finally:
            record.retire()
