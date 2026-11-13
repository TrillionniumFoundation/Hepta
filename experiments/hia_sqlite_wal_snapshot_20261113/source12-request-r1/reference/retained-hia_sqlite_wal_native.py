"""Private byte transport for an explicitly qualified HIA WAL image.

Checksum arithmetic, format admission and frame validation belong to the HIA
entry. This bridge validates transport types, allocates buffers and exposes the
returned words. It has no database connection, journal selector or fallback.
"""
from __future__ import annotations

import ctypes
import struct

from .hia_json_preflight_native import NativeHiaJsonImage

MAGIC = int.from_bytes(b'HIASWL01', 'little')
CHECKSUM, HEADER, FRAME = 1, 2, 3
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_FORMAT = 0xfffffffc
REFUSE_CHECKSUM = 0xfffffffb
REFUSE_SALT = 0xfffffffa
REFUSE_VERSION = 0xfffffff9
_REFUSALS = {REFUSE_PROTOCOL, REFUSE_FORMAT, REFUSE_CHECKSUM, REFUSE_SALT, REFUSE_VERSION}
_CANARY = bytes(range(64))


class SQLiteWalProtocolError(RuntimeError):
    pass


class SQLiteWalRejected(ValueError):
    def __init__(self, status):
        super().__init__('HIA WAL byte kernel refused with status ' + hex(status))
        self.status = status


def _uint32(value, label):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError(label + ' requires an exact unsigned 32-bit integer')
    return value


def _order(value):
    if type(value) is not str or value not in ('little', 'big'):
        raise ValueError('WAL checksum byte order must be little or big')
    return int(value == 'big')


def _pair(value, label):
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(label + ' requires an exact pair of u32 values')
    return tuple(_uint32(x, label) for x in value)


class NativeSQLiteWal(NativeHiaJsonImage):
    """An isolated byte kernel; successful frame admission grants no I/O authority."""
    def _invoke(self, raw, fields, capacity):
        if type(raw) is not bytes or type(fields) is not tuple or len(fields) != 7:
            raise TypeError('WAL transport requires exact bytes and command fields')
        if any(type(value) is not int or not 0 <= value <= 0xffffffffffffffff for value in fields):
            raise ValueError('WAL command field outside u64 range')
        if type(capacity) is not int or capacity not in (8, 16, 32):
            raise ValueError('WAL transport output extent differs')
        if len(raw) > 65560:
            raise ValueError('WAL transport input exceeds one maximum-sized frame')
        command = struct.pack('<8Q', MAGIC, *fields)
        before_source = raw + _CANARY
        before_output = b'\xa5' * capacity + _CANARY
        before_control = command + _CANARY
        source = ctypes.create_string_buffer(before_source, len(before_source))
        output = ctypes.create_string_buffer(before_output, len(before_output))
        control = ctypes.create_string_buffer(before_control, len(before_control))
        status = self._entry(source, len(raw), output, capacity, control, len(command))
        observed = output.raw
        if source.raw != before_source or control.raw != before_control or observed[capacity:] != _CANARY:
            raise SQLiteWalProtocolError('WAL byte-kernel buffer custody differs')
        if type(status) is not int:
            raise SQLiteWalProtocolError('WAL byte-kernel status is not an exact integer')
        if status in _REFUSALS:
            if observed != before_output:
                raise SQLiteWalProtocolError('refused WAL byte kernel modified its output')
            raise SQLiteWalRejected(status)
        if status != capacity:
            raise SQLiteWalProtocolError('WAL byte kernel returned an invalid output length')
        return struct.unpack('<' + 'I' * (capacity // 4), observed[:capacity])

    def checksum(self, payload, *, byte_order, initial=(0, 0)):
        """Checksum one nonempty 8-byte-aligned block of at most 65536 bytes."""
        seed0, seed1 = _pair(initial, 'WAL checksum initial state')
        return self._invoke(payload, (CHECKSUM, _order(byte_order), seed0, seed1, 0, 0, 0), 8)

    def header(self, payload):
        """Return checksum0/1, page size, checkpoint, salts0/1, order and version."""
        return self._invoke(payload, (HEADER, 0, 0, 0, 0, 0, 0), 32)

    def frame(self, payload, *, byte_order, initial, page_size, salts):
        """Return checksum0/1, page number and commit-size field for one frame.

        The caller must bind initial state, page size and salts to the same WAL
        header and predecessor chain. A nonzero size field is a commit marker;
        this method does not scan the WAL or publish a committed database view.
        """
        seed0, seed1 = _pair(initial, 'WAL frame initial state')
        salt0, salt1 = _pair(salts, 'WAL frame salts')
        return self._invoke(payload, (FRAME, _order(byte_order), seed0, seed1,
                                     _uint32(page_size, 'WAL page size'), salt0, salt1), 16)
