"""Custody-only transport for an explicitly supplied HIA B-tree cell image."""
from __future__ import annotations

import ctypes
import struct

from .hia_json_preflight_native import NativeHiaJsonImage

MAGIC = int.from_bytes(b'HIABTC01', 'little')
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_TRUNCATED = 0xfffffffe
REFUSE_CAPACITY = 0xfffffffc
REFUSE_FORMAT = 0xfffffffb
REFUSE_LIMIT = 0xfffffffa
REFUSE_INDEX = 0xfffffff9
OUTPUT_BYTES = 128
_FIELDS = ('page_number', 'page_type', 'usable_size', 'cell_count', 'cell_index',
           'cell_offset', 'cell_size', 'payload_offset', 'payload_size',
           'local_payload_size', 'left_child', 'key_bits', 'overflow_page',
           'overflow_pointer_offset', 'overflow_page_count', 'last_overflow_payload_size')
_CANARY = bytes(range(64))


class SQLiteBtreeCellProtocolError(RuntimeError):
    pass


class SQLiteBtreeCellRejected(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__('SQLite B-tree selected cell refused status ' + hex(status))


class NativeSQLiteBtreeCell(NativeHiaJsonImage):
    def layout(self, page, *, page_number, database_pages, cell_index, reserved_bytes=0):
        if type(page) is not bytes:
            raise TypeError('B-tree page requires exact bytes')
        if len(page) not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise ValueError('B-tree page size is outside the declared page contract')
        for name, value, low, high in (
                ('page_number', page_number, 1, 4294967294),
                ('database_pages', database_pages, page_number, 4294967294),
                ('cell_index', cell_index, 0, 65535),
                ('reserved_bytes', reserved_bytes, 0, min(255, len(page) - 480))):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(name + ' requires an exact bounded integer')
        command = struct.pack('<8Q', MAGIC, 1, len(page), reserved_bytes,
                              page_number, cell_index, database_pages, 0)
        sbytes, obytes, wbytes = page + _CANARY, b'\xa5' * OUTPUT_BYTES + _CANARY, command + _CANARY
        s = ctypes.create_string_buffer(sbytes, len(sbytes))
        o = ctypes.create_string_buffer(obytes, len(obytes))
        w = ctypes.create_string_buffer(wbytes, len(wbytes))
        status = self._entry(s, len(page), o, OUTPUT_BYTES, w, len(command))
        if s.raw != sbytes or w.raw != wbytes or o.raw[OUTPUT_BYTES:] != _CANARY:
            raise SQLiteBtreeCellProtocolError('selected-cell source/control/canary changed')
        if type(status) is not int:
            raise SQLiteBtreeCellProtocolError('selected-cell status is not an exact integer')
        if status in (REFUSE_PROTOCOL, REFUSE_TRUNCATED, REFUSE_CAPACITY,
                      REFUSE_FORMAT, REFUSE_LIMIT, REFUSE_INDEX):
            if o.raw != obytes:
                raise SQLiteBtreeCellProtocolError('refused cell changed output')
            if status == REFUSE_PROTOCOL:
                raise SQLiteBtreeCellProtocolError('selected-cell protocol refused')
            raise SQLiteBtreeCellRejected(status)
        if status != OUTPUT_BYTES:
            raise SQLiteBtreeCellProtocolError('selected-cell extent differs')
        result = dict(zip(_FIELDS, struct.unpack('<16Q', o.raw[:OUTPUT_BYTES])))
        if (result['page_number'] != page_number or result['cell_index'] != cell_index
                or result['usable_size'] != len(page) - reserved_bytes
                or result['page_type'] not in (2, 5, 10, 13)
                or not cell_index < result['cell_count'] <= 65535
                or result['cell_offset'] > result['usable_size']
                or result['cell_size'] > result['usable_size'] - result['cell_offset']):
            raise SQLiteBtreeCellProtocolError('selected-cell result envelope differs')
        if result['page_type'] != 5:
            if (result['payload_offset'] < result['cell_offset']
                    or result['payload_offset'] > result['usable_size']
                    or result['local_payload_size'] > result['usable_size'] - result['payload_offset']
                    or result['local_payload_size'] > result['payload_size']):
                raise SQLiteBtreeCellProtocolError('selected-cell result span differs')
        return result
