"""Custody-only transport for the HIA database-header decision core.

A decision is byte metadata. It neither acquires a read lock nor grants page or
transaction authority. The pager must keep one generation stable, supply its
logical page count, perform any requested WAL/open or page-size operation, and
read page one again before asking for an ACCEPT decision.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import struct

from .hia_json_preflight_native import NativeHiaJsonImage

COMMAND_MAGIC = int.from_bytes(b"HIADBH01", "little")
REPLY_MAGIC = int.from_bytes(b"HIADBR01", "little")
REFUSE_PROTOCOL = 0xfffffffd
OUTPUT_BYTES = 256
_CANARY = bytes(range(64))
_ACTIONS = {1: "accept", 2: "open_wal_and_reread", 3: "resize_and_reread", 4: "format_error"}
_SYNCS = {0: "unchanged", 1: "rollback_default", 2: "wal_default"}


class SQLiteDatabaseHeaderProtocolError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DatabaseHeaderDecision:
    action: str
    sqlite_rc: int
    read_only: bool
    page_size: int
    usable_size: int
    database_pages: int
    auto_vacuum: bool
    incremental_vacuum: bool
    sync_mode: str
    page_size_fixed: bool
    max_local: int
    min_local: int
    max_leaf: int
    min_leaf: int
    max_one_byte_payload: int


class NativeSQLiteDatabaseHeader(NativeHiaJsonImage):
    def inspect_header(self, header, *, page_size, usable_size, file_pages,
                       reset_database=False, writable_schema=False, no_wal=False,
                       read_only=False, auto_vacuum=False, incremental_vacuum=False,
                       wal_ready=False):
        if type(header) is not bytes or len(header) != 100:
            raise ValueError("database header requires exactly 100 immutable bytes")
        for name, value, low, high in (
                ("page_size", page_size, 512, 65536),
                ("usable_size", usable_size, 257, 65536),
                ("file_pages", file_pages, 0, 4294967295)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(name + " requires an exact bounded integer")
        if page_size & (page_size - 1) or not page_size - 255 <= usable_size <= page_size:
            raise ValueError("current pager geometry is outside the ABI domain")
        options = (reset_database, writable_schema, no_wal, read_only,
                   auto_vacuum, incremental_vacuum)
        if any(type(value) is not bool for value in options + (wal_ready,)):
            raise TypeError("database header options require exact booleans")
        flags = sum(int(value) << bit for bit, value in enumerate(options))
        command = struct.pack("<16Q", COMMAND_MAGIC, 1, page_size, usable_size,
                              file_pages, flags, int(wal_ready), *([0] * 9))
        before_s = header + _CANARY
        before_c = command + _CANARY
        before_o = b"\xa5" * OUTPUT_BYTES + _CANARY
        s = ctypes.create_string_buffer(before_s, len(before_s))
        c = ctypes.create_string_buffer(before_c, len(before_c))
        o = ctypes.create_string_buffer(before_o, len(before_o))
        entry = self._entry
        status = entry(s, 100, o, OUTPUT_BYTES, c, 128)
        if (self._entry is not entry or s.raw != before_s or c.raw != before_c
                or o.raw[OUTPUT_BYTES:] != _CANARY):
            raise SQLiteDatabaseHeaderProtocolError("header input, command, entry or canary changed")
        if type(status) is not int:
            raise SQLiteDatabaseHeaderProtocolError("header status is not an exact integer")
        if status == REFUSE_PROTOCOL:
            if o.raw != before_o:
                raise SQLiteDatabaseHeaderProtocolError("protocol refusal changed output")
            raise SQLiteDatabaseHeaderProtocolError("header ABI refused")
        if status != OUTPUT_BYTES:
            raise SQLiteDatabaseHeaderProtocolError("header output extent differs")
        words = struct.unpack("<32Q", o.raw[:OUTPUT_BYTES])
        if (words[0] != REPLY_MAGIC or words[1] not in _ACTIONS
                or words[9] not in _SYNCS or any(words[16:])
                or any(words[index] not in (0, 1) for index in (3, 7, 8, 10))
                or words[4] not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
                or not words[4] - 255 <= words[5] <= words[4]):
            raise SQLiteDatabaseHeaderProtocolError("header result envelope differs")
        if words[1] == 4:
            if words[2] not in (11, 26):
                raise SQLiteDatabaseHeaderProtocolError("unknown header format error")
        elif words[2] != 0:
            raise SQLiteDatabaseHeaderProtocolError("non-error decision has an SQLite error")
        if words[1] == 1:
            if (words[6] != 0 and words[5] < 480) or words[6] > file_pages or words[15] > 127:
                raise SQLiteDatabaseHeaderProtocolError("accepted header envelope differs")
        elif words[6] != 0 or any(words[11:16]):
            raise SQLiteDatabaseHeaderProtocolError("pending or failed header exposed final payload limits")
        if words[1] == 2 and (no_wal or wal_ready):
            raise SQLiteDatabaseHeaderProtocolError("unexpected WAL retry")
        if words[1] == 3 and (words[4] == page_size or words[10] != 1):
            raise SQLiteDatabaseHeaderProtocolError("unexpected page-size retry")
        return DatabaseHeaderDecision(
            _ACTIONS[words[1]], words[2], bool(words[3]), words[4], words[5], words[6],
            bool(words[7]), bool(words[8]), _SYNCS[words[9]], bool(words[10]),
            words[11], words[12], words[13], words[14], words[15])
