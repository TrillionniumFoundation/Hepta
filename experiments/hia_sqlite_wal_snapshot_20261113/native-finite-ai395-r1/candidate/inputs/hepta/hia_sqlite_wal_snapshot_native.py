"""Bounded transport for the explicitly qualified HIA WAL snapshot image.

All WAL admission, commit visibility and latest-frame selection run in HIA.
Each provide() supplies exactly the requested header or frame, never a whole
database. The objects below do not acquire locks, perform I/O, sync a file or
grant database-transaction authority. A pager must keep one database/WAL
generation stable from scanning through every lookup and page read.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import struct

from .hia_json_preflight_native import NativeHiaJsonImage

COMMAND_MAGIC = int.from_bytes(b"HIASWS01", "little")
STATE_MAGIC = int.from_bytes(b"HIASWT01", "little")
REPLY_MAGIC = int.from_bytes(b"HIASWR01", "little")
START, HEADER, FRAME, LOOKUP, FINISH = 1, 2, 3, 4, 5
REFUSE_PROTOCOL, REFUSE_VERSION, REFUSE_SNAPSHOT = 0xfffffffd, 0xfffffff9, 0xfffffff8
REFUSALS = frozenset((REFUSE_PROTOCOL, REFUSE_VERSION, REFUSE_SNAPSHOT))
STATE_BYTES, OUTPUT_BYTES, MAX_INPUT_BYTES = 256, 128, 65576
_CANARY = bytes(range(64))
_ISSUE = object()


class SQLiteWalSnapshotProtocolError(RuntimeError):
    pass


class SQLiteWalSnapshotRejected(ValueError):
    def __init__(self, status):
        super().__init__("HIA WAL snapshot refused with status " + hex(status))
        self.status = status


@dataclass(frozen=True, slots=True)
class WalReadRequest:
    kind: str
    offset: int
    size: int
    frame_number: int


@dataclass(frozen=True, slots=True)
class WalPageLocation:
    source: str
    offset: int
    size: int
    frame_number: int
    page_number: int
    database_pages: int
    committed_frame: int
    committed_end_offset: int
    checksum_before: tuple
    checksum_after: tuple


@dataclass(frozen=True, slots=True, init=False)
class WalSnapshot:
    """Immutable byte-prefix metadata, not proof that an external lock is held."""
    page_size: int
    database_pages: int
    committed_frame: int
    committed_end_offset: int
    valid_frames_scanned: int
    stop_reason: int
    wal_extent: int
    _image: object
    _entry: object
    _state: bytes

    def __init__(self, key, image, entry, state, row):
        if key is not _ISSUE:
            raise TypeError("WAL snapshots are issued only by a finished scan")
        values = {
            "page_size": row[5], "database_pages": row[6],
            "committed_frame": row[7], "committed_end_offset": row[8],
            "valid_frames_scanned": row[4], "stop_reason": row[9],
            "wal_extent": struct.unpack_from("<Q", state, 24)[0],
            "_image": image, "_entry": entry, "_state": state,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)


def _uint(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(label + " requires an exact integer in its ABI domain")
    return value


class _Session:
    __slots__ = ("_image", "_entry_identity", "_state", "_reply", "_lookup",
                 "_busy", "_closed", "_ticket")

    def __init__(self, image, *, state, lookup, fields, expected_entry=None):
        self._image = image
        self._state = state
        self._reply = None
        self._lookup = lookup
        self._busy = False
        self._closed = False
        self._ticket = None
        # Attribute acquisition is inside the guarded call: descriptor callbacks
        # cannot close a session and then have a normal native return reopen it.
        self._entry_identity = expected_entry
        self._call(LOOKUP if lookup else START, fields=fields)

    def _seal(self):
        self._closed = True
        self._busy = False
        self._ticket = None

    def _checkpoint(self, ticket):
        if self._closed or self._ticket is not ticket or not self._busy:
            self._seal()
            raise SQLiteWalSnapshotProtocolError("WAL snapshot session was permanently closed")

    def _call(self, operation, *, fields=(), payload=b""):
        if self._closed or self._busy:
            self._seal()
            raise SQLiteWalSnapshotProtocolError("WAL snapshot permission is unavailable")
        self._busy = True
        ticket = object()
        self._ticket = ticket
        try:
            if type(payload) is not bytes or type(fields) is not tuple:
                raise TypeError("WAL snapshot transport requires exact bytes and fields")
            packet = struct.pack("<" + "Q" * (2 + len(fields)), COMMAND_MAGIC, operation, *fields) + payload
            self._checkpoint(ticket)
            if len(packet) > MAX_INPUT_BYTES or type(self._state) is not bytes or len(self._state) != STATE_BYTES:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot transport extent differs")
            entry = self._image._entry
            self._checkpoint(ticket)
            if self._entry_identity is None:
                self._entry_identity = entry
            elif entry is not self._entry_identity:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot executable entry changed")
            before_source = packet + _CANARY
            before_output = b"\xa5" * OUTPUT_BYTES + _CANARY
            before_state = self._state + _CANARY
            source = ctypes.create_string_buffer(before_source, len(before_source))
            output = ctypes.create_string_buffer(before_output, len(before_output))
            state = ctypes.create_string_buffer(before_state, len(before_state))
            self._checkpoint(ticket)
            status = entry(source, len(packet), output, OUTPUT_BYTES, state, STATE_BYTES)
            self._checkpoint(ticket)
            source_after, output_after, state_after = source.raw, output.raw, state.raw
            self._checkpoint(ticket)
            if source_after != before_source or output_after[OUTPUT_BYTES:] != _CANARY or state_after[STATE_BYTES:] != _CANARY:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot buffer custody differs")
            if type(status) is not int:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot returned a non-integer status")
            if status in REFUSALS:
                if output_after != before_output or state_after != before_state:
                    raise SQLiteWalSnapshotProtocolError("refused WAL operation modified its spans")
                raise SQLiteWalSnapshotRejected(status)
            if status != OUTPUT_BYTES:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot output size differs")
            row = struct.unpack("<16Q", output_after[:OUTPUT_BYTES])
            header = struct.unpack_from("<3Q", state_after)
            self._checkpoint(ticket)
            expected = {
                START: (1, 3), HEADER: (2, 4) if self._lookup else (2, 3),
                FRAME: (2, 4) if self._lookup else (2, 3),
                LOOKUP: (1, 4), FINISH: (6,) if self._lookup else (5,),
            }[operation]
            if row[0] != REPLY_MAGIC or row[1] not in expected or header[0] != STATE_MAGIC:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot response protocol differs")
            if header[2] != (2 if self._lookup else 1):
                raise SQLiteWalSnapshotProtocolError("WAL snapshot mode differs")
            phases = {1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 5}
            if header[1] != phases[row[1]]:
                raise SQLiteWalSnapshotProtocolError("WAL snapshot phase differs")
            if row[1] == 1 and (row[2], row[3], row[4]) != (0, 32, 0):
                raise SQLiteWalSnapshotProtocolError("WAL header read request differs")
            if row[1] == 2 and not (32 <= row[2] <= (1 << 63) - 1 and 536 <= row[3] <= 65560 and row[4] > 0):
                raise SQLiteWalSnapshotProtocolError("WAL frame read request differs")
            if row[1] == 6 and row[11] not in (0, 1, 2):
                raise SQLiteWalSnapshotProtocolError("WAL page-location tag differs")
            self._state, self._reply = state_after[:STATE_BYTES], row
            return row
        except BaseException:
            self._seal()
            raise
        finally:
            if self._ticket is ticket:
                self._busy = False
                self._ticket = None

    @property
    def request(self):
        if self._closed:
            raise SQLiteWalSnapshotProtocolError("WAL snapshot session is closed")
        row = self._reply
        if row[1] == 1:
            return WalReadRequest("header", row[2], row[3], row[4])
        if row[1] == 2:
            return WalReadRequest("frame", row[2], row[3], row[4])
        return None

    def provide(self, payload):
        try:
            if self._closed or self._busy:
                self._seal()
                raise SQLiteWalSnapshotProtocolError("WAL snapshot permission is unavailable")
            row = self._reply
            if row[1] not in (1, 2):
                raise SQLiteWalSnapshotProtocolError("WAL snapshot requests no more input")
            if type(payload) is not bytes or len(payload) != row[3]:
                raise ValueError("WAL input must contain exactly the requested bytes; short I/O is not EOF")
            self._call(HEADER if row[1] == 1 else FRAME, payload=payload)
            return self.request
        except BaseException:
            self._seal()
            raise

    def finish(self):
        try:
            row = self._call(FINISH)
            if self._lookup:
                return WalPageLocation(
                    ("missing", "database", "wal")[row[11]], row[2], row[3], row[4], row[10],
                    row[6], row[7], row[8], (row[12], row[13]), (row[14], row[15]))
            return WalSnapshot(_ISSUE, self._image, self._entry_identity, self._state, row)
        finally:
            self._seal()


class NativeSQLiteWalSnapshot(NativeHiaJsonImage):
    """Explicitly qualified image with no selector or database-I/O fallback."""
    def scanner(self, *, wal_bytes, base_page_size, base_page_count):
        fields = (_uint(wal_bytes, (1 << 63) - 1, "WAL extent"),
                  _uint(base_page_count, 0xffffffff, "base database page count"),
                  _uint(base_page_size, 65536, "base database page size"))
        if base_page_size < 512 or base_page_size & (base_page_size - 1):
            raise ValueError("base database page size must be a power of two from 512 through 65536")
        return _Session(self, state=bytes(STATE_BYTES), lookup=False, fields=fields)

    def locator(self, snapshot, page_number):
        _uint(page_number, 0xffffffff, "database page number")
        if page_number == 0:
            raise ValueError("database page numbers start at one")
        if type(snapshot) is not WalSnapshot or snapshot._image is not self:
            raise TypeError("WAL snapshot belongs to a different image")
        return _Session(self, state=snapshot._state, lookup=True, fields=(page_number,),
                        expected_entry=snapshot._entry)
