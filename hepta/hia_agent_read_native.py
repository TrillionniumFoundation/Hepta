"""HIA-owned ordinary artifact pagination on the existing issued-byte store.

The original AgentStore.get still owns namespace, file custody and metadata
decoding. This adapter transports its returned bytes and one cursor row. The
selected HIA image owns every page/cursor decision and returns the exact row
values to persist on the original SQLite connection. No transaction is opened
or committed here, and no selected-image failure falls back to Python.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_read.hepta')
SCHEMA = 'hepta.hia.agent-read-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_READ_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAARDQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAARDR1', 'little')
MAX_U64 = (1 << 64) - 1
HEADER_BYTES = 128
FIELD_COUNT = 5


def _custody(message):
    from .hia_agent_store import AgentRejected
    raise AgentRejected('E_HIA_READ_NATIVE_CUSTODY', message, retry_action='stop')


def _text(value):
    if type(value) is not str:
        _custody('issued artifact reference is not text')
    return value.encode('utf-8')


def request_packet(reference, maximum, *, cursor_present=False, row=None):
    """Mechanical representation of already admitted public input and SQL row."""
    fields = tuple(_text(reference[key]) for key in ('id', 'sha256', 'uri'))
    flags, offset, row_fields = int(bool(cursor_present)), 0, (b'', b'')
    if row is not None:
        flags |= 2
        captured = []
        for bit, key in ((4, 'artifact_id'), (8, 'sha256')):
            if type(row[key]) is str:
                flags |= bit
                captured.append(row[key].encode('utf-8'))
            else:
                captured.append(b'')
        row_fields = tuple(captured)
        # SQLite INTEGER is signed 64-bit. Preserve its exact signed bit pattern;
        # the HIA owner implements Python's original slice and next-offset rules.
        if type(row['offset']) is int:
            offset = struct.unpack('<Q', struct.pack('<q', row['offset']))[0]
            flags |= 16
    fields += row_fields
    # The existing catalog accepts integral binary64 values as JSON integers.
    # Conversion here preserves the original int(max_bytes) representation.
    maximum = int(maximum)
    if not 0 <= maximum <= MAX_U64:
        _custody('page limit cannot be represented by the foreign protocol')
    words = (REQUEST_MAGIC, 1, flags, maximum, offset, FIELD_COUNT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return struct.pack('<16Q', *words) + struct.pack('<5Q', *(len(value) for value in fields)) + b''.join(fields)


def output_capacity(request):
    return len(request) * 7 + 102304


def _fields(raw, at, count, payload):
    if count > 5 or at > len(raw) or count * 8 > len(raw) - at:
        _custody('native artifact-read field table exceeds the record')
    lengths = struct.unpack_from('<' + str(count) + 'Q', raw, at)
    at += count * 8
    remaining = len(raw) - at
    if remaining != payload:
        _custody('native artifact-read payload extent differs')
    fields = []
    for extent in lengths:
        if extent > remaining:
            _custody('native artifact-read field exceeds remaining bytes')
        fields.append(raw[at:at + extent])
        at += extent
        remaining -= extent
    if remaining:
        _custody('native artifact-read record has unclaimed bytes')
    return tuple(fields)


def _signed(word):
    return struct.unpack('<q', struct.pack('<Q', word))[0]


@dataclass(frozen=True)
class AgentReadReceipt:
    status: int
    encoding: int
    offset: int
    consumed: int
    next_offset: int
    artifact_size: int
    wire_budget: int
    more: bool
    fields: tuple[bytes, ...]
    raw: bytes


class NativeAgentRead(NativeHiaJsonImage):
    """Immutable code, two immutable inputs and private per-operation workspace."""
    def transition(self, request: bytes, data: bytes) -> AgentReadReceipt:
        if type(request) is not bytes or type(data) is not bytes:
            _custody('artifact-read foreign inputs must be immutable bytes')
        capacity = output_capacity(request)
        source = ctypes.create_string_buffer(request, max(1, len(request)))
        artifact = ctypes.create_string_buffer(data, max(1, len(data)))
        output = ctypes.create_string_buffer(capacity)
        returned = self._entry(source, len(request), artifact, len(data), output, capacity)
        if not HEADER_BYTES <= returned <= capacity:
            _custody('native artifact-read image refused the byte protocol')
        raw = bytes(output.raw[:returned])
        h = struct.unpack_from('<16Q', raw)
        if h[:2] != (RESULT_MAGIC, 1) or any(h[12:]):
            _custody('native artifact-read result header is invalid')
        status, encoding, count, offset, consumed, following, size, budget, more, payload = h[2:12]
        if status:
            if status not in (1, 2) or any(h[3:]) or len(raw) != HEADER_BYTES:
                _custody('native artifact-read refusal shape is invalid')
            return AgentReadReceipt(status, 0, 0, 0, 0, 0, 0, False, (), raw)
        if encoding not in (1, 2) or count != FIELD_COUNT or more not in (0, 1):
            _custody('native artifact-read success shape is invalid')
        fields = _fields(raw, HEADER_BYTES, FIELD_COUNT, payload)
        if len(request) < 168:
            _custody('native artifact-read success lacks its request frame')
        req = struct.unpack_from('<16Q', request)
        if req[:2] != (REQUEST_MAGIC, 1) or req[5] != FIELD_COUNT:
            _custody('native artifact-read success admits an unknown request')
        source_fields = _fields(request, HEADER_BYTES, FIELD_COUNT, len(request) - 168)
        if (fields[:3] != source_fields[:3] or offset != req[4] or consumed > req[3]
                or following != (offset + consumed) & MAX_U64 or size != len(data)):
            _custody('native artifact-read response lost its captured input identity')
        if budget > 230000 or budget < 8:
            _custody('native artifact-read response contradicts its wire budget')
        if more:
            cursor = fields[3]
            if len(cursor) != 69 or not cursor.startswith(b'page-') or any(
                    value not in b'0123456789abcdef' for value in cursor[5:]):
                _custody('native artifact-read cursor shape is invalid')
        elif fields[3]:
            _custody('native artifact-read terminal page publishes a cursor')
        return AgentReadReceipt(0, encoding, _signed(offset), consumed, _signed(following),
                                size, budget, bool(more), fields, raw)


def installed_agent_read(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentRead)


def selected_agent_read():
    selected = os.environ.get(SELECTOR)
    if selected is None:
        return None
    if not selected:
        _custody('explicit artifact-read manifest selection is empty')
    try:
        return installed_agent_read(selected)
    except (ValueError, OSError, TypeError, OverflowError) as exc:
        _custody('selected artifact-read executable was not admitted: ' + str(exc))


class NativeAgentReadStore:
    """One existing store/connection; caller retains its original request scope."""
    def __init__(self, store, image):
        self.store, self.db, self.image = store, store.db, image

    def _same_connection(self):
        if self.store.db is not self.db:
            _custody('artifact-read store connection changed')

    def read(self, args):
        from .hia_agent_store import reject
        self._same_connection()
        # The ordinary call envelopes already snapshot arguments. Also capture
        # this boundary before Store.get can yield while reading a large file:
        # retain every supplied field so the old shape/identity refusals remain.
        captured = dict(args) if type(args) is dict else args
        supplied_reference = captured['artifact']
        reference = dict(supplied_reference) if type(supplied_reference) is dict else supplied_reference
        # Preserve the actual old order, including metadata decoding in get():
        # retained identity/file bytes first, then cursor lookup/admission.
        data, _metadata = self.store.get(reference)
        row = None
        cursor_present = 'cursor' in captured
        if cursor_present:
            row = self.db.execute('SELECT * FROM cursors WHERE id=?', (captured['cursor'],)).fetchone()
        packet = request_packet(reference, captured.get('max_bytes', 65536),
                                cursor_present=cursor_present, row=row)
        receipt = self.image.transition(packet, data)
        if receipt.status == 1:
            reject('E_HIA_CURSOR', 'cursor is not bound to this exact artifact')
        if receipt.status:
            _custody('native artifact-read image rejected the captured request protocol')
        identity = {name: value.decode('utf-8') for name, value in zip(
            ('id', 'sha256', 'uri'), receipt.fields[:3])}
        content = receipt.fields[4].decode('utf-8')
        cursor = receipt.fields[3].decode('ascii') if receipt.more else None
        self._same_connection()
        if receipt.more:
            self.db.execute('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)',
                            (cursor, identity['id'], identity['sha256'], receipt.next_offset))
        return {'artifact': identity, 'encoding': 'utf8' if receipt.encoding == 1 else 'base64',
                'content': content, 'next_cursor': cursor}
