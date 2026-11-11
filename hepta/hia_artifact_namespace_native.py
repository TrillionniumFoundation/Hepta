"""Retained HIA namespace policy; fixed SQLite and native-byte effect transport.

The original database remains authoritative. Selected operations cannot borrow
another connection, repeat a consumed effect, or reconstruct native state from
hosted success flags. JSON values and SQLite objects remain foreign bridges.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import stat
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/artifact_namespace.hiaasm')
SCHEMA = 'hepta.hia.artifact-namespace-native.v1'
SELECTOR = 'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST'
BYTE_SELECTOR = 'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIANSQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIANSR01', 'little')
GUARD_MAGIC = int.from_bytes(b'HIANSG01', 'little')
PREFIX = 2048
MAX_JSON = 8 * 1024 * 1024
MAX_STATE = PREFIX + 4 * MAX_JSON


class ArtifactNamespaceUnknown(RuntimeError):
    """Nonterminal custody failure, outside the request rejection formatter."""


class NativeArtifactNamespaceImage(NativeHiaJsonImage):
    pass


def admitted_artifact_namespace():
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    image = _installed_json_image(selected, SOURCE, SCHEMA, NativeArtifactNamespaceImage)
    if not os.environ.get(BYTE_SELECTOR):
        raise ArtifactNamespaceUnknown('native namespace requires its explicitly selected native byte owner')
    from .hia_agent_store import _native_artifact_admission
    _native_artifact_admission()
    return image


def artifact_namespace_store(store, admission):
    return None if admission is None else NativeArtifactNamespaceStore(store, admission)


def _reject(status):
    from .hia_agent_store import AgentRejected
    errors = {
        1: ('E_HIA_ARTIFACT_LIMIT', 'artifact or namespace input exceeds its bounded profile'),
        2: ('E_HIA_FIELDS', 'artifact namespace input has invalid fields or types'),
        3: ('E_HIA_ARTIFACT_IDENTITY', 'artifact reference was not issued in this runtime namespace'),
        4: ('E_HIA_ARTIFACT_AUTHORITY', 'input bytes cannot impersonate the retained artifact kind'),
        5: ('E_HIA_PROFILE_STALE', 'profile is unavailable or differs from the installed implementation'),
        6: ('E_HIA_PROFILE_AUTHORITY', 'profile does not resolve to its exact retained artifact'),
        7: ('E_HIA_ARTIFACT_CORRUPT', 'artifact row or bytes differ from their immutable binding'),
        12: ('E_HIA_ARTIFACT_FILE', 'native artifact read or hash was refused'),
        13: ('E_HIA_ARTIFACT_NATIVE_CUSTODY', 'native byte owner could not be admitted before any effect'),
    }
    if status in errors:
        code, message = errors[status]
        raise AgentRejected(code, message)
    raise ArtifactNamespaceUnknown({8: 'native namespace custody failed',
        9: 'namespace effect has no confirmed matching outcome',
        10: 'native namespace sequence or state capacity is exhausted',
        11: 'native namespace has a pending operation or scope'}.get(status,
        'invalid native namespace status'))


@dataclass(frozen=True)
class NamespaceBinding:
    operation: tuple[int, int]
    connection: tuple[int, int]
    scope_kind: int = 0
    scope_epoch: int = 0
    scope_nonce: tuple[int, int] = (0, 0)
    callback_token: int = 0
    operation_kind: int = 0


@dataclass(frozen=True)
class NamespaceReceipt:
    status: int
    words: tuple[int, ...]
    raw: bytes

    @property
    def sequence(self):
        return self.words[2]

    @property
    def phase(self):
        return self.words[3]

    @property
    def action(self):
        return self.words[5]

    @property
    def pending(self):
        return self.words[6]

    def field(self, offset, size):
        if type(offset) is not int or type(size) is not int or not 0 <= offset <= offset + size <= len(self.raw):
            raise ArtifactNamespaceUnknown('native namespace byte extent is invalid')
        return self.raw[offset:offset + size]

    def reference(self):
        return {'id': self.field(640, 34).decode('ascii'),
                'sha256': self.field(512, 64).decode('ascii'),
                'uri': self.field(704, 48).decode('ascii')}


class NamespaceState:
    """One mutable HIA owner, retained across every namespace operation."""
    def __init__(self, image, connection):
        self.image, self.connection = image, connection
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator = os.getpid()
        self.lock = threading.RLock()
        self.buffer = ctypes.create_string_buffer(8192)
        self.receipt = None
        self.fenced = None
        self.call(0, NamespaceBinding((0, 0), connection))

    def check(self):
        if os.getpid() != self.creator:
            raise ArtifactNamespaceUnknown('namespace state belongs to its creator process')
        if self.fenced is not None:
            raise ArtifactNamespaceUnknown('namespace state is fenced; observe the original journal and rows')

    def fence(self, error):
        if self.fenced is None:
            try:
                message = str(error)[:1024]
            except BaseException:
                message = '<unavailable>'
            self.fenced = {'type': type(error).__name__, 'message': message}

    def reserve(self, size):
        self.check()
        if type(size) is not int or not PREFIX <= size <= MAX_STATE:
            raise ArtifactNamespaceUnknown('native namespace transport capacity is outside its profile')
        if size > len(self.buffer):
            target = min(MAX_STATE, max(size, 2 * len(self.buffer)))
            grown = ctypes.create_string_buffer(target)
            ctypes.memmove(grown, self.buffer, len(self.buffer))
            self.buffer = grown

    def _packet(self, event, binding, values, payload, effect_token, sequence):
        words = [REQUEST_MAGIC, event, sequence, effect_token, *self.identity,
                 *binding.operation, *binding.connection, binding.scope_kind, binding.scope_epoch,
                 *binding.scope_nonce, binding.callback_token, binding.operation_kind, *values]
        if (len(words) > 32 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in words)
                or type(payload) is not bytes):
            raise ArtifactNamespaceUnknown('invalid namespace transport packet')
        return struct.pack('<32Q', *(words + [0] * (32 - len(words)))) + payload

    def call(self, event, binding, *, values=(), payload=b'', effect_token=0):
        self.check()
        with self.lock:
            self.check()
            try:
                sequence = 0 if self.receipt is None or event == 90 else self.receipt.sequence
                raw = self._packet(event, binding, values, payload, effect_token, sequence)
                source = ctypes.create_string_buffer(raw, len(raw))
                output = ctypes.create_string_buffer(len(self.buffer) + 32)
                count = self.image._entry(source, len(raw), output, len(output), self.buffer, len(self.buffer))
                self.check()
                if not 32 <= count <= len(output):
                    raise ArtifactNamespaceUnknown('native namespace rejected its bounded ABI')
                returned = ctypes.string_at(output, count)
                magic, status, serial, extent = struct.unpack('<4Q', returned[:32])
                if (magic != RESULT_MAGIC or status > 13 or extent < PREFIX or extent > len(self.buffer)
                        or count != extent + 32):
                    raise ArtifactNamespaceUnknown('native namespace receipt is invalid')
                owned = ctypes.string_at(self.buffer, extent)
                if returned[32:] != owned:
                    raise ArtifactNamespaceUnknown('namespace receipt differs from retained state')
                words = struct.unpack('<64Q', owned[:512])
                if (serial != words[2] or extent != words[54] or tuple(words[50:52]) != self.connection
                        or tuple(words[52:54]) != self.identity):
                    raise ArtifactNamespaceUnknown('namespace receipt owner differs')
                receipt = NamespaceReceipt(status, words, owned)
                self.receipt = receipt
                return receipt
            except BaseException as error:
                self.fence(error)
                raise

    def cleanup_claim(self, binding, in_transaction, *, acknowledge=False):
        """Independent native epoch guard remains usable after receipt loss."""
        if os.getpid() != self.creator or type(in_transaction) is not bool:
            raise ArtifactNamespaceUnknown('namespace scope cleanup has no transport custody')
        with self.lock:
            raw = self._packet(25 if acknowledge else 24, binding, (int(in_transaction),), b'', 0, 0)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(32)
            count = self.image._entry(source, len(raw), output, 32, self.buffer, len(self.buffer))
            if count != 32:
                raise ArtifactNamespaceUnknown('namespace scope cleanup has no receipt')
            magic, status, granted, epoch = struct.unpack('<4Q', output.raw)
            if (magic != GUARD_MAGIC or status or granted > 1 or epoch != binding.scope_epoch):
                raise ArtifactNamespaceUnknown('namespace scope cleanup identity differs')
            return bool(granted)

    def snapshot(self):
        receipt = self.receipt
        result = {'sequence': receipt.sequence, 'operation_phase': receipt.phase,
            'operation_kind': receipt.words[4], 'pending_action': receipt.action,
            'pending_effect_token': receipt.pending, 'status': receipt.words[7],
            'scope_kind': receipt.words[12], 'scope_epoch': receipt.words[15],
            'legacy_scope_phase': receipt.words[40], 'legacy_scope_epoch': receipt.words[41],
            'legacy_pending_action': receipt.words[44], 'legacy_pending_token': receipt.words[45],
            'last_consumed_rollback_epoch': receipt.words[47],
            'observation_grants_execution': False}
        if self.fenced is not None:
            result['native_policy_error'] = copy.deepcopy(self.fenced)
            result['native_fields_are_last_attested'] = True
        return result


@dataclass(frozen=True)
class _OperationInputs:
    binding: NamespaceBinding
    connection: object
    data: bytes


class _Operation:
    def __init__(self, inputs):
        self.inputs = inputs
        self.admission = None
        self.returned_bytes = None
        self.returned_row = None
        self.finished = False


@dataclass(frozen=True)
class _Scope:
    nonce: tuple[int, int]
    thread: int


class NativeArtifactNamespaceStore:
    """Fixed effects from one HIA owner against the original main database."""
    def __init__(self, store, image):
        self.store, self.official = store, store.db
        self.creator = os.getpid()
        self.connection_identity = struct.unpack('<2Q', os.urandom(16))
        self.path, self.identity = Path(store.database), store.database_identity
        self.sidecars = dict(store.database_sidecars)
        self.artifact_identity = self._identity(store.artifacts, directory=True)
        self.lock = store.lock
        self.closed = False
        self._scope = None
        self._operation = None
        self.state = NamespaceState(image, self.connection_identity)
        self.check()
        main = [row for row in self.official.execute('PRAGMA database_list') if row['name'] == 'main']
        if len(main) != 1 or main[0]['file'] != str(self.path):
            raise ArtifactNamespaceUnknown('namespace connection differs from the original main database')

    @staticmethod
    def _identity(path, *, directory=False):
        try:
            info = path.lstat()
        except OSError as error:
            raise ArtifactNamespaceUnknown('namespace path identity is unavailable') from error
        ordinary = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not ordinary or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ArtifactNamespaceUnknown('namespace path is not an owned private ordinary object')
        return info.st_dev, info.st_ino

    def check(self):
        if self.closed or os.getpid() != self.creator or self.store.db is not self.official:
            raise ArtifactNamespaceUnknown('namespace connection custody changed')
        self.state.check()
        if self._identity(self.path) != self.identity:
            raise ArtifactNamespaceUnknown('namespace main database identity changed')
        if self._identity(self.store.artifacts, directory=True) != self.artifact_identity:
            raise ArtifactNamespaceUnknown('namespace artifact directory identity changed')
        for suffix, identity in self.sidecars.items():
            if self._identity(Path(str(self.path) + suffix)) != identity:
                raise ArtifactNamespaceUnknown('namespace WAL identity changed')

    def _binding(self, operation, connection, nonce):
        if connection is not None:
            from .hia_request_journal_native import _EffectConnection
            if type(connection) is not _EffectConnection or connection.store.store is not self.store:
                raise ArtifactNamespaceUnknown('namespace requires the original explicit request capability')
            with connection.state.lock:
                connection.check()
                epoch = struct.unpack_from('<Q', connection.state.buffer, 25 * 8)[0]
                return NamespaceBinding(nonce, connection.state.connection,
                    3 if connection.readonly else 2, epoch,
                    connection.state.identity, connection.token, operation)
        if self._scope is None:
            if self.official.in_transaction:
                raise ArtifactNamespaceUnknown('namespace cannot borrow an unowned official transaction')
            return NamespaceBinding(nonce, self.connection_identity, operation_kind=operation)
        if threading.get_ident() != self._scope.thread or not self.official.in_transaction:
            raise ArtifactNamespaceUnknown('namespace legacy transaction has no current thread custody')
        receipt = self.state.call(90, NamespaceBinding((0, 0), self.connection_identity))
        if receipt.words[40] != 3 or tuple(receipt.words[42:44]) != self._scope.nonce:
            raise ArtifactNamespaceUnknown('native namespace transaction scope changed')
        return NamespaceBinding(nonce, self.connection_identity, 1, receipt.words[41],
                                self._scope.nonce, 0, operation)

    def _check_operation(self, operation):
        self.check()
        if self._operation is not operation:
            raise ArtifactNamespaceUnknown('namespace operation custody changed')
        inputs = operation.inputs
        observed = self._binding(inputs.binding.operation_kind, inputs.connection, inputs.binding.operation)
        if observed != inputs.binding:
            raise ArtifactNamespaceUnknown('namespace connection or request scope was revoked')

    @staticmethod
    def _text(value, maximum=MAX_JSON):
        from .hia_agent_store import reject
        if type(value) is not str:
            return b'', False
        try:
            raw = value.encode('utf-8')
        except UnicodeError:
            reject('E_HIA_FIELDS', 'namespace text must contain Unicode scalar values')
        if len(raw) > maximum:
            reject('E_HIA_ARTIFACT_LIMIT', 'namespace text exceeds its bounded profile')
        return raw, True

    @classmethod
    def _reference_fields(cls, value, names):
        shaped = type(value) is dict and set(value) == set(names)
        fields, flags = [], 0
        for index, name in enumerate(names):
            candidate = value.get(name) if type(value) is dict else None
            raw, typed = cls._text(candidate)
            # Oversized fixed reference fields are malformed identities, not
            # truncated lookup keys. An empty field makes HIA refuse them.
            maximum = 64 if name != 'id' or len(names) == 3 else MAX_JSON
            fields.append(raw if len(raw) <= maximum else b'')
            flags |= int(typed) << index
        return tuple(fields), int(shaped), flags

    def _operate(self, operation_kind, *, data=None, kind=None, metadata=None,
                 identifier=None, reference=None, expected=None, uri=None, connection=None):
        from .hia_agent_store import AgentRejected, wire, decode_data, _native_artifact_admission
        with self.lock:
            self.check()
            observed = self.state.call(90, NamespaceBinding((0, 0), self.connection_identity))
            if observed.phase in (1, 2, 5) or observed.words[40] == 8:
                raise ArtifactNamespaceUnknown('namespace operation or scope remains pending')
            nonce = struct.unpack('<2Q', os.urandom(16))
            binding = self._binding(operation_kind, connection, nonce)
            data_tag = int(type(data) is bytes) if operation_kind in (1, 4) else 0
            data_size = len(data) if data_tag else 0
            oversized_or_untyped = operation_kind in (1, 4) and (not data_tag or data_size > 64 << 20)
            if oversized_or_untyped:
                # Preserve the original payload-admission ordering and do
                # not retain an arbitrarily large rejected caller object.
                raw_kind, kind_typed = b'', type(kind) is str
                raw_identifier, identifier_typed = b'', type(identifier) is str
            else:
                raw_kind, kind_typed = self._text(kind)
                raw_identifier, identifier_typed = self._text(identifier)
            raw_expected, expected_typed = b'', False
            raw_id = raw_hash = raw_uri = expected_hash = b''
            shaped = types = expected_shape = expected_types = 0
            payload = data if data_tag and not oversized_or_untyped else b''
            metadata_wire = b''
            if operation_kind in (1, 4):
                # The codec is a foreign value bridge. Its immutable bytes
                # are captured exactly once, before any native launch claim.
                metadata_wire = wire({} if metadata is None else metadata) if data_tag and data_size <= 64 << 20 else b'{}'
            elif operation_kind == 2:
                (raw_id, raw_hash, raw_uri), shaped, types = self._reference_fields(reference, ('id', 'sha256', 'uri'))
            elif operation_kind == 3:
                raw_uri, typed = self._text(uri)
                raw_uri = raw_uri if len(raw_uri) <= 64 else b''
                types = 4 if typed else 0
            elif operation_kind == 5:
                (raw_identifier, raw_hash), shaped, types = self._reference_fields(reference, ('id', 'sha256'))
                (raw_expected, expected_hash), expected_shape, expected_types = self._reference_fields(expected, ('id', 'sha256'))
                identifier_typed, expected_typed = bool(types & 1), bool(expected_types & 1)
            kind_present = int(kind is not None)
            value_types = int(kind_typed) | (int(identifier_typed) << 1) | (int(expected_typed) << 2)
            values = (data_tag, data_size, len(raw_kind), len(metadata_wire), len(raw_identifier),
                kind_present, shaped, types, expected_shape, expected_types, len(raw_expected),
                len(raw_id), len(raw_hash), len(raw_uri), len(expected_hash), value_types)
            raw = raw_kind + metadata_wire + raw_identifier + raw_expected + raw_id + raw_hash + raw_uri + expected_hash + os.urandom(32)
            inputs_size = len(raw_kind) + len(metadata_wire) + len(raw_identifier)
            binding_size = min(MAX_JSON, 6 * len(raw_kind) + len(metadata_wire) + 128)
            self.state.reserve(min(MAX_STATE, PREFIX + inputs_size + binding_size + 512))
            operation = _Operation(_OperationInputs(binding, connection, payload))
            self._operation = operation
            try:
                receipt = self.state.call(1, binding, values=values, payload=raw)
                if receipt.status:
                    _reject(receipt.status)
                try:
                    operation.admission = _native_artifact_admission()
                    if operation.admission is None:
                        raise AgentRejected('E_HIA_ARTIFACT_NATIVE_CUSTODY', 'native byte owner is no longer selected')
                except AgentRejected:
                    cancelled = self.state.call(4, binding, effect_token=receipt.pending)
                    if cancelled.status != 13 or cancelled.phase != 4:
                        raise ArtifactNamespaceUnknown('unlaunched namespace operation could not be cancelled')
                    raise
                receipt = self._drive(operation, receipt)
                if receipt.status:
                    _reject(receipt.status)
                if receipt.phase != 3 or receipt.words[33] != operation_kind:
                    raise ArtifactNamespaceUnknown('namespace has no matching terminal result')
                metadata_value = decode_data(receipt.field(receipt.words[24] + receipt.words[25], receipt.words[26]))
                if operation_kind == 2:
                    result = operation.returned_bytes, metadata_value
                elif operation_kind == 5:
                    result = decode_data(operation.returned_bytes)
                elif operation_kind == 4:
                    profile_id = receipt.field(PREFIX + receipt.words[18] + receipt.words[19], receipt.words[20]).decode('utf-8')
                    result = ({'id': profile_id, 'sha256': receipt.field(512, 64).decode('ascii')}, receipt.reference())
                else:
                    result = receipt.reference()
                operation.finished = True
                return result
            except BaseException as error:
                attested = self.state.receipt
                if not (isinstance(error, AgentRejected) and self.state.fenced is None
                        and attested.phase in (3, 4) and tuple(attested.words[8:10]) == nonce):
                    self.state.fence(error)
                    if isinstance(error, Exception) and not isinstance(error, ArtifactNamespaceUnknown):
                        raise ArtifactNamespaceUnknown('namespace effect or receipt handoff is unconfirmed') from error
                raise

    def _execute(self, operation, statement, parameters=()):
        connection = operation.inputs.connection
        return (self.official if connection is None else connection).execute(statement, parameters)

    def _invoke(self, operation, name, *, data=b'', digest='-'):
        from .artifact_publication_native import invoke_artifact_store
        if os.environ.get(BYTE_SELECTOR) != operation.admission[0]:
            raise ArtifactNamespaceUnknown('selected native byte owner changed within namespace operation')
        return invoke_artifact_store(operation.admission[0], name, self.store.artifacts,
                                    data=data, digest=digest, _admission=operation.admission)

    def _row_outcome(self, operation, receipt, row):
        operation.returned_row = row
        if row is None:
            return self.state.call(3, operation.inputs.binding, values=(0,), effect_token=receipt.pending)
        fields, types = [], 0
        for index, name in enumerate(('id', 'sha256', 'uri', 'kind', 'metadata', 'content_key')):
            raw, typed = self._text(row[name])
            fields.append(raw); types |= int(typed) << index
        extra = min(MAX_JSON, 6 * len(fields[3]) + len(fields[4]) + 128)
        self.state.reserve(min(MAX_STATE, receipt.words[24] + len(fields[3]) + len(fields[4]) + extra + 512))
        values = (1, *(len(raw) for raw in fields), types)
        return self.state.call(3, operation.inputs.binding, values=values,
                              payload=b''.join(fields), effect_token=receipt.pending)

    def _drive(self, operation, receipt):
        from .artifact_publication_native import NativePublicationRefusal
        while receipt.phase == 1:
            self._check_operation(operation)
            binding, action, token = operation.inputs.binding, receipt.action, receipt.pending
            claimed = self.state.call(2, binding, effect_token=token)
            if claimed.status or claimed.phase != 2 or claimed.action != action or claimed.pending != token:
                raise ArtifactNamespaceUnknown('namespace effect launch was not confirmed')
            self._check_operation(operation)
            try:
                if action in (1, 2, 4):
                    content = operation.inputs.data if action != 2 else receipt.field(receipt.words[34], receipt.words[35])
                    answer = self._invoke(operation, 'store-put' if action == 4 else 'store-hash', data=content)
                    self._check_operation(operation)
                    digest, typed = self._text(answer.get('sha256'), 64)
                    size = answer.get('bytes')
                    if not typed or type(size) is not int or not 0 <= size < 1 << 64:
                        raise ArtifactNamespaceUnknown('native byte receipt has invalid transport fields')
                    receipt = self.state.call(3, binding, values=(1, size, len(digest)), payload=digest, effect_token=token)
                elif action in (3, 6):
                    row = self._execute(operation, 'SELECT * FROM main.artifacts WHERE content_key=?',
                        (receipt.field(576, 64).decode('ascii'),)).fetchone()
                    self._check_operation(operation)
                    receipt = self._row_outcome(operation, claimed, row)
                elif action == 5:
                    fields = (receipt.field(768, 34).decode('ascii'), receipt.field(512, 64).decode('ascii'),
                        receipt.field(832, 48).decode('ascii'), receipt.field(PREFIX, receipt.words[18]).decode('utf-8'),
                        receipt.field(PREFIX + receipt.words[18], receipt.words[19]).decode('utf-8'),
                        receipt.field(576, 64).decode('ascii'))
                    count = self._execute(operation, 'INSERT OR IGNORE INTO main.artifacts VALUES (?,?,?,?,?,?)', fields).rowcount
                    self._check_operation(operation)
                    if type(count) is not int or count not in (0, 1):
                        raise ArtifactNamespaceUnknown('namespace insertion has no exact affected-row count')
                    receipt = self.state.call(3, binding, values=(1, count), effect_token=token)
                elif action in (7, 9):
                    statement, value = ('SELECT * FROM main.artifacts WHERE id=?', receipt.field(640, 34)) if action == 7 else (
                        'SELECT * FROM main.artifacts WHERE uri=?', receipt.field(704, 48))
                    row = self._execute(operation, statement, (value.decode('ascii'),)).fetchone()
                    self._check_operation(operation)
                    receipt = self._row_outcome(operation, claimed, row)
                elif action == 8:
                    operation.returned_bytes = self._invoke(operation, 'store-get', digest=receipt.field(512, 64).decode('ascii'))
                    self._check_operation(operation)
                    if type(operation.returned_bytes) is not bytes:
                        raise ArtifactNamespaceUnknown('native artifact output is not exact bytes')
                    receipt = self.state.call(3, binding, values=(1, len(operation.returned_bytes)), effect_token=token)
                elif action in (10, 11):
                    identifier = receipt.field(PREFIX + receipt.words[18] + receipt.words[19], receipt.words[20]).decode('utf-8')
                    digest = receipt.field(512 if action == 10 or binding.operation_kind == 4 else 896, 64).decode('ascii')
                    if action == 10:
                        reference = receipt.field(receipt.words[34], receipt.words[35]).decode('ascii')
                        count = self._execute(operation, 'INSERT OR IGNORE INTO main.profiles VALUES (?,?,?)',
                                              (identifier, digest, reference)).rowcount
                        self._check_operation(operation)
                        if type(count) is not int or count not in (0, 1):
                            raise ArtifactNamespaceUnknown('profile insertion has no exact affected-row count')
                        receipt = self.state.call(3, binding, values=(1, count), effect_token=token)
                    else:
                        row = self._execute(operation, 'SELECT artifact FROM main.profiles WHERE id=? AND sha256=?',
                                            (identifier, digest)).fetchone()
                        self._check_operation(operation)
                        operation.returned_row = row
                        if row is None:
                            receipt = self.state.call(3, binding, values=(0,), effect_token=token)
                        else:
                            raw, typed = self._text(row['artifact'])
                            receipt = self.state.call(3, binding, values=(1, len(raw), int(typed)), payload=raw, effect_token=token)
                else:
                    raise ArtifactNamespaceUnknown('native namespace emitted an unknown effect')
            except NativePublicationRefusal as error:
                expected = 'store-get' if action == 8 else 'store-hash'
                if action not in (1, 2, 8) or error.operation != expected or type(error.returncode) is not int or not 0 <= error.returncode < 1 << 64:
                    raise
                self._check_operation(operation)
                receipt = self.state.call(3, binding, values=(2, error.returncode), effect_token=token)
            if receipt.status:
                _reject(receipt.status)
        return receipt

    def put(self, data, kind, metadata=None, *, _connection=None):
        return self._operate(1, data=data, kind=kind, metadata=metadata, connection=_connection)

    def json(self, value, kind, metadata=None, *, _connection=None):
        from .hia_agent_store import wire
        return self.put(wire(value), kind, metadata, _connection=_connection)

    def get(self, reference, *, kind=None, _connection=None):
        return self._operate(2, reference=reference, kind=kind, connection=_connection)

    def get_json(self, reference, *, kind=None, _connection=None):
        from .hia_agent_store import decode_data
        payload, metadata = self.get(reference, kind=kind, _connection=_connection)
        return decode_data(payload), metadata

    def resolve_uri(self, uri):
        return self._operate(3, uri=uri)

    def profile(self, identifier, value):
        from .hia_agent_store import wire
        return self._operate(4, data=wire(value), kind='profile', identifier=identifier)

    def check_profile(self, reference, expected, *, _connection=None):
        return self._operate(5, reference=reference, expected=expected, connection=_connection)

    def _scope_binding(self, scope):
        if self._scope is not scope or scope.thread != threading.get_ident():
            raise ArtifactNamespaceUnknown('namespace transaction scope was replaced or crossed threads')
        epoch = struct.unpack_from('<Q', self.state.buffer, 41 * 8)[0]
        return NamespaceBinding((0, 0), self.connection_identity, 1, epoch, scope.nonce)

    def _execute_scope(self, statement):
        return self.official.execute(statement)

    def _drive_scope(self, scope, receipt):
        binding = self._scope_binding(scope)
        token, action = receipt.words[45], receipt.words[44]
        if receipt.status or receipt.words[40] != 1 or action not in (14, 15, 16):
            raise ArtifactNamespaceUnknown('namespace transaction has no staged effect')
        claimed = self.state.call(21, binding, effect_token=token)
        if claimed.status or claimed.words[40] != 2 or claimed.words[44] != action or claimed.words[45] != token:
            raise ArtifactNamespaceUnknown('namespace transaction launch was not confirmed')
        self.check()
        self._execute_scope({14: 'BEGIN IMMEDIATE', 15: 'COMMIT', 16: 'ROLLBACK'}[action])
        active = self.official.in_transaction
        if type(active) is not bool:
            raise ArtifactNamespaceUnknown('namespace transaction state has no exact observation')
        self.check()
        receipt = self.state.call(22, binding, values=(1, int(active)), effect_token=token)
        if receipt.status:
            _reject(receipt.status)
        return receipt

    def _scope_failed(self, scope, error):
        """Never let nested error cleanup repeat a consumed SQL rollback."""
        if os.getpid() != self.creator:
            raise ArtifactNamespaceUnknown('namespace transaction cleanup belongs to its creator process') from error
        binding = self._scope_binding(scope)
        try:
            active = self.official.in_transaction
            granted = self.state.cleanup_claim(binding, active)
            # Native scope revocation precedes hosted diagnostic publication.
            # Losing that STORE_ATTR cannot leave a live scope available to a
            # later namespace call or restore SQL rollback authority.
            self.state.fence(error)
            if granted:
                self._execute_scope('ROLLBACK')
                if self.official.in_transaction:
                    raise ArtifactNamespaceUnknown('namespace rollback did not close its original transaction')
                self.state.cleanup_claim(binding, True, acknowledge=True)
            elif active:
                raise ArtifactNamespaceUnknown('namespace rollback was already claimed or unavailable')
        except BaseException as cleanup_error:
            raise ArtifactNamespaceUnknown('namespace transaction cleanup is unconfirmed') from cleanup_error
        raise ArtifactNamespaceUnknown('namespace transaction result is unconfirmed') from error

    @contextmanager
    def transaction(self):
        """The original official connection, with retained native end claims."""
        with self.lock:
            self.check()
            if self._scope is not None or self.official.in_transaction:
                raise ArtifactNamespaceUnknown('namespace cannot enter an already owned transaction')
            scope = _Scope(struct.unpack('<2Q', os.urandom(16)), threading.get_ident())
            self._scope = scope
            try:
                binding = NamespaceBinding((0, 0), self.connection_identity, 1, 0, scope.nonce)
                receipt = self.state.call(20, binding)
                self._drive_scope(scope, receipt)
            except BaseException as error:
                self._scope_failed(scope, error)
            try:
                yield
            except BaseException:
                try:
                    binding = self._scope_binding(scope)
                    receipt = self.state.call(23, binding, values=(0,))
                    self._drive_scope(scope, receipt)
                    self._scope = None
                except BaseException as error:
                    self._scope_failed(scope, error)
                raise
            else:
                try:
                    binding = self._scope_binding(scope)
                    receipt = self.state.call(23, binding, values=(1,))
                    self._drive_scope(scope, receipt)
                    self._scope = None
                except BaseException as error:
                    self._scope_failed(scope, error)

    def close(self):
        if os.getpid() != self.creator:
            raise ArtifactNamespaceUnknown('namespace close belongs to its creator process')
        self.closed = True
