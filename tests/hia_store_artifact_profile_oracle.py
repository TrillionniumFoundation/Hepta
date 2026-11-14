"""Independent whole-body Store observations against actual 73f1634 sources.

No Hepta package is imported.  The eight unmodified original methods execute
against finite fake providers.  There is no filesystem, SQLite, native image,
VM, subprocess, deadline change, or transaction execution in this oracle.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
import types

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / 'fixtures'
METHODS = ('put', 'json', '_ref', 'get', 'get_json', 'resolve_uri', 'profile', 'check_profile')
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ERROR_TYPES = {
    'ValueError': ValueError, 'StopIteration': StopIteration,
    'OSError': OSError, 'FileExistsError': FileExistsError,
    'AttributeError': AttributeError, 'KeyError': KeyError,
    'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit,
    'GeneratorExit': GeneratorExit, 'RuntimeError': RuntimeError,
    'TypeError': TypeError, 'OverflowError': OverflowError,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def cases():
    """Return the source-frozen finite input list, never generated expectations."""
    return json.loads((FIXTURES / 'hia_store_artifact_profile_cases_73f1634.json').read_bytes())['cases']


class Marker:
    def __init__(self, label):
        self.label = label


class Truth(Marker):
    def __init__(self, fixture, label, value):
        super().__init__(label)
        self.fixture, self.value = fixture, value

    def __bool__(self):
        self.fixture.emit(self.label + '.bool')
        return self.value


class Mapping(Marker):
    def __init__(self, fixture, label, data):
        super().__init__(label)
        self.fixture, self.data = fixture, data
        self.reads = Counter()

    def __getitem__(self, key):
        self.fixture.emit(self.label + '.getitem', key)
        self.reads[key] += 1
        changes = self.fixture.case.get('mapping_reads', {}).get(self.label, {}).get(str(key))
        if changes is not None:
            return self.fixture.decode_spec(changes[min(self.reads[key] - 1, len(changes) - 1)])
        return self.data[key]

    def __ne__(self, other):
        self.fixture.emit(self.label + '.ne', other)
        choice = self.fixture.case.get('comparison', {}).get(self.label)
        if choice is not None:
            return Truth(self.fixture, self.label + '.ne-result', choice)
        return self.data != (other.data if isinstance(other, Mapping) else other)

    def __eq__(self, other):
        self.fixture.emit(self.label + '.eq', other)
        return self.data == (other.data if isinstance(other, Mapping) else other)


class SequenceResult(Marker):
    def __init__(self, fixture, label, values):
        super().__init__(label)
        self.fixture, self.values, self.index = fixture, values, 0

    def __iter__(self):
        self.fixture.emit(self.label + '.iter')
        return self

    def __next__(self):
        self.fixture.emit(self.label + '.next', self.index)
        if self.index >= len(self.values):
            raise StopIteration
        value = self.values[self.index]
        self.index += 1
        return value

    def __length_hint__(self):
        self.fixture.emit(self.label + '.length_hint')
        raise AssertionError('original Store unpack does not request length_hint')


class SubscriptionResult(Marker):
    def __init__(self, fixture, label, value):
        super().__init__(label)
        self.fixture, self.value = fixture, value

    def __getitem__(self, key):
        self.fixture.emit(self.label + '.getitem', key)
        return self.value


class PathValue(Marker):
    def __init__(self, fixture, parts):
        super().__init__('path:' + '/'.join(str(x) for x in parts))
        self.fixture, self.parts = fixture, parts

    def __truediv__(self, name):
        self.fixture.emit('path.divide', self, name)
        return PathValue(self.fixture, self.parts + (name,))

    def unlink(self, **kwargs):
        self.fixture.emit('path.unlink', self, kwargs)
        self.fixture.state['temporary_exists'] = False


class DigestValue(Marker):
    def __init__(self, fixture):
        super().__init__('hash-result')
        self.fixture = fixture

    def hexdigest(self):
        self.fixture.emit('hash.hexdigest')
        return self.fixture.case.get('sha_value', self.fixture.content_hash)


class UUIDValue(Marker):
    def __init__(self, fixture, index):
        super().__init__('uuid-' + str(index))
        self.fixture, self.index = fixture, index

    @property
    def hex(self):
        self.fixture.emit('uuid.hex', self.index)
        return f'{self.index:032x}'


class UUIDProvider:
    def __init__(self, fixture):
        self.fixture, self.index = fixture, 0

    def uuid4(self):
        self.fixture.emit('uuid.uuid4')
        self.index += 1
        return UUIDValue(self.fixture, self.index)


class Stream(Marker):
    def __init__(self, fixture):
        super().__init__('stream')
        self.fixture = fixture

    def __getattribute__(self, name):
        if name in ('write', 'flush', 'fileno'):
            object.__getattribute__(self, 'fixture').emit('stream.lookup.' + name)
        return object.__getattribute__(self, name)

    def write(self, data):
        self.fixture.emit('stream.write', data)
        self.fixture.state['temporary_data'] = data
        return self.fixture.decode_spec(self.fixture.case.get('write_result', {'kind': 'length-data'}))

    def flush(self):
        self.fixture.emit('stream.flush')
        self.fixture.state['stream_flushed'] = True

    def fileno(self):
        self.fixture.emit('stream.fileno')
        return 11


class StreamSpecial:
    def __init__(self, name):
        self.name = name

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        f = obj.fixture
        f.emit('stream.special.lookup.' + self.name)
        if self.name == '__enter__':
            def enter():
                f.emit('stream.enter')
                f.state['stream_entered'] = True
                return f.stream
            return enter
        def exit(kind, error, traceback):
            f.emit('stream.exit', None if kind is None else kind.__name__,
                   None if error is None else f.error_token(error), traceback is not None)
            f.state['stream_exited'] = True
            choice = f.case.get('exit_result', False)
            if isinstance(choice, dict) and choice.get('kind') == 'truth':
                return Truth(f, 'stream.exit-result', choice['value'])
            return choice
        return exit


class StreamManager(Marker):
    __enter__ = StreamSpecial('__enter__')
    __exit__ = StreamSpecial('__exit__')

    def __init__(self, fixture):
        super().__init__('stream-manager')
        self.fixture = fixture


class OSProvider:
    O_WRONLY, O_CREAT, O_EXCL, O_CLOEXEC, O_NOFOLLOW = 1, 64, 128, 524288, 131072
    O_RDONLY, O_DIRECTORY = 0, 65536

    def __init__(self, fixture):
        self.fixture = fixture

    def open(self, path, flags, *mode):
        f = self.fixture
        role = 'temporary' if mode else 'directory'
        f.emit('os.open.' + role, path, flags, mode)
        if mode:
            f.state['temporary_exists'] = True
            return 11
        f.state['directory_open'] = True
        return 12

    def fdopen(self, descriptor, mode):
        self.fixture.emit('os.fdopen', descriptor, mode)
        return StreamManager(self.fixture)

    def fsync(self, descriptor):
        role = 'file' if descriptor == 11 else 'directory'
        self.fixture.emit('os.fsync.' + role, descriptor)
        self.fixture.state[role + '_synced'] = True

    def link(self, source, destination, **kwargs):
        f = self.fixture
        f.emit('os.link', source, destination, kwargs)
        if f.case.get('link_exists'):
            raise f.link_exists_error
        f.state['durable_data'] = f.state.get('temporary_data')

    def close(self, descriptor):
        self.fixture.emit('os.close', descriptor)
        self.fixture.state['directory_open'] = False


class Cursor(Marker):
    def __init__(self, fixture, role, row):
        super().__init__('cursor:' + role)
        self.fixture, self.role, self.row = fixture, role, row

    def fetchone(self):
        self.fixture.emit('sql.fetchone.' + self.role)
        return self.row


class Execute(Marker):
    def __init__(self, db, generation):
        super().__init__('execute:' + str(generation))
        self.db, self.generation = db, generation

    def __call__(self, sql, arguments):
        return self.db.run(self.generation, sql, arguments)


class Database(Marker):
    def __init__(self, fixture):
        super().__init__('database')
        self.fixture, self.generation = fixture, 1
        self.content_selects = 0
        self.inserted = None

    def __getattribute__(self, name):
        if name == 'execute':
            f = object.__getattribute__(self, 'fixture')
            generation = object.__getattribute__(self, 'generation')
            f.emit('db.execute.lookup', generation)
            return Execute(self, generation)
        return object.__getattribute__(self, name)

    def run(self, generation, sql, arguments):
        f = self.fixture
        if sql.startswith('INSERT OR IGNORE INTO artifacts'):
            role = 'insert-artifact'
        elif sql.startswith('INSERT OR IGNORE INTO profiles'):
            role = 'insert-profile'
        elif 'content_key=?' in sql:
            role = 'select-content'
        elif sql.startswith('SELECT artifact'):
            role = 'select-profile'
        elif 'WHERE uri=?' in sql:
            role = 'select-uri'
        elif 'WHERE id=?' in sql:
            role = 'select-id'
        else:
            raise AssertionError('unexpected original SQL: ' + sql)
        f.emit('sql.execute.' + role, generation, sql, arguments)
        row = None
        if role == 'select-content':
            self.content_selects += 1
            if self.content_selects == 1:
                row = f.row if f.case.get('previous') else None
            else:
                row = (None if f.case.get('final_row_none') else f.winning_row
                       if f.case.get('race_winner') else self.inserted)
        elif role == 'insert-artifact':
            keys = ('id', 'sha256', 'uri', 'kind', 'metadata', 'content_key')
            self.inserted = Mapping(f, 'inserted-row', dict(zip(keys, arguments, strict=True)))
            f.state['artifact_insert'] = tuple(arguments)
        elif role == 'insert-profile':
            f.state['profile_insert'] = tuple(arguments)
        elif role == 'select-profile':
            row = None if f.case.get('row_none') else f.profile_row
        else:
            row = None if f.case.get('row_none') else f.row
        return Cursor(f, role, row)


class Override(Marker):
    def __init__(self, fixture, name, specification):
        super().__init__('override:' + name)
        self.fixture, self.name, self.specification = fixture, name, specification

    def __getattribute__(self, name):
        if name in ('__func__', '__self__'):
            f = object.__getattribute__(self, 'fixture')
            f.emit('override.inspect', object.__getattribute__(self, 'name'), name)
            raise AssertionError('ordinary Store call never inspects a callable binding')
        return object.__getattribute__(self, name)

    def __call__(self, *args, **kwargs):
        f = self.fixture
        f.emit('override.call.' + self.name, args, kwargs)
        f.override_arguments[self.name] = args
        result = f.override_result(self.name, self.specification)
        f.override_results[self.name] = result
        return result


class OverrideDescriptor:
    def __init__(self, fixture, name, specification):
        self.fixture, self.name, self.specification = fixture, name, specification

    def __get__(self, obj, cls=None):
        self.fixture.emit('override.descriptor.' + self.name)
        return Override(self.fixture, self.name, self.specification)


def namespace_for(fixture):
    module = (FIXTURES / 'hia_agent_store_73f1634.py.txt').read_text()
    lines = module.splitlines(keepends=True)
    tree = ast.parse(module)
    retained = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in ('AgentRejected', 'reject', 'keys'):
            retained.append(''.join(lines[node.lineno - 1:node.end_lineno]))
    ns = {'__builtins__': __builtins__, 'MAX_ARTIFACT_BYTES': MAX_ARTIFACT_BYTES}
    exec(compile('\n\n'.join(retained), '<frozen-73-Store-foreign-keys-reject>', 'exec'), ns)
    fixture.original_reject = ns['reject']
    fixture.original_keys = ns['keys']
    ns.update({
        '_native_artifact_admission': fixture.native_admission,
        '_native_artifact_file': fixture.native_file,
        'sha256': fixture.sha256, 'digest': fixture.digest,
        'wire': fixture.wire, 'decode_data': fixture.decode_data,
        'stable_read': fixture.stable_read, 'keys': fixture.keys,
        'reject': fixture.reject, 'uuid': UUIDProvider(fixture), 'os': OSProvider(fixture),
    })
    methods = ''.join((FIXTURES / ('AgentStore.' + name + '.py.txt')).read_text() + '\n'
                      for name in METHODS)
    exec(compile('class OriginalStore:\n' + methods,
                 '<frozen-73-Store-eight-whole-methods>', 'exec'), ns)
    return ns


class Fixture:
    def __init__(self, case, bindings=None):
        self.case = case
        self.events, self.counts, self.state = [], Counter(), {}
        self.override_arguments, self.override_results = {}, {}
        self.provider_values = {}
        self.error_labels, self.error_refs, self.byte_cache = {}, [], {}
        self.faults = []
        for index, item in enumerate(case.get('faults', ())):
            error = ERROR_TYPES[item['error']](item.get('message', 'injected-' + str(index + 1)))
            self.error_labels[id(error)] = 'injected-' + str(index + 1)
            self.error_refs.append(error)
            self.faults.append((item, error))
        self.outer = RuntimeError('outer-active-error')
        self.error_labels[id(self.outer)] = 'outer-active-error'
        self.link_exists_error = FileExistsError('destination already exists')
        self.error_labels[id(self.link_exists_error)] = 'link-exists'
        self.error_refs.extend((self.outer, self.link_exists_error))
        self.content_hash = 'b' * 64
        self.payload = b'{"answer":7}'
        self.data = self.data_value(case.get('data', 'ordinary'))
        self.metadata = self.decode_spec(case.get('metadata', {'kind': 'dict', 'value': {'origin': 'fixture'}}))
        self.kind = self.decode_spec(case.get('kind', 'native'))
        self.ref = {'id': 'a-existing', 'sha256': self.content_hash, 'uri': 'hia://artifacts/existing'}
        self.expected = self.ref
        self.result_marker = Marker('result-marker')
        self.admission = Marker('artifact-admission')
        self.decoded_data = {'answer': 7}
        self.decoded_metadata = {'origin': 'stored'}
        self.row = Mapping(self, 'row', {**self.ref, 'kind': case.get('row_kind', self.kind),
                                       'metadata': '{"origin":"stored"}', 'content_key': 'content-key'})
        self.winning_row = Mapping(self, 'winning-row', {**self.row.data, 'id': 'a-race-winner',
                                                       'uri': 'hia://artifacts/race-winner'})
        self.profile_row = Mapping(self, 'profile-row', {'artifact': 'profile-ref-json'})
        self.namespace = namespace_for(self)
        Base = self.namespace['OriginalStore']
        f = self
        class Subject(Base):
            def __getattribute__(self, name):
                if name in METHODS or name in ('db', 'artifacts'):
                    f.emit('self.lookup.' + name)
                return object.__getattribute__(self, name)
        if bindings is not None:
            for name in METHODS:
                setattr(Subject, name, staticmethod(bindings[name]) if name == '_ref' else bindings[name])
        self.subject = Subject()
        self.database = Database(self)
        self.subject.db = self.database
        self.subject.artifacts = PathValue(self, ('artifacts',))
        self.stream = Stream(self)
        for name, specification in case.get('overrides', {}).items():
            self.set_override(name, specification)
        if case.get('ref_missing'):
            del self.ref[case['ref_missing']]
        if case.get('ref_extra'):
            self.ref['unexpected'] = 1
        if case.get('ref_mismatch'):
            self.ref = {**self.ref, 'sha256': 'wrong-sha'}
        if case.get('ref_mapping'):
            self.ref = Mapping(self, 'reference', self.ref)
        if case.get('expected_distinct'):
            self.expected = {'id': 'different', 'sha256': 'wrong'}
        if case.get('ref_comparison') is not None:
            self.ref = Mapping(self, 'reference', self.ref)
            self.case = {**case, 'comparison': {**case.get('comparison', {}),
                                              'reference': case['ref_comparison']}}
        self.events.clear()
        self.counts.clear()

    def data_value(self, choice):
        if choice == 'ordinary':
            return self.payload
        if choice == 'empty':
            return b''
        if choice == 'limit':
            return b'\0' * MAX_ARTIFACT_BYTES
        if choice == 'over-limit':
            return b'\0' * (MAX_ARTIFACT_BYTES + 1)
        if choice == 'bytearray':
            return bytearray(b'a')
        if choice == 'bytes-subclass':
            return type('ByteSubclass', (bytes,), {})(b'a')
        if choice == 'memoryview':
            return memoryview(b'a')
        return {'none': None, 'str': 'a', 'integer': 1, 'bool': False, 'list': []}[choice]

    def decode_spec(self, value):
        if not isinstance(value, dict) or 'kind' not in value:
            return value
        kind = value['kind']
        if kind == 'dict':
            return dict(value['value'])
        if kind == 'marker':
            return Marker(value.get('label', 'opaque-value'))
        if kind == 'length-data':
            return len(self.data)
        if kind == 'bytes':
            return bytes.fromhex(value['hex'])
        if kind == 'ref':
            return self.ref
        if kind == 'result':
            return self.result_marker
        if kind == 'huge-int':
            return 1 << value.get('bits', 4096)
        if kind == 'negative-int':
            return -(1 << value.get('bits', 4096))
        if kind == 'truth':
            return Truth(self, value.get('label', 'truth-value'), value['value'])
        raise AssertionError('unknown input specification: ' + kind)

    def snapshot(self, value):
        if value is None or type(value) in (bool, int, str):
            return value
        if type(value) is float:
            return {'float64': struct.pack('>d', value).hex()}
        if isinstance(value, bytes):
            if len(value) <= 128:
                result = {'bytes': value.hex()}
            else:
                key = id(value)
                if key not in self.byte_cache:
                    self.byte_cache[key] = (value, hashlib.sha256(value).hexdigest())
                result = {'bytes_length': len(value), 'sha256': self.byte_cache[key][1]}
            if type(value) is not bytes:
                result['subclass'] = type(value).__name__
            return result
        if isinstance(value, (bytearray, memoryview)):
            return {'type': type(value).__name__, 'bytes': bytes(value).hex()}
        if isinstance(value, Marker):
            return {'opaque': object.__getattribute__(value, 'label')}
        if type(value) is dict:
            return {'dict': [[self.snapshot(key), self.snapshot(item)] for key, item in dict.items(value)]}
        if type(value) is tuple:
            return {'tuple': [self.snapshot(item) for item in value]}
        if type(value) is list:
            return {'list': [self.snapshot(item) for item in value]}
        if isinstance(value, BaseException):
            return {'exception_identity': self.error_token(value)}
        if value is getattr(self, 'subject', None):
            return {'identity': 'subject'}
        if isinstance(value, type):
            return {'type': value.__name__}
        return {'object_type': type(value).__name__}

    def error_token(self, error):
        if id(error) not in self.error_labels:
            label = 'observed-' + str(len(self.error_labels) + 1)
            self.error_labels[id(error)] = label
            self.error_refs.append(error)
        return self.error_labels[id(error)]

    def emit(self, name, *values):
        self.counts[name] += 1
        current = sys.exception()
        self.events.append({'event': name, 'occurrence': self.counts[name],
                            'values': self.snapshot(values),
                            'active_exception': None if current is None else self.error_token(current)})
        for mutation in self.case.get('mutations', ()):
            if mutation['event'] == name and mutation.get('occurrence', 1) == self.counts[name]:
                if mutation['target'] == 'db.execute':
                    self.database.generation += 1
                elif mutation['target'].startswith('self.'):
                    self.set_override(mutation['target'].split('.', 1)[1], mutation.get('value', {'result': 'marker'}))
                else:
                    provider = mutation['target']
                    result_spec = mutation.get('result', {'kind': 'result'})
                    def replacement(*args, _provider=provider, _result=result_spec, **kwargs):
                        self.emit('rebound-provider.' + _provider, args, kwargs)
                        return self.decode_spec(_result)
                    self.namespace[provider] = replacement
        for fault, error in self.faults:
            if fault['event'] == name and fault.get('occurrence', 1) == self.counts[name]:
                raise error

    def set_override(self, name, specification):
        shape = specification.get('shape', 'instance')
        if shape == 'descriptor':
            setattr(type(self.subject), name, OverrideDescriptor(self, name, specification))
        elif shape == 'subclass':
            def override(subject, *args, **kwargs):
                self.emit('override.subclass.' + name, subject, args, kwargs)
                self.override_arguments[name] = args
                result = self.override_result(name, specification)
                self.override_results[name] = result
                return result
            setattr(type(self.subject), name, staticmethod(override) if name == '_ref' else override)
        elif shape == 'noncallable':
            setattr(self.subject, name, 17)
        else:
            setattr(self.subject, name, Override(self, name, specification))

    def override_result(self, name, specification):
        choice = specification.get('result', 'ordinary')
        if choice == 'marker':
            return self.result_marker
        if choice == 'none':
            return None
        if choice == 'observed-ref':
            return Mapping(self, 'override-ref', dict(self.ref))
        if choice == 'subscription':
            return SubscriptionResult(self, 'override-subscription', self.result_marker)
        if choice == 'empty':
            return ()
        if choice == 'string':
            return 'abc'
        if choice == 'iterator':
            count = specification.get('count', 2)
            return SequenceResult(self, 'override-iterator', [self.payload, self.metadata, self.result_marker][:count])
        if choice in ('tuple', 'list'):
            values = [self.payload, self.metadata, self.result_marker][:specification.get('count', 2)]
            return tuple(values) if choice == 'tuple' else values
        if name == 'get':
            return self.payload, self.metadata
        if name == 'get_json':
            return self.decoded_data, self.decoded_metadata
        return dict(self.ref)

    def native_admission(self):
        self.emit('native.admission')
        choice = self.case.get('admission', 'native')
        value = None if choice == 'none' else False if choice == 'false' else {} if choice == 'empty-dict' else self.admission
        self.provider_values['admission'] = value
        return value

    def native_file(self, operation, root, *, data=b'', content_hash='-', _admission=None):
        self.emit('native.file.' + operation, root, data, content_hash, _admission)
        self.state.setdefault('native_operations', []).append(operation)
        if operation in ('store-hash', 'store-put'):
            self.state.setdefault('same_admission_object', []).append(
                _admission is self.provider_values.get('admission'))
        if operation == 'store-get':
            choice = self.case.get('native_get', 'ordinary')
            return None if choice == 'none' else b'' if choice == 'empty' else False if choice == 'false' else self.payload
        if operation == 'store-hash':
            choice = self.case.get('native_hash', 'ordinary')
            if choice == 'none':
                return None
            if choice == 'false':
                return False
            if choice == 'missing':
                return {}
        receipt = {'sha256': self.content_hash, 'size': len(data)}
        if operation == 'store-put':
            self.state['durable_data'] = data
            if self.case.get('stored_mismatch'):
                receipt['sha256'] = 'mismatched-sha'
            if self.case.get('observed_stored'):
                return Mapping(self, 'stored-receipt', receipt)
        return receipt

    def sha256(self, data):
        self.emit('hash.sha256', data)
        return DigestValue(self)

    def digest(self, value):
        self.emit('digest', value)
        self.state['digest_metadata_is_input'] = value['metadata'] is self.metadata
        self.provider_values['digest_metadata'] = value['metadata']
        return 'content-key'

    def wire(self, value):
        self.emit('wire', value)
        if 'digest_metadata' in self.provider_values:
            self.state.setdefault('wire_reuses_digest_metadata', []).append(
                value is self.provider_values['digest_metadata'])
        if self.case.get('wire_invalid_utf8'):
            return b'\xff'
        if self.case.get('wire_wrong_type'):
            return bytearray(b'{}')
        if self.case.get('wire_result') is not None:
            return self.decode_spec(self.case['wire_result'])
        try:
            return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        except (ValueError, TypeError):
            # The JSON provider is a declared opaque boundary.  This explicit
            # fake result is useful for checking that Store adds no new type
            # or truthiness restriction of its own.
            return b'{"opaque-provider-value":true}'

    def decode_data(self, payload):
        self.emit('decode', payload)
        if payload == 'profile-ref-json':
            return self.ref
        if payload == self.payload:
            return self.decoded_data
        if payload == '{"origin":"stored"}':
            return self.decoded_metadata
        return json.loads(payload)

    def stable_read(self, path, limit):
        self.emit('stable_read', path, limit)
        return b'corrupt' if self.case.get('stable_mismatch') else self.data if self.case['method'] == 'put' else self.payload

    def keys(self, value, required, optional=(), label='object'):
        self.emit('keys', value, required, optional, label)
        return self.original_keys(value, required, optional, label)

    def reject(self, *args, **kwargs):
        self.emit('reject', args, kwargs)
        return self.original_reject(*args, **kwargs)

    def arguments(self):
        method = self.case['method']
        if method == 'put':
            return (self.data, self.kind, self.metadata), {}
        if method == 'json':
            return ({'value': 1}, self.kind, self.metadata), {}
        if method == '_ref':
            row = self.row
            if self.case.get('row_missing'):
                row.data.pop(self.case['row_missing'])
            return (row,), {}
        if method in ('get', 'get_json'):
            kind = None if self.case.get('kind_none') else self.kind
            return (self.ref,), {'kind': kind}
        if method == 'resolve_uri':
            return ('hia://artifacts/existing',), {}
        if method == 'profile':
            return (self.decode_spec(self.case.get('identifier', 'profile-id')), {'value': 1}), {}
        return (self.ref, self.expected), {}

    def exception_record(self, error, seen=None):
        seen = set() if seen is None else seen
        if id(error) in seen:
            return {'cycle': self.error_token(error)}
        seen.add(id(error))
        result = {'identity': self.error_token(error), 'type': type(error).__name__,
                  'args': self.snapshot(error.args), 'suppress_context': error.__suppress_context__}
        for attribute in ('code', 'phase', 'retry_action', 'details_artifact', 'name', 'obj'):
            if hasattr(error, attribute):
                result[attribute] = self.snapshot(getattr(error, attribute))
        result['cause'] = None if error.__cause__ is None else self.exception_record(error.__cause__, seen)
        result['context'] = None if error.__context__ is None else self.exception_record(error.__context__, seen)
        return result

    def observe(self, owner=None):
        args, kwargs = self.arguments()
        def invoke():
            try:
                if owner is None:
                    method = getattr(self.namespace['OriginalStore'], self.case['method'])
                    value = method(*args, **kwargs) if self.case['method'] == '_ref' else method(self.subject, *args, **kwargs)
                else:
                    value = owner(self.case['method'], self.subject, args, kwargs, self.namespace)
                outcome = {'returned': self.snapshot(value), 'aliases': {
                    'input_data': value is self.data, 'input_metadata': value is self.metadata,
                    'input_ref': value is self.ref, 'result_marker': value is self.result_marker,
                    'decoded_data': value is self.decoded_data,
                    'pair_payload': isinstance(value, tuple) and len(value) > 0 and value[0] is self.payload,
                    'pair_decoded_data': isinstance(value, tuple) and len(value) > 0 and value[0] is self.decoded_data,
                    'pair_metadata': isinstance(value, tuple) and len(value) > 1 and value[1] is self.metadata,
                    'pair_decoded_metadata': isinstance(value, tuple) and len(value) > 1 and value[1] is self.decoded_metadata,
                    'returned_override_results': [name for name, result in self.override_results.items() if value is result],
                    'pair_second_override_results': [name for name, result in self.override_results.items()
                        if isinstance(value, tuple) and len(value) > 1 and value[1] is result],
                    'same_ref_passed_to_override_get': bool(self.override_arguments.get('get'))
                        and value is self.override_arguments['get'][0]}}
            except BaseException as error:
                outcome = {'exception': self.exception_record(error)}
            return outcome
        if self.case.get('outer_except'):
            try:
                raise self.outer
            except BaseException:
                outcome = invoke()
                self.emit('owner.returned-to-caller')
        else:
            outcome = invoke()
            self.emit('owner.returned-to-caller')
        return {'name': self.case['name'], 'method': self.case['method'],
                'outcome': outcome, 'trace': json.loads(canonical(self.events)),
                'state': self.snapshot(self.state)}


def observe_case(case, owner=None, bindings=None):
    """owner(method, store, args, kwargs, namespace); optional canonical bridges.

    Candidate integration must also arrange its real provider module to use
    this fixture's namespace during nested public calls.  No expected result
    is generated from a candidate or from its control graph.
    """
    return Fixture(case, bindings=bindings).observe(owner)
