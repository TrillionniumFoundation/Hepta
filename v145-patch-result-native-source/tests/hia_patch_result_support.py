"""Evidence and explicit test context for the new patch-policy component.

Importing this file executes no compiler, HIA port, native image or Core VM.
Full frame bytes are lossless CAS members; hashes never substitute for data.
"""
from __future__ import annotations

import ctypes
from hashlib import sha1, sha256
import json
from pathlib import Path
import struct
import traceback
import zlib

CAPACITY = 1048576
VM_STEPS = 10000000
VM_HEAP = 8 << 20
VM_CALL_DEPTH = 128
CONTEXT = None
FRAME_KEYS = ('source_before', 'output_before', 'workspace_before',
              'source_after', 'output_after', 'workspace_after')
VM_KEYS = ('apply-start', 'interface-start', 'import-claim', 'import-ack',
           'unpack4-claim', 'unpack4-ack', 'generator-start', 'normal-terminal',
           'exception-terminal', 'retirement-start', 'retirement-ack', 'lost-claim')


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    require(type(raw) is bytes, 'exact evidence bytes required')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def publish(path, value):
    raw = encoded(value)
    with Path(path).open('xb') as stream:
        stream.write(raw)
    require(Path(path).read_bytes() == raw, 'evidence publication differs')


def configure(value):
    global CONTEXT
    require(CONTEXT is None and type(value) is dict, 'one explicit test context required')
    CONTEXT = value


def context():
    require(type(CONTEXT) is dict, 'explicit qualification request is required; no ambient selector')
    return CONTEXT


class BufferStore:
    def __init__(self, directory, *, create=True):
        self.directory = Path(directory).absolute()
        if create:
            self.directory.mkdir(mode=0o700)

    def put(self, raw):
        identity = pin(raw)
        path = self.directory / (identity['sha256'] + '.zlib')
        if path.exists():
            require(zlib.decompress(path.read_bytes()) == raw, 'full buffer CAS changed')
        else:
            with path.open('xb') as stream:
                stream.write(zlib.compress(raw, 1))
            require(zlib.decompress(path.read_bytes()) == raw, 'full buffer CAS write differs')
        return {**identity, 'file': path.name}

    def get(self, row):
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'git_blob', 'file'}
                and row['file'] == row['sha256'] + '.zlib', 'buffer reference differs')
        raw = zlib.decompress((self.directory / row['file']).read_bytes())
        require(pin(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')},
                'actual complete buffer identity differs')
        return raw


def shape(output, workspace):
    result = {'command': None, 'entry_mode': None, 'issued_operation': None, 'issued_raw': None}
    if len(workspace) >= 48:
        command, nonce, sequence, mode, error, profile = struct.unpack_from('<6Q', workspace)
        result.update(command=command, nonce=nonce, sequence=sequence,
                      entry_mode=mode if command == 0 else None, runtime_profile=profile)
    if len(output) >= 128:
        head = struct.unpack_from('<10Q', output)
        nd, na, nr, nv = head[5:9]
        if max(nd, na, nr, nv) <= 65536 and 128 + 8 * (nd + na + nr + nv) <= len(output):
            result['issued_operation'] = head[4]
            result['issued_raw'] = list(struct.unpack_from('<' + 'Q' * nr, output, 128 + 8 * (nd + na)))
    return result


class FrameJournal:
    """Journal the real mapped entry, never replace its decision or result.

    Each before publication precedes that exact native invocation. The finally
    block attempts all three after buffers independently; any incomplete IO
    fails the group and retains what was observed, without retrying the entry.
    """
    def __init__(self, owner, directory):
        self.owner, self.directory = owner, Path(directory).absolute()
        self.directory.mkdir(mode=0o700)
        self.buffers = BufferStore(self.directory / 'buffers')
        self.frames = self.directory / 'frames'
        self.frames.mkdir(mode=0o700)
        self.original = owner._entry
        self.entry = self.invoke
        self.rows, self.started = [], 0
        self.tag = 'unassigned'
        self.closed = False
        owner._entry = self.entry

    def invoke(self, source, source_size, output, output_size, workspace, workspace_size):
        for length in (source_size, output_size, workspace_size):
            require(type(length) is int and 0 <= length <= CAPACITY, 'frame capacity differs')
        index = self.started
        self.started += 1
        pointers = ((source, source_size), (output, output_size), (workspace, workspace_size))
        before = [ctypes.string_at(pointer, length) for pointer, length in pointers]
        row = {'index': index, 'case': self.tag, 'image_sha256': self.owner.image_sha256,
               'returned': False, 'complete': False, **shape(before[1], before[2])}
        for name, raw in zip(('source', 'output', 'workspace'), before):
            row[name + '_before'] = self.buffers.put(raw)
        publish(self.frames / ('%08d-BEFORE.json' % index), row)
        try:
            result = self.original(source, source_size, output, output_size, workspace, workspace_size)
            row.update(returned=True, result=result)
            return result
        except BaseException:
            row['entry_traceback'] = traceback.format_exc()
            raise
        finally:
            errors = []
            for name, (pointer, length) in zip(('source', 'output', 'workspace'), pointers):
                try:
                    row[name + '_after'] = self.buffers.put(ctypes.string_at(pointer, length))
                except BaseException:
                    errors.append({'field': name + '_after', 'traceback': traceback.format_exc()})
            row['complete'] = all(key in row for key in FRAME_KEYS)
            row['source_unchanged'] = (row.get('source_before') == row.get('source_after'))
            if errors:
                row['observation_errors'] = errors
            self.rows.append(row)
            publish(self.frames / ('%08d-AFTER.json' % index), row)
            require(row['complete'] and not errors, 'native after-frame observation incomplete; no replay')

    def close(self):
        require(not self.closed, 'journal already closed')
        self.closed = True
        restored = self.owner._entry is self.entry
        if restored:
            self.owner._entry = self.original
        value = {'schema': 'hepta.hia.patch-result.full-native-frames.v1',
                 'image_sha256': self.owner.image_sha256,
                 'started_calls': self.started, 'complete_calls': len(self.rows),
                 'entry_restored': restored, 'frames': sorted(self.rows, key=lambda row: row['index']),
                 'all_complete': len(self.rows) == self.started and all(row['complete'] for row in self.rows),
                 'all_source_unchanged': all(row['source_unchanged'] for row in self.rows)}
        publish(self.directory / 'INDEX.json', value)
        require(restored and value['all_complete'] and value['all_source_unchanged'],
                'journal did not restore/observe its complete actual entry interval')
        return value


def observed_admission(owner_class, directory, admit, *args, **kwargs):
    """Observe actual table/delivery emission as well as later policy frames.

    The qualification-only wrapper calls the inherited initializer exactly
    once. It never constructs a substitute owner or supplies an HIA result.
    A cached dependency may perform zero new initializations; that fact is
    recorded explicitly, and the policy test still requires real entry calls.
    """
    from unittest.mock import patch
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700)
    original = owner_class._initialize_control
    original_code = original.__code__
    observations = []
    def initialize(owner):
        journal = FrameJournal(owner, directory / ('mapping-%03d' % len(observations)))
        journal.tag = 'actual-admission-emission'
        observations.append({'image_sha256': owner.image_sha256, 'status': 'FAIL'})
        row = observations[-1]
        try:
            result = original(owner)
            row['status'] = 'PASS'
            return result
        except BaseException:
            row['traceback'] = traceback.format_exc()
            raise
        finally:
            row['frames'] = journal.close()
    try:
        with patch.object(owner_class, '_initialize_control', initialize):
            return admit(*args, **kwargs)
    finally:
        require(owner_class._initialize_control is original and original.__code__ is original_code,
                'real initializer was not restored byte-for-byte')
        publish(directory / 'ADMISSION.json', {
            'schema': 'hepta.hia.patch-result.admission-observation.v1',
            'original_initializer_code_unchanged': True,
            'new_mappings': len(observations), 'observations': observations,
        })


def exception_value(error):
    seen = {}
    def visit(value):
        if value is None:
            return None
        if id(value) in seen:
            return {'cycle': seen[id(value)]}
        seen[id(value)] = len(seen)
        return {'type': type(value).__module__ + '.' + type(value).__qualname__,
                'text': str(value), 'name': getattr(value, 'name', None),
                'suppress_context': value.__suppress_context__,
                'cause': visit(value.__cause__), 'context': visit(value.__context__)}
    return visit(error)


def make_vm_catalog(journals, output, image_sha256):
    """Read each complete index once; selected rows retain exact authority pins."""
    rows, inputs = [], []
    for directory in journals:
        directory = Path(directory).absolute()
        raw = (directory / 'INDEX.json').read_bytes()
        index = json.loads(raw)
        require(index['schema'] == 'hepta.hia.patch-result.full-native-frames.v1'
                and index['image_sha256'] == image_sha256
                and index['all_complete'] is True and index['all_source_unchanged'] is True
                and index['entry_restored'] is True
                and index['started_calls'] == index['complete_calls'] == len(index['frames']),
                'complete same-image Native observation is required')
        index_pin = pin(raw)
        inputs.append({'path': str(directory / 'INDEX.json'), **index_pin})
        for row in index['frames']:
            after = directory / 'frames' / ('%08d-AFTER.json' % row['index'])
            after_raw = after.read_bytes()
            require(json.loads(after_raw) == row and row['returned'] is True
                    and row['complete'] is True and row['source_unchanged'] is True,
                    'actual Native row incomplete or index disagrees')
            rows.append({'journal': str(directory / 'INDEX.json'), 'journal_pin': index_pin,
                         'after': str(after), 'after_pin': pin(after_raw),
                         'buffers': str(directory / 'buffers'), 'frame': row})
    predicates = {
        'apply-start': lambda r: r['command'] == 0 and r['entry_mode'] == 2,
        'interface-start': lambda r: r['command'] == 0 and r['entry_mode'] == 1,
        'import-claim': lambda r: r['command'] == 2 and r['issued_operation'] == 19 and r['result'] == 4,
        'import-ack': lambda r: r['command'] == 1 and r['issued_operation'] == 19,
        'unpack4-claim': lambda r: r['command'] == 2 and r['issued_operation'] == 13
            and r['issued_raw'] == [4] and r['result'] == 4,
        'unpack4-ack': lambda r: r['command'] == 1 and r['issued_operation'] == 13 and r['issued_raw'] == [4],
        'generator-start': lambda r: r['command'] == 0 and r['entry_mode'] > 2,
        'normal-terminal': lambda r: r['command'] == 1 and r['result'] == 0,
        'exception-terminal': lambda r: r['command'] == 1 and r['result'] == 3,
        'retirement-start': lambda r: r['command'] == 4,
        'retirement-ack': lambda r: r['command'] == 1 and r['result'] == 5,
        'lost-claim': lambda r: r['case'] == 'lost-claim' and r['command'] == 2 and r['result'] == 4,
    }
    selected = {}
    for key in VM_KEYS:
        matches = [row for row in rows if predicates[key](row['frame'])]
        require(matches, 'required actual transition absent: ' + key)
        selected[key] = matches[0]
    result = {'schema': 'hepta.hia.patch-result.native-vm-catalog.v1',
              'selection_order': list(VM_KEYS), 'selected': selected,
              'inputs': inputs, 'image_sha256': image_sha256,
              'actual_native_frames': len(rows), 'selected_frames': len(selected),
              'max_steps': VM_STEPS, 'heap_bytes': VM_HEAP, 'call_depth': VM_CALL_DEPTH,
              'all_native_frames_replayed': False}
    publish(output, result)
    return result
