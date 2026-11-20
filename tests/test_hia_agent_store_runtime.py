"""Exercise the cold-built Agent Store's direct native argv and streaming ABI."""

import argparse
import fcntl
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def command(request, kind, target=0, body=b''):
    return struct.pack('<8s5Q', b'HIATCM01', 1, request, kind, target, len(body)) + body


def text_bindings(magic, values, *, insert_table=None):
    header_size = 32 if insert_table is None else 40
    offset = header_size + 24 * len(values)
    cells, contents = [], []
    for value in values:
        data = b'' if value is None else value.encode('utf-8')
        cells.append(struct.pack('<3Q', 0 if value is None else 3, offset, len(data)))
        contents.append(data)
        offset += len(data)
    if insert_table is None:
        header = struct.pack('<8s3Q', magic, 1, len(values), offset)
    else:
        header = struct.pack('<8s4Q', magic, 1, insert_table, 0, len(values))
    return header + b''.join(cells + contents)


class NativeStoreArgv(unittest.TestCase):
    test_root = None
    batch = None
    cost_sequence = None

    def run_native(self, arguments, data=b'', expected=0):
        result = subprocess.run(arguments, input=data, capture_output=True, env={'PATH': ''},
                                timeout=3, check=False)
        self.assertEqual(result.returncode, expected, result)
        self.assertEqual(result.stderr, b'')
        if expected:
            self.assertEqual(result.stdout, b'')
        return result.stdout

    def replies(self, output, kinds):
        at, acks, rows, receipts = 0, [], [], 0
        current = None
        while at < len(output):
            magic = output[at:at + 8]
            if magic == b'HIATXR01':
                _, version, request, kind, status, *_ = struct.unpack_from('<8s9Q', output, at)
                self.assertEqual((version, request, status), (1, len(acks), 0))
                acks.append(kind)
                at += 80
            elif magic == b'HIAWTA01':
                receipts += 1
                at += 256
            else:
                self.assertEqual(magic, b'HIAQRF01')
                _, kind, table, rowid, offset, size, _, reserved = struct.unpack_from(
                    '<8s7Q', output, at)
                body = output[at + 64:at + 64 + size]
                self.assertEqual((reserved, len(body)), (0, size))
                if kind == 1:
                    self.assertIsNone(current)
                    self.assertEqual((table, rowid, size, body[:8]), (4, 1, 128, b'HIAIXLF1'))
                    current = bytearray()
                elif kind == 2:
                    self.assertEqual((table, rowid, offset), (4, 1, len(current)))
                    current.extend(body)
                elif kind == 3:
                    self.assertEqual((table, rowid, offset), (4, 1, len(current)))
                    self.assertEqual(current[:8], b'HIAROW01')
                    columns, = struct.unpack_from('<Q', current, 24)
                    values = []
                    for i in range(columns):
                        tag, start, width = struct.unpack_from('<3Q', current, 32 + i * 24)
                        self.assertIn(tag, (0, 3))
                        values.append(None if tag == 0 else current[start:start + width].decode('utf-8'))
                    rows.append(tuple(values))
                    current = None
                else:
                    self.assertEqual((kind, size), (4, 416))
                    self.assertIsNone(current)
                    self.assertEqual(struct.unpack_from('<Q', body, 384)[0], 9)
                at += 64 + size
        self.assertEqual(at, len(output))
        self.assertIsNone(current)
        self.assertEqual(acks, [0, *kinds])
        return rows, receipts

    def test_initializer_refuses_existing_names_without_creating_a_stage(self):
        if self.test_root is None:
            self.skipTest('run with the cold-built native Agent Store paths')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            root = Path(temporary)
            self.assertEqual(self.run_native([self.initializer, root, 'store'])[:8], b'HIAWNA01')
            store = self.state(root)
            (root / 'file').write_bytes(b'retained')
            (root / 'empty').mkdir()
            (root / 'link').symlink_to('store')
            (root / 'dangling').symlink_to('missing')
            names = {'store', 'file', 'empty', 'link', 'dangling'}
            for name in sorted(names):
                with self.subTest(name=name):
                    self.run_native([self.initializer, root, name], expected=76)
                    self.assertEqual({entry.name for entry in root.iterdir()}, names)
            self.assertEqual(self.state(root), store)
            self.assertEqual((root / 'file').read_bytes(), b'retained')
            self.assertEqual(list((root / 'empty').iterdir()), [])
            self.assertEqual((root / 'link').readlink(), Path('store'))
            self.assertEqual((root / 'dangling').readlink(), Path('missing'))

    def test_direct_native_cli(self):
        if self.test_root is None:
            self.skipTest('run with the cold-built native Agent Store paths')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            self.run_native([self.initializer, parent, 'store'])
            args = [self.executable, parent, 'store', self.module_root]
            initial = self.state(parent)
            values = ('test-request', 'a' * 64, 'hia_artifact', 'running', None, '1234')
            entry = text_bindings(b'HIAINS01', values, insert_table=6)
            lookup = text_bindings(b'HIAQPA01', values[:1])
            insert = command(1, 27, 1, entry)
            select = command(2, 27, 12, lookup)
            rollback = command(3, 3)
            commit = command(3, 2)

            self.assertEqual(self.replies(self.run_native(args, insert + select + rollback), (27, 27, 3)),
                             ([values], 0))
            self.assertEqual(self.state(parent), initial)
            self.assertEqual(self.replies(self.run_native(args, command(1, 27, 12, lookup) + command(2, 3)),
                                          (27, 3)), ([], 0))
            self.assertEqual(self.replies(self.run_native(args, insert + select + commit), (27, 27, 2)),
                             ([values], 1))
            self.assertEqual(self.replies(self.run_native(args, command(1, 27, 12, lookup) + command(2, 3)),
                                          (27, 3)), ([values], 0))

            link = parent / 'module-link'
            link.symlink_to(self.module_root, target_is_directory=True)
            self.run_native([*args[:3], link], expected=74)
            self.run_native([*args[:2], '../store', self.module_root], expected=73)
            self.run_native([*args[:2], '', self.module_root], expected=73)
            self.run_native(args[:3], expected=64)

            wal = parent / 'store' / 'wal.data'
            valid = wal.read_bytes()
            reopen = command(1, 27, 12, lookup) + command(2, 3)
            for offset in (0, 96 + 64 + 32 + 32, len(valid) - 1):
                with self.subTest(corrupt_offset=offset):
                    corrupted = bytearray(valid)
                    corrupted[offset] ^= 1
                    wal.write_bytes(corrupted)
                    before = self.state(parent)
                    self.run_native(args, reopen, expected=73)
                    self.assertEqual(self.state(parent), before)

    def test_direct_migration_batch(self):
        if self.batch is None:
            self.skipTest('run with the cold-built native Agent batch commit path')
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            parent = Path(temporary)
            self.run_native([self.initializer, parent, 'store'])
            store = parent / 'store'
            initial = self.state(parent)
            values = ('migrated-request', 'b' * 64, 'hia_artifact', 'running', None, '4321')
            cells = text_bindings(b'HIAROW01', values)[32:]
            row = struct.pack('<8s3Q', b'HIAROW01', 1, 4, len(values)) + cells
            proposal = (struct.pack('<8s3Q', b'HIATXB01', 1, 1, 1)
                        + struct.pack('<Qq2Q', 4, 1, 64, len(row)) + row)
            data = struct.pack('<Q', len(proposal)) + proposal
            args = [self.batch, store]

            for malformed in (data[:-1], data + b'\0', struct.pack('<Q', 1000000033)):
                self.run_native(args, malformed, expected=64)
            link = parent / 'linked-store'
            link.symlink_to(store, target_is_directory=True)
            self.run_native([self.batch, link], data, expected=74)
            self.run_native([self.batch, str(link) + '/'], data, expected=64)
            self.assertEqual(self.state(parent), initial)

            with (store / 'wal.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.run_native(args, data, expected=75)
            self.assertEqual(self.state(parent), initial)

            receipt = self.run_native(args, data)
            self.assertEqual((len(receipt), receipt[:8]), (256, b'HIAWTA01'))
            self.assertEqual(receipt[-128:], (store / 'anchor.0000000000000001').read_bytes())
            committed = self.state(parent)
            self.refused_batch(args, data)
            self.assertEqual(self.state(parent), committed)

            lookup = text_bindings(b'HIAQPA01', values[:1])
            query = command(1, 27, 12, lookup) + command(2, 3)
            reopened = self.run_native([self.executable, parent, 'store', self.module_root], query)
            self.assertEqual(self.replies(reopened, (27, 3)), ([values], 0))
            if self.cost_sequence is not None:
                self.check_cost_sequence(parent, args)

    def check_cost_sequence(self, parent, batch_args):
        high_water = 128
        sequence = (struct.pack('<8s3Q', b'HIASQH01', 1, 2, 0)
                    + bytes((3, 23, 2)) + b'costs' + high_water.to_bytes(2, 'big'))
        frame = struct.pack('<8s3Q', b'HIASCC01', len(sequence), 656, 4096) + sequence
        response = self.run_native([self.cost_sequence], frame)
        self.assertEqual(struct.unpack_from('<8s3Q', response), (b'HIASCR01', 0, 656, 4096))
        sealed = response[32:32 + 656]
        self.assertEqual(sealed[:8], b'HIAWAL01')
        data = struct.pack('<Q', len(sealed)) + sealed
        store = parent / 'store'
        before = self.state(parent)
        for generation in ('000000000000000', '000000000000000A', '../wal.data'):
            self.run_native([*batch_args, generation], data, expected=64)
        self.assertEqual(self.state(parent), before)

        args = [*batch_args, '0000000000000001']
        receipt = self.run_native(args, data)
        updated = self.state(parent)
        self.assertEqual(receipt[-128:], updated['anchor.0000000000000002'])
        self.assertEqual(updated['wal.data'], before['wal.data'] + sealed)
        self.refused_batch(args, data)
        self.assertEqual(self.state(parent), updated)

        values = (None, 'hia_artifact', 'first-cost-after-migration', '1', 'completed', '{}')
        insert = command(1, 27, 1, text_bindings(b'HIAINS01', values, insert_table=2))
        native = self.run_native([self.executable, parent, 'store', self.module_root], insert + command(2, 2))
        self.assertEqual(self.replies(native, (27, 2)), ([], 1))
        new_transaction = (store / 'wal.data').read_bytes()[len(updated['wal.data']):]
        _, begin_size = struct.unpack_from('<8sQ', new_transaction)
        magic, _, _, kind, table, key_size = struct.unpack_from('<8s5Q', new_transaction, begin_size)
        self.assertEqual((magic, kind, table, key_size), (b'HIAWAL01', 2, 5, 32))
        self.assertEqual(struct.unpack_from('<8s2Qq', new_transaction, begin_size + 64),
                         (b'HIARID01', 1, 5, high_water + 1))

    def refused_batch(self, args, data):
        result = subprocess.run(args, input=data, capture_output=True, env={'PATH': ''},
                                timeout=3, check=False)
        self.assertIn(result.returncode, (73, 74), result)
        self.assertEqual((result.stdout, result.stderr), (b'', b''))

    @staticmethod
    def state(parent):
        return {file.name: file.read_bytes() for file in (parent / 'store').iterdir()}


class InstalledAgentStore(NativeStoreArgv):
    def setUp(self):
        if self.test_root is None or self.module_root != self.executable.parent:
            self.skipTest('run with the installed native Store release')

    def test_typed_records_never_dispatch_sql_operations(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_agent_store_native import NativeStoreConnection

        selection = self.selection()
        key, digest = 'a' * 64, 'b' * 64
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary, \
                patch.object(NativeStoreConnection, '_execute',
                             side_effect=AssertionError('typed operation entered SQL compatibility')):
            path = Path(temporary)
            self.run_native([self.initializer, path, 'store'])
            store = AgentStore(path, native_store=selection)
            try:
                self.assertIsNone(store.journal_lookup(key))
                with store.transaction():
                    store.journal_reserve(key, digest, 'hia_artifact', '1')
                    self.assertEqual(store.journal_lookup(key)['state'], 'running')
                before = self.state(path)
                with self.assertRaisesRegex(ValueError, 'rollback probe'), store.transaction():
                    store.journal_complete(key, '{}')
                    store.journal_cost(None, 'hia_artifact', 'r-' + digest, '2', 'completed', '{}')
                    raise ValueError('rollback probe')
                self.assertEqual(self.state(path), before)
                with store.transaction():
                    store.journal_complete(key, '{"status":"completed"}')
                    store.journal_cost(None, 'hia_artifact', 'r-' + digest, '3', 'completed', '{}')
                ref = store.put(b'opaque', 'input')
                self.assertEqual(store.put(b'opaque', 'input'), ref)
                self.assertEqual(store.resolve_uri(ref['uri']), ref)
                profile, _ = store.profile('test-profile', {'test': True})
                store.cursor_retain('cursor', ref['id'], ref['sha256'], 2)
            finally:
                store.close()
            committed = self.state(path)
            reopened = AgentStore(path, native_store=selection)
            try:
                row = reopened.journal_lookup(key)
                self.assertEqual((row['digest'], row['state'], row['response']),
                                 (digest, 'completed', '{"status":"completed"}'))
                costs = reopened.context_costs(None)
                self.assertEqual([(row['request_id'], row['wall_ns']) for row in costs], [('r-' + digest, '3')])
                self.assertEqual(reopened.get(ref), (b'opaque', {}))
                self.assertEqual(reopened.check_profile(profile, profile), {'test': True})
                self.assertEqual(tuple(reopened.cursor_lookup('cursor')),
                                 ('cursor', ref['id'], ref['sha256'], 2))
            finally:
                reopened.close()
            self.assertEqual(self.state(path), committed)

    def test_public_tools_with_no_sqlite_connection(self):
        guard = """
import importlib.abc
import subprocess
import sys
from unittest.mock import patch

class NoSQLite(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'sqlite3', '_sqlite3'}:
            raise AssertionError('selected native Agent imported SQLite: ' + fullname)

assert not {'sqlite3', '_sqlite3'} & set(sys.modules)
sys.meta_path.insert(0, NoSQLite())
source, temporary, initializer, *selection = sys.argv[1:]
sys.path.insert(0, source)
from hepta import hia_service_artifact_native, hia_service_read_native
from hepta.hia_agent_service import HIAAgentService
from tests.test_hia_agent_native_tools import ArtifactContractTests, NativeLifecycleTests

def construct(path, **kwargs):
    path.mkdir(mode=0o700)
    subprocess.run([initializer, path, 'store'], input=b'', capture_output=True,
                   check=True, timeout=3, env={'PATH': ''})
    return HIAAgentService(path, native_store=selection, **kwargs)

with patch('tempfile.tempdir', temporary), \\
     patch('hepta.hia_agent_store.stable_read', side_effect=AssertionError('hosted artifact read')), \\
     patch('tests.test_hia_agent_native_tools.HIAAgentService', construct):
    case = NativeLifecycleTests('test_all_eleven_tools_and_full_u8_native_workload')
    case.setUp()
    try:
        case.test_all_eleven_tools_and_full_u8_native_workload()
        assert not (case.state_root / 'state.sqlite3').exists()
    finally:
        case.tearDown()
    with patch('hepta.hia_agent_store.capture_path', side_effect=AssertionError('hosted artifact capture')):
        case = ArtifactContractTests('test_file_capture_enforces_roots_regular_identity_and_expected_hash')
        case.debug()
assert not {'sqlite3', '_sqlite3'} & set(sys.modules)
"""
        source = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, '-I', '-B', '-c', guard, source,
                                 self.test_root, self.initializer, *self.selection()],
                                input=b'', capture_output=True, timeout=90, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_public_worker_reopens_native_state_with_exact_replay(self):
        from hepta.hia_agent_contract import installation_manifest
        from hepta.hia_agent_store import AgentRejected, AgentStore, wire
        from hepta.hia_agent_worker import main as worker

        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            path = Path(temporary)
            self.run_native([self.initializer, path, 'store'])
            release, executable_sha256, artifact_sha256, capture_sha256 = self.selection()
            pins = installation_manifest()

            def envelope(tool, arguments):
                request = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
                           'arguments': arguments, 'profile_sha256': 'a' * 64,
                           'catalog_sha256': pins['catalog_sha256']}
                request['request_sha256'] = sha256(wire(request)).hexdigest()
                return request

            describe = envelope('hia_describe', {'section': 'manifest'})
            files = path / 'inputs'
            files.mkdir(mode=0o700)
            source = files / 'content'
            source.write_bytes(b'captured via the installed native executable')
            source_digest = sha256(source.read_bytes()).hexdigest()
            args = ['--state-root', str(path), '--request-json-stdin',
                    '--artifact-root', str(files), '--native-store-release', str(release),
                    '--expected-native-store-sha256', executable_sha256,
                    '--expected-native-artifact-sha256', artifact_sha256,
                    '--expected-native-capture-sha256', capture_sha256]

            def invoke(flags, envelope):
                output, errors = io.BytesIO(), io.StringIO()
                with patch('sys.stdin', SimpleNamespace(buffer=io.BytesIO(wire(envelope)))), \
                        patch('sys.stdout', SimpleNamespace(buffer=output)), patch('sys.stderr', errors):
                    self.assertEqual(worker(flags), 0, errors.getvalue())
                return json.loads(output.getvalue())

            snapshot = self.state(path)
            with patch.object(sqlite3, 'connect', side_effect=AssertionError('SQLite engine was opened')), \
                    patch('hepta.hia_agent_store.stable_read', side_effect=AssertionError('hosted artifact read')):
                refused = invoke([*args[:-1], '0' * 64], describe)
                self.assertEqual(refused['response']['status'], 'rejected')
                self.assertEqual(self.state(path), snapshot)
                with self.assertRaisesRegex(AgentRejected, 'native Store'):
                    AgentStore(path)
                self.assertFalse((path / 'state.sqlite3').exists())

                discovery = invoke(args, describe)['response']
                self.assertEqual(discovery['status'], 'completed', discovery)
                upload = {'catalog_sha256': pins['catalog_sha256'], 'request_key': 'durable-capture',
                          'artifact_profile': discovery['result']['artifact_profiles'][0],
                          'source': {'kind': 'path', 'path': str(source),
                                     'expected_sha256': source_digest, 'max_bytes': 4096}}
                request = envelope('hia_artifact', upload)
                first = invoke(args, request)
                self.assertEqual(first['response']['status'], 'completed', first)
                self.assertEqual(first['response']['result']['artifact']['sha256'], source_digest)
                self.assertEqual((path / 'artifacts' / source_digest).read_bytes(), source.read_bytes())
                source.write_bytes(b'source changed after commit')
                committed = self.state(path)
                self.assertNotEqual(committed, snapshot)
                self.assertEqual(invoke(args, request), first)
                # Replaying a known key has no durable effect.
                self.assertEqual(self.state(path), committed)
                self.assertFalse((path / 'state.sqlite3').exists())

    def test_public_worker_accepts_store_via_existing_helper_profile(self):
        from hepta.hia_agent_store import wire
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        from tools.bind_hia_worker_store import bind_worker_store

        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            path = Path(temporary)
            helper = self.worker_request_manifest
            base = path / 'helpers.json'
            base.write_bytes(wire({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
                'helpers': [{'selector': 'HEPTA_HIA_WORKER_REQUEST_MANIFEST',
                             'manifest_path': str(helper),
                             'manifest_sha256': sha256(helper.read_bytes()).hexdigest()}]}))
            base.chmod(0o600)
            profile = path / 'worker-store.json'
            pin = bind_worker_store(profile, base, self.module_root)
            worker = [sys.executable, '-B', '-E', '-s', '-m', 'hepta.hia_agent_worker']

            def invoke(flags, *, manifest=profile, profile_pin=pin, data=b''):
                return subprocess.run([*worker, *flags, '--native-helpers-manifest', str(manifest),
                                       '--expected-native-helpers-sha256', profile_pin],
                                      input=data, capture_output=True, timeout=15, check=False)

            manifest = invoke(['--installation-manifest'])
            self.assertEqual((manifest.returncode, manifest.stderr), (0, b''))
            pins = json.loads(manifest.stdout)
            self.assertEqual(pins['native_helpers_sha256'], pin)

            state, files = path / 'state', path / 'input'
            state.mkdir(mode=0o700)
            files.mkdir(mode=0o700)
            self.run_native([self.initializer, state, 'store'])
            before = self.state(state)
            source = files / 'artifact'
            source.write_bytes(b'original captured content')
            digest = sha256(source.read_bytes()).hexdigest()
            flags = ['--state-root', str(state), '--request-json-stdin', '--artifact-root', str(files)]
            for role in ('worker', 'backend', 'catalog'):
                flags.extend(('--expected-' + role + '-sha256', pins[role + '_sha256']))

            def request(tool, arguments):
                body = {'schema': 'hia-agent-worker-request-v1', 'tool': tool, 'arguments': arguments,
                        'profile_sha256': 'a' * 64, 'catalog_sha256': pins['catalog_sha256']}
                return wire({**body, 'request_sha256': sha256(wire(body)).hexdigest()})

            discover = request('hia_describe', {'section': 'manifest'})
            malformed = path / 'bad-store.json'
            for field in ('base_bundle_sha256', 'store_sha256', 'artifact_sha256', 'capture_sha256'):
                record = {**json.loads(profile.read_bytes()), field: '0' * 64}
                malformed.write_bytes(wire(record))
                malformed.chmod(0o600)
                bad_pin = sha256(malformed.read_bytes()).hexdigest()
                result = invoke(flags, manifest=malformed, profile_pin=bad_pin, data=discover)
                self.assertEqual((result.returncode, result.stdout), (2, b''), result.stderr)
                self.assertEqual(self.state(state), before)
            result = invoke(flags, profile_pin='0' * 64, data=discover)
            self.assertEqual((result.returncode, result.stdout), (2, b''))

            release, store_pin, artifact_pin, capture_pin = self.selection()
            override = ['--native-store-release', str(release), '--expected-native-store-sha256', store_pin,
                        '--expected-native-artifact-sha256', artifact_pin,
                        '--expected-native-capture-sha256', capture_pin]
            result = invoke([*flags, *override], data=discover)
            self.assertEqual((result.returncode, result.stdout), (2, b''))
            self.assertIn(b'only once', result.stderr)
            self.assertEqual(self.state(state), before)

            result = invoke(flags, data=discover)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            reply = json.loads(result.stdout)
            self.assertEqual(reply['native_helpers_sha256'], pin)
            description = reply['response']
            self.assertEqual(description['status'], 'completed')
            upload = request('hia_artifact', {'catalog_sha256': pins['catalog_sha256'],
                'request_key': 'profile-capture', 'artifact_profile': description['result']['artifact_profiles'][0],
                'source': {'kind': 'path', 'path': str(source), 'expected_sha256': digest, 'max_bytes': 4096}})
            result = invoke(flags, data=upload)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            reply = json.loads(result.stdout)
            self.assertEqual(reply['response']['status'], 'completed', reply)
            self.assertEqual(reply['response']['result']['artifact']['sha256'], digest)
            self.assertEqual((state / 'artifacts' / digest).read_bytes(), source.read_bytes())
            source.write_bytes(b'changed on disk')
            committed = self.state(state)
            self.assertNotEqual(committed, before)
            replay = invoke(flags, data=upload)
            self.assertEqual((replay.returncode, replay.stdout, replay.stderr), (0, result.stdout, b''))
            self.assertEqual(self.state(state), committed)
            self.assertFalse((state / 'state.sqlite3').exists())

    def test_fresh_initialization_is_serialized_and_never_replaces_prior_data(self):
        from concurrent.futures import ThreadPoolExecutor

        from hepta.hia_agent_store import AgentRejected, AgentStore
        from hepta.hia_agent_store_native import StoreProtocolError

        selection = self.selection()
        initializer = self.initializer.read_bytes()

        def open_store(root, native):
            store = AgentStore(root, native_store=selection if native else None)
            store.close()

        with (tempfile.TemporaryDirectory(dir=self.test_root) as temporary,
              patch('hepta.hia_native_helpers.pinned_store_initializer', return_value=initializer)):
            parent = Path(temporary)
            fresh = parent / 'new'
            with (patch('sqlite3.connect', side_effect=AssertionError('native Store selected SQLite')),
                  ThreadPoolExecutor(max_workers=4) as pool):
                opened = [pool.submit(open_store, fresh, True) for _ in range(4)]
                for result in opened:
                    result.result()
            first = self.state(fresh)
            self.assertEqual({entry.name for entry in fresh.iterdir()}, {'artifacts', 'store'})
            open_store(fresh, True)
            self.assertEqual(self.state(fresh), first)
            with self.assertRaisesRegex(AgentRejected, 'belongs to the explicitly selected native Store'):
                open_store(fresh, False)

            legacy = parent / 'legacy'
            open_store(legacy, False)
            database = legacy / 'state.sqlite3'
            original = database.read_bytes()
            with self.assertRaisesRegex(AgentRejected, 'separate staged state root'):
                open_store(legacy, True)
            self.assertEqual(database.read_bytes(), original)
            self.assertFalse((legacy / 'store').exists())

            retained = parent / 'retained'
            artifacts = retained / 'artifacts'
            artifacts.mkdir(parents=True)
            (artifacts / 'retained').write_bytes(b'untouched')
            with self.assertRaisesRegex(StoreProtocolError, 'retained artifacts'):
                open_store(retained, True)
            self.assertEqual((artifacts / 'retained').read_bytes(), b'untouched')
            self.assertFalse((retained / 'store').exists())

    def test_connection_cannot_move_to_replacement_namespace(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_agent_store_native import StoreProtocolError

        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            path = Path(temporary)
            self.run_native([self.initializer, path, 'store'])
            store = AgentStore(path, native_store=self.selection())
            try:
                contents = self.state(path)
                (path / 'store').rename(path / 'original')
                self.run_native([self.initializer, path, 'store'])
                replacement = self.state(path)
                self.assertNotEqual(replacement['namespace.bin'], contents['namespace.bin'])
                with self.assertRaisesRegex(StoreProtocolError, 'namespace identity changed'):
                    store.db.execute("INSERT INTO contexts VALUES (?,?,?,?,0)",
                                     ('replacement', 'sha', 'artifact', '0'))
                self.assertEqual(self.state(path), replacement)
                self.assertEqual({entry.name: entry.read_bytes() for entry in (path / 'original').iterdir()},
                                 contents)
            finally:
                store.close()

    def selection(self):
        images = (self.executable, self.module_root / 'hia-artifact',
                  self.module_root / 'hia-agent-artifact-capture')
        return self.module_root, *(sha256(path.read_bytes()).hexdigest() for path in images)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('executable', 'module-root', 'initializer', 'test-root'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--batch', type=Path)
    parser.add_argument('--cost-sequence', type=Path)
    parser.add_argument('--worker-request-manifest', type=Path)
    for key, value in vars(parser.parse_args()).items():
        setattr(NativeStoreArgv, key, value.resolve() if value is not None else None)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeStoreArgv)
    if NativeStoreArgv.module_root == NativeStoreArgv.executable.parent:
        suite.addTests(InstalledAgentStore(name) for name in (
            'test_typed_records_never_dispatch_sql_operations',
            'test_public_tools_with_no_sqlite_connection',
            'test_public_worker_reopens_native_state_with_exact_replay',
            'test_fresh_initialization_is_serialized_and_never_replaces_prior_data',
            'test_connection_cannot_move_to_replacement_namespace',
        ))
        if NativeStoreArgv.worker_request_manifest is not None:
            suite.addTest(InstalledAgentStore('test_public_worker_accepts_store_via_existing_helper_profile'))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
