"""Current Store bodies, real native continuation and installed public routing."""
from __future__ import annotations

import ast
import builtins
import ctypes
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_agent_store as api
from hepta import hia_store_lifecycle_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_store_lifecycle_fixtures import Fixture, FIXTURE, frozen
from tools import generate_hia_store_lifecycle as generator

ROOT = Path(__file__).resolve().parents[1]
BRANCHES = (
    {}, {'budget': True}, {'database_exists': True}, {'symlink': 'root'},
    {'wrong_uid': 'root'}, {'writable': 'root'}, {'symlink': 'root/artifacts'},
    {'non_directory': True}, {'wrong_uid': 'root/artifacts'}, {'writable': 'root/artifacts'},
    {'database_exists': True, 'database_not_regular': True},
    {'database_exists': True, 'wrong_uid': 'root/state.sqlite3'},
    {'database_exists': True, 'writable': 'root/state.sqlite3'},
    {'after_connect_not_regular': True}, {'budget': True, 'sidecar_not_regular': True},
    {'budget': True, 'wrong_uid': 'root/state.sqlite3-wal'},
    {'budget': True, 'writable': 'root/state.sqlite3-wal'},
    {'budget': True, 'writable': 'root/state.sqlite3-shm'},
)


class StoreLifecycleSourceTests(unittest.TestCase):
    def test_source_and_current_original_bodies_are_exact(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        program = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in program['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in program['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in program['functions'] for block in fn['blocks']), 16)
        original = ast.parse(FIXTURE.read_text()).body[0]
        actual = next(node for node in ast.parse((ROOT / 'hepta/hia_agent_store.py').read_text()).body
                      if isinstance(node, ast.ClassDef) and node.name == 'AgentStore')
        for old_name, new_name in (('__init__', '_initialize_reference'), ('close', '_close_reference')):
            old = next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == old_name)
            new = next(node for node in actual.body if isinstance(node, ast.FunctionDef) and node.name == new_name)
            new.name = old_name
            self.assertEqual(ast.dump(new), ast.dump(old))
        frozen()

    def test_absent_selector_retains_bodies_without_optional_native_import(self):
        actual_import = builtins.__import__
        def guarded(name, *arguments, **keywords):
            if name.endswith('hia_store_lifecycle_native'):
                raise AssertionError('unselected Store imported optional native owner')
            return actual_import(name, *arguments, **keywords)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                store = api.AgentStore(directory)
                store.close()


class StoreLifecycleNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_lifecycle import build
        evidence = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_EVIDENCE')
        cls.temporary = None
        if evidence is not None:
            if not evidence:
                raise ValueError('store-lifecycle evidence selector must not be empty')
            cls.root = Path(evidence)
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-store-lifecycle-')
            cls.root = Path(cls.temporary.name)
        cold = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_DEVELOPMENT_COMPILER')
        if cold is not None and development is not None:
            raise ValueError('choose matching cold custody or explicit development compiler')
        if cold is not None:
            if not cold:
                raise ValueError('store-lifecycle cold selector must not be empty')
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        elif development is not None:
            if not development:
                raise ValueError('store-lifecycle development compiler selector must not be empty')
            compiler = Path(development)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
        cls.cold_report, cls.compiler = cold, compiler
        cls.compiler_bytes = compiler.read_bytes()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_store_lifecycle(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        same = cls.compiler.read_bytes() == cls.compiler_bytes
        (cls.root / 'component-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.store-lifecycle-test-custody.v1',
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'compiler_unchanged': same, 'manifest': str(cls.manifest),
            'matching_cold_report': cls.cold_report,
            'test_result_owned_by_outer_runner': True,
        }, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not same:
            raise AssertionError('native lifecycle compiler bytes changed')

    def compare(self, options):
        original = Fixture(**options)
        baseline = frozen(original.namespace)
        expected, old_error = original.observe(lambda: baseline.__init__(original.store, 'root'))
        selected = Fixture(**options)
        actual, error = selected.observe(lambda: native.LifecycleFrame(
            self.image, 1, selected.store, 'root', namespace=selected.namespace).finish())
        self.assertEqual(actual, expected, options)
        for fixture, raised in ((original, old_error), (selected, error)):
            if raised is not None and str(raised) == 'primary':
                self.assertIs(raised, fixture.primary)
            if raised is not None and str(raised) == 'note':
                self.assertIs(raised, fixture.note_error)
        return len(expected['trace'])

    def test_complete_original_branches_and_each_foreign_failure(self):
        for options in BRANCHES:
            with self.subTest(options=options):
                self.compare(options)
        # Returning from a replacement reject port must retain the original
        # continuation; rejection policy is not silently assumed by Python.
        for options in BRANCHES[3:]:
            self.compare(dict(options, reject_returns=True))
        cases = 0
        for budget in (False, True):
            count = self.compare({'budget': budget, 'database_exists': True})
            for point in range(1, count + 1):
                for cleanup, note in ((False, False), (True, False), (True, True)):
                    with self.subTest(budget=budget, point=point, cleanup=cleanup, note=note):
                        self.compare(dict(budget=budget, database_exists=True, fail_at=point,
                                          cleanup_fails=cleanup, note_fails=note))
                    cases += 1
        self.assertEqual(cases, 420)
        (self.root / 'original-effects.json').write_text(json.dumps({
            'ordinary_branches': len(BRANCHES), 'returning_reject_branches': len(BRANCHES) - 3,
            'fault_combinations': cases, 'exact_effect_order_and_active_exception': True,
            'original_exception_identity_preserved': True,
            'connect_following_chmod_pragma_schema_failures_close_database': True,
        }, indent=2, sort_keys=True) + '\n')

    def test_close_stops_on_first_failure_and_keeps_exact_active_exception(self):
        for fail_at in (None, 1, 2, 3, 4):
            results = []
            for selected in (False, True):
                fixture = Fixture(fail_at=fail_at)
                object.__setattr__(fixture.store, 'db', fixture.db)
                object.__setattr__(fixture.store, 'execution_budgets', fixture.budget_owner)
                body = (lambda: native.LifecycleFrame(self.image, 2, fixture.store,
                        namespace=fixture.namespace).finish()) if selected else (
                        lambda: frozen(fixture.namespace).close(fixture.store))
                observed, error = fixture.observe(body)
                if error is not None:
                    self.assertIs(error, fixture.primary)
                results.append(observed)
            self.assertEqual(*results)

    def test_public_routes_are_pinned_to_store_lifetime_without_reference(self):
        from hepta.hia_store_lifecycle_selection import store_lifecycle_owner
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            ordinary = api.AgentStore(Path(directory) / 'ordinary')
            self.assertIsNone(store_lifecycle_owner(ordinary))
            os.environ[native.SELECTOR] = str(self.manifest)
            with (patch.object(api, '_NATIVE_STORE_INITIALIZE_REFERENCE', side_effect=AssertionError('host init')),
                    patch.object(api, '_NATIVE_STORE_CLOSE_REFERENCE', side_effect=AssertionError('host close'))):
                selected = api.AgentStore(Path(directory) / 'selected')
                self.assertIs(store_lifecycle_owner(selected).image, self.image)
                self.assertEqual(selected.db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
                os.environ[native.SELECTOR] = '/invalid-new-selector'
                selected.close()
            with patch.object(native, 'installed_store_lifecycle', side_effect=AssertionError('close reselected image')):
                ordinary.close()

    def test_empty_invalid_selection_is_refused_before_directory_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'must-not-exist'
            for selector in ('', '/no-such-lifecycle-manifest'):
                with patch.dict(os.environ, {native.SELECTOR: selector}), \
                        patch.object(api, '_NATIVE_STORE_INITIALIZE_REFERENCE', side_effect=AssertionError('fallback')):
                    with self.assertRaises((OSError, ValueError)):
                        api.AgentStore(root)
                self.assertFalse(root.exists())

    def invoke(self, raw, state):
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(b'\xa5' * (native.OUTPUT_BYTES + 16), native.OUTPUT_BYTES + 16)
        code = self.image._entry(source, len(raw), output, native.OUTPUT_BYTES, state, native.STATE_BYTES)
        self.assertEqual(source.raw, raw or b'\0')
        self.assertEqual(output.raw[native.OUTPUT_BYTES:], b'\xa5' * 16)
        return code, output.raw[:native.OUTPUT_BYTES]

    def test_full_native_protocol_matches_independent_core_vm(self):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        # No image feedback chooses the next request: these paths are fixed
        # from the frozen ordinary bodies, including both nested handlers.
        paths = [
            (1, list(range(1, 19)) + list(range(23, 36)) + [44], {}),
            (2, [70, 71], {}),
            (1, list(range(1, 19)) + [23, 24, 80, 81], {24, 80}),
        ]
        calls = 0
        for mode, ports, failed in paths:
            machine_state = _Owner(3, bytearray(native.STATE_BYTES))
            actual_state = ctypes.create_string_buffer(native.STATE_BYTES)
            sequence, port = 0, 0
            def compare(event, observation=0):
                nonlocal sequence, port, calls
                raw = struct.pack('<10Q', native.REQUEST_MAGIC, event, sequence, port,
                                  observation, mode, 17, 23, 0, 0)
                owners = [_Owner(1, bytearray(raw)), _Owner(2, bytearray(b'\xa5' * native.OUTPUT_BYTES)), machine_state]
                machine = _Machine(self.program, 2_000_000, 16 << 20, None, 128)
                code = machine.invoke(machine.functions['f0'], [_View(value, i != 0)
                    for i, value in enumerate(owners)])[0]
                actual = self.invoke(raw, actual_state)
                self.assertEqual(actual, (code, bytes(owners[1].data)))
                self.assertEqual(actual_state.raw, bytes(machine_state.data))
                self.assertEqual(bytes(owners[0].data), raw)
                words = struct.unpack('<10Q', actual[1])
                port, sequence = words[2:4]
                calls += 1
                return words
            compare(0)
            for expected in ports:
                self.assertEqual(port, expected)
                compare(1)
                words = compare(3 if expected in failed else 2, int(expected in (13, 27)))
            if words[4] == 3:
                words = compare(4)
            self.assertEqual(words[4], 5 if failed else 4)
        self.assertGreater(calls, 100)

    def test_lost_native_claim_and_ack_never_repeat_foreign_effect(self):
        for lost_event in (1, 2):
            fixture = Fixture()
            frame = native.LifecycleFrame(self.image, 1, fixture.store, 'root', namespace=fixture.namespace)
            actual = self.image._entry
            error = RuntimeError('lost native acknowledgement')
            def lost(source, size, output, capacity, state, extent):
                code = actual(source, size, output, capacity, state, extent)
                if struct.unpack('<2Q', ctypes.string_at(source, 16))[1] == lost_event:
                    raise error
                return code
            with (patch.object(self.image, '_entry', lost),
                  patch.object(frame, 'effect', side_effect=lambda port: fixture.event('foreign', port))):
                with self.assertRaises(RuntimeError) as raised:
                    frame.finish()
            self.assertIs(raised.exception, error)
            self.assertTrue(frame.fenced)
            before = list(fixture.trace)
            with self.assertRaises(native.StoreLifecycleUnknown):
                frame.call(1)
            self.assertEqual(fixture.trace, before)
            self.assertEqual(len(before), int(lost_event == 2))

    def test_real_connect_lost_ack_retains_unknown_custody_without_close_or_retry(self):
        closed, finalized, connections = [], [], []
        real_connect = sqlite3.connect
        class Connection(sqlite3.Connection):
            def close(connection):
                closed.append('explicit close')
                return super().close()
            def __del__(connection):
                finalized.append('finalized')
        def connect(*args, **keywords):
            value = real_connect(*args, **keywords, factory=Connection)
            connections.append(weakref.ref(value))
            return value
        entry = self.image._entry
        unknown = RuntimeError('connect acknowledgement lost')
        def lost(source, size, output, capacity, state, extent):
            returned = entry(source, size, output, capacity, state, extent)
            words = struct.unpack('<10Q', ctypes.string_at(source, size))
            if (words[1], words[3]) == (2, 23):
                raise unknown
            return returned
        with (tempfile.TemporaryDirectory() as directory,
              patch.dict(native._FRAME_CUSTODY),
              patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}),
              patch.object(api.sqlite3, 'connect', connect), patch.object(self.image, '_entry', lost),
              patch.object(api, '_NATIVE_STORE_INITIALIZE_REFERENCE', side_effect=AssertionError('fallback')),
              patch.object(api, '_NATIVE_STORE_CLOSE_REFERENCE', side_effect=AssertionError('fallback'))):
            before = native.unconfirmed_lifecycle_count()
            with self.assertRaises(RuntimeError) as raised:
                api.AgentStore(Path(directory) / 'state')
            self.assertIs(raised.exception, unknown)
            raised = None
            gc.collect()
            self.assertEqual(native.unconfirmed_lifecycle_count(), before + 1)
            self.assertEqual(len(connections), 1)
            self.assertIsNotNone(connections[0]())
            self.assertEqual(connections[0]().execute('SELECT 1').fetchone(), (1,))
            self.assertEqual(closed, [])
            self.assertEqual(finalized, [])
            held = next(frame for frame in native._FRAME_CUSTODY.values()
                        if frame.unconfirmed and frame.receipt.port == 23)
            with self.assertRaises(native.StoreLifecycleUnknown):
                held.call(2)
            with self.assertRaises(native.StoreLifecycleUnknown):
                held.store.close()
            del os.environ[native.SELECTOR]
            with self.assertRaises(native.StoreLifecycleUnknown):
                api.AgentStore.__init__(held.store, Path(directory) / 'forbidden-reopen')
            self.assertFalse((Path(directory) / 'forbidden-reopen').exists())
            self.assertEqual(closed, [])
            # Explicit test cleanup after observing the actual connection;
            # production offers no in-process release for unknown custody.
            connections[0]().close()

    def test_custody_grows_and_allocation_failure_precedes_external_effects(self):
        fixture = Fixture()
        object.__setattr__(fixture.store, 'db', fixture.db)
        object.__setattr__(fixture.store, 'execution_budgets', fixture.budget_owner)
        with patch.dict(native._FRAME_CUSTODY, {}, clear=True):
            active = [native.LifecycleFrame(self.image, 2, fixture.store, namespace=fixture.namespace)
                      for _ in range(70)]
            self.assertEqual(len(native._FRAME_CUSTODY), 70)
            self.assertEqual(fixture.trace, [])
            for frame in active:
                frame.finish()
            self.assertEqual(native._FRAME_CUSTODY, {})
        class Unavailable(dict):
            def __setitem__(self, key, value):
                raise MemoryError('custody allocation failed')
        with (tempfile.TemporaryDirectory() as directory,
              patch.object(native, '_FRAME_CUSTODY', Unavailable()),
              patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})):
            with self.assertRaises(MemoryError):
                api.AgentStore(Path(directory) / 'unentered')
            self.assertFalse((Path(directory) / 'unentered').exists())

    def test_lost_foreign_exception_storage_keeps_claimed_frame_unknown(self):
        fixture = Fixture()
        lost = MemoryError('lost foreign observation storage')
        class LostStorage(list):
            def append(self, value):
                raise lost
        with patch.dict(native._FRAME_CUSTODY):
            frame = native.LifecycleFrame(self.image, 1, fixture.store, 'root', namespace=fixture.namespace)
            effect = frame.effect
            def observed(port):
                if port == 24:
                    raise fixture.primary
                return effect(port)
            frame.errors = LostStorage()
            with patch.object(frame, 'effect', observed):
                _result, error = fixture.observe(frame.finish)
            self.assertIs(error, lost)
            self.assertTrue(frame.fenced)
            self.assertTrue(frame.unconfirmed)
            self.assertIs(native._FRAME_CUSTODY[id(frame)], frame)
            self.assertIs(frame.store, fixture.store)
            self.assertEqual((frame.receipt.port, frame.receipt.phase), (24, 2))
            self.assertEqual(fixture.db.close_count, 0)
            with self.assertRaises(native.StoreLifecycleUnknown):
                frame.call(3)

    def test_fork_rebuilds_only_custody_lock_and_retains_unknown_references(self):
        fixture = Fixture()
        entered, release = threading.Event(), threading.Event()
        with (tempfile.TemporaryDirectory() as directory,
              patch.dict(native._FRAME_CUSTODY),
              patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})):
            held = native.LifecycleFrame(self.image, 1, fixture.store, 'root', namespace=fixture.namespace)
            actual = self.image._entry
            def lost(source, size, output, capacity, state, extent):
                actual(source, size, output, capacity, state, extent)
                raise RuntimeError('claim receipt lost before fork')
            with patch.object(self.image, '_entry', lost):
                with self.assertRaises(RuntimeError):
                    held.call(1)
            self.assertTrue(held.unconfirmed)
            def holding():
                with native._custody_lock():
                    entered.set()
                    release.wait(15)
            holder = threading.Thread(target=holding)
            holder.start()
            self.assertTrue(entered.wait(5))
            reader, writer = os.pipe()
            child = None
            try:
                child = os.fork()
                if child == 0:
                    os.close(reader)
                    try:
                        assert native._FRAME_CUSTODY[id(held)] is held and held.store is fixture.store
                        assert native.unconfirmed_lifecycle_count() >= 1
                        store = api.AgentStore(Path(directory) / 'child-state')
                        store.close()
                        assert native._FRAME_CUSTODY[id(held)] is held and fixture.db.close_count == 0
                        os.write(writer, b'CHILD_STORE_CLOSED_WITH_UNKNOWN_RETAINED')
                    except BaseException as error:
                        os.write(writer, (type(error).__name__ + ': ' + str(error)).encode()[:4096])
                        os._exit(1)
                    os._exit(0)
                os.close(writer); writer = None
                ready, _, _ = select.select([reader], [], [], 10)
                if not ready:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0); child = None
                    self.fail('child blocked on the inherited lifecycle custody lock')
                output = os.read(reader, 4096)
                _, status = os.waitpid(child, 0); child = None
                self.assertEqual(status, 0, output)
                self.assertEqual(output, b'CHILD_STORE_CLOSED_WITH_UNKNOWN_RETAINED')
            finally:
                if child:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                if writer is not None:
                    os.close(writer)
                os.close(reader)
                release.set(); holder.join(5)
            self.assertFalse(holder.is_alive())
            self.assertIs(native._FRAME_CUSTODY[id(held)], held)
            self.assertEqual(fixture.db.close_count, 0)
            with patch.object(native, '_CUSTODY_PID', -1):
                with self.assertRaisesRegex(native.StoreLifecycleUnknown, 'not established'):
                    native.unconfirmed_lifecycle_count()

    def test_confirmed_foreign_exception_keeps_original_traceback_lifetime(self):
        for selected in (False, True):
            references = []
            class Store(api.AgentStore):
                def __new__(cls, *args, **keywords):
                    value = super().__new__(cls)
                    references.append(weakref.ref(value))
                    return value
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
                os.environ.pop(native.SELECTOR, None)
                if selected:
                    os.environ[native.SELECTOR] = str(self.manifest)
                before = native.unconfirmed_lifecycle_count()
                failure = RuntimeError('ordinary chmod failure')
                caught_error = None
                with patch.object(api.os, 'chmod', side_effect=failure):
                    try:
                        Store(Path(directory) / 'state')
                    except RuntimeError as caught:
                        caught_error = caught
                self.assertIs(caught_error, failure)
                gc.collect()
                self.assertIsNotNone(references[0]())
                self.assertEqual(native.unconfirmed_lifecycle_count(), before)
                caught_error.__traceback__ = None
                gc.collect()
                self.assertIsNone(references[0]())

    def test_replay_cross_identity_and_mutated_state_refuse(self):
        start = struct.pack('<10Q', native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 17, 23, 0, 0)
        for kind in ('replay', 'identity', 'state'):
            state = ctypes.create_string_buffer(native.STATE_BYTES)
            self.assertEqual(self.invoke(start, state)[0], native.OUTPUT_BYTES)
            request = struct.pack('<10Q', native.REQUEST_MAGIC, 1, 1, 1, 0, 1,
                                  19 if kind == 'identity' else 17, 23, 0, 0)
            if kind == 'state':
                state[24] = b'\x02'
                self.assertEqual(self.invoke(request, state)[0], 4294967293)
            elif kind == 'identity':
                self.assertEqual(struct.unpack('<10Q', self.invoke(request, state)[1])[1], 1)
            else:
                self.assertEqual(struct.unpack('<10Q', self.invoke(request, state)[1])[1], 0)
                self.assertEqual(struct.unpack('<10Q', self.invoke(request, state)[1])[1], 1)

    def test_fresh_selection_rechecks_manifest_source_and_image(self):
        folder = self.root / 'identity'; folder.mkdir()
        record = json.loads(self.manifest.read_bytes())
        source = folder / 'source.hepta'; source.write_bytes(native.SOURCE.read_bytes())
        image = folder / record['image_path']
        image.write_bytes((self.manifest.parent / record['image_path']).read_bytes())
        manifest = folder / 'manifest.json'; manifest.write_bytes(self.manifest.read_bytes())
        with patch.object(native, 'SOURCE', source):
            held = native.installed_store_lifecycle(str(manifest))
            for target in (source, image, manifest):
                raw = target.read_bytes()
                try:
                    target.write_bytes(raw + b'\n')
                    if target is manifest:
                        # Harmless JSON whitespace is newly read but valid.
                        self.assertIs(native.installed_store_lifecycle(str(manifest)), held)
                    else:
                        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                            native.installed_store_lifecycle(str(manifest))
                finally:
                    target.write_bytes(raw)
            self.assertIs(native.installed_store_lifecycle(str(manifest)), held)

    def test_pinned_administrator_bundle_calls_store_and_restores_scope(self):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope, native_helpers_identity
        folder = self.root / 'bundle'; folder.mkdir()
        source = folder / 'store.hepta'; source.write_bytes(native.SOURCE.read_bytes())
        record = json.loads(self.manifest.read_bytes())
        image = folder / record['image_path']
        image.write_bytes((self.manifest.parent / record['image_path']).read_bytes())
        child = folder / 'manifest.json'; child.write_bytes(self.manifest.read_bytes())
        bundle = folder / 'helpers.json'
        bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
            {'selector': native.SELECTOR, 'manifest_path': child.name,
             'manifest_sha256': sha256(child.read_bytes()).hexdigest()}]}, sort_keys=True))
        expected = sha256(bundle.read_bytes()).hexdigest()
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        environment[native.SELECTOR] = ''
        with (patch.dict(os.environ, environment, clear=True), patch.object(native, 'SOURCE', source),
              patch.object(api, '_NATIVE_STORE_INITIALIZE_REFERENCE', side_effect=AssertionError('host init')),
              patch.object(api, '_NATIVE_STORE_CLOSE_REFERENCE', side_effect=AssertionError('host close'))):
            before = dict(os.environ)
            for altered in (source, child):
                with native_helpers_scope(str(bundle), expected):
                    with patch.object(native, '_mapped_lifecycle', side_effect=AssertionError('general map')):
                        store = api.AgentStore(folder / ('store-' + altered.name))
                        store.close()
                    self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': expected})
                    raw = altered.read_bytes()
                    try:
                        altered.write_bytes(raw + b'\n')
                        with self.assertRaisesRegex(ValueError, 'inputs changed'):
                            native_helpers_identity()
                    finally:
                        altered.write_bytes(raw)
                self.assertEqual(dict(os.environ), before)
                self.assertEqual(native_helpers_identity(), {})
                raw = altered.read_bytes()
                try:
                    altered.write_bytes(raw + b'\n')
                    with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                        with native_helpers_scope(str(bundle), expected):
                            self.fail('changed administrator input admitted')
                finally:
                    altered.write_bytes(raw)
                self.assertEqual(dict(os.environ), before)
            with native_helpers_scope(str(bundle), expected):
                store = api.AgentStore(folder / 'recovered')
                store.close()

    def test_actual_installed_wheel_uses_bundled_source_and_rejects_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        self.assertIn('examples/hia_bootstrap/store_lifecycle.hepta', RESOURCES)
        folder = self.root / 'installation'; folder.mkdir()
        source = folder / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        def run(arguments, cwd=source):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cwd,
                env=environment, capture_output=True, text=True, timeout=60)
            if result.returncode:
                self.fail(result.stdout + result.stderr)
            return result
        wheels = folder / 'wheels'
        run(['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', wheels, source])
        wheel, = wheels.glob('*.whl')
        installed = folder / 'installed'
        run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
        script = r'''import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hepta import hia_agent_store as api
from hepta import hia_store_lifecycle_native as native
assert Path(api.__file__).is_relative_to(Path(sys.argv[1]))
assert native.SOURCE.is_relative_to(Path(sys.argv[1]))
def forbidden(*args, **keywords): raise AssertionError('installed reference fallback')
api._NATIVE_STORE_INITIALIZE_REFERENCE = api._NATIVE_STORE_CLOSE_REFERENCE = forbidden
os.environ[native.SELECTOR] = sys.argv[2]
if sys.argv[4] == 'worker':
    import io
    from hashlib import sha256
    from hepta.hia_agent_contract import installation_manifest
    from hepta.hia_agent_worker import main
    from hepta.hia_agent_store import wire
    modes = []
    finish = native.LifecycleFrame.finish
    def counted(frame):
        modes.append(frame.mode)
        return finish(frame)
    native.LifecycleFrame.finish = counted
    envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_describe',
        'arguments': {'section': 'manifest'}, 'profile_sha256': 'a' * 64,
        'catalog_sha256': installation_manifest()['catalog_sha256']}
    envelope['request_sha256'] = sha256(wire(envelope)).hexdigest()
    sys.stdin = io.TextIOWrapper(io.BytesIO(wire(envelope)), encoding='utf-8')
    del os.environ[native.SELECTOR]
    code = main(['--state-root', sys.argv[3], '--request-json-stdin',
        '--native-helpers-manifest', sys.argv[5], '--expected-native-helpers-sha256', sys.argv[6]])
    assert code == 0 and modes == [1, 2], (code, modes)
elif sys.argv[4] == 'accept':
    store = api.AgentStore(sys.argv[3])
    assert store.db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0] == 0
    os.environ[native.SELECTOR] = '/selector-changed-after-construction'
    store.close()
    print('INSTALLED_NATIVE_STORE_CLOSED')
else:
    try: api.AgentStore(sys.argv[3])
    except ValueError as error:
        assert 'source identity mismatch' in str(error), str(error)
        assert not Path(sys.argv[3]).exists()
        print('REFUSED_CHANGED_INSTALLED_SOURCE')
    else: raise AssertionError('changed installed source admitted')
'''
        result = run(['-I', '-c', script, installed, self.manifest, folder / 'accepted', 'accept'], cwd=folder)
        self.assertEqual(result.stdout.strip(), 'INSTALLED_NATIVE_STORE_CLOSED')
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        record = json.loads(self.manifest.read_bytes())
        child = folder / 'store-manifest.json'; child.write_bytes(self.manifest.read_bytes())
        (folder / record['image_path']).write_bytes((self.manifest.parent / record['image_path']).read_bytes())
        bundle = folder / 'helpers.json'
        bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
            {'selector': native.SELECTOR, 'manifest_path': child.name,
             'manifest_sha256': sha256(child.read_bytes()).hexdigest()}]}, sort_keys=True))
        digest = sha256(bundle.read_bytes()).hexdigest()
        result = run(['-I', '-c', script, installed, self.manifest, folder / 'worker', 'worker', bundle, digest], cwd=folder)
        report = json.loads(result.stdout)
        self.assertEqual(report['native_helpers_sha256'], digest)
        self.assertTrue(report['complete'])
        self.assertEqual(report['response']['status'], 'completed')
        packaged = installed / 'hepta/_data/examples/hia_bootstrap/store_lifecycle.hepta'
        packaged.write_bytes(packaged.read_bytes() + b'\n')
        result = run(['-I', '-c', script, installed, self.manifest, folder / 'refused', 'reject'], cwd=folder)
        self.assertEqual(result.stdout.strip(), 'REFUSED_CHANGED_INSTALLED_SOURCE')


if __name__ == '__main__':
    unittest.main()
