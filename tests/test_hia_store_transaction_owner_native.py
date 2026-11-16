"""Reconstructed Native6 controls for explicit transaction-owner routing.

This is a new source identity after the historical six-method file was lost.
It does not replace the complete original 15/11/61/112/130 scopes. The image
and every transaction below are actual compiled HIA; no VM or mock image is
used. SQLite and the Python lock/generator protocols remain hosted providers.
"""
from __future__ import annotations

from contextlib import ExitStack
import contextvars
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hepta import hia_agent_store as api
from hepta import hia_store_transaction_native as native
from hepta.hia_native_helpers import native_helpers_identity, native_helpers_scope
from tests.test_hia_store_transaction_native import (
    ControlStore, bundle, clean_environment, encoded, poison,
)

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_STORE_TRANSACTION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_STORE_TRANSACTION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STORE_TRANSACTION_OWNER_EVIDENCE'
PROCESS_DEADLINE_SECONDS = 5
TEST_IDS = (
    'test_01_actual_SQLite_clear_environment_current_image_commit_and_rollback',
    'test_02_nested_scope_and_original_absent_empty_and_lazy_selection',
    'test_03_manifest_source_image_and_selector_drift_refuse_before_effect',
    'test_04_stale_copied_context_thread_and_fork_refuse_before_entry',
    'test_05_started_transaction_can_resume_after_scope_exit_on_another_thread',
    'test_06_actual_pinned_worker_exclusivity_and_declared_current_image',
)


def _source_pins():
    from tools.build_hia_json_preflight import current_sources
    from tools.build_hia_store_transaction import INPUTS
    names = {*INPUTS, 'docs/HIA_STORE_TRANSACTION_NATIVE.md',
             'tests/test_hia_store_transaction_owner_native.py'}
    return {**current_sources(), **{
        name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(names)}}


class StoreTransactionOwnerNativeTests(unittest.TestCase):
    """Six independent controls; no inherited original methods are duplicated."""

    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_transaction import build
        cold, development, evidence = (os.environ.get(key) for key in (COLD, DEVELOPMENT, EVIDENCE))
        if ((cold is None) == (development is None) or cold == ''
                or development == '' or evidence == ''):
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-transaction-owner-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.cold = cold
        cls.cold_raw = None if cold is None else Path(cold).read_bytes()
        if cold is not None:
            outer = json.loads(cls.cold_raw)
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            cls.compiler = Path(development).resolve(strict=True)
        cls.compiler_raw = cls.compiler.read_bytes()
        cls.source_before = _source_pins()
        cls.manifest = build(cls.root / 'built', cls.compiler, cold, development=cold is None)
        cls.manifest_raw = cls.manifest.read_bytes()
        cls.manifest_value = json.loads(cls.manifest_raw)
        cls.image_path = cls.manifest.parent / cls.manifest_value['image_path']
        cls.image_raw = cls.image_path.read_bytes()
        cls.image = native.installed_store_transaction(str(cls.manifest))
        cls.started = []
        cls.stopped = []
        cls.case_reports = []

    @classmethod
    def tearDownClass(cls):
        after = _source_pins()
        stable = (after == cls.source_before
                  and cls.compiler.read_bytes() == cls.compiler_raw
                  and cls.manifest.read_bytes() == cls.manifest_raw
                  and cls.image_path.read_bytes() == cls.image_raw
                  and (cls.cold is None or Path(cls.cold).read_bytes() == cls.cold_raw))
        report = {
            'schema': 'hepta.hia.transaction-owner-component.v1',
            'source_identity': 'RECONSTRUCTED_NATIVE6_NOT_RECOVERED_HISTORICAL_SOURCE',
            'scope': ('DEVELOPMENT_COMPONENT' if cls.cold is None
                      else 'MATCHING_SOURCE_COLD_COMPONENT'),
            'planned': list(TEST_IDS), 'started': cls.started, 'stopped': cls.stopped,
            'case_reports': cls.case_reports,
            'source_before': cls.source_before, 'source_after': after,
            'source_compiler_manifest_and_image_unchanged': stable,
            'manifest': str(cls.manifest),
            'manifest_sha256': sha256(cls.manifest_raw).hexdigest(),
            'image_sha256': sha256(cls.image_raw).hexdigest(),
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'cold_report_sha256': None if cls.cold_raw is None else sha256(cls.cold_raw).hexdigest(),
            'python_version': sys.version,
            'result_and_test_outcomes_owned_by_outer_unittest_runner': True,
            'original_15_11_61_112_130_scopes_remain_separate': True,
            'old_administrator_bundle_enlarged': False,
            'whole_native_stack_qualified': False,
        }
        (cls.root / 'component-custody.json').write_bytes(encoded(report) + b'\n')
        if not stable:
            raise AssertionError('transaction owner source/compiler/manifest/image custody changed')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.entries, self.frames, self.observations = [], [], {}
        self.frame_keys_before = set(native._FRAME_CUSTODY)
        self.type_prior_owner = api._STORE_TRANSACTION_OWNER.get()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, clean_environment(), clear=True))
        self.__class__.started.append(self._testMethodName)

    def tearDown(self):
        # Flush raw observations even on an assertion failure. The outer
        # unittest result, rather than this record, determines PASS or HOLD.
        self.stack.close()
        record = {
            'test': self._testMethodName,
            'actual_native_entries': self.entries, 'actual_frames': self.frames,
            'observations': self.observations,
            'native_frame_keys_before': sorted(self.frame_keys_before),
            'native_frame_keys_after': sorted(native._FRAME_CUSTODY),
            'explicit_owner_restored': api._STORE_TRANSACTION_OWNER.get() is self.type_prior_owner,
            'outcome_owned_by_outer_unittest_runner': True,
        }
        raw = encoded(record) + b'\n'
        path = self.case / 'observations.json'
        path.write_bytes(raw)
        self.__class__.case_reports.append({
            'test': self._testMethodName, 'path': str(path), 'sha256': sha256(raw).hexdigest(),
            'actual_native_entries': len(self.entries), 'actual_frames': len(self.frames)})
        self.__class__.stopped.append(self._testMethodName)
        self.assertEqual(set(native._FRAME_CUSTODY), self.frame_keys_before)
        self.assertIs(api._STORE_TRANSACTION_OWNER.get(), self.type_prior_owner)

    def observe(self, stack, image, label):
        original_entry = image._entry
        original_init = native.StoreTransactionFrame.__init__

        def entry(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = original_entry(source, size, output, capacity, state, extent)
            self.entries.append({'label': label, 'event': packet[1], 'port': packet[3],
                                 'result': result, 'pid': os.getpid(),
                                 'thread': threading.get_ident()})
            if packet[0] != native.REQUEST_MAGIC or result != native.OUTPUT_BYTES:
                raise AssertionError('actual transaction entry did not return its complete ABI')
            return result

        def initialize(frame, selected, *arguments, **keywords):
            if selected is not image:
                raise AssertionError('public transaction selected a different current image')
            original_init(frame, selected, *arguments, **keywords)
            self.frames.append({'label': label, 'pid': os.getpid(),
                                'thread': threading.get_ident()})

        initialize._owner_control_original = getattr(
            original_init, '_owner_control_original', original_init)
        stack.enter_context(patch.object(image, '_entry', entry))
        stack.enter_context(patch.object(native.StoreTransactionFrame, '__init__', initialize))

    def copied_manifest(self, label):
        directory = self.case / label
        directory.mkdir(mode=0o700)
        image = directory / self.manifest_value['image_path']
        image.write_bytes(self.image_raw)
        manifest = directory / 'manifest.json'
        manifest.write_bytes(self.manifest_raw)
        return manifest, image

    def actual_store(self, label):
        store = api.AgentStore(self.case / label)
        self.addCleanup(store.close)
        return store

    def refuse_public(self, store):
        before = len(self.entries)
        cm = api.AgentStore.transaction(store)
        self.assertEqual(store.events, [])
        try:
            with self.assertRaises(ValueError):
                cm.__enter__()
        finally:
            cm.gen.close()
        self.assertEqual(store.events, [])
        self.assertEqual(len(self.entries), before)

    def test_01_actual_SQLite_clear_environment_current_image_commit_and_rollback(self):
        with ExitStack() as stack:
            poison(stack)
            self.observe(stack, self.image, 'actual-SQLite')
            store = self.actual_store('sqlite')
            trace = []
            store.db.set_trace_callback(trace.append)
            store.db.execute('CREATE TABLE owner_route_probe(value INTEGER)')
            with native.transaction_owner_scope(str(self.manifest), self.image) as binding:
                self.assertIs(binding.select(), self.image)
                self.assertNotIn(native.SELECTOR, os.environ)
                cm = store.transaction()
                self.assertEqual(len(self.entries), 0)
                with cm:
                    store.db.execute('INSERT INTO owner_route_probe VALUES (1)')
                marker = MemoryError('same actual body object through rollback')
                caught = None
                try:
                    with store.transaction():
                        store.db.execute('INSERT INTO owner_route_probe VALUES (2)')
                        raise marker
                except MemoryError as error:
                    caught = error
                self.assertIs(caught, marker)
                # Clear the original mapping cache without changing any source
                # or supplied image. A live owner must keep its exact image.
                native._mapped_transaction.cache_clear()
                with store.transaction():
                    store.db.execute('INSERT INTO owner_route_probe VALUES (3)')
            values = [row[0] for row in store.db.execute(
                'SELECT value FROM owner_route_probe ORDER BY value')]
            self.assertEqual(values, [1, 3])
            self.assertEqual(trace.count('BEGIN IMMEDIATE'), 3)
            self.assertEqual(trace.count('COMMIT'), 2)
            self.assertEqual(trace.count('ROLLBACK'), 1)
            self.assertEqual(len(self.frames), 3)
            self.assertGreater(len(self.entries), 0)
            self.observations = {'SQL': trace, 'stored_values': values,
                                 'rollback_error_is_original_object': caught is marker,
                                 'environment_selector_absent': native.SELECTOR not in os.environ}

    def test_02_nested_scope_and_original_absent_empty_and_lazy_selection(self):
        # Outside an owner the documented retained route remains available.
        plain = ControlStore()
        with patch.object(native, 'installed_store_transaction',
                          side_effect=AssertionError('unexpected unselected admission')):
            cm = api.AgentStore.transaction(plain)
            self.assertEqual(plain.events, [])
            with cm:
                pass
        self.assertEqual(plain.events, ['enter', 'BEGIN IMMEDIATE', 'COMMIT', 'exit'])
        self.assertEqual(self.entries, [])
        with patch.dict(os.environ, {native.SELECTOR: ''}):
            never_started = api.AgentStore.transaction(ControlStore())
            never_started.gen.close()
            self.refuse_public(ControlStore())

        second_manifest, _ = self.copied_manifest('second-image')
        native._mapped_transaction.cache_clear()
        second = native.installed_store_transaction(str(second_manifest))
        self.assertIsNot(second, self.image)
        lazy = ControlStore()
        lazy_cm = api.AgentStore.transaction(lazy)
        self.assertEqual(lazy.events, [])
        with ExitStack() as outer:
            poison(outer)
            self.observe(outer, self.image, 'outer')
            with native.transaction_owner_scope(str(self.manifest), self.image) as first:
                with lazy_cm:
                    pass
                with ExitStack() as inner:
                    # An inner counter replaces the outer initializer rather
                    # than stacking two mutually-exclusive image assertions.
                    original_init = native.StoreTransactionFrame.__init__
                    inner.enter_context(patch.object(native.StoreTransactionFrame, '__init__',
                                                      self._unwrapped_initializer(original_init)))
                    self.observe(inner, second, 'inner')
                    with native.transaction_owner_scope(str(second_manifest), second) as nested:
                        self.assertIs(api._STORE_TRANSACTION_OWNER.get(), nested)
                        with self.assertRaises(ValueError):
                            first.select()
                        with api.AgentStore.transaction(ControlStore()):
                            pass
                self.assertIs(api._STORE_TRANSACTION_OWNER.get(), first)
                with api.AgentStore.transaction(ControlStore()):
                    pass
                delayed = ControlStore()
                delayed_cm = api.AgentStore.transaction(delayed)
            self.assertIs(api._STORE_TRANSACTION_OWNER.get(), self.type_prior_owner)
        before = len(self.entries)
        # Its first advance is after the owner exited; original lazy absence
        # selects the retained body. No retained poison is active here.
        with delayed_cm:
            pass
        self.assertEqual(len(self.entries), before)
        self.assertEqual(delayed.events, ['enter', 'BEGIN IMMEDIATE', 'COMMIT', 'exit'])
        self.assertEqual([row['label'] for row in self.frames], ['outer', 'inner', 'outer'])
        self.observations = {'absent_route_events': plain.events,
                             'created_before_owner_events': lazy.events,
                             'first_advanced_after_owner_events': delayed.events}

    @staticmethod
    def _unwrapped_initializer(value):
        # observe() exposes the captured real initializer explicitly so a nested
        # observation remains a single passive wrapper, never a routing change.
        return getattr(value, '_owner_control_original', value)

    def test_03_manifest_source_image_and_selector_drift_refuse_before_effect(self):
        manifest, image_path = self.copied_manifest('drift')
        source_path = self.case / 'source-copy.hepta'
        original_source = native.SOURCE.read_bytes()
        source_path.write_bytes(original_source)
        rows = []
        with ExitStack() as stack:
            poison(stack)
            self.observe(stack, self.image, 'drift-control')
            stack.enter_context(patch.object(native, 'SOURCE', source_path))
            with native.transaction_owner_scope(str(manifest), self.image):
                for field in ('compiler_sha256', 'source_sha256', 'image_sha256'):
                    changed = dict(self.manifest_value)
                    changed[field] = ('0' if changed[field][0] != '0' else '1') + changed[field][1:]
                    manifest.write_bytes(encoded(changed) + b'\n')
                    try:
                        self.refuse_public(ControlStore())
                    finally:
                        manifest.write_bytes(self.manifest_raw)
                    rows.append({'case': field, 'effects': [], 'entries': 0})
                for label, path, raw in (
                        ('actual-image-bytes', image_path, self.image_raw),
                        ('actual-source-bytes', source_path, original_source)):
                    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    try:
                        self.refuse_public(ControlStore())
                    finally:
                        path.write_bytes(raw)
                    rows.append({'case': label, 'effects': [], 'entries': 0})
                for label, value in (('empty-selector', ''), ('conflicting-selector', str(self.manifest))):
                    with patch.dict(os.environ, {native.SELECTOR: value}):
                        self.refuse_public(ControlStore())
                    rows.append({'case': label, 'effects': [], 'entries': 0})
                self.assertEqual(len(self.entries), 0)
                with api.AgentStore.transaction(ControlStore()):
                    pass
            self.assertGreater(len(self.entries), 0)
        self.observations = {'refusals': rows, 'healthy_after_exact_restoration': True}

    def test_04_stale_copied_context_thread_and_fork_refuse_before_entry(self):
        rows = {}
        with ExitStack() as stack:
            poison(stack)
            self.observe(stack, self.image, 'creator-only')
            with native.transaction_owner_scope(str(self.manifest), self.image):
                copied = contextvars.copy_context()
                thread_result = {}

                def foreign_thread():
                    store = ControlStore()
                    before = len(self.entries)
                    try:
                        copied.run(lambda: api.AgentStore.transaction(store).__enter__())
                    except BaseException as error:
                        thread_result['error_type'] = type(error).__name__
                    thread_result.update(events=store.events, entry_delta=len(self.entries) - before)

                worker = threading.Thread(target=foreign_thread, daemon=True)
                worker.start()
                worker.join(PROCESS_DEADLINE_SECONDS)
                self.assertFalse(worker.is_alive(), 'foreign thread guard did not terminate')
                self.assertEqual(thread_result,
                                 {'error_type': 'ValueError', 'events': [], 'entry_delta': 0})
                rows['thread'] = thread_result
                read_fd, write_fd = os.pipe()
                deadline = time.monotonic() + PROCESS_DEADLINE_SECONDS
                pid = os.fork()
                if pid == 0:
                    os.close(read_fd)
                    try:
                        child_store = ControlStore()
                        count = len(self.entries)
                        error_type = None
                        try:
                            api.AgentStore.transaction(child_store).__enter__()
                        except BaseException as error:
                            error_type = type(error).__name__
                        record = {'error_type': error_type, 'events': child_store.events,
                                  'entry_delta': len(self.entries) - count,
                                  'pid': os.getpid(), 'ppid': os.getppid()}
                        raw = encoded(record)
                        if len(raw) > 4096:
                            os._exit(74)
                        os.write(write_fd, raw)
                        os.close(write_fd)
                        os._exit(0)
                    except BaseException:
                        os._exit(73)
                os.close(write_fd)
                reaped = False
                try:
                    ready, _, _ = select.select([read_fd], [], [],
                                                max(0, deadline - time.monotonic()))
                    self.assertTrue(ready, 'fork guard exceeded its five-second observation budget')
                    raw = os.read(read_fd, 4096)
                    while True:
                        done, status = os.waitpid(pid, os.WNOHANG)
                        if done:
                            reaped = True
                            break
                        if time.monotonic() >= deadline:
                            self.fail('fork guard did not exit within its five-second budget')
                        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    record = json.loads(raw)
                    self.assertEqual(record['error_type'], 'ValueError')
                    self.assertEqual(record['events'], [])
                    self.assertEqual(record['entry_delta'], 0)
                    self.assertEqual(record['pid'], pid)
                    self.assertEqual(record['ppid'], os.getpid())
                    (self.case / 'fork-observation.json').write_bytes(raw + b'\n')
                    rows['fork'] = record
                finally:
                    os.close(read_fd)
                    if not reaped:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(pid, 0)
                self.assertEqual(self.entries, [])
                with api.AgentStore.transaction(ControlStore()):
                    pass
            before = len(self.entries)
            stale_store = ControlStore()
            with self.assertRaises(ValueError):
                copied.run(lambda: api.AgentStore.transaction(stale_store).__enter__())
            self.assertEqual(stale_store.events, [])
            self.assertEqual(len(self.entries), before)
            rows['stale'] = {'events': stale_store.events, 'entry_delta': 0}
            self.assertGreater(len(self.entries), 0)
        self.observations = rows

    def test_05_started_transaction_can_resume_after_scope_exit_on_another_thread(self):
        store = ControlStore()
        result = {}
        with ExitStack() as stack:
            poison(stack)
            self.observe(stack, self.image, 'legal-resume')
            with native.transaction_owner_scope(str(self.manifest), self.image):
                cm = api.AgentStore.transaction(store)
                cm.__enter__()
                self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE'])
            self.assertIs(api._STORE_TRANSACTION_OWNER.get(), self.type_prior_owner)

            def resume():
                try:
                    result['exit_value'] = cm.__exit__(None, None, None)
                except BaseException as error:
                    result['error_type'] = type(error).__name__
                    result['error_message'] = str(error)
                result['thread'] = threading.get_ident()

            worker = threading.Thread(target=resume, daemon=True)
            worker.start()
            worker.join(PROCESS_DEADLINE_SECONDS)
            self.assertFalse(worker.is_alive(), 'legal resumed transaction did not terminate')
            self.assertNotIn('error_type', result, result)
            self.assertFalse(result['exit_value'])
            self.assertNotEqual(result['thread'], threading.get_ident())
            self.assertEqual(store.events, ['enter', 'BEGIN IMMEDIATE', 'COMMIT', 'exit'])
            self.assertEqual(len(self.frames), 1)
            self.assertGreater(len(self.entries), 0)
        self.observations = {
            'events': store.events, 'resume': result,
            'scope': 'already-started transaction with original opaque custom lock/DB providers',
            'sqlite_or_RLock_cross_thread_semantics_claimed': False,
        }

    def test_06_actual_pinned_worker_exclusivity_and_declared_current_image(self):
        bundle_path = self.case / 'bundle.json'
        pin = bundle(bundle_path, [(native.SELECTOR, self.manifest)])
        rows = {}
        with ExitStack() as stack:
            poison(stack)
            self.observe(stack, self.image, 'outside-worker')
            with native.transaction_owner_scope(str(self.manifest), self.image):
                with native_helpers_scope() as unselected:
                    self.assertIsNone(unselected)
                    self.refuse_public(ControlStore())
                    with self.assertRaises(ValueError):
                        with native.transaction_owner_scope(str(self.manifest), self.image):
                            pass
                self.assertEqual(self.entries, [])
                with native_helpers_scope(str(bundle_path), pin):
                    self.refuse_public(ControlStore())
            self.assertEqual(self.entries, [])

        with native_helpers_scope(str(bundle_path), pin) as worker_binding:
            worker_image = native.installed_store_transaction(str(self.manifest))
            self.assertIsNot(worker_image, self.image)
            self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': pin})
            with self.assertRaises(ValueError):
                with native.transaction_owner_scope(str(self.manifest), self.image):
                    pass
            with ExitStack() as stack:
                poison(stack)
                self.observe(stack, worker_image, 'declared-worker')
                store = self.actual_store('worker-sqlite')
                SQL = []
                store.db.set_trace_callback(SQL.append)
                store.db.execute('CREATE TABLE worker_owner_probe(value INTEGER)')
                with native.transaction_owner_scope(str(self.manifest), worker_image):
                    with store.transaction():
                        store.db.execute('INSERT INTO worker_owner_probe VALUES (7)')
                    before = len(self.entries)
                    with patch.dict(os.environ, clean_environment(), clear=True):
                        self.refuse_public(ControlStore())
                    self.assertEqual(len(self.entries), before)
                    native._mapped_transaction.cache_clear()
                    with store.transaction():
                        self.assertEqual(store.db.execute(
                            'SELECT value FROM worker_owner_probe').fetchone()[0], 7)
                self.assertEqual(SQL.count('BEGIN IMMEDIATE'), 2)
                self.assertEqual(SQL.count('COMMIT'), 2)
                self.assertEqual(len(self.frames), 2)
                self.assertGreater(len(self.entries), 0)
                rows = {'SQL': SQL, 'bundle_sha256': pin,
                        'worker_binding_identity': worker_binding.sha256,
                        'declared_image_is_actual_pinned_object': True,
                        'outside_image_rejected_even_with_equal_image_hash': True,
                        'selection_clear_inside_worker_refused': True}
        self.observations = {
            **rows,
            'scope': 'actual native_helpers_scope and real SQLite transaction; not a worker CLI subprocess',
            'old_administrator_bundles_enlarged': False,
            'original_installed_worker_gate_remains_separate': True,
        }
