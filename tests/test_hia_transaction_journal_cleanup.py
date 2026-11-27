"""Four independent actual-image journal/transaction cleanup controls.

The unchanged original journal21/TX61 modules remain separate mandatory gates.
Fourteen fixed control IDs contain sixteen real service request attempts: the
two preentry controls each compare separate before/after-confirmed services.
Two additional original unknown-intent retries bring actual public calls to 18.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

from tests.hia_transaction_journal_controls import GROUPS, ALL_IDS, METHOD_GROUP_ORDER, TEST_FILES, encoded, source_pins

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_TRANSACTION_JOURNAL_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_TRANSACTION_JOURNAL_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_TRANSACTION_JOURNAL_EVIDENCE'
CHILD_SECONDS = 120
CLEANUP_SECONDS = 5


def clean_environment():
    return {name: value for name, value in os.environ.items()
            if name not in ('PYTHONPATH', 'PYTHONHOME') and not name.startswith('HEPTA_HIA_')}


def pins(directory):
    return {str(path.resolve()): sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(directory).rglob('*')) if path.is_file()}


def group_exists(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


class TransactionJournalCleanupNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if ((cold is None) == (development is None) or cold == '' or development == ''
                or evidence is None or evidence == ''):
            raise ValueError('choose matching cold or explicit DEV and a fresh owned evidence directory')
        from tools.qualify_hia_store_transaction import admit_separate_inventory
        original = admit_separate_inventory()
        if len(ALL_IDS) != 14 or len(set(ALL_IDS)) != 14 or original['test_count'] != 61:
            raise AssertionError('control or original complete-module identity differs')
        cls.root = Path(evidence).absolute()
        cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.before, cls.manifests, cls.built, cls.group_reports = source_pins(), {}, {}, {}
        cls.setup_complete = False
        cls.cold_path = None if cold is None else Path(cold).resolve(strict=True)
        cls.cold_raw = None if cold is None else cls.cold_path.read_bytes()
        if cold is not None:
            from tools.build_hia_json_preflight import admit_cold_build
            from tools.hia_cold_compiler import read_cold_build_inputs
            cls.cold_inputs = read_cold_build_inputs(cls.cold_path)
            if cls.cold_inputs.report_bytes != cls.cold_raw:
                raise ValueError('journal/TX cold report changed during admission')
            cls.compiler = cls.cold_inputs.compiler
            cls.compiler_raw = cls.cold_inputs.compiler_bytes
            admitted = admit_cold_build(cls.compiler_raw, cls.cold_raw)
            names = (*TEST_FILES, 'hepta/hia_agent_journal_native.py',
                     'hepta/hia_store_transaction_native.py', 'hepta/hia_native_delivery.py')
            if cls.cold_inputs.native:
                captured = {name: (ROOT / name).read_bytes() for name in names}
                if any(sha256(raw).hexdigest() != cls.before[name] for name, raw in captured.items()):
                    raise ValueError('journal/TX controls changed during authoring custody')
                cls.cold_inputs.capture_custody(captured, root=ROOT)
            else:
                for name in names:
                    if admitted.get(name) != cls.before[name]:
                        raise ValueError('new journal/TX controls are not part of this current cold: ' + name)
            cls.scope = 'MATCHING_SOURCE_COLD_COMPONENT'
        else:
            cls.compiler = Path(development).resolve(strict=True)
            cls.compiler_raw = cls.compiler.read_bytes()
            cls.scope = 'DEVELOPMENT_COMPONENT'
        cls.addClassCleanup(cls._finish_custody)
        (cls.root / 'source-before.json').write_bytes(encoded(cls.before) + b'\n')
        (cls.root / 'original-61-inventory.json').write_bytes(encoded(original) + b'\n')
        (cls.root / 'control-inputs.json').write_bytes(encoded({
            'schema': 'hepta.hia.transaction-journal-controls-inputs.v1',
            'groups': GROUPS, 'ordered_ids': ALL_IDS, 'control_count': 14,
            'request_attempts': 16, 'public_call_count': 18,
            'method_group_order': METHOD_GROUP_ORDER,
            'original_21_61_or_24_case_methods_modified': False}) + b'\n')
        from tools.build_hia_store_transaction import build as transaction_build
        tx_manifest = transaction_build(cls.root / 'transaction', cls.compiler, cls.cold_path,
                                        development=cold is None)
        if cold is not None:
            from tools.build_hia_json_preflight import build as journal_build
            journal_manifest = journal_build(cls.root / 'agent-journal', cls.compiler,
                                             cls.cold_path, candidate='agent-journal')
        else:
            from tools.qualify_hia_store_transaction import development_journal
            journal_manifest = development_journal(cls.root / 'agent-journal', cls.compiler)
        cls.manifests = {'agent_journal': str(journal_manifest.resolve(strict=True)),
                         'store_transaction': str(tx_manifest.resolve(strict=True))}
        for path in cls.manifests.values():
            manifest = json.loads(Path(path).read_bytes())
            if manifest['compiler_sha256'] != sha256(cls.compiler_raw).hexdigest():
                raise AssertionError('journal and TX are not built by this same compiler attempt')
            if not Path(path).is_relative_to(cls.root):
                raise AssertionError('a control reused an external image build')
        cls.built = {**pins(cls.root / 'transaction'), **pins(cls.root / 'agent-journal')}
        cls.setup_complete = True
        (cls.root / 'manifests.json').write_bytes(encoded(cls.manifests) + b'\n')
        (cls.root / 'build-pins.json').write_bytes(encoded(cls.built) + b'\n')
        if source_pins() != cls.before or cls.compiler.read_bytes() != cls.compiler_raw:
            raise AssertionError('source or compiler changed while building the two control images')

    @classmethod
    def _finish_custody(cls):
        after = source_pins()
        cold_stable = cls.cold_path is None or (
            cls.cold_path.read_bytes() == cls.cold_raw
            and all(path.read_bytes() == raw for path, raw in cls.cold_inputs.files))
        stable = (after == cls.before and cls.compiler.read_bytes() == cls.compiler_raw
                  and cold_stable and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                                          for path, digest in cls.built.items()))
        record = {'schema': 'hepta.hia.transaction-journal-controls-custody.v1',
                  'scope': cls.scope, 'setup_complete': cls.setup_complete,
                  'matching_cold_report': None if cls.cold_path is None else str(cls.cold_path),
                  'cold_report_sha256': None if cls.cold_raw is None else sha256(cls.cold_raw).hexdigest(),
                  'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
                  'manifests': cls.manifests, 'build_files': cls.built,
                  'source_before': cls.before, 'source_after': after,
                  'source_compiler_cold_and_build_unchanged': stable,
                  'group_reports': cls.group_reports,
                  'planned_control_ids': ALL_IDS, 'planned_control_count': 14,
                  'planned_faulted_request_attempts': 16, 'planned_public_call_count': 18,
                  'method_group_order': METHOD_GROUP_ORDER,
                  'original_21_and_61_are_separate_required_gates': True,
                  'test_result_owned_by_complete_outer_runner': True,
                  'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if not stable:
            raise AssertionError('journal/TX controls source, cold report, compiler or build changed')

    def child(self, group):
        directory = self.root / self._testMethodName
        directory.mkdir()
        script = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'from tests.hia_transaction_journal_controls import run_group;'
                  'run_group(*sys.argv[1:])')
        command = [sys.executable, '-I', '-B', '-c', script, str(ROOT), group,
                   str(directory), encoded(self.manifests).decode(),
                   str(self.root / 'source-before.json')]
        started_ns, begin = time.time_ns(), time.monotonic()
        command_record = {'schema': 'hepta.hia.transaction-journal-control-command.v1',
                          'test_id': self.id(), 'group': group, 'command': command,
                          'cwd': str(directory), 'parent_pid': os.getpid(),
                          'started_time_ns': started_ns, 'timeout_seconds': CHILD_SECONDS,
                          'cleanup_seconds': CLEANUP_SECONDS, 'owned_process_group': True}
        # Persist the command before Popen. Every operation after a successful
        # spawn is inside the same cleanup boundary, including evidence writes.
        (directory / 'command.json').write_bytes(encoded(command_record) + b'\n')
        process = None
        stdout = stderr = b''
        timed_out, killed, reaped, absent = False, False, False, False
        failure = cleanup_failure = None
        cleanup_deadline = None

        def kill_and_reap():
            nonlocal stdout, stderr, killed, reaped, absent, cleanup_deadline
            if cleanup_deadline is None:
                cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            try:
                os.killpg(process.pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                pass
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            stdout, stderr = process.communicate(timeout=remaining)
            reaped = process.poll() is not None
            absent = not group_exists(process.pid)

        try:
            process = subprocess.Popen(command, cwd=directory, env=clean_environment(),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=CHILD_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_and_reap()
            reaped = process.poll() is not None
            absent = not group_exists(process.pid)
        except BaseException as error:
            failure = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            try:
                if process is not None and (process.poll() is None or group_exists(process.pid)):
                    kill_and_reap()
            except BaseException as error:
                cleanup_failure = type(error).__name__ + ': ' + str(error)
            finally:
                if process is not None:
                    reaped = process.poll() is not None
                    absent = not group_exists(process.pid)
                (directory / 'stdout.log').write_bytes(stdout)
                (directory / 'stderr.log').write_bytes(stderr)
                result = {'schema': 'hepta.hia.transaction-journal-control-process.v1',
                          'test_id': self.id(), 'group': group,
                          'child_pid': None if process is None else process.pid,
                          'returncode': None if process is None else process.returncode,
                          'timed_out': timed_out, 'owned_group_killed': killed,
                          'child_reaped': reaped, 'owned_group_absent': absent,
                          'supervisor_exception': failure, 'cleanup_exception': cleanup_failure,
                          'started_time_ns': started_ns, 'ended_time_ns': time.time_ns(),
                          'elapsed_seconds': time.monotonic() - begin,
                          'stdout_sha256': sha256(stdout).hexdigest(),
                          'stderr_sha256': sha256(stderr).hexdigest()}
                (directory / 'process.json').write_bytes(encoded(result) + b'\n')
                observation_path = directory / 'observations.json'
                if observation_path.is_file():
                    self.group_reports[group] = {'path': str(observation_path),
                        'sha256': sha256(observation_path.read_bytes()).hexdigest(),
                        'validated_by_parent': False,
                        'returncode': None if process is None else process.returncode}
        self.assertIsNotNone(process)
        self.assertFalse(timed_out, stdout + stderr)
        self.assertIsNone(cleanup_failure)
        self.assertTrue(reaped and absent)
        self.assertEqual(process.returncode, 0, stdout.decode(errors='backslashreplace')
                         + stderr.decode(errors='backslashreplace'))
        raw = (directory / 'observations.json').read_bytes()
        value = json.loads(raw)
        expected = [case['id'] for case in GROUPS[group]]
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['planned'], expected)
        self.assertEqual(value['started'], expected)
        self.assertEqual(value['stopped'], expected)
        self.assertEqual(value['failures'], [])
        self.assertEqual(value['control_count'], len(expected))
        self.assertEqual(value['request_attempts'], 4 if group == 'preentry' else len(expected))
        self.assertEqual(value['public_call_count'], 6 if group == 'preentry' else len(expected))
        self.assertEqual(value['source_before'], self.before)
        self.assertEqual(value['source_after'], self.before)
        self.assertIs(value['source_unchanged'], True)
        self.group_reports[group] = {'validated_by_parent': True,
                                    'path': str(directory / 'observations.json'),
                                    'sha256': sha256(raw).hexdigest(), 'controls': len(expected),
                                    'request_attempts': value['request_attempts'],
                                    'public_call_count': value['public_call_count']}

    def test_preentry_ack_rollback_confirms_before_journal_loss_publication(self):
        self.child('preentry')

    def test_actual_journal_ack_handoff_loss_still_fences_native_transaction(self):
        self.child('native')

    def test_suppressed_unconfirmed_sql_ack_cannot_continue_or_finalize(self):
        self.child('suppressed')

    def test_cleanup_replacement_or_native_loss_cannot_erase_pending_sql_ack(self):
        self.child('cleanup')
