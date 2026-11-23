"""Complete Slot controller qualification; immutable originals remain separate.

Source3 / Native6 are new gates. Native resource4/9, original Slot15, original
TX61 and ordinary112/128/Store130 scopes and all of their deadlines stay intact.
"""
from __future__ import annotations
import ast
import base64
from contextlib import closing
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zipfile

from tests.hia_slot_operations_qualification_support import (
    ORACLE_PREFIX, DERIVED_FILE, NAMES, admit_originals, admit_cases,
    canonical, clean_environment, pin, product_snapshot, read_json, regular_bytes,
    run_owned, sha, successful_exit, write_json)
from tests.hia_slot_operations_component_fixture import ComponentFixture

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'HEPTA_HIA_SLOT_OPERATIONS_'


def source_freeze(directory):
    from tools.build_hia_slot_operations import INPUTS
    path = directory / 'qualification-source-freeze.json'
    write_json(path, {'schema': 'hepta.slot-operations.qualification-source-freeze.v1',
        'files': product_snapshot(ROOT, INPUTS),
        'scope': 'complete explicit component INPUTS; native matching-cold additionally binds current full source'})
    return path, sha(regular_bytes(path))


def source_directory(label):
    evidence = os.environ.get(PREFIX + 'SOURCE_EVIDENCE')
    if evidence == '':
        raise ValueError('empty Slot source evidence')
    if evidence is None:
        temporary = tempfile.TemporaryDirectory(prefix='hia-slot-source-')
        directory = Path(temporary.name)
    else:
        base = Path(evidence).resolve()
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = None
        directory = Path(tempfile.mkdtemp(prefix=label + '-', dir=base))
    write_json(directory / 'invocation.json', {
        'parent_argv': sys.argv, 'pid': os.getpid(), 'runtime': sys.version,
        'enclosing_source_build_observations': os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS'),
        'new_complete_source_methods': 3})
    return temporary, directory


def complete_matrix(directory, backend, freeze, digest, manifest=None):
    from tools.qualify_hia_slot_operations_observations import main
    arguments = ['--root', str(ROOT), '--oracle-root', str(ROOT / ORACLE_PREFIX),
        '--derived-inputs', str(ROOT / DERIVED_FILE), '--product-freeze', str(freeze),
        '--product-freeze-sha256', digest, '--python', sys.executable,
        '--backend', backend, '--evidence', str(directory)]
    if manifest is not None:
        arguments += ['--manifest', str(manifest)]
    code = main(arguments)
    if code != 0:
        raise AssertionError('complete Slot original248/derived7574 comparison HOLD: ' + str(directory))
    report = read_json(directory / 'independent-readback/report.json')
    if report['status'] != 'PASS' or report['total_cases_per_backend'] != 7822:
        raise AssertionError('complete Slot finite readback not accepted')
    return report


def supplement(directory, backend, group, freeze, digest, manifest=None):
    from tools.read_hia_slot_operations_observations import compare, read_lines
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    expected_count = 84 if group == 'public' else 12
    groups = []
    expected_bytes = None
    expected_raw = {}
    for label, current in (('original-1', 'original'), ('original-2', 'original'), ('candidate', backend)):
        if label == 'candidate':
            write_json(directory / 'expectations-frozen.json', {
                'source': 'independent original functions only',
                'candidate_started': False, 'groups': expected_raw})
        target = directory / label
        command = [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_slot_operations_public_observer.py'),
            '--root', str(ROOT), '--oracle-root', str(ROOT / ORACLE_PREFIX),
            '--derived-inputs', str(ROOT / DERIVED_FILE), '--group', group, '--backend', current,
            '--product-freeze', str(freeze), '--product-freeze-sha256', digest,
            '--output', str(target / 'observation')]
        if current == 'native':
            command += ['--manifest', str(manifest)]
        result = run_owned(command, cwd=ROOT, directory=target, timeout_seconds=180)
        if not successful_exit(result):
            raise AssertionError('complete supplemental child HOLD: ' + str(target))
        report = read_json(target / 'observation/report.json')
        planned = read_json(target / 'observation/planned.json')
        raw = regular_bytes(target / 'observation/observations.jsonl')
        if (report['status'] != 'RECORDED' or report['failures']
                or report['planned'] != report['started'] or report['planned'] != report['stopped']
                or len(report['planned']) != expected_count
                or [row['id'] for row in read_lines(target / 'observation/observations.jsonl')] != report['planned']
                or report['planned'] != planned['ordered_ids']
                or type(report['pid']) is not int or report['pid'] != result['pid']
                or type(report['pgid']) is not int or report['pgid'] != result['pid']
                or type(report['ppid']) is not int or report['ppid'] != os.getpid()
                or report['source_before'] != report['source_after']
                or report['product_before'] != report['product_after']):
            raise AssertionError('supplemental full raw/report/supervisor binding differs')
        if label.startswith('original'):
            if expected_bytes is None:
                expected_bytes = raw
            elif raw != expected_bytes:
                raise AssertionError('fresh same-runtime supplemental originals are not stable')
            expected_raw[label] = {name: pin(target / 'observation' / name)
                                  for name in ('report.json', 'planned.json', 'observations.jsonl', 'raw-exceptions.jsonl')}
        else:
            for original, pins in expected_raw.items():
                for name, expected in pins.items():
                    if pin(directory / original / 'observation' / name) != expected:
                        raise AssertionError('candidate phase changed frozen original raw')
            counts = report['counts']
            if counts['retained_calls'] or (counts['returned_entries'] <= 0 if backend in ('native', 'vm')
                                            else counts['returned_entries'] != 0):
                raise AssertionError('selected/unselected public route execution differs')
        groups.append({'label': label, 'result': result, 'report': report,
                       'raw_sha256': sha(raw)})
    comparison = compare(directory / 'original-1/observation/observations.jsonl',
        directory / 'candidate/observation/observations.jsonl', directory / 'all-diffs.jsonl')
    write_json(directory / 'comparison.json', {'status': 'PASS' if comparison['different_cases'] == 0 else 'HOLD',
        'group': group, 'backend': backend, 'all_raw_fields_compared': True,
        'originals_before_candidate': True, 'cases': expected_count, 'comparison': comparison,
        'children': groups, 'new_inputs_not_replacements_for_248_or_7574': True})
    if comparison['different_cases']:
        raise AssertionError('supplemental complete original observations differ: ' + str(directory))
    return comparison


class SlotOperationsSourceTests(unittest.TestCase):
    def test_00_original_methods_actual_public_bindings_and_generated_profile(self):
        from hepta import hia_slot_operations_native as native
        from hepta import hia_slot_operations_selection as selection
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_native_helpers import HELPERS
        from tools import generate_hia_slot_operations as generator
        admit_originals(ROOT / ORACLE_PREFIX)
        self.assertEqual(len(admit_cases(ROOT / ORACLE_PREFIX, ROOT / DERIVED_FILE, 'original248')[0]), 248)
        self.assertEqual(len(admit_cases(ROOT / ORACLE_PREFIX, ROOT / DERIVED_FILE, 'derived7574')[0]), 7574)
        original = (ROOT / ORACLE_PREFIX / 'originals/NativeSlotLedgerStore.py.txt').read_bytes().rstrip(b'\n')
        raw = (ROOT / 'hepta/hia_slot_ledger_native.py').read_bytes()
        node = next(node for node in ast.parse(raw).body if isinstance(node, ast.ClassDef)
                    and node.name == 'NativeSlotLedgerStore')
        self.assertEqual(ast.get_source_segment(raw.decode(), node).encode(), original)
        self.assertEqual(tuple(NativeSlotLedgerStore._hia_slot_reference_methods), NAMES)
        for name in NAMES:
            self.assertIs(type(vars(NativeSlotLedgerStore)[name]), selection._SlotControlMethod)
            self.assertEqual(vars(NativeSlotLedgerStore)[name].name, name)
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_slot_operations_native', 'NativeSlotOperations'))
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        doc = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), 8192)
        for fn in doc['functions']:
            definitions = {value['name'] for value in fn['params']}
            self.assertLessEqual(len(fn['blocks']), 256)
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                definitions.update(value['name'] for value in block['params'])
                definitions.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(definitions), 2048)

    def test_01_complete_original248_and_derived7574_via_independent_VM(self):
        temporary, directory = source_directory('complete-VM')
        try:
            freeze, digest = source_freeze(directory)
            complete_matrix(directory / 'complete', 'vm', freeze, digest)
        finally:
            if temporary is not None:
                temporary.cleanup()

    def test_02_complete_unselected_public_and_handled_traceback_originals(self):
        temporary, directory = source_directory('unselected-public')
        try:
            freeze, digest = source_freeze(directory)
            supplement(directory / 'public', 'unselected', 'public', freeze, digest)
            supplement(directory / 'handled-traceback', 'unselected', 'handled-traceback', freeze, digest)
        finally:
            if temporary is not None:
                temporary.cleanup()


class SlotOperationsNativeTests(ComponentFixture, unittest.TestCase):
    def setUp(self):
        self.check_sources()
        self.case = self.folder / self._testMethodName
        self.case.mkdir(mode=0o700, exist_ok=False)

    def tearDown(self):
        self.check_sources()

    def test_00_complete_native_original248_and_derived7574_with_retained_poison(self):
        complete_matrix(self.case / 'complete', 'native', self.product_freeze,
                        self.product_freeze_sha256, self.controller)

    def test_01_actual_instance_class_overrides_namespace_and_signature(self):
        supplement(self.case / 'public', 'native', 'public', self.product_freeze,
                   self.product_freeze_sha256, self.controller)

    def test_02_normal_completion_after_retained_provider_traceback(self):
        supplement(self.case / 'handled-traceback', 'native', 'handled-traceback',
                   self.product_freeze, self.product_freeze_sha256, self.controller)

    def control(self, group):
        command = [sys.executable, '-I', '-B',
            str(ROOT / 'tests/hia_slot_operations_transport_controls.py'),
            '--manifest', str(self.controller), '--decision-manifest', str(self.decision), '--group', group,
            '--output', str(self.case / group / 'observation')]
        result = run_owned(command, cwd=ROOT, directory=self.case / group, timeout_seconds=60)
        self.assertTrue(successful_exit(result), result)
        report = read_json(self.case / group / 'observation/report.json')
        self.assertEqual(report['status'], 'PASS', report)
        self.assertEqual(report['pid'], result['pid'])
        self.assertEqual(report['pgid'], result['pid'])
        self.assertEqual(report['ppid'], os.getpid())
        self.assertEqual(report['actual_SQL'], 0)

    def test_03_actual_transport_four_dimensions_and_exception_identity(self):
        self.control('transport')
        report = read_json(self.case / 'transport/observation/transport.json')
        self.assertEqual(len(report['records']), 21)
        self.assertEqual([row['id'] for row in report['records']], report['planned'])
        self.assertEqual(report['four_dimensions'], ['return', 'request', 'output', 'state'])

    def test_04_explicit_scope_lazy_binding_stale_thread_pid_and_source_drift(self):
        self.control('selection')
        report = read_json(self.case / 'selection/observation/selection.json')
        self.assertGreater(report['actual_entries'], 0)
        self.assertEqual(report['retained_calls'], [])
        self.assertFalse(report['old_administrator_bundles_extended'])
        self.assertTrue(report['class_and_instance_same_actual_selected_image'])

    def test_05_actual_installed_worker_new_helper_and_unconfirmed_SQL(self):
        from tests.hia_slot_worker_terminal import SourceAuthority, assert_terminal, worker_profile
        authority = SourceAuthority(ROOT)
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from tools.hia_agent_native_qualification import exhaustive_u8_workload
        from hepta import hia_agent_service as api
        from hepta import hia_slot_operations_native as native
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
        staging = self.case / 'source'
        staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'

        def run(label, args, *, body=None, code=0):
            result = run_owned([sys.executable, '-B', *map(str, args)], cwd=self.case,
                directory=self.case / label, timeout_seconds=60, environment=environment, stdin=body)
            self.assertEqual(result['exit_code'], code, result)
            self.assertFalse(result['timed_out'], result)
            self.assertIsNone(result['interruption'], result)
            self.assertEqual(result['owned_cleanup']['after'], [], result)
            self.assertTrue(result['owned_cleanup']['reaped'], result)
            self.assertEqual(result['owned_cleanup']['signals'], [], result)
            return result, regular_bytes(self.case / label / 'stdout.log'), regular_bytes(self.case / label / 'stderr.log')

        from tests.hia_distribution_fixture import installed_wheel_path, ordinary_wheel
        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
            '--wheel-dir', self.case / 'wheels', ordinary_wheel(staging)])
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
            '--target', installed, wheel])
        profile = worker_profile(regular_bytes(installed / 'hepta/hia_agent_worker.py'))
        self.assertEqual(profile, authority.profile)
        checked = {}
        with zipfile.ZipFile(wheel) as archive:
            record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
            for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode())):
                raw = archive.read(name)
                if digest:
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode())
                    self.assertEqual(size, str(len(raw)))
                if name != record_name:
                    self.assertEqual(installed_wheel_path(installed, name).read_bytes(), raw, name)
                    checked[name] = sha(raw)
        resource = installed / 'hepta/_data/examples/hia_bootstrap/slot_operations.hepta'
        self.assertEqual(resource.read_bytes(), native.SOURCE.read_bytes())
        installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO(
            (installed / record_name).read_text()))}
        for name in ('hepta/hia_slot_operations_native.py', 'hepta/hia_slot_operations_selection.py',
                     'hepta/hia_slot_operation_series.py', 'hepta/hia_slot_operations_protocol.py',
                     'hepta/hia_slot_ledger_native.py', str(resource.relative_to(installed))):
            raw = installed_wheel_path(installed, name).read_bytes()
            self.assertEqual(installed_record[name], [
                'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode(), str(len(raw))])
        bundle = self.case / 'bundle.json'
        write_json(bundle, {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
            {'selector': 'HEPTA_HIA_SLOT_LEDGER_MANIFEST', 'manifest_path': str(self.decision),
             'manifest_sha256': sha(self.decision.read_bytes())},
            {'selector': native.SELECTOR, 'manifest_path': str(self.controller),
             'manifest_sha256': sha(self.controller.read_bytes())}]})
        bundle_sha = sha(bundle.read_bytes())

        def prepare():
            case = AgentToolCase('runTest')
            saved = dict(os.environ)
            try:
                os.environ.clear()
                os.environ.update(environment)
                with native_helpers_scope(str(bundle), bundle_sha):
                    case.setUp()
                    case.session.freeze(exhaustive_u8_workload())
                    arguments = case.session.arguments(target_slot='installed-slot-missing',
                        expected_current={'generation': '0', 'epoch': '0'},
                        retained_generation='0', reason='qualification missing slot remains rejected')
                    request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_rollback',
                        'arguments': arguments, 'profile_sha256': 'a' * 64,
                        'catalog_sha256': case.service.catalog_sha256}
                    request['request_sha256'] = api.digest(request)
                    case.service.close()
                return case, request
            finally:
                os.environ.clear()
                os.environ.update(saved)

        def state(case, request):
            key = api.digest({'tool': request['tool'], 'key': request['arguments']['request_key']})
            with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
                db.row_factory = sqlite3.Row
                row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
                return {'request': None if row is None else dict(row),
                    'slots': [tuple(row) for row in db.execute('SELECT * FROM slots ORDER BY name')],
                    'versions': [tuple(row) for row in db.execute('SELECT * FROM versions ORDER BY slot,generation')],
                    'leases': [tuple(row) for row in db.execute('SELECT * FROM leases ORDER BY id')],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        def worker(label, case, request, mode='normal', code=0):
            result, stdout, stderr = run(label, ['-I',
                ROOT / 'tests/hia_slot_operations_installed_observer.py',
                '--installed', installed, '--mode', mode,
                '--state-root', case.state_root, '--artifact-root', case.files_root,
                '--request-json-stdin', '--native-helpers-manifest', bundle,
                '--expected-native-helpers-sha256', bundle_sha], body=canonical(request), code=code)
            prefix = b'SLOT_OPERATIONS_INSTALLED='
            rows = [json.loads(line[len(prefix):]) for line in stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(rows), 1, stderr)
            self.assertEqual(rows[0]['retained_calls'], [])
            assert_terminal(self, rows[0]['terminal'], stderr, label, profile)
            return result, stdout, rows[0]

        observations = {}
        case, request = prepare()
        try:
            before = state(case, request)
            result, raw, counts = worker('normal', case, request)
            report, after = json.loads(raw), state(case, request)
            self.assertEqual(report['native_helpers_sha256'], bundle_sha)
            self.assertEqual(report['response']['status'], 'rejected', report)
            self.assertGreater(sum(counts['request'].values()), 0)
            self.assertGreater(counts['request_modes'].get('4', 0), 0)
            self.assertGreater(counts['request_modes'].get('2', 0), 0)
            self.assertGreater(counts['decision_request'], 0)
            self.assertEqual(counts['unknown_records'], 0)
            self.assertEqual(after['request']['state'], 'completed')
            for name in ('slots', 'versions', 'leases'):
                self.assertEqual(after[name], before[name])
            replay, replay_raw, replay_counts = worker('replay', case, request)
            self.assertEqual(json.loads(replay_raw)['response'], report['response'])
            self.assertEqual(sum(replay_counts['request'].values()), 0)
            self.assertEqual(state(case, request), after)
            observations['normal'] = {'response': report, 'counts': counts, 'before': before, 'after': after}
            observations['replay'] = {'response': json.loads(replay_raw), 'counts': replay_counts}
        finally:
            case.tearDown()
        case, request = prepare()
        try:
            before = state(case, request)
            result, raw, counts = worker('lost-SQL-ACK', case, request, 'lost-execute-ack',
                                         authority.profile['lost_ack_exit'])
            after = state(case, request)
            self.assertEqual(raw, b'')
            self.assertTrue(counts['lost_ack_injected'])
            self.assertGreater(counts['unknown_records'], 0)
            self.assertGreater(counts['unknown_resource_observations'], 0)
            self.assertEqual(counts['close_calls'], 0)
            self.assertEqual(after['request']['state'], 'running')
            self.assertIsNone(after['request']['response'])
            self.assertEqual(after['costs'], before['costs'])
            for name in ('slots', 'versions', 'leases'):
                self.assertEqual(after[name], before[name])
            replay, replay_raw, replay_counts = worker('unknown-replay', case, request)
            response = json.loads(replay_raw)
            replay_after = state(case, request)
            self.assertEqual(response['response']['status'], 'rejected')
            self.assertEqual(response['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(sum(replay_counts['request'].values()), 0)
            self.assertEqual(replay_after['request'], after['request'])
            self.assertEqual(replay_after['costs'], after['costs'] + 1)
            observations['lost_SQL_ACK'] = {'counts': counts, 'before': before, 'after': after}
            observations['unknown_replay'] = {'response': response, 'counts': replay_counts,
                                             'after': replay_after}
        finally:
            case.tearDown()
        authority.finish()
        write_json(self.case / 'installation.json', {'wheel': str(wheel), 'wheel_pin': pin(wheel),
            'terminal_source_authority': authority.summary(),
            'installed': str(installed), 'wheel_files_readback': checked,
            'installed_RECORD': pin(installed / record_name), 'bundle_sha256': bundle_sha,
            'controller_manifest': str(self.controller), 'decision_manifest': str(self.decision),
            'observations': observations,
            'scope': 'actual installed original worker; missing-slot SQL read/rejection and actual lost execute ACK',
            'all_fifteen_methods_in_worker_observed': False,
            'complete_old_bundles_expanded': False, 'whole_native_stack_qualified': False})


if __name__ == '__main__':
    unittest.main(verbosity=2)
