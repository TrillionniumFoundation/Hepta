"""Run the three complete original journal/budget/slot-ledger modules (61).

The transaction is explicitly selected in the test process. Original tests,
administrator bundles, fixture setup and inner deadlines are unchanged. The
112 ordinary and 130 artifact-provider gates remain separate commands.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURE = 'tests/fixtures/hia_store_transaction_separate_5bf.json'
FIXTURE_SHA256 = '7c6ebe725943cb69f20e8c2fc2c9aa9d59059bceeb47be7e9d21e6f32c285db8'
DEADLINE_SECONDS = 1800


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


_JOURNAL_CALLER = 'tests/test_hia_agent_journal_native.py'
_JOURNAL_HELPER = 'tests/hia_journal_installed_preparation.py'
_JOURNAL_HELPER_PIN = {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _bind_source_admission(proof, digests):
    for name, expected in proof['captured_files'].items():
        if digests.get(name) != expected['sha256']:
            raise ValueError('transaction Journal admission differs from source capture: ' + name)


def admit_separate_inventory(*, with_source_admission=False):
    raw = (ROOT / FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('independent complete 61-method inventory changed')
    captured = {FIXTURE: raw}
    value = json.loads(raw)
    adjustments = {}
    names = ['tests.test_hia_agent_journal_native', 'tests.test_hia_execution_budget_native',
             'tests.test_hia_slot_ledger_native']
    if (value['base_commit'] != '5bf69586b890706290c5fbfe93065ec0d3af40b1'
            or value['modules_in_requested_order'] != names or value['test_count'] != 61
            or len(value['ordered_ids']) != 61 or len(set(value['ordered_ids'])) != 61
            or [row['module'] for row in value['modules']] != names
            or [row['test_count'] for row in value['modules']] != [21, 25, 15]):
        raise ValueError('complete separate original module identity differs')
    from tests.hia_installed_distribution_history import journal_preparation_source, predecessor
    installed_predecessors = {}
    for record in value['modules']:
        physical = (ROOT / record['path']).read_bytes()
        captured[record['path']] = physical
        raw = predecessor(record['path'], physical)
        if raw != physical:
            installed_predecessors[record['path']] = _source_pin(raw)
        if len(raw) != record['bytes'] or sha256(raw).hexdigest() != record['sha256']:
            if record['path'] != _JOURNAL_CALLER:
                raise ValueError('complete original caller source differs: ' + record['path'])
            helper = (ROOT / _JOURNAL_HELPER).read_bytes()
            if _source_pin(helper) != _JOURNAL_HELPER_PIN:
                raise ValueError('transaction Journal preparation helper changed')
            from tests import hia_journal_installed_preparation as journal
            if Path(journal.__file__).read_bytes() != helper:
                raise ValueError('transaction imported a different Journal admission')
            proof = journal_preparation_source(ROOT, physical,
                                               {key: record[key] for key in ('bytes', 'sha256')})
            for name, expected in proof['captured_files'].items():
                consumed = (ROOT / name).read_bytes()
                checked = predecessor(name, consumed) if name == _JOURNAL_CALLER else consumed
                if (_source_pin(checked) != expected
                        or name in captured and captured[name] != consumed):
                    raise ValueError('transaction Journal source changed after admission: ' + name)
                captured[name] = consumed
            if captured[_JOURNAL_HELPER] != helper:
                raise ValueError('transaction Journal helper changed after import')
            adjustments[record['path']] = proof
        identities = [name for name in value['ordered_ids'] if name.startswith(record['module'] + '.')]
        if len(identities) != record['test_count']:
            raise ValueError('complete original method list differs: ' + record['module'])
    for name, source in captured.items():
        if (ROOT / name).read_bytes() != source:
            raise ValueError('transaction caller captured source changed: ' + name)
    proof = {
        'schema': 'hepta.hia.transaction-journal-preparation-source-admission.v1',
        'authority': {'path': FIXTURE, **_source_pin(captured[FIXTURE])},
        'original_ordered_ids': list(value['ordered_ids']), 'original_count': 61,
        'original_module_counts': [21, 25, 15], 'original_outer_seconds': DEADLINE_SECONDS,
        'reviewed_journal_installed_preparation_source_adjustments': adjustments,
        'installed_distribution_predecessors': installed_predecessors,
        'captured_files': {name: _source_pin(source) for name, source in captured.items()},
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }
    return (value, proof) if with_source_admission else value


def source_pins():
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_store_transaction import INPUTS
    paths = {*INPUTS, FIXTURE, 'tools/qualify_hia_store_transaction.py',
             *(row['path'] for row in admit_separate_inventory()['modules'])}
    return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in sorted(paths)}}


def execute_module(selector, manifest, report_path):
    from tools.run_hia_unittest_gate import load_declared_suite
    from hepta import hia_agent_store as api
    from hepta import hia_store_transaction_native as native
    original, source_admission = admit_separate_inventory(with_source_admission=True)
    if selector not in original['modules_in_requested_order']:
        raise ValueError('only a complete original module can be selected')
    suite, planned = load_declared_suite([selector])
    planned = list(planned)
    expected = [name for name in original['ordered_ids'] if name.startswith(selector + '.')]
    if planned != expected:
        raise ValueError('actual complete discovery differs from frozen static inventory')
    image = native.installed_store_transaction(str(manifest))
    before, started, stopped, outcomes = source_pins(), [], [], []
    _bind_source_admission(source_admission, before)
    frames, events, references = Counter(), Counter(), []
    active = ['outside-test']

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id());active[0] = test.id();super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id());super().stopTest(test);active[0] = 'outside-test'
        def addSuccess(self, test):
            outcomes.append([test.id(), 'ok']);super().addSuccess(test)
        def addFailure(self, test, error):
            outcomes.append([test.id(), 'failure']);super().addFailure(test, error)
        def addError(self, test, error):
            outcomes.append([test.id(), 'error']);super().addError(test, error)
        def addSkip(self, test, reason):
            outcomes.append([test.id(), 'skip']);super().addSkip(test, reason)

    initializer, entry = native.StoreTransactionFrame.__init__, image._entry
    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('original caller selected another transaction image')
        initializer(frame, selected, *arguments, **keywords)
        frames[active[0]] += 1
    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = entry(source, size, output, capacity, state, extent)
        if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
            raise AssertionError('actual transaction ABI differs')
        events[str(event)] += 1
        return code
    def forbidden(*arguments, **keywords):
        references.append(active[0])
        raise AssertionError('original caller entered retained transaction')
    forbidden.__wrapped__ = forbidden
    owner_binding = None
    begin = time.monotonic()
    with ExitStack() as scope:
        scope.enter_context(patch.dict(os.environ, {native.SELECTOR: str(manifest)}))
        if selector == 'tests.test_hia_slot_ledger_native':
            owner_binding = scope.enter_context(
                native.transaction_owner_scope(str(manifest), image))
        scope.enter_context(patch.object(api, '_STORE_TRANSACTION_REFERENCE', forbidden))
        scope.enter_context(patch.object(api.AgentStore, '_transaction_reference', forbidden))
        scope.enter_context(patch.object(native.StoreTransactionFrame, '__init__', counted_frame))
        scope.enter_context(patch.object(image, '_entry', counted_entry))
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
    after = source_pins()
    _bind_source_admission(source_admission, after)
    anomalies = {name: [row[0].id() for row in getattr(result, name)]
                 for name in ('errors', 'failures', 'skipped', 'expectedFailures')}
    anomalies['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
    passed = (planned == started == stopped and result.testsRun == len(expected)
              and result.wasSuccessful() and not any(anomalies.values())
              and before == after and not references)
    record = {'schema': 'hepta.hia.transaction-separate-module.v1',
        'status': 'PASS' if passed else 'HOLD', 'selector': selector,
        'caller_source_admission': source_admission,
        'planned': planned, 'started': started, 'stopped': stopped, 'outcomes': outcomes,
        'unstarted': [name for name in planned if name not in started],
        'unterminated': [name for name in started if name not in stopped],
        'testsRun': result.testsRun, 'anomalies': anomalies, 'elapsed_seconds': time.monotonic() - begin,
        'actual_transaction_frames': dict(frames), 'actual_native_events': dict(events),
        'reference_calls': references, 'native_image_sha256': image.image_sha256,
        'selection_channel': ('environment-plus-explicit-current-image-owner-scope'
                              if owner_binding is not None else 'original-environment-selection'),
        'owner_scope_manifest_sha256': (None if owner_binding is None
                                       else owner_binding.manifest_sha256),
        'original_environment_selection_retained': True,
        'original_clear_environments_intercepted': False,
        'source_before': before, 'source_after': after, 'source_unchanged': before == after,
        'original_methods_or_fixtures_or_deadlines_changed': False,
        'parent_process_poison_is_not_inherited_by_subprocesses': True,
        'every_original_test_claimed_to_enter_transaction': False}
    Path(report_path).write_bytes(encoded(record) + b'\n')
    return 0 if passed else 1


def development_journal(directory, compiler):
    from hepta import hia_agent_journal_native as native
    from tools.qualify_hia_selfhost import compile_stage
    from tools.build_hia_source_build import _check_pack_output
    directory.mkdir(mode=0o700)
    source, compiler_raw = native.SOURCE.read_bytes(), compiler.read_bytes()
    image, receipt = compile_stage(directory, 'agent-journal', compiler, source)
    raw = image.read_bytes()
    packed = _check_pack_output(receipt, (directory / 'agent-journal.output.bin').read_bytes(),
                               artifact=compiler_raw, source=source)
    if packed != raw or native.SOURCE.read_bytes() != source or compiler.read_bytes() != compiler_raw:
        raise ValueError('explicit development journal build custody changed')
    value = {'schema': native.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
             'image_path': image.name, 'image_sha256': sha256(raw).hexdigest(),
             'compiler_sha256': sha256(compiler_raw).hexdigest()}
    manifest = directory / 'manifest.json';manifest.write_bytes(encoded(value) + b'\n')
    (directory / 'development-build.json').write_bytes(encoded({
        'scope': 'EXPLICIT_DEVELOPMENT_NOT_COLD_QUALIFIED',
        'manifest': value, 'native_compile_receipt': receipt}) + b'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-compiler', type=Path)
    parser.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--execute-module', help=argparse.SUPPRESS)
    parser.add_argument('--manifest', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--stage-report', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    original, source_admission = admit_separate_inventory(with_source_admission=True)
    if args.execute_module:
        return execute_module(args.execute_module, args.manifest, args.stage_report)
    if args.cold_report is not None:
        if args.development_manifest is not None:
            raise ValueError('development image cannot override current cold')
        from tools.build_hia_json_preflight import admit_cold_build
        cold_raw = args.cold_report.read_bytes()
        from tools.hia_cold_compiler import read_cold_build_inputs; _cold_inputs = read_cold_build_inputs(args.cold_report); outer = _cold_inputs.report
        nested = _cold_inputs.location
        compiler = Path(nested['generations'][-1]['produced_image'])
        admit_cold_build(compiler.read_bytes(), cold_raw)
        scope = 'MATCHING_SOURCE_COLD_THREE_COMPLETE_TRANSACTION_CALLER_MODULES'
    else:
        compiler = args.development_compiler.resolve(strict=True)
        cold_raw = None
        scope = 'EXPLICIT_DEVELOPMENT_THREE_COMPLETE_TRANSACTION_CALLER_MODULES'
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    before, compiler_raw, begin = source_pins(), compiler.read_bytes(), time.monotonic()
    _bind_source_admission(source_admission, before)
    from tools.build_hia_store_transaction import build, INPUTS
    if args.development_manifest is None:
        manifest = build(args.evidence / 'transaction', compiler, args.cold_report,
                         development=args.cold_report is None)
    else:
        manifest = args.development_manifest.resolve(strict=True)
        build_record = json.loads((manifest.parent / 'build.json').read_bytes())
        expected = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
        if (build_record.get('scope') != 'DEVELOPMENT_COMPONENT'
                or build_record.get('component_inputs') != expected
                or build_record['manifest'] != json.loads(manifest.read_bytes())
                or build_record['manifest']['compiler_sha256'] != sha256(compiler_raw).hexdigest()):
            raise ValueError('supplied transaction development build is not this exact source')
    journal = None if args.cold_report else development_journal(args.evidence / 'agent-journal', compiler)
    pins = {str(path): sha256(path.read_bytes()).hexdigest()
            for parent in (manifest.parent, *(() if journal is None else (journal.parent,)))
            for path in sorted(parent.rglob('*')) if path.is_file()}
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    records = []
    actual_frames, actual_events = 0, Counter()
    for index, selector in enumerate(original['modules_in_requested_order'], 1):
        stem = str(index) + '-' + selector.rsplit('.', 1)[-1]
        report = args.evidence / (stem + '.json')
        selected = dict(environment)
        prefix = {'tests.test_hia_agent_journal_native': 'AGENT_JOURNAL',
                  'tests.test_hia_execution_budget_native': 'EXECUTION_BUDGET',
                  'tests.test_hia_slot_ledger_native': 'SLOT_LEDGER'}[selector]
        if args.cold_report:
            selected['HEPTA_HIA_' + prefix + '_COLD_REPORT'] = str(args.cold_report.resolve())
        elif journal is not None and prefix == 'AGENT_JOURNAL':
            selected['HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST'] = str(journal)
        else:
            selected['HEPTA_HIA_' + prefix + '_DEVELOPMENT_COMPILER'] = str(compiler)
        if prefix != 'AGENT_JOURNAL':
            selected['HEPTA_HIA_' + prefix + '_EVIDENCE'] = str(args.evidence / (stem + '-component'))
        choice = ['--cold-report', str(args.cold_report)] if args.cold_report else ['--development-compiler', str(compiler)]
        command = [sys.executable, '-B', str(Path(__file__).resolve()), *choice,
            '--evidence', str(args.evidence), '--execute-module', selector,
            '--manifest', str(manifest), '--stage-report', str(report)]
        remaining = DEADLINE_SECONDS - (time.monotonic() - begin)
        if remaining <= 0:
            records.append({'selector': selector, 'status': 'NOT_STARTED', 'reason': '1800 seconds exhausted'})
            continue
        process = subprocess.Popen(command, cwd=ROOT, env=selected, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        timed_out, group_killed, cleanup_unconfirmed = False, False, False
        try:
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as timeout:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL);group_killed = True
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as cleanup:
                stdout, stderr = cleanup.stdout or timeout.stdout or b'', cleanup.stderr or timeout.stderr or b''
                process.stdout.close();process.stderr.close();cleanup_unconfirmed = True
        (args.evidence / (stem + '.stdout')).write_bytes(stdout)
        (args.evidence / (stem + '.stderr')).write_bytes(stderr)
        value = json.loads(report.read_bytes()) if report.is_file() else None
        if value is not None:
            actual_frames += sum(value['actual_transaction_frames'].values())
            actual_events.update(value['actual_native_events'])
        passed = process.returncode == 0 and not timed_out and value is not None and value['status'] == 'PASS'
        records.append({'selector': selector, 'status': 'PASS' if passed else 'HOLD',
            'command': command, 'returncode': process.returncode, 'timed_out': timed_out,
            'process_group_killed': group_killed, 'cleanup_pipes_unconfirmed': cleanup_unconfirmed,
            'stage_report': str(report) if value is not None else None,
            'stage_report_sha256': sha256(report.read_bytes()).hexdigest() if value is not None else None})
    after = source_pins()
    _bind_source_admission(source_admission, after)
    stable = (before == after and compiler.read_bytes() == compiler_raw
              and all(sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in pins.items())
              and (cold_raw is None or args.cold_report.read_bytes() == cold_raw))
    passed = (stable and all(row['status'] == 'PASS' for row in records)
              and actual_frames > 0 and all(actual_events[str(event)] > 0 for event in (0, 1, 2, 4)))
    result = {'schema': 'hepta.hia.transaction-three-complete-callers.v1',
        'status': 'PASS' if passed else 'HOLD', 'scope': scope, 'stages': records,
        'caller_source_admission': source_admission,
        'original_inventory_sha256': FIXTURE_SHA256, 'original_ordered_ids': original['ordered_ids'],
        'original_count': 61, 'source_before': before, 'source_after': after,
        'source_compiler_and_builds_unchanged': stable, 'build_pins': pins,
        'compiler_sha256': sha256(compiler_raw).hexdigest(), 'deadline_seconds': DEADLINE_SECONDS,
        'actual_transaction_frames': actual_frames, 'actual_native_events': dict(actual_events),
        'positive_transaction_observations_required_for_aggregate_PASS': True,
        'elapsed_seconds': time.monotonic() - begin, 'original_inner_limits_changed': False,
        'original_administrator_bundles_enlarged': False,
        'ordinary_112_and_artifact_130_are_separate_gates': True,
        'whole_project_dynamic_caller_closure_claimed': False}
    (args.evidence / 'report.json').write_bytes(encoded(result) + b'\n')
    print(json.dumps({'status': result['status'], 'scope': scope, 'original_count': 61}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
