"""Complete original gates and explicit shared-delivery controls.

No original assertion, input, test, or inner timeout is changed. A selected
group retains one 1,800-second outer allowance. DEV never supplies cold proof.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
DEADLINE_SECONDS = 1800
PREFIXES = ('SERVICE_CONTEXT', 'STORE_LIFECYCLE', 'COST_LEDGER', 'EVALUATION',
            'NATIVE_BUILD_ADMISSION', 'NATIVE_BUILD_DISPATCH', 'EMISSION',
            'NATIVE_TRANSPORT', 'EXECUTION_BUDGET', 'CANDIDATE_BUDGET', 'AGENT_JOURNAL', 'NATIVE_DELIVERY')
CALLERS = ('service_context', 'cost_ledger', 'evaluation', 'native_build_admission', 'emission', 'agent_journal')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def child(selector, report_path, original):
    import unittest
    from tools.run_hia_unittest_gate import load_declared_suite
    from tests.test_hia_native_delivery import source_pins
    suite, planned = load_declared_suite([selector])
    planned = list(planned)
    expected = original['component_ordered_ids'].get(selector, planned)
    if planned != expected:
        raise ValueError('complete original ordered inventory differs: ' + selector)
    before, started, stopped, outcomes = source_pins(), [], [], []
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            started.append(test.id()); super().startTest(test)
        def stopTest(self, test):
            stopped.append(test.id()); super().stopTest(test)
        def addSuccess(self, test):
            outcomes.append([test.id(), 'ok']); super().addSuccess(test)
        def addFailure(self, test, error):
            outcomes.append([test.id(), 'failure']); super().addFailure(test, error)
        def addError(self, test, error):
            outcomes.append([test.id(), 'error']); super().addError(test, error)
        def addSkip(self, test, reason):
            outcomes.append([test.id(), 'skip']); super().addSkip(test, reason)
        def addExpectedFailure(self, test, error):
            outcomes.append([test.id(), 'expected_failure']); super().addExpectedFailure(test, error)
        def addUnexpectedSuccess(self, test):
            outcomes.append([test.id(), 'unexpected_success']); super().addUnexpectedSuccess(test)
    begin = time.monotonic()
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
    after = source_pins()
    anomalies = {name: [row[0].id() for row in getattr(result, name)]
                 for name in ('errors', 'failures', 'skipped', 'expectedFailures')}
    anomalies['unexpectedSuccesses'] = [test.id() for test in result.unexpectedSuccesses]
    passed = (bool(planned) and planned == started == stopped and result.testsRun == len(planned)
              and not any(anomalies.values()) and result.wasSuccessful() and before == after)
    Path(report_path).write_bytes(encoded({'schema': 'hepta.hia.native-delivery-stage.v1',
        'selector': selector, 'status': 'PASS' if passed else 'HOLD', 'planned': planned,
        'started': started, 'stopped': stopped, 'outcomes': outcomes, 'testsRun': result.testsRun,
        'unstarted': [name for name in planned if name not in started],
        'unterminated': [name for name in started if name not in stopped], 'anomalies': anomalies,
        'source_before': before, 'source_after': after, 'source_unchanged': before == after,
        'original_registry_count_adjustments': original['registry_count_adjustments'],
        'elapsed_seconds': time.monotonic() - begin, 'original_deadlines_changed': False}) + b'\n')
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=('focused', 'components', 'callers'), required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-compiler', type=Path)
    parser.add_argument('--development-manifests', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--execute-module', help=argparse.SUPPRESS)
    parser.add_argument('--stage-report', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    from tests.test_hia_native_delivery import admit_originals, source_pins, clean_environment
    original = admit_originals()
    if args.execute_module:
        return child(args.execute_module, args.stage_report, original)
    cold_bytes = None
    if args.cold_report is not None:
        from tools.build_hia_json_preflight import admit_cold_build
        cold_bytes = args.cold_report.read_bytes()
        outer = json.loads(cold_bytes)
        nested = json.loads(Path(outer['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        admit_cold_build(compiler.read_bytes(), cold_bytes)
        scope = 'MATCHING_SOURCE_COLD_D0_D3_' + args.group.upper()
    else:
        compiler = args.development_compiler.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_D0_D3_' + args.group.upper()
    manifests = {}
    if args.development_manifests is not None:
        if args.cold_report is not None:
            raise ValueError('development manifests cannot override matching cold custody')
        manifests = json.loads(args.development_manifests.read_bytes())
    if args.development_compiler is not None and args.group != 'focused' and not manifests:
        raise ValueError('DEV original gates require the actual same-source focused manifests')
    compiler_raw, manifest_pins = compiler.read_bytes(), {}
    for owner, name in manifests.items():
        path = Path(name).resolve(strict=True)
        raw = path.read_bytes(); value = json.loads(raw)
        image = path.parent / value['image_path']
        source = (ROOT / ('examples/hia_bootstrap/' + owner + '.hepta')).read_bytes()
        if (value['source_sha256'] != sha256(source).hexdigest()
                or value['compiler_sha256'] != sha256(compiler_raw).hexdigest()
                or value['image_sha256'] != sha256(image.read_bytes()).hexdigest()):
            raise ValueError('same-source DEV manifest mismatch: ' + owner)
        manifest_pins[str(path)], manifest_pins[str(image)] = sha256(raw).hexdigest(), value['image_sha256']
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    before, records, begin = source_pins(), [], time.monotonic()
    if args.group == 'focused':
        stages = [('tests.test_hia_native_delivery', None)]
    elif args.group == 'components':
        stages = [(name, None) for name in original['component_modules']]
    else:
        stages = [('tools/qualify_hia_' + name + '_callers.py', name) for name in CALLERS]
    environment = dict(clean_environment(), PYTHONDONTWRITEBYTECODE='1')
    for prefix in PREFIXES:
        key = 'HEPTA_HIA_' + prefix
        environment[key + ('_COLD_REPORT' if args.cold_report is not None else '_DEVELOPMENT_COMPILER')] = str(
            args.cold_report.resolve() if args.cold_report is not None else compiler)
        environment[key + '_EVIDENCE'] = str(args.evidence / ('component-' + prefix.lower()))
    for index, (selector, owner) in enumerate(stages, 1):
        remaining = DEADLINE_SECONDS - (time.monotonic() - begin)
        if remaining <= 0:
            records.append({'selector': selector, 'status': 'NOT_STARTED', 'reason': 'outer allowance exhausted'})
            continue
        stem = f'{index:02d}-' + selector.replace('/', '_').replace('.', '_')
        report_path = args.evidence / (stem + '.json')
        selection = ['--cold-report', str(args.cold_report)] if args.cold_report is not None else ['--development-compiler', str(compiler)]
        if owner is None:
            command = [sys.executable, '-B', str(Path(__file__).resolve()), '--group', args.group,
                       '--evidence', str(args.evidence), '--execute-module', selector,
                       '--stage-report', str(report_path), *selection]
        elif owner == 'agent_journal':
            report_path = args.evidence / 'agent-journal-callers.json'
            selection = ['--cold-report', str(args.cold_report)] if args.cold_report is not None else ['--manifest', manifests[owner], '--development']
            command = [sys.executable, '-B', str(ROOT / selector), '--output', str(report_path), *selection]
        else:
            report_path = args.evidence / (owner + '-callers') / 'report.json'
            selection = ['--cold-report', str(args.cold_report)] if args.cold_report is not None else ['--development-manifest', manifests[owner]]
            command = [sys.executable, '-B', str(ROOT / selector), '--evidence', str(report_path.parent), *selection]
        stage_environment = dict(environment)
        if manifests and selector == 'tests.test_hia_agent_journal_native':
            stage_environment['HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST'] = manifests['agent_journal']
        process = subprocess.Popen(command, cwd=ROOT, env=stage_environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        group_killed = False
        cleanup_pipes_unconfirmed = False
        try:
            stdout, stderr = process.communicate(timeout=remaining)
            code, timed_out = process.returncode, False
        except subprocess.TimeoutExpired as error:
            # A group created by this supervisor contains its original gate and
            # ordinary descendants. A timeout never widens the original budget.
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_killed = True
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as cleanup:
                # An escaped session retaining a pipe is not a cleanup PASS.
                # Do not let its pipe turn the failed supervisor into a hang.
                stdout = cleanup.stdout or error.stdout or b''
                stderr = cleanup.stderr or error.stderr or b''
                process.stdout.close()
                process.stderr.close()
                cleanup_pipes_unconfirmed = True
            code, timed_out = process.returncode, True
        (args.evidence / (stem + '.stdout')).write_bytes(stdout)
        (args.evidence / (stem + '.stderr')).write_bytes(stderr)
        value = json.loads(report_path.read_bytes()) if report_path.is_file() else None
        passed = code == 0 and not timed_out and value is not None and value.get('status') == 'PASS'
        records.append({'selector': selector, 'command': command, 'supervised_pid': process.pid,
                        'status': 'PASS' if passed else 'HOLD', 'exit_code': code,
                        'journal_development_manifest_environment': stage_environment.get('HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST'),
                        'timed_out': timed_out, 'report': str(report_path), 'report_present': value is not None,
                        'owned_process_group_killed_on_timeout': group_killed,
                        'cleanup_pipes_unconfirmed': cleanup_pipes_unconfirmed,
                        'escaped_process_sessions_qualified': False,
                        'stdout_sha256': sha256(stdout).hexdigest(), 'stderr_sha256': sha256(stderr).hexdigest()})
    after = source_pins()
    stable = (before == after and compiler.read_bytes() == compiler_raw
              and (args.cold_report is None or args.cold_report.read_bytes() == cold_bytes)
              and all(sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in manifest_pins.items()))
    passed = stable and bool(records) and all(row['status'] == 'PASS' for row in records)
    (args.evidence / 'report.json').write_bytes(encoded({'schema': 'hepta.hia.native-delivery-gate.v1',
        'scope': scope, 'status': 'PASS' if passed else 'HOLD', 'stages': records,
        'outer_allowance_seconds': DEADLINE_SECONDS, 'elapsed_seconds': time.monotonic() - begin,
        'source_before': before, 'source_after': after, 'source_and_build_unchanged': stable,
        'compiler_sha256': sha256(compiler_raw).hexdigest(), 'manifest_pins': manifest_pins,
        'original_registry_count_adjustments': original['registry_count_adjustments'],
        'original_assertions_inputs_and_timeouts_changed': False, 'whole_native_delivery_qualified': False}) + b'\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
