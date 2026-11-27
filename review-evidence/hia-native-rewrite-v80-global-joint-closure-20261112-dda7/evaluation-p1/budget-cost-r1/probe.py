"""One unchanged original case, selectively instrumented; no qualification.

This is deliberately a different environment and observer from the retained
CPython 3.14 full groups. Every public publisher call still performs its full
fresh admission. The original test, deadlines, and selected policy poisons are
unchanged. Timers add Python frames and therefore cannot establish performance
equivalence or clear an original failure.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
from hashlib import sha256
import importlib.metadata
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def write(path, value):
    with Path(path).open('xb') as stream:
        stream.write(wire(value))


def file_record(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'mode': oct(path.stat().st_mode & 0o7777)}


def snapshot(root):
    return {p.relative_to(root).as_posix(): file_record(p)
            for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and '.git' not in p.parts}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--evaluation-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    compiler = args.compiler.resolve(strict=True)
    manifest = args.evaluation_manifest.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(source))
    selected_env = {key: value for key, value in os.environ.items()
                    if key.startswith('HEPTA_')}
    if selected_env:
        raise ValueError('diagnostic requires an explicit empty initial HEPTA environment')
    original_test_id = ('tests.test_hia_agent_native_tools.NativeLifecycleTests.'
                        'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner')
    report = {'schema': 'hepta.hia.evaluation-budget-cost-diagnostic.v1',
              'scope': 'INSTRUMENTED_DEVELOPMENT_DIAGNOSTIC_NOT_QUALIFICATION',
              'python': sys.version, 'executable': sys.executable,
              'original_test_id': original_test_id,
              'original_total_wall_ms': 3000, 'original_native_wall_ms': 1000,
              'original_test_body_modified': False, 'old_results_reclassified': False,
              'public_fresh_source_admission_changed': False,
              'timing_observer_adds_frames_and_overhead': True,
              'original_qualifier_full_per_entry_observer_reused': False,
              'entry_observer': 'integer return counter only; no per-entry ABI decoding',
              'default_changed': False, 'current_cold': False, 'whole_native': False,
              'dependencies': {name: importlib.metadata.version(name)
                               for name in ('jsonschema', 'z3-solver')}}
    before = snapshot(source)
    inputs = {str(compiler): file_record(compiler), str(manifest): file_record(manifest)}
    manifest_value = json.loads(manifest.read_bytes())
    image_path = manifest.parent / manifest_value['image_path']
    inputs[str(image_path)] = file_record(image_path)
    write(output / 'SOURCE-BEFORE.json', before)
    write(output / 'INPUTS.json', inputs)
    rows, stack, public_records, contexts = [], [], [], []
    metrics = defaultdict(lambda: Counter())
    entries = Counter()
    mapped_images = []
    started_ns = time.monotonic_ns()
    clock_origin_ns = time.time_ns()
    report.update(monotonic_origin_ns=started_ns, realtime_origin_ns=clock_origin_ns)

    def measured(owner, name, label, *, describe=None, observe=None):
        original = getattr(owner, name)
        def wrapped(*arguments, **keywords):
            details = describe(arguments, keywords) if describe else {}
            row = {'index': len(rows), 'label': label, 'parent': stack[-1] if stack else None,
                   'detail': details, 'start_ns': time.monotonic_ns() - started_ns}
            rows.append(row)
            stack.append(row['index'])
            cpu = time.process_time_ns()
            value = None
            ok = False
            try:
                value = original(*arguments, **keywords)
                ok = True
                return value
            except BaseException as error:
                row['exception_type'] = type(error).__name__
                raise
            finally:
                row['cpu_ns'] = time.process_time_ns() - cpu
                row['elapsed_ns'] = time.monotonic_ns() - started_ns - row['start_ns']
                row['returned'] = ok
                if stack.pop() != row['index']:
                    raise AssertionError('diagnostic timing stack differs')
                if observe is not None and ok:
                    observe(value, row)
                value = None
        return patch.object(owner, name, wrapped)

    fixture = None
    try:
        from hepta import hia_agent_service as service
        from hepta import hia_agent_store as store
        from hepta import hia_agent_contract as contract
        from hepta import hia_program_native as backend
        from hepta import hia_checker_identity as checker
        from hepta import artifact_publication_native as publisher
        from hepta import hia_service_evaluation_native as evaluation
        from hepta import hia_execution_budget as budget_reference
        from tools import hia_selfhost_contract as source_contract
        from tools import build_hia_json_preflight as source_admission
        from tools import build_hia_artifact_publication as publisher_builder
        from tools import qualify_hia_service_evaluation as qualification
        from tests import test_hia_artifact_namespace_native as namespace
        from tests import test_hia_agent_native_tools as original_tests
        fixture = namespace.ArtifactNamespaceNativeTests
        fixture_root = output / 'namespace-fixture'
        with patch.dict(os.environ, {
            'HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER': str(compiler),
            'HEPTA_HIA_ARTIFACT_NAMESPACE_EVIDENCE': str(fixture_root)}):
            fixture_started = time.monotonic_ns()
            fixture.setUpClass()
            report['fixture_elapsed_ns'] = time.monotonic_ns() - fixture_started
        report['fixture_joint_build'] = json.loads((fixture.folder / 'joint-build.json').read_bytes())
        instance = fixture(methodName='test_actual_all_seven_apis_dedup_restart_and_original_namespace_authority')
        selected_inputs = (fixture.manifest, fixture.byte_manifest,
                           fixture.request_manifest, fixture.budget_manifest)
        for path in selected_inputs:
            inputs[str(path)] = file_record(path)
        test = unittest.defaultTestLoader.loadTestsFromName(original_test_id)
        if test.countTestCases() != 1:
            raise AssertionError('exact original case was not collected')
        raw_test = original_tests.NativeLifecycleTests.test_expired_evaluation_is_rejected_before_any_reference_or_native_runner
        report['original_test_code'] = {
            'module': raw_test.__module__, 'qualname': raw_test.__qualname__,
            'file': file_record(source / 'tests/test_hia_agent_native_tools.py')}

        def public_observe(value, row):
            response = {'tool': row['detail']['tool'], 'timing_index': row['index'],
                        'status': value.get('status')}
            if 'error' in value:
                response['error'] = value['error']
            result = value.get('result', {})
            if row['detail']['tool'] == 'hia_context' and isinstance(result, dict):
                response['context'] = result
            public_records.append(response)

        def digests_observe(value, row):
            row['source_count'] = len(value)
            row['declared_bytes_from_before_snapshot'] = sum(before[name]['bytes'] for name in value)
            row['all_digests_equal_before'] = all(before[name]['sha256'] == digest for name, digest in value.items())

        old_teardown = original_tests.AgentToolCase.tearDown
        def observed_teardown(case):
            try:
                contexts.extend(dict(row) for row in case.service.store.db.execute('SELECT id,created_ns FROM contexts'))
                write(output / 'EXISTING-CLIENT-RECORDS.json', case.client.records)
            finally:
                old_teardown(case)

        old_init = evaluation.NativeEvaluationImage.__init__
        def observed_image(image, raw, expected, namespace=None):
            old_init(image, raw, expected, namespace)
            entry = image._entry
            def counted(*arguments):
                result = entry(*arguments)
                entries['actual_returns'] += 1
                return result
            image._entry = counted
            mapped_images.append(image)

        def denied(*arguments, **keywords):
            raise AssertionError('diagnostic selected Evaluation entered retained policy')

        stream = io.StringIO()
        with ExitStack() as controls:
            controls.enter_context(instance.selected(joint=True))
            controls.enter_context(instance.old_namespace_forbidden(hashing=False, payload_io=False))
            controls.enter_context(patch.dict(os.environ, {evaluation.SELECTOR: str(manifest)}))
            controls.enter_context(patch.object(service.HIAAgentService, '_call_reference', side_effect=AssertionError('old request policy')))
            for old in (budget_reference._ReferenceExecutionBudgetStore, budget_reference._ReferenceBudgetClaim):
                controls.enter_context(patch.object(old, '__init__', side_effect=AssertionError('old budget policy')))
            for name in qualification.REFERENCE_METHODS:
                controls.enter_context(patch.object(service.HIAAgentService, name, denied))
            controls.enter_context(patch.object(original_tests.AgentToolCase, 'tearDown', observed_teardown))
            controls.enter_context(patch.object(evaluation.NativeEvaluationImage, '__init__', observed_image))
            controls.enter_context(measured(service.HIAAgentService, 'call', 'service.call',
                describe=lambda a,k: {'tool': a[1]}, observe=public_observe))
            for name in ('_hia_verify_reference', '_compile_reference', '_remaining_ms_reference', '_budget_reference'):
                controls.enter_context(measured(service.HIAAgentService, name, 'service.' + name))
            for owner, name, label in (
                (source_contract, 'file_digests', 'source.file_digests'),
                (source_contract, 'support_contract', 'source.support_contract'),
                (source_contract, 'validate_contract', 'source.validate_contract'),
                (source_admission, 'current_sources', 'source.current_sources'),
                (publisher_builder, 'current_sources', 'publication.current_sources'),
                (publisher, '_admitted_code', 'publication.admit_code'),
                (publisher, '_execute_native', 'publication.execute'),
                (contract, 'installation_manifest', 'installation.manifest'),
                (service, 'installation_manifest', 'service.installation_manifest'),
                (backend, '_implementation_hash', 'backend.implementation_hash'),
                (checker, 'checker_digest', 'checker.digest'),
                (checker, 'checker_source_identity', 'checker.source_identity'),
            ):
                controls.enter_context(measured(owner, name, label,
                    observe=digests_observe if label == 'source.file_digests' else None))
            controls.enter_context(measured(evaluation.NativeEvaluationService, 'finish', 'evaluation.finish',
                describe=lambda a,k: {'mode': a[1].mode}))
            controls.enter_context(measured(publisher.subprocess, 'run', 'subprocess.run',
                describe=lambda a,k: {'operation': str(a[0][1]) if len(a[0]) > 1 else ''}))
            run_started = time.monotonic_ns()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(test)
            report['original_case_elapsed_ns'] = time.monotonic_ns() - run_started
        with (output / 'ORIGINAL-TEST.log').open('x') as log:
            log.write(stream.getvalue())
        report.update(tests_run=result.testsRun,
            failures=[(test.id(), trace) for test, trace in result.failures],
            errors=[(test.id(), trace) for test, trace in result.errors],
            skips=[(test.id(), reason) for test, reason in result.skipped],
            expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
            unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
            observed_case_pass=result.wasSuccessful() and result.testsRun == 1 and not result.skipped,
            actual_machine_returns=entries['actual_returns'], actual_mappings=len(mapped_images),
            executable_mappings_unchanged=all(sha256(image._mapping[:]).hexdigest() == manifest_value['image_sha256']
                                              for image in mapped_images))
        report['status'] = 'OBSERVATION_COMPLETE'
    except BaseException:
        report.update(status='DIAGNOSTIC_HOLD', traceback=traceback.format_exc())
    finally:
        if fixture is not None and hasattr(fixture, 'temporary'):
            fixture.tearDownClass()
        for row in rows:
            row['exclusive_elapsed_ns'] = row['elapsed_ns']
            row['exclusive_cpu_ns'] = row['cpu_ns']
        for row in rows:
            if row['parent'] is not None:
                parent = rows[row['parent']]
                parent['exclusive_elapsed_ns'] -= row['elapsed_ns']
                parent['exclusive_cpu_ns'] -= row['cpu_ns']
        for row in rows:
            aggregate = metrics[row['label']]
            aggregate['calls'] += 1
            for key in ('elapsed_ns', 'exclusive_elapsed_ns', 'cpu_ns', 'exclusive_cpu_ns'):
                aggregate[key] += row[key]
            aggregate['source_files_derived'] += row.get('source_count', 0)
            aggregate['source_bytes_derived'] += row.get('declared_bytes_from_before_snapshot', 0)
        after = snapshot(source)
        write(output / 'SOURCE-AFTER.json', after)
        report.update(source_files=len(before), source_unchanged=before == after,
            changed_source_paths=sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name)),
            retained_inputs_unchanged=all(file_record(Path(path)) == value for path, value in inputs.items()),
            public_calls=public_records, contexts=contexts, metrics=dict(metrics),
            total_elapsed_ns=time.monotonic_ns() - started_ns)
        write(output / 'TIMINGS.json', rows)
        write(output / 'FINAL-INPUTS.json', inputs)
        write(output / 'REPORT.json', report)
    print(json.dumps({key: report.get(key) for key in ('status','tests_run','observed_case_pass',
                      'actual_machine_returns','source_unchanged','retained_inputs_unchanged')}), flush=True)
    return 0 if report['status'] == 'OBSERVATION_COMPLETE' and report['source_unchanged'] and report['retained_inputs_unchanged'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
