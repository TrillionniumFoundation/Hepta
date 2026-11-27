"""Run complete original ordinary112 or direct76 caller scopes with lease selected.

Original modules, ordered identities, work and deadlines are preserved. Existing
administrator bundles are not enlarged, and subprocess poison is not inferred
from the parent process. This gate does not replace other owner/provider gates.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURE_NAME = 'tests/fixtures/hia_emission_original_73f1634/original-freeze.json'
FIXTURE_SHA256 = 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048'


def run_child(args):
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_service_lease import INPUTS
    initial_sources = file_digests()
    from tools.qualify_hia_emission_callers import admit_original_sources
    raw = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original complete caller inventory changed')
    original = json.loads(raw)
    caller_path = ROOT / 'tests/fixtures/hia_service_lease_original_r3/callers.json'
    if sha256(caller_path.read_bytes()).hexdigest() != '3e25dead1b040619826962762a40585dd956d280d2d19c9f0d4b6f2ee797df61':
        raise ValueError('complete lease caller source inventory differs')
    callers = json.loads(caller_path.read_bytes())
    modules = original['ordinary_modules'] if args.scope == 'ordinary' else callers['direct_modules']
    original_files = {record['path']: record['sha256'] for record in original['callers'].values()}
    terminal_evidence = []
    count_adjustments = admit_original_sources(ROOT, original, terminal_evidence=terminal_evidence)
    if len(terminal_evidence) != 1:
        raise ValueError('Lease callers require one complete original source admission')
    terminal_sources = terminal_evidence[0]['captured_files']
    direct_capture = {}
    for name, record in callers['direct_sources'].items():
        if (original_files.get(name) != record['sha256']
                or type(record['bytes']) is not int or record['bytes'] <= 0
                or record['old_inventory_matched'] is not True):
            raise ValueError('Lease direct authority differs from the original complete caller inventory')
        raw_source = (ROOT / name).read_bytes()
        actual = {'bytes': len(raw_source), 'sha256': sha256(raw_source).hexdigest()}
        if terminal_sources.get(name) != actual:
            raise ValueError('Lease direct source differs from its complete source admission: ' + name)
        direct_capture[name] = actual
    direct_source_admission = {
        'schema': 'hepta.hia.service-lease-direct-source-admission.v1',
        'authority': {'path': 'tests/fixtures/hia_service_lease_original_r3/callers.json',
            'sha256': '3e25dead1b040619826962762a40585dd956d280d2d19c9f0d4b6f2ee797df61'},
        'original_direct_sources': {name: {'bytes': row['bytes'], 'sha256': row['sha256']}
                                    for name, row in callers['direct_sources'].items()},
        'physical_direct_sources': direct_capture,
        'original_ordered_ids': list(callers['direct_ordered_ids']),
        'complete_original_source_admission': terminal_evidence[0],
        'original_test_budgets_changed': False,
        'prior_projection_is_physical_source': False,
    }
    if (len(original['ordinary_modules']) != 9 or original['ordinary_count'] != 112
            or len(original['ordinary_ordered_ids']) != 112
            or len(original['callers']) != 17
            or sum(len(row['recorded_ids']) for row in original['callers'].values()) != 240
            or original['separate_scope_count'] != 128):
        raise ValueError('the complete original caller modules differ')
    suite, planned = load_declared_suite(modules)
    planned = list(planned)
    declared_ids = original['ordinary_ordered_ids'] if args.scope == 'ordinary' else callers['direct_ordered_ids']
    if planned != declared_ids:
        raise ValueError('original complete caller inventory differs')

    def source_pins():
        paths = {*INPUTS, *original_files, *terminal_sources, FIXTURE_NAME,
                 'tests/fixtures/hia_service_lease_original_r3/callers.json',
                 'tools/qualify_hia_service_lease_callers.py',
                 'tools/qualify_hia_emission_callers.py'}
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                    for name in sorted(paths)}}

    before = source_pins()
    if (any(before.get(name) != digest for name, digest in initial_sources.items())
            or any(before.get(name) != row['sha256'] for name, row in terminal_sources.items())):
        raise ValueError('Lease source changed between admission, module loading and source seal')
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    cold_inputs = None
    if args.cold_report is not None:
        from tools.build_hia_service_lease import build
        from tools.hia_cold_compiler import read_cold_build_inputs
        cold_inputs = read_cold_build_inputs(args.cold_report)
        manifest = build(args.evidence / 'qualified',
            cold_inputs.compiler, args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_COMPLETE_LEASE_CALLER_MODULES'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_COMPLETE_LEASE_CALLER_MODULES'
    from hepta import hia_agent_service as api
    from hepta import hia_service_lease_native as native
    image = native.installed_service_lease(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, reference_calls = [], [], []
    entries, frame_counts, per_test_entries = Counter(), Counter(), defaultdict(Counter)
    active = ['outside-test']

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            active[0] = test.id()
            started.append(test.id())
            super().startTest(test)

        def stopTest(self, test):
            stopped.append(test.id())
            super().stopTest(test)
            active[0] = 'outside-test'

    initializer, actual_entry = native.ServiceLeaseFrame.__init__, image._entry

    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('ordinary caller selected another service lease image')
        initializer(frame, selected, *arguments, **keywords)
        frame_counts[active[0]] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = actual_entry(source, size, output, capacity, state, extent)
        if magic != native.REQUEST_MAGIC or code != native.OUTPUT_BYTES:
            raise AssertionError('service lease machine return differs from declared ABI')
        entries[str(event)] += 1
        per_test_entries[active[0]][str(event)] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(active[0])
        raise AssertionError('ordinary caller entered the retained Python service lease body')

    begin = time.monotonic()
    runtime_environment = {native.SELECTOR: str(manifest)}
    if args.scope == 'direct' and args.cold_report is not None:
        runtime_environment['HEPTA_HIA_SLOT_LEDGER_COLD_REPORT'] = str(
            args.cold_report.resolve(strict=True))
        runtime_environment['HEPTA_HIA_SLOT_LEDGER_EVIDENCE'] = str(args.evidence / 'slot-original')
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, runtime_environment))
        for name in ('ACQUIRE', 'LEASE', 'INVOKE', 'RELEASE'):
            stack.enter_context(patch.object(api, '_SERVICE_LEASE_' + name + '_REFERENCE', forbidden))
        stack.enter_context(patch.object(native.ServiceLeaseFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    if cold_inputs is not None:
        cold_inputs.unchanged()
    stable = source_pins() == before and all(
        sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in bundle.items())
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    passed = (clean and stable and started == stopped == planned and result.testsRun == len(declared_ids)
              and not reference_calls and sum(frame_counts.values()) > 0
              and all(entries[str(event)] > 0 for event in (0, 1, 2, 4)))
    report = {
        'schema': 'hepta.hia.service-lease-nine-ordinary-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'],
        'original_modules': modules, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_service_lease_frames': sum(frame_counts.values()),
        'frames_by_original_test': dict(frame_counts),
        'actual_native_event_counts': dict(entries),
        'native_event_counts_by_original_test': dict(per_test_entries),
        'native_image_sha256': image.image_sha256,
        'reference_calls': reference_calls, 'retained_service_lease_forbidden': True,
        'reference_poison_scope': 'test process; subprocesses inherit selector, not Python patches',
        'all_selected_modules_unfiltered': True, 'caller_selection': args.scope,
        'ordinary_nine_module_112_scope': args.scope == 'ordinary',
        'complete_direct_five_module_76_scope': args.scope == 'direct', 'original_test_budgets_changed': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'original_registry_count_assertion_adjustments': count_adjustments,
        'direct_source_admission': direct_source_admission,
        'separate_original_administrator_scope_gates': original['separate_scope_modules'],
        'other_owner_or_artifact_provider_gates_replaced_by_112': False,
        'ledger_SQL_provider_native_qualification_inferred': False,
        'acquire_and_release_original_with_control_selected': True,
        'resource_qualification_inferred_from_caller_success': False,
        'whole_project_dynamic_caller_closure_claimed': False,
        'whole_native_delivery_qualified': False,
    }
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in (
        'status', 'scope', 'actual_tests', 'wall_seconds', 'actual_service_lease_frames')}))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--scope', choices=('ordinary', 'direct'), required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--inside-supervisor', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside_supervisor:
        return run_child(args)
    from tests.hia_slot_operations_qualification_support import (
        run_owned, successful_exit, read_json, write_json, clean_environment)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    code = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
            'runpy.run_module("tools.qualify_hia_service_lease_callers",run_name="__main__")')
    command = [sys.executable, '-I', '-B', '-c', code, str(ROOT),
        '--inside-supervisor', '--scope', args.scope, '--evidence', str(args.evidence / 'complete-callers')]
    if args.cold_report is not None:
        command += ['--cold-report', str(args.cold_report.resolve(strict=True))]
    else:
        command += ['--development-manifest', str(args.development_manifest.resolve(strict=True))]
    result = run_owned(command, cwd=ROOT, directory=args.evidence / 'process',
        timeout_seconds=1800, environment=clean_environment())
    report_path = args.evidence / 'complete-callers/report.json'
    actual = read_json(report_path) if report_path.exists() else None
    passed = successful_exit(result) and actual is not None and actual['status'] == 'PASS'
    write_json(args.evidence / 'report.json', {'status': 'PASS' if passed else 'HOLD',
        'scope': args.scope, 'process': result, 'complete_callers': actual,
        'original_budget_seconds': 1800, 'whole_native_qualified': False})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
