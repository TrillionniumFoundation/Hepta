"""Execute or read the two additional matching-cold UNPACK gates.

The full original Core116 runs once under its unchanged 180/3 process owner.
All eighteen additional controls use a separate 180/3 owner and the same new
cold caller images. Only their complete conjunction grants either new gate.
No development selector, split group or bootstrap compiler is accepted here.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tools import hia_core_unpack_gates as gates


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def owned_environment(environment, cold):
    from tools.qualify_hia_compiler_owner_ci import owned_environment as original_environment
    value = original_environment(environment, 'core', cold)
    for name in tuple(value):
        if name.startswith('HEPTA_') and ('DEVELOPMENT' in name or name.endswith(('_MANIFEST', '_BUNDLE'))):
            value.pop(name)
    value['HEPTA_HIA_CORE_UNPACK_COLD_REPORT'] = str(Path(cold).resolve(strict=True))
    return value


def execute_owned(part, cold, base, context):
    from tools import hia_selfhost_process_owner
    base = Path(base).resolve()
    gates.require(part in ('callers', 'component'), 'UNPACK phase differs')
    gates.require(Path(hia_selfhost_process_owner.__file__).resolve()
                  == ROOT / 'tools/hia_selfhost_process_owner.py', 'UNPACK actual process-owner source differs')
    runtime = gates.runtime_identity()
    gates.admit_dependencies(context)
    if part == 'component':
        # This phase cannot start on a report-only or split/development result.
        gates.inspect_owned('callers', cold, base, context)
        gates.inspect_callers(base, cold, context)
    base.mkdir(mode=0o700, parents=True, exist_ok=(part == 'component'))
    directory = base / (part + '-owner')
    directory.mkdir(mode=0o700, exist_ok=False)
    gates.require(not (base / part).exists(), 'preserve existing UNPACK product evidence')
    command = gates.owned_command(part, cold, base)
    result = {'schema': 'hepta.hia.core-unpack-owned-command.v1', 'status': 'HOLD',
        'part': part, 'command': command, 'cwd': str(ROOT), 'cold_inputs': context['identities'],
        'source_before': gates.source_now(context), 'source_after': None,
        'source_preserved': False, 'cold_inputs_preserved': False,
        'runtime_before': runtime, 'runtime_after': None}
    try:
        result['returned_owner'] = hia_selfhost_process_owner.run_owned(
            command, cwd=ROOT, env=owned_environment(os.environ, cold),
            stdout_path=directory / 'stdout.log', stderr_path=directory / 'stderr.log',
            receipt_path=directory / 'process-owner.json', qualification_seconds=180, cleanup_seconds=3)
        result['status'] = 'OWNED_COMMAND_RETURNED_PENDING_READBACK'
    except BaseException:
        result['status'] = 'HOLD'
        result['error'] = traceback.format_exc()
    finally:
        try:
            result['source_after'] = gates.source_now(context)
            result['source_preserved'] = result['source_before'] == result['source_after']
            result['cold_inputs_preserved'] = gates.cold_inputs(cold) == context
            result['runtime_after'] = gates.runtime_identity()
            gates.require(result['source_preserved'] and result['cold_inputs_preserved']
                          and result['runtime_after'] == runtime, 'UNPACK owned final identities changed')
        except BaseException:
            result['status'] = 'HOLD'
            result['final_identity_error'] = traceback.format_exc()
        write_new(directory / 'run-result.json', result)
    return gates.inspect_owned(part, cold, base, context)


def execute_component(cold, base, context):
    from hepta import hia_core_lowering_selection as core
    from hepta import hia_core_unpack_selection as selection
    from hepta import hia_core_unpack_native as primitive
    base = Path(base).resolve(strict=True)
    runtime = gates.runtime_identity()
    caller_owner = gates.inspect_owned('callers', cold, base, context)
    callers = gates.inspect_callers(base, cold, context)
    before = gates.component_binding(callers)
    ids = gates.expected_component_ids()
    directory = base / 'component'
    directory.mkdir(mode=0o700, exist_ok=False)
    report = {'schema': 'hepta.hia.core-unpack-composition.v1', 'status': 'HOLD',
        'scope': gates.COMPONENT_SCOPE, 'complete_source_methods': 2, 'complete_native_methods': 6,
        'complete_component_count': 18, 'complete_component_groups': [4, 6, 8],
        'all_component_ids': [*gates.FINITE_IDS['shim'], *gates.FINITE_IDS['finite-native'], *ids],
        'finite_groups': [],
        'cold_inputs': context['identities'], 'source_before': gates.source_now(context),
        'source_after': None, 'source_preserved': False, 'cold_inputs_preserved': False,
        'runtime_before': runtime, 'runtime_after': None,
        'caller_report': callers['producer'], 'caller_process': caller_owner,
        'build_bindings_before': before, 'build_bindings_after': None, 'builds_preserved': False,
        'native_step_semantics': gates.LEDGER_MEANING,
        'CPython_object_runtime_still_hosted': True, 'default_activated': False,
        'whole_native_delivery_qualified': False}
    started = time.monotonic()
    executed, current, returns = [], ['outside-test'], Counter()
    try:
        for label in ('shim', 'finite-native'):
            command = gates.finite_command(label, base, before)
            at = time.monotonic()
            process = subprocess.run(command, cwd=ROOT, env=owned_environment(os.environ, cold),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            row = {'label': label, 'command': command, 'returncode': process.returncode,
                   'seconds': time.monotonic() - at}
            report['finite_groups'].append(row)
            for name, raw in (('stdout', process.stdout), ('stderr', process.stderr)):
                path = directory / (label + '.' + name + '.log')
                with path.open('xb') as stream:
                    stream.write(raw)
                row[name] = gates.file_record(path)
            row['report'] = gates.json_file(directory / label / 'report.json')
            row['report_original'] = gates.file_record(directory / label / 'report.json')
            gates.inspect_finite(label, base, before, context, row)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(gates.COMPOSITION_MODULE)
        loaded = [test.id() for test in gates.previous.flatten(suite)]
        report.update(loaded_test_ids=loaded, chosen_test_ids=loaded, executed_test_ids=executed,
                      loader_errors=list(loader.errors), tests_loaded=len(loaded), tests_chosen=len(loaded))
        gates.require(not loader.errors and loaded == ids, 'complete composition eight discovery differs')
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id()
                executed.append(test.id())
                super().startTest(test)
        actual_step = primitive.UnpackSession._step
        def record_step(session, packet):
            status = actual_step(session, packet)
            returns[(current[0], session.image.image_sha256, status)] += 1
            return status
        environment = owned_environment(os.environ, cold)
        environment.update({core.SELECTOR: before['Core39']['bundle_files'][0]['path'],
            selection.SELECTOR: before['UNPACK']['files'][0]['path'],
            'HEPTA_HIA_CORE_UNPACK_FIXTURE_EVIDENCE': str(directory / 'fixture')})
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(primitive.UnpackSession, '_step', record_step), \
                (directory / 'unittest.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, unittest_successful=result.wasSuccessful())
        for name, attr in zip(gates.previous.previous.ANOMALIES,
                ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')):
            items = []
            for item in getattr(result, attr):
                if isinstance(item, tuple):
                    test, detail = item
                    items.append({'test': test.id(), 'detail': detail})
                else:
                    items.append({'test': item.id()})
            report[name] = items
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report['actual_UNPACK_step_returns'] = [dict(test=key[0], image_sha256=key[1], status=key[2], count=n)
                                               for key, n in sorted(returns.items())]
        try:
            after_callers = gates.inspect_callers(base, cold, context)
            report['build_bindings_after'] = gates.component_binding(after_callers)
            report['builds_preserved'] = before == report['build_bindings_after']
            gates.require(callers == after_callers
                          and caller_owner == gates.inspect_owned('callers', cold, base, context),
                          'composition changed its complete116 originals')
            report['source_after'] = gates.source_now(context)
            report['source_preserved'] = report['source_before'] == report['source_after']
            report['cold_inputs_preserved'] = gates.cold_inputs(cold) == context
            report['runtime_after'] = gates.runtime_identity()
            gates.require(report['runtime_after'] == runtime, 'composition interpreter changed')
            gates.validate_component(report, ids, before, context, callers['producer'])
            for label, row in zip(('shim', 'finite-native'), report['finite_groups']):
                gates.inspect_finite(label, base, before, context, row)
        except BaseException:
            report['status'] = 'HOLD'
            report['final_identity_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        write_new(directory / 'report.json', report)
    return report


def qualify_all(cold, base):
    """Full-harness API: two fixed owners, no extra enclosing 180-second fiction."""
    context = gates.cold_inputs(cold)
    runtime = gates.runtime_identity()
    gates.admit_dependencies(context)
    execute_owned('callers', cold, base, context)
    execute_owned('component', cold, base, context)
    inspection = gates.inspect_all(base, cold, context)
    gates.require(gates.cold_inputs(cold) == context and gates.runtime_identity() == runtime,
                  'UNPACK qualification final cold/runtime identity changed')
    return inspection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('owned-callers', 'owned-component', 'check', 'component-child'))
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if (args.operation == 'component-child') != (args.output is None):
        parser.error('only the internal composition child omits --output')
    if args.output is not None and (args.output.exists()
            or args.output.resolve().is_relative_to(args.evidence_dir.resolve())):
        parser.error('use a new gate output outside the immutable product evidence directory')
    # Cold and exact runtime admission precede any product output or native call.
    context = gates.cold_inputs(args.cold_report)
    gates.runtime_identity()
    gates.admit_dependencies(context)
    if args.operation == 'component-child':
        report = execute_component(args.cold_report, args.evidence_dir, context)
        return 0 if report['status'] == 'PASS' else 1
    started = time.monotonic()
    report = {'schema': 'hepta.hia.core-unpack-gates.v1', 'operation': args.operation,
        'status': 'HOLD', 'scope': gates.SCOPE, 'cold_inputs': context['identities'],
        'source_before': gates.source_now(context), 'source_after': None,
        'source_preserved': False, 'cold_inputs_preserved': False,
        'whole_native_delivery_qualified': False, 'gates': {name: False for name in gates.NEW_GATES}}
    try:
        if args.operation.startswith('owned-'):
            part = 'callers' if args.operation == 'owned-callers' else 'component'
            execute_owned(part, args.cold_report, args.evidence_dir, context)
        if args.operation == 'owned-callers':
            report['caller_readback'] = gates.inspect_callers(args.evidence_dir, args.cold_report, context)
            report['process_owner'] = gates.inspect_owned('callers', args.cold_report, args.evidence_dir, context)
            report['status'] = 'CALLERS_READBACK_ACCEPTED_PENDING_COMPOSITION'
        else:
            report['inspection'] = gates.inspect_all(args.evidence_dir, args.cold_report, context)
            report['gates'] = report['inspection']['gates']
            report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            report['source_after'] = gates.source_now(context)
            report['source_preserved'] = report['source_before'] == report['source_after']
            report['cold_inputs_preserved'] = gates.cold_inputs(args.cold_report) == context
            gates.require(report['source_preserved'] and report['cold_inputs_preserved'],
                          'UNPACK gate final source/cold drift')
            if report['status'] == 'PASS':
                gates.validate_gate_report(report, report['inspection'], context)
        except BaseException:
            report['status'] = 'HOLD'
            report['final_identity_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        write_new(args.output, report)
    print(json.dumps({'operation': args.operation, 'status': report['status'], 'output': str(args.output)}), flush=True)
    return 0 if report['status'] in ('PASS', 'CALLERS_READBACK_ACCEPTED_PENDING_COMPOSITION') else 1


if __name__ == '__main__':
    raise SystemExit(main())
