"""Execute the complete ELF component or independently read compiler-owner gates.

Other compiler qualifiers retain their original complete component/caller runs.
This adapter never substitutes a development manifest for a cold fixture.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tools import hia_compiler_owner_gates as gates


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def component_environment(environment, cold, fixture):
    value = dict(environment)
    for config in gates.OWNERS.values():
        value.pop(config['prefix'] + config['development_suffix'], None)
    value['HEPTA_HIA_MACHINE_ELF_COLD_REPORT'] = str(Path(cold).resolve(strict=True))
    value['HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE'] = str(Path(fixture).resolve())
    return value


def execute_elf_component(evidence, cold, context, expected):
    evidence = Path(evidence).resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 'hepta.hia.compiler-owner-component.v1', 'owner': 'elf',
        'status': 'HOLD', 'scope': 'MATCHING_SOURCE_COLD_COMPONENT',
        'source_before': context['source_manifest'], 'source_after': None,
        'source_preserved': False, 'cold_inputs_preserved': False,
        'cold_inputs': context['identities'], 'modules': expected['modules'],
        'python': sys.version, 'executable': sys.executable,
        'build_bindings_before': {}, 'build_bindings_after': {},
        'builds_preserved': False}
    started = time.monotonic()
    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(expected['modules'])
        loaded = [test.id() for test in gates.flatten(suite)]
        gates.require(not loader.errors and loaded == expected['ids'], 'complete ELF module discovery changed')
        executed = []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        module = sys.modules[gates.OWNERS['elf']['module']]
        before = {}
        report['build_bindings_before'] = before
        report.update(loaded_test_ids=loaded, chosen_test_ids=loaded,
                      executed_test_ids=executed, loader_errors=list(loader.errors))
        def wrapped_setup(cls, original, class_name):
            original()
            gates.require(cls.scope == 'MATCHING_SOURCE_COLD_BUILD',
                          'ELF component attempted a development fixture')
            gates.require(class_name not in before, 'ELF class fixture captured twice')
            before[class_name] = gates.single_build('elf', cls.manifest.parent, context)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,
                component_environment(os.environ, cold, evidence / 'fixture'), clear=True))
            for class_name in ('MachineElfNativeTests', 'MachineElfBoundaryTests'):
                cls = getattr(module, class_name)
                original = cls.setUpClass
                def setup(actual_cls, _old=original, _name=class_name):
                    return wrapped_setup(actual_cls, _old, _name)
                stack.enter_context(patch.object(cls, 'setUpClass', classmethod(setup)))
            log = stack.enter_context((evidence / 'unittest.log').open('x'))
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
        report.update(loaded_test_ids=loaded, chosen_test_ids=loaded,
            executed_test_ids=executed, tests_loaded=len(loaded), tests_chosen=len(loaded),
            tests_run=result.testsRun, loader_errors=list(loader.errors),
            unittest_successful=result.wasSuccessful())
        for name, attr in zip(gates.previous.ANOMALIES,
                ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')):
            items = []
            for item in getattr(result, attr):
                if isinstance(item, tuple):
                    test, detail = item
                    items.append({'test': test.id(), 'detail': detail})
                else:
                    items.append({'test': item.id()})
            report[name] = items
        report['build_bindings_before'] = before
        after = gates.elf_component_builds(evidence, context)
        report['build_bindings_after'] = after
        report['builds_preserved'] = before == after
        report['runtime_observations'] = gates.inspect_elf_observations(evidence, context, after)
        report['source_after'] = gates.source_now(context)
        report['source_preserved'] = report['source_before'] == report['source_after']
        report['cold_inputs_preserved'] = gates.cold_inputs(cold) == context
        report['status'] = 'PASS'
        gates.validate_elf_component(report, expected, after, report['runtime_observations'], context)
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        # A final identity error cannot leave a previously marked PASS.
        try:
            report['source_after'] = gates.source_now(context)
            report['source_preserved'] = report['source_before'] == report['source_after']
            report['cold_inputs_preserved'] = gates.cold_inputs(cold) == context
            if not report['source_preserved'] or not report['cold_inputs_preserved']:
                raise ValueError('component final current source/cold changed')
        except BaseException:
            report['status'] = 'HOLD'
            report['final_identity_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        write_new(evidence / 'report.json', report)
    return report



def owned_environment(environment, owner, cold):
    # Preserve ordinary test/runtime inputs, not unrelated CI credential variables.
    standard = {'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TMPDIR', 'TMP', 'TEMP',
                'LD_LIBRARY_PATH', 'PYTHONUTF8', 'PYTHONHASHSEED', 'PYTHONDONTWRITEBYTECODE',
                'CARGO_HOME', 'RUSTUP_HOME', 'CARGO_NET_OFFLINE', 'CARGO_BUILD_JOBS'}
    value = {name: text for name, text in environment.items()
             if name in standard or name.startswith('HEPTA_')}
    for config in gates.OWNERS.values():
        value.pop(config['prefix'] + config['development_suffix'], None)
    value[gates.OWNERS[owner]['prefix'] + '_COLD_REPORT'] = str(Path(cold).resolve(strict=True))
    return value


def execute_owned_product(owner, part, cold, evidence, process_evidence, context):
    from tools import hia_selfhost_process_owner
    directory = Path(process_evidence).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    gates.require(Path(hia_selfhost_process_owner.__file__).resolve()
                  == ROOT / 'tools/hia_selfhost_process_owner.py', 'actual process owner source differs')
    command = gates.owned_product_command(owner, part, cold, evidence, directory)
    result = {'schema': 'hepta.hia.compiler-owner-owned-command.v1',
        'status': 'HOLD', 'owner': owner, 'part': part,
        'command': command, 'cwd': str(ROOT), 'cold_inputs': context['identities'],
        'source_before': gates.source_now(context), 'source_after': None,
        'source_preserved': False, 'cold_inputs_preserved': False}
    try:
        result['returned_owner'] = hia_selfhost_process_owner.run_owned(
            command, cwd=ROOT, env=owned_environment(os.environ, owner, cold),
            stdout_path=directory / 'stdout.log', stderr_path=directory / 'stderr.log',
            receipt_path=directory / 'process-owner.json',
            qualification_seconds=180, cleanup_seconds=3)
        result['status'] = 'OWNED_COMMAND_RETURNED_PENDING_READBACK'
    except BaseException:
        result['status'] = 'HOLD'
        result['error'] = traceback.format_exc()
    finally:
        try:
            result['source_after'] = gates.source_now(context)
            result['source_preserved'] = result['source_before'] == result['source_after']
            result['cold_inputs_preserved'] = gates.cold_inputs(cold) == context
            if not result['source_preserved'] or not result['cold_inputs_preserved']:
                raise ValueError('owned product final current source/cold changed')
        except BaseException:
            result['status'] = 'HOLD'
            result['final_identity_error'] = traceback.format_exc()
        write_new(directory / 'run-result.json', result)
    return gates.inspect_owned_product(owner, part, cold, evidence, directory, context)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('component', 'check-callers', 'check-component', 'owned-callers', 'owned-component'))
    parser.add_argument('--owner', required=True, choices=tuple(gates.OWNERS))
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process-evidence', type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('preserve an existing gate report')
    if args.operation in ('component', 'check-component', 'owned-component') and args.owner != 'elf':
        parser.error('state/instructions/Core complete components belong to their original qualifiers')
    if args.output.resolve() == (args.evidence_dir / 'report.json').resolve():
        parser.error('gate output must preserve the original producer report')
    owned = args.operation.startswith('owned-')
    if owned != (args.process_evidence is not None):
        parser.error('only owned product operations require a new --process-evidence directory')
    if owned and (args.evidence_dir.exists() or args.process_evidence.exists()):
        parser.error('preserve existing product or process evidence')
    started = time.monotonic()
    result = {'schema': 'hepta.hia.compiler-owner-gate.v1', 'owner': args.owner,
        'operation': args.operation, 'status': 'HOLD',
        'scope': 'MATCHING_SOURCE_COLD_OWNER_GATES',
        'source_preserved': False, 'cold_inputs_preserved': False,
        'whole_native_delivery_qualified': False,
        'development_or_prior_result_reused': False}
    context = None
    try:
        context = gates.cold_inputs(args.cold_report)
        result['cold_inputs'] = context['identities']
        result['source_before'] = gates.source_now(context)
        expected = gates.expected_groups(args.owner)
        part = 'component' if args.operation in ('component', 'check-component', 'owned-component') else 'callers'
        owner_observation = None
        if owned:
            owner_observation = execute_owned_product(args.owner, part, args.cold_report,
                args.evidence_dir, args.process_evidence, context)
        elif args.operation == 'component':
            execute_elf_component(args.evidence_dir, args.cold_report, context, expected[0])
        inspection = gates.inspect_evidence(args.owner, part, args.evidence_dir, context, expected)
        if owned:
            observed_after = gates.inspect_owned_product(args.owner, part, args.cold_report,
                args.evidence_dir, args.process_evidence, context)
            gates.require(owner_observation == observed_after, 'owned original evidence changed during product readback')
            inspection['process_owner'] = observed_after
        result['inspection'] = inspection
        result['gates'] = inspection['gates']
        result['source_after'] = gates.source_now(context)
        result['source_preserved'] = result['source_before'] == result['source_after']
        result['cold_inputs_preserved'] = gates.cold_inputs(args.cold_report) == context
        gates.require(result['source_preserved'] and result['cold_inputs_preserved'],
                      'final gate source/cold changed')
        result['status'] = 'PASS'
    except BaseException:
        result['status'] = 'HOLD'
        result['error'] = traceback.format_exc()
    finally:
        if context is not None:
            try:
                result['source_after'] = gates.source_now(context)
                result['source_preserved'] = result.get('source_before') == result['source_after']
                result['cold_inputs_preserved'] = gates.cold_inputs(args.cold_report) == context
                if not result['source_preserved'] or not result['cold_inputs_preserved']:
                    raise ValueError('gate final source/cold changed')
            except BaseException:
                result['status'] = 'HOLD'
                result['final_identity_error'] = traceback.format_exc()
        result['seconds'] = time.monotonic() - started
        write_new(args.output, result)
    print(json.dumps({'owner': args.owner, 'operation': args.operation,
                      'status': result['status'], 'report': str(args.output)}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
