"""Execute or read strict matching-source cold Store/page CI evidence."""
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
from tools import hia_store_page_gates as gates


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite): yield from flatten(test)
        else: yield test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('component', 'check-callers'))
    parser.add_argument('--owner', required=True, choices=tuple(gates.OWNERS))
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--caller-report', type=Path)
    args = parser.parse_args(); config = gates.OWNERS[args.owner]
    if args.output.exists(): parser.error('preserve existing report')
    if any(os.environ.get(v['prefix'] + '_DEVELOPMENT_MANIFEST') for v in gates.OWNERS.values()):
        parser.error('development selection cannot enter a cold CI gate')
    if bool(args.caller_report) != (args.operation == 'check-callers'):
        parser.error('check-callers requires --caller-report; component must omit it')
    context = gates.cold_inputs(args.cold_report)
    from tools.build_hia_json_preflight import current_sources
    started = time.monotonic(); report = {'schema': 'hepta.hia.store-page-component.v1', 'owner': args.owner,
        'status': 'HOLD', 'scope': 'MATCHING_SOURCE_COLD_COMPONENT', 'source_before': context['source_manifest'],
        'cold_inputs': context['identities'], 'source_preserved': False, 'cold_inputs_preserved': False,
        'modules': [config['module']], 'python': sys.version, 'executable': sys.executable}
    try:
        if args.operation == 'component':
            args.evidence_dir.mkdir(mode=0o700, parents=True)
            loader = unittest.TestLoader(); suite = loader.loadTestsFromName(config['module'])
            loaded = [test.id() for test in flatten(suite)]; executed = []
            class Result(unittest.TextTestResult):
                def startTest(self, test):
                    executed.append(test.id()); super().startTest(test)
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {
                    config['prefix'] + '_COLD_REPORT': str(args.cold_report.resolve(strict=True)),
                    config['prefix'] + '_FIXTURE_EVIDENCE': str(args.evidence_dir / 'fixture')}))
                log = stack.enter_context((args.evidence_dir / 'unittest.log').open('x'))
                result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
            report.update(loaded_test_ids=loaded, chosen_test_ids=loaded, executed_test_ids=executed,
                tests_loaded=len(loaded), tests_chosen=len(loaded), tests_run=result.testsRun,
                loader_errors=list(loader.errors), unittest_successful=result.wasSuccessful())
            for field, original in zip(gates.ANOMALIES, ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')):
                report[field] = [({'test': t.id(), 'detail': detail} if isinstance(item, tuple)
                                 else {'test': item.id()}) for item in getattr(result, original)
                                for t, detail in ([item] if isinstance(item, tuple) else [(item, None)])]
            binding = gates.inspect_build(args.owner, args.evidence_dir / 'fixture' / config['fixture_build'], context)
            report['build_binding'] = binding
            report['runtime_observations'] = gates.inspect_component_observations(args.owner, args.evidence_dir / 'fixture', binding, context)
            report['source_after'] = current_sources()
            report['source_preserved'] = report['source_after'] == report['source_before']
            report['cold_inputs_preserved'] = gates.cold_inputs(args.cold_report) == context
            report['status'] = 'PASS'
            gates.validate_component(args.owner, report, loaded, binding, context)
        else:
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(gates.CALLER_MODULES)
            expected = [test.id() for test in flatten(suite)]
            gates.require(not loader.errors, 'original caller modules failed to load')
            caller = gates.json_file(args.caller_report)
            binding = gates.inspect_build(args.owner, args.evidence_dir / config['caller_build'], context)
            gates.validate_callers(args.owner, caller, expected, binding, context)
            gates.require(current_sources() == context['source_manifest'] and gates.cold_inputs(args.cold_report) == context,
                          'source/cold changed during caller readback')
            report = {'schema': 'hepta.hia.store-page-caller-gate.v1', 'owner': args.owner, 'status': 'PASS',
                'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS', 'caller_report': gates.file_record(args.caller_report),
                'tests_run': 67, 'loaded_test_ids': expected, 'build_binding': binding,
                'cold_inputs': context['identities'], 'source_preserved': True, 'cold_inputs_preserved': True,
                'v8_PASS_reused_for_new_gate': False, 'whole_native_delivery_qualified': False}
    except BaseException:
        report['status'] = 'HOLD'; report['error'] = traceback.format_exc()
    report['wall_seconds'] = time.monotonic() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'owner': args.owner, 'status': report['status'], 'operation': args.operation,
                      'report': str(args.output)}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
