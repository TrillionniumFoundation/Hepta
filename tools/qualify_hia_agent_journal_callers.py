"""Run existing ordinary Agent regressions with the HIA journal owner selected.

This is separate from the default retained-owner regression. It refuses the
retained call owner, records actual native stage entries and reports every
failure, skip and explicit development exclusion without weakening assertions.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

DEFAULT_MODULES = (
    'tests.test_hia_agent_native_tools',
    'tests.test_hia_agent_native_proof_contract',
    'tests.test_hia_agent_native_lease_snapshot',
    'tests.test_hia_agent_native_machine_choices',
    'tests.test_hia_agent_native_campaign',
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def strict_pass(result, chosen_ids, executed_ids, all_tools):
    return (bool(chosen_ids) and result.testsRun == len(chosen_ids)
            and executed_ids == chosen_ids and all_tools
            and not result.errors and not result.failures and not result.skipped
            and not result.expectedFailures and not result.unexpectedSuccesses)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--manifest', type=Path)
    selection.add_argument('--cold-report', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--module', action='append')
    parser.add_argument('--exclude', action='append', default=[], metavar='TEST_ID=REASON')
    args = parser.parse_args()
    if bool(args.manifest) != args.development:
        parser.error('--manifest requires --development; a cold report cannot be relabeled development')
    if args.cold_report and args.exclude:
        parser.error('qualified caller runs cannot exclude existing tests')
    exclusions = {}
    for spec in args.exclude:
        key, equal, reason = spec.partition('=')
        if not equal or not reason.strip() or key in exclusions:
            parser.error('each exclusion must name one test and a nonempty reason')
        exclusions[key] = reason
    if args.output.exists():
        parser.error('output already exists; preserve prior observations')
    from hepta.hia_agent_journal_native import SELECTOR, TOOLS, JournalSession, installed_agent_journal
    from hepta.hia_agent_service import HIAAgentService
    from hepta import hia_agent_journal_native as native
    with tempfile.TemporaryDirectory(prefix='hia-journal-callers-') as tmp:
        if args.cold_report:
            from tools.build_hia_json_preflight import build
            cold = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(cold['nested_report']).read_bytes())
            manifest = build(Path(tmp) / 'build', Path(nested['generations'][-1]['produced_image']),
                             args.cold_report, candidate='agent-journal')
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        image = installed_agent_journal(str(manifest))
        suites = [unittest.defaultTestLoader.loadTestsFromName(name)
                  for name in (args.module or DEFAULT_MODULES)]
        tests = list(flatten(unittest.TestSuite(suites)))
        loaded_ids = [test.id() for test in tests]
        available = {test.id() for test in tests}
        if set(exclusions) - available:
            parser.error('exclusion does not identify an actually loaded test')
        chosen_tests = [test for test in tests if test.id() not in exclusions]
        chosen_ids = [test.id() for test in chosen_tests]
        chosen = unittest.TestSuite(chosen_tests)
        executed_ids = []
        tools, stages, by_case = Counter(), Counter(), {}
        current = ['outside-test']
        original_driver, original_stage = native.call_with_native_journal, JournalSession._run

        def driver(service, tool, arguments, selected):
            if str(Path(selected).resolve()) != str(manifest.resolve()):
                raise AssertionError('ordinary call changed the selected journal manifest')
            name = tool if type(tool) is str else type(tool).__name__
            tools[name] += 1
            by_case.setdefault(current[0], Counter())['selected_driver'] += 1
            return original_driver(service, tool, arguments, selected)

        def stage(session, number, raw=b'', foreign_types=b''):
            result = original_stage(session, number, raw, foreign_types)
            stages[str(number)] += 1
            by_case.setdefault(current[0], Counter())['native_stage'] += 1
            return result

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id()
                executed_ids.append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test)
                current[0] = 'outside-test'

        started = time.monotonic()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
            stack.enter_context(patch.object(HIAAgentService, '_reference_call',
                                            side_effect=AssertionError('retained journal owner entered')))
            stack.enter_context(patch.object(native, 'call_with_native_journal', driver))
            stack.enter_context(patch.object(JournalSession, '_run', stage))
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(chosen)
        needed = set(TOOLS[:-1])
        all_tools = needed <= set(tools)
        status = 'PASS' if strict_pass(result, chosen_ids, executed_ids, all_tools) else 'FAIL_OR_INCOMPLETE'
        source_names = ['hepta/hia_agent_journal_native.py', 'hepta/hia_agent_service.py',
                        'hepta/hia_agent_store.py', 'hepta/hia_agent_contract.py',
                        'tools/generate_hia_agent_journal.py', 'tools/qualify_hia_agent_journal_callers.py',
                        'examples/hia_bootstrap/agent_journal.hiaasm']
        report = {
            'schema': 'hepta.hia.agent-journal-selected-callers.v1',
            'status': status, 'scope': scope,
            'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
            'image_sha256': image.image_sha256,
            'manifest': json.loads(manifest.read_bytes()),
            'source_sha256': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names},
            'wall_seconds': time.monotonic() - started,
            'tests_run': result.testsRun,
            'loaded_test_ids': loaded_ids, 'chosen_test_ids': chosen_ids,
            'executed_test_ids': executed_ids,
            'tests_loaded': len(loaded_ids), 'tests_chosen': len(chosen_ids),
            'failures': [{'test': test.id(), 'trace': trace} for test, trace in result.failures],
            'errors': [{'test': test.id(), 'trace': trace} for test, trace in result.errors],
            'skipped': [{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
            'expected_failures': [{'test': test.id(), 'trace': trace} for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'explicit_development_exclusions': exclusions,
            'retained_call_owner_forbidden': True,
            'selected_driver_calls': dict(tools), 'actual_native_stage_returns': dict(stages),
            'per_test_entries': {name: dict(counts) for name, counts in by_case.items()},
            'all_eleven_tools_entered_selected_driver': all_tools,
            'subprocesses_inherit_selector': True,
            'subprocess_stage_entries_in_parent_counters': False,
            'default_whole_regression_claimed': False,
            'sqlite_durability_replaced': False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': status, 'report': str(args.output), 'tests_run': result.testsRun,
                          'scope': scope, 'all_eleven_tools': all_tools}), flush=True)
        return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
