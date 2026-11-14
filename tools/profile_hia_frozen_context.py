"""Observe costs of the unmodified original 3 s test with both native owners."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--budget-manifest', type=Path, required=True)
    parser.add_argument('--journal-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; preserve the prior observation')
    os.chdir(ROOT); sys.path.insert(0, str(ROOT))
    source_path = 'tests/test_hia_agent_native_tools.py'
    raw = (ROOT / source_path).read_bytes()
    if sha256(raw).hexdigest() != 'c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a':
        raise ValueError('the original frozen-context test source changed')
    os.environ['HEPTA_HIA_EXECUTION_BUDGET_MANIFEST'] = str(args.budget_manifest.resolve())
    os.environ['HEPTA_HIA_AGENT_JOURNAL_MANIFEST'] = str(args.journal_manifest.resolve())
    from hepta import hia_execution_budget as reference
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_execution_budget_native import BudgetState
    from hepta.hia_agent_journal_native import JournalSession
    from hepta import hia_agent_service as hosted
    events = []
    def timed(label, function):
        def observed(*values, **keywords):
            start = time.perf_counter_ns()
            row = {'label': label, 'started_ns': start}
            if label == 'service.call':
                row['tool'] = values[1]
            elif label == 'journal._run':
                row['stage'] = values[1]
                payload = values[2] if len(values) > 2 else keywords.get('raw', b'')
                row['input_bytes'] = len(payload)
            elif label == 'budget.call':
                row['event'] = values[1]
            try:
                result = function(*values, **keywords)
                row['outcome'] = 'returned'
                if label == 'service.call':
                    row['status'] = result.get('status')
                return result
            except BaseException as error:
                row['outcome'] = type(error).__name__
                raise
            finally:
                row['seconds'] = (time.perf_counter_ns() - start) / 1e9
                events.append(row)
        return observed
    name = 'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline'
    suite = unittest.defaultTestLoader.loadTestsFromName(name)
    started = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('hosted journal entered')))
        for owner in (reference._ReferenceExecutionBudgetStore, reference._ReferenceBudgetClaim):
            stack.enter_context(patch.object(owner, '__init__', side_effect=AssertionError('hosted budget entered')))
        for owner, attribute, label in ((HIAAgentService, 'call', 'service.call'),
                (JournalSession, '_run', 'journal._run'), (BudgetState, 'call', 'budget.call'),
                (hosted, 'installation_manifest', 'installation_manifest')):
            stack.enter_context(patch.object(owner, attribute, timed(label, getattr(owner, attribute))))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    contexts = [row for row in events if row.get('tool') == 'hia_context']
    evaluations = [row for row in events if row.get('tool') == 'hia_evaluate']
    preparation = None
    if contexts and evaluations:
        context, evaluation = contexts[-1], evaluations[0]
        elapsed = (evaluation['started_ns'] - context['started_ns']) / 1e9
        preparation = {'context_call_start_to_evaluation_start_seconds': elapsed,
            'context_call_end_to_evaluation_start_seconds': elapsed - context['seconds'],
            'costs': {label: sum(row['seconds'] for row in events
                if row['label'] == label and context['started_ns'] <= row['started_ns'] < evaluation['started_ns'])
                for label in ('journal._run', 'budget.call', 'installation_manifest')},
            'complete_catalog_bind_seconds': sum(row['seconds'] for row in events
                if row['label'] == 'journal._run' and row['stage'] == 9
                and context['started_ns'] <= row['started_ns'] < evaluation['started_ns'])}
    report = {'schema': 'hepta.hia.original-frozen-context-cost-observation.v1',
        'scope': 'ONE_REPEATED_ORIGINAL_TEST_WITH_OBSERVATIONAL_TIMING_NOT_NEW_UNIQUE_COVERAGE',
        'python': sys.version, 'command': sys.argv, 'test': name, 'original_test_unchanged': True,
        'original_test_source_sha256': sha256(raw).hexdigest(),
        'fixed_context_budget_seconds': 3, 'absolute_completion_allowance_seconds': 0.650,
        'hosted_journal_and_budget_construction_forbidden': True,
        'source_preserved': raw == (ROOT / source_path).read_bytes(),
        'preparation': preparation,
        'budget_manifest': json.loads(args.budget_manifest.read_bytes()),
        'journal_manifest': json.loads(args.journal_manifest.read_bytes()),
        'tests_run': result.testsRun, 'seconds': time.monotonic() - started,
        'errors': [{'test': test.id(), 'traceback': text} for test, text in result.errors],
        'failures': [{'test': test.id(), 'traceback': text} for test, text in result.failures],
        'skipped': [{'test': test.id(), 'reason': text} for test, text in result.skipped],
        'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
        'events': sorted(events, key=lambda row: row['started_ns']),
        'matching_current_source_cold_qualified': False, 'whole_native_delivery_qualified': False}
    report['passed'] = (result.wasSuccessful() and result.testsRun == 1 and report['source_preserved'] and not result.skipped
                        and not result.expectedFailures and not result.unexpectedSuccesses)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'tests_run': result.testsRun,
                     'seconds': report['seconds'], 'output': str(args.output)}, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
