"""Exercise existing bounded-wire and Agent callers through the selected HIA owner."""
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
    'tests.test_hia_bounded_agent_json',
    'tests.test_hia_inmemory_surrogate_wire',
    'tests.test_hia_inmemory_json_key_collisions',
    'tests.test_hia_inmemory_agent_node_ceiling',
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--manifest', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence-dir', '--fixture-evidence', dest='evidence_dir', type=Path)
    parser.add_argument('--module', action='append')
    parser.add_argument('--exclude', action='append', default=[], metavar='TEST_ID=REASON')
    args = parser.parse_args()
    if bool(args.manifest) != args.development:
        parser.error('--manifest requires --development; cold cannot be relabeled development')
    if args.cold_report and args.exclude:
        parser.error('qualified runs cannot exclude existing callers')
    if args.output.exists():
        parser.error('output already exists; preserve prior observations')
    exclusions = {}
    for value in args.exclude:
        name, equal, reason = value.partition('=')
        if not equal or not reason.strip() or name in exclusions:
            parser.error('exclusions require a unique test ID and reason')
        exclusions[name] = reason
    from hepta import hia_program_tools as program_tools
    from hepta.hia_agent_journal_native import TOOLS
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_json_wire_native import NativeJsonWire, WireSession, SELECTOR, ORDINARY_PROFILE, installed_json_wire
    from tools.build_hia_json_wire import build
    with ExitStack() as stack:
        if args.evidence_dir is None:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-wire-callers-')))
        else:
            folder = args.evidence_dir.absolute()
            folder.mkdir(mode=0o700, parents=True)
        if args.cold_report:
            outer = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(folder / 'wire', compiler, args.cold_report)
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        image = installed_json_wire(str(manifest))
        manifest_raw = manifest.read_bytes()
        manifest_value = json.loads(manifest_raw)
        executable = (manifest.parent / manifest_value['image_path']).resolve(strict=True)
        executable_sha = sha256(executable.read_bytes()).hexdigest()
        source_names = ('hepta/hia_json_wire_native.py', 'hepta/hia_program_tools.py',
                        'hepta/hia_agent_store.py', 'tools/generate_hia_json_wire.py',
                        'examples/hia_bootstrap/json_wire.hiaasm', 'tools/qualify_hia_json_wire_callers.py')
        sources = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names}
        loaded = list(flatten(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name)
                                                for name in (args.module or DEFAULT_MODULES))))
        loaded_ids = [test.id() for test in loaded]
        if set(exclusions) - set(loaded_ids):
            parser.error('an exclusion does not identify a loaded test')
        chosen = [test for test in loaded if test.id() not in exclusions]
        chosen_ids = [test.id() for test in chosen]
        executed_ids, retained_entries, encoder_entries = [], [], []
        calls, steps, tools_with_wire, tools_without_wire, per_test = Counter(), Counter(), Counter(), Counter(), {}
        current = ['outside-test']
        original_encode, original_step, original_call = NativeJsonWire.encode_ordinary, WireSession.step, HIAAgentService.call

        def forbidden_owner(*args, **kwargs):
            retained_entries.append(current[0])
            raise AssertionError('retained bounded-wire decision owner entered')

        def forbidden_encoder(*args, **kwargs):
            encoder_entries.append(current[0])
            raise AssertionError('host JSON encoder entered selected native wire')

        def encode(owner, *values, **options):
            if owner.image_sha256 != image.image_sha256:
                raise AssertionError('ordinary wire selected a different executable')
            calls['ordinary'] += 1
            per_test.setdefault(current[0], Counter())['ordinary_wire_calls'] += 1
            with patch.object(json.JSONEncoder, 'iterencode', forbidden_encoder):
                return original_encode(owner, *values, **options)

        def step(session, packet=None):
            result = original_step(session, packet)
            steps[str(result)] += 1
            per_test.setdefault(current[0], Counter())['native_step_returns'] += 1
            return result

        def call(service, tool, arguments):
            before = calls['ordinary']
            try:
                return original_call(service, tool, arguments)
            finally:
                name = tool if type(tool) is str else type(tool).__name__
                (tools_with_wire if calls['ordinary'] > before else tools_without_wire)[name] += 1

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id()
                executed_ids.append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test)
                current[0] = 'outside-test'

        started = time.monotonic()
        with (patch.dict(os.environ, {SELECTOR: str(manifest)}),
              patch.object(program_tools, '_reference_bounded_json_wire', forbidden_owner),
              patch.object(NativeJsonWire, 'encode_ordinary', encode),
              patch.object(WireSession, 'step', step),
              patch.object(HIAAgentService, 'call', call)):
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(unittest.TestSuite(chosen))
        stable = (manifest.read_bytes() == manifest_raw
                  and sha256(executable.read_bytes()).hexdigest() == executable_sha
                  and all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in sources.items()))
        all_tools = set(TOOLS[:-1]) <= set(tools_with_wire)
        anomalies = (result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses)
        passed = (bool(chosen_ids) and result.testsRun == len(chosen_ids) and executed_ids == chosen_ids
                  and not any(anomalies) and not retained_entries and not encoder_entries
                  and bool(calls['ordinary']) and bool(steps) and all_tools and stable)
        report = {
            'schema': 'hepta.hia.json-wire-selected-callers.v1', 'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE',
            'scope': scope, 'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
            'loaded_test_ids': loaded_ids, 'chosen_test_ids': chosen_ids, 'executed_test_ids': executed_ids,
            'tests_loaded': len(loaded_ids), 'tests_chosen': len(chosen_ids), 'tests_run': result.testsRun,
            'failures': [{'test': test.id(), 'trace': trace} for test, trace in result.failures],
            'errors': [{'test': test.id(), 'trace': trace} for test, trace in result.errors],
            'skipped': [{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
            'expected_failures': [{'test': test.id(), 'trace': trace} for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'explicit_development_exclusions': exclusions, 'retained_owner_forbidden': True,
            'retained_owner_entries': retained_entries, 'host_encoder_forbidden_inside_native_owner': True,
            'host_encoder_entries': encoder_entries, 'ordinary_wire_calls': calls['ordinary'],
            'actual_native_step_returns': dict(steps), 'per_test_entries': {k: dict(v) for k, v in per_test.items()},
            'all_eleven_agent_tools_entered_selected_wire': all_tools,
            'agent_tools_with_native_wire': dict(tools_with_wire), 'agent_tools_without_native_wire': dict(tools_without_wire),
            'source_sha256': sources, 'manifest': manifest_value, 'manifest_path': str(manifest),
            'image_sha256': image.image_sha256, 'source_manifest_image_stable': stable,
            'ordinary_entry_profile': ORDINARY_PROFILE, 'wall_seconds': time.monotonic() - started,
            'evidence_dir': str(folder), 'evidence_dir_retained': args.evidence_dir is not None,
            'subprocesses_inherit_selector': True, 'subprocess_entries_in_parent_counters': False,
            'default_whole_regression_claimed': False, 'sqlite_durability_replaced': False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': report['status'], 'report': str(args.output),
                          'tests_run': result.testsRun, 'scope': scope, 'all_eleven_tools': all_tools}), flush=True)
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
