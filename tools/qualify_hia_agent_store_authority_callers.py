"""Run unchanged ordinary Agent caller suites with six retained store owners forbidden."""
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
import uuid

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
METHODS = ('ref', 'get', 'resolve_uri', 'profile', 'check_profile', 'put')


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def uri_control(folder, manifest):
    """A separately named real SQLite control; it is not one of the old tests."""
    from hepta import hia_agent_store as store_module
    from hepta.hia_agent_store_authority_native import SELECTOR
    folder.mkdir(mode=0o700)
    counter = iter(range(1, 100))
    observed_uuids = []
    def next_uuid():
        value = next(counter); observed_uuids.append(value); return uuid.UUID(int=value)
    with patch.dict(os.environ, {SELECTOR: str(manifest) if manifest is not None else ''}), \
         patch.object(store_module.uuid, 'uuid4', side_effect=next_uuid):
        store = store_module.AgentStore(folder / 'state')
        sql = []; store.db.set_trace_callback(sql.append)
        try:
            reference = store.put(b'URI-control\0\xff', 'data', {'authority': 'retained-issuance'})
            before = [tuple(row) for row in store.db.execute('SELECT * FROM artifacts ORDER BY rowid')]
            known = store.resolve_uri(reference['uri'])
            read, metadata = store.get(known, kind='data')
            try:
                store.resolve_uri('never-issued://opaque-value')
            except store_module.AgentRejected as exc:
                unknown = {'code': exc.code, 'message': str(exc), 'phase': exc.phase,
                           'retry_action': exc.retry_action}
            else:
                raise AssertionError('unknown URI acquired retained authority')
            after = [tuple(row) for row in store.db.execute('SELECT * FROM artifacts ORDER BY rowid')]
            if before != after:
                raise AssertionError('URI read changed retained state')
        finally:
            store.close()
        restarted = store_module.AgentStore(folder / 'state')
        try:
            reopened = [tuple(row) for row in restarted.db.execute('SELECT * FROM artifacts ORDER BY rowid')]
        finally:
            restarted.close()
        if reopened != after or known != reference:
            raise AssertionError('URI retained identity or restart state differs')
        record = {'reference': reference, 'known': known, 'read_hex': read.hex(), 'metadata': metadata,
                  'unknown': unknown, 'before': before, 'after': after, 'reopened': reopened,
                  'sql': sql, 'uuid_values': observed_uuids,
                  'files': {p.name: {'hex': p.read_bytes().hex(), 'mode': p.stat().st_mode & 0o777}
                            for p in sorted((folder / 'state/artifacts').iterdir())}}
    (folder / 'observations.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--manifest', type=Path)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence-dir', type=Path)
    parser.add_argument('--module', action='append')
    args = parser.parse_args()
    if bool(args.manifest) != args.development:
        parser.error('--manifest requires --development; cold cannot be relabelled development')
    if args.output.exists():
        parser.error('output exists; preserve prior observations')
    from hepta.hia_agent_store import AgentStore
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_agent_journal_native import TOOLS
    from hepta.hia_agent_store_authority_native import SELECTOR, NativeAgentStoreAuthority, StoreAuthoritySession, installed_agent_store_authority
    from tools.build_hia_agent_store_authority import build
    from tools.build_hia_json_preflight import current_sources
    with ExitStack() as stack:
        if args.evidence_dir is None:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-store-authority-callers-')))
        else:
            folder = args.evidence_dir.absolute(); folder.mkdir(mode=0o700, parents=True)
        if args.cold_report:
            report = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(folder / 'authority', compiler, args.cold_report)
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        source_manifest = current_sources() if args.cold_report else None
        owner = installed_agent_store_authority(str(manifest))
        manifest_raw = manifest.read_bytes(); value = json.loads(manifest_raw)
        executable = (manifest.parent / value['image_path']).resolve(strict=True)
        image_sha = sha256(executable.read_bytes()).hexdigest()
        source_names = ('hepta/hia_agent_store.py', 'hepta/hia_agent_store_authority_native.py',
                        'hepta/hia_worker_report_native.py', 'hepta/hia_json_wire_native.py',
                        'tools/generate_hia_agent_store_authority.py', 'tools/generate_hia_worker_report.py',
                        'examples/hia_bootstrap/agent_store_authority.hiaasm',
                        'tools/qualify_hia_agent_store_authority_callers.py')
        source_before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names}
        modules = args.module or DEFAULT_MODULES
        loaded = list(flatten(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in modules)))
        loaded_ids = [test.id() for test in loaded]
        if not loaded_ids or len(set(loaded_ids)) != len(loaded_ids):
            parser.error('caller IDs must be nonempty and unique')
        executed, retained = [], []
        modes, steps, tools_with_owner, tools_without_owner, per_test = Counter(), Counter(), Counter(), Counter(), {}
        current = ['outside-test']
        original_run, original_step, original_call = NativeAgentStoreAuthority.run, StoreAuthoritySession.step, HIAAgentService.call
        def forbidden(name):
            def fail(*arguments, **keywords):
                retained.append({'test': current[0], 'owner': name})
                raise AssertionError('retained AgentStore authority entered: ' + name)
            return fail
        def entered(image, store, mode, *arguments):
            if image.image_sha256 != owner.image_sha256:
                raise AssertionError('ordinary AgentStore selected another image')
            modes[METHODS[mode]] += 1
            per_test.setdefault(current[0], Counter())[METHODS[mode]] += 1
            return original_run(image, store, mode, *arguments)
        def step(session, packet=None):
            status = original_step(session, packet)
            steps[str(status)] += 1
            return status
        def call(service, tool, arguments):
            before = sum(modes.values())
            try:
                return original_call(service, tool, arguments)
            finally:
                name = tool if type(tool) is str else type(tool).__name__
                target = tools_with_owner if sum(modes.values()) > before else tools_without_owner
                target[name] += 1
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id(); executed.append(test.id()); super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test); current[0] = 'outside-test'
        # The baseline runs before the selected region. The native control
        # below runs with exactly the same old-owner prohibitions as callers.
        reference_uri = uri_control(folder / 'uri-reference', None)
        native_uri = None
        uri_failure = None
        start = time.monotonic()
        with ExitStack() as selected:
            selected.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
            for name in METHODS:
                selected.enter_context(patch.object(AgentStore, '_reference_' + name, forbidden(name)))
            selected.enter_context(patch.object(NativeAgentStoreAuthority, 'run', entered))
            selected.enter_context(patch.object(StoreAuthoritySession, 'step', step))
            selected.enter_context(patch.object(HIAAgentService, 'call', call))
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(unittest.TestSuite(loaded))
            current[0] = 'independent-uri-control'
            try:
                native_uri = uri_control(folder / 'uri-native', manifest)
            except BaseException as exc:
                import traceback
                uri_failure = {'type': type(exc).__name__, 'message': str(exc), 'trace': traceback.format_exc()}
            finally:
                current[0] = 'outside-test'
        source_after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names}
        stable = source_before == source_after and manifest.read_bytes() == manifest_raw and sha256(executable.read_bytes()).hexdigest() == image_sha
        cold_stable = current_sources() == source_manifest if args.cold_report else None
        all_tools = set(TOOLS[:-1]) <= (set(tools_with_owner) | set(tools_without_owner))
        all_modes = set(modes) == set(METHODS) and all(count > 0 for count in modes.values())
        uri_equal = uri_failure is None and native_uri == reference_uri
        anomalies = (result.errors, result.failures, result.skipped, result.expectedFailures, result.unexpectedSuccesses)
        passed = (result.testsRun == len(loaded_ids) and executed == loaded_ids and not any(anomalies)
                  and not retained and all_modes and all_tools and uri_equal and stable and cold_stable is not False)
        record = {
            'schema': 'hepta.hia.agent-store-authority-selected-callers.v1',
            'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE', 'scope': scope,
            'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
            'modules': list(modules), 'loaded_test_ids': loaded_ids, 'chosen_test_ids': loaded_ids,
            'executed_test_ids': executed, 'tests_loaded': len(loaded_ids), 'tests_chosen': len(loaded_ids),
            'tests_run': result.testsRun,
            'failures': [{'test': test.id(), 'trace': trace} for test, trace in result.failures],
            'errors': [{'test': test.id(), 'trace': trace} for test, trace in result.errors],
            'skipped': [{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
            'expected_failures': [{'test': test.id(), 'trace': trace} for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'explicit_development_exclusions': {}, 'retained_owner_forbidden': True, 'retained_owner_entries': retained,
            'all_six_store_modes_entered_native': all_modes, 'actual_native_modes': dict(modes),
            'independent_uri_control': {'status': 'PASS' if uri_equal else 'HOLD',
                                        'part_of_original_loaded_ids': False,
                                        'reference': reference_uri, 'native': native_uri, 'failure': uri_failure},
            'actual_native_step_returns': dict(steps), 'per_test_entries': {k: dict(v) for k, v in per_test.items()},
            'all_eleven_agent_tools_exercised': all_tools, 'agent_tools_with_native_store': dict(tools_with_owner),
            'agent_tools_without_native_store': dict(tools_without_owner),
            'tools_without_store_operations_do_not_require_a_native_store_entry': True,
            'source_sha256': source_before, 'source_after_sha256': source_after,
            'manifest': value, 'manifest_path': str(manifest), 'image_sha256': owner.image_sha256,
            'source_manifest_image_stable': stable, 'matching_cold_source_closure_stable': cold_stable,
            'source_manifest': source_manifest, 'wall_seconds': time.monotonic() - start,
            'evidence_dir': str(folder), 'evidence_dir_retained': args.evidence_dir is not None,
            'subprocess_entries_in_parent_counters': False, 'subprocess_environment_is_controlled_by_original_tests': True,
            'default_whole_regression_claimed': False, 'sqlite_durability_replaced': False,
            'field_shape_codecs_and_unselected_file_publication_remain_independent': True,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': record['status'], 'tests_run': result.testsRun,
                          'all_six_store_modes': all_modes, 'all_eleven_tools': all_tools,
                          'scope': scope, 'report': str(args.output)}), flush=True)
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
