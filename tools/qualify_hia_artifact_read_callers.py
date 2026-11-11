"""Run unchanged ordinary Agent callers with the retained page owner forbidden."""
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
SOURCE_NAMES = (
    'hepta/hia_agent_service.py', 'hepta/hia_artifact_page_native.py',
    'tools/generate_hia_artifact_page.py', 'tools/build_hia_artifact_page.py',
    'examples/hia_bootstrap/artifact_page.hiaasm', 'examples/hia_bootstrap/json_wire.hiaasm',
    'hepta/hia_json_wire_native.py', 'tools/qualify_hia_artifact_read_callers.py',
)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def bundle_identities(manifest):
    paths = [manifest]
    bundle = json.loads(manifest.read_bytes())
    for name in ('policy', 'wire'):
        child = manifest.parent / bundle[name + '_manifest']
        value = json.loads(child.read_bytes())
        paths.extend((child, child.parent / value['image_path']))
    return {str(path.resolve(strict=True)): {'size': path.stat().st_size,
            'sha256': sha256(path.read_bytes()).hexdigest()} for path in paths}


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
    from hepta import hia_agent_service as service_module
    from hepta.hia_agent_service import HIAAgentService
    from hepta.hia_agent_journal_native import TOOLS
    from hepta.hia_artifact_page_native import SELECTOR, NativeArtifactPage, PageSession, installed_artifact_page
    from tools.build_hia_artifact_page import build
    from tools.build_hia_json_preflight import current_sources
    with ExitStack() as stack:
        if args.evidence_dir is None:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hia-artifact-read-callers-')))
        else:
            folder = args.evidence_dir.absolute(); folder.mkdir(mode=0o700, parents=True)
        if args.cold_report:
            report = json.loads(args.cold_report.read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            manifest = build(folder / 'page', compiler, args.cold_report)
            scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
        else:
            manifest = args.manifest.resolve(strict=True)
            scope = 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'
        source_manifest = current_sources() if args.cold_report else None
        owner = installed_artifact_page(manifest)
        identities_before = bundle_identities(manifest)
        source_before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_NAMES}
        modules = args.module or DEFAULT_MODULES
        loaded = list(flatten(unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in modules)))
        loaded_ids = [test.id() for test in loaded]
        if not loaded_ids or len(set(loaded_ids)) != len(loaded_ids):
            parser.error('caller IDs must be nonempty and unique')
        executed, retained = [], []
        entries, steps, tools_with_owner, tools_without_owner, per_test = Counter(), Counter(), Counter(), Counter(), {}
        current = ['outside-test']
        original_read, original_step, original_call = NativeArtifactPage.read, PageSession.step, HIAAgentService.call
        def forbidden(name):
            def fail(*arguments, **keywords):
                retained.append({'test': current[0], 'owner': name})
                raise AssertionError('retained artifact-read semantic owner entered: ' + name)
            return fail
        def entered(image, service, arguments):
            if (image.policy.image_sha256 != owner.policy.image_sha256
                    or image.wire.image_sha256 != owner.wire.image_sha256):
                raise AssertionError('ordinary artifact read selected another bundle')
            entries['read'] += 1
            per_test[current[0]] = per_test.get(current[0], 0) + 1
            # These symbols are used by the retained page implementation. The
            # selected HIA page invokes the admitted wire image directly. Store
            # get/schema/SQL remain independent, declared foreign operations.
            with patch.object(service_module, 'wire', forbidden('page wire')), \
                 patch.object(service_module, 'digest', forbidden('cursor digest')), \
                 patch.object(service_module.base64, 'b64encode', forbidden('page base64')):
                return original_read(image, service, arguments)
        def step(session, packet=None):
            status = original_step(session, packet)
            steps[str(status)] += 1
            return status
        def call(service, tool, arguments):
            before = entries['read']
            try:
                return original_call(service, tool, arguments)
            finally:
                name = tool if type(tool) is str else type(tool).__name__
                target = tools_with_owner if entries['read'] > before else tools_without_owner
                target[name] += 1
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                current[0] = test.id(); executed.append(test.id()); super().startTest(test)
            def stopTest(self, test):
                super().stopTest(test); current[0] = 'outside-test'
        start = time.monotonic()
        with ExitStack() as selected:
            selected.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
            selected.enter_context(patch.object(HIAAgentService, '_reference_hia_read', forbidden('_reference_hia_read')))
            selected.enter_context(patch.object(NativeArtifactPage, 'read', entered))
            selected.enter_context(patch.object(PageSession, 'step', step))
            selected.enter_context(patch.object(HIAAgentService, 'call', call))
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(unittest.TestSuite(loaded))
        source_after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_NAMES}
        identities_after = bundle_identities(manifest)
        stable = source_before == source_after and identities_before == identities_after
        cold_stable = current_sources() == source_manifest if args.cold_report else None
        all_tools = set(TOOLS[:-1]) <= (set(tools_with_owner) | set(tools_without_owner))
        native_read = entries['read'] > 0 and tools_with_owner['hia_read'] > 0 and steps['2'] > 0
        anomalies = (result.errors, result.failures, result.skipped, result.expectedFailures, result.unexpectedSuccesses)
        passed = (result.testsRun == len(loaded_ids) and executed == loaded_ids and not any(anomalies)
                  and not retained and native_read and all_tools and stable and cold_stable is not False)
        record = {
            'schema': 'hepta.hia.artifact-read-selected-callers.v1',
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
            'ordinary_hia_read_entered_native': native_read, 'actual_native_entries': dict(entries),
            'actual_native_step_returns': dict(steps), 'per_test_entries': per_test,
            'all_eleven_agent_tools_exercised': all_tools, 'agent_tools_with_native_page': dict(tools_with_owner),
            'agent_tools_without_native_page': dict(tools_without_owner),
            'other_ten_tools_do_not_require_native_page_entry': True,
            'source_sha256': source_before, 'source_after_sha256': source_after,
            'manifest_path': str(manifest), 'bundle_manifest': json.loads(manifest.read_bytes()),
            'policy_image_sha256': owner.policy.image_sha256, 'wire_image_sha256': owner.wire.image_sha256,
            'bundle_files_before': identities_before, 'bundle_files_after': identities_after,
            'source_manifest_images_stable': stable, 'matching_cold_source_closure_stable': cold_stable,
            'source_manifest': source_manifest, 'wall_seconds': time.monotonic() - start,
            'evidence_dir': str(folder), 'evidence_dir_retained': args.evidence_dir is not None,
            'subprocess_entries_in_parent_counters': False, 'subprocess_environment_is_controlled_by_original_tests': True,
            'default_whole_regression_claimed': False, 'sqlite_durability_replaced': False,
            'AgentStore_file_and_metadata_owners_remain_independent': True,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': record['status'], 'tests_run': result.testsRun,
                          'native_read': native_read, 'all_eleven_tools': all_tools,
                          'scope': scope, 'report': str(args.output)}), flush=True)
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
