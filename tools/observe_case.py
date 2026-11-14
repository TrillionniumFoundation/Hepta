"""Run one unchanged original method with exact retained native inputs and observation."""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch
from budget_profile import Profile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--retained', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--method', required=True)
    args = parser.parse_args()
    expected = json.loads(args.inputs.read_bytes())
    assert expected['methods'] == [args.method]
    assert tuple(sys.version_info[:3]) == tuple(expected['python_version'])
    source, retained, evidence = args.source.resolve(), args.retained.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source))
    for key in tuple(os.environ):
        if key.startswith('HEPTA_HIA_'):
            del os.environ[key]
    nested = retained / 'original-nested-evidence/ArtifactNamespaceNativeTests'
    selectors = {
        'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST': nested / 'namespace/manifest.json',
        'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST': nested / 'publication/build.json',
        'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': nested / 'request/manifest.json',
        'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': nested / 'budget/manifest.json',
        'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST': retained / 'build/manifest.json',
    }
    os.environ.update({key: str(value) for key, value in selectors.items()})
    from tools import hia_selfhost_contract as contract
    from tools import build_hia_json_preflight as builder
    from tools import hia_agent_native_qualification as client_api
    from hepta import hia_agent_service as service_api, hia_agent_store as store_api
    from hepta import artifact_publication_native as publication
    from hepta import hia_execution_budget as budget_reference
    from hepta import hia_artifact_namespace_native as namespace_api
    from hepta import hia_request_journal_native as request_api
    from hepta import hia_execution_budget_native as budget_api
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from hepta.hia_store_lifecycle_native import NativeStoreLifecycleImage, StoreLifecycleFrame, _mapped_store_lifecycle
    from hepta.hia_machine_plan_control_native import MAGIC
    from tests.test_hia_artifact_namespace_native import ArtifactNamespaceNativeTests
    from tests.test_hia_agent_native_tools import NativeLifecycleTests

    frozen_build = json.loads((nested / 'joint-build.json').read_bytes())
    # Original complete checkout admission before the observed case, not a substitute inside it.
    current = builder.current_sources()
    assert current == frozen_build['source_manifest']
    expected_map = dict(current)
    del expected_map['docs/HIA_SELFHOST_CORE_SUPPORT.json']
    (evidence / 'EXPECTED-FRESH-MAP.json').write_text(json.dumps(expected_map, sort_keys=True, indent=2) + '\n')
    assert _mapped_store_lifecycle.cache_info().currsize == 0
    manifest = json.loads((retained / 'build/manifest.json').read_bytes())
    profile = Profile()
    original_entries = Counter()
    modes = Counter()
    forbidden_calls = []
    images = []
    clients = []
    report = {'schema': 'hepta.original-namespace-method-section-diagnostic.v2',
        'status': 'INCOMPLETE', 'python': sys.version, 'method': args.method,
        'source_commit': expected['source_commit'], 'source_tree': expected['source_tree'],
        'original_run': expected['original_run'], 'original_native_job': expected['original_native_job'],
        'original_test_id': expected['test_id'],
        'store_observer_revision': expected['store_observer_revision'],
        'store_observer_addendum': expected['store_observer_addendum'],
        'binary_scope': 'RETAINED_EXACT_ORIGINAL_RUN_INPUTS', 'qualification': False,
        'whole_native': False, 'new_fixture_compilations': 0,
        'selection': {key: str(value) for key, value in selectors.items()}}
    result = None
    failure = None

    def forbidden(*unused, **ignored):
        forbidden_calls.append(args.method)
        raise AssertionError('selected Store lifecycle entered retained policy')

    def map_observed(row, value, unused, ignored):
        started = time.monotonic_ns()
        matched = type(value) is dict and value == expected_map and list(value) == sorted(expected_map)
        row['fresh_map_paths'] = len(value)
        row['fresh_map_matches_exact_original'] = matched
        row['observer_after_timer_ns'] = time.monotonic_ns() - started
        assert matched, 'actual fresh map changed during original case'

    def context_observed(row, value, arguments, ignored):
        if type(value) is not dict or 'context' not in value:
            return
        # This single extra read is expressly diagnostic; it never changes created_ns.
        started = time.monotonic_ns()
        fetched = arguments[0].store.db.execute('SELECT created_ns FROM contexts WHERE id=?',
                                               (value['context']['id'],)).fetchone()
        profile.extra_observations.append({'kind': 'context-created-read', 'parent_span': row['id'],
            'context_id': value['context']['id'], 'created_ns': fetched['created_ns'],
            'sampled_at': value['sampled_at'], 'elapsed_ns': time.monotonic_ns() - started})

    def remaining_observed(row, value, arguments, ignored):
        context = arguments[1]
        row['remaining_ms'] = value
        row['context_id'] = context['ref']['id']
        row['budget'] = dict(context['budget'])

    original_json_init = NativeHiaJsonImage.__init__
    def json_init(image, raw, expected):
        # Only the exact Store image is observed by store_init below.  Its original
        # receipt predicate and constructor still run; the generic sampled wrapper
        # must not wrap the same entry a second time (immutable prior addendum).
        if type(image) is NativeStoreLifecycleImage:
            return original_json_init(image, raw, expected)
        label = type(image).__name__
        with profile.span('image-admission', label):
            original_json_init(image, raw, expected)
        actual = image._entry
        assert sha256(image._mapping[:]).hexdigest() == expected
        images.append({'kind': label, 'sha256': expected, 'bytes': len(raw)})
        image._entry = lambda *arguments: profile.native_call(label, actual, arguments)

    original_store_init = NativeStoreLifecycleImage.__init__
    def store_init(image, raw, expected, namespace=None):
        assert expected == manifest['image_sha256'] and sha256(raw).hexdigest() == expected
        with profile.span('image-admission', 'NativeStoreLifecycleImage'):
            original_store_init(image, raw, expected, namespace)
        assert sha256(image._mapping[:]).hexdigest() == expected
        actual = image._entry
        images.append({'kind': 'NativeStoreLifecycleImage', 'sha256': expected, 'bytes': len(raw)})
        def counted_entry(source, size, output, output_size, state, state_size):
            returned = profile.native_call('NativeStoreLifecycleImage', actual,
                (source, size, output, output_size, state, state_size))
            # Preserve the original qualifier's complete per-return observer.
            if size == len(image.table):
                assert output_size == 2048 and state_size == image.workspace_bytes
                assert type(returned) is int and returned in (0, 1, 2, 3, 4, 5)
                words = struct.unpack('<21Q', ctypes.string_at(state, 168))
                assert words[16] == MAGIC and words[19] in range(1, image.function_count + 1)
                assert struct.unpack('<2Q', ctypes.string_at(output, 16)) == (MAGIC, words[17])
                original_entries[words[19]] += 1
            return returned
        image._entry = counted_entry

    original_frame_init = StoreLifecycleFrame.__init__
    def frame_init(frame, image, mode, arguments, captures=(), *, witness=None):
        with profile.span('frame-initialization', 'StoreLifecycleFrame', {'mode': mode}):
            original_frame_init(frame, image, mode, arguments, captures, witness=witness)
        modes[mode] += 1

    original_client_init = client_api.ToolClient.__init__
    def client_init(client, *positional, **keywords):
        original_client_init(client, *positional, **keywords)
        clients.append(client)

    try:
        selected = ArtifactNamespaceNativeTests('test_original_agent_tools_and_campaign_with_all_three_owners_and_no_namespace_reference')
        with ExitStack() as stack:
            stack.enter_context(selected.old_namespace_forbidden(hashing=False, payload_io=False))
            stack.enter_context(patch.object(service_api.HIAAgentService, '_call_reference', side_effect=AssertionError('old request policy')))
            for cls in (budget_reference._ReferenceExecutionBudgetStore, budget_reference._ReferenceBudgetClaim):
                stack.enter_context(patch.object(cls, '__init__', side_effect=AssertionError('old budget policy')))
            for name in ('_initialize_reference', '_close_reference'):
                stack.enter_context(patch.object(store_api.AgentStore, name, forbidden))
            for name in ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE'):
                stack.enter_context(patch.object(store_api, name, forbidden))
            stack.enter_context(patch.object(NativeHiaJsonImage, '__init__', json_init))
            stack.enter_context(patch.object(NativeStoreLifecycleImage, '__init__', store_init))
            stack.enter_context(patch.object(StoreLifecycleFrame, '__init__', frame_init))
            stack.enter_context(patch.object(client_api.ToolClient, '__init__', client_init))

            def install(obj, name, kind, *, metadata=None, observed=None, counter=None):
                original = getattr(obj, name)
                stack.enter_context(patch.object(obj, name,
                    profile.wrapper(original, kind, name, metadata, observed, counter)))

            original_digests = contract.file_digests
            digest_wrapper = profile.wrapper(original_digests, 'fresh-admission', 'file_digests',
                                               observed=map_observed, counter='fresh_scans')
            stack.enter_context(patch.object(contract, 'file_digests', digest_wrapper))
            install(publication, '_admitted_code', 'code-admission', counter='code_admissions')
            install(publication, '_execute_native', 'publication-effect',
                metadata=lambda a, k: {'operation': a[1]}, counter='publication_effects')
            install(subprocess, 'run', 'subprocess', metadata=lambda a, k: {
                'argv': [os.fspath(v) for v in a[0]] if a and type(a[0]) in (list, tuple) else None})
            for name in ('put', 'json', 'get', 'get_json', 'resolve_uri', 'profile', 'check_profile'):
                install(store_api.AgentStore, name, 'public-store')
            for name in ('freeze', 'import_program', 'verify', 'emit', 'encoding', 'evaluate'):
                install(client_api.Session, name, 'client-stage')
            install(client_api.ToolClient, 'call', 'tool-call', metadata=lambda a, k: {'tool': a[1]})
            for name in ('_context', '_profile', '_program', '_required_claims', '_native', '_build_inputs',
                         '_hia_emit', '_compile', '_hia_evaluate', '_cost_ledger'):
                install(service_api.HIAAgentService, name, 'service')
            install(service_api.HIAAgentService, '_hia_context_reference', 'context-create', observed=context_observed)
            install(service_api.HIAAgentService, '_remaining_ms', 'remaining-budget', observed=remaining_observed)
            for owner, name in ((namespace_api.NamespaceState, 'call'),
                                (request_api.RequestState, 'call'),
                                (budget_api.BudgetState, 'call'),
                                (StoreLifecycleFrame, '_effect')):
                original = getattr(owner, name)
                stack.enter_context(patch.object(owner, name,
                    profile.aggregate_wrapper(original, owner.__name__ + '.' + name)))
            case = NativeLifecycleTests(args.method)
            suite = unittest.TestSuite([case])
            with (evidence / 'ORIGINAL-TEST.log').open('x') as stream, profile.span('original-method', case.id()):
                result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        report.update(status='OBSERVATIONS_COMPLETE', tests_run=result.testsRun,
            failures=[(case.id(), detail) for case, detail in result.failures],
            errors=[(case.id(), detail) for case, detail in result.errors],
            skipped=[(case.id(), why) for case, why in result.skipped],
            expected_failures=[(case.id(), detail) for case, detail in result.expectedFailures],
            unexpected_successes=[case.id() for case in result.unexpectedSuccesses],
            original_outcome='PASS' if result.wasSuccessful() else 'FAIL')
        assert result.testsRun == 1 and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
        assert not forbidden_calls and original_entries and modes
    except BaseException:
        failure = traceback.format_exc()
        report.update(status='DIAGNOSTIC_FAILURE', diagnostic_error=failure)
    finally:
        report.update(original_store_receipt_entries=dict(original_entries), store_modes=dict(modes),
                      forbidden_calls=forbidden_calls, actual_images=images, profile=profile.report())
        for index, client in enumerate(clients):
            (evidence / ('CLIENT-RECORDS-%02d.json' % index)).write_text(json.dumps(client.records, sort_keys=True, indent=2) + '\n')
        (evidence / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({key: value for key, value in report.items() if key not in ('profile', 'failures', 'errors')}, sort_keys=True))
        if failure:
            print(failure, file=sys.stderr)
    return 0 if report['status'] == 'OBSERVATIONS_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
