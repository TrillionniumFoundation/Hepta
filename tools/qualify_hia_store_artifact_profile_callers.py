"""Run ten complete original Store caller modules, with 130 unchanged methods.

The nine ordinary modules (112) and the artifact-store module (18) retain their
own ordered inventories, original fixture setup and all deadlines. Explicit
administrator-bundle modules remain separate; this command does not add the
new Store image to them or claim a whole-project dynamic caller closure.
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
FIXTURE_NAME = 'tests/fixtures/hia_store_artifact_profile_callers_73f1634.json'
FIXTURE_SHA256 = 'acbb8c221d80788ef96eb4b596c24fc1c3eb410229e605b2f01ef77e5530b7d6'
ARTIFACT_MODULE = 'tests.test_hia_agent_artifact_store_native'


def original_inventory():
    raw = (ROOT / FIXTURE_NAME).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('original Store caller inventory changed')
    original = json.loads(raw)
    ordinary = original['prior_ordinary_9_modules']
    ordinary_ids = original['prior_ordinary_112_ordered_ids']
    artifact = original['modules'][ARTIFACT_MODULE]
    if (len(ordinary) != 9 or len(ordinary_ids) != 112 or artifact['count'] != 18
            or len(artifact['ordered_ids']) != 18 or ARTIFACT_MODULE in ordinary
            or original['candidate_module_count'] != 40
            or original['candidate_complete_module_method_count'] != 612
            or len(original['prior_separate_8_modules']) != 8
            or len(original['prior_separate_128_ordered_ids']) != 128
            or original['every_listed_method_claimed_to_enter_Store_artifact_owner'] is not False):
        raise ValueError('complete original Store inventory scope differs')
    flattened = [name for module in ordinary for name in original['modules'][module]['ordered_ids']]
    if flattened != ordinary_ids:
        raise ValueError('the original ordinary ordered inventory differs')
    modules = [*ordinary, ARTIFACT_MODULE]
    planned = [*ordinary_ids, *artifact['ordered_ids']]
    if len(set(planned)) != 130:
        raise ValueError('the original two Store groups overlap or lost a method')
    return original, modules, planned


def admit_original_sources(root, original):
    """Preserve all selected and separate original files, except helper count."""
    from hepta.hia_native_helpers import HELPERS
    count = len(HELPERS)
    if count < 37:
        raise ValueError('the original helper registry lost an owner')
    baseline_line = b'        self.assertEqual(len(HELPERS), 37)\n'
    current_line = ('        self.assertEqual(len(HELPERS), ' + str(count) + ')\n').encode()
    names = {*original['prior_ordinary_9_modules'], *original['prior_separate_8_modules'], ARTIFACT_MODULE}
    adjustments = []
    for module in sorted(names):
        record = original['modules'][module]
        name, digest = record['source'], record['sha256']
        raw = (root / name).read_bytes()
        actual = sha256(raw).hexdigest()
        if actual == digest:
            continue
        if (name != 'tests/test_hia_worker_native_helpers.py' or raw.count(current_line) != 1
                or sha256(raw.replace(current_line, baseline_line, 1)).hexdigest() != digest):
            raise ValueError('original Store caller source differs: ' + name)
        adjustments.append({'path': name, 'original_sha256': digest, 'current_sha256': actual,
            'original_helper_count': 37, 'current_helper_count': count,
            'sole_permitted_change': 'one exact registry-count assertion decimal literal',
            'all_other_source_bytes_unchanged': True})
    return adjustments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.hia_selfhost_contract import file_digests
    from tools.build_hia_store_artifact_profile import INPUTS
    from hepta import hia_agent_store as api
    from hepta.hia_store_artifact_profile_native import (StoreArtifactProfileFrame, SELECTOR,
        REQUEST_MAGIC, OUTPUT_BYTES, installed_store_artifact_profile)
    original, modules, expected = original_inventory()
    count_adjustments = admit_original_sources(ROOT, original)
    suite, planned = load_declared_suite(modules)
    planned = list(planned)
    if planned != expected:
        raise ValueError('complete original 130-method Store caller inventory differs')
    pinned_modules = {*modules, *original['prior_separate_8_modules']}
    original_files = {original['modules'][module]['source']: original['modules'][module]['sha256']
                      for module in pinned_modules}
    def source_pins():
        paths = {*INPUTS, *original_files, FIXTURE_NAME, 'tools/qualify_hia_store_artifact_profile_callers.py'}
        return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}}
    before = source_pins()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.cold_report is not None:
        from tools.build_hia_store_artifact_profile import build
        outer = json.loads(args.cold_report.read_bytes())
        nested = json.loads(Path(outer['nested_report']).read_bytes())
        manifest = build(args.evidence / 'qualified', Path(nested['generations'][-1]['produced_image']), args.cold_report)
        scope = 'MATCHING_SOURCE_COLD_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES'
    else:
        manifest = args.development_manifest.resolve(strict=True)
        scope = 'EXPLICIT_DEVELOPMENT_TEN_ORIGINAL_STORE_ARTIFACT_PROFILE_CALLER_MODULES'
    image = installed_store_artifact_profile(str(manifest))
    bundle = {str(path): sha256(path.read_bytes()).hexdigest()
              for path in sorted(manifest.parent.rglob('*')) if path.is_file()}
    started, stopped, reference_calls = [], [], []
    entries, frame_counts, mode_counts = Counter(), Counter(), Counter()
    per_test_entries, per_test_modes = defaultdict(Counter), defaultdict(Counter)
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

    initializer, actual_entry = StoreArtifactProfileFrame.__init__, image._entry
    def counted_frame(frame, selected, *arguments, **keywords):
        if selected is not image:
            raise AssertionError('ordinary caller selected a different Store artifact image')
        initializer(frame, selected, *arguments, **keywords)
        frame_counts[active[0]] += 1
        mode_counts[str(frame.mode)] += 1
        per_test_modes[active[0]][str(frame.mode)] += 1

    def counted_entry(source, size, output, capacity, state, extent):
        magic, event = struct.unpack('<2Q', ctypes.string_at(source, 16))
        code = actual_entry(source, size, output, capacity, state, extent)
        if magic != REQUEST_MAGIC or code != OUTPUT_BYTES:
            raise AssertionError('Store artifact machine return differs from its declared ABI')
        key = 'continuation:' + str(event)
        entries[key] += 1
        per_test_entries[active[0]][key] += 1
        return code

    def forbidden(*arguments, **keywords):
        reference_calls.append(active[0])
        raise AssertionError('selected Store caller entered one of eight retained original bodies')

    selection = {SELECTOR: str(manifest)}
    if args.cold_report is not None:
        # The original 18-method fixture itself consumes its original cold
        # selector and invokes its unchanged strict builder. No fake receipt,
        # replaced setUpClass or development substitute is introduced.
        selection['HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT'] = str(args.cold_report)
    artifact_fixture_selection = selection.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT',
                                               os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT'))
    begin = time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, selection))
        for name in ('_put_reference', '_json_reference', '_ref_reference', '_get_reference',
                     '_get_json_reference', '_resolve_uri_reference', '_profile_reference', '_check_profile_reference'):
            stack.enter_context(patch.object(api.AgentStore, name, forbidden))
        stack.enter_context(patch.dict(api._STORE_ARTIFACT_PROFILE_REFERENCES,
            {name: forbidden for name in api._STORE_ARTIFACT_PROFILE_REFERENCES}))
        stack.enter_context(patch.object(StoreArtifactProfileFrame, '__init__', counted_frame))
        stack.enter_context(patch.object(image, '_entry', counted_entry))
        with (args.evidence / 'tests.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    stable = source_pins() == before and all(sha256(Path(name).read_bytes()).hexdigest() == digest
                                             for name, digest in bundle.items())
    anomalies = ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')
    clean = result.wasSuccessful() and all(not getattr(result, name) for name in anomalies)
    artifact_ids = original['modules'][ARTIFACT_MODULE]['ordered_ids']
    ordinary_ids = original['prior_ordinary_112_ordered_ids']
    observed_artifact_entries = sum(sum(per_test_entries[name].values()) for name in artifact_ids)
    observed_ordinary_entries = sum(sum(per_test_entries[name].values()) for name in ordinary_ids)
    passed = (clean and stable and started == stopped == planned and result.testsRun == 130
              and not reference_calls and observed_artifact_entries > 0 and observed_ordinary_entries > 0
              and entries['continuation:0'] > 0 and entries['continuation:1'] > 0 and entries['continuation:2'] > 0)
    groups = {'ordinary_112': {'modules': original['prior_ordinary_9_modules'], 'ordered_ids': ordinary_ids,
                             'original_source_sha256': {
                                 original['modules'][name]['source']: original['modules'][name]['sha256']
                                 for name in original['prior_ordinary_9_modules']},
                             'actual_native_entries': observed_ordinary_entries},
              'artifact_store_18': {'modules': [ARTIFACT_MODULE], 'ordered_ids': artifact_ids,
                                    'original_source_sha256': {
                                        original['modules'][ARTIFACT_MODULE]['source']:
                                        original['modules'][ARTIFACT_MODULE]['sha256']},
                                    'actual_native_entries': observed_artifact_entries}}
    report = {'schema': 'hepta.hia.store-artifact-profile-ten-original-callers.v1',
        'status': 'PASS' if passed else 'FAIL', 'scope': scope,
        'original_baseline_commit': original['base_commit'], 'original_groups': groups,
        'original_modules': modules, 'planned': planned, 'started': started, 'stopped': stopped,
        'actual_tests': result.testsRun, 'wall_seconds': time.monotonic() - begin,
        'errors': [(test.id(), error) for test, error in result.errors],
        'failures': [(test.id(), error) for test, error in result.failures],
        'skipped': [(test.id(), reason) for test, reason in result.skipped],
        'expected_failures': [(test.id(), error) for test, error in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'actual_store_artifact_profile_frames': sum(frame_counts.values()),
        'frames_by_original_test': dict(frame_counts), 'frames_by_mode': dict(mode_counts),
        'modes_by_original_test': dict(per_test_modes), 'actual_native_event_counts': dict(entries),
        'native_event_counts_by_original_test': dict(per_test_entries),
        'native_image_sha256': image.image_sha256, 'reference_calls': reference_calls,
        'all_eight_retained_bodies_forbidden': True,
        'reference_poison_scope': 'test process; subprocesses retain their original environment and do not inherit Python patches',
        'all_ten_original_modules_unfiltered': True, 'original_test_budgets_changed': False,
        'original_artifact_fixture_cold_selector': artifact_fixture_selection,
        'original_artifact_bytes_limit': 67108864, 'original_store_subprocess_deadline_seconds': 60,
        'new_production_wall_cap': False, 'original_18_fixture_setup_replaced': False,
        'source_and_bundle_unchanged': stable, 'source_pins': before, 'bundle_pins': bundle,
        'original_registry_count_assertion_adjustments': count_adjustments,
        'separate_original_administrator_scope_gates': original['prior_separate_8_modules'],
        'separate_original_administrator_scope_ordered_ids': original['prior_separate_128_ordered_ids'],
        'whole_project_dynamic_caller_closure_claimed': False, 'whole_native_delivery_qualified': False}
    (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'actual_tests', 'wall_seconds',
                                                 'actual_store_artifact_profile_frames')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
