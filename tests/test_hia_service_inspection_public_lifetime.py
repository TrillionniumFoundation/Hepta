"""Separate complete temporary-receiver supplement; original 3+8 stay intact."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_INSPECTION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_SERVICE_INSPECTION_DEVELOPMENT_COMPILER'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_INSPECTION_PUBLIC_LIFETIME_SOURCE_EVIDENCE'
EVIDENCE = 'HEPTA_HIA_SERVICE_INSPECTION_PUBLIC_LIFETIME_EVIDENCE'
SOURCE_FREEZE_SHA256 = 'be107f3a2b4250747d8dfebfbb4d2154dca414776b76a45d4ecbc87ed31a79ef'


def new_root(test, environment):
    value = os.environ.get(environment)
    if value == '':
        raise ValueError('empty supplemental evidence selector')
    if value is None:
        temporary = tempfile.TemporaryDirectory(prefix='hia-inspection-lifetime-')
        test.addCleanup(temporary.cleanup)
        return Path(temporary.name)
    directory = Path(value).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    return directory


def invoke_qualifier(arguments):
    # Standard-library-only tool import; originals execute in owned clean children.
    from tools.qualify_hia_service_inspection_public_lifetime import main
    return main(arguments)


def capture_report(path):
    raw = path.read_bytes()
    return raw, json.loads(raw), sha256(raw).hexdigest()


def originals(root):
    target = root / 'originals'
    code = invoke_qualifier(['--backend', 'originals',
        '--source-freeze-sha256', SOURCE_FREEZE_SHA256,
        '--evidence', str(target)])
    path = target / 'report.json'
    raw, report, digest = capture_report(path)
    if code != 0 or report['status'] != 'PASS':
        raise AssertionError(('complete original supplement failed', code, report))
    if (len(report['planned']) != 16 or report['actual_original_invocations'] != 32
            or not report['two_fresh_original_children_equal']
            or not report['source_unchanged']
            or any(command['status'] != 'PASS' for command in report['commands'])):
        raise AssertionError('original supplement scope or process custody differs')
    return path, raw, report, digest


class ServiceInspectionPublicLifetimeSourceTests(unittest.TestCase):
    def test_complete_temporary_receivers_through_unselected_public_dispatch(self):
        root = new_root(self, SOURCE_EVIDENCE)
        path, raw, original, digest = originals(root)
        code = invoke_qualifier(['--backend', 'unselected',
            '--source-freeze-sha256', SOURCE_FREEZE_SHA256,
            '--original-report', str(path), '--original-report-sha256', digest,
            '--evidence', str(root / 'unselected')])
        candidate_raw, candidate, candidate_sha = capture_report(root / 'unselected/report.json')
        self.assertEqual(code, 0)
        self.assertEqual(candidate['status'], 'PASS')
        self.assertEqual(candidate['planned'], original['planned'])
        self.assertEqual(candidate['started'], original['planned'])
        self.assertEqual(candidate['stopped'], original['planned'])
        self.assertEqual(candidate['mismatches'], [])
        self.assertEqual(candidate['observer_errors'], [])
        self.assertTrue(candidate['source_and_originals_unchanged'])
        self.assertTrue(candidate['all_16_public_invocations_accounted'])
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual((root / 'unselected/report.json').read_bytes(), candidate_raw)


class ServiceInspectionPublicLifetimeNativeTests(unittest.TestCase):
    def test_complete_temporary_receivers_through_actual_selected_public_dispatch(self):
        root = new_root(self, EVIDENCE)
        cold, development = (os.environ.get(name) for name in (COLD, DEVELOPMENT))
        if ((cold is None) == (development is None) or cold == '' or development == ''):
            raise ValueError('choose one nonempty matching cold or explicit development compiler')
        # Complete original bytes exist before this test builds or maps a candidate.
        path, raw, original, digest = originals(root)
        from tools.build_hia_service_inspection import build
        from tools.build_hia_json_preflight import current_sources
        sources = current_sources()
        if cold is None:
            compiler = Path(development)
        else:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        compiler_raw = compiler.read_bytes()
        manifests = {}
        def finish_custody():
            after = current_sources()
            stable = sources == after and compiler.read_bytes() == compiler_raw
            value = {'schema': 'hepta.hia.service-inspection-public-lifetime-custody.v1',
                'source_before': sources, 'source_after': after,
                'source_and_compiler_unchanged': stable,
                'compiler_sha256': sha256(compiler_raw).hexdigest(),
                'matching_cold_report': cold,
                'scope': 'DEVELOPMENT_COMPONENT' if cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
                'manifests': manifests, 'runtime': sys.version,
                'original_report_sha256': digest,
                'source_freeze_sha256': SOURCE_FREEZE_SHA256,
                'all_runtime_histories_proved': False, 'whole_native_stack_qualified': False}
            (root / 'component-custody.json').write_text(
                json.dumps(value, sort_keys=True, indent=2) + '\n')
            if not stable:
                raise AssertionError('supplemental source/compiler changed')
        self.addCleanup(finish_custody)
        manifest = build(root / 'built', compiler, cold, development=cold is None)
        manifests['inspection'] = str(manifest)
        code = invoke_qualifier(['--backend', 'native',
            '--source-freeze-sha256', SOURCE_FREEZE_SHA256,
            '--original-report', str(path), '--original-report-sha256', digest,
            '--manifest', str(manifest), '--evidence', str(root / 'native')])
        candidate_raw, candidate, candidate_sha = capture_report(root / 'native/report.json')
        self.assertEqual(code, 0)
        self.assertEqual(candidate['status'], 'PASS')
        self.assertEqual(candidate['planned'], original['planned'])
        self.assertEqual(candidate['started'], original['planned'])
        self.assertEqual(candidate['stopped'], original['planned'])
        self.assertEqual(candidate['mismatches'], [])
        self.assertEqual(candidate['observer_errors'], [])
        self.assertTrue(candidate['source_and_originals_unchanged'])
        inner_path = root / 'native/candidate/report.json'
        inner_raw = inner_path.read_bytes()
        self.assertEqual({'bytes': len(inner_raw), 'sha256': sha256(inner_raw).hexdigest()},
                         candidate['candidate_report_pin'])
        inner = json.loads(inner_raw)
        self.assertTrue(inner['actual_public_dispatch'])
        self.assertTrue(inner['selected_retained_complete_handlers_poisoned'])
        self.assertTrue(inner['constructor_only_injects_original_namespace'])
        self.assertEqual(inner['frame_counts'], {'1': 8, '2': 8})
        self.assertEqual(inner['public_dispatch_counts'], {'1': 8, '2': 8})
        self.assertTrue(all(value > 0 for value in inner['entries_by_case'].values()))
        self.assertEqual(inner['remaining_delivery_custody'], [])
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual((root / 'native/report.json').read_bytes(), candidate_raw)
        self.assertEqual(inner_path.read_bytes(), inner_raw)
