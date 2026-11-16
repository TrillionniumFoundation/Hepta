"""Complete controls for Capture's explicit admission I/O capability.

The original Capture Source3/Native8/FDv2 Native2 and all caller gates remain
separate, unchanged requirements. These controls do not qualify whole-native I/O.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_EVIDENCE = 'HEPTA_HIA_NATIVE_ADMISSION_IO_SOURCE_EVIDENCE'
NATIVE_EVIDENCE = 'HEPTA_HIA_NATIVE_ADMISSION_IO_EVIDENCE'
COLD = 'HEPTA_HIA_STORE_FILE_CAPTURE_COLD_REPORT'
DEV = 'HEPTA_HIA_STORE_FILE_CAPTURE_DEVELOPMENT_COMPILER'
SOURCE_ACTIONS = ('paths', 'regular', 'io-failures', 'resolver-failures', 'cold-source')
NATIVE_ACTIONS = ('admission', 'cold-public', 'pinned', 'installed')


def evidence_directory(environment, phase):
    selected = os.environ.get(environment)
    if selected == '':
        raise ValueError('empty explicit admission evidence directory')
    parent = None
    if selected is not None:
        parent = Path(selected).absolute()
        parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=phase + '-' + str(os.getpid()) + '-', dir=parent))
    from tests.hia_native_admission_io_controls import write
    write(root / 'invocation.json', {
        'schema': 'hepta.hia.native-admission-invocation.v1',
        'phase': phase, 'argv': list(sys.argv), 'pid': os.getpid(),
        'ppid': os.getppid(), 'pgid': os.getpgrp(), 'started_ns': time.time_ns(),
        'executable': sys.executable,
        'enclosing_source_build_observations': os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS'),
        'original_Capture_gates_replaced': False,
        'retained_diagnostics': str(root)})
    return root


class NativeAdmissionIOSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_native_admission_io_controls import sources
        cls.root = evidence_directory(SOURCE_EVIDENCE, 'source')
        cls.before = sources()
        cls.regular_observer_status = 'NOT_RUN'
        cls.regular_observer_scope = None

    @classmethod
    def tearDownClass(cls):
        from tests.hia_native_admission_io_controls import sources, write
        after = sources()
        write(cls.root / 'source-custody.json', {'source_before': cls.before,
              'source_after': after, 'unchanged': cls.before == after,
              'runtime': sys.version, 'all_original_gates_still_required': True,
              'regular_observer_status': cls.regular_observer_status,
              'regular_observer_scope': cls.regular_observer_scope,
              'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
              'legacy_v1_failure_reclassified': False})
        if cls.before != after:
            raise AssertionError('source changed during admission Source controls')

    def run_control(self, action, *, regular_observer='legacy-v1'):
        from tests.hia_store_file_capture_controls import run_process, clean_environment
        from tools.read_hia_native_admission_io import child, matched_child, MATCHED_STATUS
        script = ROOT / 'tests/hia_native_admission_io_controls.py'
        arguments = [script, '--action', action, '--output', self.root / action]
        if regular_observer in ('matched-v2', 'matched-v3'):
            self.assertEqual(action, 'regular')
            arguments += ['--regular-observer', regular_observer]
        else:
            self.assertEqual(regular_observer, 'legacy-v1')
        run_process(self.root, action, arguments, env=clean_environment(), timeout=60)
        if regular_observer in ('matched-v2', 'matched-v3'):
            report = matched_child(self.root, repository=ROOT, observer=regular_observer)
            self.assertEqual(report['status'], MATCHED_STATUS)
            self.assertEqual(report['whole_admission_qualification'], 'HOLD')
            self.assertIs(report['all_input_equivalence'], False)
            self.assertIs(report['legacy_v1_failure_reclassified'], False)
            type(self).regular_observer_status = report['status']
            type(self).regular_observer_scope = report['observations']
        else:
            report = child(self.root, action, repository=ROOT)
            self.assertEqual(report['status'], 'PASS')

    def test_01_complete_runtime_path_and_source_anchor_originals(self):
        self.run_control('paths')

    def test_02_original_regular_reader_and_descriptor_integrity(self):
        self.run_control('regular', regular_observer='matched-v3')

    def test_03_complete_real_descriptor_IO_failure_table(self):
        self.run_control('io-failures')

    def test_04_complete_resolver_capability_failure_table(self):
        self.run_control('resolver-failures')

    def test_05_fresh_shared_and_capture_imports_do_not_use_business_OS(self):
        self.run_control('cold-source')


class NativeAdmissionIONativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_file_capture import build
        from tools.build_hia_json_preflight import current_sources
        cold, development = os.environ.get(COLD), os.environ.get(DEV)
        if (cold is None) == (development is None) or cold == '' or development == '':
            raise ValueError('require exactly one matching cold report or explicit DEV compiler')
        cls.root = evidence_directory(NATIVE_EVIDENCE, 'native')
        cls.before = current_sources();cls.cold = cold
        if cold is not None:
            raw = Path(cold).read_bytes();outer = json.loads(raw)
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.cold_raw = raw
        else:
            cls.compiler = Path(development);cls.cold_raw = None
        cls.compiler_raw = cls.compiler.read_bytes()
        cls.manifest = build(cls.root / 'built', cls.compiler, cold, development=cold is None)

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        from tests.hia_native_admission_io_controls import write
        after = current_sources()
        stable = (after == cls.before and cls.compiler.read_bytes() == cls.compiler_raw
                  and (cls.cold is None or Path(cls.cold).read_bytes() == cls.cold_raw))
        write(cls.root / 'component-custody.json', {
            'schema': 'hepta.hia.native-admission-component.v1',
            'source_before': cls.before, 'source_after': after, 'unchanged': stable,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'manifest': str(cls.manifest), 'manifest_sha256': sha256(cls.manifest.read_bytes()).hexdigest(),
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'whole_native_stack_qualified': False, 'old_Capture_5101_equivalence_asserted': False})
        if not stable:
            raise AssertionError('native admission component source/cold/compiler changed')

    def run_control(self, action):
        from tests.hia_store_file_capture_controls import run_process, clean_environment
        from tools.read_hia_native_admission_io import child
        script = ROOT / 'tests/hia_native_admission_io_controls.py'
        # The old installed helper still retains its 60-second budget per
        # owned command. This NEW outer control gives its complete sequence
        # a declared 600-second owner; no old budget is increased or replaced.
        timeout = 600 if action == 'installed' else 60
        run_process(self.root, action,
            [script, '--action', action, '--output', self.root / action,
             '--manifest', self.manifest],
            env=clean_environment(), timeout=timeout)
        report = child(self.root, action, repository=ROOT)
        self.assertEqual(report['status'], 'PASS')

    def test_01_all_fresh_reads_identity_changes_symlinks_and_terminal_rereads(self):
        self.run_control('admission')

    def test_02_cold_public_route_and_all_unchanged_OS_races(self):
        self.run_control('cold-public')

    def test_03_actual_worker_bundle_view_keeps_fresh_admission(self):
        self.run_control('pinned')

    def test_04_complete_original_installed_worker_with_actual_capsule(self):
        self.run_control('installed')
