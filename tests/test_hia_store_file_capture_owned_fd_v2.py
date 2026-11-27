"""Independent v2 descriptor ownership controls; all old 3 + 8 methods remain."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
import unittest
from tests import hia_store_file_capture_controls as controls
from tests import hia_store_file_capture_owned_fd_v2_controls as owned
ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_STORE_FILE_CAPTURE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_STORE_FILE_CAPTURE_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STORE_FILE_CAPTURE_OWNED_FD_V2_EVIDENCE'


class StoreFileCaptureOwnedFDV2NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_file_capture import build
        from tools.build_hia_json_preflight import current_sources
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if (cold is None) == (development is None) or cold == '' or development == '':
            raise ValueError('require exactly one same-source cold or explicit DEV compiler')
        evidence = os.environ.get(EVIDENCE)
        cls.temporary = None
        if evidence == '':
            raise ValueError('explicit v2 evidence path is empty')
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-owned-fd-v2-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is not None:
            from tools.hia_cold_compiler import compiler_from_cold_report
            cls.compiler = compiler_from_cold_report(Path(cold))
        else:
            cls.compiler = Path(development)
        cls.cold = cold
        cls.compiler_raw, cls.sources = cls.compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', cls.compiler, cold, development=cold is None)

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = after == cls.sources and cls.compiler.read_bytes() == cls.compiler_raw
        controls.write(cls.root / 'component-custody.json', {
            'schema': 'hepta.hia.store-file-capture-owned-fd-component-custody.v2',
            'source_before': cls.sources, 'source_after': after,
            'source_and_compiler_unchanged': stable, 'manifest': str(cls.manifest),
            'matching_cold_report': cls.cold,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'whole_native_stack_qualified': False})
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('v2 control source or compiler changed')

    def setUp(self):
        self.output = self.root / self._testMethodName
        self.output.mkdir()

    def test_actual_directory_fdopen_and_close_failure_keep_one_descriptor_owner(self):
        script = ROOT / 'tests/hia_store_file_capture_owned_fd_v2_controls.py'
        rows = []
        with tempfile.TemporaryDirectory(prefix='hia-owned-fd-inputs-') as temporary:
            root = Path(temporary)
            file = root / 'data'
            file.write_bytes(b'payload')
            directory = root / 'directory'
            directory.mkdir()
            for label in owned.ORDINARY_CASES:
                pair = []
                for lane in ('original', 'selected'):
                    name = label + '.' + lane
                    controls.run_process(self.output, name, [
                        script, '--manifest', self.manifest, '--output', self.output / name,
                        '--ordinary', label, '--lane', lane,
                        '--path', directory if label == 'directory' else file],
                        env=controls.clean_environment(), timeout=60)
                    pair.append(json.loads((self.output / name / 'control.json').read_bytes()))
                self.assertEqual(controls.canonical(pair[0]['semantic']),
                                 controls.canonical(pair[1]['semantic']))
                for record in pair:
                    self.assertFalse(record['observer_closed_descriptor'])
                    self.assertEqual(record['semantic']['fdopen_closefd'], [False])
                    self.assertEqual(record['semantic']['close_attempt_count'], 1)
                if label == 'directory':
                    self.assertEqual(pair[1]['semantic']['result']['error']['cause']['type'],
                                     'builtins.IsADirectoryError')
                    self.assertEqual(pair[1]['semantic']['gained_count'], 0)
                rows.append({'id': label, 'original': pair[0], 'selected': pair[1]})
        self.assertEqual(len(rows), 6)
        controls.write(self.output / 'all-ordinary-v2.json', rows)

    def test_real_close_claim_and_both_return_channels_never_retry_after_loss(self):
        script = ROOT / 'tests/hia_store_file_capture_owned_fd_v2_controls.py'
        rows = []
        for port in owned.CLOSE_PORTS:
            for event in owned.ACK_EVENTS:
                for family in owned.FAMILIES:
                    label = port + '.' + event + '.' + family
                    controls.run_process(self.output, label, [
                        script, '--manifest', self.manifest, '--output', self.output / label,
                        '--port', port, '--event', event, '--family', family],
                        env=controls.clean_environment(), timeout=60)
                    row = json.loads((self.output / label / 'control.json').read_bytes())
                    self.assertTrue(row['same_exception'])
                    self.assertTrue(row['loss_retained'])
                    self.assertTrue(row['fenced'])
                    self.assertFalse(row['claim_is_close_confirmation'])
                    self.assertFalse(row['observer_closed_descriptor'])
                    self.assertEqual(row['extra_replay_entries'], 0)
                    expected = 0 if event == 'CLAIM' else 1
                    self.assertEqual(len(row['close_attempts']), expected)
                    self.assertEqual(len(row['actual_close_completions']), expected)
                    rows.append(row)
        self.assertEqual(len(rows), 24)
        controls.write(self.output / 'all-close-ACK-loss-v2.json', rows)
