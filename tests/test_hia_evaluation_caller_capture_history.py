"""Physical pair and old-authority controls for Evaluation caller source history."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tests import hia_cold_caller_selection_history as history

ROOT = Path(__file__).resolve().parents[1]
NAME = history.EVALUATION_CAPTURE_PATH
PATHS = (*history.EVALUATION_CAPTURE_EXPECTED,
         history.EVALUATION_CAPTURE_FIXTURE, history.INVERSE_HELPER, history.FIXTURE)


def stage(root):
    for name in PATHS:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())


class EvaluationCallerCaptureTests(unittest.TestCase):
    def test_current_pair_restores_both_complete_files_before_the_original_selection(self):
        raw = (ROOT / NAME).read_bytes()
        selected, pair, saved = history._evaluation_capture_predecessor(NAME, raw, ROOT, Path.read_bytes)
        self.assertEqual(history.pin(selected), history.EXPECTED[NAME]['new'])
        self.assertEqual(set(saved), set(PATHS) - {history.FIXTURE})
        self.assertEqual(pair, history._evaluation_capture_proof())
        original, proof = history.reviewed(NAME, raw, root=ROOT)
        self.assertEqual(history.pin(original), history.EXPECTED[NAME]['old'])
        self.assertEqual(proof['evaluation_caller_capture'], pair)
        self.assertEqual(proof['exact_selection_splices'], 2)
        self.assertEqual(pair['original_complete_callers'], 81)
        self.assertFalse(pair['physical_capture_rewritten'])
        prior = {'path': NAME, 'current_bytes': len(original),
                 'current_sha256': history.pin(original)['sha256'], 'separate_original': 'retained'}
        rebound = history.bind_adjustment(prior, raw, proof)
        self.assertEqual(rebound['separate_original'], 'retained')
        self.assertEqual(rebound['current_sha256'], history.current_pin(NAME)['sha256'])

    def test_previous_complete_qualifier_keeps_only_its_original_v1_authority(self):
        raw = (ROOT / NAME).read_bytes()
        prior, _, _ = history._evaluation_capture_predecessor(NAME, raw, ROOT, Path.read_bytes)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / history.FIXTURE
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / history.FIXTURE).read_bytes())
            consumed = []
            def take(path):
                consumed.append(path)
                return path.read_bytes()
            original, proof = history.reviewed(NAME, prior, root=root, take=take)
            self.assertEqual(history.pin(original), history.EXPECTED[NAME]['old'])
            self.assertNotIn('evaluation_caller_capture', proof)
            self.assertEqual(consumed, [target, target])

    def test_each_missing_tampered_or_partially_reverted_pair_input_is_rejected(self):
        raw = (ROOT / NAME).read_bytes()
        for name in PATHS:
            for missing in (True, False):
                with self.subTest(path=name, missing=missing), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    stage(root)
                    if missing:
                        (root / name).unlink()
                    else:
                        (root / name).write_bytes((root / name).read_bytes() + b' ')
                    with self.assertRaises((ValueError, OSError)):
                        history.reviewed(NAME, raw, root=root)
        from tools.hia_frozen_component_sources import history_inverse
        import json
        value = json.loads((ROOT / history.EVALUATION_CAPTURE_FIXTURE).read_bytes())
        for name, expected in history.EVALUATION_CAPTURE_EXPECTED.items():
            with self.subTest(partially_reverted=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root)
                (root / name).write_bytes(history_inverse((root / name).read_bytes(),
                    value['files'][name], expected['old']))
                with self.assertRaises(ValueError):
                    history.reviewed(NAME, raw, root=root)

    def test_every_pair_capture_is_rechecked_after_the_older_selection_returns(self):
        raw = (ROOT / NAME).read_bytes()
        original_review = history._review_selection
        for name in PATHS[:-1]:
            late = [False]
            def wrapped(*args, **kwargs):
                result = original_review(*args, **kwargs)
                late[0] = True
                return result
            def take(path):
                data = path.read_bytes()
                return data + b' ' if late[0] and path == ROOT / name else data
            with self.subTest(path=name), patch.object(history, '_review_selection', wrapped):
                with self.assertRaises(ValueError):
                    history.reviewed(NAME, raw, root=ROOT, take=take)

    def test_rebound_partial_cross_path_and_boolean_proofs_cannot_replace_whole_identity(self):
        raw = (ROOT / NAME).read_bytes()
        original, proof = history.reviewed(NAME, raw, root=ROOT)
        prior = {'path': NAME, 'current_bytes': len(original),
                 'current_sha256': history.pin(original)['sha256']}
        for field in proof['evaluation_caller_capture']:
            changed = deepcopy(proof)
            del changed['evaluation_caller_capture'][field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                history.bind_adjustment(prior, raw, changed)
        for field in ('complete_predecessor_restored', 'complete_successor_replayed',
                      'terminal_reread_identical', 'physical_capture_rewritten',
                      'whole_native_delivery_qualified'):
            changed = deepcopy(proof)
            changed['evaluation_caller_capture'][field] = int(changed['evaluation_caller_capture'][field])
            with self.subTest(boolean_alias=field), self.assertRaises(ValueError):
                history.bind_adjustment(prior, raw, changed)
        detached = history._evaluation_capture_proof()
        detached['complete_pair'][NAME]['new']['bytes'] += 1
        self.assertEqual(history._evaluation_capture_proof(), proof['evaluation_caller_capture'])
        changed = deepcopy(proof)
        changed['evaluation_caller_capture']['complete_pair'][NAME]['new']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            history.bind_adjustment(prior, raw, changed)
        with self.assertRaises(ValueError):
            history.bind_adjustment({**prior, 'path': 'tools/qualify_hia_emission_callers.py'}, raw, proof)

    def test_unknown_whole_source_gets_no_pair_projection_or_authority_reads(self):
        raw = (ROOT / NAME).read_bytes()
        for changed in (raw + b' ', b'#' + raw[1:]):
            with self.subTest(bytes=len(changed)):
                restored, proof = history.reviewed(NAME, changed,
                    take=lambda path: self.fail('unknown source borrowed an authority'))
                self.assertEqual(restored, changed)
                self.assertIsNone(proof)

    def test_fresh_pair_reader_imports_no_product_builder_generator_or_oracle(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname.startswith(('hepta.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tests import hia_cold_caller_selection_history as h
root=Path(sys.argv[1]);name=h.EVALUATION_CAPTURE_PATH
original,proof=h.reviewed(name,(root/name).read_bytes(),root=root)
assert h.pin(original)==h.EXPECTED[name]['old']
assert proof['evaluation_caller_capture']['original_complete_callers']==81
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
