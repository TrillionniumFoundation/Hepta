"""Exact terminal helper history controls beside every original source gate."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_terminal_admission_source_history as history
from tests import hia_native_transport_worker_successor as transport

ROOT = Path(__file__).resolve().parents[1]


def write(root, name, raw):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)


class CurrentTerminalHistoryTests(unittest.TestCase):
    def stage(self, root):
        for name in (history.PATH, *history.DEPENDENCIES):
            write(root, name, (ROOT / name).read_bytes())

    def test_complete_source_inverse_and_actual_older_consumer_remain_exact(self):
        raw = (ROOT / history.PATH).read_bytes()
        old, proof = history.predecessor(ROOT, history.PATH, raw)
        self.assertEqual(history.pin(old), history.PREDECESSOR)
        self.assertEqual(proof['physical'], history.CURRENT)
        self.assertTrue(proof['complete_inverse_and_forward_replay_verified'])
        self.assertFalse(proof['physical_capture_rewritten'])
        capture = lambda name: (ROOT / name).read_bytes()
        expected = transport.reviewed_qualifier_dependency(old, capture)
        actual = transport.reviewed_qualifier_dependency(raw, capture)
        self.assertEqual(actual, expected)
        admission = transport._admit_qualifier_dependency(raw, capture)
        self.assertEqual(admission['current'], history.CURRENT)
        self.assertEqual(admission['current_terminal_source_history'], proof)
        self.assertEqual(admission['original'],
                         transport.QUALIFIER_DEPENDENCIES[history.PATH])

    def test_old_and_unrelated_sources_gain_no_new_history_dependency(self):
        raw = (ROOT / history.PATH).read_bytes()
        old, _ = history.predecessor(ROOT, history.PATH, raw)
        def forbidden(path):
            raise AssertionError('old source added a history dependency: ' + str(path))
        self.assertEqual(history.predecessor(ROOT, history.PATH, old, take=forbidden),
                         (old, None))
        self.assertEqual(history.predecessor(ROOT, 'unrelated.py', raw, take=forbidden),
                         (raw, None))

    def test_supplied_current_bytes_cannot_replace_selected_root_physical_source(self):
        raw = (ROOT / history.PATH).read_bytes()
        old, _ = history.predecessor(ROOT, history.PATH, raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.stage(root)
            write(root, history.PATH, old)
            with self.assertRaises(ValueError):
                history.predecessor(root, history.PATH, raw)

    def test_actual_consumer_refuses_each_missing_or_tampered_local_dependency(self):
        raw = (ROOT / history.PATH).read_bytes()
        for name in (history.PATH, *history.DEPENDENCIES):
            for missing in (True, False):
                with self.subTest(path=name, missing=missing), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.stage(root)
                    if missing:
                        (root / name).unlink()
                    else:
                        write(root, name, (root / name).read_bytes() + b' ')
                    with patch.object(transport, 'ROOT', root):
                        with self.assertRaises((ValueError, OSError)):
                            transport._current_terminal_dependency(raw,
                                lambda path: (root / path).read_bytes())

    def test_every_physical_capture_is_reread_before_return(self):
        raw = (ROOT / history.PATH).read_bytes()
        for name in (history.PATH, history.FIXTURE, history.ENGINE):
            with self.subTest(path=name):
                calls = {}
                def drifting(path):
                    calls[path] = calls.get(path, 0) + 1
                    data = path.read_bytes()
                    return data + b' ' if path == ROOT / name and calls[path] >= 2 else data
                with self.assertRaises(ValueError):
                    history.predecessor(ROOT, history.PATH, raw, take=drifting)

    def test_unknown_whole_source_is_rejected_by_the_original_complete_authority(self):
        raw = (ROOT / history.PATH).read_bytes()
        for changed in (raw + b' ', b'#' + raw[1:]):
            with self.subTest(bytes=len(changed)):
                self.assertEqual(history.predecessor(ROOT, history.PATH, changed),
                                 (changed, None))
                with self.assertRaises(ValueError):
                    transport.reviewed_qualifier_dependency(changed,
                        lambda name: (ROOT / name).read_bytes())

    def test_fresh_data_only_inverse_imports_no_product_test_builder_or_oracle(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname=='tests' or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_terminal_admission_source_history as h
root=Path(sys.argv[1])
raw=(root/h.PATH).read_bytes()
old,proof=h.predecessor(root,h.PATH,raw)
assert h.pin(old)==h.PREDECESSOR
assert proof['physical']==h.CURRENT
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
