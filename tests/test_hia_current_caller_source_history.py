"""Exact current caller composition and immutable v2 compatibility controls."""
from hashlib import sha256
import importlib.abc
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import hia_current_caller_source_history as current
from tests import hia_cold_caller_selection_history as qualifiers
from tests import hia_caller_terminal_admission as terminal

ROOT = Path(__file__).resolve().parents[1]


def write(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


class CurrentCallerSourceHistoryTests(unittest.TestCase):
    def test_actual_current_source_is_physical_and_old_full_identity_is_restored(self):
        captures = {}
        def take(path):
            raw = path.read_bytes()
            if path in captures:
                self.assertEqual(captures[path], raw)
            captures[path] = raw
            return raw
        raw = (ROOT / current.RESULT_PATH).read_bytes()
        original, proof = current.result_predecessor(ROOT, current.RESULT_PATH, raw, take=take)
        self.assertEqual(current.pin(raw), current.RESULT_CURRENT)
        self.assertEqual(current.pin(original), current.RESULT_ORIGINAL)
        self.assertEqual(proof['assertion_revision'],
                         {'function_results': {'old': 3, 'new': 6}, 'changed_bytes': 1})
        self.assertFalse(proof['deadline_methods_changed'])
        self.assertFalse(proof['whole_native_delivery_qualified'])
        reviewed = current.reviewed_source(ROOT, current.RESULT_PATH, raw, take=take)
        self.assertEqual(current.pin(reviewed), {
            'bytes': 46518,
            'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'})
        self.assertTrue({ROOT / current.RESULT_PATH, ROOT / current.RESULT_HELPER,
                         ROOT / current.RESULT_FIXTURE}.issubset(captures))

    def test_previous_complete_version_gains_no_new_exception_or_dependency(self):
        raw = (ROOT / current.RESULT_PATH).read_bytes()
        old, _ = current.result_predecessor(ROOT, current.RESULT_PATH, raw)
        same, proof = current.result_predecessor(
            Path('/no-borrowed-root'), current.RESULT_PATH, old,
            take=lambda path: self.fail('earlier source borrowed new authority'))
        self.assertEqual(same, old)
        self.assertIsNone(proof)
        for name, changed in ((current.RESULT_PATH, raw + b' '),
                              ('unrelated.py', raw)):
            same, proof = current.result_predecessor(
                ROOT, name, changed,
                take=lambda path: self.fail('unknown source borrowed new authority'))
            self.assertEqual(same, changed)
            self.assertIsNone(proof)

    def test_composed_review_rechecks_new_dependencies_after_old_authority(self):
        raw = (ROOT / current.RESULT_PATH).read_bytes()
        for target in (current.RESULT_PATH, current.RESULT_HELPER, current.RESULT_FIXTURE):
            seen_old = []
            def take(path):
                if path.name == 'hia_frozen_component_source_relations.json':
                    seen_old.append(True)
                data = path.read_bytes()
                if seen_old and path == ROOT / target:
                    return data + b' changed after old authority'
                return data
            with self.subTest(path=target), self.assertRaises(ValueError):
                current.reviewed_source(ROOT, current.RESULT_PATH, raw, take=take)
            self.assertTrue(seen_old)

    def test_actual_terminal_capture_uses_explicit_root_and_retains_physical_bytes(self):
        paths = (current.RESULT_PATH, current.RESULT_HELPER, current.RESULT_FIXTURE,
                 'tools/hia_current_caller_source_history.py',
                 'tests/fixtures/hia_installed_distribution_sources.json',
                 'tests/fixtures/hia_component_authoring_successor_v1.json')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in paths:
                write(root, name, (ROOT / name).read_bytes())
            admitted = terminal._CapturedAdmission.__new__(terminal._CapturedAdmission)
            admitted._root, admitted._captured, admitted._physical = root, {}, {}
            admitted._result_source_history = {}
            result = admitted._capture(current.RESULT_PATH)
            self.assertEqual(current.pin(result), current.RESULT_ORIGINAL)
            self.assertEqual(current.pin(admitted._physical[current.RESULT_PATH]),
                             current.RESULT_CURRENT)
            self.assertEqual(set(admitted._physical), set(paths))
            self.assertIn(current.RESULT_PATH, admitted._result_source_history)
            (root / current.RESULT_PATH).write_bytes(result)
            with self.assertRaises(ValueError):
                admitted._capture_path(root / current.RESULT_PATH)

    def test_actual_terminal_capture_refuses_missing_or_changed_local_history(self):
        paths = (current.RESULT_PATH, current.RESULT_HELPER, current.RESULT_FIXTURE,
                 'tools/hia_current_caller_source_history.py',
                 'tests/fixtures/hia_installed_distribution_sources.json',
                 'tests/fixtures/hia_component_authoring_successor_v1.json')
        for target in paths[1:]:
            for missing in (True, False):
                with self.subTest(path=target, missing=missing), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for name in paths:
                        write(root, name, (ROOT / name).read_bytes())
                    if missing:
                        (root / target).unlink()
                    else:
                        (root / target).write_bytes((root / target).read_bytes() + b' ')
                    admitted = terminal._CapturedAdmission.__new__(terminal._CapturedAdmission)
                    admitted._root, admitted._captured, admitted._physical = root, {}, {}
                    admitted._result_source_history = {}
                    with self.assertRaises((ValueError, OSError)):
                        admitted._capture(current.RESULT_PATH)

    def test_legacy_v2_qualifiers_keep_their_fixed_whole_source_authority(self):
        fixture = json.loads((ROOT / qualifiers.LEGACY_INTEGRATED_FIXTURE).read_bytes())
        for name, record in fixture['files'].items():
            current_raw = (ROOT / name).read_bytes()
            selected, _, _ = qualifiers._integrated_predecessor(
                name, current_raw, ROOT, Path.read_bytes)
            self.assertEqual(qualifiers.pin(selected), record['old'])
            pieces, end = [], 0
            for hunk in record['hunks']:
                at = hunk['old_offset']
                old, new = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
                self.assertEqual(selected[at:at + len(old)], old)
                pieces.extend((selected[end:at], new))
                end = at + len(old)
            legacy = b''.join((*pieces, selected[end:]))
            self.assertEqual(qualifiers.pin(legacy), record['new'])
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for dependency in (qualifiers.FIXTURE, qualifiers.LEGACY_INTEGRATED_FIXTURE,
                                   qualifiers.INVERSE_HELPER):
                    write(root, dependency, (ROOT / dependency).read_bytes())
                write(root, name, legacy)
                original, proof = qualifiers.reviewed(name, legacy, root=root)
                self.assertEqual(qualifiers.pin(original), qualifiers.EXPECTED[name]['old'])
                self.assertEqual(proof['integrated_source_admission']['schema'],
                                 'hepta.hia.integrated-caller-source-admission-review.v2')
                prior = {'path': name, 'current_bytes': len(original),
                         'current_sha256': sha256(original).hexdigest()}
                rebound = qualifiers.bind_adjustment(prior, legacy, proof)
                self.assertEqual(rebound['current_sha256'], record['new']['sha256'])
                (root / qualifiers.LEGACY_INTEGRATED_FIXTURE).write_bytes(b'{}')
                with self.assertRaises(ValueError):
                    qualifiers.reviewed(name, legacy, root=root)

    def test_data_only_current_reader_imports_no_product_builder_generator_or_test(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname=='tests' or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_current_caller_source_history as h
root=Path(sys.argv[1])
raw=(root/h.RESULT_PATH).read_bytes()
assert h.reviewed_source(root,h.RESULT_PATH,raw)!=raw
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
