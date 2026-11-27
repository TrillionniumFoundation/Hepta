"""Physical source-root and terminal-capture controls for historical readers."""
from hashlib import sha256
import importlib.abc
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_component_authoring_history as component
from tests import hia_installed_distribution_history as installed
from tests import hia_native_transport_worker_successor as delivery

ROOT = Path(__file__).resolve().parents[1]
BUILDER = 'tools/build_hia_full_cost.py'
CALLER = 'tests/hia_service_bootstrap_installed.py'


class HistoryFixtureCustodyTests(unittest.TestCase):
    def fixtures(self, root):
        for name in (component.FIXTURE, installed.FIXTURE):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())

    def caller(self, root):
        target = root / CALLER
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / CALLER).read_bytes())

    def inventory(self):
        row = json.loads((ROOT / installed.FIXTURE).read_bytes())['files'][CALLER]
        return {'unchanged_files': {CALLER: row['original']}}

    def admit(self, root):
        return delivery.delivery_sources(root, self.inventory(), {'source_adjustments': {}})

    def test_real_complete_builder_and_installed_predecessors_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            current = (ROOT / BUILDER).read_bytes()
            expected = json.loads((ROOT / component.FIXTURE).read_bytes())['files'][BUILDER]
            restored = component.predecessor(BUILDER, current, root=root)
            self.assertEqual(len(restored), expected['old_bytes'])
            self.assertEqual(sha256(restored).hexdigest(), expected['old_sha256'])
            self.assertEqual(restored, component.predecessor(BUILDER, current))
            current = (ROOT / CALLER).read_bytes()
            expected = self.inventory()['unchanged_files'][CALLER]
            restored = installed.predecessor(CALLER, current, root=root)
            self.assertEqual({'bytes': len(restored), 'sha256': sha256(restored).hexdigest()}, expected)
            self.assertEqual(restored, installed.predecessor(CALLER, current))
            self.caller(root)
            admitted = self.admit(root)['source_adjustments'][CALLER]
            self.assertEqual(admitted['original_sha256'], expected['sha256'])
            self.assertEqual(admitted['current_sha256'], sha256(current).hexdigest())

    def test_actual_delivery_entry_refuses_missing_reader_fixtures(self):
        for missing in ('both', component.FIXTURE, installed.FIXTURE):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.caller(root)
                if missing != 'both':
                    self.fixtures(root)
                    (root / missing).unlink()
                with self.assertRaises((FileNotFoundError, ValueError)):
                    self.admit(root)

    def test_actual_delivery_entry_refuses_corrupted_reader_fixtures(self):
        for name in (component.FIXTURE, installed.FIXTURE):
            with self.subTest(fixture=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixtures(root)
                self.caller(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaises(ValueError):
                    self.admit(root)

    def test_both_nested_helpers_use_only_the_explicit_root_and_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            captured = []
            def take(path):
                self.assertIn(path, (root / component.FIXTURE, root / installed.FIXTURE))
                captured.append(path)
                return path.read_bytes()
            with patch.object(component, 'ROOT', root / 'absent-author-tree'), \
                 patch.object(installed, 'ROOT', root / 'another-absent-author-tree'):
                restored = installed.predecessor(CALLER, (ROOT / CALLER).read_bytes(),
                                                  root=root, take=take)
                self.assertEqual(sha256(restored).hexdigest(),
                                 self.inventory()['unchanged_files'][CALLER]['sha256'])
            self.assertEqual(set(captured), {root / component.FIXTURE, root / installed.FIXTURE})
            self.assertGreaterEqual(captured.count(root / component.FIXTURE), 3)
            self.assertGreaterEqual(captured.count(root / installed.FIXTURE), 3)

    def test_component_fixture_physical_change_after_capture_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            changed = []
            def take(path):
                raw = path.read_bytes()
                if not changed:
                    changed.append(path)
                    path.write_bytes(raw + b' ')
                return raw
            with self.assertRaises(ValueError):
                component.predecessor(BUILDER, (ROOT / BUILDER).read_bytes(), root=root, take=take)
            self.assertEqual(changed, [root / component.FIXTURE])

    def test_installed_fixture_physical_change_after_capture_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            changed = []
            def take(path):
                raw = path.read_bytes()
                if not changed:
                    changed.append(path)
                    path.write_bytes(raw + b' ')
                return raw
            with self.assertRaises(ValueError):
                installed._records(root=root, take=take)
            self.assertEqual(changed, [root / installed.FIXTURE])

    def test_nested_component_fixture_remains_bound_after_child_returns(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            changed = []
            def take(path):
                raw = path.read_bytes()
                if path == root / installed.FIXTURE and not changed:
                    target = root / component.FIXTURE
                    target.write_bytes(target.read_bytes() + b' ')
                    changed.append(target)
                return raw
            with self.assertRaises(ValueError):
                installed.predecessor(CALLER, (ROOT / CALLER).read_bytes(), root=root, take=take)
            self.assertEqual(changed, [root / component.FIXTURE])

    def test_delivery_rechecks_fixture_after_nested_predecessor_returns(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            self.caller(root)
            original = installed.predecessor
            changed = []
            def mutate_after(*args, **kwargs):
                result = original(*args, **kwargs)
                target = root / installed.FIXTURE
                target.write_bytes(target.read_bytes() + b' ')
                changed.append(target)
                return result
            with patch.object(installed, 'predecessor', side_effect=mutate_after):
                with self.assertRaises(ValueError):
                    self.admit(root)
            self.assertEqual(changed, [root / installed.FIXTURE])

    def test_cached_author_parse_never_substitutes_for_reader_bytes(self):
        installed._records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                installed._records(root=root)
            self.fixtures(root)
            path = root / installed.FIXTURE
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                installed._records(root=root)

    def test_unreviewed_source_bytes_never_gain_a_predecessor_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixtures(root)
            raw = (ROOT / BUILDER).read_bytes() + b'# unreviewed\n'
            self.assertEqual(component.predecessor(BUILDER, raw, root=root), raw)
            raw = (ROOT / CALLER).read_bytes() + b'# unreviewed\n'
            self.assertEqual(installed.predecessor(CALLER, raw, root=root), raw)

    def test_fresh_reader_imports_no_product_author_or_oracle(self):
        script = """import importlib.abc,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname.startswith(('hepta.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tests import hia_component_authoring_history as component
from tests import hia_installed_distribution_history as installed
from tests import hia_native_transport_worker_successor as delivery
root=Path(sys.argv[1])
assert component.predecessor('unrelated.py',b'unchanged',root=root)==b'unchanged'
assert installed.predecessor('unrelated.py',b'unchanged',root=root)==b'unchanged'
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
