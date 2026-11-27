"""Custody and original-assertion controls for isolated historical source fixtures."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import hia_native_cold_original_fixture as preparation
from tools import hia_frozen_component_sources as engine
from tools import hia_native_cold_caller_history as cold

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_native_cold_original_source_controls_v1.json'
FIXTURE_PIN = {"bytes":5490,"sha256":"f8b430273c17f0e31a375ff0ddf5bbbdadc7a5961d8f02cc2d1bbade4589a0cb"}
VERSIONS = {
    "tests/test_hia_native_cold_caller_sources.py": {
        "before": {
            "bytes": 4776,
            "sha256": "92946c39c44a40ce0e99ed0ec7d51cb398c161cba608d89e9596c99d0022dc37"
        },
        "after": {
            "bytes": 4961,
            "sha256": "512ee6419eb214bd84cd82cce762390db80a40b67b0cc203d62a20f10454dd18"
        },
        "test_methods": 7
    },
    "tests/test_hia_native_cold_caller_integration.py": {
        "before": {
            "bytes": 4339,
            "sha256": "df7eb6d6ee64b07222397cca858cfd3640b22cd3bd9d9ac7cf8f9e259288b7ab"
        },
        "after": {
            "bytes": 4552,
            "sha256": "e918da340eef996430baad9a176a81fba443f33694bd2473047a4106b2ef5ca2"
        },
        "test_methods": 3
    },
    "tests/test_hia_transport_native_cold_source_admission.py": {
        "before": {
            "bytes": 11085,
            "sha256": "1fdd3bfd56f2d4213096d74362b0888e3194e734b27ba4594abd94b4de269997"
        },
        "after": {
            "bytes": 11329,
            "sha256": "ae5c682e0448c6b688311b6aa9c0f8c9e89ef842f0506e630d0095cf82f19e90"
        },
        "test_methods": 6
    },
    "tests/test_hia_native_cold_caller_physical_history.py": {
        "before": {
            "bytes": 19354,
            "sha256": "65afe0ae91af9f567479ca011b19d78492159bee91e535599186cf10dff388ec"
        },
        "after": {
            "bytes": 19481,
            "sha256": "dd94005be07817479bbe75a53a0b1127078210c13257f29d27e6e2fe34355461"
        },
        "test_methods": 17
    }
}


def methods(raw):
    result = {}
    def visit(node, prefix=''):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + '.')
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name.startswith('test_'):
                    result[prefix + child.name] = child
            else:
                visit(child, prefix)
    visit(ast.parse(raw))
    return result


class NativeColdOriginalFixtureCustodyTests(unittest.TestCase):
    def test_complete_preparation_inverse_preserves_original_test_bodies(self):
        raw = (ROOT / FIXTURE).read_bytes()
        self.assertEqual(preparation.pin(raw), FIXTURE_PIN)
        fixed = json.loads(raw)
        self.assertEqual(set(fixed['files']), set(VERSIONS))
        for name, versions in VERSIONS.items():
            with self.subTest(path=name):
                current = (ROOT / name).read_bytes()
                self.assertEqual(preparation.pin(current), versions['after'])
                old = engine.history_inverse(current, fixed['files'][name], versions['before'])
                previous, present = methods(old), methods(current)
                self.assertEqual(set(previous), set(present))
                self.assertEqual(len(previous), versions['test_methods'])
                for method in previous:
                    before, after = previous[method], present[method]
                    if name.endswith('/test_hia_native_cold_caller_sources.py') and method.endswith('.test_existing_frozen_component_relations_keep_all_original_hashes'):
                        self.assertIsInstance(after.body[0], ast.ImportFrom)
                        self.assertEqual(after.body[0].module, 'tools.hia_frozen_component_sources')
                        self.assertEqual([x.name for x in after.body[0].names], ['FIXTURE'])
                        self.assertIsInstance(after.body[1], ast.ImportFrom)
                        self.assertEqual(after.body[1].module, 'tools.hia_current_store_source_history')
                        self.assertEqual([x.name for x in after.body[1].names], ['reviewed_source'])
                        after.body[:2] = [before.body[0]]
                    self.assertEqual(ast.dump(before, include_attributes=False),
                                     ast.dump(after, include_attributes=False), method)

    def test_all_historical_sources_are_isolated_and_actual_inputs_are_reread(self):
        original = {name: (ROOT / name).read_bytes() for name in preparation.VERSIONS}
        with preparation.original_view(ROOT) as (stage, review):
            self.assertNotEqual(stage, ROOT)
            self.assertTrue(review['original_fixed_131_source_domain_restored'])
            self.assertFalse(review['historical_view_is_current_repository'])
            self.assertFalse(review['native_product_execution_claimed'])
            self.assertFalse(review['terminal_reread_identical'])
            self.assertEqual({name: preparation.pin((stage / name).read_bytes()) for name in cold.PATHS},
                             cold.KNOWN_CURRENT)
            for name, raw in original.items():
                self.assertEqual((ROOT / name).read_bytes(), raw)
                self.assertEqual(review['actual_captured_files'][name], preparation.pin(raw))
                self.assertEqual(preparation.pin((stage / name).read_bytes()),
                                 preparation.VERSIONS[name]['original'])
        self.assertTrue(review['terminal_reread_identical'])
        self.assertFalse(stage.exists())
        for name, raw in original.items():
            self.assertEqual((ROOT / name).read_bytes(), raw)

    def test_changed_fixed_authority_is_refused_before_historical_stage(self):
        real_read = Path.read_bytes
        target = ROOT / preparation.FIXTURE
        def changed(path):
            raw = real_read(path)
            return raw + b'\n' if path == target else raw
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'complete fixed relation changed'):
                with preparation.original_view(ROOT):
                    self.fail('changed authority entered original test view')

    def test_changed_executing_reader_is_refused_before_historical_stage(self):
        real_read = Path.read_bytes
        target = Path(preparation.__file__)
        def changed(path):
            raw = real_read(path)
            return raw + b'\n' if path == target else raw
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'executing reader changed'):
                with preparation.original_view(ROOT):
                    self.fail('changed reader entered original test view')

    def test_late_actual_source_changes_are_refused(self):
        # The injected read reports an actual late input change without editing
        # shared repository files or modifying the authority under test.
        target = ROOT / next(iter(preparation.VERSIONS))
        real_read = Path.read_bytes
        with self.assertRaisesRegex(ValueError, 'physical input changed'):
            with preparation.original_view(ROOT) as (stage, review):
                self.assertTrue(stage.is_dir())
                def changed(path):
                    raw = real_read(path)
                    return raw + b'\n' if path == target else raw
                patcher = patch.object(Path, 'read_bytes', changed)
                patcher.start()
                self.addCleanup(patcher.stop)
        self.assertFalse(review['terminal_reread_identical'])


if __name__ == '__main__':
    unittest.main()
