"""Complete scoped source controls; native caller execution remains separate."""
from hashlib import sha256
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import hia_scoped_caller_source_history as history

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ('discovery', 'ordinary', 112), ('discovery', 'journal', 21),
    ('discovery', 'context', 15), ('verification', 'ordinary', 112),
    ('verification', 'journal', 21), ('bootstrap', 'ordinary', 112),
    ('bootstrap', 'journal', 21), ('bootstrap', 'context', 15),
)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def module(domain):
    return importlib.import_module('tools.qualify_hia_service_' + domain + '_callers')


def stage(root, data):
    for name, raw in data.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


class ScopedCallerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_scoped_evaluation_cold_preparation import install_view
        install_view(cls, globals(), domain="scoped")
        cls.states = {}
        for domain, scope, count in CASES:
            caller = module(domain)
            value, proof = caller.admit_original_scope(ROOT, scope)
            physical = {name: (ROOT / name).read_bytes() for name in proof['captured_files']}
            cls.states[(domain, scope)] = (caller, value, proof, physical)

    def test_all_eight_current_scopes_keep_original_complete_order_and_physical_captures(self):
        for domain, scope, count in CASES:
            with self.subTest(domain=domain, scope=scope):
                caller, value, proof, physical = self.states[(domain, scope)]
                original = json.loads((ROOT / caller.FIXTURE).read_bytes())['scopes'][scope]
                self.assertEqual(value, original)
                self.assertEqual(len(value['ordered_ids']), count)
                self.assertEqual(len(set(value['ordered_ids'])), count)
                self.assertEqual(value['outer_seconds'], 1800)
                self.assertEqual(proof['original_ordered_ids'], value['ordered_ids'])
                self.assertEqual(proof['original_files'], value['files'])
                self.assertEqual(proof['captured_files'],
                                 {name: pin(raw) for name, raw in physical.items()})
                self.assertFalse(proof['whole_native'])
                self.assertTrue(proof['terminal_reread_identical'])
                for name, review in proof.get('reviewed_scope_predecessors', {}).items():
                    self.assertEqual(review['physical'], pin(physical[name]))
                    self.assertFalse(review['physical_capture_rewritten'])
                    self.assertFalse(review['prior_projection_is_physical_source'])
                if scope == 'ordinary':
                    review = proof['reviewed_scope_predecessors'][history.TOOLS]
                    self.assertEqual(review['native_result_source_history']['assertion_revision'],
                                     {'function_results': {'old': 3, 'new': 6}, 'changed_bytes': 1})
                    self.assertFalse(review['native_result_source_history']['deadline_methods_changed'])
                elif scope == 'journal':
                    review = proof['reviewed_journal_installed_preparation_source_adjustments'][history.JOURNAL]
                    self.assertEqual(review['original_method_ids'], value['ordered_ids'])
                    self.assertEqual(review['original_method_count'], 21)
                    self.assertEqual(review['current'], history.REVIEWED[history.JOURNAL])

    def test_all_original_whole_sources_keep_their_prior_authorities_and_capture_sets(self):
        from tests import hia_caller_diagnostics_admission as diagnostic
        for domain, scope, count in CASES:
            caller, value, _, physical = self.states[(domain, scope)]
            old = {caller.FIXTURE: physical[caller.FIXTURE]}
            for name, expected in value['files'].items():
                raw = physical[name]
                if name == history.JOURNAL:
                    raw = (ROOT / 'tests/fixtures/journal_installed_preparation_v1.py.txt').read_bytes()
                elif pin(raw) != expected:
                    raw, _ = history.predecessor(ROOT, name, raw, expected)
                    if name == history.TOOLS:
                        raw = diagnostic.restore(raw, (ROOT / diagnostic.FIXTURE).read_bytes())
                self.assertEqual(pin(raw), expected)
                old[name] = raw
            with self.subTest(domain=domain, scope=scope), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root, old)
                admitted, proof = caller.admit_original_scope(root, scope)
                self.assertEqual(admitted, value)
                self.assertEqual(set(proof['captured_files']), set(old))
                self.assertFalse(proof.get('reviewed_scope_predecessors', {}))
                self.assertFalse(proof['reviewed_diagnostic_source_adjustments'])

    def test_each_actual_capture_refuses_missing_and_tampered_independent_root_bytes(self):
        for domain, scope, _ in CASES:
            caller, _, _, physical = self.states[(domain, scope)]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root, physical)
                for name, raw in physical.items():
                    for missing in (True, False):
                        with self.subTest(domain=domain, scope=scope, path=name, missing=missing):
                            if missing:
                                (root / name).unlink()
                            else:
                                (root / name).write_bytes(raw + b' ')
                            try:
                                with self.assertRaises((ValueError, OSError)):
                                    caller.admit_original_scope(root, scope)
                            finally:
                                (root / name).write_bytes(raw)

    def test_every_consumed_physical_source_is_rechecked_at_terminal(self):
        original_read = Path.read_bytes
        for domain, scope, _ in CASES:
            caller, _, _, physical = self.states[(domain, scope)]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root, physical)
                for name in physical:
                    target = root / name
                    reads = [0]
                    def changed(path):
                        raw = original_read(path)
                        if path == target:
                            reads[0] += 1
                            if reads[0] > 1:
                                return raw + b' '
                        return raw
                    with self.subTest(domain=domain, scope=scope, path=name):
                        with patch.object(Path, 'read_bytes', changed):
                            with self.assertRaises((ValueError, OSError)):
                                caller.admit_original_scope(root, scope)
                        self.assertGreaterEqual(reads[0], 2)

    def test_source_capture_binding_rejects_missing_changed_and_stale_admissions(self):
        for domain, scope, _ in CASES:
            caller, _, proof, physical = self.states[(domain, scope)]
            expected = {name: identity['sha256'] for name, identity in proof['captured_files'].items()}
            caller.bind_scope_admission_to_source_capture(proof, expected)
            for name in expected:
                for missing in (True, False):
                    broken = dict(expected)
                    if missing:
                        del broken[name]
                    else:
                        broken[name] = '0' * 64
                    with self.subTest(domain=domain, scope=scope, path=name, missing=missing):
                        with self.assertRaises(ValueError):
                            caller.bind_scope_admission_to_source_capture(proof, broken)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root, physical)
                caller.admit_original_scope(root, scope)
                name = next(iter(proof['original_files']))
                (root / name).write_bytes(physical[name] + b' ')
                with self.assertRaises(ValueError):
                    caller.admit_original_scope(root, scope)

    def test_mutated_order_budget_or_source_inventory_cannot_authorize_new_bytes(self):
        for domain, scope, _ in CASES:
            caller, _, _, physical = self.states[(domain, scope)]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage(root, physical)
                for kind in ('order', 'budget', 'source', 'count'):
                    value = json.loads(physical[caller.FIXTURE])
                    selected = value['scopes'][scope]
                    if kind == 'order':
                        selected['ordered_ids'].reverse()
                    elif kind == 'budget':
                        selected['outer_seconds'] += 1
                    elif kind == 'source':
                        name = next(iter(selected['files']))
                        selected['files'][name] = pin(physical[name])
                    else:
                        selected['ordered_ids'].pop()
                    (root / caller.FIXTURE).write_text(json.dumps(value))
                    with self.subTest(domain=domain, scope=scope, mutation=kind):
                        with self.assertRaises(ValueError):
                            caller.admit_original_scope(root, scope)
                    (root / caller.FIXTURE).write_bytes(physical[caller.FIXTURE])

    def test_real_unfiltered_current_loader_keeps_all_eight_original_method_sequences(self):
        from tools.run_hia_unittest_gate import load_declared_suite
        for domain, scope, count in CASES:
            _, value, _, _ = self.states[(domain, scope)]
            with self.subTest(domain=domain, scope=scope):
                _, actual = load_declared_suite(value['modules'])
                self.assertEqual(list(actual), value['ordered_ids'])
                self.assertEqual(len(actual), count)

    def test_fresh_source_inverse_imports_no_product_test_builder_or_oracle(self):
        script = """import importlib.abc,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='hepta' or fullname=='tests' or fullname.startswith(('hepta.','tests.','tools.build_','tools.generate_')) or 'oracle' in fullname:
            raise AssertionError(fullname)
sys.meta_path.insert(0,Guard())
from tools import hia_scoped_caller_source_history as h
root=Path(sys.argv[1])
for name,expected in h.ORIGINAL.items():
    raw=(root/name).read_bytes()
    old,proof=h.predecessor(root,name,raw,expected)
    assert h.pin(old)==h.REVIEWED[name]
    assert proof['physical']==h.pin(raw)
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
