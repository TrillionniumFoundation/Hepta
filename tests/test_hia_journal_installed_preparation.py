"""Source-only controls for the versioned Journal wheel preparation.

No wheel, product, HIA compiler/VM, native image or old test module is executed.
The original complete 21-method Journal qualification remains a separate gate.
"""
from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_journal_installed_preparation as subject
from tests.hia_store_delivery_successor import reverse_exact

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ('setup.py', 'hepta/hia_agent_contract.py', 'hepta/hia_executable_capture.py')
CONTRACT_POLICY = 'hepta/hia_agent_contract.py'
POLICY_SUCCESSOR = 'tests/fixtures/journal_package_policy_successor.json'
POLICY_SUCCESSOR_SHA256 = '194f45b213421d3592256cf5d9b752fe425ce9ba8add4bf3c43836c09e6f6c36'
PROOF_WIRE_POLICY_SHA256 = '771e093a1bbfccc01010d566e1dff98e97c680a4d89eb509ffbb36791afb683a'
PROOF_WIRE_POLICY_PREDECESSOR_SHA256 = '08c9b79f4ea7e186d92b5e4e905046a5c1d34df9748ebc83c11bdd412d1f9b9b'
PROOF_WIRE_RESOURCE = b"    'examples/hia_bootstrap/core_proof_wire.hepta',\n"
STORE_TRANSPORT_RESOURCE = (
    b"    'examples/hia_bootstrap/agent_read_page.hepta',\n",
    b"    'examples/hia_bootstrap/agent_store_transport.hepta',\n",
    b"    'examples/hia_bootstrap/agent_inspection.hepta',\n",
)
INPUTS = (*subject.SOURCE_PATHS, *POLICIES, POLICY_SUCCESSOR, 'tests/test_hia_journal_installed_preparation.py')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def store(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


class JournalInstalledPreparationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: (ROOT / name).read_bytes() for name in INPUTS}
        cls.authority = json.loads(cls.sources[subject.FIXTURE])
        reviewed = cls.sources[POLICY_SUCCESSOR]
        if sha256(reviewed).hexdigest() != POLICY_SUCCESSOR_SHA256:
            raise AssertionError('Journal package policy successor evidence differs')
        raw = cls.sources[CONTRACT_POLICY]
        expected = cls.authority['policy_sources'][CONTRACT_POLICY]
        if sha256(raw).hexdigest() == PROOF_WIRE_POLICY_SHA256:
            predecessor = raw.replace(PROOF_WIRE_RESOURCE, b'', 1)
            if sha256(predecessor).hexdigest() != PROOF_WIRE_POLICY_PREDECESSOR_SHA256:
                raise AssertionError('exact Core proof wire package composition differs')
            raw = predecessor
        # The preparation controls test the frozen 196-resource package. The
        # current installed release is independently qualified at its normal
        # packaging entry point and must not become this test's historical pin.
        if pin(raw) == expected:
            cls.policy = raw
        else:
            record = json.loads(reviewed)
            if sha256(raw).hexdigest() != record['new_sha256']:
                before, addition, after = STORE_TRANSPORT_RESOURCE
                group = before + addition + after
                if raw.count(group) != 1:
                    raise AssertionError('exact native Store transport package composition differs')
                raw = raw.replace(group, before + after, 1)
            cls.policy = reverse_exact(raw, record, expected)
        cls.agent = tuple(cls.authority['original_agent_resources'])
        cls.extra = tuple(cls.authority['current_executable_capture_resources']
                          + cls.authority['current_integer_resources'])

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {name: (ROOT / name).read_bytes() for name in INPUTS}:
            raise AssertionError('Journal preparation Source inputs changed during controls')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hia-journal-preparation-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        for name in self.agent + self.extra + ('pyproject.toml', 'MANIFEST.in'):
            store(self.root, name, ('SOURCE-ONLY-RESOURCE:' + name + '\n').encode())
        for name, raw in self.sources.items():
            store(self.root, name, raw)
        store(self.root, CONTRACT_POLICY, self.policy)

    def admit(self):
        return subject.admit_source(self.root, subject.PATH,
                                    self.sources[subject.PATH], subject.ORIGINAL)

    def stage(self, names):
        target = Path(self.temp.name) / 'staged'
        target.mkdir()
        for name in names + ('setup.py', 'pyproject.toml', 'MANIFEST.in',
                             'hepta/hia_agent_contract.py', 'hepta/hia_executable_capture.py'):
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root / name, path)
        return target

    def test_01_complete_original_two_splices_all_21_ids_and_budgets_are_preserved(self):
        original, current = self.sources[subject.ARCHIVE], self.sources[subject.PATH]
        self.assertEqual(pin(original), subject.ORIGINAL)
        self.assertEqual(pin(current), subject.CURRENT)
        self.assertEqual(subject.restore_source(current, self.authority), original)
        old_tree, new_tree = ast.parse(original), ast.parse(current)
        ids = lambda tree: sorted('tests.test_hia_agent_journal_native.' + cls.name + '.' + node.name
            for cls in tree.body if isinstance(cls, ast.ClassDef)
            and cls.name in ('JournalNativeTests', 'JournalSourceTests')
            for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        self.assertEqual(ids(old_tree), self.authority['original_method_ids'])
        self.assertEqual(ids(new_tree), ids(old_tree))
        self.assertEqual(len(ids(new_tree)), 21)
        # Remove precisely the three added preparation statements from the one
        # method AST; all original syntax, including 120/120/30 timeouts, remains.
        target = 'test_installed_wheel_ordinary_call_no_tools_and_source_catalog_binding'
        cls, = (node for node in new_tree.body if isinstance(node, ast.ClassDef)
                 and node.name == 'JournalNativeTests')
        method, = (node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == target)
        import_index, = (i for i, node in enumerate(method.body) if isinstance(node, ast.ImportFrom)
                         and node.module == 'tests.hia_journal_installed_preparation')
        del method.body[import_index:import_index + 2]
        verify_index, = (i for i, node in enumerate(method.body) if isinstance(node, ast.Expr)
                         and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                         and node.value.func.id == 'verify_staged_resources')
        del method.body[verify_index]
        self.assertEqual(ast.dump(new_tree, include_attributes=False), ast.dump(old_tree, include_attributes=False))
        controls = []
        for field in ('path', 'original', 'current'):
            value = deepcopy(self.authority)
            value[field] = 'wrong'
            controls.append(value)
        for variant in ('missing', 'tuple', 'reverse-order', 'extra-key', 'bool-offset',
                        'shift', 'overlap', 'uppercase-hex', 'old-byte', 'new-byte', 'wrong-id'):
            value = deepcopy(self.authority)
            if variant == 'missing': value['splices'].pop()
            elif variant == 'tuple': value['splices'] = tuple(value['splices'])
            elif variant == 'reverse-order': value['splices'].reverse()
            elif variant == 'extra-key': value['splices'][0]['unreviewed'] = True
            elif variant == 'bool-offset': value['splices'][0]['old_offset'] = True
            elif variant == 'shift': value['splices'][0]['new_offset'] += 1
            elif variant == 'overlap': value['splices'][1]['old_offset'] = 0
            elif variant == 'uppercase-hex': value['splices'][0]['new_hex'] = value['splices'][0]['new_hex'].upper()
            elif variant == 'old-byte': value['splices'][0]['old_hex'] = '00' + value['splices'][0]['old_hex'][2:]
            elif variant == 'new-byte': value['splices'][0]['new_hex'] = '00' + value['splices'][0]['new_hex'][2:]
            else: value['splices'][0]['id'] = 'unreviewed'
            controls.append(value)
        self.assertEqual(len(controls), 14)
        for index, value in enumerate(controls):
            with self.subTest(control=index), self.assertRaises(ValueError):
                subject.restore_source(current, value)
        for raw in (bytearray(current), current + b'\n', original):
            with self.subTest(raw_type=type(raw).__name__, size=len(raw)), self.assertRaises(ValueError):
                subject.restore_source(raw, self.authority)

    def test_02_exact_source_admission_missing_drift_no_cache_and_terminal_custody(self):
        proof = self.admit()
        self.assertEqual(set(proof['captured_files']), set(subject.SOURCE_PATHS))
        self.assertEqual(proof['original_method_ids'], self.authority['original_method_ids'])
        self.assertEqual(proof['production_source_exceptions'], [])
        self.assertTrue(proof['terminal_reread_identical'])
        for action in ('missing', 'tamper', 'no-cache', 'terminal-drift'):
            for name in subject.SOURCE_PATHS:
                with self.subTest(action=action, path=name):
                    path = self.root / name
                    raw = path.read_bytes()
                    if action == 'no-cache': self.admit()
                    if action == 'missing':
                        path.unlink()
                        try:
                            with self.assertRaises(FileNotFoundError): self.admit()
                        finally: path.write_bytes(raw)
                    elif action == 'terminal-drift':
                        real_read, count = Path.read_bytes, []
                        def changed(selected):
                            value = real_read(selected)
                            if selected == path:
                                count.append(True)
                                if len(count) > 1: return value + b'\n'
                            return value
                        with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                            self.admit()
                        self.assertGreaterEqual(len(count), 2)
                    else:
                        path.write_bytes(raw + b'\n')
                        try:
                            with self.assertRaises(ValueError): self.admit()
                        finally: path.write_bytes(raw)
        for name, raw, old in ((subject.PATH + '.other', self.sources[subject.PATH], subject.ORIGINAL),
                              (subject.PATH, self.sources[subject.ARCHIVE], subject.ORIGINAL),
                              (subject.PATH, self.sources[subject.PATH], subject.CURRENT)):
            with self.subTest(path=name, original=old), self.assertRaises(ValueError):
                subject.admit_source(self.root, name, raw, old)

    def test_03_exact_current_required_resources_no_product_import_and_missing_inputs(self):
        real_import = builtins.__import__
        def no_product(name, *args, **kwargs):
            if name == 'hepta' or name.startswith(('hepta.', 'tools.')) or name == 'tests.test_hia_agent_journal_native':
                raise AssertionError('resource preparation executed a product or old test import: ' + name)
            return real_import(name, *args, **kwargs)
        with patch.object(builtins, '__import__', no_product):
            resources, proof = subject.prepare_resources(self.root, self.agent)
        self.assertEqual(resources, self.agent + self.extra)
        self.assertEqual((len(self.agent), len(self.extra), len(resources)), (176, 20, 196))
        self.assertEqual(len(proof['copied_paths']), 199)
        self.assertEqual(proof['original_build_timeout_seconds'], 120)
        self.assertEqual(proof['original_install_timeout_seconds'], 120)
        self.assertEqual(proof['original_probe_timeout_seconds'], 30)
        self.assertEqual(proof['original_scope_budget_seconds'], 1800)
        self.assertFalse(proof['whole_native'])
        for names in (list(self.agent), self.agent[:-1], self.agent + (self.agent[0],), tuple(reversed(self.agent))):
            with self.subTest(inventory_type=type(names).__name__, size=len(names)), self.assertRaises(ValueError):
                subject.prepare_resources(self.root, names)
        for name in POLICIES:
            path, raw = self.root / name, (self.root / name).read_bytes()
            path.write_bytes(raw + b'\n')
            try:
                with self.subTest(policy=name), self.assertRaises(ValueError):
                    subject.prepare_resources(self.root, self.agent)
            finally: path.write_bytes(raw)
        for name in self.extra:
            path, raw = self.root / name, (self.root / name).read_bytes()
            path.unlink()
            try:
                with self.subTest(required_extra=name), self.assertRaises(FileNotFoundError):
                    subject.prepare_resources(self.root, self.agent)
            finally: path.write_bytes(raw)

    def test_04_staged_all_required_bytes_source_drift_and_typed_preparation_are_checked(self):
        resources, preparation = subject.prepare_resources(self.root, self.agent)
        staged = self.stage(resources)
        receipt = Path(self.temp.name) / 'preparation.json'
        report = subject.verify_staged_resources(self.root, staged, preparation, receipt)
        self.assertEqual(json.loads(receipt.read_bytes()), report)
        self.assertEqual(len(report['staged_files']), 201)
        self.assertTrue(report['staged_required_bytes_identical'])
        self.assertTrue(report['source_terminal_reread_identical'])
        self.assertEqual(report['qualification'],
                         'PREPARATION_ONLY_ORIGINAL_WHEEL_AND_INSTALLED_ASSERTIONS_STILL_REQUIRED')
        for name in self.extra + ('setup.py', 'hepta/hia_agent_contract.py', 'hepta/hia_executable_capture.py'):
            path, raw = staged / name, (staged / name).read_bytes()
            for action in ('missing', 'tamper'):
                with self.subTest(path=name, action=action):
                    if action == 'missing': path.unlink()
                    else: path.write_bytes(raw + b'\n')
                    try:
                        with self.assertRaises((FileNotFoundError, ValueError)):
                            subject.verify_staged_resources(self.root, staged, preparation, receipt)
                    finally: path.write_bytes(raw)
        for name in (self.extra[0], subject.ARCHIVE, subject.FIXTURE, subject.HELPER, subject.PATH):
            path, raw = self.root / name, (self.root / name).read_bytes()
            path.write_bytes(raw + b'\n')
            try:
                with self.subTest(source=name), self.assertRaises(ValueError):
                    subject.verify_staged_resources(self.root, staged, preparation, receipt)
            finally: path.write_bytes(raw)
        for field, value in (('original_resource_count', True), ('additional_resource_count', 0),
                ('original_build_timeout_seconds', 121), ('original_install_timeout_seconds', 121),
                ('original_probe_timeout_seconds', 31), ('original_scope_budget_seconds', 1801),
                ('setup_required_resources_unchanged', False), ('whole_native', True),
                ('copied_paths', preparation['copied_paths'][:-1]),
                ('source_admission', {}), ('captured_files', {}), ('unreviewed', True)):
            changed = deepcopy(preparation)
            changed[field] = value
            with self.subTest(proof_field=field), self.assertRaises(ValueError):
                subject.verify_staged_resources(self.root, staged, changed, receipt)
        # The final source reread follows the actual staged-byte consumption.
        real_read, seen = Path.read_bytes, []
        target = self.root / self.extra[0]
        def after_staging(path):
            raw = real_read(path)
            if path == staged / self.extra[0]: seen.append(True)
            if path == target and seen: return raw + b'\n'
            return raw
        with patch.object(Path, 'read_bytes', after_staging), self.assertRaises(ValueError):
            subject.verify_staged_resources(self.root, staged, preparation, receipt)
        self.assertTrue(seen)


if __name__ == '__main__':
    unittest.main()
