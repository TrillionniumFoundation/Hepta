"""Exercise the actual setup.py literal resource reader, not a replacement."""
from __future__ import annotations
import ast
import os
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from development_literal_registry import extend_development_tuple

BASE = Path(os.environ['HIA_EMISSION_BASE']).resolve(strict=True)
NATIVE = 'examples/hia_bootstrap/service_emission.hiaasm'
ROLES = ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES',
         'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES')


def wheel_resources(root):
    original = ast.parse((BASE / 'setup.py').read_bytes())
    function, = [node for node in original.body if isinstance(node, ast.FunctionDef)
                 and node.name == 'agent_resources']
    namespace = {'Path': Path, 'ast': ast, 'ROOT': root}
    exec(compile(ast.Module(body=[deepcopy(function)], type_ignores=[]),
                 str(BASE / 'setup.py'), 'exec'), namespace)
    return namespace['agent_resources']()


class DevelopmentLiteralRegistryTests(unittest.TestCase):
    def prepare(self):
        temporary = tempfile.TemporaryDirectory(prefix='emission-literal-registry-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'hepta').mkdir()
        target = root / 'hepta/hia_agent_contract.py'
        target.write_bytes((BASE / 'hepta/hia_agent_contract.py').read_bytes())
        return root, target

    def test_original_augassign_is_not_a_resource_of_actual_wheel_reader(self):
        root, target = self.prepare()
        before = wheel_resources(root)
        target.write_bytes(target.read_bytes() + b'\nNATIVE_SOURCE_FILES += (' + repr(NATIVE).encode() + b',)\n')
        self.assertEqual(wheel_resources(root), before)
        self.assertNotIn(NATIVE, before)
        previous = target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'one original literal'):
            extend_development_tuple(root, 'hepta/hia_agent_contract.py', 'NATIVE_SOURCE_FILES', (NATIVE,))
        self.assertEqual(target.read_bytes(), previous)

    def test_literal_union_is_seen_by_actual_setup_and_preserves_five_roles(self):
        root, target = self.prepare()
        before = wheel_resources(root)
        before_tree = ast.parse(target.read_bytes())
        original = {name: ast.literal_eval(next(node.value for node in before_tree.body
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)))
                    for name in ROLES}
        result = extend_development_tuple(root, 'hepta/hia_agent_contract.py', 'NATIVE_SOURCE_FILES', (NATIVE,))
        after = wheel_resources(root)
        self.assertEqual(set(after), set(before) | {NATIVE})
        after_tree = ast.parse(target.read_bytes())
        for name in ROLES:
            value = ast.literal_eval(next(node.value for node in after_tree.body
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)))
            self.assertEqual(value, original[name] + ((NATIVE,) if name == 'NATIVE_SOURCE_FILES' else ()))
        self.assertEqual(result['added'], [NATIVE])
        self.assertEqual(result['scope'], 'DEVELOPMENT_ONLY')
        previous = target.read_bytes()
        again = extend_development_tuple(root, 'hepta/hia_agent_contract.py', 'NATIVE_SOURCE_FILES', (NATIVE,))
        self.assertEqual(again['added'], [])
        self.assertEqual(target.read_bytes(), previous)

    def test_bad_registry_or_names_refuse_without_writing(self):
        root, target = self.prepare()
        original = target.read_bytes()
        for addition in ([NATIVE], (NATIVE, NATIVE), ('',), (True,)):
            with self.subTest(addition=addition):
                with self.assertRaises(ValueError):
                    extend_development_tuple(root, 'hepta/hia_agent_contract.py', 'NATIVE_SOURCE_FILES', addition)
                self.assertEqual(target.read_bytes(), original)
        for suffix in (b'\nNATIVE_SOURCE_FILES=()\n', b'\nNATIVE_SOURCE_FILES+=()\n'):
            target.write_bytes(original + suffix)
            with self.assertRaises(ValueError):
                extend_development_tuple(root, 'hepta/hia_agent_contract.py', 'NATIVE_SOURCE_FILES', (NATIVE,))
            self.assertEqual(target.read_bytes(), original + suffix)

    def test_utf8_offsets_and_existing_rust_source_entry_survive_literal_edit(self):
        root, _target = self.prepare()
        target = root / 'unicode.py'
        before = '# 非 ASCII 字节不改变 AST 列位置的处理\nVALUES=(\n    "already",\n)\nanswer=37\n'.encode()
        target.write_bytes(before)
        extend_development_tuple(root, target.name, 'VALUES', ('new',))
        tree = ast.parse(target.read_bytes())
        value = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'VALUES' for t in node.targets)))
        self.assertEqual(value, ('already', 'new'))
        target = root / 'source.py'; target.write_bytes((BASE / 'tools/hia_selfhost_contract.py').read_bytes())
        extend_development_tuple(root, target.name, 'SOURCE_FILES', (NATIVE,))
        tree = ast.parse(target.read_bytes())
        value = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'SOURCE_FILES' for t in node.targets)))
        self.assertIn('tests/test_hia_rust_finite_heap.py', value)
        self.assertEqual(value[-1], NATIVE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
