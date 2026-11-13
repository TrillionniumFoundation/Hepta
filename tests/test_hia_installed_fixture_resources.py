"""Keep explicit whole-package wheel copy fixtures complete as roles grow.

This static regression detects the actual omitted role lists seen in wire and
worker-report fixtures. It is not a replacement for executing installed wheels.
"""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class InstalledFixtureRoleInventoryTests(unittest.TestCase):
    def test_explicit_whole_package_copy_fixtures_cover_all_current_roles(self):
        module=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
        needed={target.id for node in module.body if isinstance(node,ast.Assign)
            for target in node.targets if isinstance(target,ast.Name)
            and (target.id.endswith('_BUILD_FILES') or target.id in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES'))}
        self.assertTrue({'NATIVE_SOURCE_FILES','MACHINE_OBJECT_BUILD_FILES',
                         'EXECUTION_OBSERVATION_BUILD_FILES'}.issubset(needed))
        observed=[]
        for file in sorted((ROOT/'tests').glob('*.py')):
            tree=ast.parse(file.read_text())
            strings={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) is str}
            names={n.id for n in ast.walk(tree) if isinstance(n,ast.Name)}|{
                n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute)}
            copies=any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                and n.func.attr in ('copytree','copyfile') for n in ast.walk(tree))
            used=needed&(strings|names)
            if copies and 'setup.py' in strings and used:
                observed.append(file.name)
                with self.subTest(fixture=file.name):self.assertEqual(needed-used,set())
        self.assertIn('test_hia_json_wire_native.py',observed)
        self.assertIn('test_hia_worker_report_native.py',observed)
        self.assertGreaterEqual(len(observed),25)


if __name__=='__main__':unittest.main()
