"""Product boundary controls plus actual standalone Core behavior."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import shutil
from tools.check_hia_core_only import check, ROOT

class CoreOnlyTests(unittest.TestCase):
    def test_stale_string_selector_refuses_instead_of_disappearing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['pyproject.toml','docs/HIA_CORE_ONLY_SCOPE.json']:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            (root/'tools').mkdir()
            (root/'tools/gate.py').write_text("SUITE = ('tests.test_deleted_language',)\n")
            with self.assertRaisesRegex(ValueError,'absent test selector'):
                check(root)

    def test_relative_alias_import_of_removed_parser_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['pyproject.toml','docs/HIA_CORE_ONLY_SCOPE.json']:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            (root/'hepta').mkdir()
            (root/'hepta/bridge.py').write_text('from . import parser as old_parser\n')
            with self.assertRaisesRegex(ValueError,'deleted-language import'):
                check(root)

    def test_removed_cli_instruction_cannot_return_through_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['pyproject.toml','docs/HIA_CORE_ONLY_SCOPE.json']:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            (root/'docs/START.md').write_text('Run `hepta hia build input.json`.\n')
            with self.assertRaisesRegex(ValueError,'removed CLI instruction'):
                check(root)

    def test_actual_tree_has_no_high_level_source_or_import(self):
        self.assertEqual(check()['status'],'PASS')

    def test_only_agent_console_is_installed(self):
        import tomllib
        metadata=tomllib.loads((ROOT/'pyproject.toml').read_text())
        self.assertEqual(metadata['project']['scripts'],{'hia':'hepta.cli:hia_main'})

    def test_source_and_migration_cli_routes_are_rejected(self):
        for command in ['check','lower','import-executable','import-scalar','import-cpp-project','hepta','hia']:
            result=subprocess.run([sys.executable,'-B','-m','hepta',command],cwd=ROOT,capture_output=True)
            self.assertEqual(result.returncode,2,(command,result.stdout,result.stderr))

    def test_core_route_rejects_source_without_selecting_a_frontend(self):
        from hepta.hia_routes import admit_route, RouteRejected
        with self.assertRaises(RouteRejected):admit_route('removed-source',b'not Core')
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import execute_program
        text=(ROOT/'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()
        program=assemble_program(text)
        self.assertTrue(program.report()['ok'])

    def test_release_descriptor_does_not_claim_native_completion(self):
        from tools.hia_release import describe
        value=describe()
        self.assertEqual(value['high_level_source_language'],'removed')
        self.assertFalse(value['whole_native_delivery_qualified'])
        self.assertFalse(value['production_activated'])
