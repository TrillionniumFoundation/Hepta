"""The Linux campaign must retain rejected units and original Kbuild semantics."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.qualify_hia_linux_translation import audit_translation, source_inventory


class LinuxTranslationCampaignTests(unittest.TestCase):
    def test_whole_database_limit_does_not_erase_33_rejected_units(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "linux"
            source.mkdir()
            records = []
            for index in range(33):
                file = source / f"unit_{index}.c"
                file.write_text("int f(void) { return 0; }\n")
                records.append({"directory": str(source), "file": file.name,
                                "arguments": ["clang", "-std=gnu11", "-mcmodel=kernel",
                                              "-c", file.name, "-o", f"unit_{index}.o"]})
            database = root / "compile_commands.json"
            original = json.dumps(records).encode()
            database.write_bytes(original)
            config = root / ".config"
            config.write_text("CONFIG_64BIT=y\n")
            result = audit_translation(database, config, source, root / "results", "clang")
            self.assertEqual(result["active_compile_units"], 33)
            self.assertEqual(result["attempted_compile_units"], 33)
            self.assertEqual(result["intake_status_counts"], {"rejected": 33})
            self.assertEqual(result["declaration_inventory_complete_units"], 0)
            self.assertIsNone(result["function_denominator"])
            self.assertEqual(result["hia_compiled_units"], 0)
            self.assertEqual(result["full_project_capture"]["code"], "E_C_BUILD_DATABASE")
            self.assertFalse(result["per_command_intake_is_full_project_capture"])
            self.assertEqual(database.read_bytes(), original)
            with gzip.open(result["ledger"]["path"], "rt") as stream:
                rows = [json.loads(line) for line in stream]
            self.assertEqual([row["original_entry"] for row in rows], records)
            self.assertEqual([row["index"] for row in rows], list(range(33)))
            self.assertTrue(all(row["declaration_analysis"] == "not_reached" for row in rows))
            self.assertTrue(all(row["hia_native_build"] == "not_run" for row in rows))
            self.assertTrue(all("gnu11" in row["rejection"]["message"] for row in rows))

    def test_original_relative_directory_resolves_against_original_database(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "linux"
            source.mkdir()
            (source / "a.c").write_text("int f(void) { return 1; }")
            entry = {"directory": "linux", "file": "a.c",
                     "arguments": ["clang", "-std=c11", "-c", "a.c"]}
            database = root / "compile_commands.json"
            database.write_text(json.dumps([entry]))
            config = root / ".config"
            config.write_text("CONFIG_TEST=y\n")
            observed = []

            def migrate(shard, output, **kwargs):
                content = json.loads(Path(shard).read_text())
                self.assertEqual(content, [entry])
                self.assertEqual(Path(shard).parent, database.parent)
                observed.append(shard)
                return {"ok": False, "declaration_inventory_complete": False,
                        "status": "rejected", "diagnostics": [{"code": "fixture"}]}

            # Resolve/import the consumer before replacing its dependency.
            # Otherwise that first lazy import permanently binds the temporary
            # capture mock through its `from c_project import capture_project`.
            with (patch("hepta.c_migration_project.migrate_project", side_effect=migrate),
                  patch("tools.qualify_hia_linux_translation.c_project.capture_project",
                        return_value={"fixture": "full_capture_only"})):
                result = audit_translation(database, config, source, root / "results", "clang")
            self.assertEqual(len(observed), 1)
            self.assertEqual(result["intake_status_counts"], {"admitted": 1})
            self.assertEqual(result["hia_compiled_units"], 0)
            self.assertEqual(result["hia_kernel_status"], "not_built")
            self.assertFalse(result["all_configurations_translated"])
            self.assertFalse(Path(observed[0]).exists())

    def test_first_lazy_migration_import_does_not_retain_temporary_capture_mock(self):
        # A clean interpreter is essential: earlier imports in the wider suite
        # can hide this bug. Execute the real relative-directory test first,
        # then inspect the restored production binding in that same process.
        script = '''
import sys, unittest
sys.path.insert(0, sys.argv[1])
assert 'hepta.c_migration_project' not in sys.modules
suite = unittest.defaultTestLoader.loadTestsFromName(
    'tests.test_hia_linux_translation.LinuxTranslationCampaignTests.test_original_relative_directory_resolves_against_original_database')
result = unittest.TextTestRunner(verbosity=2).run(suite)
assert result.wasSuccessful() and result.testsRun == 1 and not result.skipped
from hepta import c_migration_project, c_project
assert c_migration_project.capture_project is c_project.capture_project
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script,
            str(Path(__file__).resolve().parents[1])], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicate_database_keys_fail_before_claiming_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = root / "compile_commands.json"
            db.write_text('[{"directory":"/a","directory":"/b","file":"a.c","command":"clang a.c"}]')
            config = root / ".config"
            config.write_text("")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                audit_translation(db, config, root, root / "result", "clang")
            self.assertFalse((root / "result").exists())

    def test_source_inventory_counts_unused_architecture_and_symlink_without_following(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "linux"
            source.mkdir()
            (source / "arch").mkdir()
            (source / "arch" / "unused.S").write_bytes(b"ret\n")
            (source / "main.c").write_bytes(b"int x;\n")
            (source / "README").write_bytes(b"upstream\n")
            outside = root / "outside.c"
            outside.write_bytes(b"not an upstream source\n")
            (source / "link.c").symlink_to(outside)
            receipt = {"version": "6.18.60", "sha256": "0" * 64}
            result = source_inventory(source, receipt, root / "inventory")
            self.assertEqual(result["regular_files"], 3)
            self.assertEqual(result["symlinks"], 1)
            self.assertEqual(result["c_source_files_total"], 1)
            self.assertEqual(result["files_by_kind"]["asm_cpp"], 1)
            self.assertEqual(result["source_files_total"], 2)
            self.assertFalse(result["all_configurations_compiled"])
            with gzip.open(result["manifest"]["path"], "rb") as stream:
                manifest = stream.read()
            self.assertEqual(hashlib.sha256(manifest).hexdigest(),
                             result["manifest"]["uncompressed_jsonl_sha256"])
            links = [json.loads(line) for line in manifest.splitlines()
                     if json.loads(line)["type"] == "symlink"]
            self.assertEqual(links[0]["target"], str(outside))


if __name__ == "__main__":
    unittest.main()
