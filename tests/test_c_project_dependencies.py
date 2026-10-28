"""Real Clang dependency capture plus explicit Make-vs-shell syntax boundaries."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_project import _make_dependency_tokens, capture_project, invoke, verify_capture


class ClangMakeDependencySyntaxTests(unittest.TestCase):
    def test_windows_drive_unc_and_native_backslashes_are_not_shell_escapes(self):
        raw = ("hepta_dependencies: input.c \\\r\n  "
               + r"C:\Program\ Files\LLVM\lib\clang\20\include\limits.h "
               + r"\\server\include\shared.h" + "\r\n")
        self.assertEqual(_make_dependency_tokens(raw), ["input.c",
            r"C:\Program Files\LLVM\lib\clang\20\include\limits.h",
            r"\\server\include\shared.h"])

    def test_clang_escaped_spaces_hash_dollar_and_literal_quotes(self):
        raw = "hepta_dependencies: input.c a\\ b\\#c$$d'e\"f.h\n"
        self.assertEqual(_make_dependency_tokens(raw), ["input.c", "a b#c$d'e\"f.h"])

    def test_backslash_runs_before_spaces_and_hashes_follow_clang_emission(self):
        self.assertEqual(_make_dependency_tokens("hepta_dependencies: "
            + r"dir\\\ file.h folder\\#name.h" + "\n"),
            [r"dir\ file.h", r"folder\#name.h"])

    def test_other_rules_variables_comments_and_ambiguous_whitespace_reject(self):
        bodies = ("other: input.c\n", "hepta_dependencies: input.c\nother: hidden.h\n",
                  "hepta_dependencies: $(ROOT)/input.c\n", "hepta_dependencies: input.c # hidden.h\n",
                  "hepta_dependencies: input.c\theader.h\n", "hepta_dependencies: input.c\x00\n",
                  "hepta_dependencies: tail\\\n", "hepta_dependencies: ")
        for raw in bodies:
            with self.subTest(raw=raw), self.assertRaises(MigrationRejected) as failure:
                _make_dependency_tokens(raw)
            self.assertEqual(failure.exception.code, "E_C_BUILD_DEPENDENCIES")

    def test_dependency_count_is_bounded_before_path_resolution(self):
        self.assertEqual(len(_make_dependency_tokens("hepta_dependencies: " + " ".join(f"h{i}.h" for i in range(512)) + "\n")), 512)
        with self.assertRaises(MigrationRejected):
            _make_dependency_tokens("hepta_dependencies: " + " ".join(f"h{i}.h" for i in range(513)) + "\n")


class ClangMakeDependencyNativeTests(unittest.TestCase):
    def setUp(self):
        self.clang = os.environ.get("CLANG") or shutil.which("clang")
        self.assertIsNotNone(self.clang, "Actual Clang is required")
        temporary = tempfile.TemporaryDirectory(prefix="hepta-dependency-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.header = self.root / "include path" / "cash$#'value.h"
        self.header.parent.mkdir()
        self.header.write_text("#define VALUE 7u\n", encoding="utf-8")
        self.source = self.root / "input.c"
        self.source.write_text('#include "include path/cash$#\'value.h"\n'
                               "unsigned probe(unsigned x) { return x + VALUE; }\n", encoding="utf-8")
        self.database = self.root / "compile_commands.json"
        self.database.write_text(json.dumps([{"directory": str(self.root), "file": "input.c",
            "arguments": ["clang", "-std=c11", "-c", "input.c", "-o", "input.o"]}]), encoding="utf-8")

    def test_actual_clang_make_bytes_bind_the_complete_escaped_header(self):
        raw = invoke([self.clang, "-std=c11", "-M", "-MT", "hepta_dependencies", "input.c"], self.root)
        self.assertIn("$$", raw)
        self.assertIn("\\#", raw)
        capture = capture_project(self.database, clang=self.clang)
        identities = {row["path"]: row for row in capture["dependencies"]}
        self.assertEqual(identities[str(self.header.resolve())]["sha256"], hashlib.sha256(self.header.read_bytes()).hexdigest())
        self.assertEqual(len([row for row in identities.values() if row["project_input"]]), 2)
        verify_capture(capture)
        migration = migrate_c_project(self.database, self.root / "translated", clang=self.clang)
        self.assertTrue(migration["ok"], migration)
        self.assertEqual(migration["coverage"]["active_project_declarations"], 1)

    def test_changed_and_removed_escaped_header_still_reject_capture_replay(self):
        capture = capture_project(self.database, clang=self.clang)
        self.header.write_text("#define VALUE 99u\n", encoding="utf-8")
        with self.assertRaises(MigrationRejected) as changed:
            verify_capture(capture)
        self.assertEqual(changed.exception.code, "E_C_BUILD_CHANGED")
        self.header.unlink()
        with self.assertRaises(MigrationRejected) as absent:
            verify_capture(capture)
        self.assertEqual(absent.exception.code, "E_C_BUILD_CHANGED")
        self.assertIn(repr(str(self.header)), str(absent.exception))


if __name__ == "__main__":
    unittest.main()
