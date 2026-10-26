"""P3: untrusted compile_commands.json is bounded at capture and replay."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.c_project import (
    _MAX_COMPDB_BYTES, _read_compilation_database, capture_project, verify_capture,
)


class CCompilationDatabaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "compile_commands.json"
        self.source = self.root / "native.c"
        self.source.write_text("int f(int n) { return n + 1; }\n")

    def payload(self):
        return [{"directory": str(self.root), "file": "native.c",
                 "arguments": ["clang", "-std=c11", "-c", "native.c"]}]

    def write(self, value):
        self.database.write_text(json.dumps(value, ensure_ascii=False))

    def rejected(self, data: bytes, code: str):
        self.database.write_bytes(data)
        with self.assertRaises(MigrationRejected) as raised:
            _read_compilation_database(self.database)
        self.assertEqual(raised.exception.code, code)

    def test_small_real_compdb_identity_bytes(self):
        self.write(self.payload())
        original = self.database.read_bytes()
        data, records = _read_compilation_database(self.database)
        self.assertEqual(original, data)
        self.assertEqual(records, self.payload())

    def test_duplicate_keys_and_nonfinite_constants(self):
        prefix = json.dumps(str(self.root))
        self.rejected(
            ('[{"directory":' + prefix + ',"file":"native.c",'
             '"file":"other.c","arguments":["clang","-std=c11","native.c"]}]').encode(),
            "E_C_BUILD_DATABASE")
        self.rejected(
            ('[{"directory":' + prefix + ',"file":"native.c",'
             '"arguments":["clang","-std=c11","native.c"],'
             '"untrusted":NaN}]').encode(),
            "E_C_BUILD_DATABASE")
        self.rejected(
            ('[{"directory":' + prefix + ',"file":"native.c",'
             '"arguments":["clang","-std=c11","native.c"],'
             '"untrusted":Infinity}]').encode(),
            "E_C_BUILD_DATABASE")

    def test_deep_nested_metadata_and_invalid_types(self):
        doc = self.payload()
        nested = "value"
        for _ in range(55):
            nested = [nested]
        doc[0]["unsupported_nested"] = nested
        self.rejected(json.dumps(doc).encode(), "E_C_BUILD_SIZE")
        doc = self.payload()
        doc[0]["arguments"].append(1)
        self.rejected(json.dumps(doc).encode(), "E_C_BUILD_DATABASE")
        doc = self.payload()
        doc[0]["unknown"] = "x" * 65537
        self.rejected(json.dumps(doc).encode(), "E_C_BUILD_DATABASE")

    def test_bounded_read_and_bad_encoding(self):
        self.rejected(b" " * (_MAX_COMPDB_BYTES + 1), "E_C_BUILD_SIZE")
        self.rejected(b"\xff", "E_C_BUILD_DATABASE")
        self.rejected(b"[]", "E_C_BUILD_DATABASE")
        self.rejected(b"{}", "E_C_BUILD_DATABASE")

    @unittest.skipUnless(shutil.which("clang"), "Clang required for actual TU capture/replay")
    def test_identical_parser_is_used_at_capture_and_replay(self):
        self.write(self.payload())
        recorded = capture_project(self.database, clang="clang")
        verify_capture(recorded)
        # Malformed duplicate keys must not pass even if a stale manifest has
        # already been captured. Replaying the record must use the SAME parser.
        duplicate = self.database.read_text().replace(
            '"file": "native.c",', '"file": "native.c", "file": "native.c",')
        self.database.write_text(duplicate)
        with self.assertRaisesRegex(MigrationRejected, "duplicate JSON keys"):
            verify_capture(recorded)


if __name__ == "__main__":
    unittest.main()
