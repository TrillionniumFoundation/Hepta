"""P3: bounded, deterministic C compile database intake (no Clang needed).

All malformed cases must reject before any compiler command is executed.
The same intake function is called on initial capture and on replay.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.c_project import _load_compdb, _MAX_COMPDB_BYTES


class CompilationDatabaseIntakeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "compile_commands.json"
        self.valid = {"directory": temp.name, "file": "input.c",
                      "arguments": ["clang", "-std=c11", "-c", "input.c"]}

    def read(self, content, code=None):
        raw = (content.encode("utf-8") if isinstance(content, str) else content)
        self.path.write_bytes(raw)
        if code is None:
            return _load_compdb(self.path)
        with self.assertRaises(MigrationRejected) as error:
            _load_compdb(self.path)
        self.assertEqual(error.exception.code, code)

    def test_roundtrip_arguments_and_explicit_command(self):
        original = json.dumps([self.valid])
        raw, parsed = self.read(original)
        self.assertEqual(raw, original.encode())
        self.assertEqual(parsed, [self.valid])
        cmd = {"directory": self.valid["directory"], "file": "input.c",
               "command": 'clang -std=c11 -c "input.c"', "output": "input.o"}
        _, parsed = self.read(json.dumps([cmd]))
        self.assertEqual(parsed, [cmd])

    def test_duplicate_keys_even_if_resealed_elsewhere(self):
        directory = json.dumps(self.valid["directory"])
        nested = ('[{"directory":' + directory +
                  ',"file":"input.c","file":"renamed.c",'
                  '"arguments":["clang","-std=c11","-c","input.c"]}]')
        self.read(nested, "E_C_BUILD_JSON")
        self.read('[{"directory":"/tmp","file":"input.c",'
                  '"arguments":["clang"],"arguments":["gcc"]}]',
                  "E_C_BUILD_JSON")
        self.read('[{"directory":"/tmp","file":"input.c","output":"f.o",'
                  '"arguments":["clang"],"output":"g.o"}]', "E_C_BUILD_JSON")

    def test_unknown_schema_and_ambiguous_command(self):
        mutations = [
            {**self.valid, "unsafe": "ignored"},
            {**self.valid, "command": "clang input.c"},
            {"directory": self.valid["directory"], "file": "input.c"},
            {**self.valid, "arguments": "clang -std=c11 input.c"},
            {**self.valid, "arguments": ["clang", 7]},
            {**self.valid, "arguments": ["clang", ""]},
            {**self.valid, "arguments": ["clang", "abc\x00def"]},
            {**self.valid, "output": 7},
            {**self.valid, "directory": ""},
            {**self.valid, "file": "\ud800"},
            ["not a command"],
            None,
        ]
        for row in mutations:
            with self.subTest(case=repr(row)[:120]):
                payload = json.dumps([row] if isinstance(row, dict) else row)
                self.read(payload, "E_C_BUILD_JSON" if row is not None else "E_C_BUILD_DATABASE")

    def test_nonfinite_invalid_unicode_and_extra_input(self):
        for text in ['[NaN]', '[Infinity]', '[-Infinity]',
                     json.dumps([self.valid]) + "\nnot-json"]:
            with self.subTest(input=text[:24]):
                self.read(text, "E_C_BUILD_JSON")
        self.read(b"\xff\xfe\xfd", "E_C_BUILD_JSON")

    def test_quote_flag_and_capacity_limits(self):
        base = {"directory": "/tmp", "file": "main.c",
                "command": "clang -std=c11 -c 'unterminated"}
        self.read(json.dumps([base]), "E_C_BUILD_JSON")
        self.read(json.dumps([self.valid] * 33), "E_C_BUILD_DATABASE")
        self.read(json.dumps([{**self.valid, "arguments": ["clang"] * 257}]),
                  "E_C_BUILD_JSON")
        self.read(json.dumps([{**self.valid, "arguments": ["clang", "X" * 16400]}]),
                  "E_C_BUILD_SIZE")
        self.read(json.dumps([{**self.valid, "file": "X" * 5000}]),
                  "E_C_BUILD_SIZE")
        self.read(b" " * (_MAX_COMPDB_BYTES + 1), "E_C_BUILD_SIZE")


if __name__ == "__main__":
    unittest.main()
