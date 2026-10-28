"""The application corpus and failure paths must validate real migrated code."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_program import execute_program
from hepta.hia_program_source import lower_c_multi_owner
from tools.qualify_hia_filecheck import (FIXTURE, PROTOCOL, SOURCES, cases, checksum,
                                         corpus, order, quantile, update)


class FilecheckProtocolTests(unittest.TestCase):
    def test_known_vectors_and_chunking_independence(self):
        data = b"123456789"
        self.assertEqual(checksum(data, 0xedb88320), 0xcbf43926)
        self.assertEqual(checksum(data, 0x82f63b78), 0xe3069283)
        for polynomial in PROTOCOL["algorithms"].values():
            for width in range(1, 9):
                state = 0xffffffff
                for offset in range(0, len(data), width):
                    state = update(state, data[offset:offset + width], polynomial)
                self.assertEqual(state ^ 0xffffffff, checksum(data, polynomial))

    def test_complete_counterbalanced_trials_and_independent_training(self):
        rows = list(order())
        self.assertEqual(len(rows), 7 * 2 * 8)
        for group in range(7):
            for algorithm in PROTOCOL["algorithms"]:
                self.assertCountEqual([arm for g, a, arm in rows if (g, a) == (group, algorithm)], PROTOCOL["arms"])
        train = PROTOCOL["training"]
        held = PROTOCOL["held_out"]
        self.assertNotEqual(corpus(train["seed"], 16384), corpus(held["seed"], 16384))
        self.assertEqual(quantile(list(range(1, 101)), .99), 99)

    @unittest.skipUnless(os.environ.get("CLANG") or shutil.which("clang"), "actual Clang required")
    def test_real_multifile_translation_normal_invalid_and_allocator_refusal(self):
        with tempfile.TemporaryDirectory(prefix="filecheck-test-") as tmp:
            database = Path(tmp) / "compile_commands.json"
            database.write_text(json.dumps([{"directory": str(FIXTURE), "file": name,
                "arguments": ["clang", "-std=c11", "-I.", "-c", name, "-o", name + ".o"]} for name in SOURCES]))
            migration = lower_c_multi_owner(database, clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(len(migration["functions"]), 2)
            self.assertEqual(migration["owners_lowered"], 1)
            core = migration["program"]
            for case in list(cases())[:12]:
                for refusal in (None, 1):
                    args = case["arguments"]
                    report = execute_program(core, "c_checksum_chunk", args, allocation_fail_at=refusal)
                    expected = 2 << 32 if refusal and 0 < args[0] <= 8 else case["expected"]
                    self.assertEqual(report["result"], expected)
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["live_bytes"], 0)
                    self.assertEqual(report["resources"]["loans_started"], report["resources"]["loans_ended"])


if __name__ == "__main__":
    unittest.main()
