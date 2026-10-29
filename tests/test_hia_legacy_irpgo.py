"""Reject fabricated profile activity and changes to the actual HIA build input.

These checks use emitted LLVM and retained-format profile text. They do not
compile a native image, execute a model, train PGO, or collect timing samples.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from tools.qualify_hia_legacy_irpgo import IRPGOTrial, inspect_ir_counters
from tools.qualify_hia_legacy_queue import ENTRY, generated_program_identity


PROFILE = f"""Counters:
  unrelated_function:
    Hash: 0x0a4d0ad3efffffff
    Counters: 1
    Block counts: [999]
  {ENTRY}:
    Hash: 0x0d3e10436267f4fe
    Counters: 3
    Block counts: [16, 0, 2]
Instrumentation level: IR  entry_first = 0  instrument_loop_entries = 0
Functions shown: 2
Total functions: 2
Maximum function count: 999
Maximum internal block count: 2
Total number of blocks: 4
Total count: 1017
"""


class ActualEntryCounterTests(unittest.TestCase):
    def test_target_function_counters_are_retained_without_call_count_claim(self):
        report = inspect_ir_counters(PROFILE)
        self.assertEqual(report["entry_function"], ENTRY)
        self.assertEqual(report["entry_function_block_counts"], [16, 0, 2])
        self.assertEqual(report["entry_function_counters"], 3)
        self.assertIn("not entry invocation counts", report["entry_counter_interpretation"])

    def test_other_function_activity_cannot_rescue_a_zero_target(self):
        forged = PROFILE.replace("[16, 0, 2]", "[0, 0, 0]")
        self.assertIn("Total count: 1017", forged)
        with self.assertRaisesRegex(ValueError, "actual entry function counters must be nonzero"):
            inspect_ir_counters(forged)

    def test_missing_or_duplicate_target_is_rejected(self):
        missing = PROFILE.replace("  " + ENTRY + ":", "  another_function:")
        duplicate = PROFILE.replace("  unrelated_function:", "  " + ENTRY + ":")
        for shown in (missing, duplicate):
            with self.subTest(shown=shown):
                with self.assertRaisesRegex(ValueError, "exactly one actual entry"):
                    inspect_ir_counters(shown)

    def test_malformed_width_count_and_duplicate_counter_lists_are_rejected(self):
        bad = [PROFILE.replace("Counters: 3", "Counters: 2"),
               PROFILE.replace("[16, 0, 2]", "[16, -1, 2]"),
               PROFILE.replace("[16, 0, 2]", "[16, 18446744073709551616, 2]"),
               PROFILE.replace("[16, 0, 2]", "[16, 1e9, 2]"),
               PROFILE.replace("[16, 0, 2]", "[16, " + "9" * 1000 + ", 2]"),
               PROFILE.replace("Counters: 3", "Counters: 3\n    Counters: -1"),
               PROFILE.replace("Block counts: [16, 0, 2]", "Block counts: [16, 0, 2]\n    Block counts: broken"),
               PROFILE.replace("Instrumentation level: IR", "Instrumentation level: Front-end")]
        for shown in bad:
            with self.subTest(shown=shown[:300]):
                with self.assertRaises(ValueError):
                    inspect_ir_counters(shown)


class SameCoreBuildInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)
        self.directory = self.out / "migration"
        self.directory.mkdir()
        params = [{"name": name, "type": "u32"} for name in ("a", "b")]
        self.core = verify_program({"schema": "hepta.hia.program.v1", "module": "bound_ir",
            "functions": [{"name": "sum", "params": params, "returns": ["u32"], "effects": [],
                "entry": "entry", "blocks": [{"id": "entry", "params": params,
                    "ops": [{"op": "int.add.wrap", "args": ["a", "b"],
                             "out": [{"name": "answer", "type": "u32"}], "attrs": {}}],
                    "term": {"op": "ret", "values": ["answer"]}}]}]})
        (self.directory / "program.hia.json").write_bytes(self.core.canonical_bytes)
        self.llvm = emit_program_llvm(self.core).text
        (self.directory / "program.ll").write_text(self.llvm)
        self.binding = generated_program_identity(self.core, self.directory)

    def corrupt_llvm(self):
        changed = self.llvm.replace(" = add i32 ", " = sub i32 ")
        self.assertNotEqual(changed, self.llvm)
        self.assertEqual(len(changed), len(self.llvm))
        (self.directory / "program.ll").write_text(changed)

    def trial(self):
        trial = IRPGOTrial.__new__(IRPGOTrial)
        trial.out, trial.core = self.out, self.core
        trial.tools, trial.flags = {"clang": "unused-compiler"}, []
        trial.report = {"migration": {"generated_program": self.binding}}
        trial.command = Mock(return_value={})
        return trial

    def test_generated_core_and_llvm_are_bound_to_exact_verified_bytes(self):
        actual = generated_program_identity(self.core, self.directory)
        self.assertEqual(actual["core"]["sha256"], self.core.sha256)
        self.assertEqual(actual["llvm"]["bytes"], len(self.llvm.encode("utf-8")))

    def test_changed_ir_with_the_same_export_and_size_is_rejected_before_build(self):
        trial = self.trial()
        self.corrupt_llvm()
        with self.assertRaisesRegex(ValueError, "generated llvm differs"):
            trial.irpgo_build("hia", self.out / "unused.so", [], "refused_before_build")
        trial.command.assert_not_called()

    def test_mutation_during_research_build_is_rejected_after_return(self):
        trial = self.trial()
        trial.command.side_effect = lambda *args, **kwargs: self.corrupt_llvm()
        with self.assertRaisesRegex(ValueError, "generated llvm differs"):
            trial.irpgo_build("hia", self.out / "unused.so", [], "refused_after_build")
        trial.command.assert_called_once()

    def test_changed_canonical_core_file_cannot_hide_behind_unchanged_llvm(self):
        path = self.directory / "program.hia.json"
        path.write_bytes(path.read_bytes().replace(b"bound_ir", b"forgedir"))
        with self.assertRaisesRegex(ValueError, "generated core differs"):
            generated_program_identity(self.core, self.directory)


if __name__ == "__main__":
    unittest.main()
