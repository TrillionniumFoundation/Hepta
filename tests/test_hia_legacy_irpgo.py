"""Reject fabricated profile activity and changes to the actual HIA build input.

Counter checks use emitted LLVM and retained-format profile text. Target
binding checks capture actual frontend attributes; the supervised failure
control executes one deliberately signalled child. No timing campaign or
model execution is performed.
"""
from copy import deepcopy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from tools.qualify_hia_legacy_irpgo import IRPGOTrial, inspect_ir_counters
from tools.qualify_hia_legacy_queue import ENTRY, LegacyTrial, generated_program_identity
from tools.qualify_hia_filecheck import identity
from tools.hia_filecheck_target_profile import elf_linker_driver


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
        self.linker_contexts = ExitStack()
        self.addCleanup(self.linker_contexts.close)
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
        clang = shutil.which(os.environ.get("CLANG", "clang"))
        linker = shutil.which(os.environ.get("HEPTA_LLD", "ld.lld"))
        self.assertIsNotNone(clang, "actual Clang required for native target binding")
        self.assertIsNotNone(linker, "actual LTO linker required")
        driver, _ = self.linker_contexts.enter_context(elf_linker_driver(linker))
        trial.tools = {"clang": clang}
        trial.flags = ["-O3", "-flto=full", "-fuse-ld=" + driver, "-march=native",
                       "-fPIC", "-shared", "-Wl,-Bsymbolic-functions"]
        trial.report = {"commands": [], "migration": {"generated_program": self.binding}}
        trial.prepare_native_ir()
        trial.command = Mock(return_value={"wall_ns": 0})
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

    def test_changed_bound_ir_profile_and_compiler_refuse_before_build(self):
        trial = self.trial()
        bound = self.directory / "program.native.ll"
        original = bound.read_bytes()
        changed = original.replace(b" = add i32 ", b" = sub i32 ")
        self.assertNotEqual(changed, original)
        bound.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "native target artifact changed"):
            trial.irpgo_build("hia", self.out / "absent.so", [], "refused_bound_body")
        bound.write_bytes(original)
        snapshot = deepcopy(trial.report["native_target_binding"])
        trial.report["native_target_binding"]["profile"]["target_cpu"] = "synthetic_changed_cpu"
        with self.assertRaisesRegex(ValueError, "native target binding changed"):
            trial.irpgo_build("hia", self.out / "absent.so", [], "refused_profile")
        trial.report["native_target_binding"] = snapshot
        saved_profile = self.out / "native-target-profile/profile.json"
        profile_bytes = saved_profile.read_bytes()
        saved_profile.write_bytes(profile_bytes + b"\n")
        with self.assertRaises(ValueError):
            trial.irpgo_build("hia", self.out / "absent.so", [], "refused_profile_bytes")
        saved_profile.write_bytes(profile_bytes)
        compiler = trial.tools["clang"]
        trial.tools["clang"] = sys.executable
        with self.assertRaisesRegex(ValueError, "native compiler changed"):
            trial.irpgo_build("hia", self.out / "absent.so", [], "refused_compiler")
        trial.tools["clang"] = compiler
        trial.flags.append("-O0")
        with self.assertRaisesRegex(ValueError, "native target binding changed"):
            trial.irpgo_build("hia", self.out / "absent.so", [], "refused_flags")
        trial.flags.pop()
        for extra in (["-march=znver4"], ["-mavx512f"], ["-O0"],
                      ["-fprofile-generate", "-Xclang", "+avx512f"]):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError, "only the declared profile-generation/use flags"):
                    trial.irpgo_build("hia", self.out / "absent.so", extra, "refused_extra_target_flags")
        trial.require_native_ir()
        trial.command.assert_not_called()
        self.assertFalse((self.out / "absent.so").exists())


class SupervisedChildFailureTests(unittest.TestCase):
    def test_actual_sigill_retains_failed_child_receipt_without_retry(self):
        clang = shutil.which(os.environ.get("CLANG", "clang"))
        self.assertIsNotNone(clang, "actual Clang required for supervised native failure")
        with tempfile.TemporaryDirectory(prefix="hepta-legacy-supervised-signal-") as tmp:
            root = Path(tmp)
            source = root / "signal.c"
            source.write_text('#include <signal.h>\n#include <sys/resource.h>\n'
                'int main(void) { struct rlimit limit = {0, 0};\n'
                'if (setrlimit(RLIMIT_CORE, &limit)) return 70;\n'
                'raise(SIGILL); return 71; }\n')
            supervisor = Path(__file__).resolve().parents[1] / "examples/hia_filecheck/rss_supervisor.c"
            builds = []
            for input_path, output in ((source, root / "filecheck"), (supervisor, root / "rss-supervisor")):
                argv = [clang, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(input_path), "-o", str(output)]
                process = subprocess.run(argv, text=True, capture_output=True, timeout=30)
                builds.append({"argv": argv, "returncode": process.returncode,
                               "stdout": process.stdout, "stderr": process.stderr})
                self.assertEqual(process.returncode, 0, builds[-1])
            (root / "unused-image").write_bytes(b"not loaded by signal control")
            (root / "held-out.bin").write_bytes(b"fixture")
            trial = LegacyTrial.__new__(LegacyTrial)
            trial.out = root
            trial.libraries = {"signal_control": root / "unused-image"}
            trial.runtime_images = {str(root / "unused-image"): identity(root / "unused-image")}
            trial.driver_identity = identity(root / "filecheck")
            trial.supervisor_identity = identity(root / "rss-supervisor")
            trial.application_serial = 0
            trial.report = {"commands": [], "inputs": {"held-out.bin": identity(root / "held-out.bin")}}
            with self.assertRaisesRegex(ValueError, r"child_signal=SIGILL \(4\)"):
                trial.application("signal_control", "castagnoli", stage="actual_signal_control")
            self.assertEqual(len(trial.report["commands"]), 1)
            self.assertEqual(trial.report["commands"][0]["returncode"], 1)
            failures = trial.report["failed_applications"]
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["memory"]["child_signal"], 4)
            self.assertEqual(failures[0]["memory"]["child_exit_code"], -1)
            self.assertEqual(failures[0]["child_signal_name"], "SIGILL")
            self.assertEqual(failures[0]["memory_receipt"], identity(root / "rss-0000.json"))
            payload = {"schema": "hepta.legacy-supervised-signal-regression.v1", "builds": builds,
                       "report": trial.report, "library_image_executed": False, "retries": 0}
            (root / "execution.json").write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
            retained = os.environ.get("HEPTA_FILECHECK_TARGET_EVIDENCE")
            if retained:
                destination = Path(retained) / "supervised-sigill"
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(root, destination)
            print(json.dumps({"legacy_supervised_signal_execution": payload}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
