"""Native host binding and actual captured C -> HIA LLVM application behavior.

The application tests execute only the current host. An x86 run never counts as
an AArch64 execution, even though the existing backend can emit an ARM object.
"""
from __future__ import annotations

import ctypes
from dataclasses import replace
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import (HIAProgramLLVMRejected, TARGET, TARGET_AARCH64,
                                    compile_program_llvm, emit_program_llvm,
                                    native_driver_matches_host, native_host_profile)
from hepta.hia_program_source import lower_c_project_views
from tools.qualify_hia_c_posttest import (HOST_PROTOCOL, PROTOCOL, build_host_executables,
    inspect_host_executable, native_abi_preamble, native_driver_source, prepare_project,
    qualify, read_native_results, require_independent_original_c, require_native_host)
from tools.qualify_hia_filecheck import RESOURCE_HARNESS, update
from tools.qualify_hia_legacy_queue import ENTRY, SOURCES, compile_database
from tools.qualify_hia_program import block, function, ret


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
HOSTED = platform.system() == "Linux" and platform.machine().lower() in {
    "x86_64", "amd64", "aarch64", "arm64"}


def tiny_program():
    return verify_program({"schema": "hepta.hia.program.v1", "module": "native_host_test",
        "functions": [function("identity", [("x", "u64")], ["u64"], [],
                               [block("entry", [("x", "u64")], [], ret("x"))])]})


class HIAProgramNativeHostContractTests(unittest.TestCase):
    def test_clang_under_two_labels_is_not_an_independent_gnu_c_differential(self):
        distinct = {"clang": {"sha256": "a" * 64}, "cc": {"sha256": "b" * 64}}
        require_independent_original_c("#define __GNUC__ 14\n", distinct)
        for macros, tools in (("#define __GNUC__ 4\n#define __clang__ 1\n", distinct),
                               ("#define __GNUC__ 14\n", {"clang": distinct["clang"], "cc": distinct["clang"]}),
                               ("#define OTHER_COMPILER 1\n", distinct)):
            with self.assertRaisesRegex(ValueError, "independent original Clang and GNU C"):
                require_independent_original_c(macros, tools)

    def test_driver_target_rejects_foreign_machine_ilp32_and_non_linux(self):
        for target, arch in ((TARGET, "x86_64"), (TARGET_AARCH64, "aarch64")):
            host = {"target": target}
            for triple in (arch + "-linux-gnu", arch + "-unknown-linux-gnu", arch + "-pc-linux-gnu"):
                self.assertTrue(native_driver_matches_host(triple, host))
            other = "aarch64" if arch == "x86_64" else "x86_64"
            for triple in (other + "-unknown-linux-gnu", arch + "-unknown-linux-gnuilp32",
                           arch + "-apple-darwin", arch + "-linux-musl", target + "\nextra"):
                self.assertFalse(native_driver_matches_host(triple, host), triple)

    def test_host_rejects_wrong_os_unknown_machine_and_big_endian(self):
        for system, machine, byteorder in (("Darwin", "arm64", "little"),
                                            ("Linux", "riscv64", "little"),
                                            ("Linux", "aarch64", "big")):
            with self.subTest(system=system, machine=machine, byteorder=byteorder), \
                 patch("hepta.hia_program_llvm.platform.system", return_value=system), \
                 patch("hepta.hia_program_llvm.platform.machine", return_value=machine), \
                 patch("hepta.hia_program_llvm.sys.byteorder", byteorder):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "little-endian.*LP64"):
                    native_host_profile()

    def test_host_rejects_llp64_and_ilp32_processes(self):
        real_sizeof = ctypes.sizeof
        for changed_type in (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long):
            with self.subTest(changed_type=changed_type), \
                 patch("hepta.hia_program_llvm.platform.system", return_value="Linux"), \
                 patch("hepta.hia_program_llvm.platform.machine", return_value="aarch64"), \
                 patch("hepta.hia_program_llvm.ctypes.sizeof", side_effect=lambda value:
                       4 if value is changed_type else real_sizeof(value)):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "LP64"):
                    native_host_profile()

    @unittest.skipUnless(HOSTED, "requires an admitted executing Linux host")
    def test_requested_native_host_cannot_relabel_the_current_machine(self):
        actual = native_host_profile()
        self.assertEqual(require_native_host(actual["normalized_machine"]), actual)
        wrong = "aarch64" if actual["normalized_machine"] == "x86_64" else "x86_64"
        with self.assertRaisesRegex(ValueError, "differs from the executing machine"):
            require_native_host(wrong)
        with tempfile.TemporaryDirectory() as directory:
            report = qualify(Path(directory) / "refused", clang=CLANG, cc="gcc",
                             native_host=wrong, expected_source="a" * 40)
            self.assertFalse(report["ok"])
            self.assertFalse(report["claims"]["native_host_application_executed"])
            self.assertEqual(report["commands"], [])
            self.assertIn("executing machine", report["error"]["message"])

    @unittest.skipUnless(HOSTED, "requires an admitted executing Linux host")
    def test_native_host_protocol_does_not_relabel_the_legacy_v1_cohort(self):
        self.assertEqual(PROTOCOL["schema"], "hepta.hia.c-posttest-protocol.v1")
        self.assertEqual(PROTOCOL["host"], "Linux x86_64 LP64")
        self.assertEqual(HOST_PROTOCOL["schema"], "hepta.hia.c-posttest-native-host-protocol.v2")
        self.assertEqual(HOST_PROTOCOL["original_c_link_inputs_in_hia_target"], [])
        with tempfile.TemporaryDirectory() as directory, \
             patch("tools.qualify_hia_c_posttest._source_state", return_value={"head": "a" * 40,
                                                                                 "status": " M compiler.py"}):
            report = qualify(Path(directory) / "dirty", clang=CLANG, cc="gcc",
                             native_host=native_host_profile()["normalized_machine"],
                             expected_source="a" * 40)
            self.assertFalse(report["ok"])
            self.assertEqual(report["commands"], [])
            self.assertIn("exact clean expected commit", report["error"]["message"])

    @unittest.skipUnless(HOSTED and shutil.which(CLANG), "actual selected Clang required")
    def test_a_host_label_alone_cannot_admit_an_unmatched_compiler(self):
        program = tiny_program()
        other = "aarch64" if native_host_profile()["normalized_machine"] == "x86_64" else "x86_64"
        ir = emit_program_llvm(program, target=TARGET_AARCH64 if other == "aarch64" else TARGET)
        actual_target = TARGET if other == "aarch64" else TARGET_AARCH64
        with tempfile.TemporaryDirectory() as directory, \
             patch("hepta.hia_program_llvm.platform.machine", return_value=other), \
             patch("hepta.hia_program_llvm.run_bounded", side_effect=[
                 SimpleNamespace(returncode=0, stdout="clang version 20.1.8\n"),
                 SimpleNamespace(returncode=0, stdout=actual_target + "\n")]) as invoked:
            output = Path(directory) / "not-native.o"
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "matching the measured native host"):
                compile_program_llvm(ir, program=program, output=output, clang=CLANG, kind="object")
            self.assertEqual(invoked.call_count, 2)
            self.assertFalse(output.exists())

    def test_aarch64_shared_and_forged_target_still_reject_before_tools(self):
        program = tiny_program()
        ir = emit_program_llvm(program, target=TARGET_AARCH64)
        with tempfile.TemporaryDirectory() as directory, \
             patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("compiler must not run")):
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "relocatable"):
                compile_program_llvm(ir, program=program, output=Path(directory) / "arm.so", clang=CLANG)
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                compile_program_llvm(replace(ir, target=TARGET), program=program,
                                     output=Path(directory) / "forged.o", clang=CLANG, kind="object")


@unittest.skipUnless(HOSTED and shutil.which(CLANG) and shutil.which("gcc"),
                     "actual Linux LP64 Clang 20+ and GCC required")
class CapturedPostTestNativeHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-posttest-host-")
        cls.out = Path(cls.temporary.name)
        cls.host = native_host_profile()
        cls.project = cls.out / "project"
        contracts, _ = prepare_project(cls.project)
        database = compile_database(cls.project, cls.out / "capture")
        with patch("hepta.backend.emit_rust", side_effect=AssertionError("Rust fallback is forbidden")), \
             patch("hepta.backend.compile_rust", side_effect=AssertionError("Rust fallback is forbidden")):
            migrated = lower_c_project_views(database, contracts=contracts, clang=CLANG,
                                             client_source=(cls.project / "client.hepta").read_text())
        cls.core = migrated["program"]
        cls.cases = [{"arguments": [count, packed, PROTOCOL["state"], polynomial],
                      "expected": 1 << 32 if count > 8 else
                          update(PROTOCOL["state"], packed.to_bytes(8, "little")[:count], polynomial)}
                     for polynomial in PROTOCOL["polynomials"] for count in PROTOCOL["counts"]
                     for packed in PROTOCOL["packed_values"]]

        def command(argv, stage, *, cwd=None, timeout=45):
            result = run_bounded(list(map(str, argv)), cwd=cwd, timeout=timeout)
            if result.returncode:
                raise AssertionError(stage + ": " + result.stderr)
            return result.stdout

        cls.command = staticmethod(command)
        cls.native, cls.receipt, cls.builds = build_host_executables(cls.core, host=cls.host,
            tools={"clang": CLANG, "cc": shutil.which("gcc")}, project=cls.project, out=cls.out,
            cases=cls.cases, command=command)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_hia_object_original_clang_gcc_vm_and_crc_agree(self):
        self.assertEqual(self.receipt["target"], self.host["target"])
        self.assertFalse(self.receipt["cross_target_compilation"])
        self.assertFalse(self.receipt["claims"]["native_execution_qualified"])
        self.assertFalse(self.builds["hia"]["original_c_implementation_linked"])
        self.assertEqual([Path(row["path"]).name for row in self.builds["hia"]["implementation_inputs"]],
                         ["hia.o"])
        for label, path in self.native.items():
            probe, rows = read_native_results(self.command([path], label), self.cases, self.host)
            self.assertEqual(probe["machine"], self.host["normalized_machine"])
            self.assertEqual(len(rows), 48)
        for case in self.cases:
            result = execute_program(self.core, ENTRY, case["arguments"])
            self.assertEqual(result["result"], case["expected"])
            self.assertEqual(result["resources"]["live_owners"], 0)
            self.assertEqual(result["resources"]["loans_started"], result["resources"]["loans_ended"])

    def test_actual_native_allocation_refusal_and_cleanup_match_vm(self):
        driver = self.out / "resource_harness.c"
        driver.write_text(native_abi_preamble(self.host) + RESOURCE_HARNESS)
        for label in ("c", "hia"):
            inputs = [self.out / "hia.o"] if label == "hia" else [*SOURCES, "client.c"]
            path = self.out / ("resource_" + label)
            self.command([CLANG, "-std=c11", "-DNDEBUG", "-funsigned-char", "-fno-builtin",
                "-Icompare/platform", "-O3", "-DENTRY=" + ENTRY, driver, *inputs,
                "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", path],
                "resource_build_" + label, cwd=self.project)
            inspect_host_executable(path, self.host)
        for count in PROTOCOL["resource_counts"]:
            args = [count, 0xfedcba9876543210, 0xffffffff, 0xedb88320]
            for refusal in PROTOCOL["allocation_refusal_indices"]:
                reference = execute_program(self.core, ENTRY, args, allocation_fail_at=refusal or None)
                ledger = reference["resources"]
                expected = {"result": reference["result"], "attempts": ledger["allocation_attempts"],
                            "allocations": ledger["allocations"], "frees": ledger["frees"], "live": 0}
                for label in ("c", "hia"):
                    actual = json.loads(self.command([self.out / ("resource_" + label), *args, refusal],
                                                     "resource_execution_" + label))
                    self.assertEqual(actual, expected)
                self.assertEqual(ledger["live_owners"], 0)

    def test_compiled_driver_rejects_wrong_target_and_result_relabeling(self):
        other = dict(self.host, normalized_machine=("aarch64" if self.host["normalized_machine"] == "x86_64"
                                                   else "x86_64"))
        source = self.out / "wrong_driver.c"
        source.write_text(native_driver_source(self.cases, other))
        output = self.out / "wrong_driver.o"
        result = run_bounded([CLANG, "-std=c11", "-c", str(source), "-o", str(output)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wrong native host architecture", result.stderr)
        self.assertFalse(output.exists())
        raw = self.command([self.native["hia"]], "actual_result")
        with self.assertRaisesRegex(ValueError, "ABI probe"):
            read_native_results(raw, self.cases, other)
        rows = [json.loads(line) for line in raw.splitlines()]
        rows[1]["result"] ^= 1
        with self.assertRaisesRegex(ValueError, "functional oracle"):
            read_native_results("\n".join(map(json.dumps, rows)), self.cases, self.host)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            read_native_results("\n".join(raw.splitlines()[:-1]), self.cases, self.host)

    def test_wrong_machine_elf_and_objects_are_not_admitted_as_native_executables(self):
        source = Path(self.native["hia"])
        raw = bytearray(source.read_bytes())
        raw[18:20] = (183 if self.host["elf_machine"] == 62 else 62).to_bytes(2, "little")
        wrong = self.out / "wrong_machine"
        wrong.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "ELF machine/type"):
            inspect_host_executable(wrong, self.host)
        with self.assertRaisesRegex(ValueError, "ELF machine/type"):
            inspect_host_executable(self.out / "hia.o", self.host)


if __name__ == "__main__":
    unittest.main()
