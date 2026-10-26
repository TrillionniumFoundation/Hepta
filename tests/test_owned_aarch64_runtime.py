"""Real finite Owned runtime smoke: native host execution vs ARM64 link only."""
from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from hepta.owned_aarch64_runtime import (
    OwnedAArch64RuntimeRejected, probe_finite_owned_aarch64_runtime,
)
from hepta.llvm_owned_aarch64 import _finite_runtime_abi_allowed
from hepta import owned_aarch64_runtime as runtime


class ReviewedFiniteRuntimeSourceGateTests(unittest.TestCase):
    """Source-byte admission runs without a native compiler or QEMU."""

    def test_reviewed_4259_byte_source_fits_separate_8192_source_budget(self):
        actual = runtime._FIXTURE.read_bytes()
        self.assertGreater(len(actual), 4096)
        self.assertLessEqual(len(actual), runtime._MAX_RUNTIME_SOURCE_BYTES)
        source, content_sha = runtime._read_reviewed_runtime()
        self.assertEqual(source, actual)
        self.assertEqual(content_sha, sha256(source).hexdigest())
        self.assertEqual(content_sha, runtime._REVIEWED_RUNTIME_SHA256)
        # The allocator's HEPTA_CAPACITY remains exactly 4096 bytes.
        self.assertIn(b"#define HEPTA_CAPACITY 4096u", source)

    def test_wrong_or_oversized_runtime_source_fails_closed_before_compilation(self):
        original = runtime._FIXTURE
        with tempfile.TemporaryDirectory(prefix="hepta-p7-runtime-source-") as root:
            path = Path(root) / "runtime.c"
            for name, payload in (
                ("tampered_same_length", original.read_bytes().replace(
                    b"#define HEPTA_CAPACITY 4096u",
                    b"#define HEPTA_CAPACITY 8192u")),
                ("over_limit", original.read_bytes() + b" " * 8192),
                ("unreviewed_marker", b"not a checked runtime"),
            ):
                with self.subTest(name=name):
                    path.write_bytes(payload)
                    with patch.object(runtime, "_FIXTURE", path):
                        with self.assertRaisesRegex(
                                OwnedAArch64RuntimeRejected, "runtime|allocator"):
                            runtime._read_reviewed_runtime()


STANDIN = """\
typedef __SIZE_TYPE__ hs;
typedef __UINT8_TYPE__ u8;
typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
extern void *malloc(hs);
extern void free(void *);
extern void *memset(void *,int,hs);
u64 owned_case(hs size, u8 value, hs index, u32 reject, u32 early) {
   if (size>9223372036854775807ull) return 1001;
   u8 *p = (u8*)malloc(size);
   if (size && !p) return 1001;
   if (reject) { free(p); return 1002; }
   for (hs i=0;i<size;++i) p[i] = value;
   if (size) p[0] = value ^ 90;
   if (early) { free(p);return 2002; }
   if (index>=size) { free(p);return 2003; }
   u64 answer = p[index]+p[index]+size;
   free(p);
   return answer;
}
"""


def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


@unittest.skipUnless(shutil.which("clang") and shutil.which("ld.lld"),
                     "real Clang + lld needed for cross and freestanding host tests")
class FiniteOwnedRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-aarch64-finite-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.clang = shutil.which("clang")
        self.runtime = Path(__file__).resolve().parents[1] / (
            "examples/llvm_owned/finite_aarch64_runtime.c")

    def build(self, target, cpp_text=STANDIN):
        runtime = self.root / ("runtime-" + target + ".o")
        owner = self.root / ("owner-" + target + ".o")
        source = self.root / ("owner-" + target + ".c")
        source.write_text(cpp_text)
        args = [self.clang, "--target=" + target, "-x", "c", "-std=c11",
                "-ffreestanding", "-nostdinc", "-fno-builtin",
                "-fno-stack-protector", "-O2", "-Wall", "-Wextra", "-Werror"]
        for path, obj in ((self.runtime, runtime), (source, owner)):
            result = run([*args, "-c", str(path), "-o", str(obj)])
            self.assertEqual(result.returncode, 0, result.stderr)
        return runtime, owner

    def test_real_native_linux_allocator_exercises_bounded_ownership(self):
        runtime, owner = self.build("x86_64-unknown-linux-gnu")
        linked = self.root / "native.elf"
        result = run([self.clang, "--target=x86_64-unknown-linux-gnu",
                      "-fuse-ld=lld", "-nostdlib", "-static", "-Wl,-z,noexecstack",
                      "-Wl,-e,_start", str(runtime), str(owner), "-o", str(linked)])
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = run([str(linked)])
        self.assertEqual(actual.returncode, 0, actual.stderr)

        # Remove the unused computation too; -Werror must remain enabled.
        wrong = STANDIN.replace(
            "   u64 answer = p[index]+p[index]+size;\n   free(p);\n   return answer;",
            "   free(p);\n   return 0;")
        runtime2, owner2 = self.build("x86_64-unknown-linux-gnu", wrong)
        bad = self.root / "bad.elf"
        self.assertEqual(run([self.clang, "-fuse-ld=lld", "-nostdlib", "-static",
                              "-Wl,-e,_start", str(runtime2), str(owner2),
                              "-o", str(bad)]).returncode, 0)
        self.assertEqual(run([str(bad)]).returncode, 11)

    def test_real_arm64_link_honestly_records_no_execution(self):
        _, owner = self.build("aarch64-unknown-linux-gnu")
        report = probe_finite_owned_aarch64_runtime(
            owner.read_bytes(), ("owned_case",), clang=self.clang)
        self.assertEqual(report["status"], "finite_real_runtime_linked_not_executed")
        self.assertEqual(report["target"], "aarch64-unknown-linux-gnu")
        self.assertGreater(report["linked_bytes"], 512)
        self.assertEqual(report["symbols"]["external_functions"],
                         sorted(("owned_case", "malloc", "free", "abort",
                                 "memcpy", "memmove", "memset", "_start")))
        self.assertTrue(report["real_finite_allocator_linked"])
        self.assertIsNone(report["execution"])
        for field in ("qemu_user_mode_executed", "real_target_device_executed",
                      "general_allocator_qualified", "general_linux_abi_qualified",
                      "whole_language_soundness_proved"):
            self.assertIs(report[field], False)
        # Opt in only when the runner is actually installed. A non-executed
        # test may not be transformed into fake emulation evidence.
        if shutil.which("qemu-aarch64"):
            emulated = probe_finite_owned_aarch64_runtime(
                owner.read_bytes(), ("owned_case",), clang=self.clang,
                qemu_aarch64="qemu-aarch64")
            self.assertEqual(emulated["status"], "finite_qemu_userspace_execution_passed")
            self.assertTrue(emulated["qemu_user_mode_executed"])
            self.assertEqual(emulated["execution"]["returncode"], 0)
            self.assertEqual(emulated["execution"]["linked_sha256"], emulated["linked_sha256"])
            self.assertEqual(emulated["execution"]["runner_sha256"], emulated["runner_sha256"])

    @unittest.skipUnless(shutil.which("qemu-aarch64"), "actual QEMU AArch64 runner required")
    def test_failed_actual_emulation_retains_the_bound_process_record(self):
        _, owner = self.build("aarch64-unknown-linux-gnu", STANDIN.replace("return answer;", "return answer+1;"))
        with self.assertRaises(OwnedAArch64RuntimeRejected) as caught:
            probe_finite_owned_aarch64_runtime(
                owner.read_bytes(), ("owned_case",), clang=self.clang, qemu_aarch64="qemu-aarch64")
        record = caught.exception.execution
        self.assertIsInstance(record, dict)
        self.assertEqual(record["returncode"], 11)
        self.assertEqual(record["runner_sha256"], sha256(Path(shutil.which("qemu-aarch64")).read_bytes()).hexdigest())
        self.assertEqual(record["stdout_sha256"], sha256(record["stdout"].encode()).hexdigest())

    def test_wrong_export_and_unavailable_runner_reject(self):
        _, owner = self.build("aarch64-unknown-linux-gnu")
        with self.assertRaisesRegex(OwnedAArch64RuntimeRejected, "exact|one checked"):
            probe_finite_owned_aarch64_runtime(owner.read_bytes(), ("different",),
                                               clang=self.clang)
        with self.assertRaisesRegex(OwnedAArch64RuntimeRejected, "unavailable"):
            probe_finite_owned_aarch64_runtime(
                owner.read_bytes(), ("owned_case",), clang=self.clang,
                qemu_aarch64="/nonexistent/qemu-aarch64")

    def test_unreviewed_foreign_import_rejected_before_linking(self):
        foreign = STANDIN.replace(
            "extern void free(void *);", "extern void free(void *); extern int getpid(void);")
        foreign = foreign.replace(
            "   if (size>9223372036854775807ull)",
            "   if (getpid() == -777) return 44;\n   if (size>9223372036854775807ull)")
        _, owner = self.build("aarch64-unknown-linux-gnu", foreign)
        with self.assertRaisesRegex(ValueError, "IMPORT|import"):
            probe_finite_owned_aarch64_runtime(
                owner.read_bytes(), ("owned_case",), clang=self.clang)


class SourceBoundRuntimeProfileTests(unittest.TestCase):
    def test_finite_runtime_requires_exact_checked_c_signature(self):
        def param(name, mode="value"):
            return SimpleNamespace(mode=mode, type=SimpleNamespace(
                name=name, args=(), lifetimes=(), length=None))
        fn = SimpleNamespace(
            name="owned_case", export_c=True, extern_c=False, body=[object()],
            type_params=(), lifetime_params=(), return_mode="value",
            return_type=SimpleNamespace(name="u64", args=()),
            params=[param(x) for x in ("usize", "u8", "usize", "u32", "u32")])
        program = SimpleNamespace(functions=[fn])
        ir = SimpleNamespace(functions=("owned_case",))
        self.assertTrue(_finite_runtime_abi_allowed(program, ir))
        fn.params[1].type.name = "u32"
        self.assertFalse(_finite_runtime_abi_allowed(program, ir))
        fn.params[1].type.name = "u8"
        fn.params[0].mode = "take"
        self.assertFalse(_finite_runtime_abi_allowed(program, ir))
        fn.params[0].mode = "value"
        fn.return_type.name = "i64"
        self.assertFalse(_finite_runtime_abi_allowed(program, ir))
        fn.return_type.name = "u64"
        ir.functions = ("owned_case", "extra")
        self.assertFalse(_finite_runtime_abi_allowed(program, ir))


if __name__ == "__main__":
    unittest.main()
