"""Independent mathematical cells and adversarial signed-driver observations."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import benchmark_hia_verified_signed as signed


class SignedProtocolTests(unittest.TestCase):
    def test_fixed_complete_inventory_and_core_reference(self):
        from hepta.hia_program import verify_program
        self.assertEqual(json.loads(signed.PROTOCOL_PATH.read_bytes()), signed.fixed_protocol())
        cells = signed.case_specs()
        self.assertEqual(len(cells), 33)
        self.assertEqual(len({cell["id"] for cell in cells}), 33)
        traps = 0
        for index, cell in enumerate(cells):
            with self.subTest(cell=cell["id"]):
                matrix = signed.input_matrix(cell, index)
                self.assertEqual(matrix, signed.input_matrix(cell, index))
                self.assertEqual(len(matrix["valid"]), 64)
                self.assertEqual(len({(r["a"], r["b"]) for r in matrix["valid"]}), 64)
                self.assertGreaterEqual(sum(r["origin"] == "seeded" for r in matrix["valid"]), 48)
                document = signed.core_document(cell)
                self.assertEqual(document["functions"][0]["params"][0]["type"], cell["source"])
                self.assertEqual(len(document["functions"][0]["blocks"][0]["ops"]),
                                 0 if cell["operation"] == "identity" else 1)
                signed.check_core_reference(verify_program(document), matrix)
                traps += len(matrix["traps"])
        self.assertEqual(traps, 78)

    def test_math_handles_signed_division_remainder_shifts_and_casts(self):
        cells = {c["id"]: c for c in signed.case_specs()}
        vectors = [
            ("i64_div_checked", -7, 3, -2, None),
            ("i64_rem_checked", -7, 3, -1, None),
            ("i64_div_checked", -(1 << 63), -1, None, "overflow"),
            ("i64_rem_checked", -(1 << 63), -1, None, "overflow"),
            ("i64_div_checked", 4, 0, None, "division_by_zero"),
            ("i64_shl_checked", -1, 63, -(1 << 63), None),
            ("i64_shr_checked", -7, 1, -4, None),
            ("i64_shr_checked", 7, 1 << 32, None, "overflow"),
            ("i64_shr_checked", 7, -1, None, "overflow"),
            ("i8_identity", 0x123456789abcde80, 0, -128, None),
            ("i8_add_wrap", 0x123456789abcde7f, 1, -128, None),
            ("i8_add_checked", 0x123456789abcde7f, 1, None, "overflow"),
            ("i64_to_u64_wrap", -1, 0, signed.MASK, None),
            ("i64_to_u64_checked", -1, 0, None, "overflow"),
            ("u64_to_i32_wrap", signed.MASK, 0, -1, None),
            ("u64_to_i32_checked", 1 << 31, 0, None, "overflow"),
        ]
        for name, a, b, result, error in vectors:
            with self.subTest(cell=name, a=a, b=b):
                self.assertEqual(signed.independent_result(cells[name], a & signed.MASK, b & signed.MASK),
                                 (None if result is None else result & signed.MASK, error))

    def timing_fixture(self):
        cell = signed.case_specs()[0]
        matrix = signed.input_matrix(cell, 0)
        valid, traps = signed.encoded_inputs(matrix)
        binary = {"sha256": "a" * 64, "bytes": 1234}
        binding = {"kind": "binding", "artifact_sha256": binary["sha256"], "artifact_bytes": binary["bytes"],
                   "input_sha256": sha256(valid).hexdigest(), "trap_sha256": sha256(traps).hexdigest(),
                   "symbol": "kernel", "sealed": True, "entry_owner": "sealed_image",
                   "image_base": 0x700000000000, "symbol_address": 0x700000001000,
                   "symbol_offset": 4096, "cpu": 2, "affinity_count": 1}
        checksum = (signed.CHECKSUM_SEED + sum(r["expected"] for r in matrix["valid"]) *
                    (signed.ITERATIONS // signed.INPUT_COUNT)) & signed.MASK
        rows = [binding] + [{"kind": "sample", "batch": batch, "warmup": batch < 0,
                            "elapsed_ns": (batch + 10) * 1000000, "calls": signed.ITERATIONS,
                            "checksum": checksum, "cpu_before": 2, "cpu_after": 2}
                           for batch in range(-3, 21)]
        return matrix, binary, rows

    def parse_timing(self, rows, matrix, binary):
        return signed.parse_driver("\n".join(json.dumps(r) for r in rows), matrix=matrix,
                                   expected_image=binary, symbol="kernel", cpu=2, measuring=True)

    def test_all_samples_are_used_and_warmups_retained(self):
        matrix, binary, rows = self.timing_fixture()
        result = self.parse_timing(rows, matrix, binary)
        self.assertEqual(len(result["samples"]), 24)
        self.assertEqual(result["median_ns_per_call"], 20000000 / signed.ITERATIONS)
        self.assertEqual(result["min_ns_per_call"], 10000000 / signed.ITERATIONS)
        self.assertEqual(result["max_ns_per_call"], 30000000 / signed.ITERATIONS)

    def test_edited_bindings_samples_checksums_and_cpu_refuse(self):
        matrix, binary, original = self.timing_fixture()
        mutations = [
            lambda r: r[0].update(artifact_sha256="b" * 64),
            lambda r: r[0].update(input_sha256="b" * 64),
            lambda r: r[0].update(trap_sha256="b" * 64),
            lambda r: r[0].update(sealed=False),
            lambda r: r[0].update(entry_owner="dependency"),
            lambda r: r[0].update(image_base=0),
            lambda r: r[0].update(symbol_address=0x700000002000),
            lambda r: r[0].update(affinity_count=2),
            lambda r: r.pop(),
            lambda r: r.append(deepcopy(r[-1])),
            lambda r: r[1].update(batch=-2),
            lambda r: r[1].update(warmup=False),
            lambda r: r[1].update(elapsed_ns=0),
            lambda r: r[1].update(elapsed_ns=True),
            lambda r: r[1].update(calls=1),
            lambda r: r[1].update(checksum=0),
            lambda r: r[1].update(cpu_after=3),
            lambda r: r[1].update(ns_per_call=1.0),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                rows = deepcopy(original)
                mutation(rows)
                with self.assertRaises(ValueError):
                    self.parse_timing(rows, matrix, binary)


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("gcc") is not None and hasattr(os, "sched_getaffinity"))


@unittest.skipUnless(AVAILABLE, "Linux x86-64 and GCC are required")
class SignedDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-signed-driver-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.driver = cls.root / "driver"
        subprocess.run(["gcc", *signed.fixed_protocol()["c_flags"], str(signed.ASSETS / "signed_driver.c"),
                        "-ldl", "-o", str(cls.driver)], check=True, capture_output=True, timeout=30)
        source = cls.root / "fixture.c"
        source.write_text("#include <stdint.h>\n#include <stdlib.h>\n#include <signal.h>\n"
                          "uint64_t kernel(uint64_t a,uint64_t b){return a+b;}\n"
                          "uint64_t checked(uint64_t a,uint64_t b){(void)b;if(a>>63)abort();return a;}\n"
                          "uint64_t wrong_trap(uint64_t a,uint64_t b){(void)b;if(a>>63)raise(SIGILL);return a;}\n"
                          "uint64_t no_trap(uint64_t a,uint64_t b){(void)b;return a;}\n")
        cls.library = cls.root / "fixture.so"
        subprocess.run(["gcc", "-O2", "-fPIC", "-shared", str(source), "-o", str(cls.library)],
                       check=True, capture_output=True, timeout=30)
        cls.identity = signed.file_identity(cls.library)

    def driver_call(self, name, symbol, *, digest=None, truncate=False, measuring=False):
        index, cell = next((i, c) for i, c in enumerate(signed.case_specs()) if c["id"] == name)
        matrix = signed.input_matrix(cell, index)
        valid, traps = signed.encoded_inputs(matrix)
        directory = self.root / self._testMethodName
        directory.mkdir(exist_ok=True)
        (directory / "inputs").write_bytes(valid[:-1] if truncate else valid)
        (directory / "traps").write_bytes(traps)
        affinity = os.sched_getaffinity(0)
        cpu = min(affinity)
        try:
            os.sched_setaffinity(0, {cpu})
            args = [self.driver, "measure" if measuring else "functional", self.library, symbol,
                    digest or self.identity["sha256"], directory / "inputs", directory / "traps"]
            if measuring:
                args += [str(signed.ITERATIONS), str(signed.SAMPLES)]
            result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=20)
        finally:
            os.sched_setaffinity(0, affinity)
        return result, matrix, cpu

    def test_sealed_image_and_all_legal_observations(self):
        result, matrix, cpu = self.driver_call("i64_add_wrap", "kernel")
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = signed.parse_driver(result.stdout, matrix=matrix, expected_image=self.identity,
                                     symbol="kernel", cpu=cpu, measuring=False)
        self.assertEqual((parsed["inputs"], parsed["traps"]), (64, 0))

    def test_checked_invalid_values_abort_only_in_children(self):
        result, matrix, cpu = self.driver_call("i64_to_u64_checked", "checked")
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = signed.parse_driver(result.stdout, matrix=matrix, expected_image=self.identity,
                                     symbol="checked", cpu=cpu, measuring=False)
        self.assertEqual(parsed["traps"], 2)

    def test_dependency_symbol_cannot_stand_in_for_sealed_image_entry(self):
        # dlopen's handle search includes DT_NEEDED dependencies. The admitted
        # outer image has no kernel; a correct result from its dependency must
        # not be attributed to the outer sealed bytes.
        source = self.root / "dependency_shell.c"
        outer = self.root / "dependency_shell.so"
        source.write_text("int shell_marker = 1;\n")
        subprocess.run(["gcc", "-O2", "-fPIC", "-shared", str(source),
                        "-Wl,--no-as-needed", str(self.library), "-o", str(outer)],
                       check=True, capture_output=True, timeout=30)
        with patch.object(self, "library", outer), patch.object(self, "identity", signed.file_identity(outer)):
            result, _, _ = self.driver_call("i64_add_wrap", "kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("sealed image", result.stderr)

    def test_wrong_image_digest_rejects_before_any_binding_or_execution(self):
        result, _, _ = self.driver_call("i64_add_wrap", "kernel", digest="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("before load", result.stderr)

    def test_truncated_input_matrix_rejects(self):
        result, _, _ = self.driver_call("i64_add_wrap", "kernel", truncate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_incorrect_native_results_reject(self):
        result, _, _ = self.driver_call("i64_sub_wrap", "kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong word", result.stderr)

    def test_return_and_wrong_signal_cannot_pass_abort_controls(self):
        for symbol in ("no_trap", "wrong_trap"):
            with self.subTest(symbol=symbol):
                result, _, _ = self.driver_call("i64_to_u64_checked", symbol)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("did not abort", result.stderr)

    def test_native_timing_path_retains_exact_fixed_batch_inventory(self):
        # This is a driver integrity smoke with a C fixture, not a HIA/Rust
        # performance campaign or a reported speed comparison.
        result, matrix, cpu = self.driver_call("i64_add_wrap", "kernel", measuring=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = signed.parse_driver(result.stdout, matrix=matrix, expected_image=self.identity,
                                     symbol="kernel", cpu=cpu, measuring=True)
        self.assertEqual([row["batch"] for row in parsed["samples"]], list(range(-3, 21)))


if __name__ == "__main__":
    unittest.main()
