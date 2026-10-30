"""Real GCC host-interface execution and adversarial qualification evidence."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_linux_interfaces import (CASE_ORDER, FIXTURE, LinuxInterfaceRejected,
                                        qualify_linux_interfaces, validate_observations)


@unittest.skipUnless(platform.system() == "Linux" and
                     platform.machine().lower() in {"x86_64", "amd64", "aarch64", "arm64"} and
                     shutil.which("gcc"), "real native Linux LP64 GNU C host required")
class LinuxInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.report = qualify_linux_interfaces(cls.directory / "reference", mode="host-reference")
        if not cls.report["ok"]:
            raise AssertionError(cls.report.get("error", cls.report))
        cls.text = (cls.directory / "reference/RAW.jsonl").read_text()
        cls.rows = [json.loads(line) for line in cls.text.splitlines()]

    def test_actual_kernel_workers_and_failure_recovery_are_observed(self):
        report = self.report
        self.assertTrue(report["claims"]["host_interface_qualified"])
        self.assertFalse(report["claims"]["hepta_native_abi_qualified"])
        self.assertFalse(report["claims"]["hardware_device_qualified"])
        self.assertFalse(report["claims"]["dma_mmio_interrupt_qualified"])
        self.assertFalse(report["claims"]["cross_target_execution_qualified"])
        self.assertTrue(report["execution"]["sealed_snapshot"])
        self.assertEqual(report["status"], "host_reference_qualified_hepta_pending")
        self.assertEqual(len(report["observations"]["cases"]), 21)
        self.assertEqual(tuple(row["case"] for row in self.rows[2:]), CASE_ORDER)
        self.assertEqual([row["name"] for row in report["link_inputs"]], ["host_harness.c", "reference.c"])
        self.assertTrue(all(row["fd_before"] == row["fd_after"] and
                            row["threads_before"] == row["threads_after"] == 1 for row in self.rows[2:]))
        normal = self.rows[2]
        self.assertEqual((normal["worker_mask"], normal["peak_jobs"], normal["allocations"], normal["frees"]),
                         (7, 3, 14, 14))

    def test_modified_callback_resources_concurrency_and_failure_evidence_are_rejected(self):
        for attack in ("result", "live_bytes", "missing_case", "case_order", "false_count",
                       "worker", "peak", "allocation_failure", "cancel", "quiescence"):
            with self.subTest(attack=attack):
                rows = deepcopy(self.rows)
                normal = rows[2]
                if attack == "result": normal["jobs"][0]["result"] ^= 1
                elif attack == "live_bytes": normal["live_bytes"] = 1
                elif attack == "missing_case": rows.pop()
                elif attack == "case_order": rows[2], rows[3] = rows[3], rows[2]
                elif attack == "false_count": normal["completed"] -= 1
                elif attack == "worker": normal["worker_mask"] = 1
                elif attack == "peak": normal["peak_bytes"] = 0
                elif attack == "allocation_failure":
                    next(row for row in rows[2:] if row["case"] == "allocation_fail_1")["allocation_failures"] = 0
                elif attack == "quiescence": normal["thread_quiescence_polls"] = 1001
                else:
                    next(row for row in rows[2:] if row["case"] == "cooperative_cancel")["completed"] = 16
                with self.assertRaises(LinuxInterfaceRejected):
                    validate_observations("\n".join(json.dumps(row) for row in rows), self.report["host"])

    def test_kernel_errors_cannot_be_replaced_by_success_claims(self):
        for field in ("empty_errno", "invalid_errno", "full_errno"):
            with self.subTest(field=field):
                rows = deepcopy(self.rows)
                rows[1][field] = 0
                with self.assertRaises(LinuxInterfaceRejected):
                    validate_observations("\n".join(json.dumps(row) for row in rows), self.report["host"])

    def test_duplicate_fields_and_boolean_counts_fail_closed(self):
        lines = self.text.splitlines()
        lines[0] = lines[0][:-1] + ',"workers":3}'
        with self.assertRaisesRegex(LinuxInterfaceRejected, "duplicate"):
            validate_observations("\n".join(lines), self.report["host"])
        rows = deepcopy(self.rows)
        rows[2]["threads_before"] = True
        with self.assertRaisesRegex(LinuxInterfaceRejected, "non-integer"):
            validate_observations("\n".join(json.dumps(row) for row in rows), self.report["host"])

    def test_missing_hepta_toolchain_never_falls_back_to_reference_code(self):
        output = self.directory / "missing-clang"
        report = qualify_linux_interfaces(output, mode="hepta", clang="no-such-hepta-clang-toolchain")
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["claims"]["hepta_native_abi_qualified"])
        self.assertFalse((output / "host-interfaces").exists())
        self.assertFalse(any(command["label"] == "link" for command in report["commands"]))

    def test_requested_other_architecture_is_not_cross_execution_qualification(self):
        machine = "aarch64" if self.report["host"]["normalized_machine"] == "x86_64" else "x86_64"
        output = self.directory / "foreign-cohort"
        with self.assertRaisesRegex(LinuxInterfaceRejected, "executing host"):
            qualify_linux_interfaces(output, expected_machine=machine)
        self.assertFalse(output.exists())

    def test_real_hepta_interpreter_has_the_callback_failure_contract(self):
        from hepta.hia_program_source import lower_source
        from hepta.hia_program_runtime import execute_program
        core = lower_source((FIXTURE / "worker.hepta").read_text())
        for count in (0, 1, 7, 64):
            for seed in (0, 2**32 - 1):
                for fail_at in (None, 1):
                    record = execute_program(core, "worker_checksum", [count, seed], allocation_fail_at=fail_at)
                    expected = 1001 if count and fail_at else sum((index + seed) & 255 for index in range(count))
                    self.assertEqual(record["result"], expected)
                    self.assertEqual(record["resources"]["live_owners"], 0)

    def test_evidence_output_is_no_replace(self):
        with self.assertRaisesRegex(LinuxInterfaceRejected, "new evidence"):
            qualify_linux_interfaces(self.directory / "reference")

    def test_implementation_mutation_denies_even_successful_host_execution(self):
        from hepta import hia_linux_interfaces as interfaces
        identity = interfaces._implementation_sources()
        changed = dict(identity)
        changed["hepta/hia_semantic_kernel.py"] = "0" * 64
        with patch.object(interfaces, "_implementation_sources", side_effect=[identity, changed]):
            report = qualify_linux_interfaces(self.directory / "source-changed")
        self.assertEqual(report["execution"]["returncode"], 0)
        self.assertEqual(len(report["observations"]["cases"]), 21)
        self.assertFalse(report["ok"])
        self.assertFalse(report["claims"]["host_interface_qualified"])
        self.assertFalse(report["claims"]["hepta_native_abi_qualified"])
        self.assertIn("implementation source set changed", report["error"])


if __name__ == "__main__":
    unittest.main()
