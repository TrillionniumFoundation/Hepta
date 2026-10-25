"""Compiler-free formal receipt consistency tests, not Lean qualification.

All receipts below are deliberately synthetic, in-memory unit controls. A
consistent forged receipt remains constructible: hashes and reported output do
not authenticate execution. Never export these dictionaries as proof evidence.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from tools import release_check, verify_formal
from tools.release_check import require_qualification
from tools.verify_formal import MUTATION_FAILURE, negative_sources

ROOT = Path(__file__).resolve().parents[1]


def synthetic_consistent_receipt():
    """Return a schema-valid control, NOT the result of a Lean invocation."""
    source = (ROOT / "formal/HeptaCore.lean").read_bytes()
    names = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)", source.decode())
    kernel_log = "SYNTHETIC UNIT CONTROL; NOT EXECUTED\n" + "\n".join(
        f"'Hepta.{name}' depends on axioms: [propext]" for name in names)
    checks = "\n".join("#print axioms Hepta." + name for name in names)
    negative = []
    for name, broken in negative_sources(source.decode()).items():
        log = ("error: SYNTHETIC UNIT CONTROL; NOT EXECUTED\n"
               f"'Hepta.{MUTATION_FAILURE[name]}' depends on axioms: [propext, sorryAx]\n")
        negative.append({"mutation": name, "status": "rejected_as_expected", "exit_code": 1,
                         "source_sha256": hashlib.sha256(broken.encode()).hexdigest(),
                         "log": log, "log_sha256": hashlib.sha256(log.encode()).hexdigest()})
    return {
        "schema": "hepta.formal.v2",
        "status": "passed",
        "source": "formal/HeptaCore.lean",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "lean": "Lean (version 4.19.0, SYNTHETIC UNIT CONTROL; NOT EXECUTED)",
        # Copying a public pin is not evidence that this binary was executed.
        "lean_binary_sha256": json.loads((ROOT / "formal/toolchain-lock.json").read_text())["lean_binary_sha256"],
        "theorems": {name: ["propext"] for name in names},
        "version_exit_code": 0, "kernel_exit_code": 0,
        "checked_source_sha256": hashlib.sha256((source.decode() + "\n" + checks + "\n").encode()).hexdigest(),
        "kernel_output": kernel_log, "kernel_output_sha256": hashlib.sha256(kernel_log.encode()).hexdigest(),
        "claims": {"abstract_core_theorems_checked": True,
                   "production_compiler_refinement_proved": False,
                   "whole_language_soundness_proved": False,
                   "ffi_or_hardware_proved": False,
                   "termination_or_bounded_cancellation_proved": False},
        "negative_mutations": negative,
    }


class FormalReceiptTests(unittest.TestCase):
    def setUp(self):
        # Any accidental attempt to execute Lean/native commands fails the test.
        self.commands = patch("subprocess.run", side_effect=AssertionError("receipt tests must not execute commands"))
        self.commands.start()
        self.addCleanup(self.commands.stop)
        self.report = synthetic_consistent_receipt()

    def reject(self):
        with self.assertRaises(ValueError):
            require_qualification("formal_core", self.report)

    def rehash_kernel(self):
        self.report["kernel_output_sha256"] = hashlib.sha256(self.report["kernel_output"].encode()).hexdigest()

    def rehash_negative(self):
        case = self.report["negative_mutations"][0]
        case["log_sha256"] = hashlib.sha256(case["log"].encode()).hexdigest()

    def test_consistent_synthetic_metadata_is_not_execution_evidence(self):
        # Acceptance establishes ONLY internal metadata consistency. This
        # control intentionally has no real Lean binary, commands or proof run.
        require_qualification("formal_core", self.report)

    def test_count_only_forgery_rejected(self):
        self.report = {"status": "passed", "theorems": {f"fake_{i}": [] for i in range(11)},
                       "negative_mutations": [{"status": "not_run"}] * 2}
        self.reject()

    def test_unexecuted_status_rejected(self):
        self.report["status"] = "not_run"
        self.reject()

    def test_wrong_schema_rejected(self):
        self.report["schema"] = "hepta.formal.v0"
        self.reject()

    def test_unexecuted_negative_rejected(self):
        self.report["negative_mutations"][0]["status"] = "not_run"
        self.reject()

    def test_failed_to_reject_negative_rejected(self):
        self.report["negative_mutations"][0]["status"] = "accepted"
        self.reject()

    def test_duplicate_negative_rejected(self):
        self.report["negative_mutations"][1] = deepcopy(self.report["negative_mutations"][0])
        self.reject()

    def test_wrong_negative_name_rejected(self):
        self.report["negative_mutations"][1]["mutation"] = "unrelated_mutation"
        self.reject()

    def test_missing_negative_rejected(self):
        self.report["negative_mutations"].pop()
        self.reject()

    def test_unapplied_mutation_rejected(self):
        self.report["negative_mutations"][0]["source_sha256"] = self.report["source_sha256"]
        self.reject()

    def test_repeated_mutated_source_rejected(self):
        self.report["negative_mutations"][1]["source_sha256"] = self.report["negative_mutations"][0]["source_sha256"]
        self.reject()

    def test_bad_negative_hashes_rejected(self):
        for field in ("source_sha256", "log_sha256"):
            for invalid in (None, "", "x" * 64, "0" * 63, [], True):
                with self.subTest(field=field, invalid=invalid):
                    self.report = synthetic_consistent_receipt()
                    self.report["negative_mutations"][0][field] = invalid
                    self.reject()

    def test_malformed_negative_rejected(self):
        for invalid in (None, [], "rejected_as_expected", {"mutation": []}):
            with self.subTest(invalid=invalid):
                self.report = synthetic_consistent_receipt()
                self.report["negative_mutations"][0] = invalid
                self.reject()

    def test_wrong_theorem_name_rejected(self):
        first = next(iter(self.report["theorems"]))
        self.report["theorems"]["unrelated_theorem"] = self.report["theorems"].pop(first)
        self.reject()

    def test_count_preserving_duplicate_theorem_list_rejected(self):
        self.report["theorems"] = ["resource_preservation"] * 11
        self.reject()

    def test_unapproved_axioms_rejected(self):
        first = next(iter(self.report["theorems"]))
        for invalid in (["sorryAx"], ["untrusted"], [["propext"]], "propext", None, ["propext", "propext"]):
            with self.subTest(invalid=invalid):
                self.report["theorems"][first] = invalid
                self.reject()

    def test_wrong_formal_source_hash_rejected(self):
        self.report["source_sha256"] = "0" * 64
        self.reject()

    def test_wrong_formal_source_path_rejected(self):
        self.report["source"] = "formal/HeptaMemory.lean"
        self.reject()

    def test_wrong_lean_version_rejected(self):
        self.report["lean"] = "Lean (version 4.18.0, synthetic)"
        self.reject()

    def test_missing_binary_identity_rejected(self):
        self.report.pop("lean_binary_sha256")
        self.reject()

    def test_wrong_binary_identity_rejected(self):
        self.report["lean_binary_sha256"] = "0" * 64
        self.reject()

    def test_missing_kernel_output_rejected(self):
        self.report.pop("kernel_output")
        self.reject()

    def test_truncated_kernel_theorem_inventory_rejected(self):
        self.report["kernel_output"] = self.report["kernel_output"].rsplit("\n", 1)[0]
        self.rehash_kernel()
        self.reject()

    def test_kernel_dependency_disagreement_rejected(self):
        self.report["kernel_output"] = self.report["kernel_output"].replace("[propext]", "[Quot.sound]", 1)
        self.rehash_kernel()
        self.reject()

    def test_conflicting_duplicate_kernel_output_rejected(self):
        first = next(iter(self.report["theorems"]))
        self.report["kernel_output"] += f"\n'Hepta.{first}' depends on axioms: [Quot.sound]"
        self.rehash_kernel()
        self.reject()

    def test_matching_duplicate_kernel_output_accepted(self):
        # HeptaCore already prints four dependencies; verify_formal appends all
        # eleven. Consistent duplicate lines are therefore valid producer output.
        first = next(iter(self.report["theorems"]))
        self.report["kernel_output"] += f"\n'Hepta.{first}' depends on axioms: [propext]"
        self.rehash_kernel()
        require_qualification("formal_core", self.report)

    def test_sorry_in_kernel_output_rejected(self):
        self.report["kernel_output"] += "\nsorryAx"
        self.rehash_kernel()
        self.reject()

    def test_inflated_or_mistyped_claims_rejected(self):
        for claim in self.report["claims"]:
            for invalid in (not self.report["claims"][claim], int(self.report["claims"][claim])):
                with self.subTest(claim=claim, invalid=invalid):
                    report = deepcopy(self.report)
                    report["claims"][claim] = invalid
                    with self.assertRaises(ValueError):
                        require_qualification("formal_core", report)

    def test_missing_or_extra_claim_rejected(self):
        self.report["claims"].pop("whole_language_soundness_proved")
        self.reject()
        self.report = synthetic_consistent_receipt()
        self.report["claims"]["general_soundness_proved"] = True
        self.reject()

    def test_malformed_top_level_rejected(self):
        for invalid in (None, [], "passed", 11):
            with self.subTest(invalid=invalid):
                self.report = invalid
                self.reject()

    def test_v1_receipt_is_no_longer_accepted(self):
        self.report["schema"] = "hepta.formal.v1"
        self.reject()

    def test_missing_positive_execution_fields_rejected(self):
        for field in ("version_exit_code", "kernel_exit_code", "checked_source_sha256", "kernel_output_sha256"):
            with self.subTest(field=field):
                self.report = synthetic_consistent_receipt()
                self.report.pop(field)
                self.reject()

    def test_invalid_positive_exits_rejected(self):
        for field in ("version_exit_code", "kernel_exit_code"):
            for value in (True, False, 1, -9, "0", None):
                with self.subTest(field=field, value=value):
                    self.report = synthetic_consistent_receipt()
                    self.report[field] = value
                    self.reject()

    def test_wrong_checked_source_hash_rejected(self):
        self.report["checked_source_sha256"] = self.report["source_sha256"]
        self.reject()

    def test_wrong_kernel_output_hash_rejected(self):
        self.report["kernel_output_sha256"] = "0" * 64
        self.reject()

    def test_positive_error_diagnostic_rejected(self):
        self.report["kernel_output"] += "\nerror: synthetic loader error\n"
        self.rehash_kernel()
        self.reject()

    def test_arbitrary_well_formed_negative_source_hash_rejected(self):
        self.report["negative_mutations"][0]["source_sha256"] = "1" * 64
        self.reject()

    def test_negative_source_hashes_cannot_be_swapped(self):
        a, b = self.report["negative_mutations"]
        a["source_sha256"], b["source_sha256"] = b["source_sha256"], a["source_sha256"]
        self.reject()

    def test_negative_log_must_be_retained(self):
        self.report["negative_mutations"][0].pop("log")
        self.reject()

    def test_negative_log_hash_must_match_content(self):
        self.report["negative_mutations"][0]["log_sha256"] = "2" * 64
        self.reject()

    def test_negative_exit_must_be_positive_nonboolean_integer(self):
        for value in (0, -9, True, False, "1", 1.0, None):
            with self.subTest(value=value):
                self.report = synthetic_consistent_receipt()
                self.report["negative_mutations"][0]["exit_code"] = value
                self.reject()

    def test_negative_missing_exit_rejected(self):
        self.report["negative_mutations"][0].pop("exit_code")
        self.reject()

    def test_generic_infrastructure_failure_is_not_proof_rejection(self):
        self.report["negative_mutations"][0]["log"] = "error: cannot load shared library; SYNTHETIC\n"
        self.rehash_negative()
        self.reject()

    def test_negative_must_contain_error_diagnostic(self):
        case = self.report["negative_mutations"][0]
        case["log"] = case["log"].replace("error:", "warning:")
        self.rehash_negative()
        self.reject()

    def test_wrong_theorem_failure_rejected(self):
        case = self.report["negative_mutations"][0]
        case["log"] = case["log"].replace("Hepta.resource_preservation", "Hepta.budget_preservation")
        self.rehash_negative()
        self.reject()

    def test_target_without_failed_proof_dependency_rejected(self):
        case = self.report["negative_mutations"][0]
        case["log"] = case["log"].replace(", sorryAx", "")
        self.rehash_negative()
        self.reject()

    def test_negative_unapproved_or_duplicate_dependencies_rejected(self):
        for replacement in ("[propext, sorryAx, untrusted]", "[propext, sorryAx, sorryAx]"):
            with self.subTest(replacement=replacement):
                self.report = synthetic_consistent_receipt()
                case = self.report["negative_mutations"][0]
                case["log"] = case["log"].replace("[propext, sorryAx]", replacement)
                self.rehash_negative()
                self.reject()

    def test_negative_conflicting_target_reports_rejected(self):
        self.report["negative_mutations"][0]["log"] += "'Hepta.resource_preservation' depends on axioms: [sorryAx]\n"
        self.rehash_negative()
        self.reject()

    def test_negative_sources_match_independent_frozen_hashes(self):
        # Independently retained old-source variant identities, not generated by
        # the function under test. This is text identity, never Lean execution.
        expected = {"release_while_borrowed": "bc654b94e6787809b717ad9e232bbbd92d8fe08a8d65725078517f2af5d996c4",
                    "unbounded_task_admission": "38ea1bd19d04928db1f21956323ae2b307ede2c978e683ea21519e5231a0700d"}
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        observed = {name: hashlib.sha256(broken.encode()).hexdigest() for name, broken in negative_sources(source).items()}
        self.assertEqual(observed, expected)

    def test_missing_or_ambiguous_mutation_site_rejected(self):
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        for changed in (source.replace("s.readers = 0", "s.readers = 1"), source + source):
            with self.subTest(case="missing" if len(changed) < len(source) * 2 else "ambiguous"):
                with self.assertRaises(RuntimeError):
                    negative_sources(changed)

    def test_both_expected_failure_targets_are_already_printed(self):
        source = (ROOT / "formal/HeptaCore.lean").read_text()
        for target in MUTATION_FAILURE.values():
            self.assertIn("#print axioms " + target + "\n", source)

    def test_known_lean419_failures_with_target_sorry_are_rejected(self):
        # Independently transcribed from pinned v4.19.0 primary-source strings;
        # retain the intended target + error + exact log hash in every case.
        diagnostics = (
            "(deterministic) timeout, maximum number of heartbeats (200000) has been reached",
            "maximum recursion depth has been reached",
            "(kernel) deterministic timeout",
            "(kernel) excessive memory consumption detected",
            "excessive memory consumption detected at 'kernel'",
            "deep recursion was detected at 'elaborator'",
            "(kernel) deep recursion detected",
            "(kernel) interrupted",
            "resource exhausted (error code: 12)",
            "PANIC at Lean.Elab:1:1: synthetic runtime failure",
        )
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.report = synthetic_consistent_receipt()
                self.report["negative_mutations"][0]["log"] += "error: " + diagnostic + "\n"
                self.rehash_negative()
                self.reject()

    def test_positive_panic_cannot_hide_behind_successful_dependencies(self):
        self.report["kernel_output"] += "\nPANIC at Lean.Elab:1:1: synthetic runtime failure\n"
        self.rehash_kernel()
        self.reject()

    def test_resource_theorem_name_is_not_a_failure_marker(self):
        self.report["negative_mutations"][0]["log"] += "resource_preservation resourceStep Resource.Valid\n"
        self.rehash_negative()
        require_qualification("formal_core", self.report)

    def producer_fixture(self, directory):
        # This file is intentionally NOT executable. Calls are always mocked,
        # and the output Path is a mock: no successful proof artifact is saved.
        root = Path(directory)
        (root / "formal").mkdir()
        (root / "formal/HeptaCore.lean").write_bytes((ROOT / "formal/HeptaCore.lean").read_bytes())
        binary = root / "not-an-executable-fixture"
        binary.write_bytes(b"SYNTHETIC MOCK ONLY; never executed")
        pin = hashlib.sha256(binary.read_bytes()).hexdigest()
        (root / "formal/toolchain-lock.json").write_text(json.dumps({"lean_binary_sha256": pin}))
        controls = synthetic_consistent_receipt()
        responses = [SimpleNamespace(returncode=0, stdout=controls["lean"], stderr=""),
                     SimpleNamespace(returncode=0, stdout=controls["kernel_output"], stderr="")]
        responses += [SimpleNamespace(returncode=case["exit_code"], stdout=case["log"], stderr="")
                      for case in controls["negative_mutations"]]
        return root, binary, responses

    def test_mocked_producer_v2_round_trip_without_saving_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-formal-schema-") as td:
            root, binary, responses = self.producer_fixture(td)
            output = MagicMock(spec=Path)
            with patch.object(verify_formal, "ROOT", root), patch.object(release_check, "ROOT", root), \
                    patch("subprocess.run", side_effect=responses) as commands:
                report = verify_formal.verify(str(binary), output)
                require_qualification("formal_core", report)
            self.assertEqual(report["schema"], "hepta.formal.v2")
            self.assertEqual(commands.call_count, 4)
            self.assertEqual([call.kwargs["timeout"] for call in commands.call_args_list], [20, 60, 60, 60])
            self.assertEqual(commands.call_args_list[0].args[0], [str(binary), "--version"])
            self.assertEqual(output.write_text.call_count, 1)
            self.assertEqual(json.loads(output.write_text.call_args.args[0]), report)
            self.assertFalse((root / "artifacts").exists())

    def test_mocked_producer_wrong_binary_pin_prevents_commands(self):
        with tempfile.TemporaryDirectory(prefix="hepta-formal-schema-") as td:
            root, binary, responses = self.producer_fixture(td)
            (root / "formal/toolchain-lock.json").write_text(json.dumps({"lean_binary_sha256": "0" * 64}))
            output = MagicMock(spec=Path)
            with patch.object(verify_formal, "ROOT", root), patch("subprocess.run", side_effect=responses) as commands:
                with self.assertRaises(RuntimeError):
                    verify_formal.verify(str(binary), output)
            commands.assert_not_called()
            output.write_text.assert_not_called()

    def test_mocked_producer_infrastructure_failure_saves_no_success_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-formal-schema-") as td:
            root, binary, responses = self.producer_fixture(td)
            responses[2] = SimpleNamespace(returncode=1, stdout="error: missing runtime; SYNTHETIC", stderr="")
            output = MagicMock(spec=Path)
            with patch.object(verify_formal, "ROOT", root), patch("subprocess.run", side_effect=responses) as commands:
                with self.assertRaises(ValueError):
                    verify_formal.verify(str(binary), output)
            self.assertEqual(commands.call_count, 3)
            output.write_text.assert_not_called()

    def test_mocked_producer_runtime_failure_with_sorry_saves_no_success_receipt(self):
        with tempfile.TemporaryDirectory(prefix="hepta-formal-schema-") as td:
            root, binary, responses = self.producer_fixture(td)
            responses[2].stdout += "error: (deterministic) timeout, maximum number of heartbeats (200000) has been reached\n"
            output = MagicMock(spec=Path)
            with patch.object(verify_formal, "ROOT", root), patch("subprocess.run", side_effect=responses) as commands:
                with self.assertRaises(ValueError):
                    verify_formal.verify(str(binary), output)
            self.assertEqual(commands.call_count, 3)
            output.write_text.assert_not_called()


if __name__ == "__main__":
    unittest.main()
