"""Run current native Cell controls without transferring the old f33 pin."""
from __future__ import annotations

import argparse
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_TEST_SHA256 = "f6cef59a2437140dd7bf25c84ad274b2bbbc51cf19a9770bc0810bb0fda2e1cd"
SOURCES = (
    "pyproject.toml",
    "docs/HIA_CORE_LOWERING_ABI.json",
    "docs/HIA_CORE_EMITTER_ABI.json",
    "docs/HIA_BYTE_WRAPPER_ABI.json",
    "docs/HIA_MACHINE_OBJECT_ABI.json",
    "examples/hia_cell_bridge/continuation.hepta",
    "examples/hia_cell_bridge/image_packer.hepta",
    "examples/hia_bootstrap/elf_shared_linker.hepta",
    "tools/cell_bridge_native.py",
    "tools/generate_cell_bridge_continuation.py",
    "tools/generate_hia_cell_bridge_image_packer.py",
    "tools/hia_cell_bridge_entry.S",
    "tools/build_hia_cell_bridge.py",
    "tools/qualify_cell_bridge_continuation.py",
    "tools/qualify_hia_cell_bridge_native.py",
    "tests/test_hia_cell_bridge.py",
    "tests/test_hia_cell_current_native.py",
    "tests/hia_cell_native_fixture.py",
    "tests/hia_cell_test_directory_preparation.py",
    "tests/test_hia_cell_test_directory_preparation.py",
    "tests/test_hia_cell_build_custody.py",
    "tools/hia_cold_compiler.py",
    "tools/hia_component_input_custody.py",
    "tools/qualify_hia_selfhost.py",
    "tools/build_hia_source_build.py",
    "hepta/hia_json_preflight_native.py",
)
ORIGINAL_METHODS = (
    "test_loader_actual_multi_image_close_reopen_and_simultaneous_handles",
    "test_loader_concurrent_loads_share_one_retained_image_per_digest",
    "test_loader_close_waits_for_admitted_native_call_then_revokes_instance",
    "test_loader_seals_bytes_and_rechecks_changed_source_even_on_cache_hit",
    "test_loader_rechecks_pinned_hia_source",
    "test_loader_registry_survives_independent_wrapper_imports",
    "test_loader_retained_image_count_is_bounded_and_duplicates_still_work",
    "test_loader_retained_byte_and_individual_image_bounds",
    "test_loader_load_failure_and_missing_entry_keep_bounded_custody",
    "test_generated_source_is_exact_and_original_compiler_is_pinned",
    "test_actual_native_roundtrip_complete_state_and_full_payload_bound",
    "test_complete_failure_and_cancellation_are_actual_result_observations",
    "test_unknown_and_cold_recovery_never_reissue_an_invocation",
    "test_cancellation_is_one_request_and_success_can_win_the_race",
    "test_pending_and_terminal_continuations_cannot_begin_again",
    "test_every_identity_digest_byte_is_bound_and_mismatches_are_atomic",
    "test_malformed_requests_refuse_without_state_or_output_writes",
    "test_corrupted_pending_state_and_invalid_results_refuse_atomically",
    "test_wrapper_checks_actual_payload_preimages_and_native_image_hash",
    "test_original_native_abi_rejects_aliases_before_core",
    "test_new_process_loads_original_state_and_accepts_retained_result",
)
NEW_METHODS = (
    "test_native_pipeline_rejects_late_artifact_replacement",
    "test_current_native_abi_preserves_null_address_and_alias_priorities",
    "test_hia_object_matches_independent_layout_and_assembler_prefix",
    "test_native_packer_refusals_publish_no_output",
    "test_native_packer_capacity_refusals_publish_no_output",
    "test_native_linker_malformed_objects_publish_no_output",
    "test_current_native_abi_preserves_all_three_original_extent_limits",
    "test_native_packer_maximum_declared_length_is_exact",
)


def identities():
    from tools.hia_cold_compiler import _regular
    return {name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
            for name in SOURCES for raw in [_regular(ROOT / name, 16 << 20)]}


class Result(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args)
        self.terminals, self.starts, self.bad, self.subtests = [], {}, set(), 0

    def startTest(self, test):
        self.starts[test.id()] = time.perf_counter_ns()
        super().startTest(test)

    def addFailure(self, test, error):
        self.bad.add(test.id())
        super().addFailure(test, error)

    def addError(self, test, error):
        self.bad.add(test.id())
        super().addError(test, error)

    def addSkip(self, test, reason):
        self.bad.add(test.id())
        super().addSkip(test, reason)

    def addSubTest(self, test, subtest, error):
        self.subtests += 1
        if error is not None:
            self.bad.add(test.id())
        super().addSubTest(test, subtest, error)

    def stopTest(self, test):
        self.terminals.append({
            "id": test.id(), "wall_ns": time.perf_counter_ns() - self.starts[test.id()],
            "method_completed": True, "status": "failed" if test.id() in self.bad else "completed",
        })
        super().stopTest(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cold-report", type=Path)
    mode.add_argument("--development-compiler", type=Path)
    parser.add_argument("--generation-index", type=Path)
    args = parser.parse_args()
    if args.generation_index is not None and args.cold_report is None:
        parser.error("--generation-index requires --cold-report")
    args.output.mkdir(parents=True, exist_ok=False)
    before = identities()
    if before["tests/test_hia_cell_bridge.py"]["sha256"] != ORIGINAL_TEST_SHA256:
        raise ValueError("complete original 21-control Cell source differs")
    for key in ("HIA_CELL_NATIVE_COLD_REPORT", "HIA_CELL_NATIVE_DEVELOPMENT_COMPILER",
                "HIA_CELL_NATIVE_GENERATION_INDEX"):
        os.environ.pop(key, None)
    if args.cold_report:
        os.environ["HIA_CELL_NATIVE_COLD_REPORT"] = str(args.cold_report.absolute())
        if args.generation_index:
            os.environ["HIA_CELL_NATIVE_GENERATION_INDEX"] = str(args.generation_index.absolute())
    else:
        os.environ["HIA_CELL_NATIVE_DEVELOPMENT_COMPILER"] = str(args.development_compiler.absolute())
    os.environ["HIA_CELL_BRIDGE_TEST_OUTPUT"] = str(args.output.absolute() / "build")
    from tests import test_hia_cell_bridge as original
    from tests import test_hia_cell_current_native as current
    baseline = unittest.defaultTestLoader.getTestCaseNames(original.HiaCellBridgeNativeTests)
    selected = unittest.defaultTestLoader.getTestCaseNames(current.HiaCellCurrentNativeTests)
    if baseline != sorted(ORIGINAL_METHODS) or selected != sorted((*ORIGINAL_METHODS, *NEW_METHODS)):
        raise ValueError("fixed original/current Cell control population differs")
    identity = "test_generated_source_is_exact_and_original_compiler_is_pinned"
    for name in ORIGINAL_METHODS:
        if name != identity and getattr(current.HiaCellCurrentNativeTests, name) is not getattr(original.HiaCellBridgeNativeTests, name):
            raise ValueError("original Cell behavioral method was replaced: " + name)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(current.HiaCellCurrentNativeTests)
    expected = [test.id() for test in suite]
    transcript = io.StringIO()
    start = time.perf_counter_ns()
    result = unittest.TextTestRunner(stream=transcript, verbosity=2, resultclass=Result).run(suite)
    elapsed = time.perf_counter_ns() - start
    after = identities()
    complete = (result.testsRun == len(expected) == 29
                and [row["id"] for row in result.terminals] == expected)
    passed = (result.wasSuccessful() and complete and not result.skipped
              and before == after and not result.bad)
    development = args.development_compiler is not None
    report = {
        "schema": "hepta.cell-hia-current-native-controls.v1",
        "status": ("COMPONENT_DEVELOPMENT_PASS" if development else "PASS") if passed else "HOLD",
        "loaded_test_ids": expected, "tests_run": result.testsRun,
        "terminals": result.terminals, "subtests_observed": result.subtests,
        "wall_ns": elapsed, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "source_before": before, "source_after": after,
        "source_stable": before == after, "complete_current_population": complete,
        "original_behavior_methods_unchanged": 20,
        "legacy_original_21_executed_by_this_gate": False,
        "legacy_original_file_preserved_sha256": ORIGINAL_TEST_SHA256,
        "claims": {"component_native_controls_passed": passed,
                   "current_cold_compiler_controls_passed": passed and not development,
                   "development_only": development, "cell_execution_qualified": False,
                   "learning_benefit_qualified": False, "whole_stack_qualified": False,
                   "production_activated": False},
    }
    log = transcript.getvalue().encode()
    (args.output / "unittest.log").write_bytes(log)
    report["unittest_log_sha256"] = sha256(log).hexdigest()
    (args.output / "RESULT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8",
    )
    print(transcript.getvalue(), end="")
    print(json.dumps({"status": report["status"], "tests_run": result.testsRun,
                      "result": str(args.output / "RESULT.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
