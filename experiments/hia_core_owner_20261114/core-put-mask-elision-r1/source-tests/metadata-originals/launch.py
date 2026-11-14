"""One fixed original source-test group; admit owner closure before all child bodies."""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import traceback
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as common

GROUPS = {
    "source4": [
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_complete_original_Function_and_five_helpers_are_independent",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_current_32_sources_keep_original_Core_caps_and_literal_VM",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unqualified_cold_refuses_before_output_creation",
        "tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unselected_constructor_subclass_and_early_target_errors_stay_original"
    ],
    "fixture6": [
        "tests.test_hia_core_unpack_native.UnpackCompositionSourceTests.test_original_39_units_and_Core_ABI_are_unchanged",
        "tests.test_hia_core_compare_source.ExactNumericComparisonSourceTests.test_complete_Core39_outer_protocol_and_original116_are_unchanged",
        "tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests.test_resource_inventory_preserves_original92_and_Core39",
        "tests.test_hia_core_integer_integration.IntegerIntegrationSourceTests.test_exact_completed_kernel_bridge_and_original_Core39_are_preserved",
        "tests.test_hia_core_integer_native_integration.IntegerNativeIntegrationSourceTests.test_original32_Core39_116_18_kernel_and_bridge_are_unchanged",
        "tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests.test_portable_fixture_keeps_all_eleven_original_method_bodies"
    ]
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request, materialization, request_pin = common.load_request(args.request, args.sha256)
    common.require(type(request["group"]) is str and request["group"] in GROUPS,
                   "fixed source group")
    ids = GROUPS[request["group"]]
    common.require(request["requested_ids"] == ids
        and type(request["expected_tests"]) is int and request["expected_tests"] == len(ids),
        "fixed original method vector")
    common.require(request["generated_write_paths"] == []
        and request["allowed_changed_documents"] == []
        and request["unchanged_generated_paths"] == [], "no writable project source")
    root, output = Path(request["source_root"]), Path(request["output_root"])
    common.require(not output.exists() and output.parent.resolve(strict=True) == output.parent,
                   "fresh non-aliased output root")
    common.require(not output.is_relative_to(root) and not root.is_relative_to(output),
                   "disjoint source and evidence roots")
    environment = request["environment"]
    common.require(environment.get("TMPDIR") == str(output / "scratch")
        and environment.get("HEPTA_COMPARE_BASE_ROOT") == str(root)
        and environment.get("HEPTA_COMPARE_CONTROL_EVIDENCE") ==
            str(output / "scratch/comparison-evidence")
        and not any(k.startswith("HEPTA_HIA_") and v for k, v in environment.items()),
        "explicit source-only environment")
    resource = os.statvfs(output.parent)
    common.require(resource.f_bavail * resource.f_frsize >= request["minimum_free_bytes"]
        and resource.f_favail >= request["minimum_free_inodes"], "source capacity HOLD")
    before = common.source_snapshot(request, materialization)
    common.require_source_before(request, materialization, before)
    output.mkdir(mode=0o700)
    (output / "scratch").mkdir(mode=0o700)
    final = {
        "schema": "hia.core-balanced-dispatch.original-source-tests-final.v1",
        "status": "HOLD", "group": request["group"], "requested_ids": ids,
        "request_sha256": request_pin["sha256"], "closed": False, "natural_zero": False,
        "errors": [], "native_image_or_compiler_execution": False,
        "Core_author_write_executed": False, "is_full_standard_CI": False,
        "fresh_space": {"bytes": resource.f_bavail * resource.f_frsize,
                        "inodes": resource.f_favail},
    }
    try:
        common.save_json(output / "parent-source-before.json", before)
        spec = importlib.util.spec_from_file_location("pc_source_owned_process",
                                                       request["owner_implementation"]["path"])
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        wrapper = owner.run_owned(request["worker_command"], cwd=request["source_root"],
            env=environment, stdout_path=output / "child.stdout",
            stderr_path=output / "child.stderr", receipt_path=output / "process-owner.json",
            qualification_seconds=180, cleanup_seconds=3)
        common.save_json(output / "owner-wrapper.json", wrapper)
        receipt, child_request, natural = common.bind_closed(
            request, wrapper, output / "process-owner.json")
        final["closed"], final["natural_zero"] = True, natural
        common.save_json(output / "OWNER-CLOSURE.json", {
            "closed": True, "natural_zero": natural, "owner": receipt,
            "child_request_sha256":
                common.read_regular(str(output / "process-owner.json") + ".request.json")[1]["sha256"],
            "owner_wrapper": wrapper})
        # No child report, log, evidence directory or test output is opened above.
        report_raw, report_pin = common.read_regular(output / "source-tests-report.json")
        report = common.decode(report_raw)
        final["test_report"] = report_pin
        after = common.source_snapshot(request, materialization)
        final["changed_paths"] = common.require_source_after(request, before, after)
        common.require(final["changed_paths"] == [] and after == before,
                       "source changed during original source tests")
        common.save_json(output / "parent-source-after.json", after)
        child_before = common.decode(common.read_regular(output / "source-before.json")[0])
        child_after = common.decode(common.read_regular(output / "source-after.json")[0])
        common.require(child_before == before == after == child_after,
                       "parent/child complete source snapshots differ")
        common.require(natural, "original source owner did not finish naturally")
        expected_status = "ORIGINAL_" + request["group"].upper() + "_PASS_ONLY"
        common.require(report["schema"] == "hia.core-balanced-dispatch.original-source-tests-result.v1"
            and report["status"] == expected_status
            and report["request_sha256"] == request_pin["sha256"]
            and report["group"] == request["group"]
            and report["requested_ids"] == report["loaded_ids"] == report["started_ids"]
                == report["stopped_ids"] == report["success_ids"] == ids
            and type(report["tests_run"]) is int and report["tests_run"] == len(ids)
            and report["changed_paths"] == []
            and report["Core_author_write_executed"] is False
            and report["native_image_or_compiler_execution"] is False
            and report["is_full_standard_CI"] is False
            and report["original_python_object_emission_permitted"] is (request["group"] == "source4")
            and report["original_python_compile_exec_binder_permitted"] is (request["group"] == "source4")
            and all(report[name] == [] for name in (
                "errors", "loader_errors", "forbidden_attempts", "test_failures",
                "test_errors", "test_skips", "test_expected_failures", "test_unexpected_successes")),
            "complete original group report required")
        expected_events = [(phase, name) for name in ids for phase in ("start", "stop")]
        common.require([(row["event"], row["id"]) for row in report["events"]] == expected_events
            and all(type(row["monotonic_ns"]) is int for row in report["events"])
            and [row["monotonic_ns"] for row in report["events"]] ==
                sorted(row["monotonic_ns"] for row in report["events"]), "complete test event order")
        common.require(report["original_test_files_before"] == report["original_test_files_after"]
            and len(report["original_test_files_after"]) == 6, "six original complete test files")
        for row in report["original_test_files_after"]:
            common.require(row["pin"] == after[row["relative_path"]], "test source snapshot binding")
        vm = report["VM"]
        common.require(set(vm) == {"invoke_attempts", "invoke_returns", "invoke_exceptions",
                                  "root_attempts", "root_returns", "root_exceptions"}
            and all(type(value) is int and value >= 0 for value in vm.values())
            and vm["invoke_attempts"] == vm["invoke_returns"] + vm["invoke_exceptions"]
            and vm["root_attempts"] == vm["root_returns"] + vm["root_exceptions"],
            "actual VM observation accounting")
        if request["group"] == "source4":
            common.require(vm["root_attempts"] > 0 and vm["root_returns"] > 0,
                           "original literal VM was not exercised")
        else:
            common.require(all(value == 0 for value in vm.values()), "fixture6 VM exclusion")
            common.read_regular(output / "scratch/comparison-evidence/actual-VM-cases.json",
                                report["comparison_class_evidence"])
        final["tests_run"] = len(ids)
        final["VM"] = vm
        final["status"] = expected_status
    except BaseException as error:
        final["status"] = "HOLD"
        final["errors"].append({"type": type(error).__name__, "message": str(error),
                                "traceback": traceback.format_exc()})
    finally:
        if final["closed"]:
            try:
                originals = []
                for path in sorted(output.rglob("*")):
                    if path.is_dir():
                        continue
                    originals.append(common.read_regular(path)[1])
                common.save_json(output / "ORIGINALS.json", originals)
                final["originals"] = len(originals)
                for value in request["inputs"]:
                    common.read_regular(value["path"], value)
            except BaseException as error:
                final["status"] = "HOLD"
                final["errors"].append({"type": type(error).__name__, "message": str(error),
                                        "traceback": traceback.format_exc()})
        else:
            final["child_body_custody"] = "UNREAD_UNCONFIRMED_OWNER"
        common.save_json(output / "FINAL.json", final)
    print(final["status"])
    return 0 if final["status"] != "HOLD" and not final["errors"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
