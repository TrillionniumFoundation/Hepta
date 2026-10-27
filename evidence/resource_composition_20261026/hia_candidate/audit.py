#!/usr/bin/env python3
"""Independent arithmetic and receipt review of retained HIA data only.

This module never imports Hepta, production qualifiers, or archived source.
It never starts a compiler, benchmark, emulator, or other child process.
"""
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

COMMIT = "3a424e427b378400802c9e3c2fef558c0a352756"
COMPILER = "baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7"
SNAPSHOT = "339ed18eafd41c41e6b1e84f18bec100db5122cf60983c948aa721f54249c10b"
QUALIFICATION_SHA = "434d1139f753ca54b12b2e49450cdf58b387fb88d2781df23dab7dbf59d4b602"
PERFORMANCE_SHA = "34d41fff6c99bc68f402f1ee81535e74f8779462082ed0c3f719428f21bb5e89"
PROTOCOL_SHA = "df1df380d1ddc84836093ac0e83824d907b9341d31b6e8c00ad230089a6f9891"
ORIGINAL_ROOT = "/workspace/scratch/c7c6ee414a6c/hepta-research"
OUTPUT = ORIGINAL_ROOT + "/artifacts/composition-hia-20261026-run2"
KERNELS = ("full_lifecycle", "constructor_error", "two_stage")
BACKENDS = ("rust", "llvm", "handwritten_rust")
BASELINES = ("rust", "handwritten_rust")
CALLS = {"full_lifecycle": 1048576, "constructor_error": 8388608, "two_stage": 1048576}
NATIVE_FIELDS = {"elapsed_ns", "checksum", "clock_resolution_ns", "process_peak_rss_kib",
                 "process_cpu_ns", "voluntary_context_switches", "involuntary_context_switches",
                 "minor_page_faults", "major_page_faults"}
COUNTERS = ("voluntary_context_switches", "involuntary_context_switches",
            "minor_page_faults", "major_page_faults")
GATES = ("unit_regression", "standalone_native", "standalone_resources", "composite_resources",
         "composite_bulk_targets", "source_migration", "cpp_template_migration",
         "c_configuration_matrix", "cpp_configuration_matrix", "selected_core_formal",
         "standalone_aarch64_qemu", "legacy_executable_core", "legacy_hosted_composition",
         "legacy_cortex_m4_qemu", "standalone_performance")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def same(left, right):
    return wire(left) == wire(right)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    def reject(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject)


def process(row, expected_returncode=0):
    require(type(row) is dict and type(row.get("returncode")) is int
            and row["returncode"] == expected_returncode, "recorded process exit differs")
    require(type(row.get("command")) is list and all(type(x) is str for x in row["command"]),
            "recorded process command malformed")
    for channel in ("stdout", "stderr"):
        require(type(row[channel]) is str and sha(row[channel].encode()) == row[channel + "_sha256"],
                "recorded process output hash differs")


def schedule():
    result = []
    for group in range(7):
        for position in range(3):
            original_index = (group + position) % 3
            kernel = KERNELS[original_index]
            rotation = (group + original_index) % 3
            order = list(BACKENDS[rotation:] + BACKENDS[:rotation])
            if group % 2:
                order.reverse()
            result.extend((group, kernel, backend) for backend in order)
    return result


def oracle(kernel, size, seed):
    if kernel == "two_alloc":
        return 1 if size >= 2**63 else 2 if seed else size + 19
    if size >= 2**63:
        return 1001 + (seed if kernel == "constructor_error" else 0)
    if kernel == "constructor_error":
        return 1002 + seed
    if kernel == "two_stage":
        return size * ((seed % 256) ^ 90)
    require(kernel == "full_lifecycle", "unknown kernel")
    blocks, tail = divmod(size, 256)
    return blocks * sum(range(256)) + sum((index + seed) % 256 for index in range(tail))


@lru_cache(maxsize=3)
def checksum(kernel):
    # This is integer digest arithmetic over formula values, never a native run
    # or a timing experiment. All three results are cached for negative tests.
    values = [oracle(kernel, 4093, (index * 17 + 13) % 97 + 1) for index in range(64)]
    result = 1469598103934665603
    for _ in range(CALLS[kernel] // 64):
        for value in values:
            result = ((result ^ value) * 1099511628211) % 2**64
    return result


def correctness(report):
    cases = []
    for kernel in KERNELS:
        cases.extend((kernel, size, seed) for size in (0, 1, 2, 7, 255, 256, 257, 4093, 65519)
                     for seed in (0, 1, 90, 255, 256, 2**32 - 1))
    cases.extend((kernel, size, seed) for kernel in (*KERNELS, "two_alloc")
                 for size in (2**63, 2**64 - 1) for seed in (0, 2**32 - 1))
    cases.extend(("two_alloc", size, seed) for size in (0, 1, 3, 5, 17, 4093)
                 for seed in (0, 1, 2**32 - 1))
    expected = [{"backend": backend, "kernel": kernel, "size": size, "seed": seed,
                 "expected": oracle(kernel, size, seed), "actual": oracle(kernel, size, seed)}
                for backend in BACKENDS for kernel, size, seed in cases]
    row = report["correctness"]
    process(row["process"])
    observed = [parse(line) for line in row["process"]["stdout"].splitlines()]
    require(same(observed, expected) and same(row["observations"], expected),
            "finite native correctness receipts differ from independent formulas")
    require(row["native_calls"] == len(expected) == 588 and row["status"] == "passed_finite_domain"
            and row["observations_sha256"] == sha(wire(expected)), "finite correctness denominator")
    return {"cases_per_backend": len(cases), "backends": list(BACKENDS), "native_calls": len(expected),
            "recorded_outputs_match_independent_formulas": True}


def recompute(report):
    require(report["schema"] == "hepta.hia.program-perf-qualification.v1"
            and report["phase"] == "complete", "complete HIA performance report required")
    require(report["git_commit"] == COMMIT and report["compiler_tree_sha256"] == COMPILER,
            "performance source identity differs")
    protocol = report["protocol"]
    require(sha(wire(protocol)) == report["protocol_sha256"] == PROTOCOL_SHA,
            "frozen HIA v3 protocol differs")
    require(protocol["native_calls_per_sample"] == CALLS and protocol["paired_groups"] == 7
            and protocol["warmup_calls_per_process"] == 8192
            and protocol["minimum_sample_seconds"] == 0.05
            and protocol["maximum_sample_seconds"] == 30.0
            and protocol["maximum_relative_mad"] == 0.05
            and protocol["maximum_kernel_paired_time_ratio"] == 1.2
            and protocol["maximum_geometric_mean_paired_time_ratio"] == 1.1,
            "frozen workload or thresholds differ")
    rows = report["raw_samples"]
    require(type(rows) is list and len(rows) == 63, "all 63 samples are required")
    indexed, associations = {}, []
    for index, (row, identity) in enumerate(zip(rows, schedule())):
        require(same([row[k] for k in ("group", "kernel", "backend", "sample_index")], [*identity, index]),
                "HIA v3 stable-kernel sample order differs")
        require(all(type(row[field]) is int for field in NATIVE_FIELDS), "noninteger native sample field")
        require(all(row[field] > 0 for field in ("elapsed_ns", "clock_resolution_ns", "process_peak_rss_kib", "process_cpu_ns"))
                and all(row[field] >= 0 for field in COUNTERS), "missing or invalid native observation")
        require(row["checksum"] == checksum(row["kernel"]), "timed checksum differs from formula digest")
        execution = row["execution"]
        process(execution)
        native = parse(execution["stdout"])
        require(set(native) == NATIVE_FIELDS and same(native, {key: row[key] for key in NATIVE_FIELDS})
                and execution["stderr"] == "", "native output fields are not retained exactly")
        artifacts = report["artifacts"]
        require(execution["command"] == [artifacts["driver"]["path"], artifacts[row["backend"]]["path"], row["kernel"]]
                and row["library_sha256"] == artifacts[row["backend"]]["sha256"]
                and row["driver_sha256"] == artifacts["driver"]["sha256"], "sample artifact or command association")
        indexed[identity] = row
        associations.append({key: row[key] for key in ("sample_index", "group", "kernel", "backend",
                             "driver_sha256", "library_sha256", *sorted(NATIVE_FIELDS))}
                            | {"stdout_sha256": execution["stdout_sha256"],
                               "stderr_sha256": execution["stderr_sha256"]})
    summary, quality, performance = {}, [], []
    medians = {backend: [] for backend in BASELINES}
    for kernel in KERNELS:
        implementations, comparisons = {}, {}
        for backend in BACKENDS:
            values = [indexed[group, kernel, backend]["elapsed_ns"] for group in range(7)]
            median = sorted(values)[3]
            mad = sorted(abs(value - median) for value in values)[3]
            relative = Fraction(mad, median)
            calculated = {"samples_ns": values, "median_ns": median, "minimum_ns": min(values),
                          "maximum_ns": max(values), "relative_mad": float(relative),
                          "median_ns_per_native_call": median / CALLS[kernel]}
            require(same(calculated, report["evaluation"]["summary"][kernel]["implementations"][backend]),
                    "retained per-implementation statistics differ")
            implementations[backend] = calculated | {"mad_ns": mad, "relative_mad_fraction": str(relative),
                "quality_pass": min(values) >= 50_000_000 and max(values) <= 30_000_000_000
                                and relative <= Fraction(1, 20)}
            if min(values) < 50_000_000:
                quality.append(kernel + "/" + backend + ": sample shorter than fixed minimum")
            if max(values) > 30_000_000_000:
                quality.append(kernel + "/" + backend + ": sample longer than fixed maximum")
            if relative > Fraction(1, 20):
                quality.append(kernel + "/" + backend + ": relative MAD above fixed maximum")
        for backend in BASELINES:
            pairs = [Fraction(indexed[group, kernel, "llvm"]["elapsed_ns"],
                              indexed[group, kernel, backend]["elapsed_ns"]) for group in range(7)]
            median = sorted(pairs)[3]
            calculated = {"paired_time_ratios": list(map(float, pairs)), "median_paired_time_ratio": float(median)}
            require(same(calculated, report["evaluation"]["summary"][kernel]["comparisons"][backend]),
                    "retained paired ratios differ")
            comparisons[backend] = calculated | {"paired_time_ratio_fractions": list(map(str, pairs)),
                "median_paired_time_ratio_fraction": str(median), "threshold_pass": median <= Fraction(6, 5)}
            medians[backend].append(median)
            if median > Fraction(6, 5):
                performance.append(kernel + "/" + backend + ": paired ratio exceeds fixed maximum")
        summary[kernel] = {"implementations": implementations, "comparisons": comparisons}
    geometric = {}
    for backend, values in medians.items():
        product = math.prod(values)
        value = float(product) ** (1 / 3)
        passed = product <= Fraction(11, 10) ** 3
        require(math.isclose(value, report["evaluation"]["geometric_mean_paired_time_ratios"][backend],
                             rel_tol=1e-14, abs_tol=1e-15), "retained geometric mean differs")
        geometric[backend] = {"ratio": value, "product_fraction": str(product), "threshold_pass": passed}
        if not passed:
            performance.append(backend + ": geometric mean exceeds fixed maximum")
    status = "measurement_inconclusive" if quality else "performance_failed" if performance else "passed"
    require(same(quality, report["evaluation"]["measurement_quality_failures"])
            and same(performance, report["evaluation"]["performance_threshold_failures"]), "reported failure list differs")
    require(report["status"] == report["evaluation"]["status"] == status
            and report["ok"] is report["evaluation"]["ok"] is (status == "passed"), "performance status differs")
    fractions = [Fraction(row["process_cpu_ns"], row["elapsed_ns"]) for row in rows]
    interference = {"sample_count": 63, "cpu_to_wall_ratio": {
        "minimum": float(min(fractions)), "median": float(sorted(fractions)[31]), "maximum": float(max(fractions))},
        "totals": {field: sum(row[field] for row in rows) for field in COUNTERS},
        "scope": "CPU interval brackets the wall interval; overhead and host interference are not isolated",
        "samples_excluded": 0, "acceptance_thresholds_adjusted": False}
    require(same(interference, report["interference_observations"]), "native observation summary differs")
    require(report["environment"]["scheduler"]["exclusive_cpu_ownership"] is False
            and report["environment"]["selected_cpu"] == min(report["environment"]["allowed_cpus_before"]),
            "shared-host scope or affinity selection differs")
    require(report["claims"] == {"actual_owned_cleanup_checked": True, "backend_refinement_proved": False,
        "finite_correctness_checked": True, "host_performance_gate_passed": False, "physical_device_qualified": False,
        "source_free_core_executed": True, "universal_rust_superiority_proved": False,
        "whole_language_performance_qualified": False}, "finite performance claim enlarged")
    return {"status": status, "performance_qualified": status == "passed", "sample_count": 63,
        "protocol_sha256": PROTOCOL_SHA, "kernel_order": list(KERNELS), "backend_order": list(BACKENDS),
        "summary": summary, "geometric_means": geometric, "measurement_quality_failures": quality,
        "performance_threshold_failures": performance, "interference_observations": interference,
        "raw_sample_associations": associations, "all_retained_evaluation_fields_match": True,
        "geometric_comparison_tolerance": {"relative": 1e-14, "absolute": 1e-15},
        "threshold_decisions": "exact rational comparisons, including the cubed geometric threshold",
        "scope": "native interval observations, not the new source-qualifier process observer; no causal interference attribution"}


def verify_artifacts(report, members):
    retained = report["artifact_retention"]
    prefix = "attempt2/performance-artifacts/"
    require(retained["retained"] is True and retained["status"] == "complete"
            and retained["directory"] == OUTPUT + "/performance-artifacts", "native artifact retention missing")
    manifest_bytes = members[prefix + "artifact-retention.json"]
    require(sha(manifest_bytes) == retained["manifest_sha256"], "native retention manifest hash")
    manifest = parse(manifest_bytes)
    require(manifest["files"] == retained["files"] and manifest["path_mapping"] == retained["path_mapping"]
            and manifest["build_layout"] == report["build_layout"], "retention records differ")
    names = {key[len(prefix):] for key in members if key.startswith(prefix)}
    require(names == set(retained["files"]) | {"artifact-retention.json"}
            and len(retained["files"]) == 16, "retained native file denominator")
    build_directory = report["build_layout"]["directory"]
    require(re.fullmatch(r"/tmp/hepta-hia-perf-[a-z0-9_]{8}", build_directory) is not None
            and report["build_layout"]["directory_characters"] == len(build_directory), "fixed build layout")
    require({k: v for k, v in report["build_layout"].items() if k not in {"directory", "directory_characters"}}
            == report["protocol"]["build_layout"], "build policy differs")
    for name, identity in retained["files"].items():
        data = members[prefix + name]
        require(identity == {"bytes": len(data), "sha256": sha(data)}, "retained native bytes differ")
        require(retained["path_mapping"][name] == {"original": build_directory + "/" + name,
                "retained": OUTPUT + "/performance-artifacts/" + name,
                **identity, "source_and_copy_hashes_verified": True}, "original-to-copy mapping differs")
    bound = {}
    for label, identity in {**report["artifacts"], **report["resource_observation"]["artifacts"]}.items():
        require(PurePosixPath(identity["path"]).parent.as_posix() == build_directory, "recorded artifact outside build")
        name = PurePosixPath(identity["path"]).name
        require({key: identity[key] for key in ("bytes", "sha256")} == retained["files"][name],
                "measured or observed binary differs from archived bytes")
        bound[label] = {"archive_member": prefix + name, **identity}
    for backend in BACKENDS:
        receipt = report["native_receipts"][backend]
        require(receipt["artifact_sha256"] == report["artifacts"][backend]["sha256"]
                and receipt["artifact_bytes"] == report["artifacts"][backend]["bytes"], "native receipt/library identity")
    llvm = report["native_receipts"]["llvm"]
    require(all(llvm["claims"][key] is False for key in ("c_codegen_used", "rust_codegen_used", "fallback_used")),
            "independent LLVM route claim differs")
    for field, name in (("core_sha256", "program.hia"), ("llvm_sha256", "program.ll"),
                        ("generated_rust_sha256", "generated.rs")):
        require(report[field] == retained["files"][name]["sha256"], "retained generated input identity")
    for name, source in (("driver.c", "examples/hia_program/perf_driver.c"),
                         ("observer.c", "examples/llvm_owned/observe.c"),
                         ("handwritten.rs", "examples/llvm_owned/reference.rs")):
        require(retained["files"][name]["sha256"] == report["inputs"][source], "retained source input identity")
    observation = report["resource_observation"]
    require(observation["status"] == "passed" and observation["rehashed_llvm_rejected"] is True,
            "resource observation incomplete")
    require(sha(members[prefix + "leak.ll"]) == observation["mutant_sha256"], "retained leak mutation differs")
    for kind, returncode, expected in (("positive", 0, {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}),
                                      ("negative", 1, {"allocations": 7, "frees": 0, "live": 7, "refusals": 1})):
        row = observation[kind]
        process(row, returncode)
        require(row["command"] == [observation["artifacts"][kind]["path"]]
                and same(parse(row["stdout"]), expected) and row["stderr"] == "",
                "allocator cleanup/refusal or missing-free negative receipt differs")
    return {"retained_files": 16, "retention_manifest_sha256": retained["manifest_sha256"],
            "measured_and_observed_binaries": bound, "all_retained_bytes_match_recorded_identities": True,
            "positive": {"allocations": 7, "frees": 7, "live": 0, "refusals": 1},
            "missing_free_negative": {"returncode": 1, "allocations": 7, "frees": 0, "live": 7, "refusals": 1},
            "scope": "untimed standalone LLVM observer; no allocator-trace comparison for Rust or timed libraries"}


def review(members):
    qraw, praw = members["attempt2/qualification.json"], members["attempt2/performance.json"]
    require(sha(qraw) == QUALIFICATION_SHA and sha(praw) == PERFORMANCE_SHA, "original report bytes differ")
    report, perf = parse(qraw), parse(praw)
    before, after = report["source_snapshot_before"], report["source_snapshot_after"]
    require(same(before, after) and len(before["files"]) == 920
            and before["sha256"] == sha(wire(before["files"])) == SNAPSHOT, "source snapshot denominator or identity")
    require(report["git_commit"] == COMMIT and report["compiler_tree_sha256"] == COMPILER
            and report["unchanged_source"] is True, "qualification source identity")
    require(report["full_six_deliverables_complete"] is report["full_seven_deliverables_complete"] is False,
            "unsupported completion claim")
    require(all(before["files"][path] == digest for path, digest in perf["inputs"].items())
            and perf["source_sha256"] == before["files"]["examples/hia_program/benchmarks.hepta"], "performance inputs/source mismatch")
    require(report["schema"] == "hepta.hia.unified-qualification.v1" and report["ok"] is False
            and report["status"] == "scoped_gates_not_all_qualified"
            and report["completed_gates"] == 15 and report["passed_gates"] == 14, "qualification outcome differs")
    gates = report["gates"]
    require(tuple(report["planned_gates"]) == tuple(row["name"] for row in gates) == GATES, "gate order/denominator")
    plan = parse(members["attempt2/plan.json"])
    require(plan["git_commit"] == COMMIT and plan["source_snapshot_sha256"] == SNAPSHOT
            and plan["commands"] == [{"name": row["name"], "argv": row["argv"]} for row in gates], "plan/execution mismatch")
    driver = [parse(line) for line in members["runner/attempt2-driver.log"].splitlines()]
    require(len(driver) == 31, "terminal driver row denominator")
    retained_gates = []
    for index, gate in enumerate(gates):
        passed = index != 14
        require(gate["passed"] is passed and type(gate["returncode"]) is int
                and gate["returncode"] == (0 if passed else 1), "gate outcome differs")
        require(driver[2 * index] == {"gate": gate["name"], "status": "running"}
                and same(driver[2 * index + 1], {"gate": gate["name"], "passed": passed,
                    "seconds": gate["seconds"], "returncode": gate["returncode"]}), "driver terminal gate linkage")
        for channel in ("stdout", "stderr"):
            identity = gate[channel]
            data = members["attempt2/" + identity["path"]]
            require(len(data) == identity["bytes"] and sha(data) == identity["sha256"], "gate log identity")
        record = {key: gate[key] for key in ("name", "passed", "returncode", "seconds")}
        if index:
            evidence = gate["evidence"]
            data = members["attempt2/" + evidence["path"]]
            value = parse(data)
            require(sha(data) == evidence["sha256"] and evidence["status"] == value.get("status")
                    and evidence["ok"] is value.get("ok"), "gate evidence identity/outcome")
            require((value.get("ok") is True or (gate["name"] == "legacy_cortex_m4_qemu" and value["status"] == "passed"))
                    is passed, "producer outcome/gate mismatch")
            record["evidence"] = evidence
        retained_gates.append(record)
    final = {key: report[key] for key in ("ok", "status", "passed_gates", "completed_gates", "unchanged_source",
                                         "full_seven_deliverables_complete")}
    require(same(driver[-1], final), "driver final outcome differs")
    unit = gates[0]
    require({key: unit[key] for key in ("tests_run", "skipped", "failures", "errors")}
            == {"tests_run": 2093, "skipped": 0, "failures": 0, "errors": 0}, "unit denominator differs")
    terminal = re.search(rb"\nRan 2093 tests in ([0-9.]+)s\n\nOK\n\Z", members["attempt2/unit_regression.stderr.log"])
    require(terminal is not None, "complete zero-skip unittest terminal log missing")
    journal = parse(members["runner/attempt2-job.json"])
    spec = parse(members["runner/attempt2-spec.json"])
    require(journal["schema"] == "hepta.qualification-job.v1" and journal["status"] == "completed"
            and journal["child_returncode"] == 1 and journal["spec"] == spec
            and journal["qualification_sha256"] == QUALIFICATION_SHA and journal["qualification_bytes"] == len(qraw),
            "durable job completion differs")
    require(journal["supervisor_sha256"] == sha(members["runner/supervisor.py"])
            and journal["driver_log_sha256"] == sha(members["runner/attempt2-driver.log"])
            and journal["driver_log_bytes"] == len(members["runner/attempt2-driver.log"]), "durable runner/log identity")
    require(spec["expected_commit"] == COMMIT and spec["cwd"] == ORIGINAL_ROOT and spec["output_directory"] == OUTPUT,
            "runner source/output scope differs")
    interruption = parse(members["attempt1/interruption-observation.json"])
    plan1 = parse(members["attempt1/plan.json"])
    require({name for name in members if name.startswith("attempt1/")}
            == {"attempt1/plan.json", "attempt1/interruption-observation.json"}, "interrupted attempt inventory differs")
    require(interruption["source_commit"] == plan1["git_commit"] == COMMIT
            and plan1["source_snapshot_sha256"] == SNAPSHOT
            and interruption["status"] == "interrupted_unqualified"
            and interruption["child_exit_code"] is interruption["unit_completed_test_count"] is None
            and interruption["interruption_cause"] == "unknown"
            and interruption["qualification_report_present"] is False
            and interruption["performance_samples_retained"] == 0
            and interruption["performance_stage_observed_started"] is False, "interrupted attempt promoted or altered")
    require(interruption["retained_driver_sha256"] == sha(members["runner/attempt1-driver.log"])
            and interruption["retained_plan_sha256"] == sha(members["attempt1/plan.json"])
            and members["runner/attempt1-driver.log"] == b'{"gate": "unit_regression", "status": "running"}\n',
            "interrupted attempt original driver/plan differs")
    return {"schema": "hepta.hia-candidate.independent-review.v1", "tested_source_commit": COMMIT,
        "compiler_sha256": COMPILER, "source_snapshot_sha256": SNAPSHOT, "source_files_before": 920,
        "source_files_after": 920, "source_maps_equal": True,
        "source_byte_to_git_binding": "shared sibling source_candidate bundle; not duplicated or re-executed here",
        "qualification_sha256": QUALIFICATION_SHA, "performance_sha256": PERFORMANCE_SHA,
        "attempt1": {"status": "interrupted_unqualified", "child_exit_code": None, "unit_tests_completed": None,
                     "performance_samples_retained": 0, "cause": "unknown", "original_files": 2},
        "attempt2": {**final, "child_returncode": 1, "started_utc": report["started_utc"],
                     "finished_utc": report["finished_utc"], "supervisor_finished_utc": journal["finished_utc"],
                     "original_files": sum(name.startswith("attempt2/") for name in members),
                     "gates": retained_gates},
        "unit": {"tests_run": 2093, "skipped": 0, "failures": 0, "errors": 0,
                 "terminal_seconds": float(terminal.group(1)), "collector_seconds": unit["seconds"]},
        "performance": recompute(perf), "correctness": correctness(perf),
        "artifact_retention": verify_artifacts(perf, members),
        "verification_scope": {"native_execution_repeated": False, "performance_remeasured": False,
            "production_qualifier_imported": False, "sample_selection": False, "threshold_adjustment": False,
            "independent_execution_authentication": False, "whole_project_blockers_closed": False}}
