#!/usr/bin/env python3
"""Run concrete release gates and bind their evidence to an unchanged snapshot."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import stat
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import compiler_hash


# JSON qualification reports are separate from large retained binary artifacts.
MAX_RELEASE_EVIDENCE_BYTES = 64 * 1024 * 1024



def _evidence_state(path: Path):
    """Capture the *path entry*, not the target of a symlink."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_regular_evidence(path: Path):
    """Read one stable, regular evidence file; reject symlinks and replacement.

    A zero-exit producer is not sufficient: bytes must come from the same
    filesystem object before, during and after the read. The producer and
    local filesystem are still trusted; this is not a remote attestation.
    """
    before = _evidence_state(path)
    if before is None:
        raise ValueError("E_MISSING_GATE_EVIDENCE: producer did not create a report")
    if not stat.S_ISREG(before[2]):
        raise ValueError("E_UNSAFE_GATE_EVIDENCE: report is not a regular file")
    if not 0 < before[3] <= MAX_RELEASE_EVIDENCE_BYTES:
        raise ValueError("E_OVERSIZED_GATE_EVIDENCE: bounded JSON report required")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("E_UNSAFE_GATE_EVIDENCE: no-follow nonblocking descriptors required")
    # Do not block when a checked regular pathname is replaced by a FIFO.
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
             | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(os.open(path, flags), "rb") as stream:
        def identity():
            current = os.fstat(stream.fileno())
            return (current.st_dev, current.st_ino, current.st_mode,
                    current.st_size, current.st_mtime_ns, current.st_ctime_ns)
        if identity() != before:
            raise ValueError("E_UNSAFE_GATE_EVIDENCE: report changed before opening")
        data = stream.read(MAX_RELEASE_EVIDENCE_BYTES + 1)
        if len(data) != before[3] or len(data) > MAX_RELEASE_EVIDENCE_BYTES:
            raise ValueError("E_UNSAFE_GATE_EVIDENCE: extent changed during bounded read")
        if identity() != before:
            raise ValueError("E_UNSAFE_GATE_EVIDENCE: report changed while reading")
    if _evidence_state(path) != before:
        raise ValueError("E_UNSAFE_GATE_EVIDENCE: report path changed during read")
    return data, before


# Source files are hashed separately from qualification JSON. A streamed,
# bounded snapshot must not follow symlinks, materialize entire large files,
# or block after a regular-file -> FIFO swap during untrusted local editing.
MAX_SOURCE_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024
SOURCE_SNAPSHOT_CHUNK_BYTES = 1024 * 1024


def _stable_source_digest(path: Path) -> str:
    """Hash one exact ordinary source inode with bounded memory and no-follow I/O.

    This is a point-in-time filesystem/source identity gate, not a guarantee
    against later noncooperating writes or a remote toolchain attestation.
    """
    before = _evidence_state(path)
    if (before is None or not stat.S_ISREG(before[2])
            or not 0 <= before[3] <= MAX_SOURCE_SNAPSHOT_FILE_BYTES):
        raise ValueError("E_SOURCE_SNAPSHOT_UNSAFE: not a bounded ordinary file")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("E_SOURCE_SNAPSHOT_UNSAFE: no-follow nonblocking I/O required")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
             | getattr(os, "O_CLOEXEC", 0))
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            fd = stream.fileno()

            def identity():
                current = os.fstat(fd)
                return (current.st_dev, current.st_ino, current.st_mode,
                        current.st_size, current.st_mtime_ns, current.st_ctime_ns)

            if identity() != before or _evidence_state(path) != before:
                raise ValueError("E_SOURCE_SNAPSHOT_RACE: replaced before read")
            digest = hashlib.sha256()
            remaining = before[3]
            while remaining:
                block = stream.read(min(remaining, SOURCE_SNAPSHOT_CHUNK_BYTES))
                if not block:
                    raise ValueError("E_SOURCE_SNAPSHOT_RACE: truncated source")
                digest.update(block)
                remaining -= len(block)
            if stream.read(1) or identity() != before:
                raise ValueError("E_SOURCE_SNAPSHOT_RACE: changed during hash")
        if _evidence_state(path) != before:
            raise ValueError("E_SOURCE_SNAPSHOT_RACE: source pathname replaced")
    except OSError as exc:
        raise ValueError("E_SOURCE_SNAPSHOT_UNSAFE: source file unavailable") from exc
    return digest.hexdigest()


def snapshot():
    """Immutable content inventory of the selected source tree at this instant.

    All enumerated non-directory, non-excluded entries must be ordinary files.
    An opaque symlink/special-file entry cannot silently disappear from the
    inventory. Generated qualification evidence remains excluded.
    """
    excluded = {".git", "__pycache__", "artifacts", "evidence", "build", ".venv"}
    files = {}
    for p in sorted(ROOT.rglob("*")):
        relative = p.relative_to(ROOT)
        if (excluded.intersection(relative.parts) or p.suffix in {".pyc", ".bundle"}
                or p.name.endswith(".hepta-lock")):
            continue
        info = _evidence_state(p)
        if info is None:
            raise ValueError("E_SOURCE_SNAPSHOT_RACE: listed source disappeared")
        if stat.S_ISDIR(info[2]):
            continue
        if not stat.S_ISREG(info[2]):
            raise ValueError("E_SOURCE_SNAPSHOT_UNSAFE: symlink or special source entry")
        files[str(relative)] = _stable_source_digest(p)
    identity = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sha256": identity, "files": files}


def _unittest_passed_count(stderr: str) -> int:
    """Count only a completed, unskipped terminal unittest stderr report.

    Test-controlled stdout or early stderr lines cannot inflate this value.
    This is a parser for local validation logs, not remote attestation.
    """
    if not isinstance(stderr, str):
        return 0
    match = re.search(
        r"(?m)^Ran ([0-9]+) tests? in [0-9]+(?:\.[0-9]+)?s\r?\n\r?\nOK\r?\n?\Z",
        stderr,
    )
    return int(match.group(1)) if match else 0


def _sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _number(value, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def _same_number(value, expected):
    return _number(value) and math.isclose(value, expected, rel_tol=1e-12, abs_tol=1e-12)


def _native_build(build, *, status="rustc_checked", check_only=False):
    if (build.get("ok") is not True or build.get("status") != status
            or build.get("check_only") is not check_only or build.get("diagnostics") != []
            or not _sha256(build.get("validation_artifact_sha256"))):
        return False
    return check_only or (_integer(build.get("artifact_bytes"), 1)
                          and _sha256(build.get("artifact_sha256"))
                          and build["artifact_sha256"] == build["validation_artifact_sha256"])


def _frontend_checked(report, *, allow_external=False):
    expected = {"syntax": "passed", "types_effects_resources": "passed_in_supported_subset", "rust_borrows_types": "rustc_checked"}
    statuses = {"checked", "checked_with_external_assumptions"} if allow_external else {"checked"}
    return (report.get("ok") is True and report.get("status") in statuses and report.get("diagnostics") == []
            and all(report.get("checks", {}).get(key) == value for key, value in expected.items()))


def _command_completed(result):
    return (type(result.get("exit_code")) is int and result["exit_code"] == 0
            and isinstance(result.get("argv"), list) and bool(result["argv"])
            and _number(result.get("seconds")))


def _strict_json(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON field in retained graph: " + key)
            value[key] = item
        return value

    def invalid(value):
        raise ValueError("Nonfinite JSON constant in retained graph: " + value)

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def require_qualification(name, evidence):
    """Malformed nested evidence fails the gate rather than escaping its report."""
    try:
        _require_qualification(name, evidence)
    except (AttributeError, KeyError, TypeError, IndexError, OverflowError, RecursionError, OSError) as exc:
        raise ValueError("Malformed nested qualification evidence: " + name) from exc


def _require_qualification(name, evidence):
    """An outer success must not hide a required inner check marked not_run."""
    if name == "native_and_performance":
        results = evidence.get("results", {})
        required = {"c_abi": "passed", "no_std": "passed", "kernel_correctness": "passed",
                    "safe_borrowed": "passed", "kernel_codegen": "completed", "benchmarks": "completed"}
        if any(results.get(key, {}).get("status") != value for key, value in required.items()):
            raise ValueError("A required native qualification did not complete")
        targets = results["no_std"].get("targets", {})
        for target in ("host", "aarch64-unknown-linux-gnu", "thumbv7em-none-eabi", "x86_64-pc-windows-msvc"):
            if targets.get(target, {}).get("status") != "passed":
                raise ValueError(f"Required no_std object target not qualified: {target}")
    elif name == "representative_performance":
        if (evidence.get("correctness", {}).get("status") != "passed"
                or evidence.get("function_bytes", {}).get("status") != "completed"
                or evidence.get("measurements", {}).get("status") != "completed"):
            raise ValueError("Representative correctness/code comparison/timing did not all complete")
        from tools.benchmark_suite import KERNELS
        implementations = {"rust", "hepta_rust", "hepta_c", "hepta_c_unroll"}
        measurements = evidence["measurements"]
        trials = measurements.get("trials")
        summary = measurements.get("summary", [])
        samples = measurements.get("samples", [])
        correctness = evidence["correctness"]
        if (evidence.get("schema") != "hepta.representative-benchmarks.v1"
                or len(correctness.get("implementations", [])) != 4
                or set(correctness.get("implementations", [])) != implementations
                or correctness.get("kernels") != list(KERNELS)
                or correctness.get("counts") != [1, 3, 31, 255, 257, 4099]
                or correctness.get("zero_length_also_checked") is not True
                or type(trials) is not int or trials < 3
                or len(summary) != len(KERNELS) * 2
                or {(row.get("kernel"), row.get("elements")) for row in summary}
                    != {(kernel, count) for kernel in KERNELS for count in (4096, 262144)}
                or any(set(row.get("implementations", {})) != implementations
                       or set(row.get("time_relative_to_independent_rust", {})) != implementations - {"rust"}
                       for row in summary)
                or len(samples) != trials * len(KERNELS) * 2 * len(implementations)
                or evidence.get("builds", {}).get("hepta_c_unroll", {}).get("optimization_profile") != "unroll"
                or evidence.get("builds", {}).get("hepta_c", {}).get("optimization_profile") != "default"):
            raise ValueError("Both explicit C profiles and both Rust paths must retain the full benchmark denominator")
        builds = evidence["builds"]
        if (builds.get("hepta_rust", {}).get("ok") is not True
                or not _frontend_checked(builds["hepta_rust"].get("validation", {}), allow_external=True)
                or not _native_build(builds["hepta_rust"].get("build", {}))
                or not _native_build(builds["hepta_c"], status="gcc_checked")
                or not _native_build(builds["hepta_c_unroll"], status="gcc_checked")
                or set(builds.get("undefined_symbols", {})) != implementations):
            raise ValueError("All representative native objects must actually build")
        functions = evidence["function_bytes"].get("functions", {})
        if set(functions) != set(KERNELS):
            raise ValueError("Every representative function must retain its measured text section")
        for function in functions.values():
            shapes = function.get("implementations", {})
            if (set(shapes) != {"rust", "hepta_rust"}
                    or any(not _integer(s.get("bytes"), 1) or not _sha256(s.get("sha256")) for s in shapes.values())
                    or function.get("identical_function_bytes") is not (shapes["rust"] == shapes["hepta_rust"])):
                raise ValueError("Function text identity must agree with both observed byte sections")
        expected = {(kernel, count, implementation, trial) for kernel in KERNELS
                    for count in (4096, 262144) for implementation in implementations for trial in range(trials)}
        identities = [(s.get("kernel"), s.get("elements"), s.get("implementation"), s.get("trial")) for s in samples]
        if len(set(identities)) != len(expected) or set(identities) != expected:
            raise ValueError("Every kernel/count/profile/trial must have exactly one raw timing observation")
        checksums = {}
        grouped = {}
        for sample in samples:
            kernel, count, implementation, trial = (sample[k] for k in ("kernel", "elements", "implementation", "trial"))
            iterations = 512 if kernel == "binary_search" else (1 << 26) // count
            queries = 2048 if kernel == "binary_search" else 0
            operations = iterations * (queries or count)
            if (not _integer(count, 1) or not _integer(trial)
                    or type(sample.get("iterations")) is not int or sample["iterations"] != iterations
                    or type(sample.get("queries")) is not int or sample["queries"] != queries
                    or not _integer(sample.get("elapsed_ns"), 1)
                    or not _number(sample.get("ns_per_operation"), 1e-15)
                    or not math.isclose(sample["ns_per_operation"], sample["elapsed_ns"] / operations, rel_tol=1e-8, abs_tol=1e-9)
                    or not _integer(sample.get("reference_checksum"))):
                raise ValueError("Raw benchmark timing must contain finite positive native observations")
            checksums.setdefault((kernel, count), set()).add(sample["reference_checksum"])
            grouped.setdefault((kernel, count, implementation), []).append(sample["ns_per_operation"])
        if any(len(values) != 1 for values in checksums.values()):
            raise ValueError("Timed native implementations disagree on the reference checksum")
        slowdowns = {}
        for row in summary:
            kernel, count = row["kernel"], row["elements"]
            if row.get("operation") != ("query" if kernel == "binary_search" else "element"):
                raise ValueError("Benchmark operation denominator changed")
            medians = {}
            for implementation, reported in row["implementations"].items():
                values = grouped[kernel, count, implementation]
                actual = {"median_ns_per_operation": statistics.median(values),
                          "min_ns_per_operation": min(values), "max_ns_per_operation": max(values)}
                if set(reported) != set(actual) or any(not _same_number(reported[k], v) for k, v in actual.items()):
                    raise ValueError("Benchmark summary differs from its complete raw samples")
                medians[implementation] = actual["median_ns_per_operation"]
            for implementation, ratio in row["time_relative_to_independent_rust"].items():
                actual = medians[implementation] / medians["rust"]
                if not _same_number(ratio, actual):
                    raise ValueError("Benchmark ratio differs from its observed median times")
                if actual > 1:
                    slowdowns[kernel, count, implementation] = actual
        regressions = measurements.get("all_observed_slowdowns", [])
        if (len(regressions) != len(slowdowns)
                or {(r.get("kernel"), r.get("elements"), r.get("implementation")) for r in regressions} != set(slowdowns)
                or any(not _same_number(r.get("observed_median_time_ratio"), slowdowns[r["kernel"], r["elements"], r["implementation"]])
                       for r in regressions)):
            raise ValueError("Every observed performance regression must remain in the report")
    elif name == "application_performance":
        from tools.benchmark_applications import validate_application_report
        validate_application_report(evidence)
    elif name == "bounded_concurrency":
        from tools.validate_groups import SCENARIOS
        scenarios = evidence.get("scenarios", [])
        if (len(scenarios) != len(SCENARIOS) or {s.get("scenario") for s in scenarios} != set(SCENARIOS)
                or any(s.get("status") != "passed" or len(s.get("runs", [])) != 3
                       or any(r.get("returncode") != 0 or set(r.get("metrics", {})) != set(SCENARIOS[s["scenario"]])
                              for r in s.get("runs", [])) for s in scenarios)):
            raise ValueError("Every bounded-group scenario, including real channel deadlines, must execute three times")
        fixed = {
            "bounded_pipeline": {"received_sum": 32768, "completed_tasks": 8, "admitted_input_bytes": 32768, "active_tasks": 0},
            "admission_budgets": {"admitted_tasks": 2, "task_budget_rejections": 1, "admitted_input_bytes": 8,
                                  "input_budget_rejections": 1, "zero_budget_completed": 0},
            "cancellation": {"completed_tasks": 4, "active_tasks": 0, "waiting_senders": 0, "discarded_values": 1, "worker_result_sum": 256},
            "worker_failure": {"failure_code": 17, "completed_tasks": 4, "active_tasks": 0, "waiting_senders": 0},
            "timeouts": {"send_timeouts": 1, "receive_timeouts": 1, "received": 1,
                         "completed_tasks": 1, "active_tasks": 0, "worker_result_sum": 2},
        }
        if evidence.get("schema") != "hepta.groups.evidence.v1":
            raise ValueError("Unknown bounded-group evidence schema")
        for scenario in scenarios:
            label = scenario["scenario"]
            if (any(not _sha256(scenario.get(key)) for key in ("source_sha256", "compiler_sha256", "rust_sha256", "artifact_sha256"))
                    or scenario.get("backend_validation", {}).get("rust_borrows_types") != "rustc_checked"):
                raise ValueError("Bounded-group execution lacks native artifact and validation identities")
            for run in scenario["runs"]:
                metrics = run["metrics"]
                if (type(run["returncode"]) is not int or not _number(run.get("elapsed_ms"))
                        or any(not _integer(n) for n in metrics.values())
                        or any(metrics[key] != value for key, value in fixed[label].items())
                        or (label == "bounded_pipeline" and not (1 <= metrics["peak_queued"] <= 4 and metrics["send_waits"] > 0))
                        # The failing worker sends twice but returns its input
                        # length (one); received messages and worker sums differ.
                        or (label == "worker_failure" and not (2 <= metrics["received_before_close"] <= 194))):
                    raise ValueError("Bounded-group cleanup, budgets, or deadlines contradict the native program's required observations")
    elif name == "formal_core":
        from tools.verify_formal import validate_report
        validate_report(evidence)
    elif name == "source_bound_resource_ir":
        from tools.qualify_resource_source import validate_report
        validate_report(evidence)
    elif name == "local_stored_resource_views":
        from tools.qualify_resource_views import validate_report
        validate_report(evidence)
    elif name == "llvm_local_stored_views":
        from tools.qualify_llvm_local_views import validate_report
        validate_report(evidence)
    elif name == "task_io_composition":
        from tools.qualify_task_io import validate_report
        validate_report(evidence, minimum_repeats=3)
    elif name == "cpp_class_migration":
        from tools.validate_cpp_class import validate_report
        validate_report(evidence)
    elif name == "cpp_owned_migration":
        from tools.validate_cpp_owned import validate_report
        validate_report(evidence)
    elif name == "cpp_owned_to_llvm":
        from tools.qualify_cpp_owned_llvm import validate_report
        validate_report(evidence)
    elif name == "cpp_composed_migration":
        from tools.validate_cpp_composed import validate_report
        validate_report(evidence)
    elif name == "cpp_composed_to_llvm":
        from tools.qualify_cpp_composed_llvm import validate_report
        validate_report(evidence)
    elif name == "cpp_upstream_upgrade":
        from tools.qualify_cpp_upgrade import validate_report
        validate_report(evidence)
    elif name == "llvm_owned_rust_allocator":
        from tools.qualify_llvm_owned_rust_allocator import validate_report
        validate_report(evidence)
    elif name == "llvm_native_performance":
        from tools.qualify_llvm_native import validate_report
        identity = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                  capture_output=True, text=True)
        if identity.returncode != 0:
            raise ValueError("LLVM qualification requires the current candidate commit identity")
        validate_report(evidence, expected_git_commit=identity.stdout.strip())
    elif name == "llvm_owned_performance":
        from tools.qualify_llvm_owned import validate_report
        identity = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                  capture_output=True, text=True)
        if identity.returncode != 0:
            raise ValueError("Owned LLVM qualification requires the current candidate commit identity")
        validate_report(evidence, expected_git_commit=identity.stdout.strip())
    elif name == "provenance_and_type_core":
        from tools.verify_memory import validate_report
        validate_report(evidence)
    elif name == "partial_owned_places":
        from tools.qualify_places import validate_places_qualification
        validate_places_qualification(evidence)
    elif name == "owned_c_backend":
        from tools.validate_c_owned import validate_c_owned_qualification
        validate_c_owned_qualification(evidence)
    elif name == "stored_borrows":
        from tools.qualify_borrowed_storage import validate_borrowed_storage_report
        validate_borrowed_storage_report(evidence)
    elif name == "shared_runtime":
        from tools.validate_shared_runtime import validate_shared_runtime_report
        validate_shared_runtime_report(evidence, minimum_repeats=3)
    elif name == "independent_concurrent_ir":
        from tools.validate_concurrent_ir import validate_report
        validate_report(evidence)
    elif name == "structured_task_trees":
        from tools.validate_task_tree import validate_task_tree_report
        validate_task_tree_report(evidence, minimum_repeats=3)
    elif name == "bounded_async_io":
        from tools.validate_io import validate_io_report
        validate_io_report(evidence, minimum_repeats=3)
    elif name == "system_board":
        from tools.validate_board import validate_report
        validate_report(evidence)
    elif name == "native_host_abi":
        from tools.validate_native_host import validate_report
        validate_report(evidence)
    elif name == "native_debugger":
        from tools.validate_debugger import validate_report
        validate_report(evidence)
    elif name == "aarch64_execution":
        cases = {case.get("case"): case for case in evidence.get("cases", [])}
        if (cases.get("correct", {}).get("returncode") != 0
                or cases.get("wrong_sum_negative_control", {}).get("returncode") != 11):
            raise ValueError("Cross-execution positive and negative controls did not both qualify")
    elif name == "agent_evaluator_fixtures":
        if (evidence.get("actual_ai_model_runs") != 0
                or evidence.get("ai_comparison_eligible") is not False
                or evidence.get("oracle_fixture_runs") != 8):
            raise ValueError("Fixture evidence must retain its exact non-AI qualification scope")
    elif name in {"c_project_migration", "upstream_c_modules"}:
        migration = evidence.get("migration", {})
        coverage = migration.get("coverage", {})
        if (evidence.get("ok") is not True or migration.get("ok") is not True
                or migration.get("native_validation") != "passed"
                or migration.get("declaration_inventory_complete") is not True
                or sum(coverage.get("status_counts", {}).values()) != coverage.get("active_project_declarations")):
            raise ValueError("C module capture, full declaration accounting and native build must complete")
        execution = evidence.get("execution", {})
        if name == "upstream_c_modules":
            if (execution.get("total_differential_cases") != 25302
                    or execution.get("wrong_result_control_rejected") is not True
                    or execution.get("same_address_read_alias_cases") != 8434):
                raise ValueError("Upstream C differential controls and alias cases did not qualify")
        else:
            faults = execution.get("fault_injection", [])
            if (sum(execution.get("differential_cases", {}).values()) != 1046 or len(faults) != 10
                    or any(f.get("c_live_allocations") != 0 or f.get("hepta_live_allocations") != 0 for f in faults)):
                raise ValueError("C allocation refusal, recovery and cleanup evidence is incomplete")
    elif name == "stateful_c_module":
        from tools.qualify_c_ring_buffer import EXPECTED_BLOBS, FLAGS, UPSTREAM_COMMIT
        migration = evidence.get("migration", {})
        coverage = migration.get("coverage", {})
        expected_counts = {"function_converted": 9, "prototype_resolved": 9, "record_converted": 1,
                           "record_forward_resolved": 1, "type_alias_resolved": 2}
        upstream = evidence.get("upstream", {})
        if (evidence.get("schema") != "hepta.c-stateful-upstream-qualification.v1"
                or evidence.get("ok") is not True or evidence.get("stage") != "complete"
                or upstream.get("commit") != UPSTREAM_COMMIT
                or {entry.get("local_path"): entry.get("git_blob") for entry in upstream.get("files", [])} != EXPECTED_BLOBS
                or evidence.get("build_configuration") != FLAGS
                or migration.get("ok") is not True or migration.get("native_validation") != "passed"
                or migration.get("declaration_inventory_complete") is not True
                or coverage.get("active_project_declarations") != 22
                or coverage.get("status_counts") != expected_counts):
            raise ValueError("The frozen stateful C module must retain all 22 active declarations and its actual build configuration")
        declarations = [d for d in migration.get("declarations", []) if d.get("status") != "system_or_compiler_declaration"]
        if (len(upstream.get("files", [])) != len(EXPECTED_BLOBS)
                or any(not _sha256(f.get("sha256")) or not _integer(f.get("bytes"), 1) for f in upstream["files"])
                or len(declarations) != 22
                or {status: sum(d.get("status") == status for d in declarations) for status in expected_counts} != expected_counts
                or len({(d.get("unit"), d.get("file"), d.get("kind"), d.get("name"), d.get("offset"), d.get("status"))
                        for d in declarations}) != 22
                or migration.get("frontend_validation") != "passed"
                or migration.get("status") != "native_built_not_equivalence_proved"
                or not _native_build(migration.get("native_build", {}))
                or not _command_completed(evidence.get("original_build", {}))
                or not _command_completed(evidence.get("performance", {}).get("build", {}))):
            raise ValueError("The full C declaration inventory and original/translated/timing native builds must exist and succeed")
        if (any(value is not False for value in migration.get("claims", {}).values())
                or set(migration.get("claims", {})) != {"all_c_or_cpp_supported", "foreign_pointer_validity_checked", "pointer_contracts_inferred",
                                                       "source_equivalence_proved", "unlisted_build_configurations_qualified", "whole_language_soundness_proved"}
                or any(migration.get("record_views", {}).get(flag) is not False for flag in
                       ("allocation_inference", "ownership_inference", "source_equivalence_proved", "stored_references_added_to_language"))):
            raise ValueError("C record-view evidence must retain its external assumptions and bounded claims")
        execution = evidence.get("execution", {})
        calls = execution.get("calls_by_function", {})
        boundaries = evidence.get("boundary_controls", [])
        boundary_names = {"null_record", "misaligned_record", "record_buffer_overlap", "output_buffer_overlap",
                          "input_buffer_overlap", "extent_overflow", "bad_index", "null_storage", "zero_capacity"}
        layout = evidence.get("layout_probe", {})
        wrong = evidence.get("wrong_implementation_control", {})
        if (execution.get("state_transitions") != 16384 or execution.get("native_differential_calls") != 65544
                or execution.get("capacities") != [1, 2, 4, 8, 16, 32, 64, 256]
                or execution.get("steps_per_capacity") != 2048 or execution.get("zero_length_null_slice_calls") != 543
                or set(calls) != {"init", "queue", "queue_arr", "dequeue", "dequeue_arr", "peek", "is_empty", "is_full", "num_items"}
                or any(type(n) is not int or n <= 0 for n in calls.values()) or sum(calls.values()) != 65544
                or len(boundaries) != 9 or {b.get("case") for b in boundaries} != boundary_names
                or any(b.get("actual_exit") != -6 or b.get("expected_exit") != -6
                       or b.get("original_C_executed") is not False for b in boundaries)
                or set(layout) != {"size", "align", "buffer", "buffer_mask", "head_index", "tail_index"}
                or any(set(item) != {"gcc", "rust"} or item["gcc"] != item["rust"] for item in layout.values())
                or wrong.get("compiled") is not True or wrong.get("rejected_by_full_oracle") is not True):
            raise ValueError("Stateful C execution, independent layout probes and native rejection controls must all complete")
        sizes = {key: value["gcc"] for key, value in layout.items()}
        expected_checks = {"C/Hepta returns", "independent bounded deque oracle", "all persistent scalar state",
                           "every backing-store byte", "output sentinels", "unchanged source input", "backing-pointer identity"}
        if (any(not _integer(value) for value in sizes.values())
                or any(type(item["rust"]) is not int for item in layout.values())
                or sizes["align"] < 1 or sizes["align"] & (sizes["align"] - 1)
                or sizes["size"] < sizes["align"] or sizes["size"] % sizes["align"]
                or not (sizes["buffer"] == 0 < sizes["buffer_mask"] < sizes["tail_index"] < sizes["head_index"] < sizes["size"])
                or set(execution.get("checks", [])) != expected_checks or len(execution["checks"]) != len(expected_checks)
                or execution.get("source_equivalence_proved") is not False
                or not isinstance(wrong.get("first_mismatch"), str) or not wrong["first_mismatch"]):
            raise ValueError("C layout and differential evidence must contain concrete independent observations")
        owner = evidence.get("owned_client", {})
        owner_calls = owner.get("calls", [])
        measurements = evidence.get("performance", {}).get("measurements", [])
        if (owner.get("actual_allocator_refusal") is not True or owner.get("upstream_allocator_migration_claimed") is not False
                or owner.get("client_kind") != "authored_Hepta_Buffer_owner_of_upstream_caller_owned_storage"
                or [c.get("result") for c in owner_calls] != [0, 7, -1, 0, -1, 0]
                or any(c.get("live_allocations_after") != 0 for c in owner_calls)
                or evidence.get("performance", {}).get("status") != "measured" or len(measurements) != 3
                or {m.get("case") for m in measurements} != {"single_byte_enqueue_dequeue", "64_byte_enqueue_dequeue", "count_empty_full_queries"}
                or any(m.get("iterations_per_sample") != 100000 or len(m.get("execution_order", [])) != 14
                       or set(m.get("samples_nanoseconds", {})) != {"original_C", "Hepta_C_ABI"}
                       or any(len(samples) != 7 or any(type(n) is not int or n <= 0 for n in samples)
                              for samples in m.get("samples_nanoseconds", {}).values()) for m in measurements)
                or evidence.get("cost", {}).get("model_runs") != 0
                or any(evidence.get(flag) is not False for flag in ("source_equivalence_proved", "foreign_pointer_validity_proved", "performance_parity_claimed", "whole_project_blockers_closed"))
                or evidence.get("source_snapshot_before") != evidence.get("source_snapshot_after")
                or evidence.get("source_snapshot_before") != snapshot()):
            raise ValueError("C ownership, complete cost samples and unchanged-source evidence must retain their bounded claims")
        expected_owner_calls = [(8, False, 0), (8, True, 7), (65519, False, -1),
                                (16, False, 0), (65519, True, -1), (32, False, 0)]
        if (not _native_build(owner.get("native_build", {}))
                or any(type(call.get("size")) is not int or type(call.get("result")) is not int
                       or type(call.get("early_return")) is not bool or type(call.get("live_allocations_after")) is not int
                       for call in owner_calls)
                or [(call.get("size"), call.get("early_return"), call.get("result")) for call in owner_calls] != expected_owner_calls):
            raise ValueError("The actual owning client must build and retain allocation refusal, cleanup, early-return and recovery inputs")
        expected_order = [name for trial in range(7)
                          for name in (("original_C", "Hepta_C_ABI") if trial % 2 == 0 else ("Hepta_C_ABI", "original_C"))]
        for measurement in measurements:
            samples = measurement["samples_nanoseconds"]
            original = statistics.median(samples["original_C"]) / 100000
            translated = statistics.median(samples["Hepta_C_ABI"]) / 100000
            if (measurement["execution_order"] != expected_order
                    or measurement.get("ABI_calls_per_iteration") != (3 if measurement["case"] == "count_empty_full_queries" else 2)
                    or not _integer(measurement.get("checksum"))
                    or not _same_number(measurement.get("original_C_median_ns_per_iteration"), original)
                    or not _same_number(measurement.get("Hepta_C_ABI_median_ns_per_iteration"), translated)
                    or not _same_number(measurement.get("observed_Hepta_over_C_ratio"), translated / original)):
                raise ValueError("C bridge timing order, operation counts and summaries must agree with every retained raw sample")
    elif name == "cpp_library_interop":
        execution = evidence.get("execution", {})
        if (evidence.get("ok") is not True or evidence.get("native_link_qualified") is not True
                or any(execution.get(k) is not True for k in ("bidirectional_native", "borrowed", "cpp_templates", "negative_boundaries", "std_string", "std_vector"))
                or evidence.get("performance", {}).get("status") != "measured"
                or len(evidence["performance"].get("measurements", [])) != 6):
            raise ValueError("C++ library execution and separately measured bridge costs must complete")
    elif name == "cpp_constructor_interop":
        from tools.validate_cpp_constructors import validate_constructor_qualification
        validate_constructor_qualification(evidence)
        if any(row.get("iterations") != 100000 for row in evidence["performance"]["measurements"]):
            raise ValueError("Release constructor lifecycle and method samples must each retain 100000 native iterations")
    elif name == "cpp_scoped_raii":
        from hepta.cpp_contracts import _Generator, _validate
        from hepta.cpp_scoped import EXAMPLE
        from tools.evidence_checks import native_build, strict_equal

        expected = {"vector_differential_cases": 16, "probe_lifecycle_paths": 4,
                    "unit_cleanup_paths": 2, "pod_reference_copy": True,
                    "output_guard_cases": 2, "allocation_refusal_sites": 2,
                    "allocation_recoveries": 2, "direct_cpp_new_calls": 2,
                    "scoped_cpp_new_calls": 2, "handle_cpp_new_calls": 5,
                    "scoped_wrapper_allocation_delta": 0, "live_cpp_allocation_delta": 0,
                    "output_after_destructor": True, "foreign_cpp_library_rewritten": False}
        if (evidence.get("schema") != "hepta.cpp-scoped-qualification.v1"
                or evidence.get("ok") is not True or evidence.get("native_link_qualified") is not True
                or evidence.get("source_snapshot_unchanged") is not True
                or any(evidence.get(flag) is not False for flag in
                       ("foreign_cpp_library_rewritten", "whole_library_memory_safety_proved", "arbitrary_hepta_raii_supported"))
                or not _frontend_checked(evidence.get("hepta_consumer", {}), allow_external=True)
                or not _native_build(evidence.get("hepta_native_library", {}))
                or type(evidence.get("execution_process", {}).get("returncode")) is not int
                or evidence["execution_process"]["returncode"] != 0
                or not _sha256(evidence.get("executable_sha256"))
                or json.dumps(evidence.get("execution"), sort_keys=True) != json.dumps(expected, sort_keys=True)):
            raise ValueError("Scoped C++ qualification requires the complete real lifecycle and allocation observations")
        inputs = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(EXAMPLE.iterdir()) if path.is_file()}
        bridge = evidence.get("bridge_generation", {})
        consumer = evidence["hepta_consumer"]
        library = evidence["hepta_native_library"]
        contract = _validate(json.loads((EXAMPLE / "contract.json").read_bytes()))
        cpp, header, source = _Generator((EXAMPLE / "foreign.hpp").resolve(), contract).render()
        generated = {"bridge.cpp": cpp, "bridge.h": header, "bridge.hepta": source,
                     "contract.json": json.dumps(contract, indent=2, sort_keys=True) + "\n"}
        outputs = bridge.get("outputs", {})
        if (not strict_equal(evidence.get("inputs"), inputs)
                or evidence.get("scope") != "selected_cpp_automatic_objects_with_scalar_or_POD_results"
                or bridge.get("ok") is not True or bridge.get("status") != "cpp_object_and_hepta_native_checked"
                or any(bridge.get(flag) is not False for flag in
                       ("foreign_library_soundness_proved", "borrow_retention_proved", "foreign_thread_safety_proved", "caller_pointer_validity_proved"))
                or bridge.get("header_sha256") != inputs[str((EXAMPLE / "foreign.hpp").relative_to(ROOT))]
                or bridge.get("contract_sha256") != hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                or set(outputs) != set(generated)
                or any(outputs[name].get("sha256") != hashlib.sha256(text.encode()).hexdigest()
                       or not isinstance(outputs[name].get("path"), str) or not outputs[name]["path"]
                       for name, text in generated.items())
                or consumer.get("compiler_sha256") != compiler_hash()
                or bridge.get("hepta_validation", {}).get("compiler_sha256") != compiler_hash()
                or consumer.get("source_sha256") != inputs[str((EXAMPLE / "consumer.hepta").relative_to(ROOT))]
                or bridge["hepta_validation"].get("source_sha256") != outputs["bridge.hepta"]["sha256"]
                or not _frontend_checked(bridge["hepta_validation"], allow_external=True)
                or not _integer(bridge.get("object_bytes"), 1) or not _sha256(bridge.get("object_sha256"))
                or set(evidence.get("object_sha256", {})) != {"bridge.o", "foreign.o", "harness.o"}
                or any(not _sha256(value) for value in evidence["object_sha256"].values())
                or evidence.get("hepta_library_sha256") != library["artifact_sha256"]):
            raise ValueError("Scoped C++ evidence must bind current inputs, generated bridge, compiler and linked native library")
        expected_sources = {outputs["bridge.hepta"]["path"]: outputs["bridge.hepta"]["sha256"],
                            consumer["path"]: consumer["source_sha256"]}
        if not strict_equal(consumer.get("project", {}).get("sources"), expected_sources):
            raise ValueError("Scoped Hepta consumer does not identify its actual generated bridge")
        native_build(consumer["backend"], "rust", check_only=True, crate_type="staticlib", source_sha256=consumer["rust_sha256"])
        native_build(library, "rust", check_only=False, crate_type="staticlib", source_sha256=consumer["rust_sha256"])
        bridge_native = bridge["hepta_validation"]["backend"]
        native_build(bridge_native, "rust", check_only=True, crate_type="rlib",
                     source_sha256=bridge["hepta_validation"]["rust_sha256"])
        if (consumer["backend"].get("crate_type") != "staticlib" or library.get("crate_type") != "staticlib"
                or not strict_equal(consumer["backend"]["toolchain"], library["toolchain"])
                or not strict_equal(bridge_native["toolchain"], library["toolchain"])
                or consumer["backend"]["target"] != library["target"] or bridge_native["target"] != library["target"]):
            raise ValueError("Scoped C++ native checks and linked library have different toolchain identities")
        for tool in (bridge.get("compiler", {}), library["toolchain"]):
            if (not isinstance(tool.get("version"), str) or not tool["version"]
                    or not isinstance(tool.get("path"), str) or not tool["path"]
                    or not _sha256(tool.get("executable_sha256"))
                    or hashlib.sha256(Path(tool["path"]).read_bytes()).hexdigest() != tool["executable_sha256"]):
                raise ValueError("Scoped C++ qualification tool identity changed or is missing")
        measured = evidence.get("performance", {})
        rows = measured.get("measurements", [])
        if (measured.get("status") != "measured" or len(rows) != 4
                or not _sha256(measured.get("benchmark_sha256"))
                or measured.get("scope") != "construct_append_at_and_destroy_entire_lifecycle"
                or {row.get("case") for row in rows} != {"native_cpp_lifecycle", "scoped_cpp_lifecycle", "hepta_scoped_lifecycle", "handle_cpp_lifecycle"}):
            raise ValueError("All four complete C++ lifecycle cost paths are required")
        empty = hashlib.sha256(b"").hexdigest()
        for process in (evidence["execution_process"], measured.get("process", {})):
            if (type(process.get("returncode")) is not int or process["returncode"] != 0
                    or not _sha256(process.get("stdout_sha256")) or process["stdout_sha256"] == empty
                    or process.get("stderr_sha256") != empty):
                raise ValueError("Scoped C++ native execution and timing require successful processes and retained output identities")
        for row in rows:
            if (type(row.get("iterations")) is not int or row["iterations"] != 100000 or len(row.get("samples_ns", [])) != 7
                    or any(not _integer(n, 1) for n in row["samples_ns"])
                    or type(row.get("checksum")) is not int or row["checksum"] != (100000 // 32) * sum(range(32))
                    or not _same_number(row.get("median_ns_per_lifecycle"), statistics.median(row["samples_ns"]) / 100000)):
                raise ValueError("Scoped lifecycle measurements lack valid raw samples or native checksum")
        medians = {row["case"]: row["median_ns_per_lifecycle"] for row in rows}
        ratios = measured.get("observed_median_ratios_to_native", {})
        if (set(ratios) != set(medians)
                or any(not _same_number(ratios[name], value / medians["native_cpp_lifecycle"])
                       for name, value in medians.items())):
            raise ValueError("Scoped C++ timing ratios differ from their retained raw samples")
    elif name == "independent_resource_ir":
        from hepta.resource_ir import verify_resource_ir
        projects = evidence.get("projects", [])
        if (evidence.get("schema") != "hepta.resource-qualification.v1"
                or any(evidence.get(flag) is not False for flag in
                       ("native_codegen_uses_resource_ir", "source_to_ir_refinement_proved", "whole_language_soundness_proved"))
                or evidence.get("ok") is not True or len(projects) != 3
                or {p.get("name") for p in projects} != {"owned_library", "returned_views", "owned_generics"}):
            raise ValueError("Expected three natively executed independently resource-verified projects")
        expected_entries = {"owned_library": "examples/owned/main.hepta",
                            "returned_views": "examples/resource_ir/returned_views.hepta",
                            "owned_generics": "examples/owned_generics/main.hepta"}
        retained_paths = set()
        for project in projects:
            execution = project.get("execution", {})
            native = project.get("native_gate", {})
            build = project.get("native_build", {})
            verifier = project.get("resource_verifier", {})
            inputs = project.get("inputs", {})
            if (type(execution.get("exit_code")) is not int or execution["exit_code"] != 0
                    or not _frontend_checked(native)
                    or not _native_build(native.get("backend", {}), check_only=True)
                    or not _native_build(build)
                    or not _sha256(execution.get("executable_sha256"))
                    or execution["executable_sha256"] != build["artifact_sha256"]
                    or native.get("rust_sha256") != build.get("rust_sha256")
                    or native["backend"].get("rust_sha256") != build.get("rust_sha256")
                    or verifier.get("ok") is not True or verifier.get("frontend_modules_imported") != []
                    or project.get("entry") != expected_entries[project["name"]]
                    or not isinstance(inputs, dict) or not inputs
                    or any(not _sha256(value) for value in inputs.values())
                    or inputs.get(project["entry"]) != native.get("source_sha256")):
                raise ValueError("Resource verification or real native execution did not complete")
            retained = project.get("resource_ir", {})
            if (not isinstance(retained.get("path"), str) or not retained["path"]
                    or not _integer(retained.get("bytes"), 1) or retained["bytes"] > 16 * 1024 * 1024
                    or not _sha256(retained.get("sha256")) or not _sha256(retained.get("canonical_sha256"))
                    or retained["canonical_sha256"] != verifier.get("ir_sha256")):
                raise ValueError("Each independent resource verification requires its exact retained serialized graph")
            path = Path(retained["path"])
            if not path.is_absolute():
                path = ROOT / path
            if path.resolve() in retained_paths:
                raise ValueError("Distinct resource projects cannot silently share one retained graph")
            retained_paths.add(path.resolve())
            with path.open("rb") as stream:
                data = stream.read(16 * 1024 * 1024 + 1)
            if len(data) != retained["bytes"] or hashlib.sha256(data).hexdigest() != retained["sha256"]:
                raise ValueError("Retained resource graph bytes differ from the independently checked input")
            graph = _strict_json(data)
            canonical = hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            if (canonical != retained["canonical_sha256"] or graph.get("source_sha256") != native.get("source_sha256")
                    or graph.get("project_sha256") != native.get("project", {}).get("sha256")):
                raise ValueError("Retained resource graph differs from its native source/project or canonical identity")
            replay = verify_resource_ir(graph)
            if replay.get("ok") is not True or {k: v for k, v in verifier.items() if k != "frontend_modules_imported"} != replay:
                raise ValueError("Independent replay of retained resource graph disagrees with its recorded full verification")
        generic = next(p for p in projects if p["name"] == "owned_generics")["resource_verifier"]
        if generic.get("generic_functions_checked") != 6 or generic.get("generic_calls_checked") != 16:
            raise ValueError("All abstract generic bodies and concrete/abstract generic calls must be independently checked")
        controls = {"removed_drop": "E_RIR_LEAK", "duplicate_move": "E_RIR_USE_AFTER_MOVE",
                    "drop_during_loan": "E_RIR_LOAN_CONFLICT", "loop_backedge_changes_loans": "E_RIR_JOIN",
                    "invalid_enum_payload": "E_RIR_AGGREGATE", "unknown_operation": "E_RIR_OP",
                    "borrow_escapes_local": "E_RIR_RETURN", "owned_generic_replaced_with_copy_argument": "E_RIR_GENERIC",
                    "generic_call_arguments_omitted": "E_RIR_GENERIC", "abstract_generic_destructor_omitted": "E_RIR_LEAK",
                    "callee_type_parameter_escapes_to_main": "E_RIR_GENERIC"}
        adversarial = evidence.get("adversarial_checks", [])
        if (len(adversarial) != len(controls) or {c.get("case") for c in adversarial} != set(controls)
                or any(c.get("ok") is not True or c.get("actual") != controls[c["case"]]
                       or c.get("expected") != controls[c["case"]] for c in adversarial)):
            raise ValueError("Resource IR adversarial rejection controls did not qualify")
    elif name == "crossfile_agent_fixtures":
        from experiments.crossfile_eval.tasks import ARMS, LANGUAGES, TASK_IDS
        from experiments.crossfile_eval.workspace_evidence import validate_workspace_record
        if (evidence.get("actual_ai_model_runs") != 0 or evidence.get("provider_tokens") != 0
                or evidence.get("ai_comparison_eligible") is not False
                or evidence.get("fixture_runs") != 20 or evidence.get("starter_runs") != 10
                or evidence.get("production_workspace_v4_runs") != 5 or evidence.get("workspace_errors") != []
                or evidence.get("hidden_native_cases_passed") != 1248
                or len(evidence.get("runs", [])) != 20 or len(evidence.get("starters", [])) != 10):
            raise ValueError("Cross-file fixture qualification must cover all four arms and retain its non-AI scope")
        if ({(r.get("task_id"), r.get("arm")) for r in evidence["runs"]}
                != {(task, arm) for task in TASK_IDS for arm in ARMS}
                or {(r.get("task_id"), r.get("language")) for r in evidence["starters"]}
                != {(task, language) for task in TASK_IDS for language in LANGUAGES}):
            raise ValueError("Every task, study arm and starter must appear exactly once")
        if any(r.get("status") != "fixture_scored" or r.get("score", {}).get("ok") is not True for r in evidence.get("runs", [])):
            raise ValueError("A cross-file fixture failed or did not run")
        if any(r.get("starter_compiles_without_new_contract", {}).get("ok") is not True
               or r.get("starter_fails_target_oracle") is not True for r in evidence["starters"]):
            raise ValueError("A starter failed to compile or already passed its target oracle")
        for run in evidence["runs"]:
            if run["arm"] == "hepta_protocol":
                validate_workspace_record(run, require_committed=True)
    elif name == "production_workspace_namespace":
        from experiments.crossfile_eval.tasks import TASK_IDS
        from experiments.crossfile_eval.workspace_evidence import validate_workspace_record
        if (evidence.get("run_kind") != "trusted_namespace_workspace_qualification"
                or evidence.get("environment", {}).get("available") is not True
                or evidence.get("fixture_mode") is not False or evidence.get("isolation") != "allowlisted_namespace_capsules"
                or evidence.get("actual_ai_model_runs") != 0 or evidence.get("provider_tokens") != 0
                or evidence.get("provider_receipts") != [] or evidence.get("ai_comparison_eligible") is not False
                or evidence.get("planned_workspace_fixtures") != 5 or evidence.get("strict_workspace_v4_runs") != 5
                or evidence.get("hidden_native_cases_passed") != 312 or len(evidence.get("runs", [])) != 5
                or {r.get("task_id") for r in evidence["runs"]} != set(TASK_IDS)
                or evidence.get("claims", {}).get("strict_hidden_test_namespace_isolation_exercised") is not True):
            raise ValueError("All five actual namespace workspace transactions must qualify without AI receipts")
        for run in evidence["runs"]:
            score = run.get("score", {})
            if (run.get("status") != "qualified" or run.get("actual_ai_model_runs") != 0
                    or run.get("arm") != "hepta_protocol" or run.get("fixture_mode") is not False
                    or run.get("isolation") != "allowlisted_namespace_capsules"
                    or run.get("session", {}).get("namespace_required") is not True
                    or any(event.get("namespace_required") is not True for event in run.get("session", {}).get("events", []))
                    or run.get("provider_receipts") != [] or score.get("ok") is not True
                    or score.get("compiled") is not True or score.get("native_status") != "exited"
                    or score.get("native_returncode") != 0 or score.get("source_sha256") != run.get("submitted_sha256")):
                raise ValueError("A namespace workspace task lacks successful native hidden evaluation")
            validate_workspace_record(run, require_committed=True)
    elif name == "production_workspace_crashes":
        from experiments.crossfile_eval.workspace_crash_evidence import validate_crash_matrix
        validate_crash_matrix(evidence)
    elif name == "strict_namespace_execution":
        required = {"startup", "namespace_identity", "capabilities_dropped", "empty_proc",
                    "parent_paths_unreadable", "credentials_not_inherited", "host_network_unreachable",
                    "system_files_read_only", "hepta_rust_native", "workspace_native_profile"}
        checks = evidence.get("checks", {})
        if (evidence.get("qualified") is not True or evidence.get("status") != "qualified"
                or evidence.get("ai_comparison_eligible") is not False
                or set(checks) != required
                or any(checks[name].get("status") != "passed" for name in required)):
            raise ValueError("Every real namespace, boundary and native execution check must pass")


def require_collected_qualification(name, evidence):
    """Check a producer's exact success convention and its nested evidence.

    The collector separately requires fresh output and an actual zero process
    exit. Keep this payload boundary shared with native producer regressions.
    """
    if not isinstance(evidence, dict):
        raise ValueError("Qualification evidence must be a JSON object")
    if name in {"independent_resource_ir", "partial_owned_places", "owned_c_backend", "c_project_migration", "upstream_c_modules", "stateful_c_module", "cpp_library_interop", "cpp_constructor_interop", "cpp_scoped_raii", "cpp_class_migration"}:
        if evidence.get("ok") is not True:
            raise ValueError("Required native qualification did not report ok=true")
    else:
        expected = ("qualified_fixtures_only" if name in {"agent_evaluator_fixtures", "crossfile_agent_fixtures"}
                    else "qualified_workspace_fixtures_only" if name == "production_workspace_namespace"
                    else "qualified_workspace_crash_fixtures_only" if name == "production_workspace_crashes"
                    else "qualified" if name == "strict_namespace_execution"
                    else "native_owned_implementation_and_cleanup_qualified" if name == "cpp_owned_migration"
                    else "native_composed_implementation_and_cleanup_qualified" if name == "cpp_composed_migration"
                    else "native_composed_llvm_qualified" if name == "cpp_composed_to_llvm"
                    else "passed")
        if evidence.get("status") != expected:
            raise ValueError(f"Expected evidence status {expected!r}, got {evidence.get('status')!r}")
    require_qualification(name, evidence)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path,
                        help="New evidence directory, outside source or inside artifacts/evidence; never replaced")
    parser.add_argument("--continue-on-failure", action="store_true",
                        help="Collect all gate results; any failure still fails the release")
    parser.add_argument("--qemu-aarch64", help="Actual AArch64 user emulator for the execution gate")
    args = parser.parse_args(argv)
    artifacts = args.output_directory.resolve() if args.output_directory else ROOT / "artifacts"
    if args.output_directory:
        if artifacts.is_relative_to(ROOT) and artifacts.relative_to(ROOT).parts[:1] not in {("artifacts",), ("evidence",)}:
            parser.error("Evidence may not be written into the hashed source tree")
        if artifacts.exists() or artifacts.is_symlink():
            parser.error("Evidence output directory already exists")
        artifacts.mkdir(parents=True)
    else:
        artifacts.mkdir(exist_ok=True)
    before = snapshot()
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    fixture_output = f"artifacts/agent-fixtures-{run_id}.json"
    next_stage = f"artifacts/next-stage-{run_id}"
    report = {"schema": "hepta.release.v2", "scope": "prototype-0.2-owned-migration-agent-qualified-subsets",
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_snapshot": before, "compiler_sha256": compiler_hash(), "status": "running",
              "gates": [], "evidence": {}, "whole_project_blockers_closed": False,
              "claim_scope": "executions performed by this candidate qualification; historical model studies remain separately identified",
              "claims": {"whole_language_soundness_proved": False,
                         "global_memory_budget_proved": False,
                         "physical_hardware_executed": False,
                         "general_rust_performance_superiority_established": False,
                         "actual_ai_model_runs": 0,
                         "general_agent_productivity_advantage_established": False},
              "open_production_blockers": [f"P{i:02d}" for i in range(1, 13)]}
    commands = [
        # The 2,023-test HIA baseline already took 549 seconds locally. Leave
        # room for the mandatory new native regressions; zero skips and the
        # complete terminal unittest result remain required. This is a suite
        # watchdog, not a change to any performance protocol or threshold.
        # The reconciled suite adds real guarded/graph/owner native profiles.
        # This is only the enclosing discovery wall budget; every proof,
        # candidate, runtime and economic-budget refusal remains unchanged.
        ("unit_and_integration", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], 1200),
        ("strict_namespace_execution", [sys.executable, "tools/validate_sandbox.py", "--output", next_stage + "/sandbox.json"], 120),
        ("parser_example", [sys.executable, "-m", "hepta", "run", "examples/parser.hepta", "--json"], 60),
        ("ownership_example", [sys.executable, "-m", "hepta", "run", "examples/ownership.hepta", "--json"], 60),
        ("tasks_example", [sys.executable, "-m", "hepta", "run", "examples/tasks.hepta", "--json"], 60),
        ("results_example", [sys.executable, "-m", "hepta", "run", "examples/results.hepta", "--json"], 60),
        ("owned_library_example", [sys.executable, "-m", "hepta", "run", "examples/owned/main.hepta", "--json"], 60),
        ("independent_resource_ir", [sys.executable, "-m", "tools.validate_resources", "--output", next_stage + "/resources.json"], 120),
        ("source_bound_resource_ir", [sys.executable, "-m", "tools.qualify_resource_source", next_stage + "/resources.json", "--output", next_stage + "/resource_source.json"], 120),
        ("partial_owned_places", [sys.executable, "-m", "tools.qualify_places", "--output", next_stage + "/places.json"], 120),
        ("stored_borrows", [sys.executable, "tools/qualify_borrowed_storage.py", "--output", next_stage + "/stored_borrows.json"], 120),
        ("local_stored_resource_views", [sys.executable, "-m", "tools.qualify_resource_views", "--output", next_stage + "/resource_views.json"], 120),
        ("llvm_local_stored_views", [sys.executable, "-m", "tools.qualify_llvm_local_views", "--output", next_stage + "/llvm_local_views.json"], 180),
        ("owned_c_backend", [sys.executable, "tools/validate_c_owned.py", "--output", next_stage + "/c_owned.json"], 180),
        ("c_project_migration", [sys.executable, "tools/qualify_c_migration.py", "--output", next_stage + "/c_project.json"], 120),
        ("upstream_c_modules", [sys.executable, "tools/qualify_c_algorithms.py", "--output", next_stage + "/upstream_c.json"], 120),
        ("stateful_c_module", [sys.executable, "tools/qualify_c_ring_buffer.py", "--output", next_stage + "/stateful_c.json"], 120),
        ("cpp_library_interop", [sys.executable, "tools/validate_cpp.py", "--iterations", "1000000", "--output", next_stage + "/cpp.json"], 120),
        ("cpp_constructor_interop", [sys.executable, "tools/validate_cpp_constructors.py", "--iterations", "100000", "--output", next_stage + "/cpp_constructors.json"], 180),
        ("cpp_scoped_raii", [sys.executable, "-m", "hepta.cpp_scoped", "--iterations", "100000", "--output", next_stage + "/cpp_scoped.json"], 180),
        ("cpp_class_migration", [sys.executable, "-m", "tools.validate_cpp_class", "--workdir", "artifacts/cpp-class-" + run_id, "--out", next_stage + "/cpp_class.json"], 180),
        ("cpp_owned_migration", [sys.executable, "-m", "tools.validate_cpp_owned", "--workdir", "artifacts/cpp-owned-" + run_id, "--out", next_stage + "/cpp_owned.json"], 180),
        ("cpp_owned_to_llvm", [sys.executable, "-m", "tools.qualify_cpp_owned_llvm", "--workdir", "artifacts/cpp-owned-llvm-" + run_id, "--output", next_stage + "/cpp_owned_llvm.json"], 180),
        ("cpp_composed_migration", [sys.executable, "-m", "tools.validate_cpp_composed", "--workdir", "artifacts/cpp-composed-" + run_id, "--out", next_stage + "/cpp_composed.json"], 240),
        ("cpp_composed_to_llvm", [sys.executable, "-m", "tools.qualify_cpp_composed_llvm", "--workdir", "artifacts/cpp-composed-llvm-" + run_id, "--output", next_stage + "/cpp_composed_llvm.json"], 240),
        ("cpp_upstream_upgrade", [sys.executable, "-m", "tools.qualify_cpp_upgrade", "--workdir", "artifacts/cpp-upgrade-" + run_id, "--output", next_stage + "/cpp_upgrade.json"], 180),
        ("locked_package_example", [sys.executable, "-m", "hepta", "run", "examples/packages/app", "--locked", "--json"], 60),
        ("bounded_concurrency", [sys.executable, "tools/validate_groups.py", "--repeats", "3", "--output", "evidence/groups/native_validation.json"], 180),
        ("shared_runtime", [sys.executable, "tools/validate_shared_runtime.py", "--repeats", "3", "--output", next_stage + "/shared_runtime.json"], 180),
        ("independent_concurrent_ir", [sys.executable, "tools/validate_concurrent_ir.py", "--output", next_stage + "/concurrent_ir.json"], 180),
        ("structured_task_trees", [sys.executable, "tools/validate_task_tree.py", "--repeats", "3", "--output", next_stage + "/task_trees.json"], 180),
        ("bounded_async_io", [sys.executable, "tools/validate_io.py", "--repeats", "3", "--output", next_stage + "/async_io.json"], 180),
        ("task_io_composition", [sys.executable, "-m", "tools.qualify_task_io", "--repeats", "3", "--output", next_stage + "/task_io_composition.json"], 180),
        ("abi_matrix", [sys.executable, "tools/abi_fuzz.py", "--output", "artifacts/abi-matrix.json"], 180),
        ("native_host_abi", [sys.executable, "tools/validate_native_host.py", "--expected-system", "Linux", "--expected-machine", "x86_64", "--output", next_stage + "/native_host.json"], 180),
        ("native_debugger", [sys.executable, "tools/validate_debugger.py", "--output", next_stage + "/debugger.json"], 120),
        ("native_and_performance", [sys.executable, "tools/validate.py", "--bench", "--output", "artifacts/native-validation.json"], 180),
        ("representative_performance", [sys.executable, "tools/benchmark_suite.py", "--output", "artifacts/representative-benchmarks.json"], 240),
        ("application_performance", [sys.executable, "tools/benchmark_applications.py", "--output", next_stage + "/applications.json"], 180),
        ("llvm_owned_rust_allocator", [sys.executable, "-m", "tools.qualify_llvm_owned_rust_allocator", "--output", next_stage + "/llvm_owned_rust_allocator.json"], 120),
        ("llvm_native_performance", [sys.executable, "tools/qualify_llvm_native.py", "--output", next_stage + "/llvm_native.json"], 180),
        ("llvm_owned_performance", [sys.executable, "-m", "tools.qualify_llvm_owned", "--output", next_stage + "/llvm_owned.json"], 300),
        ("formal_core", [sys.executable, "tools/verify_formal.py", "--output", "artifacts/formal-validation.json"], 180),
        ("provenance_and_type_core", [sys.executable, "tools/verify_memory.py", "--output", next_stage + "/memory_proofs.json"], 180),
        ("aarch64_execution", [sys.executable, "tools/validate_cross.py", "--output", "artifacts/cross-execution.json"], 120),
        ("system_board", [sys.executable, "tools/validate_board.py", "--output", next_stage + "/system_board.json"], 120),
        ("agent_evaluator_fixtures", [sys.executable, "-m", "experiments.agent_eval", "qualify-fixtures", "--output", fixture_output], 240),
        ("crossfile_agent_fixtures", [sys.executable, "-m", "experiments.crossfile_eval", "qualify-fixtures", "--output", next_stage + "/crossfile_agent.json"], 360),
        ("production_workspace_namespace", [sys.executable, "-m", "experiments.crossfile_eval", "qualify-workspace", "--execution-context", "release_check.py in caller-selected host execution context; namespace requirements enforced", "--output", next_stage + "/workspace_namespace.json"], 240),
        ("production_workspace_crashes", [sys.executable, "-m", "experiments.crossfile_eval", "qualify-workspace-crashes", "--execution-context", "release_check.py in caller-selected host execution context; namespace requirements enforced", "--output", next_stage + "/workspace_crashes.json"], 360),
    ]
    evidence_outputs = {
        "bounded_concurrency": "evidence/groups/native_validation.json",
        "abi_matrix": "artifacts/abi-matrix.json",
        "native_and_performance": "artifacts/native-validation.json",
        "representative_performance": "artifacts/representative-benchmarks.json",
        "application_performance": next_stage + "/applications.json",
        "llvm_owned_rust_allocator": next_stage + "/llvm_owned_rust_allocator.json",
        "llvm_native_performance": next_stage + "/llvm_native.json",
        "llvm_owned_performance": next_stage + "/llvm_owned.json",
        "formal_core": "artifacts/formal-validation.json",
        "aarch64_execution": "artifacts/cross-execution.json",
        "agent_evaluator_fixtures": fixture_output,
        "independent_resource_ir": next_stage + "/resources.json",
        "source_bound_resource_ir": next_stage + "/resource_source.json",
        "partial_owned_places": next_stage + "/places.json",
        "stored_borrows": next_stage + "/stored_borrows.json",
        "local_stored_resource_views": next_stage + "/resource_views.json",
        "llvm_local_stored_views": next_stage + "/llvm_local_views.json",
        "owned_c_backend": next_stage + "/c_owned.json",
        "shared_runtime": next_stage + "/shared_runtime.json",
        "independent_concurrent_ir": next_stage + "/concurrent_ir.json",
        "structured_task_trees": next_stage + "/task_trees.json",
        "bounded_async_io": next_stage + "/async_io.json",
        "task_io_composition": next_stage + "/task_io_composition.json",
        "system_board": next_stage + "/system_board.json",
        "native_host_abi": next_stage + "/native_host.json",
        "native_debugger": next_stage + "/debugger.json",
        "provenance_and_type_core": next_stage + "/memory_proofs.json",
        "c_project_migration": next_stage + "/c_project.json",
        "upstream_c_modules": next_stage + "/upstream_c.json",
        "stateful_c_module": next_stage + "/stateful_c.json",
        "cpp_library_interop": next_stage + "/cpp.json",
        "cpp_constructor_interop": next_stage + "/cpp_constructors.json",
        "cpp_scoped_raii": next_stage + "/cpp_scoped.json",
        "cpp_class_migration": next_stage + "/cpp_class.json",
        "cpp_owned_migration": next_stage + "/cpp_owned.json",
        "cpp_owned_to_llvm": next_stage + "/cpp_owned_llvm.json",
        "cpp_composed_migration": next_stage + "/cpp_composed.json",
        "cpp_composed_to_llvm": next_stage + "/cpp_composed_llvm.json",
        "cpp_upstream_upgrade": next_stage + "/cpp_upgrade.json",
        "crossfile_agent_fixtures": next_stage + "/crossfile_agent.json",
        "strict_namespace_execution": next_stage + "/sandbox.json",
        "production_workspace_namespace": next_stage + "/workspace_namespace.json",
        "production_workspace_crashes": next_stage + "/workspace_crashes.json",
    }
    # Relocate every generated evidence file together, including the legacy
    # fixed-path reports. Retained graph directories follow their own output
    # file. This avoids rewriting historical evidence during a new candidate
    # qualification and permits native builds in a RAM-backed temporary area.
    if args.output_directory:
        recorded_directory = artifacts.relative_to(ROOT) if artifacts.is_relative_to(ROOT) else artifacts
        replacements = {old: str(recorded_directory / Path(old).name)
                        for old in evidence_outputs.values()}
        if len(set(replacements.values())) != len(replacements):
            parser.error("Evidence filenames collide")
        commands = [(name, [replacements.get(part, part) for part in command], timeout)
                    for name, command, timeout in commands]
        evidence_outputs = {name: replacements[path] for name, path in evidence_outputs.items()}
    if args.qemu_aarch64:
        commands = [(name, command + (["--qemu", args.qemu_aarch64] if name == "aarch64_execution" else []), timeout)
                    for name, command, timeout in commands]
    report["planned_gates"] = [name for name, _, _ in commands]
    report["continue_on_failure"] = args.continue_on_failure
    git_identity = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                  capture_output=True, text=True)
    report["source_git_commit"] = git_identity.stdout.strip() if git_identity.returncode == 0 else None
    for name, command, timeout in commands:
        started = time.monotonic()
        evidence_path = ROOT / evidence_outputs[name] if name in evidence_outputs else None
        # Default legacy locations can already contain old evidence. A command
        # returning zero without replacing that file cannot credit the old run
        # to this candidate. Native tools are trusted producers, not adversaries
        # able to fake filesystem timestamps.
        previous_identity, previous_error = None, None
        if evidence_path is not None:
            try:
                previous_identity = _evidence_state(evidence_path)
            except OSError as exc:
                previous_error = str(exc)
        unit_stderr = ""
        try:
            p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
            unit_stderr = p.stderr
            text = p.stdout + p.stderr
            gate = {"name": name, "command": command, "exit_code": p.returncode,
                    "status": "passed" if type(p.returncode) is int and p.returncode == 0 else "failed"}
        except subprocess.TimeoutExpired as exc:
            text = str(exc)
            gate = {"name": name, "command": command, "status": "unknown_timeout"}
            # TimeoutExpired retains captured output, sometimes as bytes even
            # with text=True. Keep exact bytes as well as the readable gate log.
            gate["partial_output"] = {}
            for stream, value in (("stdout", exc.stdout), ("stderr", exc.stderr)):
                if value is None:
                    continue
                data = value if isinstance(value, bytes) else value.encode("utf-8")
                captured = artifacts / (name + ".partial." + stream)
                captured.write_bytes(data)
                gate["partial_output"][stream] = {
                    "path": str(captured.relative_to(ROOT)) if captured.is_relative_to(ROOT) else str(captured),
                    "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                text += "\n" + stream + ":\n" + data.decode("utf-8", errors="replace")
        except OSError as exc:
            text = str(exc)
            gate = {"name": name, "command": command, "status": "environment_error"}
        log = artifacts / (name + ".log")
        log.write_text(text)
        gate.update({"seconds": round(time.monotonic() - started, 3),
                     "log": str(log.relative_to(ROOT)) if log.is_relative_to(ROOT) else str(log),
                     "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
        if name == "unit_and_integration":
            gate["test_count"] = _unittest_passed_count(unit_stderr)
            skipped = re.search(r"(?m)^OK \([^\n]*skipped=([0-9]+)[^\n]*\)\r?\n?\Z", unit_stderr)
            gate["skipped"] = int(skipped.group(1)) if skipped else 0
            if gate["status"] == "passed" and gate["test_count"] == 0:
                gate["status"] = "failed"
                gate["reason"] = "Release requires terminal unittest OK on stderr, nonzero tests and zero skips"
        if name in evidence_outputs:
            retained = None
            try:
                evidence_bytes, identity = _read_regular_evidence(evidence_path)
                if previous_error is not None:
                    raise ValueError("E_STALE_GATE_EVIDENCE: initial path state unavailable: " + previous_error)
                retained = {"sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                            "bytes": len(evidence_bytes), "gate": name,
                            "fresh": previous_identity is None or identity != previous_identity}
                report["evidence"][evidence_outputs[name]] = retained
                gate["evidence"] = evidence_outputs[name]
                evidence = _strict_json(evidence_bytes)
                if not isinstance(evidence, dict):
                    raise ValueError("Qualification evidence must be a JSON object")
                if not retained["fresh"]:
                    raise ValueError("Evidence was not refreshed by this gate; a previous run cannot qualify the current candidate")
                if gate["status"] != "passed":
                    raise ValueError("Gate command did not succeed; retained failure evidence is not qualification")
                require_collected_qualification(name, evidence)
                retained["validation_status"] = "passed"
            except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError,
                    OverflowError, RecursionError, RuntimeError) as exc:
                if gate["status"] == "passed":
                    gate["status"] = "failed"
                gate["validation_error"] = str(exc)
                gate.setdefault("reason", str(exc))
                if retained is not None:
                    retained.update(validation_status="failed", validation_error=str(exc))
        report["gates"].append(gate)
        print(json.dumps(gate), flush=True)
        if gate["status"] != "passed" and not args.continue_on_failure:
            break
    after = snapshot()
    report["source_snapshot_after"] = after
    before_files, after_files = before["files"], after["files"]
    report["source_snapshot_changes"] = {
        "added": sorted(set(after_files) - set(before_files)),
        "removed": sorted(set(before_files) - set(after_files)),
        "modified": sorted(name for name in before_files.keys() & after_files.keys()
                           if before_files[name] != after_files[name]),
    }
    report["snapshot_unchanged"] = before == after
    report["status"] = "passed" if len(report["gates"]) == len(commands) and all(g["status"] == "passed" for g in report["gates"]) and before == after else "failed"
    report["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (artifacts / "release-validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": report["status"], "source_snapshot_sha256": before["sha256"], "whole_project_blockers_closed": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
