#!/usr/bin/env python3
"""Render terminal f5 receipts without executing Hepta, tests or benchmarks.

Run only after the two supervisors have terminated and the raw packager has
created its indexes. A failed terminal run is reportable; a live/unreaped
process is not. This is a bounded report reader, not a replacement qualifier.
Existing output directories are allowed, but all four authored filenames must
be absent. No archive, log, part, audit or historical source is modified.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat

SOURCE = "f5b6598bdd88db92c4ef2b17e10deda9a90bdd59"
HISTORICAL_SOURCE = "de49fe3e0254b7b71dbcb5b2907a3f3145999393"
NDU_SOURCE = "b92141483ca5084691f436d28d4cd0dcbefe4717"
PROFILE = "hosted-native-lifecycle-30m.v1"
OUTPUT_NAMES = ("results.json", "REPORT.zh-CN.md", "README.md", "blockers.json")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TOTAL_READ_BYTES = 96 * 1024 * 1024
GATES = (
    "unit_regression", "rust_shadow_cargo", "rust_shadow_parity", "agent_query_semantics",
    "standalone_native", "standalone_resources", "composite_resources", "composite_bulk_targets",
    "recursive_resource_chains", "source_migration", "cpp_template_migration", "c_configuration_matrix",
    "cpp_configuration_matrix", "upstream_c_resource_matrix", "upstream_cpp_composed_lifetimes",
    "cpp_composed_implementation_llvm", "llvm_local_stored_views", "task_io_composition",
    "selected_core_formal", "standalone_aarch64_qemu", "standalone_riscv64_qemu",
    "legacy_executable_core", "legacy_hosted_composition", "legacy_cortex_m4_qemu",
    "bounded_concurrency", "shared_runtime", "independent_concurrent_ir", "structured_task_trees",
    "bounded_async_io", "native_host_gcc", "native_host_clang", "provenance_and_type_core",
    "formal_core", "application_performance", "standalone_performance",
)
FINITE_GATES = {
    "P0-CURRENT-SOURCE": ("unit_regression", "agent_query_semantics", "legacy_executable_core"),
    "P2-CURRENT-SOURCE-EQUIVALENCE": (
        "unit_regression", "rust_shadow_cargo", "rust_shadow_parity", "standalone_native",
        "standalone_resources", "composite_resources", "composite_bulk_targets", "recursive_resource_chains",
        "cpp_composed_implementation_llvm", "llvm_local_stored_views", "selected_core_formal",
        "standalone_aarch64_qemu", "standalone_riscv64_qemu", "legacy_executable_core",
        "legacy_hosted_composition", "provenance_and_type_core", "formal_core"),
    "P6-CURRENT-CLEANUP-RECEIPT": ("unit_regression", "standalone_resources"),
}
RETENTION = ("single-epoch", "failed-spawn", "cleanup-owner-negative",
             "finalizer-statistics", "finalizer-close", "finalizer-constructor")
COUNT_NAMES = ("attempted_calls", "child_processes_started", "child_processes_reaped",
               "completed_observations", "native_entries_observed", "unavailable_child_start_outcomes",
               "unavailable_native_entry_outcomes", "unconfirmed_child_reaps")
PROFILE_BOUNDARIES = {
    "max_wall_seconds": 1800.0, "new_epoch_deadline_seconds": 1620.0, "max_epochs": 512,
    "max_attempted_calls": 16896, "minimum_observation_seconds": 1500.0,
    "minimum_completed_epochs": 128, "minimum_completed_observations": 5000,
    "max_evidence_bytes": 96 * 1024 * 1024,
    "max_concurrent_calls": 2, "max_pacing_fraction": 0.6,
}
RAW_ROOTS = {
    "frozen/system": "validation-v7-soak-frozen", "frozen/soak": "validation-runtime-soak-frozen",
    "development/ndu-v7": "validation-ndu-v7-next", "development/soak": "validation-runtime-soak-next",
    "independent/soak-lifecycle": "validation-runtime-soak-review",
    "integration-and-access": "validation-next-blockers", "independent/final": "validation-v7-soak-audits",
}


def require(condition, message):
    if condition is not True:
        raise ValueError("E_V7_SOAK_REPORT: " + message)


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(value):
    return type(value) is int and value >= 0


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value
    def constant(value):
        raise ValueError("nonfinite JSON constant: " + value)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    wire(value)  # Reject finite-looking overflowing literals as well.
    return value


class Reader:
    def __init__(self, base, output):
        self.base, self.output = base, output
        self.inputs, self.archive_members, self.raw = {}, {}, {}
        self.total = 0

    def archive_name(self, path):
        for prefix, root in RAW_ROOTS.items():
            try:
                return prefix + "/" + path.relative_to(self.base / root).as_posix()
            except ValueError:
                pass
        return None

    def bytes(self, path):
        path = path.absolute()
        if str(path) in self.raw:
            return self.raw[str(path)]
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_JSON_BYTES,
                "expected bounded regular input: " + str(path))
        with path.open("rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        after = path.stat()
        require(len(raw) == info.st_size and (info.st_ino, info.st_mtime_ns, info.st_size) ==
                (after.st_ino, after.st_mtime_ns, after.st_size), "input changed during read: " + str(path))
        self.total += len(raw)
        require(self.total <= MAX_TOTAL_READ_BYTES, "bounded small-receipt read budget exceeded")
        ref = {"path": str(path), "sha256": sha(raw), "bytes": len(raw)}
        archive = self.archive_name(path)
        if archive is not None:
            ref["archive_member"] = archive
            if self.archive_members:
                member = self.archive_members.get(archive)
                require(member is not None and member["sha256"] == ref["sha256"] and member["bytes"] == len(raw),
                        "input differs from packaged raw member: " + archive)
        self.inputs[str(path)], self.raw[str(path)] = ref, raw
        return raw

    def json(self, path):
        value = strict_json(self.bytes(path))
        require(type(value) is dict, "expected JSON object: " + str(path))
        return value

    def maybe(self, path):
        try:
            return {"available": True, "value": self.json(path)}
        except (OSError, ValueError, TypeError, RecursionError) as error:
            return {"available": False, "error": {"type": type(error).__name__, "message": str(error)},
                    "path": str(path)}

    def ref(self, path):
        return dict(self.inputs[str(path.absolute())])

    def stable(self):
        for path, raw in self.raw.items():
            info = Path(path).lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size == len(raw)
                    and Path(path).read_bytes() == raw, "input changed before report creation: " + path)


def package(reader):
    output = reader.output
    manifest = reader.json(output / "raw-evidence-manifest.json")
    parts = reader.json(output / "raw-evidence-parts.json")
    index = reader.json(output / "source-run-index.json")
    require(manifest.get("schema") == "hepta.hia.v7-soak-raw-manifest.v1"
            and manifest.get("source_commit") == SOURCE and index.get("tested_source_commit") == SOURCE,
            "raw indexes must bind the fixed f5 source")
    require(index.get("schema") == "hepta.hia.v7-soak-source-runs.v1"
            and parts.get("schema") == "hepta.hia.evidence-transport-parts.v1", "raw index schema differs")
    members = manifest["members"]
    require(type(members) is list and len(members) == manifest["file_count"], "raw member count differs")
    for row in members:
        name = row["path"]
        require(type(name) is str and not Path(name).is_absolute() and ".." not in Path(name).parts
                and name not in reader.archive_members and integer(row["bytes"]), "raw member identity differs")
        reader.archive_members[name] = row
    require(sum(row["bytes"] for row in members) == manifest["uncompressed_bytes"], "raw byte inventory differs")
    offset = 0
    for number, row in enumerate(parts["parts"]):
        require(row["path"] == f"raw-evidence.parts/part-{number:04d}.bin" and row["offset"] == offset
                and integer(row["bytes"]) and 0 < row["bytes"] <= parts["part_bytes_maximum"], "parts continuity differs")
        offset += row["bytes"]
    archived = parts["archive"]
    require(offset == archived["bytes"] and all(manifest["archive"][key] == archived[key]
            for key in ("path", "bytes", "sha256")), "raw archive identity differs")
    require(manifest["archive"].get("all_members_reopened_and_verified") is True,
            "packager did not record archived-member verification")
    return {"source_run_index": index, "archive": archived, "part_count": len(parts["parts"]),
            "member_count": len(members), "uncompressed_bytes": manifest["uncompressed_bytes"],
            "manifest": reader.ref(output / "raw-evidence-manifest.json"),
            "parts_index": reader.ref(output / "raw-evidence-parts.json"),
            "index": reader.ref(output / "source-run-index.json"),
            "archive_and_parts_reread_by_reporter": False,
            "scope": "Report reads small indexes and matches every consumed raw receipt to the packaged member identity; archive verification belongs to the packager."}


def terminal_steps(reader, directory, summary, field, names):
    require(summary.get("status") in {"completed", "failed", "interrupted", "registration_failed"},
            "outer supervisor is not recorded as terminal: " + str(directory))
    listed = summary.get(field, [])
    require(type(listed) is list and len({row["name"] for row in listed}) == len(listed), "duplicate outer step")
    by_name = {row["name"]: row for row in listed}
    require(set(by_name) <= set(names), "unrecognized outer step")
    rows = []
    for name in names:
        path = directory / (name + ".process.json")
        if name not in by_name and not path.exists():
            require(summary["status"] != "completed", "completed outer receipt is missing step: " + name)
            rows.append({"name": name, "started": False, "completion_known": False,
                         "disposition": "not_recorded_after_terminal_outer_failure"})
            continue
        process = reader.json(path)
        require(process.get("name") == name and process.get("process_completion_confirmed") is True
                and type(process.get("returncode")) is int,
                "step completion is unconfirmed; retain owner, do not finalize report: " + name)
        if name in by_name:
            require(wire(process) == wire(by_name[name]), "outer summary and process receipt differ: " + name)
        rows.append({**process, "started": True, "completion_known": True, "receipt": reader.ref(path)})
    return rows


def integrity(reader, directory, summary, source_field):
    require(summary.get(source_field) == SOURCE, "final supervisor is bound to another source")
    records = {name: reader.maybe(directory / (name + ".json")) for name in
               ("source-before", "source-after", "tools-before", "tools-after")}
    known = all(row["available"] for row in records.values())
    matched = False
    if known:
        before, after = records["source-before"]["value"], records["source-after"]["value"]
        matched = (before.get("git_head") == SOURCE and before.get("worktree_clean") is True
                   and before.get("tracked_files_match_commit") is True and wire(before) == wire(after)
                   and wire(records["tools-before"]["value"]) == wire(records["tools-after"]["value"]))
    passed = known and matched and summary.get("source_unchanged") is True and summary.get("tools_unchanged") is True
    return {"known": known, "qualified_identity": passed,
            "source_unchanged_recorded": summary.get("source_unchanged"),
            "tools_unchanged_recorded": summary.get("tools_unchanged"),
            "unavailable": {key: row for key, row in records.items() if not row["available"]}}


def count_summary(payload):
    counts = payload.get("counts") if isinstance(payload, dict) else None
    if not isinstance(counts, dict):
        return {"available": False, "values": None, "internally_consistent": False}
    known = all(integer(counts.get(key)) for key in COUNT_NAMES)
    if known:
        expected_entries = None if counts["unavailable_native_entry_outcomes"] else counts["native_entries_observed"]
        known = (counts.get("child_process_start_count_complete") is (counts["unavailable_child_start_outcomes"] == 0)
                 and wire(counts.get("native_entry_invocations")) == wire(expected_entries))
    return {"available": True, "values": counts, "internally_consistent": known,
            "entry_unknown_preserved": counts.get("native_entry_invocations") is None}


def unit_summary(value):
    if value is None:
        return {"available": False, "complete_ids": False, "ok": False}
    modules = value.get("modules", [])
    expected, discovered, started, finished, counters = [], value.get("discovered_ids", []), [], [], Counter()
    missing = []
    selected = {}
    for row in modules:
        expected.extend(row.get("expected_ids", []))
        child = row.get("child")
        if not isinstance(child, dict):
            missing.append(row.get("module"))
            continue
        started.extend(child.get("started_ids", []))
        finished.extend(child.get("finished_ids", []))
        for name in ("tests_run", "failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
            if integer(child.get(name)):
                counters[name] += child[name]
            else:
                missing.append(str(row.get("module")) + ":" + name)
        if row.get("module") in {"test_hia_ndu_v7", "test_hia_native_runtime_soak"}:
            selected[row["module"]] = {"passed": row.get("passed"), "returncode": row.get("returncode"),
                                      "child": child, "child_receipt": row.get("child_receipt")}
    complete = (not missing and len(set(expected)) == len(expected) and len(set(discovered)) == len(discovered)
                and len(set(started)) == len(started) and len(set(finished)) == len(finished)
                and set(expected) == set(discovered) == set(started) == set(finished)
                and value.get("expected_module_count") == value.get("completed_module_count") == len(modules)
                and value.get("reported_tests_run") == counters["tests_run"] == len(finished)
                and value.get("id_inventory_sha256") == sha(wire(sorted(discovered))))
    return {"available": True, "schema": value.get("schema"), "status": value.get("status"),
            "ok": value.get("ok") is True, "complete_ids": complete, "unique_finished_ids": len(set(finished)),
            "module_count": len(modules), "reported_tests_run": value.get("reported_tests_run"),
            "observed_counts": dict(counters), "missing_count_outcomes": missing,
            "id_inventory_sha256": value.get("id_inventory_sha256"), "selected_modules": selected,
            "scope": "Embedded final module ID lists checked for missing/duplicate/unfinished IDs; this reporter does not rerun tests or independently discover tests from source."}


def payload_or_failure(reader, path, process):
    row = reader.maybe(path)
    if not row["available"]:
        return None, row
    value = row["value"]
    expected = process.get("report_sha256")
    if expected is not None and expected != reader.ref(path)["sha256"]:
        return None, {"available": False, "path": str(path), "error": {"type": "IdentityMismatch",
                      "message": "producer report differs from terminal process reference"}}
    # A retained running checkpoint belongs to a terminated producer if wait
    # was confirmed. It is a failed/incomplete receipt, not a live process.
    return value, {"available": True, "receipt": reader.ref(path),
                   "terminal_producer_incomplete": value.get("status") in {"running", "starting", "pending"}}


def system_run(reader, packaged):
    directory = reader.base / "validation-v7-soak-frozen"
    summary = reader.json(directory / "summary.json")
    require(summary.get("schema") == "hepta.hia.system-closure-frozen-run.v1", "system schema differs")
    require(reader.ref(directory / "summary.json")["sha256"] == packaged["source_run_index"]["system"]["sha256"],
            "packaged system summary differs")
    rows = terminal_steps(reader, directory, summary, "gates", ("unified", "native_loans"))
    by_name = {row["name"]: row for row in rows}
    identity = integrity(reader, directory, summary, "git_head")
    unified, unified_read = payload_or_failure(reader, directory / "unified/qualification.json", by_name["unified"])
    gates = []
    if unified is not None:
        require(unified.get("git_commit") == SOURCE and unified.get("schema") == "hepta.hia.unified-qualification.v4",
                "unified source/schema differs")
        for row in unified.get("gates", []):
            require(row.get("name") in GATES and type(row.get("passed")) is bool, "invalid unified gate")
            evidence = row.get("evidence")
            if isinstance(evidence, dict) and evidence.get("path") is not None:
                name = "frozen/system/unified/" + evidence["path"]
                member = reader.archive_members.get(name)
                require(member is not None and member["sha256"] == evidence["sha256"], "gate raw evidence absent/different: " + name)
            gates.append(row)
        require(len({row["name"] for row in gates}) == len(gates), "duplicate unified gate")
    gate_map = {row["name"]: row for row in gates}
    gate_complete = tuple(row["name"] for row in gates) == GATES
    unit = None
    if isinstance(gate_map.get("unit_regression", {}).get("evidence"), dict):
        unit_path = directory / "unified" / gate_map["unit_regression"]["evidence"]["path"]
        unit_read = reader.maybe(unit_path)
        unit = unit_read.get("value")
    unit = unit_summary(unit)
    loan, loan_read = payload_or_failure(reader, directory / "native-loans/report.json", by_name["native_loans"])
    loan = loan or {}
    if loan:
        require(loan.get("git_commit") == SOURCE and loan.get("schema") == "hepta.hia.native-loan-qualification.v2",
                "native loan source/schema differs")
    counts = count_summary(loan)
    loan_pass = (identity["qualified_identity"] and by_name["native_loans"].get("returncode") == 0
                 and by_name["native_loans"].get("scoped_pass") is True and loan.get("ok") is True
                 and loan.get("execution_passed") is True and loan.get("source_unchanged") is True
                 and loan.get("close", {}).get("drained") is True
                 and loan.get("final_dispatch", {}).get("drained") is True and counts["internally_consistent"])
    if loan_pass:
        values = counts["values"]
        loan_pass = (all(values[key] == 7 for key in ("attempted_calls", "child_processes_started",
                    "child_processes_reaped", "completed_observations")) and values["unconfirmed_child_reaps"] == 0)
    performance = {}
    for name in ("application_performance", "standalone_performance"):
        gate = gate_map.get(name)
        if gate is None or not isinstance(gate.get("evidence"), dict):
            performance[name] = {"available": False, "gate": gate}
            continue
        path = directory / "unified" / gate["evidence"]["path"]
        read = reader.maybe(path)
        value = read.get("value", {})
        retained = ("status", "ok", "evaluation", "claims", "compile_wall_seconds", "interference_observations",
                    "summary", "all_observed_slowdowns", "timing_contract", "trials", "requests_per_trial", "warmups")
        performance[name] = {"available": read["available"], "gate_passed": gate["passed"],
                             "receipt": reader.inputs.get(str(path)), "observations": {k: value[k] for k in retained if k in value},
                             "raw_sample_count": len(value["raw_samples"]) if isinstance(value.get("raw_samples"), list) else None}
        if not read["available"]:
            performance[name]["read_error"] = read["error"]
    return {"summary": summary, "summary_ref": reader.ref(directory / "summary.json"), "steps": rows,
            "integrity": identity, "unified_read": unified_read, "unified_status": (unified or {}).get("status"),
            "unified_ok": (unified or {}).get("ok"), "gate_inventory_complete": gate_complete,
            "completed_gates": len(gates), "passed_gates": sum(row["passed"] for row in gates),
            "failed_gates": [row["name"] for row in gates if not row["passed"]],
            "not_completed_gates": [name for name in GATES if name not in gate_map], "gates": gates,
            "unit": unit, "performance": performance,
            "native_loans": {"qualified": loan_pass, "status": loan.get("status"), "read": loan_read,
                             "counts": counts, "final_drained": loan.get("final_dispatch", {}).get("drained"),
                             "close": loan.get("close"), "source_unchanged": loan.get("source_unchanged"),
                             "diagnostic_instrumentation": True, "whole_resource_ledger": False}}


def soak_run(reader, packaged):
    directory = reader.base / "validation-runtime-soak-frozen"
    summary = reader.json(directory / "summary.json")
    require(summary.get("schema") == "hepta.hia.native-soak-frozen-process.v1"
            and summary.get("profile_id") == PROFILE, "soak supervisor schema/profile differs")
    require(reader.ref(directory / "summary.json")["sha256"] == packaged["source_run_index"]["soak"]["sha256"],
            "packaged soak summary differs")
    rows = terminal_steps(reader, directory, summary, "steps", ("register", "run", "validate"))
    by_name = {row["name"]: row for row in rows}
    identity = integrity(reader, directory, summary, "source_commit")
    registration = reader.maybe(directory / "registration.json")
    registered = registration.get("value", {})
    profile = registered.get("profile", {})
    registration_ok = (registration["available"] and registered.get("source", {}).get("git_commit") == SOURCE
                       and registered.get("source", {}).get("git_status") == "" and profile.get("profile_id") == PROFILE
                       and profile.get("formal_qualification") is True and all(type(profile.get(key)) is type(value)
                           and profile[key] == value for key, value in PROFILE_BOUNDARIES.items()))
    if registration["available"]:
        registration_ok = registration_ok and summary.get("registration", {}).get("sha256") == reader.ref(directory / "registration.json")["sha256"]
    producer, producer_read = payload_or_failure(reader, directory / "run/report.json", {})
    producer = producer or {}
    if producer:
        require(producer.get("source_git_commit") == SOURCE and producer.get("schema") == "hepta.hia.native-runtime-soak.v2",
                "native soak producer source/schema differs")
        if summary.get("producer", {}).get("sha256") is not None:
            require(summary["producer"]["sha256"] == reader.ref(directory / "run/report.json")["sha256"],
                    "native soak report differs from supervisor reference")
    counts = count_summary(producer)
    timing = producer.get("timing", {})
    duration, pacing = timing.get("observation_wall_ns"), timing.get("explicit_pacing_wait_ns")
    values = counts.get("values") or {}
    epochs = producer.get("completed_epochs")
    minima = (integer(duration) and integer(pacing) and 1500 * 10**9 <= duration <= 1800 * 10**9 and pacing <= duration * .6
              and integer(epochs) and 128 <= epochs <= 512 and counts["internally_consistent"]
              and values["completed_observations"] >= 5000 and values["unconfirmed_child_reaps"] == 0)
    qualified = (summary.get("ok") is True and identity["qualified_identity"] and registration_ok
                 and all(by_name[name].get("completion_known") is True and by_name[name].get("returncode") == 0 for name in by_name)
                 and producer.get("ok") is True and producer.get("execution_passed") is True
                 and producer.get("registration_sha256") == summary.get("registration", {}).get("sha256")
                 and producer.get("status") == "passed" and producer.get("drained") is True
                 and producer.get("source_unchanged") is True and producer.get("tools_unchanged") is True and minima)
    return {"summary": summary, "summary_ref": reader.ref(directory / "summary.json"), "steps": rows,
            "integrity": identity, "registration_available": registration["available"], "registration_bound": registration_ok,
            "registered_profile": profile, "qualified": qualified, "producer_read": producer_read,
            "producer": {key: producer[key] for key in ("schema", "status", "ok", "execution_passed", "failure", "failure_phase", "drained",
                "stop_reason", "completed_epochs", "progress_wall_ns", "total_wall_ns", "counts", "case_counts",
                "timing", "resources", "cleanup_recovery", "journal", "evidence_write_error", "source_unchanged", "tools_unchanged") if key in producer},
            "counts": counts, "minimum_duration_work_and_pacing_satisfied": minima,
            "scope": "One registered finite diagnostic hosted profile; no production P7-LONGLOAD, performance gain or service SLO qualification."}


def historical_and_roadmap(reader, current, soak):
    directory = reader.base / "hepta/evidence/hia_system_closure_20261028"
    previous = reader.json(directory / "results.json")
    blockers = reader.json(directory / "blockers.json")
    require(previous.get("current_source_commit") == HISTORICAL_SOURCE, "historical result source differs")
    obligations = [(stage, row) for stage in blockers["stages"] for row in stage["blockers"]]
    require(len(obligations) == 17 and sum(row["state"] == "closed_in_declared_profile" for _, row in obligations) == 3,
            "historical seventeen-obligation ledger differs")
    require({row["id"] for _, row in obligations if row["state"] == "closed_in_declared_profile"} == set(FINITE_GATES),
            "historical finite obligation identities differ")
    require(len(previous.get("ndu_attempts", [])) == 2 and all(row.get("source_commit") == NDU_SOURCE
            for row in previous["ndu_attempts"]), "historical two-attempt NDU identity differs")
    gates = {row["name"]: row for row in current["gates"]}
    rows = []
    identity = current["integrity"]["qualified_identity"]
    unit = current["unit"]
    unit_pass = unit.get("ok") is True and unit.get("complete_ids") is True
    for stage, original in obligations:
        identifier = original["id"]
        finite = identifier in FINITE_GATES
        required = list(FINITE_GATES.get(identifier, ()))
        closed = finite and identity and unit_pass and all(gates.get(name, {}).get("passed") is True for name in required)
        if identifier == "P6-CURRENT-CLEANUP-RECEIPT":
            closed = closed and current["native_loans"]["qualified"]
        historical_gap = original.get("gap", original.get("previous_gap", ""))
        gap = historical_gap
        if closed:
            gap = {
                "P0-CURRENT-SOURCE": "当前固定源码的语义、显式适配、旧修复所需门槛、唯一ID完整性及源码/工具绑定已完成；结论限于声明profile，不扩展到未支持语言构造。",
                "P2-CURRENT-SOURCE-EQUIVALENCE": "当前声明Core范围的解释器、独立实现、native及所选形式化门槛和身份核对已完成；不构成全语言前后端精化证明，独立性能资格未通过。",
                "P6-CURRENT-CLEANUP-RECEIPT": "当前隔离子进程native-loan控制的尝试、启动、回收、完成及入口分母、版本持有和最终排空已核对；该有限结论不覆盖失败的持续负载资格或持久回调、任务、共享状态迁移。",
            }[identifier]
        if identifier == "P3-BROAD-CANDIDATE-SPACE":
            gap = "当前 primitive v7 已有 byte-swap.v1 与 checked-unsigned-reduction.v1 的有界适配；fill-loop 仍限 v1–v6。未新增 chain 优化、任意 AI 候选空间、全程序规划或全局最优证明。"
        rows.append({"id": identifier, "stage": stage["id"], "title": stage["title"], "scope": original["scope"],
            "state": "closed_in_declared_profile" if closed else "open", "current_source_commit": SOURCE,
            "historical_state": original["state"], "historical_source_commit": HISTORICAL_SOURCE,
            "required_current_gates": required, "current_identity_confirmed": identity,
            "current_unit_inventory_complete": unit_pass, "gap_or_scope_limit": gap,
            "historical_gap_or_scope_limit": historical_gap,
            "next_closure_evidence": original.get("next_closure_evidence", []),
            "historical_evidence_is_not_current_execution": True})
    broad = [row for row in rows if row["id"] not in FINITE_GATES]
    require(len(broad) == 14 and all(row["state"] == "open" for row in broad), "broader obligations must remain open")
    ledger = {"schema": "hepta.hia.v7-soak-blockers.v1", "source_commit": SOURCE,
              "historical_ledger": reader.ref(directory / "blockers.json"), "obligations": rows,
              "counts": dict(Counter(row["state"] for row in rows)), "original_obligation_count": 17,
              "broader_open_count": 14, "historical_closed_count": 3,
              "additional_finite_profile_closures": ([{"id": "FINITE-HOSTED-NATIVE-LIFECYCLE-30M-V1", "profile_id": PROFILE,
                 "state": "closed_in_declared_profile", "source_commit": SOURCE, "original_17_obligations_changed": False,
                 "production_P7_LONGLOAD_closed": False}] if soak["qualified"] else []),
              "full_p0_p7_closed": False}
    return {"source_commit": HISTORICAL_SOURCE, "results": reader.ref(directory / "results.json"),
            "source_runs": previous["source_runs"], "ndu_attempts": previous["ndu_attempts"],
            "ndu_attempts_reexecuted": False, "ndu_results_relabelled_as_f5": False,
            "historical_ledger_counts": previous["ledger_counts"],
            "historical_performance": previous.get("current_performance"),
            "historical_applications": previous.get("current_application_observations")}, ledger


def reviews_and_retention(reader, current, soak):
    histories = {
        "ndu_v7": "validation-ndu-v7-next/independent-review.json",
        "soak_reader_v2": "validation-runtime-soak-next/evidence-review-v2.json",
        "soak_reader_v3": "validation-runtime-soak-next/evidence-review-v3.json",
        "soak_reader_v4": "validation-runtime-soak-next/evidence-review-v4.json",
        "lifecycle_v2": "validation-runtime-soak-review/lifecycle-audit-v2.json",
        "lifecycle_v3": "validation-runtime-soak-review/lifecycle-audit-v3.json",
        "lifecycle_v4_identity": "validation-runtime-soak-review/relations-v4-and-retention-v1.json",
        "supervisor_owner": "validation-runtime-soak-review/supervisor-audit-v2.json",
        "focused_integration": "validation-next-blockers/focused-integration/summary.json",
        "source_publication": "validation-next-blockers/soak-publication.json",
        "runner_browser_access_snapshot": "validation-next-blockers/runner-browser-access.json",
        "cloud_target_capability_snapshot": "validation-next-blockers/cloud-targets.json",
    }
    reviews = {}
    for name, relative in histories.items():
        path = reader.base / relative
        value = reader.json(path)
        reviews[name] = {"receipt": reader.ref(path), "schema": value.get("schema"), "status": value.get("status"),
                         "scope": value.get("scope", value.get("approval_scope")),
                         "source_identity_kept_in_original_receipt": True}
        if name == "soak_reader_v4":
            reviews[name].update(controls=value["reviewer_controls"], open_in_scope_findings=value["open_in_scope_findings"])
        if name == "focused_integration":
            reviews[name].update(git_head=value.get("git_head"), ok=value.get("ok"),
                                 source_unchanged=value.get("source_unchanged"), counted_as_formal_execution=False)
    audits = []
    directory = reader.base / "validation-v7-soak-audits"
    require(directory.is_dir(), "final audit directory is missing")
    for path in sorted(directory.glob("*.json")):
        value = reader.json(path)
        audits.append({"receipt": reader.ref(path), "schema": value.get("schema"), "status": value.get("status"),
                       "source_commit": value.get("source_commit", value.get("git_commit", value.get("git_head"))),
                       "scope": value.get("scope", value.get("review_scope")),
                       "automatic_gate_override": False})
    require(bool(audits), "final audit receipts are missing")
    retained = []
    root = reader.base / "validation-v7-soak-frozen/unit-soak-development"
    for name in RETENTION:
        directory = root / name
        read = reader.maybe(directory / "report.json")
        value = read.get("value", {})
        prefix = "frozen/system/unit-soak-development/" + name + "/"
        files = [row for key, row in reader.archive_members.items() if key.startswith(prefix)]
        retained.append({"name": name, "present": bool(files), "raw_member_count": len(files),
                         "raw_bytes": sum(row["bytes"] for row in files), "report_available": read["available"],
                         "report": reader.inputs.get(str(directory / "report.json")), "status": value.get("status"),
                         "execution_passed": value.get("execution_passed"), "counts": value.get("counts"),
                         "failure": value.get("failure"), "cleanup_recovery": value.get("cleanup_recovery"),
                         "formal_hosted_evidence": False})
    causal_path = reader.base / "validation-runtime-soak-next/hosted-failure-investigation-1/causal-review.json"
    causal_read = reader.maybe(causal_path)
    causal = {"available": causal_read["available"], "bound_to_current_failed_report": False}
    if causal_read["available"]:
        value = causal_read["value"]
        causal.update(receipt=reader.ref(causal_path), status=value.get("status"))
        bound = (value.get("schema") == "hepta.hia.native-soak-causal-diagnosis.v1"
                 and value.get("source_commit") == SOURCE
                 and value.get("report", {}).get("sha256") == soak.get("producer_read", {}).get("receipt", {}).get("sha256")
                 and value.get("registration", {}).get("sha256") == soak["summary"].get("registration", {}).get("sha256"))
        causal["bound_to_current_failed_report"] = bound
        if bound:
            causal.update(policy=value.get("policy"), causal_findings=value.get("causal_findings"),
                          observed=value.get("observed"), decision=value.get("decision"), limits=value.get("limits"))
    else:
        causal["read_error"] = causal_read.get("error")
    return {"development_and_historical": reviews, "current_frozen_audits": audits,
            "raw_unit_retention": retained, "all_six_retention_directories_present": all(row["present"] for row in retained),
            "current_soak_failure_causal_investigation": causal,
            "counts_are_not_added_across_overlapping_reviews_and_tests": True}


def fmt(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def bullet_json(values):
    return "\n".join("- **" + str(key) + "**：`" + fmt(value).replace("`", "'") + "`。" for key, value in values.items())


def render(results, ledger):
    system, soak = results["current_system"], results["current_hosted_soak"]
    counts = soak["counts"].get("values")
    closed = ledger["counts"].get("closed_in_declared_profile", 0)
    main = (f"当前冻结源码 `{SOURCE}`：full35 已记录 {system['completed_gates']}/35 项，"
            f"通过 {system['passed_gates']} 项；外层 ok={fmt(system['summary'].get('ok'))}。"
            f"独立 hosted profile qualified={fmt(soak['qualified'])}。原17条义务当前有限关闭 {closed} 条，"
            f"开放 {17-closed} 条；其中14条更广义务保持开放。")
    gates = "\n".join(f"| {row['name']} | {fmt(row['passed'])} | {row.get('returncode')} | {(row.get('evidence') or {}).get('status')} |"
                      for row in system["gates"])
    roadmap = "\n".join(f"| {row['stage']} | {row['id']} | {row['historical_state']} | {row['state']} |"
                        for row in ledger["obligations"])
    retention = "\n".join(f"| {row['name']} | {fmt(row['present'])} | {row['raw_member_count']} | {row['status']} | {fmt(row['execution_passed'])} |"
                          for row in results["reviews"]["raw_unit_retention"])
    timing = soak["producer"].get("timing", {})
    native_counts = system["native_loans"]["counts"].get("values")
    profile = soak["registered_profile"]
    counts_or_unknown = counts or {}
    duration_ns = timing.get("observation_wall_ns")
    duration_seconds = duration_ns / 10**9 if integer(duration_ns) else None
    minimum_rows = [
        ("完整epochs", soak["producer"].get("completed_epochs"), profile.get("minimum_completed_epochs")),
        ("完成观察", counts_or_unknown.get("completed_observations"), profile.get("minimum_completed_observations")),
        ("实际观察秒数", duration_seconds, profile.get("minimum_observation_seconds")),
    ]
    minimum_table = "\n".join(f"| {label} | {fmt(actual)} | {fmt(required)} | " +
        (fmt(actual >= required) if type(actual) in (int, float) and type(required) in (int, float) else "unknown") + " |"
        for label, actual, required in minimum_rows)
    causal = results["reviews"]["current_soak_failure_causal_investigation"]
    failure_title = "本次正式有限profile已通过" if soak["qualified"] else "本次正式有限profile未合格"
    denominator_sentence = (
        f"完整epochs={fmt(soak['producer'].get('completed_epochs'))}；"
        f"attempts={fmt(counts_or_unknown.get('attempted_calls'))}，"
        f"starts={fmt(counts_or_unknown.get('child_processes_started'))}，"
        f"confirmed reaps={fmt(counts_or_unknown.get('child_processes_reaped'))}，"
        f"**completed observations={fmt(counts_or_unknown.get('completed_observations'))}**。"
        f"入口有观察={fmt(counts_or_unknown.get('native_entries_observed'))}，"
        f"入口结果不可用={fmt(counts_or_unknown.get('unavailable_native_entry_outcomes'))}，"
        f"总入口调用数={fmt(counts_or_unknown.get('native_entry_invocations'))}。")
    causal_text = "当前没有与本次报告及注册身份同时匹配的因果调查回执，不能填入确定归因。"
    if causal.get("bound_to_current_failed_report"):
        policy, decision = causal.get("policy") or {}, causal.get("decision") or {}
        observed = causal.get("observed") or {}
        final = observed.get("final_observation") or {}
        cleanup = (final.get("child_process") or {}).get("cleanup") or {}
        causal_text = (
            f"因果调查 `{causal['receipt']['path']}`（SHA256 `{causal['receipt']['sha256']}`）绑定本次失败报告与注册。"
            f"它记录的正常调用观察期限为 **{fmt(policy.get('wait_active_seconds'))}秒**，来源是冻结producer的 `begin()` 内置策略，"
            f"并非profile JSON独立字段；注册source snapshot仍绑定这段代码。"
            f"原生执行期限 **{fmt(policy.get('native_call_timeout_seconds'))}秒** 来自注册profile，并在Popen返回后由observer建立。"
            f"调查绑定attempt={fmt(observed.get('attempt_id'))}，admission interval={fmt(observed.get('admission_to_observation_ns'))}ns；"
            f"最终events={fmt(final.get('events'))}，ack_sent={fmt(final.get('ack_sent'))}，"
            f"child returncode={fmt(cleanup.get('returncode'))}，cleanup_confirmed={fmt(cleanup.get('cleanup_confirmed'))}，"
            f"observer error={fmt(final.get('error'))}。原始admission错误与后来的observer错误分别保留。"
            "没有per-event、Popen返回或observer首次读取时间戳，不能区分子进程启动/执行延迟与观察线程调度/IO延迟，"
            "也不能由最终loan_started反推它在观察期限内已可见。"
            f"调查结论 code_defect_demonstrated={fmt(decision.get('code_defect_demonstrated'))}，"
            f"correction_proposed={fmt(decision.get('correction_proposed'))}，"
            f"hosted_retries={fmt(decision.get('hosted_retries'))}。不据这次失败增大阈值或重试追求有利宿主状态。")
    report = f"""# Hepta v7 适配与有限原生持续负载：最终回执报告

{main}

**{failure_title}。** {denominator_sentence}

本报告由最终回执生成。通过、失败、噪声、退化、未完成和不可用结果分别保留；没有执行新的资格或重跑历史NDU计时。`null` 表示证据不可用，不能解释为零。完整机器结果见 [results.json](results.json)，原17条义务及逐项判定条件见 [blockers.json](blockers.json)。

## 1. 源码与执行身份

- 本轮固定提交：`{SOURCE}`；两份外层回执、所读报告、审计与归档成员的实际 SHA256 记录在 `results.json.inputs`。
- 历史系统交付为 `{HISTORICAL_SOURCE}`；两次历史NDU计时仍属 `{NDU_SOURCE}`。其原始状态、样本、超时、no-change、噪声与成本单独保存，没有重标为本轮结果。
- 本轮 system 身份检查：`{fmt(system['integrity'])}`。
- 本轮 hosted 身份检查：`{fmt(soak['integrity'])}`。
- 外层/子进程尚未确认终止时，生成器拒绝最终输出。已终止进程留下 running checkpoint、缺少或损坏 producer report 时，报告将它记为终止后的未完成/失败；源码或工具收尾缺失阻止有限关闭。

## 2. 本轮 full35 与独立 native-loan

| Gate | passed | returncode | producer status |
| --- | --- | --- | --- |
{gates}

未通过：`{fmt(system['failed_gates'])}`。尚未完成：`{fmt(system['not_completed_gates'])}`。完整固定门槛清单匹配：`{fmt(system['gate_inventory_complete'])}`。

当前唯一单元方法与ID完整性：`{fmt({k:v for k,v in system['unit'].items() if k != 'selected_modules'})}`。
v7 与 soak 模块在本轮单元回执内的精确方法、完成ID及结果保存在 `current_system.unit.selected_modules`；开发回归、独立审阅及重复运行不与这个唯一ID分母相加。

独立 native-loan 当前 qualified=`{fmt(system['native_loans']['qualified'])}`，status=`{fmt(system['native_loans']['status'])}`，最终 drained=`{fmt(system['native_loans']['final_drained'])}`。
其尝试/启动/回收/完成/入口分母为：`{fmt(native_counts)}`。诊断插桩观察到借用端点不等于完整内存安全证明；Popen成功也不等于原生入口已经执行。

## 3. v7 有界 NDU 适配

当前代码对已有 `byte-swap.v1` 与 `checked-unsigned-reduction.v1` 接受 primitive v7；`full-view-fill-loop.v1` 仍限 v1–v6。每个 baseline、重放结果、候选以及语义观察入口重新验证完整输入，拒绝同canonical bytes的composite身份替换、伪造结构元数据和不匹配的native receipt。

这增加版本适配，没有新增chain优化。单元控制涵盖chain/head loan经过checked reduction的返回、trap、allocation refusal和完整VM资源账本；当前执行结果以本轮 `test_hia_ndu_v7` 回执为准。开发native/NDU控制保留其各自source和artifact身份；显式synthetic-cost的真实abstain控制不成为计时收益。原两次NDU计时不重跑，不把有限候选选择称为任意程序全局最优。

## 4. 先失败、修复与独立审查

v2 reader曾错误接受7项重算摘要或重链后的证据变异，并有预算/程序角色缺口。独立lifecycle审阅还用3个真实已退出但未确认wait的子进程暴露final statistics、stream.close和Thread构造异常丢失清理owner的问题；审阅端最终实际回收这些子进程，旧失败记录没有回写成成功。

v3 producer把owner保证放入真正最外层finally，Thread构造/启动失败进入同步fallback，空owner恢复幂等；不变的3个真实故障控制随后通过。v3 reader修复原问题，但又暴露4项关系错误接受：build/pacing超出实际事件窗口、观察结束早于最后drained采样，以及同时held的子进程共享PID。

v4 reader把耗时绑定实际单调时钟窗口，要求last drained≤progress≤observation≤run_end，并维护held到terminal的活动PID集合。独立复验21个证据副本加2个profile变异全部符合预期；包括允许顺序PID复用的正例。这些是离线重放控制，没有新增native执行。v4 producer与已通过3个真实故障控制的v3字节完全相同，独立审查据此延续有限生命周期结论；补丁历史身份仍分别保存。

外层wrapper的 `wait_owned` 保持原始Popen对象和wait责任，中断最多转发一次取消，后续wait或signal异常继续保留owner；只在确认子进程结束后返回或重新抛出原异常。没有通过外层强制kill来抹掉未确认清理义务。其独立控制、初始harness失败与修正、报告解析负例保留在归档和审计引用中。

本轮完整单元执行保留六类原始目录；这些故障控制中的failed/running checkpoint是预期负例证据，不能当成一次成功正式soak：

| retained control | present | raw members | saved status | execution_passed |
| --- | --- | --- | --- | --- |
{retention}

## 5. 正式有限 hosted profile

profile=`{PROFILE}`，qualified=`{fmt(soak['qualified'])}`。外层status=`{fmt(soak['summary'].get('status'))}`，producer status=`{fmt(soak['producer'].get('status'))}`，stop_reason=`{fmt(soak['producer'].get('stop_reason'))}`。

failure_phase=`{fmt(soak['producer'].get('failure_phase'))}`；原始失败=`{fmt(soak['producer'].get('failure'))}`。

{denominator_sentence} starts/reaps与completed observations有各自分母；确认清理不把未完成调用变成成功观察。

| 最低验收项 | 实际值 | 注册最低值 | 已达到 |
| --- | --- | --- | --- |
{minimum_table}

{causal_text}

固定上限为1800秒测量墙时、1620秒停止新epoch、512epochs/16896attempts、2个并发native调用和96MiB证据预算。接受还独立要求至少1500秒实际观察、128完整epochs、5000完整观察以及显式pacing≤60%；预算上限不能充当已完成时长。没有为补足时间而在结尾空转。实际minimum checks=`{fmt(soak['minimum_duration_work_and_pacing_satisfied'])}`。

当前计数：`{fmt(counts)}`。
当前timing：`{fmt(timing)}`。延迟样本数包含已失败的admission观察；吞吐使用completed-observation分母，不能把两者混同。`case_counts`标识已尝试的预定case类别，不是成功返回次数。
当前资源摘要：`{fmt(soak['producer'].get('resources'))}`。
当前失败/恢复：`{fmt({k:soak['producer'].get(k) for k in ('failure','evidence_write_error','cleanup_recovery','drained')})}`。

负载实际执行每epoch编译/创建、候选取消、baseline活动借用跨激活、candidate双调用、跨回退持有、trap、分配拒绝、withheld ACK timeout及关闭期间持有与排空。资源是独立子进程私有标量入口的有限诊断资源；不代表进程内热补丁、跨调用外部借用、持久回调/任务或共享状态迁移。

FD/RSS阈值在drained-epoch采样点执行；before/after与held child样本是离散观察。吞吐与尾延迟包含进程启动、诊断握手、等待和清理，共享宿主没有排他性证明；这些数据不授予性能收益、网络SLO或生产长期资格。即使有限profile通过，`P7-LONGLOAD`仍开放。

## 6. 性能、失败与成本

当前performance详细保留在 `current_system.performance`：standalone的全部evaluation/quality_failures/performance_failures与原始sample分母，application的全部observed_slowdowns与timing contract均不删去。`measurement_inconclusive`不能写成性能通过；表面更快且未过固定质量门槛的样本不证明收益。历史两次NDU结果完整保存在 `historical.ndu_attempts`，包括中断后未报告工作未知的标记。

成本分层记录在 `costs`：driver main墙时与父CPU、各child step墙时与子CPU、producer观察窗口、pacing、可能重叠的call interval之和以及run进程外层等待。它们有包含/重叠关系，**没有相加成总成本**。driver main还不含模块导入、最后summary序列化及调用者开销。失败后的owner恢复可以超出1800秒测量上限，外层run step的实际wall保留该等待；工程、模型、能耗与人工成本没有因此获得实测。

## 7. 原17条义务与新增有限结论

| 阶段 | obligation | de49历史状态 | f5当前状态 |
| --- | --- | --- | --- |
{roadmap}

3个历史有限closed按当前相关gate、源码/工具身份、唯一ID完整性以及适用的native-loan结果重新判定；无关性能失败不代替语义判断。14个更广目标保持open。若本轮hosted通过，只在 `additional_finite_profile_closures` 增加独立profile closure，不改写原17条及生产P7-LONGLOAD。任意C/C++低成本重写、全语言安全/精化、工业真实热函数净收益、多物理宿主/设备、独立Agent开发经济性与生产长期负载仍需各自证据。

外部访问快照另见 `reviews.development_and_historical.runner_browser_access_snapshot` 与 `cloud_target_capability_snapshot`。这些记录没有新鲜runner探测：所记录GitHub插件能力没有 `fresh_dispatch`，浏览器观察为未登录，历史workflow run不证明runner当前在线。记录中的HTTP400不能解释成权限403。后续授权或新探测必须另留新回执，不改写此快照。访问条件只是部分外部依赖；上述14个广义目标还包含语义、实现、证明、真实工作负载和经济性工作，不可概括成只差登录。

## 8. 原始证据与复现

原始归档：`{fmt(results['raw_package']['archive'])}`；{results['raw_package']['member_count']}个成员，{results['raw_package']['part_count']}个有序parts。机器结果绑定 [raw-evidence-manifest.json](raw-evidence-manifest.json)、[raw-evidence-parts.json](raw-evidence-parts.json) 与 [source-run-index.json](source-run-index.json)。报告生成器只读取并核对小型回执/index，不重新解包或执行归档内容。Packager已经重开每个归档成员验证身份；运输parts用 [reassemble_raw_evidence.py](reassemble_raw_evidence.py) 的校验入口还原。

`results.json.reviews` 保留开发/历史审查与本轮最终审计的具体路径、schema、status、source范围和SHA。审计文件可单独放入 `audits/`，其源文件同时属于原始归档。报告不是独立运行证明；所有结论的实际执行身份以被冻结的producer与supervisor回执为准。
"""
    readme = f"""# Hepta v7 与有限原生持续负载证据

{main}

**{failure_title}。** {denominator_sentence}

本包绑定测试源码 `{SOURCE}`。项目完整P0–P7、生产长期负载、一般Rust性能超越和任意C/C++自动重写均未宣告完成。

- [REPORT.zh-CN.md](REPORT.zh-CN.md)：当前结果、故障修复、边界与成本解释。
- [results.json](results.json)：动态读取的最终结果与精确输入身份。
- [blockers.json](blockers.json)：原17条义务、当前判定条件及独立有限profile closure。
- [source-run-index.json](source-run-index.json)：两个新冻结运行的摘要身份。
- [raw-evidence-manifest.json](raw-evidence-manifest.json)：原始成员及整体归档身份。
- [raw-evidence-parts.json](raw-evidence-parts.json)：有序运输parts；按 [reassemble_raw_evidence.py](reassemble_raw_evidence.py) 校验还原。

旧PR335/de49交付及b921两次NDU计时仍保留原source；本包不重跑、不重标。失败、噪声、退化、缺失入口和未完成状态保留。开发负例、独立审阅、当前完整单元和正式hosted负载有不同分母，不相加。

报告生成器 `{Path(__file__).name}` 不调用子进程，不执行测试、不读取大型日志/归档数据，不自动授予新资格。所有目标文件以拒绝覆盖方式生成，packager原文件保持不变。真正仍活动或回收未确认的流程不能产出最终报告；已终止但缺少完整producer收尾的流程可以产出明确失败报告。
"""
    return report, readme


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=Path(__file__).absolute().parents[1])
    parser.add_argument("--output", type=Path, required=True,
                        help="Packager-created directory; results/README/REPORT/blockers must not exist")
    args = parser.parse_args()
    base, output = args.base.absolute(), args.output.absolute()
    require(output.is_dir(), "run the raw packager first; output directory does not exist")
    require(not output.is_symlink(), "output directory must not be a symlink")
    require(all(not os.path.lexists(output / name) for name in OUTPUT_NAMES), "refusing to overwrite an authored report")
    reader = Reader(base, output)
    packaged = package(reader)
    system, soak = system_run(reader, packaged), soak_run(reader, packaged)
    historical, ledger = historical_and_roadmap(reader, system, soak)
    reviews = reviews_and_retention(reader, system, soak)
    costs = {"arithmetic_total": None, "nested_durations_not_added": True,
             "system_driver_main": system["summary"].get("driver_main_cost"),
             "soak_driver_main": soak["summary"].get("driver_main_cost"),
             "system_child_steps": [{k:row.get(k) for k in ("name", "wall_ns", "child_user_seconds", "child_system_seconds",
                                      "returncode", "process_completion_confirmed")} for row in system["steps"]],
             "soak_child_steps": [{k:row.get(k) for k in ("name", "wall_ns", "child_user_seconds", "child_system_seconds",
                                    "returncode", "process_completion_confirmed")} for row in soak["steps"]],
             "producer_observation_and_overlap_fields": soak["producer"].get("timing"),
             "engineering_model_energy_human_costs_measured": False}
    results = {"schema": "hepta.hia.v7-soak-delivery.v1", "generated_utc": datetime.now(timezone.utc).isoformat(),
               "tested_source_commit": SOURCE, "draft_pr": "https://github.com/TrillionniumFoundation/Hepta/pull/343",
               "report_generation_is_not_qualification_execution": True, "current_system": system,
               "current_hosted_soak": soak, "historical": historical, "roadmap_counts": ledger["counts"],
               "additional_finite_profile_closures": ledger["additional_finite_profile_closures"],
               "reviews": reviews, "raw_package": packaged, "costs": costs,
               "claims": {"full_p0_p7_complete": False, "whole_project_blockers_closed": False,
                          "production_P7_LONGLOAD_closed": False, "global_optimality_proved": False,
                          "whole_language_soundness_proved": False, "industrial_net_gain_proved": False,
                          "universal_rust_superiority_proved": False, "independent_agent_cost_gain_proved": False,
                          "arbitrary_C_CPP_automatic_low_cost_migration_proved": False,
                          "finite_hosted_profile_qualified": soak["qualified"]}}
    reader.bytes(Path(__file__).absolute())
    results["inputs"] = sorted(reader.inputs.values(), key=lambda row: row["path"])
    report, readme = render(results, ledger)
    payloads = {"results.json": json.dumps(results, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
                "blockers.json": json.dumps(ledger, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
                "REPORT.zh-CN.md": report, "README.md": readme}
    reader.stable()
    require(all(not os.path.lexists(output / name) for name in OUTPUT_NAMES), "refusing concurrent report overwrite")
    # Validate every input and render every byte before creating any authored
    # output. Exclusive creation leaves packager files untouched.
    for name in OUTPUT_NAMES:
        with (output / name).open("xb") as stream:
            stream.write(payloads[name].encode())
    print(json.dumps({"output": str(output), "tested_source_commit": SOURCE,
                      "files": {name: {"sha256": sha(payloads[name].encode()), "bytes": len(payloads[name].encode())}
                                for name in OUTPUT_NAMES},
                      "system_outer_ok": system["summary"].get("ok"), "hosted_qualified": soak["qualified"],
                      "roadmap_counts": ledger["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
