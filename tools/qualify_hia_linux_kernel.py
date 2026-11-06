#!/usr/bin/env python3
"""Bind staged Linux evidence without promoting partial work to whole-kernel proof.

This qualifier reads existing artifacts. It neither builds nor boots a kernel.
The presently implemented intake and mixed-component schemas cannot establish
whole-Kbuild translation or a global NDU comparison. Those stages remain
NOT_RUN until a separately implemented, registered full-image contract exists.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PROTOCOL = ROOT / "benchmarks/hia_linux_kernel/PROTOCOL.json"
LINUX_COMMIT = "f45ed76d6791cf72ff1265ee93511175bbbc2f18"
ARCHIVE_SHA256 = "3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e"
ARMS = ("linux-stock", "hia-static", "hia-best-fixed", "hia-state-greedy",
        "hia-ordinary-mpc", "hia-same-objective", "hia-fixed-preference-ndu", "hia-dynamic-ndu")
SHARED = ("observation_schema_sha256", "action_registry_sha256", "external_objective_sha256",
          "forecast_inputs_sha256", "cost_model_sha256")
COSTS = ("source_acquisition", "translation_and_verification", "candidate_generation",
         "compilation_and_linking", "failed_attempts", "training_and_calibration",
         "observation", "planning", "ipc_and_logging", "adoption_and_switching",
         "warmup_and_retained_memory", "rollback_and_cleanup", "workload_execution")
SUFFIXES = {".c": "c", ".h": "header", ".S": "asm_cpp", ".s": "asm", ".rs": "rust"}
GUEST_CHECKS = ("pid1", "mount_proc", "mount_sysfs", "mount_devtmpfs", "mount_tmpfs",
                "kernel_identity", "cpu_count", "fork_exec_wait", "pipe_roundtrip", "mmap_pages",
                "mprotect_fault", "file_lifecycle", "unix_socketpair", "loopback_tcp")
CLAIMS = ("stock_kernel_built", "stock_kernel_booted", "hia_component_replacement_executed",
          "hia_whole_config_translated", "hia_kernel_booted", "whole_source_rewrite_established",
          "global_comparison_completed", "ndu_unique_gain_established")
INTERNAL_OBJECTIVES = dict(zip(ARMS, ("original_linux_algorithms", "unchanged_algorithms_static_translation",
    "development_selected_fixed_bundle", "one_step_external_objective", "declared_ordinary_planning_objective",
    "same_dynamic_external_objective", "fixed_preference_ablation", "dynamic_preference_objective")))


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def _int(value, name, minimum=0):
    _require(type(value) is int and value >= minimum, name + " must be an exact bounded integer")
    return value


def _sha(value, name):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), name + " must be a SHA256")
    return value


def _unique(values, name):
    _require(type(values) is list and all(type(x) is str and x for x in values), name + " must be strings")
    _require(len(set(values)) == len(values), name + " contains duplicate identities")
    return set(values)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _decode(raw):
    def invalid_constant(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=_object, parse_constant=invalid_constant)


def _read(path):
    return _decode(Path(path).read_bytes())


def _identity(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def _bound(reference, name):
    _require(type(reference) is dict and type(reference.get("path")) is str, name + " needs an artifact path")
    _sha(reference.get("sha256"), name)
    identity = _identity(reference["path"])
    _require(identity["sha256"] == reference["sha256"], name + " artifact SHA256 mismatch")
    if "bytes" in reference:
        _require(_int(reference["bytes"], name + " bytes") == identity["bytes"], name + " byte count mismatch")
    return identity


def _jsonl(reference, name):
    _bound(reference, name)
    count, total = 0, 0
    raw_digest = hashlib.sha256()
    with gzip.open(reference["path"], "rb") as stream:
        while line := stream.readline(2*1024*1024 + 1):
            _require(len(line) <= 2*1024*1024 and line.endswith(b"\n"), name + " malformed or oversized line")
            total += len(line)
            count += 1
            _require(total <= 512*1024*1024 and count <= 2_000_000, name + " exceeds review bound")
            raw_digest.update(line)
            value = _decode(line)
            _require(type(value) is dict, name + " record must be an object")
            yield value
    if "uncompressed_jsonl_sha256" in reference:
        _require(raw_digest.hexdigest() == reference["uncompressed_jsonl_sha256"], name + " uncompressed digest mismatch")


def _status(value):
    aliases = {"PASS": "PASS", "passed": "PASS", "FAIL": "FAIL", "failed": "FAIL",
               "NOT_RUN": "NOT_RUN", "not_run": "NOT_RUN", "SKIP": "SKIP", "skipped": "SKIP",
               "BLOCKED": "BLOCKED", "blocked": "BLOCKED"}
    _require(type(value) is str and value in aliases, "unknown evidence status")
    return aliases[value]


def _validate_protocol(protocol):
    _require(protocol.get("schema") == "hepta.hia.linux-kernel-contract.v1", "unknown Linux contract")
    linux = protocol["linux"]
    _require(linux["version"] == "6.18.60" and linux["stable_git_commit"] == LINUX_COMMIT and
             linux["archive_sha256"] == ARCHIVE_SHA256, "frozen Linux identity changed")
    _require(tuple(protocol["comparison"]["required_arms"]) == ARMS, "comparison arm inventory changed")
    _require(tuple(protocol["comparison"]["shared_fields"]) == SHARED, "shared comparison inputs changed")
    _require(tuple(protocol["comparison"]["cost_categories"]) == COSTS, "required cost scope changed")
    _require(protocol["comparison"]["internal_objectives"] == INTERNAL_OBJECTIVES and
             protocol["comparison"]["native_arms"] == list(ARMS[-2:]), "registered objective/native ablations changed")
    _require(protocol["comparison"]["online_information"] == {
        "current_and_past_only": True, "future_tape_visible": False, "holdout_labels_visible": False} and
        protocol["comparison"]["fixed_selection"] == "development_or_calibration_ex_ante_once",
        "registered controller information or ex-ante selection changed")
    _require(protocol["comparison"]["required_regimes"] == ["stationary", "adaptive", "misleading_feedback"] and
             protocol["comparison"]["budget_fields"] == ["wall_ns", "expanded_actions", "resident_bytes"] and
             protocol["comparison"]["split_names"] == ["development", "calibration", "holdout"],
             "registered environments, budgets or splits changed")
    _require(tuple(protocol["baseline"]["guest_checks"]) == GUEST_CHECKS, "boot smoke denominator changed")
    _require(protocol["baseline"]["architecture"] == "x86_64" and
             protocol["baseline"]["base_config"] == "x86_64_defconfig", "frozen configuration family changed")
    _require(protocol["accepted_evidence"]["full_kernel_evidence_available_in_this_schema"] is False,
             "present evidence schemas cannot grant full kernel authority")
    _require(protocol["production_activation"] is False, "research contract cannot claim production activation")


def _inventory(protocol, inventory):
    _require(inventory.get("schema") == "hepta.linux-source-inventory.v1", "wrong source inventory schema")
    receipt = inventory["source_receipt"]
    _require(inventory["kernel_version"] == receipt["version"] == protocol["linux"]["version"] and
             inventory["source_archive_sha256"] == receipt["sha256"] == ARCHIVE_SHA256 and
             receipt["stable_git_commit"] == LINUX_COMMIT, "source inventory is not the pinned Linux")
    _require(inventory["scope"] == "complete_upstream_archive_all_architectures_and_files", "wrong archive inventory scope")
    seen, kinds, byte_counts, lines = set(), Counter(), Counter(), Counter()
    members = {}
    regular = symlinks = total_bytes = 0
    for item in _jsonl(inventory["manifest"], "upstream manifest"):
        path = item.get("path")
        _require(type(path) is str and path and not PurePosixPath(path).is_absolute() and
                 ".." not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path,
                 "noncanonical upstream manifest path")
        _require(path not in seen, "duplicate upstream manifest path")
        seen.add(path)
        if item.get("type") == "symlink":
            _require(type(item.get("target")) is str, "symlink target missing")
            symlinks += 1
            members[path] = {key: item[key] for key in ("path", "type", "target")}
        else:
            _require(item.get("type") == "file", "unknown upstream file kind")
            kind = SUFFIXES.get(PurePosixPath(path).suffix, "other")
            _require(item["kind"] == kind, "source suffix classification changed")
            size, line_count = _int(item["bytes"], "source bytes"), _int(item["lines"], "source lines")
            _sha(item["sha256"], "source file")
            kinds[kind] += 1
            byte_counts[kind] += size
            lines[kind] += line_count
            regular += 1
            total_bytes += size
            members[path] = {key: item[key] for key in ("path", "type", "bytes", "sha256")}
    expected = {"regular_files": regular, "symlinks": symlinks, "total_files": len(seen),
                "total_bytes": total_bytes, "files_by_kind": dict(kinds),
                "bytes_by_kind": dict(byte_counts), "lines_by_kind": dict(lines),
                "source_files_total": sum(kinds[k] for k in SUFFIXES.values()),
                "c_source_files_total": kinds["c"]}
    for key, value in expected.items():
        _require(inventory.get(key) == value, "upstream manifest denominator mismatch: " + key)
    if "code_file_suffixes" in inventory:
        _require(set(inventory["code_file_suffixes"]) == set(SUFFIXES), "source suffix inventory changed")
    if "source_file_suffixes" in inventory:
        _require(set(inventory["source_file_suffixes"]) == set(SUFFIXES), "source suffix inventory changed")
    _require(inventory.get("function_denominator") is None and inventory.get("function_denominator_status") == "not_parsed",
             "file inventory cannot fabricate a function denominator")
    _require(inventory.get("all_configurations_compiled") is False, "archive inventory does not compile configurations")
    return {**expected, "members": members}


def _command(record, name):
    _require(type(record) is dict and record.get("name") == name, "missing original command: " + name)
    _require(type(record.get("argv")) is list and record["argv"] and
             all(type(x) is str for x in record["argv"]), "invalid original command arguments")
    _require(type(record.get("exit_code")) is int and type(record.get("timed_out")) is bool,
             "command termination was not observed")
    _int(record.get("elapsed_ns"), "command elapsed time", 1)
    _bound(record["stdout"], name + " stdout")
    _bound(record["stderr"], name + " stderr")
    return record["argv"]


def _option(argv, name):
    _require(argv.count(name) == 1 and argv.index(name) + 1 < len(argv), "missing or duplicated command option: " + name)
    return argv[argv.index(name) + 1]


def _same_path(left, right, name):
    _require(Path(left).resolve(strict=True) == Path(right).resolve(strict=True), name + " path differs from executed command")


def _boot_evidence(protocol, baseline, *, command_name="boot-stock-kernel-tcg"):
    """Replay actual serial frames and bind the exact guest invocation.

    Reusing the source-bound baseline parser here does not re-run the guest.
    The independent contract tests alter its raw stream and command identities.
    """
    from tools.qualify_hia_linux_baseline import parse_guest_serial, qemu_command, newc
    boot, run_id = baseline["boot"], baseline["run_id"]
    _require(type(run_id) is str and re.fullmatch(r"[a-f0-9]{24}", run_id), "invalid boot run identity")
    record = boot["command_receipt"]
    _require(command_name in {"boot-stock-kernel-tcg", "boot-control-kernel-tcg", "boot-hybrid-kernel-tcg"},
             "unregistered kernel boot command")
    argv = _command(record, command_name)
    matches = [r for r in baseline["commands"] if r.get("name") == command_name]
    _require(matches == [record], "boot receipt is not the unique original command")
    for key in ("kernel_image", "initramfs", "guest_init", "qemu"):
        _bound(baseline[key], "boot " + key)
    _bound(baseline["qemu"]["bios"], "boot BIOS")
    _same_path(argv[0], baseline["qemu"]["path"], "executed QEMU binary")
    _require(_identity(argv[0])["sha256"] == baseline["qemu"]["sha256"], "executed QEMU binary identity differs")
    # identity() canonicalizes executable paths; the immutable argv retains the
    # originally executed alias. Its spelling is not a compiler/source rewrite.
    expected = qemu_command(argv[0], _option(argv, "-L"),
                            baseline["qemu"]["bios"]["path"], baseline["kernel_image"]["path"],
                            baseline["initramfs"]["path"], run_id, protocol["linux"]["version"])
    _require(argv == expected, "boot arguments do not match the bound image, initramfs, identity and frozen machine")
    init = Path(baseline["guest_init"]["path"]).read_bytes()
    entries = [(name, stat.S_IFDIR | 0o755, b"", 0, 0) for name in ("dev", "proc", "sys", "tmp")]
    entries += [("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1),
                ("dev/null", stat.S_IFCHR | 0o666, b"", 1, 3),
                ("init", stat.S_IFREG | 0o755, init, 0, 0)]
    _require(gzip.decompress(Path(baseline["initramfs"]["path"]).read_bytes()) == newc(entries),
             "executed initramfs is not the bound finite guest program")
    text = Path(record["stdout"]["path"]).read_text(errors="replace")
    # Reject duplicate keys which ordinary json.loads would silently overwrite.
    for line in text.splitlines():
        if baseline["boot_status"] == "PASS" and line.startswith("HIA_LINUX_SMOKE "):
            _decode(line.removeprefix("HIA_LINUX_SMOKE "))
    replay = parse_guest_serial(text, run_id, record["exit_code"], record["timed_out"])
    _require(all(boot.get(key) == value for key, value in replay.items()), "boot verdict differs from original serial replay")
    _require(replay["guest_tests"] == baseline["guest_tests"] and replay["status"] == baseline["boot_status"],
             "boot summary differs from raw guest evidence")
    return replay


def _source_members(reference):
    _bound(reference, "baseline upstream source snapshot")
    with gzip.open(reference["path"], "rb") as stream:
        raw = stream.read(512 * 1024 * 1024 + 1)
    _require(len(raw) <= 512 * 1024 * 1024, "source snapshot exceeds review bound")
    rows = _decode(raw)
    _require(type(rows) is list and len(rows) <= 2_000_000, "source snapshot is not a complete bounded list")
    members = {}
    for row in rows:
        _require(type(row) is dict and row.get("type") in {"file", "symlink"}, "invalid baseline source snapshot row")
        path = row["path"]
        _require(type(path) is str and path not in members, "duplicate baseline source snapshot member")
        keys = ("path", "type", "target") if row["type"] == "symlink" else ("path", "type", "bytes", "sha256")
        members[path] = {key: row[key] for key in keys}
    return members


def _baseline(protocol, inventory, baseline, source_members):
    if baseline is None:
        return {"built": False, "booted": False, "status": "NOT_RUN", "active": None}
    _require(baseline.get("schema") == protocol["baseline"]["schema"], "wrong stock baseline schema")
    _require(baseline["kernel_version"] == inventory["kernel_version"] and
             baseline["source_archive_sha256"] == inventory["source_archive_sha256"], "baseline/source mismatch")
    _require(baseline.get("image_kind") == "stock_linux" and baseline.get("hia_compiled_units") == 0,
             "retained C baseline cannot be labeled HIA")
    build, boot, status = (_status(baseline[k]) for k in ("build_status", "boot_status", "status"))
    active = baseline["active_compile_units"]
    if active is not None:
        _int(active, "baseline C command count", 1)
    _require(baseline["fallback_c_units"] == active, "stock C command denominator changed")
    if build == "PASS":
        _require(_source_members(baseline["linux_source_inventory"]) == source_members,
                 "stock build source snapshot differs from the submitted upstream manifest")
        if baseline.get("linux_source_unchanged") is True:
            _require(_source_members(baseline["linux_source_after_inventory"]) == source_members,
                     "stock after-source snapshot differs from the submitted upstream manifest")
        _int(active, "completed baseline C command count", 1)
        for key in ("kernel_image", "vmlinux", "config", "compile_commands", "original_compile_commands"):
            _bound(baseline[key], "stock " + key)
        _require(baseline["config_sha256"] == baseline["config"]["sha256"] and
                 baseline["compile_commands_sha256"] == baseline["compile_commands"]["sha256"] and
                 baseline["original_compile_commands_sha256"] == baseline["original_compile_commands"]["sha256"],
                 "baseline config/database identity differs")
        original = _read(baseline["original_compile_commands"]["path"])
        target = _read(baseline["compile_commands"]["path"])
        _require(type(original) is list and type(target) is list, "compilation databases must retain original entry lists")
        indices = []
        for index, entry in enumerate(original):
            args = entry.get("arguments") or shlex.split(entry["command"])
            if Path(entry["file"]).suffix == ".c" and "-D__KERNEL__" in args:
                indices.append(index)
        _require(target == [original[i] for i in indices] and indices == baseline["target_compile_indices"] and
                 len(target) == active, "target C subset was edited, misclassified or removed from its full database")
        records = [r for r in baseline["commands"] if r.get("name") == "full-kbuild"]
        _require(len(records) == 1, "missing/duplicate complete Kbuild command")
        argv = _command(records[0], "full-kbuild")
        _require(records[0]["exit_code"] == 0 and records[0]["timed_out"] is False and
                 all(name in argv for name in ("vmlinux", "bzImage", "modules", "ARCH=x86_64")),
                 "partial/failed build cannot establish a complete configuration build")
        _same_path(_option(argv, "-C"), inventory["source_directory"], "upstream Kbuild source")
        builds = [arg[2:] for arg in argv if arg.startswith("O=")]
        _require(len(builds) == 1, "missing/duplicate Kbuild output directory")
        build_dir = Path(builds[0])
        _same_path(baseline["kernel_image"]["path"], build_dir / "arch/x86/boot/bzImage", "built stock image")
        _same_path(baseline["vmlinux"]["path"], build_dir / "vmlinux", "linked stock image")
        _require(_identity(build_dir / ".config")["sha256"] == baseline["config_sha256"],
                 "built image configuration differs from frozen .config")
    tests = baseline["guest_tests"]
    for key in ("total", "passed", "failed", "skipped", "not_run"):
        _int(tests[key], "guest " + key)
    _require(tests["total"] == len(GUEST_CHECKS) == sum(tests[k] for k in ("passed", "failed", "skipped", "not_run")),
             "guest failures/skips/not-run were removed from the planned denominator")
    if boot == "PASS":
        _require(build == "PASS" and tests["passed"] == len(GUEST_CHECKS), "partial guest smoke cannot pass boot gate")
    if "boot" in baseline:
        _boot_evidence(protocol, baseline)
    else:
        _require(boot != "PASS", "boot PASS has no original guest/command evidence")
    if status == "PASS":
        _require(build == boot == "PASS", "stock PASS contradicts build/boot")
        _require(baseline.get("linux_source_unchanged") is True and
                 baseline.get("source_before") is not None and baseline["source_before"] == baseline.get("source_after"),
                 "stock source identity changed or was not checked")
    identity_failed = (baseline.get("linux_source_unchanged") is False or
                       "source_after_error" in baseline or "wrapper_source_after_error" in baseline or
                       (baseline.get("source_before") is not None and baseline.get("source_after") is not None and
                        baseline["source_before"] != baseline["source_after"]))
    return {"built": build == "PASS" and not identity_failed, "booted": boot == "PASS" and not identity_failed,
            "status": status, "active": active}


def _migration(migration, baseline):
    if migration is None:
        return None
    _require(migration.get("schema") == "hepta.linux-translation-intake.v1", "wrong translation intake schema")
    n = _int(migration["active_compile_units"], "planned C commands", 1)
    attempted, not_run = _int(migration["attempted_compile_units"], "attempted C commands"), _int(migration["not_run_compile_units"], "not-run C commands")
    _require(attempted + not_run == n, "translation intake dropped planned commands")
    _sha(migration["config_sha256"], "intake config")
    _sha(migration["compile_commands_sha256"], "intake compilation database")
    if baseline is not None:
        _require(n == baseline["active_compile_units"] and migration["config_sha256"] == baseline["config_sha256"] and
                 migration["compile_commands_sha256"] == baseline["compile_commands_sha256"], "baseline/intake configuration or command denominator mismatch")
    directory = Path(migration["ledger"]["path"]).parent
    db_raw = (directory / "compile_commands.original.json").read_bytes()
    config_raw = (directory / "config.original").read_bytes()
    _require(hashlib.sha256(db_raw).hexdigest() == migration["compile_commands_sha256"] and
             hashlib.sha256(config_raw).hexdigest() == migration["config_sha256"], "retained original config/database changed")
    entries = _decode(db_raw)
    _require(type(entries) is list and len(entries) == n, "original compilation database denominator mismatch")
    counts, unique_sources = Counter(), set()
    rows = complete = 0
    for row in _jsonl(migration["ledger"], "C intake ledger"):
        _require(rows < n and row["index"] == rows, "C intake ledger missing, duplicate or reordered planned index")
        _require(row["original_entry"] == entries[rows] and row["entry_sha256"] == _digest(entries[rows]), "C intake command was normalized or rebound")
        kind = row["intake_status"]
        _require(kind in {"admitted", "rejected", "not_run"}, "unknown intake status")
        if kind == "rejected":
            _require(bool(row.get("rejection", {}).get("code")), "rejection reason omitted")
        if kind == "not_run":
            _require(bool(row.get("reason")), "not-run reason omitted")
        _require(row["whole_translation_unit_rewritten"] is False and row["hia_native_build"] == "not_run" and
                 row["kernel_object"] == "not_built", "intake or C fallback cannot stand in for HIA kernel code")
        counts[kind] += 1
        complete += row["declaration_analysis"] == "complete"
        if "source" in row:
            unique_sources.add(row["source"])
        rows += 1
    _require(rows == n and {k: v for k, v in counts.items() if v} ==
             {k: v for k, v in migration["intake_status_counts"].items() if v}, "C intake status/row denominator mismatch")
    _require(counts["not_run"] == not_run and counts["admitted"] + counts["rejected"] == attempted,
             "C intake attempt count mismatch")
    _require(migration["unique_source_files"] == len(unique_sources) and
             migration["declaration_inventory_complete_units"] == complete, "source/declaration count not supported by ledger")
    for key in ("whole_translation_units_hia_native", "hia_compiled_units", "source_files_rewritten", "ndu_calls"):
        _require(type(migration.get(key)) is int and migration[key] == 0, "intake schema cannot establish " + key)
    _require(migration["fallback_c_units"] == n and migration["fallback_policy"] == "retained_stock_baseline_not_counted_as_hia",
             "fallback C was removed from the denominator")
    _require(migration.get("all_configurations_translated") is False and migration.get("kernel_image") is None and
             migration.get("hia_kernel_status") == "not_built", "C intake was promoted to a whole HIA kernel")
    _require(migration.get("function_denominator") is None and migration.get("per_command_intake_is_full_project_capture") is False,
             "sharded intake cannot fabricate function or full-project coverage")
    _require(migration["status"] in {"blocked", "intake_completed_not_kernel_built"}, "unrecognized intake outcome")
    if counts["rejected"]:
        _require(migration["status"] == "blocked", "rejected intake cannot report completed admission")
    return {"active": n, "attempted": attempted, "not_run": not_run, "counts": dict(counts),
            "whole_hia_units": 0, "fallback_c_units": n, "declaration_complete_units": complete}


def _component(protocol, component, source_members):
    if component is None:
        return {"status": "NOT_RUN", "executed": False, "bodies": 0, "execution_count": 0}
    _require(component.get("schema") == "hepta.hia.linux-component.v1", "wrong bounded component schema")
    gate = component.get("guest_gate", {"status": "NOT_RUN"})
    status = _status(gate["status"])
    routing = component.get("routing")
    if routing is None:
        _require(_status(component["status"]) != "PASS" and status != "PASS", "passing component has no routing receipt")
        return {"status": status, "executed": False, "bodies": None, "execution_count": 0,
                "preparation_status": _status(component["status"])}
    _require(routing.get("whole_kernel_rewrite") is False, "mixed component receipt claims a whole rewrite")
    bodies = _int(routing["hia_implementation_bodies"], "component HIA bodies")
    _int(routing["asm_bridge_count"], "retained assembly bridges")
    _unique(routing["replaced_symbols"], "component replaced symbols")
    _unique(routing["retained"], "component retained symbols")
    if status != "PASS":
        return {"status": status, "executed": False, "bodies": bodies, "execution_count": 0,
                "preparation_status": _status(component["status"])}
    _require(component["source"]["linux_commit"] == LINUX_COMMIT, "component Linux source differs")
    _require(bodies > 0 and _status(component["oracle_diff"]["status"]) == "PASS" and
             _status(component["native_gate"]["status"]) == "PASS", "component has no independent native/oracle qualification")
    from hepta.hia_linux_kernel import config_profile, inspect_kernel_object
    _bound(component["source"]["configuration"], "component exact configuration")
    cfg = config_profile(Path(component["source"]["configuration"]["path"]).read_bytes())
    for name, source in component["source"]["files"].items():
        _bound(source, "component upstream source " + name)
        member = source_members.get(name)
        _require(member is not None and member["type"] == "file" and
                 (member["sha256"], member["bytes"]) == (source["sha256"], source["bytes"]),
                 "component source is not the matching pinned upstream member: " + name)
    artifact = component["artifact"]
    _bound(artifact, "HIA kernel component object")
    _require(artifact["schema"] == "hepta.hia.kernel-object.v1" and artifact["status"] == "PASS" and
             artifact["profile"] == "hepta.hia.linux-x86_64-kernel-u32-leaf.v1" and artifact["config"] == cfg,
             "component is not a qualified freestanding kernel object")
    exports = _unique(artifact["exports"], "HIA exports")
    undefined = _unique(artifact["inspection"]["undefined"], "component external symbols")
    _require(undefined == ({"__x86_return_thunk"} if cfg["rethunk"] else set()),
             "component externals do not match the configuration-required kernel ABI")
    inspected = inspect_kernel_object(Path(artifact["path"]).read_bytes(), artifact["disassembly"], artifact["exports"], cfg)
    _require(inspected == artifact["inspection"], "component object inspection differs from its actual bytes")
    _require(artifact["claims"]["actual_hia_core_to_native_object"] is True and
             all(artifact["claims"][key] is False for key in
                 ("c_codegen_used", "rust_codegen_used", "fallback_used", "whole_kernel_rewrite")),
             "hosted or C/Rust fallback cannot be counted as HIA kernel implementation")
    _bound(gate["kernel_image"], "mixed kernel image")
    _bound(gate["boot_report"], "mixed guest report")
    calls = _int(gate["execution_count"], "actual HIA guest calls", 1)
    _require(gate.get("execution_count_kind") == "completed_driver_direct_calls", "component execution-count scope is not explicit")
    executed = _unique(gate["executed_symbols"], "actually executed HIA symbols")
    _require(executed and executed <= exports, "guest did not execute named HIA implementation")
    translated = component.get("translated_bodies")
    if translated is None:
        translated = [component["translated_body"]]
    _require(type(translated) is list and len(translated) == bodies and
             all(body["target"] in exports for body in translated), "component body denominator differs from artifact exports")
    _require(len({body["target"] for body in translated}) == bodies and
             all(body["core_sha256"] == artifact["core_sha256"] and body["authored_translation"] is True for body in translated),
             "component implementation/core identities differ")
    _require(executed <= {body["target"] for body in translated}, "ASM/C wrapper counted as executed HIA body")
    _require(set(routing["hia_body_symbols"]) == {body["target"] for body in translated},
             "routing receipt does not name the translated HIA bodies")
    _bound(component["prepared_receipt"], "formal prepared component")
    prepared = _read(component["prepared_receipt"]["path"])
    _require(all(component.get(key) == value for key, value in prepared.items() if key not in {"guest_gate", "stage"}),
             "guest readback changed the formal prepared component")
    from tools.qualify_hia_linux_component import validate_guest_readback
    inputs = {key: gate[key] for key in
              ("serial_log", "kernel_image", "vmlinux", "build_object", "boot_report", "applied", "kernel_config")}
    replay = validate_guest_readback(prepared, inputs)
    _require(replay == gate, "component guest/linked-route receipt differs from exact readback")
    boot = _read(gate["boot_report"]["path"])
    _require(boot.get("schema") == "hepta.hia.linux.component-system-arm.v1" and
             boot.get("image_kind") == "hybrid_linux_hia_component" and boot.get("boot_status") == "PASS",
             "component execution is not bound to a passed mixed-kernel boot")
    for key in ("kernel_image", "vmlinux"):
        _require(boot[key] == gate[key], "mixed boot image/link identity differs: " + key)
    _bound(boot["config"], "mixed boot configuration")
    _require(boot["config"]["sha256"] == boot["config_sha256"] == cfg["sha256"] and
             boot["boot"]["command_receipt"]["stdout"] == gate["serial_log"],
             "component result is detached from the executed configuration or serial log")
    _require(_boot_evidence(protocol, boot, command_name="boot-hybrid-kernel-tcg")["status"] == "PASS",
             "component guest did not complete the registered boot lifecycle")
    return {"status": "PASS", "executed": True, "bodies": bodies, "execution_count": calls,
            "execution_count_kind": "completed_driver_direct_calls",
            "executed_symbols": sorted(executed), "retained_symbols": routing["retained"],
            "asm_bridge_count": routing["asm_bridge_count"]}


def validate_comparison_contract(protocol, registration):
    """Validate a prospective, balanced real-system comparison registration.

    Passing this function does not execute a workload or establish any outcome.
    Internal planner objectives are intentionally distinct from the shared
    external evaluation objective.
    """
    _validate_protocol(protocol)
    expected = protocol["comparison"]
    _require(registration.get("schema") == expected["schema"], "unknown comparison registration")
    _require(registration["protocol_sha256"] == _digest(protocol), "comparison protocol changed")
    _require(registration["scope"] == "whole_config_system", "userspace or component study is not a whole-system comparison")
    _require(registration["online_information"] == expected["online_information"], "future or holdout information exposed")
    _require(registration["holdout_used_for_selection"] is False and
             registration["fixed_selection"] == expected["fixed_selection"], "fixed/model selection used held-out state outcomes")
    shared = registration["shared"]
    _require(set(shared) == set(SHARED), "incomplete shared information/objective contract")
    for name, value in shared.items():
        _sha(value, name)
    budget = registration["planning_budget"]
    _require(set(budget) == set(expected["budget_fields"]), "incomplete compute budget")
    for name, value in budget.items():
        _int(value, "planning " + name, 1)
    arms = registration["arms"]
    _require(type(arms) is list and [a["id"] for a in arms] == list(ARMS), "comparison arm missing/duplicated/reordered")
    for arm in arms:
        _require(arm["shared"] == shared and arm["planning_budget"] == budget, "controller received different inputs, permissions, objective or budget")
        _require(arm["internal_objective"] == expected["internal_objectives"][arm["id"]], "internal planning objective is not the registered ablation")
        _sha(arm["implementation_sha256"], "controller implementation")
        if arm["id"] in expected["native_arms"]:
            _require(arm.get("native_backend_required") is True, "native arm permits scalar substitution")
            _sha(arm.get("native_backend_sha256"), "native backend")
    native = [a["native_backend_sha256"] for a in arms if a["id"] in expected["native_arms"]]
    _require(len(set(native)) == 1, "native preference ablation changed backend")
    splits = registration["splits"]
    _require(set(splits) == set(expected["split_names"]), "missing development/calibration/holdout split")
    seen = set()
    for name in expected["split_names"]:
        values = _unique(splits[name], name + " trace identities")
        _require(values and not seen.intersection(values), "trace split overlap or empty held-out evidence")
        seen.update(values)
    cost = registration["costs"]
    _require(set(_unique(cost["categories"], "cost categories")) >= set(COSTS), "build, failure, adoption or runtime cost omitted")
    _require(cost["outer_total_required"] is True and cost["nested_costs_additive"] is False and
             cost["runtime_compute_debits_real_resources"] is True and cost["unknown_lifecycle_costs_reported_unknown"] is True,
             "cost aggregation or real resource debit is invalid")
    workloads = registration["workloads"]
    ids = _unique([w["id"] for w in workloads], "workload identities")
    _require({w["regime"] for w in workloads} == set(expected["required_regimes"]), "missing adaptation/stability/misleading-feedback regime")
    planned = registration["planned_cells"]
    _unique([c["id"] for c in planned], "planned comparison cells")
    _require(planned, "no registered workload cells")
    factorial = set()
    for cell in planned:
        _require(cell["arm"] in ARMS and cell["workload"] in ids and cell["trace_id"] in splits["holdout"], "planned cell not bound to registered arm/workload/holdout")
        _int(cell["repeat"], "planned repeat")
        key = (cell["workload"], cell["trace_id"], cell["repeat"])
        factorial.add(key)
    expected_cells = {(arm, *key) for arm in ARMS for key in factorial}
    actual_cells = [(c["arm"], c["workload"], c["trace_id"], c["repeat"]) for c in planned]
    _require(set(actual_cells) == expected_cells and len(actual_cells) == len(expected_cells), "unequal or duplicate controller opportunities")
    _require({c["workload"] for c in planned} == ids, "registered workload silently omitted")
    _require({c["trace_id"] for c in planned} == set(splits["holdout"]), "registered holdout trace silently omitted")
    if "results" in registration:
        results = registration["results"]
        _require(type(results) is list and len(results) == len(planned) and
                 {r["id"] for r in results} == {c["id"] for c in planned}, "result denominator dropped planned failures/skips/not-run")
        for result in results:
            status = _status(result["status"])
            _require(status in {"PASS", "FAIL", "SKIP", "NOT_RUN"}, "unregistered result status")
            if status != "PASS":
                _require(bool(result.get("reason")), "failure/skip/not-run reason missing")


def assess_kernel_claims(protocol, source_inventory, baseline=None, migration=None, comparison=None, *, component=None):
    """Return scoped claims; malformed or rebound evidence raises ValueError.

    Inputs are summary dictionaries whose large manifests stay in bound files.
    File contents are read for verification; no input is modified or executed.
    """
    _validate_protocol(protocol)
    source = _inventory(protocol, source_inventory)
    stock = _baseline(protocol, source_inventory, baseline, source["members"])
    intake = _migration(migration, baseline)
    limited = _component(protocol, component, source["members"])
    if limited["executed"] and baseline is not None and baseline.get("config_sha256") is not None:
        _require(component["artifact"]["config"]["sha256"] == baseline["config_sha256"],
                 "mixed component and stock baseline used different configurations")
    if comparison is not None:
        validate_comparison_contract(protocol, comparison)
    claims = dict.fromkeys(CLAIMS, False)
    claims.update(stock_kernel_built=stock["built"], stock_kernel_booted=stock["booted"],
                  hia_component_replacement_executed=limited["executed"])
    active = intake["active"] if intake is not None else stock["active"]
    blockers = ["WHOLE_KBUILD_TRANSLATION_NOT_ESTABLISHED", "WHOLE_CONFIG_HIA_IMAGE_NOT_QUALIFIED",
                "ALL_ARCHITECTURE_CONFIGURATION_REWRITE_NOT_ESTABLISHED", "GLOBAL_COMPARISON_NOT_RUN"]
    if not stock["built"]:
        blockers.append("STOCK_KERNEL_BUILD_NOT_PASSED")
    if not stock["booted"]:
        blockers.append("STOCK_GUEST_SMOKE_NOT_PASSED")
    if intake is None:
        blockers.append("CONFIGURATION_C_INTAKE_NOT_RUN")
    elif intake["counts"].get("rejected", 0):
        blockers.append("REGISTERED_C_COMMANDS_REJECTED_BY_EXISTING_FRONTEND")
    if not limited["executed"]:
        blockers.append("HIA_COMPONENT_GUEST_EXECUTION_NOT_ESTABLISHED")
    # A completed comparison in a prospective metadata object is not a substitute
    # for the full-image evidence which this intake/component version lacks.
    if comparison is not None:
        _require(comparison.get("global_comparison_completed", False) is False and
                 comparison.get("ndu_unique_gain_established", False) is False,
                 "comparison outcome claimed without qualified whole-config HIA images")
    return {"schema": "hepta.hia.linux-kernel-assessment.v1", "status": "BLOCKED",
        "assessment_completed": True, "linux_commit": LINUX_COMMIT,
        "claims": claims, "global_comparison_status": "NOT_RUN",
        "comparison_registration_status": "VALIDATED_NOT_EXECUTED" if comparison is not None else "NOT_RUN",
        "stock_status": stock["status"], "component_status": limited["status"],
        "component": limited, "translation_intake": intake,
        "denominators": {"upstream_archive_files": source["total_files"],
            "upstream_regular_files": source["regular_files"], "source_suffix_files": source["source_files_total"],
            "upstream_c_source_files": source["c_source_files_total"], "active_config_c_commands": active,
            "active_config_all_kbuild_units": None, "source_function_count": None,
            "linked_symbol_count": None, "whole_config_hia_native_units": 0,
            "retained_stock_c_units": active},
        "blockers": blockers,
        "scope": "Current evidence can establish a stock frozen-config Linux boot and an explicitly named HIA component in a mixed image. It cannot establish a whole-config/source rewrite or global NDU gain. Subsequent full-image work requires its own implemented evidence contract.",
        "production_activation": False, "execution_authority": protocol["execution_authority"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=["assess"], default="assess")
    parser.add_argument("--protocol", type=Path, default=PROTOCOL)
    parser.add_argument("--source-inventory", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--migration", type=Path)
    parser.add_argument("--component", type=Path)
    parser.add_argument("--comparison", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError("assessment output already exists: " + str(args.output))
    began = time.monotonic_ns()
    bindings = {}
    try:
        values = {}
        for name in ("protocol", "source_inventory", "baseline", "migration", "component", "comparison"):
            path = getattr(args, name)
            values[name] = _read(path) if path is not None else None
            if path is not None:
                bindings[name] = _identity(path)
        result = assess_kernel_claims(**values)
        for name, expected in bindings.items():
            _require(_identity(expected["path"]) == expected, "assessment input changed: " + name)
    except (ValueError, KeyError, TypeError, OSError, EOFError) as error:
        result = {"schema": "hepta.hia.linux-kernel-assessment.v1", "status": "REJECTED",
            "assessment_completed": False, "claims": dict.fromkeys(CLAIMS, False),
            "global_comparison_status": "NOT_RUN", "error": {"type": type(error).__name__, "message": str(error)},
            "production_activation": False}
    result.update(inputs=bindings, qualifier=_identity(Path(__file__)), wall_ns=time.monotonic_ns()-began)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "global_comparison_status": result["global_comparison_status"],
                      "output": str(args.output)}, sort_keys=True))
    # BLOCKED records a successful assessment of incomplete research, not a
    # successful whole-kernel qualification. Automation must inspect that result.
    return 0 if result["status"] == "PASS" else 2 if result["status"] == "REJECTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
