"""Independent complete data reader for the 23 additional definition controls.

No product is imported or executed. All controls and original external scope
are required. Missing external four-method terminal evidence is HOLD, never an
invented phase completion. Bytes, tuple/list types and large integers survive.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    canonical, regular_bytes, unique_pairs, write_json, ORACLE_PREFIX, DERIVED_FILE,
    ORACLE_FREEZE_SHA256)
from tools.read_hia_slot_mechanical_installed import (
    Captures, need, integer, same, owned, capture_capsule, digest)
from tools.read_hia_slot_mechanical_observations import mechanical_counters
from tools.read_hia_slot_mechanical_routes import _read_trace_value, _read_trace

IDS = (
    "DEF-01-repeat-definition-function",
    "DEF-02-no-invocation-edges",
    "DEF-03-bind-class-instance-static",
    "DEF-04-original-binding-errors",
    "DEF-05-live-module-globals",
    "DEF-06-builtins-definition-binding",
    "DEF-07-default-identity-mutation",
    "DEF-08-expired-equivalent-owner",
    "DEF-09-nested-reentrant-calls",
    "DEF-10-thread-and-fork",
    "DEF-11-legacy-route-continuity",
    "DEF-12-override-precedence",
    "DEF-13-definition-namespace-lifetime",
    "DEF-14-public-reflection-counterexample",
    "DEF-15-real-retained-traceback",
    "DEF-16-real-unknown-custody",
    "DEF-17-private-export-drift",
    "DEF-18-partial-definition-publication",
    "DEF-19-warm-definition-private-binding-drift",
    "DEF-20-warm-definition-full-admission",
    "DEF-21-epoch-and-fork-boundaries",
    "DEF-22-definition-import-boundary",
    "DEF-23-definition-corruption-refusal",
)
NAMES = ("__init__", "_execute", "_call", "snapshot", "validate_u64", "conditional",
    "_begin", "admit_evaluation", "admit_net_benefit", "adopt", "rollback",
    "_lease_value", "acquire", "lease", "release")
FILES = ("tests/fixtures/slot_definition_lifetime_controls.json",
    "tests/hia_slot_definition_lifetime_controls.py", "tests/hia_slot_definition_epoch_control.py",
    "tests/test_hia_slot_definition_lifetime.py", "tools/read_hia_slot_definition_lifetime.py",
    "tools/run_hia_slot_definition_native4.py")
LIMITS = ("public_reflection_closed", "all_input_equivalence", "whole_native_stack_qualified",
    "default_cutover", "old_stack_can_be_removed", "original_gates_replaced",
    "gc_or_traceback_adjustment")
COUNTERS = ("public_calls", "raw_frame_calls", "initialized", "final_receipts")
METHODS = (
    "test_00_full_original248_derived7574_original_first_native_v5",
    "test_01_full_public84_handled12_original_first_native_v5",
    "test_02_complete_actual_admission_and_sealed_loader_controls",
    "test_03_actual_wheel_original_worker_v5_source_and_unknown_replay")
CLASS = "tests.test_hia_slot_mechanical_native.SlotMechanicalV5NativeTests"


def small_pin(value):
    need(type(value) is dict and {"bytes", "sha256"} <= set(value), "file pin is absent")
    integer(value["bytes"])
    need(value["bytes"] >= 0 and type(value["sha256"]) is str
         and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None, "file pin differs")
    return {key: value[key] for key in ("bytes", "sha256")}


def pinned_json(captured, value):
    return captured.json(value["path"], small_pin(value))


def decode_value(value):
    return _read_trace_value(value)


def equal_value(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if len(left) != len(right):
            return False
        for key, value in left.items():
            matches = [(other, item) for other, item in right.items()
                       if type(key) is type(other) and key == other]
            if len(matches) != 1 or not equal_value(value, matches[0][1]):
                return False
        return True
    if type(left) in (tuple, list):
        return len(left) == len(right) and all(equal_value(a, b) for a, b in zip(left, right))
    if type(left) is float:
        return math.isfinite(left) and math.isfinite(right) and struct.pack("!d", left) == struct.pack("!d", right)
    need(left is None or type(left) in (bool, int, str, bytes), "non-data decoded value")
    return left == right


def validate_limits(value):
    need(type(value) is dict and set(value) == set(LIMITS)
         and all(value[name] is False for name in LIMITS), "qualification scope was widened")


def validate_fixture(fixture):
    need(sha256(canonical(fixture)).hexdigest() == "36cce81b1e4e72efe1e209ab79884bbef49f41551a4399b8cc3b2ee8f4f28142",
         "complete predeclared fixture content changed")
    need(fixture["schema"] == "hepta.slot.definition-lifetime.controls.v1", "wrong fixture schema")
    integer(fixture["count"], 23)
    same(fixture["names"], list(NAMES))
    same(fixture["control_files"], list(FILES))
    same([row["id"] for row in fixture["cases"]], list(IDS))
    same([row["number"] for row in fixture["cases"]], list(range(1, 24)))
    integer(fixture["source_methods"], 2)
    integer(fixture["native_methods"], 1)
    integer(fixture["cleanup_seconds"], 5)
    integer(fixture["route_seconds"], 60)
    integer(fixture["outer_seconds"], 3600)
    validate_limits(fixture["qualification_limits"])
    same(fixture["original_gates_unchanged"], [
        "SlotMechanicalV5NativeTests:4", "SlotOperationsSourceTests:3",
        "SlotOperationsNativeTests:6", "dual-routes:17", "admission:25",
        "public:84", "handled:12", "original:248", "derived:7574"])
    relations = {"exact", "pair", "healthy", "refusal", "routes", "lanes",
                 "external", "epoch", "record-restoration", "custody-loss", "custody-retirement"}
    for row in fixture["cases"]:
        integer(row["seconds"])
        need(0 < row["seconds"] <= 600 and row["steps"], "missing bounded case inventory")
        for steps in [row["steps"], *(lane["steps"] for lane in row["lanes"])]:
            need(len(steps) == len({item["id"] for item in steps}), "duplicate planned relation")
            need(all(item["relation"] in relations for item in steps), "unknown relation")
        need(type(row["routes"]) is list and len(row["routes"]) == len(set(row["routes"])),
             "duplicate declared nested route")
    same(fixture["cases"][14]["external_scopes"], ["observations"])
    same(fixture["cases"][15]["external_scopes"], ["installed"])
    same(fixture["cases"][19]["external_scopes"], ["admission", "installed"])
    same([row["id"] for row in fixture["cases"][15]["lanes"]], ["receipt-loss", "failed-retirement"])
    for index, row in enumerate(fixture["cases"]):
        if index not in (14, 15, 19):
            same(row["external_scopes"], [])
    need(fixture["cases"][13]["steps"][0]["expected"]["public_reflection_closed"] is False,
         "public reflection counterexample was discarded")
    return fixture


def graph(value, *, allow_none=False):
    need(type(value) is dict and set(value) == {"root", "nodes", "formatted"}, "exception graph schema differs")
    if value["root"] is None:
        need(allow_none and value["nodes"] == [] and value["formatted"] == "", "exception is absent")
        return None
    integer(value["root"], 0)
    need(type(value["formatted"]) is str and value["formatted"]
         and type(value["nodes"]) is list and value["nodes"], "complete traceback is absent")
    nodes = value["nodes"]
    need([row["number"] for row in nodes] == list(range(len(nodes))), "exception graph numbering differs")
    for row in nodes:
        need(set(row) == {"number", "module", "qualname", "message", "suppress_context",
             "cause", "context", "frames"}, "exception graph node fields differ")
        need(all(type(row[key]) is str for key in ("module", "qualname", "message"))
             and row["module"] and row["qualname"] and type(row["suppress_context"]) is bool,
             "exception type/metadata differs")
        for label in ("cause", "context"):
            edge = row[label]
            need(edge is None or type(edge) is int and 0 <= edge < len(nodes), "exception edge differs")
        need(type(row["frames"]) is list, "traceback frame list differs")
        for frame in row["frames"]:
            need(set(frame) == {"file", "name", "line"} and type(frame["file"]) is str
                 and type(frame["name"]) is str and frame["file"] and frame["name"],
                 "actual traceback frame fields differ")
            integer(frame["line"])
            need(frame["line"] > 0, "actual traceback line differs")
    return nodes[0]


def delta(before, after, *, pid, mode, count):
    mechanical_counters(before, pid)
    mechanical_counters(after, pid)
    for name in COUNTERS:
        wanted = [0] * 16
        if name != "raw_frame_calls":
            wanted[mode] = count
        same([b-a for a, b in zip(before[name], after[name])], wanted)


def no_effect(before, after, pid):
    if before is None:
        if after is not None:
            mechanical_counters(after, pid)
            same(after["initialized"], [0] * 16)
            same(after["raw_frame_calls"], [0] * 16)
            same(after["final_receipts"], [0] * 16)
    else:
        mechanical_counters(before, pid)
        mechanical_counters(after, pid)
        for name in ("initialized", "raw_frame_calls", "final_receipts"):
            same(before[name], after[name])
        need(all(b >= a for a, b in zip(before["public_calls"], after["public_calls"])),
             "public attempted-call counter went backwards")


def evaluate_step(rule, actual, *, pid):
    relation = rule["relation"]
    if relation == "exact":
        need(equal_value(actual, rule["expected"]), "observed exact relation differs: " + rule["id"])
    elif relation == "pair":
        need(type(actual) is list and len(actual) == 2 and equal_value(actual[0], actual[1]),
             "complete typed pair differs: " + rule["id"])
    elif relation == "healthy":
        need(type(actual) is dict and set(actual) == {"original", "candidate", "original_trace",
             "candidate_trace", "before", "after", "entries", "forbidden"},
             "actual healthy witness schema differs")
        need(equal_value(actual["original"], actual["candidate"])
             and equal_value(actual["original_trace"], actual["candidate_trace"]),
             "original/candidate complete value or provider trace differs")
        need(actual["entries"] and all(x == {"actual_entry_returned": True} for x in actual["entries"])
             and actual["forbidden"] == [], "actual HIA entry/fallback witness differs")
        delta(actual["before"], actual["after"], pid=pid, mode=rule["mode"], count=rule["count"])
    elif relation == "refusal":
        need(set(actual) == {"error", "before", "after", "entries", "provider_trace"},
             "actual refusal witness schema differs")
        first = graph(actual["error"])
        need(first["module"] + "." + first["qualname"] == rule["type"]
             and rule["contains"] in first["message"] and first["frames"],
             "actual refusal is not its declared boundary")
        no_effect(actual["before"], actual["after"], pid)
        need(actual["entries"] == [] and actual["provider_trace"] == [],
             "refusal ran HIA/provider work")
    elif relation == "record-restoration":
        need(set(actual) == {"outer_records", "inner_records", "outer_sessions", "inner_sessions"},
             "actual reentrant identities differ")
        for suffix in ("records", "sessions"):
            outer, inner = actual["outer_" + suffix], actual["inner_" + suffix]
            need(type(outer) is list and len(outer) == 2 and type(inner) is list and len(inner) == 1,
                 "reentrant identity cardinality differs")
            need(all(type(x) is int and x > 0 for x in outer + inner)
                 and outer[0] == outer[1] and inner[0] != outer[0],
                 "reentrant invocation did not restore its exact outer identity")
    elif relation in ("custody-loss", "custody-retirement"):
        custody(actual, pid, relation == "custody-loss")
    else:
        need(relation in ("routes", "lanes", "external", "epoch"),
             "unknown complete relation")
        # File-backed relations are independently handled by verify_child below.


def custody(value, pid, lost):
    expected_keys = {"lane", "error", "same_top_error", "actual_loss_is_fault", "custody_registered",
        "record_owner_type", "same_record", "session_retained", "retired", "terminal",
        "native_pending", "observation_pending", "loss_present", "frame_mode", "frame_fenced",
        "frame_native_failed", "workspace_id", "buffer_bytes", "buffer", "entries", "provider_trace",
        "receipt", "before", "after"}
    need(set(value) == expected_keys, "custody actual-value fields differ")
    first = graph(value["error"])
    need(value["lane"] == ("receipt-loss" if lost else "failed-retirement"), "wrong custody lane")
    need(value["custody_registered"] is True and value["same_record"] is True
         and value["session_retained"] is True and value["retired"] is False
         and value["record_owner_type"] == "hepta.hia_slot_operations_native.SlotOperationsFrame",
         "actual pending frame/session custody was dropped")
    integer(value["frame_mode"], 5)
    integer(value["workspace_id"])
    integer(value["buffer_bytes"], 208)
    need(type(value["buffer"]) is bytes and len(value["buffer"]) == 208
         and value["buffer"][192:] == b"\xb7" * 16, "actual guarded workspace differs")
    mechanical_counters(value["before"], pid)
    mechanical_counters(value["after"], pid)
    for name in COUNTERS:
        wanted = [0] * 16
        if name == "public_calls" or not lost and name != "raw_frame_calls":
            wanted[5] = 1
        same([b-a for a, b in zip(value["before"][name], value["after"][name])], wanted)
    if lost:
        need(value["actual_loss_is_fault"] is True and value["loss_present"] is True
             and value["native_pending"] is True and value["terminal"] is False
             and value["frame_fenced"] is True and value["frame_native_failed"] is True
             and value["receipt"] is None and value["provider_trace"] == [],
             "actual lost initialization receipt was falsely confirmed")
        need(any(node["module"] == "builtins" and node["qualname"] == "ValueError"
                 and node["message"] == "DEF-16 actual returned receipt lost"
                 for node in value["error"]["nodes"]), "actual cause identity chain was discarded")
        need(len(value["entries"]) == 1, "actual receipt-loss native entry differs")
        row, = value["entries"]
        need(set(row) == {"return", "request_size", "output_capacity", "state_size", "source",
             "output", "workspace", "source_id", "output_id", "workspace_id"},
             "actual native buffer observation differs")
        for key, expected in (("return", 96), ("request_size", 128), ("output_capacity", 96), ("state_size", 192)):
            integer(row[key], expected)
        for name, size, canary in (("source", 144, b"\xc9"), ("output", 112, b"\xa5"),
                                  ("workspace", 208, b"\xb7")):
            need(type(row[name]) is bytes and len(row[name]) == size
                 and row[name][-16:] == canary * 16, "actual native guarded buffer changed")
            integer(row[name + "_id"])
        integer(row["workspace_id"], value["workspace_id"])
        need(row["workspace"] == value["buffer"], "loss custody did not retain the actual workspace")
        request = struct.unpack("<16Q", row["source"][:128])
        output = struct.unpack("<12Q", row["output"][:96])
        state = struct.unpack("<24Q", row["workspace"][:192])
        need(request[:6] == (int.from_bytes(b"HSOREQ01", "little"), 0, 0, 0, 0, 5)
             and request[8:] == (0,) * 8, "actual initialize request differs")
        need(output[0:2] == (int.from_bytes(b"HSORSP01", "little"), 0)
             and state[:3] == (int.from_bytes(b"HSOSTA01", "little"), 1, 5)
             and output[2:7] == (state[3], state[4], state[5], state[2], state[12])
             and output[3:7] == (1, 1, 5, 0)
             and output[8:10] == state[6:8] == request[6:8],
             "actual native initialize reply/workspace identity differs")
    else:
        need(value["same_top_error"] is True and value["actual_loss_is_fault"] is False
             and value["loss_present"] is False and value["terminal"] is True
             and value["native_pending"] is False and value["observation_pending"] is False
             and value["frame_fenced"] is False and value["frame_native_failed"] is False,
             "real failed retirement was cleared or relabelled")
        need(first["module"] == "builtins" and first["qualname"] == "RuntimeError"
             and first["message"] == "DEF-16 actual retirement failed",
             "actual retirement exception identity differs")
        need(value["entries"] and all(row == {"actual_entry_returned": True} for row in value["entries"])
             and value["provider_trace"], "healthy effects before failed retirement absent")
        receipt = value["receipt"]
        need(set(receipt) == {"port", "sequence", "phase", "failed"}
             and receipt["port"] == receipt["failed"] == 0 and receipt["phase"] == 4,
             "actual final receipt before retirement differs")
        integer(receipt["sequence"])
        need(receipt["sequence"] > 1, "final receipt sequence did not advance")


def lines_at(captured, path, expected=None):
    raw = captured.raw(path, expected)
    rows = []
    for line in raw.splitlines(keepends=True):
        need(line.endswith(b"\n"), "incomplete raw JSONL line")
        value = json.loads(line, object_pairs_hook=unique_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        need(canonical(value) + b"\n" == line, "noncanonical raw JSONL observation")
        rows.append(value)
    return rows


def flag(command, name):
    argv = command["argv"]
    need(argv.count(name) == 1 and argv.index(name) + 1 < len(argv),
         "actual command flag missing or repeated: " + name)
    return argv[argv.index(name) + 1]


def source_map(captured, root, freeze, *, schema, expected=None):
    raw = captured.raw(freeze, expected)
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    need(value["schema"] == schema and type(value["files"]) is dict and value["files"],
         "actual source freeze schema/inventory differs")
    for name, wanted in value["files"].items():
        need(type(name) is str and not Path(name).is_absolute() and ".." not in Path(name).parts,
             "unsafe frozen source path")
        captured.raw(Path(root) / name, small_pin(wanted))
    return value


def original_inputs(captured, root):
    oracle = Path(root) / ORACLE_PREFIX
    raw = captured.raw(oracle / "source-freeze.json")
    need(sha256(raw).hexdigest() == ORACLE_FREEZE_SHA256, "immutable original freeze differs")
    frozen = json.loads(raw, object_pairs_hook=unique_pairs)
    integer(len(frozen["files"]), 36)
    for name, wanted in frozen["files"].items():
        need(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe original input")
        captured.raw(oracle / name, small_pin(wanted))
    captured.raw(Path(root) / DERIVED_FILE)
    return frozen["files"]


def verify_observations(captured, evidence, root, freeze, freeze_pin, bundle):
    from tools.read_hia_slot_mechanical_observations import RAW_FILES, read_evidence
    evidence = Path(evidence)
    plan = captured.json(evidence / "plan.json")
    frozen = captured.json(evidence / "expectations-frozen.json")
    supervisor = captured.json(evidence / "supervisor.json")
    need(supervisor["status"] == "RECORDED" and supervisor["failure"] is None
         and supervisor["custody_failure"] is None and supervisor["source_stable"] is True
         and supervisor["old_deadlines_inputs_cases_tests_modified"] is False,
         "complete original7822 supervisor lacks a natural completion")
    same(plan["groups"], ["original248", "derived7574"])
    same(plan["backends"], ["native"])
    same(plan["mechanical_bundle"], bundle)
    for name, expected in (("original_seconds", 180), ("candidate_seconds", 1800),
                           ("total_seconds", 1800), ("cleanup_seconds", 5), ("original_repetitions", 2)):
        integer(plan[name], expected)
    need(frozen["candidate_started"] is False, "original expectations were not frozen first")
    names = [group + suffix for group in plan["groups"]
             for suffix in ("-original-1", "-original-2", "-native")]
    need(set(supervisor["children"]) == set(names), "complete six-child inventory differs")
    saved = {}
    for name in names:
        directory = evidence / name
        result = supervisor["children"][name]
        command, stdout, stderr = owned(captured, directory, result,
            1800 if name.endswith("-native") else 180)
        integer(command["parent_pid"], plan["parent_pid"])
        records = {}
        # Pin every actual full input before the old independent reader runs.
        for filename in RAW_FILES:
            records[filename] = digest(captured.raw(directory / "observation" / filename))
        item = {"raw": records, "command": digest(captured.raw(directory / "command.json")),
                "result": digest(captured.raw(directory / "result.json"))}
        item["runtime"] = captured.json(directory / "observation/runtime.json")
        report = captured.json(directory / "observation/report.json")
        item["counts"] = report["controller"]
        if name.endswith("-native"):
            item["launch"] = digest(captured.raw(directory / "observation/mechanical-launch.json"))
            captured.json(directory / "observation/controller.json")
        saved[name] = item
    # Compare the complete previously captured bytes independently as well.
    # No expected pin is refreshed after either comparison.
    exact = []
    for group, amount in (("original248", 248), ("derived7574", 7574)):
        ordered = plan["original_cases"][group]["ordered_ids"]
        integer(len(ordered), amount)
        need(len(set(ordered)) == amount, "complete group has duplicate identities")
        operands = {}
        for suffix in ("-original-1", "-original-2", "-native"):
            name = group + suffix
            directory = evidence / name / "observation"
            rows = lines_at(captured, directory / "observations.jsonl", saved[name]["raw"]["observations.jsonl"])
            same([row["id"] for row in rows], ordered)
            errors = lines_at(captured, directory / "raw-exceptions.jsonl", saved[name]["raw"]["raw-exceptions.jsonl"])
            same([row["id"] for row in errors], ordered)
            operands[suffix] = rows
        need(canonical(operands["-original-1"]) == canonical(operands["-original-2"])
             == canonical(operands["-native"]), "complete typed original/native observation fields differ")
        first = evidence / (group + "-original-1") / "observation/raw-exceptions.jsonl"
        second = evidence / (group + "-original-2") / "observation/raw-exceptions.jsonl"
        need(captured.raw(first) == captured.raw(second), "actual original raw exception files are unstable")
        exact.append({"group": group, "records": amount, "all_fields_equal": True})
    # A distinct new output directory preserves the original reader's complete
    # diff artifacts without overwriting its original qualification outputs.
    return saved, exact


def old_observations_reader(captured, evidence, root, freeze, freeze_pin, bundle, output, saved):
    from tools.read_hia_slot_mechanical_observations import read_evidence
    value = read_evidence(root, Path(root) / ORACLE_PREFIX, Path(root) / DERIVED_FILE,
        freeze, freeze_pin["sha256"], evidence, output,
        bridge_bundle=bundle["path"], expected_bridge_sha256=bundle["sha256"])
    need(value["schema"] == "hepta.slot-mechanical.observations-independent-readback.v1"
         and value["status"] == "PASS" and value["total_cases_per_backend"] == 7822
         and value["all_original_per_case_fields_compared"] is True,
         "original complete independent7822 reader is HOLD")
    same([(x["group"], x["backend"], x["records_compared"], x["different_cases"])
          for x in value["comparisons"]],
         [("original248", "native", 248, 0), ("derived7574", "native", 7574, 0)])
    same(value["product_freeze"], freeze_pin)
    same(value["expectations_freeze"], digest(captured.raw(Path(evidence) / "expectations-frozen.json")))
    same(value["mechanical_bundle"], bundle)
    need(set(value["children"]) == set(saved), "old reader omitted a complete child")
    for name, before in saved.items():
        child = value["children"][name]
        for key in ("raw", "command", "result", "runtime", "counts"):
            same(child[key], before[key])
        if "launch" in before:
            same(small_pin(child["mechanical_launch"]), before["launch"])
    return value


def verify_public(captured, evidence, root, freeze, product_pins, bundle, parent_pid):
    from tools.read_hia_slot_mechanical_observations import mechanical_launch
    report = captured.json(evidence / "report.json")
    need(report["schema"] == "hepta.slot.mechanical.public-complete.v1"
         and report["status"] == "PASS" and report["source_stable"] is True
         and report["old_inputs_or_fields_changed"] is False
         and report["actual_originals_twice_before_each_candidate"] is True,
         "complete public84/handled12 gate is HOLD")
    integer(report["public_inputs"], 84)
    integer(report["handled_inputs"], 12)
    integer(report["original_child_seconds"], 180)
    same(report["administrator_bundle"], bundle)
    originals = original_inputs(captured, root)
    checked = []
    for group, amount in (("public", 84), ("handled-traceback", 12)):
        specs = captured.json(Path(root) / "tests/fixtures/hia_slot_operations_qualification" /
                              (group + "-inputs.json"))["cases"]
        ordered = [row["id"] for row in specs]
        integer(len(ordered), amount)
        need(len(set(ordered)) == amount, "supplemental complete IDs differ")
        directory = evidence / group
        comparison = captured.json(directory / "comparison.json")
        need(comparison["status"] == "PASS" and comparison["group"] == group
             and comparison["all_raw_fields_compared"] is True
             and comparison["originals_before_candidate"] is True, "supplement comparison is incomplete")
        integer(comparison["cases"], amount)
        frozen = captured.json(directory / "expectations-frozen.json")
        need(frozen["candidate_started"] is False, "supplement expectations not frozen first")
        same([row["label"] for row in comparison["children"]], ["original-1", "original-2", "candidate"])
        observations = []
        for child in comparison["children"]:
            label = child["label"]
            target = directory / label
            command, stdout, stderr = owned(captured, target, child["result"], 180)
            integer(command["parent_pid"], parent_pid)
            raw = child["raw"]
            decoded = {}
            for name, expected in raw.items():
                need(name in ("report.json", "planned.json", "observations.jsonl", "raw-exceptions.jsonl"),
                     "unexpected supplemental raw member")
                captured.raw(target / "observation" / name, small_pin(expected))
            need(set(raw) == {"report.json", "planned.json", "observations.jsonl", "raw-exceptions.jsonl"},
                 "supplemental complete raw inventory differs")
            planned = captured.json(target / "observation/planned.json")
            same(planned["ordered_ids"], ordered)
            same(planned["inputs"], specs)
            actual = captured.json(target / "observation/report.json")
            same(actual, child["report"])
            need(actual["schema"] == "hepta.slot-operations.public-supplement.v1"
                 and actual["status"] == "RECORDED" and actual["failures"] == []
                 and actual["group"] == group and actual["no_gc_normalization"] is True
                 and actual["original_248_and_7574_modified"] is False,
                 "actual supplemental child incomplete")
            for key in ("planned", "started", "stopped"):
                same(actual[key], ordered)
            for key, expected in (("pid", command["pid"]), ("pgid", command["pid"]), ("ppid", parent_pid)):
                integer(actual[key], expected)
            same(actual["source_before"], originals)
            same(actual["source_after"], originals)
            same(actual["product_before"], product_pins)
            same(actual["product_after"], product_pins)
            rows = lines_at(captured, target / "observation/observations.jsonl", raw["observations.jsonl"])
            errors = lines_at(captured, target / "observation/raw-exceptions.jsonl", raw["raw-exceptions.jsonl"])
            same([row["id"] for row in rows], ordered)
            same([row["id"] for row in errors], ordered)
            observations.append(rows)
            if label == "candidate":
                need(actual["backend"] == "native" and actual["counts"]["retained_calls"] == []
                     and actual["counts"]["returned_entries"] > 0, "supplement lacks actual native execution")
                marker = captured.json(target / "observation/mechanical-launch.json")
                result = mechanical_launch(target, command,
                    {"argv": marker["inner_argv"], "pid": actual["pid"],
                     "ppid": actual["ppid"], "pgid": actual["pgid"]},
                    bundle, root, product_pins, "public")
                same(small_pin(result), digest(captured.raw(target / "observation/mechanical-launch.json")))
            else:
                need(actual["backend"] == "original" and actual["counts"] is None,
                     "supplemental original unexpectedly selected a controller")
                same(raw, frozen["groups"][label])
        need(canonical(observations[0]) == canonical(observations[1]) == canonical(observations[2]),
             "complete supplemental observation fields differ")
        checked.append({"group": group, "records": amount, "all_fields_equal": True})
    return checked


def capture_admission_inputs(captured, evidence):
    report = captured.json(evidence / "report.json")
    captured.json(evidence / "planned.json")
    for key in ("base_bundle", "source_capsule"):
        pinned_json(captured, report[key])
    for item in report["package_inputs"]:
        captured.raw(item["path"], small_pin(item))
    for row, observation in zip(report["commands"], report["observations"]):
        need(row["case"] == observation["case"], "admission command/observation identity differs")
        owned(captured, evidence / ("child-" + row["case"]), row["result"], 60)
        pinned_json(captured, observation)
    return report


def verify_external_native4(captured, binding, current_root, *, scopes, output):
    """Consume complete prior user/root pins, never manufacture a terminal."""
    need(binding["schema"] == "hepta.slot.definition.original-native4-binding.v1"
         and binding["errors"] == [], "explicit full Native4 authority is missing or invalid")
    need(type(scopes) is list and scopes and set(scopes) <= {"observations", "admission", "installed"},
         "undeclared original scope")
    root = Path(current_root).resolve(strict=True)
    readback_path = Path(binding["readback"]["path"])
    terminal_path = Path(binding["terminal"]["path"])
    readback = pinned_json(captured, binding["readback"])
    terminal = pinned_json(captured, binding["terminal"])
    need(readback["schema"] == "hepta.root.complete-reviewed-component-suite-readback.v1"
         and readback["status"] == "PASS" and readback["complete_ordered_ids"] is True
         and readback["source_stable"] is True and readback["residual_owned_groups"] == []
         and readback["command_errors"] == [] and readback["supervisor_failure"] is None,
         "original full Native4 root readback is HOLD")
    integer(readback["planned"], 4)
    expected = [CLASS + "." + name for name in METHODS]
    same(readback["expected"], expected)
    same(readback["observed_method_terminals"], [{"id": name, "status": "ok"} for name in expected])
    need(terminal["schema"] == "hepta.root.supervised-driver-terminal.v1"
         and terminal["terminal"] == "NATURAL_EXIT" and terminal["leader_reaped"] is True
         and terminal["observed_owned_group_gone"] is True
         and terminal["cwd"] == str(root), "original root terminal is missing/non-natural/foreign")
    integer(terminal["returncode"], 0)
    integer(terminal["pid"])
    same(terminal["driver_before"], terminal["driver_after"])
    argv = terminal["argv"]
    need(type(argv) is list and len(argv) == 4 and argv[1:3] == ["-I", "-B"],
         "actual root driver argv differs")
    driver = captured.raw(argv[3], small_pin(terminal["driver_before"]))
    # This is data extraction from the already pinned root driver. No AST,
    # import, eval, runpy, configuration code or product is executed.
    first = driver.decode("utf-8").splitlines()[0]
    match = re.fullmatch(r'CONFIG_B64="([A-Za-z0-9+/=]+)"', first)
    need(match is not None, "pinned driver lacks its explicit closed JSON configuration")
    config = json.loads(base64.b64decode(match.group(1), validate=True), object_pairs_hook=unique_pairs)
    need(config["repo"] == str(root), "old repository evidence cannot qualify the current source")
    same(config["expected"], expected)
    same(config["selectors"], [CLASS])
    need(readback_path.parent == Path(config["root"]) / config["label"],
         "actual root report directory differs from the pinned driver")
    same(readback["source_freeze"], config["freeze_pin"])
    fixed_raw = captured.raw(config["freeze"], small_pin(config["freeze_pin"]))
    fixed = json.loads(fixed_raw, object_pairs_hook=unique_pairs)
    same(fixed["index_tree"], readback["index_tree"])
    same(fixed["index_tree"], config["tree"])
    need(type(fixed["files"]) is dict and fixed["files"], "complete current source freeze is absent")
    for name, wanted in fixed["files"].items():
        need(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe root-frozen source")
        captured.raw(root / name, small_pin(wanted))
    for key in ("composition_readback", "composition_terminal"):
        captured.raw(config[key], small_pin(config[key + "_pin"]))
    if config.get("development_compiler") is not None:
        captured.raw(config["development_compiler"], small_pin(config["development_compiler_pin"]))
    for path, wanted in config.get("development_origin_files", {}).items():
        captured.raw(path, small_pin(wanted))
    suite_command, stdout, stderr = owned(captured, readback_path.parent / "suite-owned",
                                         readback["actual_suite_result"], 1800)
    integer(suite_command["parent_pid"], terminal["pid"])
    need(suite_command["cwd"] == str(root)
         and suite_command["argv"] == [argv[0], "-I", "-B",
             str(root / "tools/run_hia_unittest_gate.py"), CLASS],
         "actual complete original class command differs")
    same(digest(stdout), readback["stdout"])
    same(digest(stderr), readback["stderr"])
    text = stderr.decode("utf-8")
    stopped = []
    for line in text.splitlines():
        match = re.fullmatch(r'(test_[A-Za-z0-9_]+) \(([^)]+)\) \.\.\. (ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)', line)
        if match:
            stopped.append({"id": match.group(2), "status": match.group(3)})
    same(stopped, [{"id": name, "status": "ok"} for name in expected])
    counts = re.findall(r'^Ran ([0-9]+) tests? in [0-9.]+s$', text, re.MULTILINE)
    same(counts, ["4"])
    class_dir = Path(binding["class_evidence"]).resolve(strict=True)
    desired = Path(config["environment_additions"]["HEPTA_HIA_SLOT_OPERATIONS_EVIDENCE"]) / "SlotMechanicalV5NativeTests"
    need(class_dir == desired, "original class evidence belongs to another run")
    freeze = class_dir / "qualification-source-freeze.json"
    freeze_raw = captured.raw(freeze)
    freeze_pin = digest(freeze_raw)
    source = source_map(captured, root, freeze,
        schema="hepta.slot-operations.qualification-source-freeze.v1", expected=freeze_pin)["files"]
    original_inputs(captured, root)
    fixture = captured.json(class_dir / "fixture.json")
    same(fixture["sources"], source)
    for field in ("manifests", "images"):
        for path, wanted in fixture[field].items():
            captured.raw(path, small_pin(wanted))
    compiler_raw = captured.raw(fixture["compiler_path"])
    need(sha256(compiler_raw).hexdigest() == fixture["compiler_sha256"], "original fixture compiler differs")
    custody_report = captured.json(class_dir / "v5-component-custody.json")
    from tools.read_hia_slot_worker_terminal import admit_source_authority
    terminal_authority = admit_source_authority(captured, root)
    same(custody_report["terminal_source_authority"], terminal_authority)
    need(custody_report["schema"] == "hepta.slot.mechanical.v5-component.v2"
         and custody_report["original_Source3_Native6_denominators_retained"] is True
         and custody_report["worker_terminal_version_is_source_admitted"] is True
         and custody_report["original_v1_method_not_replaced"] is True
         and custody_report["whole_native_stack_qualified"] is False, "original class custody differs")
    integer(custody_report["new_method_count"], 4)
    same([row["method"] for row in custody_report["new_commands"]], expected)
    bundle = {key: custody_report["bundle"][key] for key in ("path", "bytes", "sha256")}
    capsule, bridge = capture_capsule(captured, bundle["path"], small_pin(bundle), root)
    method_commands = []
    for method, row in zip(METHODS, custody_report["new_commands"]):
        command, child_stdout, child_stderr = owned(captured, class_dir / method / "owned", row["result"], 1800)
        integer(command["parent_pid"], suite_command["pid"])
        need(command["cwd"] == str(root), "original method supervisor used a foreign source")
        need(command["argv"][0] == suite_command["argv"][0]
             and command["argv"][1:3] == ["-I", "-B"], "original method runtime differs")
        need(flag(command, "--evidence") == str(class_dir / method / "observations")
             and flag(command, "--product-freeze") == str(freeze)
             and flag(command, "--product-freeze-sha256") == freeze_pin["sha256"],
             "original method arguments are not this complete source/evidence")
        method_commands.append(command)
    same([row["argv"][3] for row in method_commands], [str(root / name) for name in (
        "tools/qualify_hia_slot_mechanical_observations.py",
        "tools/qualify_hia_slot_mechanical_public.py",
        "tools/qualify_hia_slot_mechanical_admission.py",
        "tools/qualify_hia_slot_mechanical_installed.py")])
    for command in method_commands[:3]:
        need(flag(command, "--bridge-bundle") == bundle["path"]
             and flag(command, "--expected-bridge-sha256") == bundle["sha256"],
             "original method changed its actual v5 authority")
    component = captured.json(class_dir / "component-custody.json")
    same(component["source_before"], {name: item["sha256"] for name, item in source.items()})
    same(component["source_after"], component["source_before"])
    need(component["compiler_sha256"] == fixture["compiler_sha256"], "original terminal compiler changed")
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = {}
    if "observations" in scopes:
        evidence = class_dir / METHODS[0] / "observations"
        saved, exact = verify_observations(captured, evidence, root, freeze, freeze_pin, bundle)
        value = old_observations_reader(captured, evidence, root, freeze, freeze_pin,
                                       bundle, output / "original7822", saved)
        results["observations"] = {"all_fields": exact, "complete_reader": value}
        results["public"] = verify_public(captured, class_dir / METHODS[1] / "observations",
            root, freeze, source, bundle, method_commands[1]["pid"])
    if "admission" in scopes:
        from tools.read_hia_slot_mechanical_admission import readback as admission_readback
        evidence = class_dir / METHODS[2] / "observations"
        before = capture_admission_inputs(captured, evidence)
        value = admission_readback(evidence, root, freeze, freeze_pin["sha256"])
        need(value["schema"] == "hepta.slot.mechanical.admission-readback.v1"
             and value["status"] == "PASS", "full actual admission25 independent reader is HOLD")
        integer(len(value["cases"]), 25)
        for path, wanted in value["actual_inputs"].items():
            captured.raw(path, small_pin(wanted))
        results["admission"] = value
    if "installed" in scopes:
        from tools.read_hia_slot_mechanical_installed import verify
        evidence = class_dir / METHODS[3] / "observations"
        results["installed"] = verify(evidence, root, freeze, freeze_pin["sha256"], captured)
    captured.stable()
    return {"schema": "hepta.slot.definition.complete-native4-consumption.v1", "status": "PASS",
        "current_root": str(root), "class_evidence": str(class_dir), "root_readback": binding["readback"],
        "root_terminal": binding["terminal"], "methods": expected, "scopes": scopes,
        "actual_interpreter": suite_command["argv"][0], "results": results,
        "product_freeze": freeze_pin, "capsule": bundle,
        "all_input_equivalence": False, "public_reflection_closed": False}


def verify_routes(captured, rows, case, parent, root, product_pins, plan):
    same([row["case"] for row in rows], case["routes"])
    legacy = {"direct-env", "v1-scope", "v1-unprimed-to-v5", "new-v1-after-v5", "raw-frame-legacy"}
    for row in rows:
        name = row["case"]
        directory = Path(parent) / ("route-" + name)
        need(row["directory"] == str(directory), "nested route directory differs")
        command, stdout, stderr = owned(captured, directory / "owned", row["result"], 60)
        integer(command["parent_pid"], plan["pid"])
        same(command["argv"], [command["argv"][0], "-I", "-B",
            str(root / "tests/hia_slot_mechanical_route_controls.py"), "--case", name,
            "--controller", plan["controller"]["path"], "--base-v1", plan["base"]["path"],
            "--base-sha256", plan["base"]["sha256"], "--bridge-bundle", plan["capsule"]["path"],
            "--expected-bridge-sha256", plan["capsule"]["sha256"],
            "--product-freeze", plan["product_freeze"]["path"],
            "--product-freeze-sha256", plan["product_freeze"]["sha256"],
            "--output", str(directory / "observation")])
        need(command["cwd"] == str(root) and stderr == b"", "nested route custody/stderr differs")
        need(row["report"]["path"] == str(directory / "observation/report.json"), "route report path differs")
        value = pinned_json(captured, row["report"])
        same(json.loads(stdout, object_pairs_hook=unique_pairs),
             {"case": name, "status": "PASS", "report": small_pin(row["report"])})
        need(value["schema"] == "hepta.slot.mechanical.route-control.v2" and value["status"] == "PASS"
             and value["case"] == name, "actual route incomplete")
        same(value["source_before"], product_pins)
        same(value["source_after"], product_pins)
        detail = value["detail"]
        reference, trace = _read_trace(detail["reference_trace"]), _read_trace(detail["provider_trace"])
        same(detail["argv"], command["argv"][3:])
        for field, expected in (("pid", command["pid"]), ("ppid", command["parent_pid"]), ("pgid", command["pid"])):
            integer(detail[field], expected)
        need(detail["case"] == name and detail["status"] == "PASS" and detail["initial_counters"] is None
             and detail["forbidden_legacy_finish"] == [] and reference, "nested original witness differs")
        integer(detail["reference_result"], 17)
        final = detail["final_counters"]
        if final is not None:
            mechanical_counters(final, command["pid"])
            same(final["raw_frame_calls"], [0] * 16)
        if name in legacy:
            need(equal_value(trace, reference) and detail["actual_entries"]
                 and all(entry == {"actual_entry_returned": True} for entry in detail["actual_entries"])
                 and (final is None or sum(final["initialized"]) == 0),
                 "actual legacy route was upgraded or changed")
        elif name == "v5-equivalent-scope":
            need(equal_value(trace, reference) and detail["actual_entries"] and final is not None
                 and final["public_calls"][5] > 0 and final["initialized"][5] > 0
                 and final["final_receipts"][5] > 0, "new owner lacked actual C/HIA completion")
            need(detail["error"]["type"] == "builtins.ValueError" and detail["error"]["message"],
                 "old captured owner did not refuse")
        else:
            need(name in {"v5-closed", "v5-thread", "v5-fork", "v1-primed-to-v5"}
                 and trace == [] and detail["actual_entries"] == []
                 and (final is None or sum(final["initialized"]) == 0), "refusal ran effects")
        if name in {"direct-env", "v1-scope", "raw-frame-legacy"}:
            need(final is None, "legacy route loaded unauthorized C")
        if name == "v5-fork":
            fork = detail["fork"]
            need(fork["reaped"] is True, "actual fork was not reaped")
            integer(fork["exit_code"], 0)
            child = json.loads(fork["raw"], object_pairs_hook=unique_pairs)
            integer(child["pid"], fork["pid"])
            need(child["trace"] == [] and child["error"]["type"] == "builtins.ValueError",
                 "actual inherited callable did not refuse")
            mechanical_counters(child["counters"], fork["pid"])
            same(child["counters"]["initialized"], [0] * 16)


def verify_epoch(captured, actual, parent, case, command, root):
    directory = Path(parent) / "actual-epoch"
    need(actual["directory"] == str(directory), "epoch directory differs")
    p = captured.json(directory / "epoch-parent.json", small_pin(actual["parent"]))
    raw = captured.raw(directory / "epoch-child.raw.json", small_pin(actual["child"]))
    child = json.loads(raw, object_pairs_hook=unique_pairs)
    need(canonical(child) + b"\n" == raw, "epoch child raw is not complete canonical JSON")
    need(p["schema"] == "hepta.slot.definition.epoch-parent.v1" and p["status"] == "PASS"
         and p["errors"] == [], "actual first-load parent is HOLD")
    same(p["child"], child)
    for field, expected in (("pid", command["pid"]), ("ppid", command["parent_pid"]), ("pgid", command["pid"])):
        integer(p[field], expected)
    integer(p["child_seconds"], case["epoch_child_seconds"])
    integer(p["max_report_bytes"], case["epoch_max_report_bytes"])
    integer(p["load_calls"], 1)
    same(p["cold"], {"pid": command["pid"], "definitions": 15,
        "extension_in_sys_modules": False, "loader_imported_by_ledger": False})
    graph(p["parent_error"], allow_none=True)
    need(p["parent_error"]["root"] is None, "actual parent loader had an error")
    same(p["child_process"], {"eof": True, "wait_status": 0, "returncode": 0,
        "reaped": True, "timed_out": False, "signals": [], "errors": []})
    need(child["schema"] == "hepta.slot.definition.epoch-child.v1" and child["status"] == "PASS",
         "actual fork child is HOLD")
    integer(child["pid"], p["child_pid"])
    need(child["pid"] != command["pid"], "actual fork PID did not change")
    integer(child["ppid"], command["pid"])
    integer(child["pgid"], command["pgid"])
    checks = {"actual_pid_changed", "actual_atfork_epoch_changed", "exact_epoch_error_in_actual_chain",
        "no_loader_publication", "loaded_module_removed", "one_confirmed_product_fd_close",
        "descriptor_is_actually_closed", "old_initializer_not_republished",
        "no_child_business_entry", "one_original_loader_return"}
    need(set(child["checks"]) == checks and all(x is True for x in child["checks"].values()),
         "actual child epoch/close guards differ")
    graph(child["exception_graph"])
    found = [node["number"] for node in child["exception_graph"]["nodes"]
             if node["module"] == "builtins" and node["qualname"] == "ValueError"
             and node["message"] == "Slot mechanical loaded module/epoch differs"
             and any(frame["name"] == "extension" and frame["file"] == str(root / "hepta/hia_slot_mechanical.py")
                     for frame in node["frames"])]
    need(len(found) == 1, "real epoch guard is absent from actual exception graph")
    same(child["epoch_error_nodes"], found)
    owner = child["descriptor_owner"]
    need(type(owner) is list and len(owner) == 4 and owner[2:] == [True, "CLOSED"],
         "actual child descriptor did not close once")
    integer(owner[0])
    integer(owner[1], 15)
    need(child["fd_probe"]["type"] == "OSError" and child["fd_probe"]["errno"] == 9
         and child["scope_owner_error_may_be_top"] is True, "actual FD or exception context differs")
    mechanical_counters(child["counters"], child["pid"])
    for name in COUNTERS:
        same(child["counters"][name], [0] * 16)
    healthy = p["healthy"]
    need(healthy["definition_objects_stable"] is True and healthy["counter_errors"] == [],
         "parent definitions/actual mode12 call failed")
    same(healthy["actual"], {"id": "epoch-lease", "slot": "slot", "generation": "generation", "artifact": None})
    same(healthy["expected"], healthy["actual"])
    delta(healthy["counters_before"], healthy["counters_after"], pid=command["pid"], mode=12, count=1)
    for name in COUNTERS:
        same(healthy["counter_delta"][name], [b-a for a, b in
             zip(healthy["counters_before"][name], healthy["counters_after"][name])])
    fd = healthy["parent_fd"]
    integer(fd["fd"], owner[0])
    need(fd["owner"] == [fd["fd"], 15, False, "MODULE_LIFETIME"]
         and type(fd["size"]) is int and fd["size"] > 0, "parent module descriptor retired")
    for key in ("dev", "ino"):
        integer(fd[key])
    closes = p["owned_test_fd_close_receipts"]
    need(len(closes) == 2 and len({row["fd"] for row in closes}) == 2, "test pipe close inventory differs")
    for row in closes:
        need(set(row) == {"fd", "attempted", "confirmed"} and type(row["fd"]) is int
             and row["attempted"] is True and row["confirmed"] is True and row["fd"] != fd["fd"],
             "test close affected module descriptor")
    child_closes = child["owned_test_fd_closes_before_output"]
    need(len(child_closes) == 1 and child_closes[0] in closes, "child read-pipe close differs")


def expected_child_argv(command, case, plan, output, *, lane=None):
    argv = [command["argv"][0], "-I", "-B",
        str(ROOT / "tests/hia_slot_definition_lifetime_controls.py"), "--case", case["id"],
        "--controller", plan["controller"]["path"],
        "--base-v1", plan["base"]["path"], "--base-sha256", plan["base"]["sha256"],
        "--bridge-bundle", plan["capsule"]["path"],
        "--expected-bridge-sha256", plan["capsule"]["sha256"],
        "--product-freeze", plan["product_freeze"]["path"],
        "--product-freeze-sha256", plan["product_freeze"]["sha256"],
        "--control-freeze", plan["control_freeze"]["path"],
        "--control-freeze-sha256", plan["control_freeze"]["sha256"],
        "--external-binding", plan["external_binding"]["path"],
        "--external-binding-bytes", str(plan["external_binding"]["bytes"]),
        "--external-binding-sha256", plan["external_binding"]["sha256"],
        "--output", str(output)]
    if lane is not None:
        argv.extend(("--lane", lane))
    return argv


def verify_child(captured, row, case, root, parent_pid, parent_plan, fixture,
                 product_pins, control_pins, independent_output, *, lane=None):
    directory = Path(row["directory"])
    observation = directory / "observation"
    # Nonzero/timeout evidence is still retained before owned() refuses it.
    raw_command = captured.json(directory / "owned/command.json")
    raw_result = captured.json(directory / "owned/result.json")
    captured.raw(directory / "owned/stdout.log", raw_result["stdout"])
    captured.raw(directory / "owned/stderr.log", raw_result["stderr"])
    if row["report"] is not None:
        pinned_json(captured, row["report"])
    seconds = case["seconds"] if lane is None else next(x["seconds"] for x in case["lanes"] if x["id"] == lane)
    command, stdout, stderr = owned(captured, directory / "owned", row["result"], seconds)
    integer(command["parent_pid"], parent_pid)
    need(command["cwd"] == str(root) and Path(command["argv"][0]).is_absolute(),
         "actual control child source/runtime differs")
    same(command["argv"], expected_child_argv(command, case, parent_plan, observation, lane=lane))
    need(stderr == b"", "recorded child emitted unexplained stderr")
    need(row["report"]["path"] == str(observation / "report.json"), "actual report path differs")
    report = pinned_json(captured, row["report"])
    child_plan = captured.json(observation / "planned.json", report["plan"])
    need(report["schema"] == "hepta.slot.definition.child-report.v1"
         and report["status"] == "RECORDED" and report["case"] == case["id"] and report["lane"] == lane,
         "actual child did not complete its declared scope")
    need(child_plan["schema"] == "hepta.slot.definition.child-plan.v1"
         and child_plan["case"] == case["id"] and child_plan["lane"] == lane,
         "actual child initial plan differs")
    validate_limits(report["qualification_limits"])
    for field, expected in (("pid", command["pid"]), ("ppid", command["parent_pid"]), ("pgid", command["pid"])):
        integer(report[field], expected)
        integer(child_plan[field], expected)
    same(report["argv"], command["argv"][3:])
    same(child_plan["argv"], command["argv"][3:])
    same(json.loads(stdout, object_pairs_hook=unique_pairs),
         {"case": case["id"], "lane": lane, "status": "RECORDED", "report": small_pin(row["report"])})
    for field in ("source_before", "source_after"):
        same(report[field], product_pins)
    for field in ("control_before", "control_after"):
        same(report[field], control_pins)
    same(child_plan["product_sources"], product_pins)
    same(child_plan["control_sources"], control_pins)
    expected_inputs = {parent_plan[key]["path"]: small_pin(parent_plan[key])
                       for key in ("controller", "base", "capsule", "external_binding")}
    same(child_plan["input_pins"], expected_inputs)
    rules = case["steps"] if lane is None else next(x["steps"] for x in case["lanes"] if x["id"] == lane)
    same(child_plan["steps"], rules)
    same([x["id"] for x in report["steps"]], [x["id"] for x in rules])
    same(lines_at(captured, observation / "progress.jsonl"),
        [{"event": "recorded", "index": index, **value} for index, value in enumerate(report["steps"])])
    verified = []
    for rule, actual_row in zip(rules, report["steps"]):
        need(set(actual_row) == {"id", "actual"}, "actual relation fields differ")
        actual = decode_value(actual_row["actual"])
        evaluate_step(rule, actual, pid=command["pid"])
        if rule["relation"] == "routes":
            verify_routes(captured, actual, case, observation, root, product_pins,
                          {**parent_plan, "pid": command["pid"]})
        elif rule["relation"] == "lanes":
            same([item["lane"] for item in actual], [item["id"] for item in case["lanes"]])
            for item in actual:
                need(item["directory"] == str(observation / ("lane-" + item["lane"])),
                     "actual custody subchild directory differs")
                verify_child(captured, item, case, root, command["pid"], parent_plan, fixture,
                    product_pins, control_pins, independent_output, lane=item["lane"])
        elif rule["relation"] == "epoch":
            verify_epoch(captured, actual, observation, case, command, root)
        elif rule["relation"] == "external":
            need(actual["path"] == str(observation / "external-readback.json"),
                 "external complete proof report path differs")
            consumed = pinned_json(captured, actual)
            need(consumed["schema"] == "hepta.slot.definition.external-consumption.v1"
                 and consumed["status"] == "PASS", "producer lacks complete original proof")
            for path, wanted in consumed["actual_inputs"].items():
                captured.raw(path, small_pin(wanted))
            binding = pinned_json(captured, parent_plan["external_binding"])
            fresh = verify_external_native4(captured, binding, root,
                scopes=case["external_scopes"], output=independent_output / case["id"])
            need(fresh["actual_interpreter"] == command["argv"][0],
                 "new controls and original full gate used different interpreters")
            for key in ("methods", "scopes", "root_readback", "root_terminal", "class_evidence",
                        "current_root", "product_freeze", "capsule", "actual_interpreter"):
                same(fresh[key], consumed["detail"][key])
            # Whole original data was just independently checked again. Output
            # diff file paths differ by construction; no original value is normalized.
        verified.append(rule["id"])
    if case["number"] == 20:
        private = captured.json(observation / "private-package-custody.json")
        need(private["schema"] == "hepta.slot.definition.private-package.v1"
             and private["source_root"] == str(root) and private["whole_native_stack_qualified"] is False,
             "private warm-admission copy has wrong provenance")
        package = observation / "private-package/hepta"
        need(private["package"] == str(package), "warm-admission copy is not privately owned")
        capsule, bridge = capture_capsule(captured, private["capsule"]["path"],
                                         small_pin(private["capsule"]), package.parent)
        same(bridge, private["bridge"])
        _, original_bridge = capture_capsule(captured, parent_plan["capsule"]["path"],
                                               small_pin(parent_plan["capsule"]), root)
        for key in ("binary", "build_receipt"):
            same(small_pin(bridge[key]), small_pin(original_bridge[key]))
        need(set(bridge["sources"]) == set(original_bridge["sources"]), "private source inventory differs")
        for name in bridge["sources"]:
            same(small_pin(bridge["sources"][name]), small_pin(original_bridge["sources"][name]))
    return {"case": case["id"], "lane": lane, "pid": command["pid"], "checks": verified,
            "report": row["report"], "actual_owned_terminal": True}


def readback(evidence, product_root, product_freeze, product_freeze_sha256, *,
             control_freeze, control_freeze_sha256, output):
    evidence, root, output = Path(evidence), Path(product_root).resolve(strict=True), Path(output)
    captured = Captures()
    failures, results = [], []
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        need(root == ROOT, "reader source differs from actual current product")
        fixture = captured.json(root / FILES[0])
        validate_fixture(fixture)
        plan = captured.json(evidence / "planned.json")
        report = captured.json(evidence / "report.json")
        need(plan["schema"] == "hepta.slot.definition.complete-plan.v1"
             and report["schema"] == "hepta.slot.definition.complete-collection.v1",
             "complete additional evidence schema differs")
        same(plan["cases"], list(IDS))
        same(plan["specifications"], fixture["cases"])
        same(plan["fixture"], {"path": str(root / FILES[0]), **digest(captured.raw(root / FILES[0]))})
        validate_limits(plan["qualification_limits"])
        validate_limits(report["qualification_limits"])
        need(plan["original_case_budgets_changed"] is False, "original budgets changed")
        integer(plan["new_outer_seconds"], fixture["outer_seconds"])
        integer(plan["parent_pid"])
        for field in ("planned", "started", "stopped"):
            same(report[field], list(IDS))
        same([row["case"] for row in report["commands"]], list(IDS))
        same(report["plan"], digest(captured.raw(evidence / "planned.json")))
        need(plan["product_freeze"]["path"] == str(product_freeze)
             and plan["product_freeze"]["sha256"] == product_freeze_sha256
             and plan["control_freeze"]["path"] == str(control_freeze)
             and plan["control_freeze"]["sha256"] == control_freeze_sha256,
             "external source authority differs")
        product = source_map(captured, root, product_freeze,
            schema="hepta.slot-operations.qualification-source-freeze.v1",
            expected=small_pin(plan["product_freeze"]))["files"]
        controls = source_map(captured, root, control_freeze,
            schema="hepta.slot.definition.control-source-freeze.v1",
            expected=small_pin(plan["control_freeze"]))["files"]
        need(set(FILES) <= set(controls) and set(product) <= set(controls), "incomplete control/support source closure")
        for key in ("controller", "base", "capsule", "external_binding"):
            captured.raw(plan[key]["path"], small_pin(plan[key]))
        capsule, bridge = capture_capsule(captured, plan["capsule"]["path"], small_pin(plan["capsule"]), root)
        need(capsule["helpers_bundle"] == plan["base"]["path"]
             and capsule["helpers_bundle_sha256"] == plan["base"]["sha256"], "actual v1/v5 inputs differ")
        base = pinned_json(captured, plan["base"])
        selected = [row for row in base["helpers"] if row["selector"] == "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST"]
        need(len(selected) == 1 and selected[0]["manifest_path"] == plan["controller"]["path"]
             and selected[0]["manifest_sha256"] == plan["controller"]["sha256"], "actual controller differs")
        same(lines_at(captured, evidence / "progress.jsonl"),
             [item for row in report["commands"] for item in (
                 {"event": "started", "id": row["case"]},
                 {"event": "stopped", "id": row["case"], "exit_code": row["result"]["exit_code"]})])
        for case, row in zip(fixture["cases"], report["commands"]):
            try:
                need(row["directory"] == str(evidence / case["id"]), "actual case directory differs")
                results.append(verify_child(captured, row, case, root, plan["parent_pid"], plan,
                    fixture, product, controls, output / "external"))
            except Exception as error:
                failures.append({"case": case["id"], "type": type(error).__module__ + "." + type(error).__qualname__,
                                 "message": str(error), "traceback": traceback.format_exc()})
        need(report["status"] == "RECORDED" and report["source_stable"] is True,
             "producer collection is HOLD or source changed")
        captured.stable()
    except Exception as error:
        failures.append({"case": None, "type": type(error).__module__ + "." + type(error).__qualname__,
                         "message": str(error), "traceback": traceback.format_exc()})
    try:
        captured.stable()
    except Exception as error:
        failures.append({"case": None, "type": type(error).__name__, "message": str(error)})
    return {"schema": "hepta.slot.definition.independent-readback.v1",
        "status": "PASS" if not failures and len(results) == 23 else "HOLD",
        "planned": list(IDS), "complete_controls": results, "failures": failures,
        "actual_inputs": captured.pins(), "product_imported_by_reader": False,
        "qualification_limits": {key: False for key in LIMITS}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "product-root", "product-freeze", "control-freeze", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("product-freeze-sha256", "control-freeze-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    value = readback(args.evidence, args.product_root, args.product_freeze,
        args.product_freeze_sha256, control_freeze=args.control_freeze,
        control_freeze_sha256=args.control_freeze_sha256, output=args.output)
    write_json(args.output / "READBACK.json", value)
    return 0 if value["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
