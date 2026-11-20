"""Independent DATA-only reader for the full 44+44+8 R3 regression evidence.

This reads complete raw logs/receipts and both original reports. It never
imports a product, producer or its helper. This is not the 17-reference /
38-phase cold binary/archive reader, which remains separately mandatory.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_INPUTS = (
    "tools/hia_cold_native_transport.h", "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_driver.c", "tools/hia_cold_native_transport_python.c",
    "tools/hia_cold_native_transport_handoff_controls.c",
    "tools/hia_cold_native_transport_bridge.py", "tools/generate_hia_cold_native_transport.py",
    "tools/build_hia_cold_native_transport.py", "tools/hia_cold_native_transport_evidence.py",
    "tools/qualify_hia_cold_native_transport.py", "tools/read_hia_cold_native_transport.py",
    "examples/hia_bootstrap/cold_native_transport.hepta",
    "tools/hia_selfhost_native_observer.py", "tools/hia_selfhost_linked_observer.py",
    "tools/qualify_hia_selfhost.py", "tools/replay_hia_selfhost_cold.py", "tools/hia_selfhost_child.py",
    "tools/build_hia_json_preflight.py", "tools/build_hia_source_build.py",
    "tools/generate_hia_selfhost.py", "tools/generate_hia_native_observer.py",
    "tools/generate_hia_linked_observer.py", "tools/hia_native_observer_template.S",
    "tools/hia_linked_observer_bridge.S",
    "tests/test_hia_selfhost_native_observer.py", "tests/test_hia_selfhost_linked_observer.py",
    "tests/test_hia_linked_observer_build_custody.py",
    "tests/test_hia_cold_native_transport.py",
    "tests/fixtures/cold_native_transport_original_gates_v3.json",
    "tests/fixtures/cold_native_transport_controls_v3.json",
    "tools/run_hia_unittest_gate.py",
)
GATE_SHA = "8720447c115e1737dc395271ebb91bb4c8bd5a83bc89558224058b09371bc1d5"
CONTROL_SHA = "abe86cfac29a3527efbf97101ef47da68d8258e1c5b8aa881bf8a8fc5b47b76d"


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value, expected=None):
    require(type(value) is int and (expected is None or value == expected), "exact integer differs")
    return value


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def pairs(rows):
    out = {}
    for key, value in rows:
        require(key not in out, "duplicate key")
        out[key] = value
    return out


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))


class Raw:
    def __init__(self):
        self.values = {}

    def take(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "regular input required")
        data = path.read_bytes()
        after = path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, name) == getattr(after, name) for name in fields)
                and len(data) == after.st_size, "read changed or short")
        if expected is not None:
            require(type(expected) is dict and set(expected) == {"bytes", "sha256"}, "exact pin shape differs")
            integer(expected["bytes"])
            require(type(expected["sha256"]) is str and pin(data) == expected, "consumed bytes differ")
        require(self.values.setdefault(path, data) == data, "repeat consumption differs")
        return data

    def json(self, path, expected=None):
        return parse(self.take(path, expected))

    def unchanged(self):
        for path, raw in self.values.items():
            require(path.read_bytes() == raw, "terminal complete raw reread differs")

    def inventory(self):
        return {str(path): pin(raw) for path, raw in sorted(self.values.items(), key=lambda row: str(row[0]))}


def owned(raw, directory, expected_argv, cwd, seconds):
    directory = Path(directory)
    command = raw.json(directory / "command.json")
    result = raw.json(directory / "result.json")
    require(command == result["command"], "actual command/result differs")
    require(command["argv"] == list(map(str, expected_argv))
            and command["cwd"] == str(Path(cwd).resolve()), "actual argv/cwd differs")
    integer(command["timeout_seconds"], seconds);integer(command["cleanup_seconds"], 3)
    require(command["new_session"] is True, "owned session was not declared")
    pid = integer(command["pid"]);require(pid > 0, "actual child PID missing")
    integer(command["pgid"], pid);integer(result["pid"], pid)
    integer(result["exit_code"], 0)
    require(result["timed_out"] is False and result["interruption"] is None, "child interrupted or timed out")
    cleanup = result["owned_cleanup"]
    require(type(cleanup) is dict and cleanup["reaped"] is True
            and cleanup["after"] == [] and cleanup["signals"] == [], "owned child did not terminate naturally and clear")
    raw.take(directory / "stdout.log", result["stdout"])
    raw.take(directory / "stderr.log", result["stderr"])
    start = integer(command["started_monotonic_ns"])
    end = integer(result["ended_monotonic_ns"])
    require(0 < start <= end, "actual command times differ")
    return command, result, start, end


def child(raw, path, expected, source, selected, extra):
    row = raw.json(path)
    require(row["schema"] == "hepta.cold-native-transport.original-gate-child.r3"
            and row["status"] == "COMPLETE_ORIGINAL_METHODS_PASS", "child gate is not complete")
    require(row["selected"] is selected and row["extra_handoff_controls"] is extra, "actual selection differs")
    require(row["planned"] == expected and row["started"] == expected and row["stopped"] == expected,
            "complete ordered original methods differ")
    integer(row["tests_run"], len(expected))
    require(row["statuses"] == {identity: "ok" for identity in expected}, "method outcomes differ")
    for key in ("problems", "errors", "failures", "skips", "expected_failures", "unexpected_successes"):
        require(row[key] == [], "original method anomaly: " + key)
    require(row["source_before"] == source and row["source_after"] == source
            and row["source_stable"] is True, "full component source changed")
    if selected and not extra:
        require(row["native_profiles"], "actual native public profile receipts absent")
        require(sum(integer(profile["calls"]) for profile in row["native_profiles"]) > 0,
                "no real selected public calls")
        for profile in row["native_profiles"]:
            require(integer(profile["entries"]) >= integer(profile["calls"]), "native entries missing")
    if not selected:
        require(row["native_profiles"] == [], "original lane used native selection")
    require(row["whole_native"] is False and row["qualification_complete"] is False,
            "child overstates its scope")
    for path, expected_pin in row["consumed"].items():
        raw.take(path, expected_pin)
    return row


def read(evidence, *, manifest_path, manifest_pin, source_root):
    evidence, source_root = Path(evidence).resolve(strict=True), Path(source_root).resolve(strict=True)
    raw = Raw()
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = raw.json(manifest_path, manifest_pin)
    require(manifest["schema"] == "hepta.cold-native-transport.hosted-build.r3"
            and manifest["status"] == "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            and manifest["whole_native"] is False, "unknown native build selection")
    require(manifest["source_root"] == str(source_root)
            and set(manifest["inputs"]) == set(SOURCE_INPUTS), "complete source closure differs")
    source = {}
    for name in SOURCE_INPUTS:
        source[name] = pin(raw.take(source_root / name, manifest["inputs"][name]))
    plan_raw = raw.take(source_root / "tests/fixtures/cold_native_transport_original_gates_v3.json")
    controls_raw = raw.take(source_root / "tests/fixtures/cold_native_transport_controls_v3.json")
    require(sha256(plan_raw).hexdigest() == GATE_SHA and sha256(controls_raw).hexdigest() == CONTROL_SHA,
            "independent original control authority changed")
    plan, controls = parse(plan_raw), parse(controls_raw)
    expected = plan["original_method_ids"]
    require(integer(plan["original_method_count"], 44) and len(expected) == 44
            and len(set(expected)) == 44, "complete original 44 identities differ")
    for name, expected_pin in plan["original_tests"].items():
        raw.take(source_root / name, expected_pin)
    for item in plan["original_observers"]:
        text = raw.take(source_root / item["path"])
        tail = item["selection_tail"].encode()
        require(text.endswith(tail) and pin(text[:-len(tail)]) == item["before"],
                "original full observer inverse differs")
    for key in ("policy", "extension", "probe", "handoff_controls", "compiler", "build_tool", "python_library"):
        item = manifest[key];raw.take(item["path"], item["pin"])
    runtime = manifest["runtime"]
    raw.take(runtime["path"], runtime["pin"])
    raw.take(runtime["subprocess_path"], runtime["subprocess_pin"])
    for path, expected_pin in manifest["python_headers"].items():
        raw.take(path, expected_pin)
    report = raw.json(evidence / "report.json")
    require(report["schema"] == "hepta.cold-native-transport.gates.r3"
            and report["scope"] == "regression"
            and report["status"] == "ORIGINAL44_SELECTED44_HANDOFF8_PASS_NOT_WHOLE_COLD",
            "not a complete R3 regression report")
    require(report["source_before"] == source and report["source_after"] == source
            and report["source_stable"] is True
            and report["whole_native"] is False and report["qualification_complete"] is False,
            "regression source/scope differs")
    lanes = ("original-1", "original-2", "selected", "atomic-handoff-8")
    require([row["lane"] for row in report["lanes"]] == list(lanes)
            and len(report["commands"]) == 4, "full original-before-candidate lanes differ")
    previous_end = 0
    children = []
    for ordinal, lane in enumerate(lanes):
        selected, extra = ordinal >= 2, ordinal == 3
        command = [runtime["path"], "-I", "-S", "-B",
                   str(source_root / "tools/qualify_hia_cold_native_transport.py"),
                   "--child", str(evidence / lane)]
        if selected:command.append("--selected")
        if extra:command.append("--handoff")
        actual, result, start, end = owned(raw, evidence / (lane + "-owned"), command, source_root, 1800)
        require(previous_end <= start and result == report["commands"][ordinal], "lane order or complete receipt differs")
        previous_end = end
        environment = actual["environment"]
        require(("HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST" in environment) is selected, "lane selector differs")
        if selected:
            require(environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST"] == str(manifest_path)
                    and environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_ALLOW_DEVELOPMENT"] == "1",
                    "selected actual manifest differs")
        expected_ids = (["tests.test_hia_cold_native_transport.ColdNativeTransportHandoffTests.test_all_eight_actual_atomic_handoff_controls"]
                        if extra else expected)
        expected_pin = report["lanes"][ordinal]["report"]
        raw.take(evidence / lane / "report.json", expected_pin)
        children.append(child(raw, evidence / lane / "report.json", expected_ids, source, selected, extra))
    authority = raw.json(evidence / "original-authority.json")
    require(authority["schema"] == "hepta.cold-native-transport.original-method-authority.r3"
            and authority["planned"] == expected and authority["source"] == source
            and authority["method_outcomes_only"] is True, "original authority differs")
    require(authority["reports"] == [pin(raw.take(evidence / lane / "report.json")) for lane in lanes[:2]]
            and children[0]["statuses"] == children[1]["statuses"], "two complete original reports differ")
    control_dir = evidence / "actual-handoff-8"
    executable = manifest["handoff_controls"]["path"]
    control_command = [executable, runtime["path"], str(control_dir / "controls.json")]
    owned(raw, control_dir / "owned", control_command, source_root, 60)
    require(raw.take(control_dir / "owned/stdout.log") == b"" and raw.take(control_dir / "owned/stderr.log") == b"",
            "atomic handoff control emitted unexpected output or unraisable diagnostics")
    observed = raw.json(control_dir / "controls.json")
    required = controls["handoff_controls"]
    integer(observed["planned"], 8)
    require(observed["schema"] == "hepta.cold-native-transport.handoff-controls.r3"
            and observed["status"] == "CONTROLS_PASS"
            and observed["whole_native"] is False and len(observed["controls"]) == 8,
            "actual native handoff controls incomplete")
    for actual, expected_row in zip(observed["controls"], required):
        require(actual["id"] == expected_row["id"] and actual["passed"] is True,
                "declared handoff control differs")
        integer(actual["handoff_return"], expected_row["expected_return"])
        require(actual["actual_pending"] is expected_row["expected_pending"], "actual pending-error observation differs")
        integer(actual["failure_line"], 0)
    for index in (0, 1, 4, 5):
        require(observed["controls"][index]["real_number_reuse_checked"] is True,
                "failed adoption did not test actual replacement descriptor survival")
    nested = raw.json(control_dir / "readback.json")
    require(nested["controls"] == [row["id"] for row in required]
            and nested["source_stable"] is True and nested["whole_native"] is False
            and nested["qualification_complete"] is False, "test's full control readback differs")
    for path, expected_pin in nested["consumed"].items():raw.take(path, expected_pin)
    for path, expected_pin in report["consumed"].items():raw.take(path, expected_pin)
    raw.unchanged()
    result = {"schema": "hepta.cold-native-transport.regression-readback.r3",
              "evidence_integrity": "PASS", "original_methods_each": 44,
              "original_runs": 2, "selected_methods": 44, "actual_handoff_controls": 8,
              "complete_original_id_order": expected, "all_consumed": raw.inventory(),
              "source_stable": True, "whole_native": False, "qualification_complete": False,
              "cold_complete_17_references_38_phases": "SEPARATE_ORIGINAL_FULL_RAW_READER_REQUIRED",
              "broader_CT36": "DECLARED_NOT_SUBSTITUTED_BY_HANDOFF8"}
    raw.unchanged()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-bytes", type=int, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("independent readback is create-only")
    result = read(args.evidence, manifest_path=args.manifest,
                  manifest_pin={"bytes": args.manifest_bytes, "sha256": args.manifest_sha256},
                  source_root=args.source_root)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"evidence_integrity": result["evidence_integrity"],
                      "qualification_complete": False, "whole_native": False}, sort_keys=True))


if __name__ == "__main__":
    main()
