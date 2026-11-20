"""Root-only isolated R4 C ownership controls; never cold qualification.

Builds the test translation unit against the exact current R4 bridge/core and
the actual runtime/header/library/compiler identities from one real R3-format
build manifest. The original 44 / CT36 / HOF8 / cold gates remain independent.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
import sysconfig

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_cold_native_transport_evidence import (
    Captures, canonical, clean_environment, data_pin, parse, regular_bytes,
    run_owned, successful_exit, terminal_owned, write_json,
)

INPUTS = [
    "tools/hia_cold_native_transport.h",
    "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_driver.c",
    "tools/hia_cold_native_transport_python.c",
    "tools/hia_cold_native_transport_handoff_controls.c",
    "tools/hia_cold_native_transport_bridge.py",
    "tools/generate_hia_cold_native_transport.py",
    "tools/build_hia_cold_native_transport.py",
    "tools/hia_cold_native_transport_evidence.py",
    "tools/qualify_hia_cold_native_transport.py",
    "tools/read_hia_cold_native_transport.py",
    "examples/hia_bootstrap/cold_native_transport.hepta",
    "tools/hia_selfhost_native_observer.py",
    "tools/hia_selfhost_linked_observer.py",
    "tools/qualify_hia_selfhost.py",
    "tools/replay_hia_selfhost_cold.py",
    "tools/hia_selfhost_child.py",
    "tools/build_hia_json_preflight.py",
    "tools/build_hia_source_build.py",
    "tools/generate_hia_selfhost.py",
    "tools/generate_hia_native_observer.py",
    "tools/generate_hia_linked_observer.py",
    "tools/hia_native_observer_template.S",
    "tools/hia_linked_observer_bridge.S",
    "tests/test_hia_selfhost_native_observer.py",
    "tests/test_hia_selfhost_linked_observer.py",
    "tests/test_hia_linked_observer_build_custody.py",
    "tests/test_hia_cold_native_transport.py",
    "tests/fixtures/cold_native_transport_original_gates_v3.json",
    "tests/fixtures/cold_native_transport_controls_v3.json",
    "tools/run_hia_unittest_gate.py"
]
BRIDGE_PIN = {
    "bytes": 38967,
    "sha256": "9ace634b913441b0c7d9736cf50223be40a72664dbb98a12729aee43b8cadb2a"
}
CONTROL_PIN = {
    "bytes": 19332,
    "sha256": "55a2c4604cdb098a4b7eb42ae429f2981e3602f3779025a071a1e03be3c3c404"
}
IDS = [
    "REF-01-empty-handled-state",
    "REF-02-existing-caller",
    "REF-03-pending-over-caller",
    "REF-04-host-before-repeat",
    "REF-05-host-perform-error",
    "REF-06-host-error-eintr",
    "REF-07-handoff-before-commit",
    "REF-08-real-close-callback",
    "REF-09-profile-heap-type",
    "REF-10-session-heap-type",
    "REF-11-profile-init-refusal",
    "REF-12-clear-preserves-raised",
    "REF-13-dealloc-preserves-raised",
    "REF-14-profile-dealloc-preserves-raised",
    "REF-15-session-run-refusal",
    "REF-16-uninitialized-profile",
    "REF-17-cleared-profile",
    "REF-18-session-without-live-profile"
]
SCHEMA = "hepta.cold-native-transport.reference-qualification.r4"
BUILD_SCHEMA = "hepta.cold-native-transport.hosted-build.r3"
CONTROL_SOURCE = "tools/hia_cold_native_transport_reference_controls.c"
BRIDGE_SOURCE = "tools/hia_cold_native_transport_python.c"
OWN_SOURCE = "tools/qualify_hia_cold_native_transport_references.py"
C_COMPILE_SECONDS = 20
CONTROL_SECONDS = 60


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin_item(capture, item):
    require(type(item) is dict and type(item.get("path")) is str, "artifact path object differs")
    return capture.raw(item["path"], item["pin"])


def typed_report(report):
    require(report.get("schema") == "hepta.cold-native-transport.reference-controls.r4", "control report schema")
    require(report.get("scope") == "ISOLATED_C_API_OWNERSHIP_NOT_CT36_OR_COLD_QUALIFICATION", "scope")
    require(type(report.get("planned")) is int and report["planned"] == len(IDS), "planned controls")
    rows = report.get("controls")
    require(type(rows) is list and [row.get("id") for row in rows] == IDS, "complete ordered controls")
    require(report.get("explicit_collect_calls") == 0 and type(report.get("explicit_collect_calls")) is int,
            "no explicit collect")
    require(report.get("tracebacks_modified") is False and report.get("whole_native") is False, "declared boundary")
    require(type(report.get("unraisables")) is list and len(report["unraisables"]) == 2, "actual two close errors")
    for index, event in enumerate(report["unraisables"]):
        require(event.get("exception_type") == "builtins.OSError" and event.get("errno") == 9,
                "actual EBADF close event")
        require(type(event.get("message")) is str and type(event.get("exception_id")) is int,
                "actual primitive exception observation")
        require(type(event.get("traceback_present")) is bool, "actual traceback presence")
        if index == 0:
            require(event.get("object_type") == "_hia_cold_native_transport.Session"
                    and type(event.get("object_id")) is int, "live tp_clear context")
        else:
            require(event.get("object_type") is None and event.get("object_id") is None,
                    "deallocator must not expose dying Session")
    for row in rows:
        require(row.get("passed") is True and type(row.get("failure_line")) is int and row["failure_line"] == 0,
                "failed actual reference control: " + row["id"])
        require(row.get("weak_dead") is True, "actual weak referents remain live")
        for key in ("before_refs", "after_refs", "before_type_refs", "after_type_refs",
                    "unraisable_start", "unraisable_end"):
            require(type(row.get(key)) is int, "typed counter " + key)
        for key in ("type_visited", "raised_same", "handled_same"):
            require(type(row.get(key)) is bool, "typed relation " + key)
        if row["before_refs"] >= 0:
            require(row["before_refs"] == row["after_refs"], "owned exception reference balance")
        if row["before_type_refs"] >= 0:
            require(row["before_type_refs"] == row["after_type_refs"], "heap type reference balance")
    for i in (8, 9):
        require(rows[i]["type_visited"] is True, "real heap type traversal edge")
    for i in (11, 12, 13):
        require(rows[i]["raised_same"] is True, "entry raised exception identity")
    for i in (*range(8), 14):
        require(rows[i]["handled_same"] is True, "handled exception identity")
    require(report.get("status") == "CONTROLS_PASS", "control terminal status")
    return rows



FD_SUCCESSOR = "tests/fixtures/cold_native_transport_fd_successor_v1.json"
FD_SUCCESSOR_PIN = {"bytes":29649,"sha256":"3acef4505b499774c107e747828e8ab5d6334ec1cdf644ae6dd46657526db545"}
FD_PATHS = (
    "tools/hia_cold_native_transport.h",
    "tools/hia_cold_native_transport.c",
    "tools/hia_cold_native_transport_python.c",
    "tools/generate_hia_cold_native_transport.py",
    "tools/hia_cold_native_transport_bridge.py",
)


def replay_source_edits(raw, edits, *, inverse=False):
    require(type(raw) is bytes and type(edits) is list, "complete source replay types")
    for edit in (reversed(edits) if inverse else edits):
        require(type(edit) is dict and set(edit) == {"before", "after"}
                and type(edit["before"]) is str and type(edit["after"]) is str,
                "literal source edit fields")
        left, right = edit["before"].encode("utf-8"), edit["after"].encode("utf-8")
        require(left and right, "nonempty reversible source edit")
        source, target = (right, left) if inverse else (left, right)
        require(raw.count(source) == 1, "unique full source edit occurrence")
        raw = raw.replace(source, target, 1)
    return raw


def admit_reference_sources(capture):
    """Admit only one complete pinned R4, FD or timeout source bundle."""
    fixture = parse(capture.raw(ROOT / FD_SUCCESSOR, FD_SUCCESSOR_PIN))
    require(set(fixture) == {"schema", "allowed_source_modes", "mixed_modes",
                             "whole_native", "files", "timeout_successor"}
            and fixture["schema"] == "hepta.cold-native-transport.fd-successor.v3"
            and fixture["allowed_source_modes"] == [
                "exact-reference-r4", "exact-fd-custody-v1", "exact-timeout-generation-v2"]
            and fixture["mixed_modes"] is False and fixture["whole_native"] is False,
            "fixed complete FD and timeout successor authority")
    rows = fixture["files"]
    successor = fixture["timeout_successor"]
    require(type(rows) is list and tuple(row["path"] for row in rows) == FD_PATHS
            and all(type(row) is dict and set(row) == {"path", "before", "after", "edits"}
                    for row in rows), "complete original five-source FD authority")
    require(type(successor) is dict and set(successor) == {
                "schema", "before_mode", "after_mode", "files"}
            and successor["schema"] == "hepta.cold-native-transport.timeout-fields-and-generation-successor.v2"
            and successor["before_mode"] == "exact-fd-custody-v1"
            and successor["after_mode"] == "exact-timeout-generation-v2",
            "explicit third whole-source authority")
    timeout_rows = successor["files"]
    require(type(timeout_rows) is list
            and tuple(row["path"] for row in timeout_rows) == FD_PATHS
            and all(type(row) is dict and set(row) == {"path", "before", "after", "edits"}
                    for row in timeout_rows), "complete five-source timeout authority")
    require(all(later["before"] == earlier["after"]
                for earlier, later in zip(rows, timeout_rows)),
            "timeout lineage starts at the exact full FD bundle")
    captured = {name: capture.raw(ROOT / name) for name in FD_PATHS}
    actual = {name: data_pin(raw) for name, raw in captured.items()}
    bundles = {
        "exact-reference-r4": {row["path"]: row["before"] for row in rows},
        "exact-fd-custody-v1": {row["path"]: row["after"] for row in rows},
        "exact-timeout-generation-v2": {row["path"]: row["after"] for row in timeout_rows},
    }
    modes = [name for name, pins in bundles.items() if actual == pins]
    require(len(modes) == 1,
            "mixed or unknown sources are not one admitted complete source bundle")
    mode = modes[0]
    for row, later in zip(rows, timeout_rows):
        raw = captured[row["path"]]
        if mode == "exact-reference-r4":
            fd_raw = replay_source_edits(raw, row["edits"])
        elif mode == "exact-fd-custody-v1":
            fd_raw = raw
        else:
            fd_raw = replay_source_edits(raw, later["edits"], inverse=True)
        require(data_pin(fd_raw) == row["after"] == later["before"],
                "whole FD source reconstruction")
        original = replay_source_edits(fd_raw, row["edits"], inverse=True)
        require(data_pin(original) == row["before"]
                and replay_source_edits(original, row["edits"]) == fd_raw,
                "whole original inverse and exact FD replay")
        latest = replay_source_edits(fd_raw, later["edits"])
        require(data_pin(latest) == later["after"]
                and replay_source_edits(latest, later["edits"], inverse=True) == fd_raw,
                "whole timeout forward and exact inverse")
        require(raw == {"exact-reference-r4": original,
                        "exact-fd-custody-v1": fd_raw,
                        "exact-timeout-generation-v2": latest}[mode],
                "reconstructed source differs from its actual captured bytes")
        if row["path"] == BRIDGE_SOURCE:
            require(data_pin(original) == BRIDGE_PIN, "original R4 bridge authority unchanged")
    capture.unchanged()
    return mode


def bind(capture, manifest_path):
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest_raw = capture.raw(manifest_path)
    manifest = parse(manifest_raw)
    require(manifest.get("schema") == BUILD_SCHEMA
            and manifest.get("status") == "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            and manifest.get("whole_native") is False, "actual unqualified build manifest")
    require(manifest.get("source_root") == str(ROOT), "current source root")
    require(type(manifest.get("inputs")) is dict and set(manifest["inputs"]) == set(INPUTS), "complete build inputs")
    for name in INPUTS:
        capture.raw(ROOT / name, manifest["inputs"][name])
    admit_reference_sources(capture)
    capture.raw(ROOT / CONTROL_SOURCE, CONTROL_PIN)
    capture.raw(ROOT / OWN_SOURCE)
    for key in ("policy", "extension", "probe", "handoff_controls", "compiler", "build_tool", "python_library"):
        pin_item(capture, manifest[key])
    runtime = manifest["runtime"]
    require(runtime["path"] == str(Path(sys.executable).resolve(strict=True))
            and runtime["version"] == sys.version, "actual runtime identity")
    capture.raw(runtime["path"], runtime["pin"])
    capture.raw(runtime["subprocess_path"], runtime["subprocess_pin"])
    include = Path(sysconfig.get_paths()["include"]).resolve(strict=True)
    headers = {str(path): data_pin(capture.raw(path)) for path in sorted(include.rglob("*.h"))}
    require(headers == manifest["python_headers"] and str(include / "Python.h") in headers,
            "whole runtime header closure")
    require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14),
            "explicit CPython 3.14")
    capture.unchanged()
    return manifest_path, manifest_raw, manifest, include


def compile_argv(manifest, include, binary):
    library = Path(manifest["python_library"]["path"])
    return [
        manifest["build_tool"]["path"], "-std=c11", "-O2", "-fno-strict-aliasing",
        "-Werror=implicit-function-declaration", "-I" + str(include),
        "-I" + str(ROOT / "tools"), "-pthread", "-Wl,-z,noexecstack",
        "-Wl,-z,relro", "-Wl,-z,now", str(ROOT / "tools/hia_cold_native_transport.c"),
        str(ROOT / CONTROL_SOURCE), str(library), "-Wl,-rpath," + str(library.parent),
        "-ldl", "-lm", "-o", str(binary),
    ]


def qualify(manifest_path, output):
    capture = Captures()
    manifest_path, manifest_raw, manifest, include = bind(capture, manifest_path)
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    before = capture.pins()
    write_json(output / "before.json", {"consumed": before, "manifest": data_pin(manifest_raw),
               "ordered_ids": IDS, "cold_qualification": False})
    binary = output / "reference-controls"
    compile_command = compile_argv(manifest, include, binary)
    commands, report, errors = [], None, []
    try:
        commands.append(run_owned(compile_command, cwd=ROOT, directory=output / "compile-owned",
                                  timeout_seconds=C_COMPILE_SECONDS, environment=clean_environment()))
        require(successful_exit(commands[-1]), "control compiler did not terminate normally")
        binary_raw = capture.raw(binary)
        identity = data_pin(canonical(manifest["inputs"]))["sha256"]
        command = [str(binary), manifest["runtime"]["path"], manifest["policy"]["path"],
                   identity, str(output / "controls.json")]
        commands.append(run_owned(command, cwd=ROOT, directory=output / "controls-owned",
                                  timeout_seconds=CONTROL_SECONDS, environment=clean_environment()))
        require(successful_exit(commands[-1]), "actual reference control binary did not terminate normally")
        report = capture.json(output / "controls.json")
        typed_report(report)
        terminal_owned(capture, output / "compile-owned", seconds=C_COMPILE_SECONDS,
                       expected_argv=compile_command, cwd=ROOT)
        terminal_owned(capture, output / "controls-owned", seconds=CONTROL_SECONDS,
                       expected_argv=command, cwd=ROOT)
        require(data_pin(binary_raw) == data_pin(capture.raw(binary)), "control binary changed")
        capture.unchanged()
    except BaseException as error:
        errors.append({"type": type(error).__module__ + "." + type(error).__qualname__,
                       "message": str(error)})
        raise
    finally:
        write_json(output / "report.json", {
            "schema": SCHEMA, "status": "REFERENCE_CONTROLS_PASS" if report is not None and not errors else "HOLD",
            "planned": len(IDS), "ordered_ids": IDS, "commands": commands, "errors": errors,
            "manifest": {"path": str(manifest_path), "pin": data_pin(manifest_raw)},
            "consumed": capture.pins(), "source_before": before,
            "source_stable": not errors, "control_report": None if report is None else data_pin(capture.raw(output / "controls.json")),
            "whole_native": False, "qualification_complete": False, "explicit_collect_calls": 0,
            "replaces_CT36": False, "replaces_original44": False, "replaces_HOF8": False,
            "original_cold_timeout_seconds": 180, "original_cold_cleanup_seconds": 3,
            "original_root_outer_timeout_seconds": 240,
        })
    capture.unchanged()
    return output / "report.json"


def readback(output):
    capture = Captures()
    output = Path(output).resolve(strict=True)
    summary = capture.json(output / "report.json")
    require(summary.get("schema") == SCHEMA and summary.get("ordered_ids") == IDS,
            "reference summary identity")
    manifest_path, manifest_raw, manifest, include = bind(capture, summary["manifest"]["path"])
    require(data_pin(manifest_raw) == summary["manifest"]["pin"], "original manifest raw identity")
    before = capture.json(output / "before.json")
    require(before["ordered_ids"] == IDS and before["consumed"] == summary["source_before"],
            "pre-execution source evidence")
    for path, expected in summary["consumed"].items():
        capture.raw(path, expected)
    for path, expected in summary["source_before"].items():
        capture.raw(path, expected)
    _, compiled = terminal_owned(capture, output / "compile-owned", seconds=C_COMPILE_SECONDS, cwd=ROOT)
    _, actual = terminal_owned(capture, output / "controls-owned", seconds=CONTROL_SECONDS, cwd=ROOT)
    require(summary["commands"] == [compiled, actual], "owned command reports")
    command = actual["command"]["argv"]
    require(command == [str(output / "reference-controls"), manifest["runtime"]["path"],
            manifest["policy"]["path"], data_pin(canonical(manifest["inputs"]))["sha256"],
            str(output / "controls.json")], "control actual invocation")
    require(compiled["command"]["argv"] == compile_argv(manifest, include, output / "reference-controls"),
            "complete actual compile command")
    control_raw = capture.raw(output / "controls.json")
    report = parse(control_raw)
    typed_report(report)
    require(data_pin(control_raw) == summary["control_report"], "actual control raw snapshot")
    require(summary.get("status") == "REFERENCE_CONTROLS_PASS" and summary.get("errors") == []
            and summary.get("source_stable") is True and summary.get("qualification_complete") is False
            and summary.get("whole_native") is False, "summary must remain narrow")
    capture.unchanged()
    result = {"schema": "hepta.cold-native-transport.reference-readback.r4",
              "status": "REFERENCE_CONTROLS_READBACK_PASS", "ordered_ids": IDS, "planned": 18,
              "consumed": capture.pins(), "errors": [], "qualification_complete": False,
              "whole_native": False, "independent_cold_reader": False}
    capture.unchanged()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--readback-only", action="store_true")
    args = parser.parse_args()
    if args.readback_only:
        require(args.manifest is None, "readback consumes the existing bound manifest")
        print(canonical(readback(args.output)).decode("ascii"))
    else:
        require(args.manifest is not None, "a complete actual R4-source build manifest is required")
        print(qualify(args.manifest, args.output))


if __name__ == "__main__":
    main()
