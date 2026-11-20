"""Root-only actual FD custody controls; never cold qualification.

Builds the test translation unit against the exact current FD bridge/core and
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
    "bytes": 47035,
    "sha256": "acba9327eb529bda8058e954e3725ec81acf749b3067fbfa1e199438e9c71567"
}
CONTROL_PIN = {
    "bytes": 22663,
    "sha256": "f851b0efdc98f20504ee55498d6c1af6a27a7e1ce557ee98a14c6e8b1aeac63f"
}
FD_CORE_PINS = {
    "tools/hia_cold_native_transport.h": {
        "bytes": 6835,
        "sha256": "991a91662abe9f23f9c04ec27f12f263b6a7911e69e3ac9c48cc5b9cb5493355"
    },
    "tools/hia_cold_native_transport.c": {
        "bytes": 54390,
        "sha256": "d2b08b290bfad1634263dc4c0b4dfce300c0fd44ec0f1f5aeb3749a89b9836a3"
    },
    "tools/hia_cold_native_transport_python.c": {
        "bytes": 47035,
        "sha256": "acba9327eb529bda8058e954e3725ec81acf749b3067fbfa1e199438e9c71567"
    },
    "tools/generate_hia_cold_native_transport.py": {
        "bytes": 23616,
        "sha256": "566e7b7a7d6ce07f4d61463bf54107a21bbe54f0da2e6e9b253df2d8591dfb9d"
    },
    "tools/hia_cold_native_transport_bridge.py": {
        "bytes": 17573,
        "sha256": "96d312386b09edfc9b81158a3f5a3c5988b022443c47cec1bb618caf60082dd1"
    }
}
IDS = [
    "FD-01-canonical-stdin",
    "FD-02-canonical-stdout",
    "FD-03-canonical-stderr",
    "FD-04-fileio-audit-refusal",
    "FD-05-buffer-allocation-stdin",
    "FD-06-buffer-allocation-stdout",
    "FD-07-buffer-allocation-stderr",
    "FD-08-raw-close-error-context",
    "FD-09-issued-slot-mismatch",
    "FD-10-stream-already-owned",
    "FD-11-terminal-residual",
    "FD-12-terminal-existing-raw",
    "FD-13-terminal-existing-stream",
    "FD-14-two-terminal-residuals",
    "FD-15-residual-dealloc-raised",
    "FD-16-real-policy-return",
    "FD-17-real-policy-buffer-error",
    "FD-18-real-policy-all-handoffs-refused"
]
SCHEMA = "hepta.cold-native-transport.fd-qualification.v1"
BUILD_SCHEMA = "hepta.cold-native-transport.hosted-build.r3"
CONTROL_SOURCE = "tools/hia_cold_native_transport_fd_controls.c"
BRIDGE_SOURCE = "tools/hia_cold_native_transport_python.c"
OWN_SOURCE = "tools/qualify_hia_cold_native_transport_fds.py"
C_COMPILE_SECONDS = 20
CONTROL_SECONDS = 60


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin_item(capture, item):
    require(type(item) is dict and type(item.get("path")) is str, "artifact path object differs")
    return capture.raw(item["path"], item["pin"])


def typed_report(report):
    require(report.get("schema") == "hepta.cold-native-transport.fd-controls.v1", "FD control schema")
    require(report.get("scope") == "ACTUAL_FD_CUSTODY_NOT_CT36_OR_COLD_QUALIFICATION", "FD control scope")
    require(type(report.get("planned")) is int and report["planned"] == 18, "FD planned count")
    rows = report.get("controls")
    require(type(rows) is list and [row.get("id") for row in rows] == IDS, "all 18 ordered actual FD controls")
    require(report.get("explicit_collect_calls") == 0 and type(report["explicit_collect_calls"]) is int
            and report.get("tracebacks_modified") is False and report.get("whole_native") is False,
            "FD control observation scope")
    require(report.get("unraisables") == [], "actual FD controls produced unraisable errors")
    integers = ("failure_line", "slot", "fd", "live_before", "live_after", "close_errno",
                "ownership", "audit_calls", "allocation_hits", "before_failures", "handoff_failures",
                "error_expected", "context_expected", "policy_complete", "reaped", "owner_lost",
                "child_created", "entries", "final_mask", "residual_mask")
    for row in rows:
        require(row.get("passed") is True and row.get("failure_line") == 0, "failed FD control: " + row["id"])
        require(all(type(row.get(key)) is int for key in integers), "FD control counter types")
        require(row["ownership"] in (0, 1, 3), "invalid ownership flag")
        error = row.get("error")
        require(error is None or type(error) is dict, "actual FD exception observation")
        if error is not None:
            require(type(error.get("id")) is int and error["id"] > 0 and type(error.get("type")) is str
                    and type(error.get("args")) is str and type(error.get("message")) is str
                    and type(error.get("traceback")) is list
                    and type(error.get("suppress_context")) is bool,
                    "raw FD exception identity/traceback")
    for index, slot in enumerate((2, 3, 5)):
        row = rows[index]
        require(row["slot"] == slot and row["ownership"] == 0 and row["live_before"] == 1
                and row["live_after"] == 0 and row["error"] is None, "actual canonical stream ownership")
    require(rows[3]["ownership"] == 0 and rows[3]["audit_calls"] == 1
            and rows[3]["error_expected"] == 1 and rows[3]["live_after"] == 1,
            "actual FileIO pre-adoption audit refusal leaves original FD live")
    for index in (4, 5, 6, 7):
        row = rows[index]
        require(row["ownership"] == 3 and row["allocation_hits"] == 1
                and row["live_after"] == 0 and row["error_expected"] == 1,
                "actual buffered allocation failure closes its real raw owner once")
    require(rows[7]["context_expected"] == 1 and rows[7]["error"]["type"] == "builtins.OSError"
            and rows[7]["error"]["errno"] == 9
            and rows[7]["error"]["context"]["type"] == "builtins.MemoryError",
            "actual raw-close error preserves prior buffer-allocation context")
    for index in (8, 9):
        require(rows[index]["ownership"] == 0 and rows[index]["error_expected"] == 1
                and rows[index]["live_after"] == 1, "issued slot/repeated owner refused without closing")
    for index, mask in ((10, 1), (11, 0), (12, 0), (13, 257), (14, 1)):
        require(rows[index]["residual_mask"] == mask and rows[index]["live_before"] == 1
                and rows[index]["live_after"] == 0, "actual terminal residual owner")
    require(rows[14]["error_expected"] == 1, "residual deallocation preserves exact raised exception")
    require(rows[15]["entries"] > 0 and rows[15]["policy_complete"] == 1 and rows[15]["reaped"] == 1
            and rows[15]["child_created"] == 1 and rows[15]["final_mask"] == rows[15]["residual_mask"] == 0,
            "actual current-policy complete child")
    require(rows[16]["entries"] > 0 and rows[16]["allocation_hits"] == 1
            and rows[16]["policy_complete"] == 1 and rows[16]["child_created"] == 0
            and rows[16]["final_mask"] == rows[16]["residual_mask"] == 0
            and rows[16]["error"]["type"] == "builtins.MemoryError", "actual HIA error cleanup")
    require(rows[17]["entries"] > 0 and rows[17]["before_failures"] == 1
            and rows[17]["handoff_failures"] >= 2 and rows[17]["policy_complete"] == 0
            and rows[17]["child_created"] == rows[17]["reaped"] == 1 and rows[17]["owner_lost"] == 0
            and rows[17]["final_mask"] == rows[17]["residual_mask"] == 1
            and rows[17]["live_before"] == 1 and rows[17]["live_after"] == 0
            and rows[17]["error_expected"] == 1, "all actual handoffs refused; nonzero custody remains explicit")
    require(report.get("status") == "CONTROLS_PASS", "FD control final status")
    return rows


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
    for name, expected in FD_CORE_PINS.items():
        capture.raw(ROOT / name, expected)
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


def qualify(manifest_path, output, target):
    capture = Captures()
    manifest_path, manifest_raw, manifest, include = bind(capture, manifest_path)
    target = Path(target).resolve(strict=True)
    target_raw = capture.raw(target)
    require(target_raw.startswith(b"\x7fELF"), "explicit actual FD control target is not ELF")
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    before = capture.pins()
    write_json(output / "before.json", {"consumed": before, "manifest": data_pin(manifest_raw),
               "ordered_ids": IDS, "cold_qualification": False})
    binary = output / "fd-controls"
    compile_command = compile_argv(manifest, include, binary)
    commands, report, errors = [], None, []
    try:
        commands.append(run_owned(compile_command, cwd=ROOT, directory=output / "compile-owned",
                                  timeout_seconds=C_COMPILE_SECONDS, environment=clean_environment()))
        require(successful_exit(commands[-1]), "control compiler did not terminate normally")
        binary_raw = capture.raw(binary)
        identity = data_pin(canonical(manifest["inputs"]))["sha256"]
        command = [str(binary), manifest["runtime"]["path"], manifest["policy"]["path"],
                   identity, str(target), str(output / "controls.json")]
        commands.append(run_owned(command, cwd=ROOT, directory=output / "controls-owned",
                                  timeout_seconds=CONTROL_SECONDS, environment=clean_environment()))
        require(successful_exit(commands[-1]), "actual FD control binary did not terminate normally")
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
            "schema": SCHEMA, "status": "FD_CONTROLS_PASS" if report is not None and not errors else "HOLD",
            "planned": len(IDS), "ordered_ids": IDS, "commands": commands, "errors": errors,
            "manifest": {"path": str(manifest_path), "pin": data_pin(manifest_raw)},
            "target": {"path": str(target), "pin": data_pin(target_raw)},
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
            "FD summary identity")
    manifest_path, manifest_raw, manifest, include = bind(capture, summary["manifest"]["path"])
    require(data_pin(manifest_raw) == summary["manifest"]["pin"], "original manifest raw identity")
    target = Path(summary["target"]["path"]).resolve(strict=True)
    target_raw = capture.raw(target, summary["target"]["pin"])
    require(target_raw.startswith(b"\x7fELF"), "actual control target")
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
    require(command == [str(output / "fd-controls"), manifest["runtime"]["path"],
            manifest["policy"]["path"], data_pin(canonical(manifest["inputs"]))["sha256"],
            str(target), str(output / "controls.json")], "control actual invocation")
    require(compiled["command"]["argv"] == compile_argv(manifest, include, output / "fd-controls"),
            "complete actual compile command")
    control_raw = capture.raw(output / "controls.json")
    report = parse(control_raw)
    typed_report(report)
    require(data_pin(control_raw) == summary["control_report"], "actual control raw snapshot")
    require(summary.get("status") == "FD_CONTROLS_PASS" and summary.get("errors") == []
            and summary.get("source_stable") is True and summary.get("qualification_complete") is False
            and summary.get("whole_native") is False, "summary must remain narrow")
    capture.unchanged()
    result = {"schema": "hepta.cold-native-transport.fd-readback.v1",
              "status": "FD_CONTROLS_READBACK_PASS", "ordered_ids": IDS, "planned": 18,
              "consumed": capture.pins(), "errors": [], "qualification_complete": False,
              "whole_native": False, "independent_cold_reader": False}
    capture.unchanged()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--readback-only", action="store_true")
    parser.add_argument("--target", type=Path, default=Path("/usr/bin/true"))
    args = parser.parse_args()
    if args.readback_only:
        require(args.manifest is None, "readback consumes the existing bound manifest")
        print(canonical(readback(args.output)).decode("ascii"))
    else:
        require(args.manifest is not None, "a complete actual R4-source build manifest is required")
        print(qualify(args.manifest, args.output, args.target))


if __name__ == "__main__":
    main()
