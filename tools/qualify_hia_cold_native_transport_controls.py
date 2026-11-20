"""Complete CT36 executable owner, additional to every retained original gate.

It creates two complete fresh original observation lanes first, freezes their
actual child reports and consumed bytes, and only then starts selected public
and actual-HIA defensive controls. No old case, limit, observer or expectation
is replaced. This component cannot authorize cold or whole-native release.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_cold_native_transport_evidence import (
    Captures, canonical, clean_environment, data_pin, parse, regular_bytes,
    run_owned, successful_exit, terminal_owned, write_json)
from tools.hia_cold_native_transport_bridge import SOURCE_INPUTS, SELECTOR, DEVELOPMENT
from tests.hia_cold_native_transport_control_cases import source_capture

FIXTURE = ROOT / "tests/fixtures/cold_native_transport_controls_v4.json"
SCHEMA = "hepta.cold-native-transport.ct36-owner.v4"
CORE_PINS = {
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bind(capture, manifest_path):
    manifest_path = Path(manifest_path).resolve(strict=True)
    manifest = capture.json(manifest_path)
    require(manifest.get("schema") == "hepta.cold-native-transport.hosted-build.r3"
            and manifest.get("status") == "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            and manifest.get("whole_native") is False, "actual hosted transport build is required")
    require(manifest.get("source_root") == str(ROOT), "build current source root differs")
    require(type(manifest.get("inputs")) is dict
            and tuple(manifest["inputs"]) == tuple(sorted(SOURCE_INPUTS)), "complete current build input order")
    for name, expected in manifest["inputs"].items():
        capture.raw(ROOT / name, expected)
    for name, expected in CORE_PINS.items():
        capture.raw(ROOT / name, expected)
    for name in ("policy", "extension", "probe", "handoff_controls", "compiler",
                 "build_tool", "python_library"):
        item = manifest[name]
        capture.raw(item["path"], item["pin"])
    runtime = manifest["runtime"]
    require(Path(runtime["path"]).resolve(strict=True) == Path(sys.executable).resolve(strict=True)
            and runtime["version"] == sys.version, "actual runtime differs")
    capture.raw(runtime["path"], runtime["pin"])
    capture.raw(runtime["subprocess_path"], runtime["subprocess_pin"])
    for name, expected in manifest["python_headers"].items():
        capture.raw(name, expected)
    capture.unchanged()
    return manifest_path, manifest


def consume_child(capture, directory, command, seconds, *, schema):
    directory = Path(directory)
    actual_command, result = terminal_owned(capture, directory / "owned", seconds=seconds,
                                            expected_argv=command, cwd=ROOT)
    report_path = directory / "observation/report.json"
    raw = capture.raw(report_path)
    report = parse(raw)
    require(report.get("schema") == schema, "actual child schema differs")
    require(type(report.get("files")) is dict, "child must bind complete observed files")
    for relative, expected in report["files"].items():
        path = Path(relative)
        require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == relative,
                "noncanonical child evidence path")
        capture.raw(directory / "observation" / path, expected)
    # The observations consumed below are exactly these already validated bytes,
    # never a later read followed by a freshly self-signed pin.
    return {"directory": str(directory / "observation"),
            "report": {"path": str(report_path), "pin": data_pin(raw)},
            "command": {"path": str(directory / "owned/command.json"),
                        "pin": data_pin(capture.raw(directory / "owned/command.json"))},
            "terminal": {"path": str(directory / "owned/result.json"),
                         "pin": data_pin(capture.raw(directory / "owned/result.json"))},
            "planned": report.get("planned"), "started": report.get("started"),
            "stopped": report.get("stopped"), "ended_monotonic_ns": result["ended_monotonic_ns"]}, report


def qualify(output, manifest_path):
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    capture = Captures()
    manifest_path, manifest = bind(capture, manifest_path)
    fixture = capture.json(FIXTURE)
    require(fixture["ordered_ids"] == ["CT-%02d" % i for i in range(1, 37)],
            "all original CT36 IDs/order are mandatory")
    before = source_capture(capture)
    environment = clean_environment()
    environment.pop(SELECTOR, None)
    environment.pop(DEVELOPMENT, None)
    runtime = str(Path(sys.executable).resolve(strict=True))
    python = [runtime, "-I", "-S", "-B"]
    deadline = time.monotonic() + 1800
    report = {"schema": SCHEMA, "status": "HOLD", "source_before": before,
              "fixture": {"path": str(FIXTURE), "pin": data_pin(capture.raw(FIXTURE))},
              "manifest": {"path": str(manifest_path), "pin": data_pin(capture.raw(manifest_path))},
              "ordered_ids": fixture["ordered_ids"], "commands": [], "originals": [],
              "selected": None, "policy_controls": [], "budgets": fixture["budgets"],
              "whole_native": False, "qualification_complete": False}
    try:
        cc = str(Path(manifest["build_tool"]["path"]).resolve(strict=True))
        common = [cc, "-std=c11", "-O2", "-fno-strict-aliasing",
                  "-Werror=implicit-function-declaration", "-I" + str(ROOT / "tools"),
                  "-pthread", "-Wl,-z,noexecstack", "-Wl,-z,relro", "-Wl,-z,now"]
        target = output / "ct36-target"
        policy_control = output / "ct36-policy-controls"
        for label, source, executable in (
                ("target", ROOT / "tools/hia_cold_native_transport_control_target.c", target),
                ("policy-controls", ROOT / "tools/hia_cold_native_transport_policy_controls.c", policy_control)):
            command = [*common, str(source), "-o", str(executable)]
            directory = output / ("build-" + label)
            result = run_owned(command, cwd=ROOT, directory=directory, timeout_seconds=20,
                               environment=environment, deadline=deadline)
            report["commands"].append(str(directory))
            require(successful_exit(result), "complete actual C build failed: " + label)
            terminal_owned(capture, directory, seconds=20, expected_argv=command, cwd=ROOT)
            capture.raw(executable)
        report["binaries"] = {
            "target": {"path": str(target), "pin": data_pin(capture.raw(target))},
            "policy_controls": {"path": str(policy_control), "pin": data_pin(capture.raw(policy_control))},
        }
        observers = output / "observer-build"
        observers.mkdir(mode=0o700)
        command = [*python, str(ROOT / "tests/hia_cold_native_transport_control_cases.py"),
                   "build-observers", "--output", str(observers / "observation")]
        result = run_owned(command, cwd=ROOT, directory=observers / "owned",
                           timeout_seconds=600, environment=environment, deadline=deadline)
        report["commands"].append(str(observers / "owned"))
        require(successful_exit(result), "complete original independent observer build failed")
        build_lane, build_report = consume_child(
            capture, observers, command, 600, schema="hepta.cold-native-transport.ct36-observers.v4")
        require(build_report["status"] == "BUILT_NOT_QUALIFIED"
                and build_report["source_before"] == before == build_report["source_after"]
                and build_report["flat_reference"]["before_B0"] is True
                and build_report["linked_reference"]["before_B0"] is True,
                "actual original reference/build order and source binding differ")
        report["observer_build"] = build_lane
        authority_path = output / "original-authority.json"
        planned = [case["subcase"] for case in fixture["public_cases"]]
        original_rows = []
        for lane_name in ("original-1", "original-2"):
            lane = output / lane_name
            lane.mkdir(mode=0o700)
            command = [*python, str(ROOT / "tests/hia_cold_native_transport_control_cases.py"),
                       "lane", "--lane", lane_name, "--output", str(lane / "observation"),
                       "--observers", build_lane["report"]["path"], "--target", str(target),
                       "--build-manifest", str(manifest_path)]
            result = run_owned(command, cwd=ROOT, directory=lane / "owned", timeout_seconds=600,
                               environment=environment, deadline=deadline)
            report["commands"].append(str(lane / "owned"))
            require(successful_exit(result), "original lane incomplete: " + lane_name)
            item, child = consume_child(capture, lane, command, 600,
                                        schema="hepta.cold-native-transport.ct36-public.v4")
            require(child["lane"] == lane_name and child["planned"] == planned
                    and child["started"] == planned and child["stopped"] == planned
                    and child["status"] == "OBSERVATIONS_COMPLETE_NOT_QUALIFIED"
                    and child["source_before"] == before == child["source_after"]
                    and child["poison_hits"] == [], "complete original domain differs")
            report["originals"].append(item)
            observed_raw = capture.raw(lane / "observation/observations.jsonl", child["files"]["observations.jsonl"])
            observed_rows = [parse(raw) for raw in observed_raw.splitlines()]
            require(observed_rows == child["rows"], "actual consumed original JSONL/report identity")
            original_rows.append(observed_rows)
        # Both full original child reports and actual command/result custody
        # precede the frozen authority. This authority contains no candidate.
        from tools.read_hia_cold_native_transport_controls import leaf_differences, public_local, public_relation
        checks, errors = [], []
        for case, first, second in zip(fixture["public_cases"], *original_rows):
            checks.append({"subcase": case["subcase"], "differences": leaf_differences(first, second)})
            try:
                public_local(first, case, False)
                public_local(second, case, False)
                public_relation(first, second, case)
            except BaseException as error:
                errors.append({"subcase": case["subcase"], "type": type(error).__name__, "message": str(error)})
        comparison_path = output / "original-comparison.json"
        write_json(comparison_path, {"original_reports": [item["report"] for item in report["originals"]],
                                    "errors": errors, "raw_differences": checks})
        comparison_raw = capture.raw(comparison_path)
        require(errors == [], "complete fresh originals disagree; candidate not started")
        capture.unchanged()
        authority = {"schema": "hepta.cold-native-transport.ct36-original-authority.v4",
                     "ordered_ids": fixture["ordered_ids"], "public_subcases": planned,
                     "lanes": report["originals"], "source": before,
                     "original_comparison": {"path": str(comparison_path), "pin": data_pin(comparison_raw)},
                     "fixture": report["fixture"], "observer_build": build_lane,
                     "sealed_monotonic_ns": time.monotonic_ns(),
                     "consumed": capture.pins(), "candidate_observations": None}
        write_json(authority_path, authority)
        authority_raw = capture.raw(authority_path)
        report["original_authority"] = {"path": str(authority_path), "pin": data_pin(authority_raw)}
        lane = output / "selected"
        lane.mkdir(mode=0o700)
        command = [*python, str(ROOT / "tests/hia_cold_native_transport_control_cases.py"),
                   "lane", "--lane", "selected", "--output", str(lane / "observation"),
                   "--observers", build_lane["report"]["path"], "--target", str(target),
                   "--build-manifest", str(manifest_path), "--original-authority", str(authority_path)]
        selected_environment = dict(environment)
        selected_environment[SELECTOR] = str(manifest_path)
        selected_environment[DEVELOPMENT] = "1"
        result = run_owned(command, cwd=ROOT, directory=lane / "owned", timeout_seconds=600,
                           environment=selected_environment, deadline=deadline)
        report["commands"].append(str(lane / "owned"))
        require(successful_exit(result), "selected full public lane incomplete")
        report["selected"], child = consume_child(capture, lane, command, 600,
                                                  schema="hepta.cold-native-transport.ct36-public.v4")
        require(child["lane"] == "selected" and child["planned"] == planned
                and child["started"] == planned and child["stopped"] == planned
                and child["source_before"] == before == child["source_after"],
                "selected public scope or source changed")
        require(parse(authority_raw)["sealed_monotonic_ns"] >
                max(item["ended_monotonic_ns"] for item in report["originals"]),
                "original authority was not sealed after both natural exits")
        # Every protocol row uses actual generated HIA; invalid entry CT34/35
        # must reject before even the policy call. No fabricated old outcome.
        for row in fixture["policy_cases"]:
            directory = output / row["subcase"]
            directory.mkdir(mode=0o700)
            observation = directory / "observation"
            observation.mkdir(mode=0o700)
            command = [str(policy_control), manifest["policy"]["path"], str(target),
                       row["variant"], str(observation)]
            result = run_owned(command, cwd=ROOT, directory=directory / "owned", timeout_seconds=60,
                               environment=environment, deadline=deadline)
            report["commands"].append(str(directory / "owned"))
            # Save the row even when the actual control fails. A failed case
            # does not erase later controls, provided its owned group is gone.
            terminal = capture.json(directory / "owned/result.json")
            cleanup = terminal.get("owned_cleanup")
            require(type(cleanup) is dict and cleanup.get("reaped") is True
                    and cleanup.get("after") == [], "protocol control lost process custody")
            raw_files = {}
            for path in sorted(observation.rglob("*")):
                if path.is_file():
                    raw_files[path.relative_to(observation).as_posix()] = data_pin(capture.raw(path))
            report["policy_controls"].append({
                **row, "directory": str(observation), "owned": str(directory / "owned"),
                "command": command, "files": raw_files,
                "successful_exit": successful_exit(result)})
        capture.unchanged()
        report["source_after"] = source_capture(capture)
        require(report["source_after"] == before, "current source changed")
        report["source_stable"] = True
        report["status"] = "ALL_CONTROLS_RECORDED_NOT_QUALIFIED"
    finally:
        report["consumed"] = capture.pins()
        write_json(output / "report.json", report)
    capture.unchanged()
    return output / "report.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    path = qualify(args.output, args.manifest)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
