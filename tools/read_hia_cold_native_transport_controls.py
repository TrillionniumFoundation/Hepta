"""Independent complete DATA readback for the 36 cold-transport controls.

Imports no product, original test, producer or candidate. Captures each raw
file before parsing, verifies every recorded complete file and both natural
original exits before candidate start, and rereads every consumed byte at the
end. All full raw differences are retained. Control assertions do not establish
full public Python/GC/TB equivalence or any of the 17-reference/38-phase cold gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cold_native_transport_controls_v4.json"
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
FIXTURE_PIN = {
  "bytes": 43825,
  "sha256": "4c805b5a08ae55228f037f597e8b75e0767c823d980c7eefb5e87d8977d7c58e"
}
SOURCE_INPUTS = [
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
NEW_INPUTS = [
  "tests/fixtures/cold_native_transport_controls_v4.json",
  "tools/hia_cold_native_transport_control_target.c",
  "tools/hia_cold_native_transport_policy_controls.c",
  "tests/hia_cold_native_transport_control_cases.py",
  "tools/qualify_hia_cold_native_transport_controls.py",
  "tools/read_hia_cold_native_transport_controls.py",
  "tests/test_hia_cold_native_transport_controls.py"
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def exact_int(value, expected=None):
    require(type(value) is int and (expected is None or value == expected), "exact integer")
    return value


def regular(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "regular evidence file")
    raw = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(raw) == after.st_size, "raw changed during complete read")
    return raw


class Captures:
    def __init__(self):
        self.bytes = {}
        self.file_sets = {}
    def raw(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        raw = regular(path)
        if expected is not None:
            require(type(expected) is dict and set(expected) == {"bytes", "sha256"}
                    and type(expected["bytes"]) is int and type(expected["sha256"]) is str
                    and pin(raw) == expected, "raw pin differs: " + str(path))
        old = self.bytes.setdefault(path, raw)
        require(old == raw, "captured bytes changed: " + str(path))
        return raw
    def json(self, path, expected=None):
        return parse(self.raw(path, expected))
    def unchanged(self):
        for path, raw in self.bytes.items():
            require(regular(path) == raw, "terminal raw changed: " + str(path))
        for directory, expected in self.file_sets.items():
            actual = {path.relative_to(directory).as_posix()
                      for path in directory.rglob("*") if path.is_file()}
            require(actual == expected, "terminal complete file set changed: " + str(directory))
    def pins(self):
        return {str(path): pin(raw) for path, raw in sorted(self.bytes.items(), key=lambda item: str(item[0]))}


def terminal(capture, directory, seconds, *, argv=None, success=True):
    directory = Path(directory)
    command = capture.json(directory / "command.json")
    result = capture.json(directory / "result.json")
    require(type(command) is dict and set(command) == {
                "argv", "cwd", "timeout_seconds", "cleanup_seconds", "new_session",
                "parent_pid", "started_monotonic_ns", "environment", "pid", "pgid",
                "owned_initial_members", "effective_timeout_seconds"}
            and type(result) is dict and set(result) == {
                "command", "pid", "exit_code", "timed_out", "interruption",
                "elapsed_seconds", "ended_monotonic_ns", "owned_cleanup", "stdout", "stderr"},
            "complete actual owned receipt fields")
    require(type(command["argv"]) is list and command["argv"]
            and all(type(value) is str for value in command["argv"]),
            "complete actual argv types")
    require(exact_int(command["parent_pid"]) > 0
            and type(command["environment"]) is dict
            and all(type(key) is str and type(value) is str
                    for key, value in command["environment"].items()),
            "actual owner/environment types")
    exact_int(command["timeout_seconds"], seconds)
    exact_int(command["cleanup_seconds"], 3)
    require(command["new_session"] is True and command["cwd"] == str(ROOT), "actual owned source/cwd")
    require(result["command"] == command, "actual command/result identity")
    pid = exact_int(command["pid"])
    require(pid > 0 and exact_int(command["pgid"]) == pid == exact_int(result["pid"]), "actual PID/PGID")
    require(type(command["effective_timeout_seconds"]) in (int, float)
            and 0 < command["effective_timeout_seconds"] <= seconds, "original cap not expanded")
    start, end = exact_int(command["started_monotonic_ns"]), exact_int(result["ended_monotonic_ns"])
    require(end >= start, "real monotonic interval")
    if argv is not None:
        require(command["argv"] == list(map(str, argv)), "actual argv differs")
    capture.raw(directory / "stdout.log", result["stdout"])
    capture.raw(directory / "stderr.log", result["stderr"])
    cleanup = result["owned_cleanup"]
    require(type(cleanup) is dict and cleanup["reaped"] is True and cleanup["after"] == [],
            "owned child/group not terminal")
    if success:
        require(exact_int(result["exit_code"]) == 0 and result["timed_out"] is False
                and result["interruption"] is None and cleanup["signals"] == [],
                "natural complete owned child required")
    return command, result


def safe_child(directory, relative):
    item = Path(relative)
    require(not item.is_absolute() and ".." not in item.parts
            and item.as_posix() == relative, "canonical child relative path")
    return Path(directory) / item


def read_files(capture, directory, files, *, report_outside_map=False):
    require(type(files) is dict, "complete raw file map")
    directory = Path(directory).resolve(strict=True)
    expected_files = set(files)
    if report_outside_map:
        require("report.json" not in files, "producer report cannot pin itself")
        expected_files.add("report.json")
    actual_files = {path.relative_to(directory).as_posix()
                    for path in directory.rglob("*") if path.is_file()}
    require(actual_files == expected_files, "complete actual raw file inventory")
    previous = capture.file_sets.setdefault(directory, expected_files)
    require(previous == expected_files, "complete raw file inventory changed")
    result = {}
    for name, expected in files.items():
        result[name] = capture.raw(safe_child(directory, name), expected)
    return result


def absolute_path(value, expected=None):
    require(type(value) is str and Path(value).is_absolute(), "absolute actual evidence path")
    path = Path(value).resolve(strict=True)
    require(str(path) == value and (expected is None or value == str(expected)),
            "actual evidence path differs")
    return path


def path_set(paths):
    return {str(Path(path).resolve(strict=True)) for path in paths}


def mapped_paths(directory, files):
    require(type(files) is dict, "complete mapped raw paths")
    return path_set(safe_child(directory, name) for name in files)


def owned_paths(directory):
    return path_set(Path(directory) / name
                    for name in ("command.json", "result.json", "stdout.log", "stderr.log"))


def consume_declared(capture, declared, expected_paths, label):
    require(type(declared) is dict and set(declared) == expected_paths,
            "complete consumed path set differs: " + label)
    for name, expected in declared.items():
        path = absolute_path(name)
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int and type(expected["sha256"]) is str,
                "complete consumed pin type: " + label)
        # These exact full bytes were already read by the independent source,
        # command or artifact check. Validate the producer's entire declaration
        # against those bytes, then retain the original final raw rereads.
        require(path in capture.bytes and pin(capture.bytes[path]) == expected,
                "consumed declaration does not bind already captured full raw: " + label)


def lane_command(python, output, lane, manifest_path):
    command = [*python, str(ROOT / "tests/hia_cold_native_transport_control_cases.py"),
               "lane", "--lane", lane, "--output", str(output / lane / "observation"),
               "--observers", str(output / "observer-build/observation/report.json"),
               "--target", str(output / "ct36-target"), "--build-manifest", str(manifest_path)]
    if lane == "selected":
        command.extend(("--original-authority", str(output / "original-authority.json")))
    return command


def public_paths(item, report):
    return (owned_paths(Path(item["directory"]).parent / "owned")
            | path_set((item["report"]["path"],))
            | mapped_paths(item["directory"], report["files"]))


def bind_commands(capture, output, report, manifest, fixture, owner_directory):
    runtime = str(Path(manifest["runtime"]["path"]).resolve(strict=True))
    python = [runtime, "-I", "-S", "-B"]
    manifest_path = absolute_path(report["manifest"]["path"])
    compiler = str(Path(manifest["build_tool"]["path"]).resolve(strict=True))
    common = [compiler, "-std=c11", "-O2", "-fno-strict-aliasing",
              "-Werror=implicit-function-declaration", "-I" + str(ROOT / "tools"),
              "-pthread", "-Wl,-z,noexecstack", "-Wl,-z,relro", "-Wl,-z,now"]
    require(type(report["binaries"]) is dict
            and set(report["binaries"]) == {"target", "policy_controls"}, "both actual control binaries")
    absolute_path(report["binaries"]["target"]["path"], output / "ct36-target")
    absolute_path(report["binaries"]["policy_controls"]["path"], output / "ct36-policy-controls")
    specifications = []
    for label, source, binary in (
            ("target", "tools/hia_cold_native_transport_control_target.c", "ct36-target"),
            ("policy-controls", "tools/hia_cold_native_transport_policy_controls.c", "ct36-policy-controls")):
        specifications.append((output / ("build-" + label), 20,
                               [*common, str(ROOT / source), "-o", str(output / binary)]))
    build_directory = output / "observer-build/observation"
    absolute_path(report["observer_build"]["directory"], build_directory)
    absolute_path(report["observer_build"]["report"]["path"], build_directory / "report.json")
    absolute_path(report["observer_build"]["command"]["path"], build_directory.parent / "owned/command.json")
    absolute_path(report["observer_build"]["terminal"]["path"], build_directory.parent / "owned/result.json")
    specifications.append((output / "observer-build/owned", 600,
                           [*python, str(ROOT / "tests/hia_cold_native_transport_control_cases.py"),
                            "build-observers", "--output", str(build_directory)]))
    require(type(report["originals"]) is list and len(report["originals"]) == 2
            and type(report["selected"]) is dict, "all three declared public lanes")
    for name, item in zip(("original-1", "original-2", "selected"),
                          [*report["originals"], report["selected"]]):
        absolute_path(item["directory"], output / name / "observation")
        specifications.append((output / name / "owned", 600,
                               lane_command(python, output, name, manifest_path)))
    require(type(report["policy_controls"]) is list
            and len(report["policy_controls"]) == len(fixture["policy_cases"]) == 32,
            "all32 actual policy controls")
    for item, expected in zip(report["policy_controls"], fixture["policy_cases"]):
        require(item["id"] == expected["id"] and item["variant"] == expected["variant"]
                and item["subcase"] == expected["subcase"], "fixed policy input order")
        directory = output / expected["subcase"]
        absolute_path(item["directory"], directory / "observation")
        absolute_path(item["owned"], directory / "owned")
        arguments = [str(output / "ct36-policy-controls"), manifest["policy"]["path"],
                     str(output / "ct36-target"), item["variant"], str(directory / "observation")]
        require(item["command"] == arguments, "actual policy command descriptor")
        specifications.append((directory / "owned", 60, arguments))
    require(len(specifications) == 38
            and report["commands"] == [str(directory) for directory, _, _ in specifications],
            "complete38 actual command directories/order")
    results, owner_pid, base_environment, previous_end = {}, None, None, None
    for ordinal, (directory, seconds, arguments) in enumerate(specifications):
        command, result = terminal(capture, directory, seconds, argv=arguments, success=ordinal < 6)
        parent = exact_int(command["parent_pid"])
        if owner_pid is None:
            owner_pid = parent
            base_environment = command["environment"]
            require(set(base_environment) <= {"PATH", "LD_LIBRARY_PATH", "CLANG", "HEPTA_CLANG"},
                    "original clean owner environment")
        require(parent == owner_pid, "all38 commands belong to the same actual owner")
        expected_environment = dict(base_environment)
        if ordinal == 5:
            expected_environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_MANIFEST"] = str(manifest_path)
            expected_environment["HEPTA_HIA_COLD_NATIVE_TRANSPORT_ALLOW_DEVELOPMENT"] = "1"
        require(command["environment"] == expected_environment,
                "actual original/selected command environment")
        if previous_end is not None:
            require(command["started_monotonic_ns"] > previous_end, "complete serial command order")
        previous_end = result["ended_monotonic_ns"]
        results[str(directory)] = (command, result)
    if owner_directory is not None:
        arguments = [*python, str(ROOT / "tools/qualify_hia_cold_native_transport_controls.py"),
                     "--manifest", str(manifest_path), "--output", str(output)]
        owner_command, owner_result = terminal(capture, owner_directory, 1800, argv=arguments)
        first = results[str(specifications[0][0])][0]
        require(exact_int(owner_result["pid"]) == owner_pid
                and owner_command["environment"] == base_environment
                and owner_command["started_monotonic_ns"] < first["started_monotonic_ns"]
                and owner_result["ended_monotonic_ns"] > previous_end,
                "actual complete owner encloses all38 declared commands")
    return python, results


def leaf_differences(left, right, path=""):
    result = []
    if type(left) is not type(right):
        return [{"path": path, "left": left, "right": right, "kind": "type"}]
    if type(left) is dict:
        for key in sorted(set(left) | set(right)):
            child = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in left:
                result.append({"path": child, "left_missing": True, "right": right[key]})
            elif key not in right:
                result.append({"path": child, "left": left[key], "right_missing": True})
            else:
                result.extend(leaf_differences(left[key], right[key], child))
    elif type(left) is list:
        for index in range(max(len(left), len(right))):
            child = path + "/" + str(index)
            if index >= len(left):
                result.append({"path": child, "left_missing": True, "right": right[index]})
            elif index >= len(right):
                result.append({"path": child, "left": left[index], "right_missing": True})
            else:
                result.extend(leaf_differences(left[index], right[index], child))
    elif left != right:
        result.append({"path": path, "left": left, "right": right})
    return result


def value_of(tagged):
    if type(tagged) is dict and tagged.get("python_type") in ("list", "tuple"):
        values = [value_of(value) for value in tagged["items"]]
        return values if tagged["python_type"] == "list" else tuple(values)
    if type(tagged) is dict and tagged.get("python_type") == "bytes":
        return bytes.fromhex(tagged["hex"])
    if type(tagged) is dict and tagged.get("python_type") == "dict":
        return {value_of(key): value_of(value) for key, value in tagged["items"]}
    return tagged


def actual_public(capture, item, expected_lane, fixture, before, *,
                  command_argv, expected_directory, consumed_before):
    directory = absolute_path(item["directory"], expected_directory)
    absolute_path(item["report"]["path"], directory / "report.json")
    absolute_path(item["command"]["path"], directory.parent / "owned/command.json")
    absolute_path(item["terminal"]["path"], directory.parent / "owned/result.json")
    command, result = terminal(capture, directory.parent / "owned", 600, argv=command_argv)
    require(pin(capture.raw(item["command"]["path"])) == item["command"]["pin"]
            and pin(capture.raw(item["terminal"]["path"])) == item["terminal"]["pin"],
            "authority actual command/result pins")
    report = capture.json(item["report"]["path"], item["report"]["pin"])
    require(report["schema"] == "hepta.cold-native-transport.ct36-public.v4"
            and report["lane"] == expected_lane
            and report["status"] == "OBSERVATIONS_COMPLETE_NOT_QUALIFIED", "full public lane report")
    planned = [case["subcase"] for case in fixture["public_cases"]]
    require(report["planned"] == planned == report["started"] == report["stopped"]
            and item["planned"] == item["started"] == item["stopped"] == planned
            and exact_int(item["ended_monotonic_ns"]) == result["ended_monotonic_ns"],
            "all public inputs/order completed")
    require(report["source_before"] == before == report["source_after"]
            and report["source_stable"] is True and report["poison_hits"] == [],
            "public source/poison")
    raw_files = read_files(capture, directory, report["files"], report_outside_map=True)
    stream = raw_files["observations.jsonl"]
    require(stream.endswith(b"\n"), "complete observation stream")
    rows = [parse(raw) for raw in stream.splitlines()]
    require(rows == report["rows"] and len(rows) == len(planned), "full observation stream/report identity")
    complete_files = {"observations.jsonl": report["files"]["observations.jsonl"]}
    for ordinal, (row, case) in enumerate(zip(rows, fixture["public_cases"])):
        require(exact_int(row["ordinal"]) == ordinal and row["id"] == case["id"]
                and row["subcase"] == case["subcase"]
                and leaf_differences(row["case"], case) == [], "actual input identity")
        relative_directory = "%03d-" % ordinal + case["subcase"]
        per_directory = directory / relative_directory
        read_files(capture, per_directory, row["files"])
        for name, expected in row["files"].items():
            complete_files[relative_directory + "/" + name] = expected
    require(report["files"] == complete_files, "every public row raw file and complete stream")
    consume_declared(capture, report["consumed"],
                     consumed_before | mapped_paths(directory, report["files"]),
                     expected_lane + " public report")
    return rows, report, command, result, raw_files


def public_local(row, case, selected):
    require("observer_error" not in row, "observer failed in " + case["subcase"])
    require(row["children_before_hex"] == "" == row["children_after_hex"], "actual target still owned")
    before_fds = [record for record in row["fds_before"] if "error" not in record]
    after_fds = [record for record in row["fds_after"] if "error" not in record]
    require(before_fds == after_fds, "actual open FD boundary changed: " + case["subcase"])
    require(type(row["execute"]) is list and len(row["execute"]) == 1, "one actual public execute")
    if "target_identity" in row:
        identity = row["target_identity"]
        require(identity["pid"] > 0 and identity["ppid"] == row["parent_pid"]
                and identity["pgid"] == row["parent_pgid"] and identity["sid"] == row["parent_sid"]
                and identity["gone"] is True, "fresh target's actual process custody")
    if selected:
        a, b = row["statistics_before"], row["statistics_after"]
        require(type(a) is dict and type(b) is dict and b["calls"] == a["calls"] + 1
                and b["entries"] > a["entries"] and b["policy_complete"] == a["policy_complete"] + 1
                and b["unknown"] == a["unknown"] and b["handed_off"] == a["handed_off"],
                "actual current selected HIA invocation/acknowledgement")
    else:
        require(row["statistics_before"] is None and row["statistics_after"] is None,
                "original lane selected a candidate")


def audit_argv(row):
    actual = [entry for entry in row["audit"] if entry["event"] == "subprocess.Popen"]
    require(len(actual) == 1, "actual subprocess audit invocation")
    values = value_of(actual[0]["arguments"])
    require(type(values) is tuple and len(values) == 4 and type(values[1]) is list,
            "actual subprocess audit tuple")
    arguments = values[1]
    require(arguments and type(arguments[0]) is str and arguments[0].startswith("/proc/self/fd/")
            and arguments[0][len("/proc/self/fd/"):].isdigit(), "actual sealed executable argv0")
    return arguments


def cwd_filename(error, row):
    actual = [entry for entry in row["audit"] if entry["event"] == "subprocess.Popen"]
    require(len(actual) == 1, "actual cwd audit invocation")
    values = value_of(actual[0]["arguments"])
    require(type(values) is tuple and len(values) == 4
            and type(row["execute"]) is list and len(row["execute"]) == 1,
            "actual cwd call and audit shape")
    arguments = value_of(row["execute"][0]["kwargs"])
    require(type(arguments) is dict and "cwd" in arguments, "actual caller cwd argument")
    cwd = arguments["cwd"]
    require(type(cwd) is dict and set(cwd) == {"python_type", "actual_identity"}
            and type(cwd["python_type"]) is str
            and type(cwd["actual_identity"]) is int and cwd["actual_identity"] > 0
            and values[2] == cwd == error["filename"],
            "actual missing-cwd filename preserves this lane's original Path object")
    return cwd


def timeout_arguments(error, row, case):
    arguments = audit_argv(row)
    actual_args = value_of(error["args"])
    require(type(actual_args) is tuple and len(actual_args) == 2
            and type(actual_args[0]) is list and actual_args[0] == arguments
            and value_of(error["cmd"]) == arguments,
            "timeout preserves exactly its actual two positional arguments and argv")
    require(case["kind"] == "execute"
            and case["id"] in {"CT-17", "CT-18", "CT-19", "CT-20", "CT-21"}
            and type(error["timeout"]) is type(case["timeout"])
            and error["timeout"] == case["timeout"], "original requested timeout field")
    frame_names = [frame["name"] for frame in error["traceback"]]
    if case["id"] == "CT-20":
        # CPython _wait raises with its actual remaining float. _communicate
        # then restores only .timeout, leaving .args[1] unchanged. Independent
        # runs have different clock values; retain every actual value in the
        # raw comparison rather than replacing it with the requested timeout.
        require(type(actual_args[1]) is float
                and -sys.float_info.max <= actual_args[1] <= sys.float_info.max
                and error["stdout"] is None and error["stderr"] is None,
                "actual WAIT timeout remaining/None-output fields")
        if row["statistics_before"] is None:
            require("_wait" in frame_names and "_check_timeout" not in frame_names,
                    "actual original WAIT timeout traceback")
    else:
        require(type(actual_args[1]) is type(error["timeout"])
                and actual_args[1] == error["timeout"], "actual IO timeout positional value")
        if row["statistics_before"] is None:
            require("_check_timeout" in frame_names, "actual original IO timeout traceback")
    return actual_args


def compare_exception(old, actual, old_row, row, case):
    require(old["type"] == actual["type"], "real exception type")
    for key in ("name", "obj", "errno", "filename2", "stdout", "stderr", "timeout",
                "notes", "suppress_context"):
        require(old[key] == actual[key], "real exception field differs: " + key)
    # Every raw identity/TB/message remains present in the unfiltered diff.
    # These finite inputs create no user outer exception/cause.
    require(old["cause"] is None and actual["cause"] is None
            and old["context"] is None and actual["context"] is None, "real cause/context differs")
    actual_argv = audit_argv(row)
    if actual["type"] == "subprocess.TimeoutExpired":
        timeout_arguments(old, old_row, case)
        timeout_arguments(actual, row, case)
    else:
        require(old["args"] == actual["args"], "actual OSError arguments differ")
        if actual["errno"] == 8:
            require(old["filename"] == audit_argv(old_row)[0]
                    and actual["filename"] == actual_argv[0],
                    "exec error filename is its actual descriptor path")
        elif case["id"] == "CT-14":
            require(case["missing_cwd"] is True and old["errno"] == actual["errno"] == 2,
                    "fixed missing-cwd failure")
            old_cwd, actual_cwd = cwd_filename(old, old_row), cwd_filename(actual, row)
            require(old_cwd["python_type"] == actual_cwd["python_type"],
                    "original missing-cwd Path type")
        else:
            require(old["filename"] == actual["filename"], "actual failure filename")


def argv_payload(raw):
    require(len(raw) >= 8, "complete argv payload")
    count = struct.unpack_from("<Q", raw)[0]
    cursor, values = 8, []
    for _ in range(count):
        require(cursor + 8 <= len(raw), "complete argv length")
        size = struct.unpack_from("<Q", raw, cursor)[0]
        cursor += 8
        require(cursor + size <= len(raw), "complete argv bytes")
        values.append(raw[cursor:cursor + size])
        cursor += size
    require(cursor == len(raw), "no unconsumed argv byte")
    return values


def public_relation(original, candidate, case):
    require(original["actual"]["outcome"]["status"] == candidate["actual"]["outcome"]["status"],
            "public outcome differs: " + case["subcase"])
    old, actual = original["actual"]["outcome"], candidate["actual"]["outcome"]
    control = case["id"]
    if actual["status"] == "raised":
        compare_exception(old["exception"], actual["exception"], original, candidate, case)
        if control == "CT-26":
            require(len(candidate["actual"]["drift_hits"]) == 1
                    and actual["exception"]["type"] == "builtins.AssertionError"
                    and actual["exception"]["message"] == old["exception"]["message"],
                    "real original terminal reread refused private drift")
        return
    old_value, actual_value = old["value"], actual["value"]
    if case["kind"] == "execute":
        require(old_value["returncode"] == actual_value["returncode"]
                and old_value["completed_process_type"] == actual_value["completed_process_type"],
                "real target completion differs")
        out = bytes.fromhex(actual_value["stdout_hex"])
        err = bytes.fromhex(actual_value["stderr_hex"])
        old_out = bytes.fromhex(old_value["stdout_hex"])
        old_err = bytes.fromhex(old_value["stderr_hex"])
        require(value_of(actual_value["args"]) == audit_argv(candidate), "CompletedProcess actual argv")
        if control == "CT-05":
            values = argv_payload(out)
            require(values == [os.fsencode(item) for item in audit_argv(candidate)], "every actual argv byte")
            require(values[1:] == argv_payload(old_out)[1:], "exact requested argument bytes")
            require(err == old_err, "argv stderr")
        elif control == "CT-25":
            require(len(out) == 32 and struct.unpack("<4Q", out) ==
                    tuple(candidate["target_identity"][key] for key in ("pid", "ppid", "pgid", "sid")),
                    "actual no-extra-process output")
            require(err == old_err, "identity stderr")
        elif control in ("CT-22", "CT-23"):
            before, after = candidate["actual"]["borrowed_before"], candidate["actual"]["borrowed_after"]
            require(len(before) == len(after) == case["borrowed"], "complete actual borrowed descriptor set")
            require(len(out) == 32 * len(before), "full actual borrowed descriptor payload")
            for index, (a, b) in enumerate(zip(before, after)):
                require("error" not in b and {key: a[key] for key in ("fd", "dev", "ino", "size", "offset")}
                        == {key: b[key] for key in ("fd", "dev", "ino", "size", "offset")},
                        "caller descriptor was retired/renumbered")
                require(struct.unpack_from("<4Q", out, 32 * index) == tuple(a[key] for key in ("fd", "dev", "ino", "size")),
                        "target used actual caller descriptor")
                raw = bytes.fromhex(b["raw"])
                require(raw == b"borrowed\0\xff\x80" + b"Z" * (4096 - 11), "full real borrowed contents")
            require(err == old_err, "borrowed stderr")
        else:
            require(out == old_out and err == old_err, "every binary stdout/stderr byte: " + case["subcase"])
        return
    old_result, actual_result = old_value["result"], actual_value["result"]
    require(old_value["output_hex"] == actual_value["output_hex"], "complete actual returned output")
    # Check every original result field except actual clocks and per-run paths,
    # which remain untouched in the raw full difference stream below.
    for key in set(old_result) | set(actual_result):
        require(key in old_result and key in actual_result, "result field set changed")
        if key not in {"native_elapsed_ns", "wall_elapsed_ns", "response_sha256"}:
            require(old_result[key] == actual_result[key], "original invoke result field: " + key)
        elif key != "response_sha256":
            require(type(actual_result[key]) is int and actual_result[key] >= 0, "actual native/wall clock")
    old_exec, new_exec = original["execute"][0], candidate["execute"][0]
    require("returned" in old_exec and "returned" in new_exec, "real observer execute returned")
    old_raw = bytes.fromhex(old_exec["returned"]["stdout_hex"])
    raw = bytes.fromhex(new_exec["returned"]["stdout_hex"])
    require(new_exec["returned"]["stderr_hex"] == old_exec["returned"]["stderr_hex"],
            "full observer stderr")
    if "response_sha256" in actual_result:
        require(actual_result["response_sha256"] == hashlib.sha256(raw).hexdigest()
                and old_result["response_sha256"] == hashlib.sha256(old_raw).hexdigest(),
                "each original raw response digest binds its own actual complete bytes")
    if control == "CT-24":
        require(actual_result["status"] == "protocol_failed" and len(raw) == len(old_raw),
                "original unchanged noise parser refused complete response")
        where = int(case["variant"].split("-")[-1])
        offset = 1 if where in (1, 2) else 0
        require((raw[:1] == b"!") == (where in (1, 2))
                and (raw[-1:] == b"!") == (where == 3), "actual constructor/callback/finalizer noise")
        require(raw[:offset + 16] == old_raw[:offset + 16]
                and raw[offset + 24:] == old_raw[offset + 24:], "every nontiming response byte")
    else:
        require(len(raw) == len(old_raw) and raw[:16] == old_raw[:16]
                and raw[24:] == old_raw[24:], "complete source/output/workspace response")
        require(len(raw) == 24 + len(bytes.fromhex(case["source_hex"]))
                + case["capacity"] + case["workspace_size"], "exact observer full response length")


def read_policy(capture, item, fixture_row, owner, target, policy):
    require(item["id"] == fixture_row["id"] and item["variant"] == fixture_row["variant"]
            and item["subcase"] == fixture_row["subcase"], "policy control ID/order")
    command = [owner["binaries"]["policy_controls"]["path"], owner["build_policy_path"],
               owner["binaries"]["target"]["path"], item["variant"], item["directory"]]
    require(item["command"] == command, "complete actual policy command")
    owned_command, owned_result = terminal(capture, item["owned"], 60, argv=command, success=False)
    raw = read_files(capture, item["directory"], item["files"])
    require(raw["consumed-policy.bin"] == policy and raw["consumed-target.bin"] == target,
            "actual C load buffers differ from current complete policy/target bytes")
    require("report.json" in raw, "actual C control report")
    report = parse(raw["report.json"])
    require(report["schema"] == "hepta.cold-native-transport.ct36-policy.v4"
            and report["variant"] == item["variant"] and report["whole_native"] is False
            and report["qualification_complete"] is False, "C actual control schema")
    runs = report["runs"]
    require(len(runs) == (2 if item["variant"] == "fresh" else 1), "full declared fresh run count")
    nonces, pids = [], []
    for index, row in enumerate(runs):
        exact_int(row["run"], index)
        integer_keys = ("rc", "nonce", "calls", "fault_hits", "rejected_sequence", "outcome",
                        "primary_errno", "primary_stage", "cleanup_errno", "cleanup_stage", "pid",
                        "returncode", "wait_status", "spawned", "exec_confirmed", "reaped",
                        "owner_lost", "policy_complete", "trace_overflow", "entries", "trace_count",
                        "trace_item_bytes", "policy_item_bytes", "final_fd_mask", "stdout_size",
                        "stderr_size", "stdout_reads", "stderr_reads", "start_ns", "end_ns",
                        "memfd", "seals", "extent", "competing_wait_pid", "competing_wait_status")
        for key in integer_keys:
            exact_int(row[key])
        require(row["passed"] is True and row["final_fd_mask"] == 0
                and row["dispositions_unchanged"] is True, "C control's actual scope incomplete")
        if row["memfd"]:
            require(row["actual_memfd_closed"] is True, "actual memfd still open")
        folder = "run-" + str(index) + "/"
        out, err = raw[folder + "stdout.bin"], raw[folder + "stderr.bin"]
        events = raw[folder + "events.bin"]
        calls = raw[folder + "policy-calls.bin"]
        require(len(out) == row["stdout_size"] and len(err) == row["stderr_size"], "complete raw capture lengths")
        require(row["trace_item_bytes"] == 80 and row["policy_item_bytes"] == 920
                and len(events) == row["trace_count"] * 80 and len(calls) == row["calls"] * 920,
                "complete real event/policy streams")
        records = [calls[at:at + 920] for at in range(0, len(calls), 920)]
        for ordinal, record in enumerate(records):
            call, run, returned = struct.unpack_from("<3Q", record)
            require(call == ordinal + 1 and run == index, "actual policy call order")
            require(struct.unpack_from("<Q", record, 24)[0] == 3688501220647785288
                    and struct.unpack_from("<Q", record, 32)[0] == row["nonce"], "actual request identity")
            require(struct.unpack_from("<Q", record, 280)[0] == 3688501229237719880,
                    "actual HIA produced reply magic before defensive seam")
            if ordinal == 0:
                require(record[408:664] == bytes(256) and row["first_workspace_zero"] is True,
                        "fresh full HIA workspace")
            require(returned in (63, 64), "only declared complete/short return")
        for ordinal in range(row["trace_count"]):
            event = struct.unpack_from("<9Q2I", events, ordinal * 80)
            require(event[0] == ordinal + 1 and 1 <= event[1] <= 25, "actual issued action trace")
        v = item["variant"]
        entry = v.startswith("closed-") or v.startswith("sig")
        healthy = v in ("seals", "fresh", "overflow")
        if entry:
            require(row["calls"] == row["entries"] == row["spawned"] == 0
                    and row["rc"] == -1 and row["outcome"] == 2 and row["primary_errno"] == 22
                    and row["actual_effects"]["fork"] == 0, "entry refusal before policy/target")
        elif v == "owner-lost":
            require(row["fault_hits"] == 1 and row["rc"] == -1 and row["outcome"] == 6
                    and row["owner_lost"] == 1 and row["reaped"] == 0
                    and row["actual_effects"]["kill"] == 0 and row["actual_child_gone"] is True
                    and row["competing_wait_pid"] == row["pid"] > 0, "actual ECHILD custody loss")
        elif healthy:
            require(row["rc"] == 0 and row["outcome"] == 0 and row["policy_complete"] == 1
                    and row["returncode"] == 0 and row["reaped"] == 1 and row["owner_lost"] == 0
                    and row["actual_effects"]["fork"] == 1 and row["actual_child_gone"] is True,
                    "actual healthy full native lifecycle")
            if v == "overflow":
                require(row["trace_overflow"] == 1 and row["trace_count"] == 1 and len(out) == 98347,
                        "actual trace overflow retained every output byte")
            else:
                require(row["trace_overflow"] == 0 and row["trace_count"] == row["entries"],
                        "complete ordinary native trace")
            if v == "seals":
                require(raw[folder + "sealed-image.bin"] == target and row["seals"] == 15
                        and row["extent"] == len(target) and len(out) == 24 + len(target),
                        "actual complete executable extent/bytes/seals")
                fd, extent, seals = struct.unpack_from("<3Q", out)
                require((fd, extent, seals) == (row["memfd"], len(target), 15)
                        and out[24:] == target, "actual target descriptor observations")
            nonces.append(row["nonce"])
            pids.append(row["pid"])
        else:
            require(row["fault_hits"] == 1 and row["rc"] == -1 and row["outcome"] == 5
                    and row["policy_complete"] == 0 and row["trace_overflow"] == 0
                    and row["entries"] + 1 == row["rejected_sequence"] == row["calls"],
                    "actual malformed issue refused before its dispatch")
            require(not row["spawned"] or (row["reaped"] == 1 and row["actual_child_gone"] is True),
                    "real emergency target cleanup")
        if entry:
            require(row["start_ns"] == row["end_ns"] == 0,
                    "entry refusal occurs before the native lifecycle clock")
        else:
            require(row["end_ns"] > 0, "actual terminal clock")
    if item["variant"] == "fresh":
        require(len(set(nonces)) == len(set(pids)) == 2, "fresh nonce and target process")
    require(owned_result["exit_code"] == 0 and type(owned_result["exit_code"]) is int
            and owned_result["timed_out"] is False and owned_result["interruption"] is None
            and owned_result["owned_cleanup"]["signals"] == [], "natural complete policy control exit")
    require(report["status"] == "CONTROLS_OBSERVED", "C report incomplete")
    return report


def read(output, destination, owner_directory=None):
    output = Path(output).resolve(strict=True)
    capture = Captures()
    report = capture.json(output / "report.json")
    require(report.get("schema") == "hepta.cold-native-transport.ct36-owner.v4"
            and report["status"] == "ALL_CONTROLS_RECORDED_NOT_QUALIFIED"
            and report["whole_native"] is False and report["qualification_complete"] is False,
            "complete CT36 observation owner required")
    fixture = capture.json(FIXTURE, FIXTURE_PIN)
    require(report["fixture"] == {"path": str(FIXTURE), "pin": FIXTURE_PIN},
            "fixed input authority differs")
    old_controls = capture.json(ROOT / "tests/fixtures/cold_native_transport_controls_v3.json")
    require(fixture["original_CT36"] == old_controls["original_CT36"]
            and fixture["ordered_ids"] == ["CT-%02d" % i for i in range(1, 37)]
            and report["ordered_ids"] == fixture["ordered_ids"], "all original36 definitions and order")
    require(report["budgets"] == fixture["budgets"]
            and fixture["budgets"]["cold_inner_seconds"] == 180
            and fixture["budgets"]["cold_outer_seconds"] == 240
            and fixture["budgets"]["owned_cleanup_seconds"] == 3, "original cold budgets")
    contract_path = ROOT / "docs/HIA_SELFHOST_CORE_SUPPORT.json"
    contract = capture.json(contract_path)
    expected_sources = set(contract["source_identity"]["files"]) | {
        "docs/HIA_SELFHOST_CORE_SUPPORT.json"} | set(SOURCE_INPUTS) | set(NEW_INPUTS)
    require(set(report["source_before"]) == expected_sources
            and report["source_before"] == report["source_after"] and report["source_stable"] is True,
            "complete current source contract and explicit inputs")
    for name, expected in report["source_before"].items():
        raw = capture.raw(ROOT / name, expected)
        if name in contract["source_identity"]["files"]:
            require(hashlib.sha256(raw).hexdigest() == contract["source_identity"]["files"][name],
                    "official current source identity")
    for name, expected in CORE_PINS.items():
        capture.raw(ROOT / name, expected)
    source_paths = path_set(ROOT / name for name in expected_sources)
    absolute_path(report["manifest"]["path"])
    manifest = capture.json(report["manifest"]["path"], report["manifest"]["pin"])
    require(manifest["source_root"] == str(ROOT)
            and manifest["schema"] == "hepta.cold-native-transport.hosted-build.r3"
            and manifest["status"] == "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            and manifest["whole_native"] is False
            and set(manifest["inputs"]) == set(SOURCE_INPUTS), "actual current build manifest")
    for name, expected in manifest["inputs"].items():
        capture.raw(ROOT / name, expected)
    artifact_names = ("policy", "extension", "probe", "handoff_controls", "compiler", "build_tool", "python_library")
    artifact_bytes = {}
    for name in artifact_names:
        artifact_bytes[name] = capture.raw(manifest[name]["path"], manifest[name]["pin"])
    for name, expected in manifest["python_headers"].items():
        capture.raw(name, expected)
    runtime = manifest["runtime"]
    capture.raw(runtime["path"], runtime["pin"])
    capture.raw(runtime["subprocess_path"], runtime["subprocess_pin"])
    require(Path(runtime["path"]).resolve(strict=True) == Path(sys.executable).resolve(strict=True)
            and runtime["version"] == sys.version, "current reader/runtime identity")
    target = capture.raw(report["binaries"]["target"]["path"], report["binaries"]["target"]["pin"])
    capture.raw(report["binaries"]["policy_controls"]["path"], report["binaries"]["policy_controls"]["pin"])
    python, command_records = bind_commands(capture, output, report, manifest, fixture, owner_directory)
    build = report["observer_build"]
    build_command, build_terminal = command_records[str(output / "observer-build/owned")]
    require(pin(capture.raw(build["command"]["path"])) == build["command"]["pin"]
            and pin(capture.raw(build["terminal"]["path"])) == build["terminal"]["pin"]
            and exact_int(build["ended_monotonic_ns"]) == build_terminal["ended_monotonic_ns"]
            and build["planned"] is None and build["started"] is None and build["stopped"] is None,
            "actual observer-build command/result descriptor")
    build_report = capture.json(build["report"]["path"], build["report"]["pin"])
    require(build_report["schema"] == "hepta.cold-native-transport.ct36-observers.v4"
            and build_report["status"] == "BUILT_NOT_QUALIFIED"
            and build_report["source_stable"] is True
            and build_report["whole_native"] is False
            and build_report["qualification_complete"] is False, "actual observer-build report")
    build_raw_files = read_files(capture, build["directory"], build_report["files"], report_outside_map=True)
    require(parse(build_raw_files["flat-reference.json"]) == build_report["flat_reference"]
            and parse(build_raw_files["linked-reference.json"]) == build_report["linked_reference"],
            "both complete actual independent-reference records")
    require(build_report["flat_reference"]["before_B0"] is True
            and build_report["flat_reference"]["every_output_byte_compared"] is True
            and build_report["linked_reference"]["before_B0"] is True
            and build_report["linked_reference"]["every_output_byte_compared"] is True
            and build_report["source_before"] == report["source_before"] == build_report["source_after"],
            "actual complete independent reference/build closure")
    build_artifacts = [build_report["artifacts"]["flat"], build_report["artifacts"]["linked"],
                       *build_report["artifacts"]["images"].values()]
    for item in build_artifacts:
        capture.raw(item["path"], item["pin"])
    build_file_paths = mapped_paths(build["directory"], build_report["files"])
    require(path_set(item["path"] for item in build_artifacts) <= build_file_paths,
            "all observer images are actual complete build outputs")
    consume_declared(capture, build_report["consumed"],
                     source_paths | build_file_paths, "observer build")
    transport_paths = source_paths | path_set((
        report["manifest"]["path"], *(manifest[name]["path"] for name in artifact_names),
        runtime["path"], runtime["subprocess_path"], *manifest["python_headers"]))
    before_originals = (transport_paths | path_set(item["path"] for item in report["binaries"].values())
                        | owned_paths(output / "build-target")
                        | owned_paths(output / "build-policy-controls")
                        | public_paths(build, build_report))
    public_consumed_before = source_paths | path_set((
        build["report"]["path"], report["manifest"]["path"], report["binaries"]["target"]["path"],
        *(item["path"] for item in build_artifacts)))
    require(len(report["originals"]) == 2, "two complete fresh originals")
    originals = [actual_public(capture, item, "original-" + str(index + 1), fixture,
                               report["source_before"],
                               command_argv=lane_command(python, output, "original-" + str(index + 1),
                                                         report["manifest"]["path"]),
                               expected_directory=output / ("original-" + str(index + 1)) / "observation",
                               consumed_before=public_consumed_before)
                 for index, item in enumerate(report["originals"])]
    absolute_path(report["original_authority"]["path"], output / "original-authority.json")
    authority = capture.json(report["original_authority"]["path"], report["original_authority"]["pin"])
    require(authority["schema"] == "hepta.cold-native-transport.ct36-original-authority.v4"
            and authority["candidate_observations"] is None and authority["lanes"] == report["originals"]
            and authority["source"] == report["source_before"]
            and authority["ordered_ids"] == fixture["ordered_ids"]
            and authority["public_subcases"] == [case["subcase"] for case in fixture["public_cases"]]
            and authority["fixture"] == report["fixture"]
            and authority["observer_build"] == build, "frozen original authority")
    absolute_path(authority["original_comparison"]["path"], output / "original-comparison.json")
    comparison = capture.json(authority["original_comparison"]["path"], authority["original_comparison"]["pin"])
    require(comparison["original_reports"] == [item["report"] for item in report["originals"]]
            and comparison["errors"] == [], "complete first-original comparison authority")
    original_ends = [value[3]["ended_monotonic_ns"] for value in originals]
    require(exact_int(authority["sealed_monotonic_ns"]) > max(original_ends), "originals exit before authority")
    authority_consumed = before_originals | path_set((authority["original_comparison"]["path"],))
    selected_original_inputs = set()
    for item, observed in zip(report["originals"], originals):
        authority_consumed |= public_paths(item, observed[1])
        selected_original_inputs |= (path_set((item["report"]["path"],))
                                     | mapped_paths(item["directory"], observed[1]["files"]))
    consume_declared(capture, authority["consumed"], authority_consumed, "frozen original authority")
    selected = actual_public(
        capture, report["selected"], "selected", fixture, report["source_before"],
        command_argv=lane_command(python, output, "selected", report["manifest"]["path"]),
        expected_directory=output / "selected/observation",
        consumed_before=(public_consumed_before | selected_original_inputs
                         | path_set((report["original_authority"]["path"],))))
    require(comparison["raw_differences"] == [{"subcase": case["subcase"], "differences": leaf_differences(a, b)}
            for case, a, b in zip(fixture["public_cases"], originals[0][0], originals[1][0])],
            "every actual original-to-original raw difference preserved")
    require(selected[2]["started_monotonic_ns"] > authority["sealed_monotonic_ns"]
            and originals[1][2]["started_monotonic_ns"] > originals[0][3]["ended_monotonic_ns"],
            "strict original1, original2, freeze, selected order")
    comparisons, outcomes = [], []
    for index, case in enumerate(fixture["public_cases"]):
        a, b, actual = originals[0][0][index], originals[1][0][index], selected[0][index]
        errors = []
        for label, row, is_selected in (("original-1", a, False), ("original-2", b, False), ("selected", actual, True)):
            try:
                public_local(row, case, is_selected)
            except BaseException as error:
                errors.append({"pair": label, "type": type(error).__name__, "message": str(error)})
        for label, left, right in (("original1-original2", a, b), ("original1-selected", a, actual)):
            differences = leaf_differences(left, right)
            comparisons.append({"subcase": case["subcase"], "pair": label, "differences": differences})
            try:
                public_relation(left, right, case)
            except BaseException as error:
                errors.append({"pair": label, "type": type(error).__name__, "message": str(error)})
        outcomes.append({"id": case["id"], "subcase": case["subcase"], "errors": errors})
    require(len(report["policy_controls"]) == len(fixture["policy_cases"]), "complete defensive control count")
    report_with_policy = dict(report)
    report_with_policy["build_policy_path"] = manifest["policy"]["path"]
    policy_reports = []
    owner_consumed = (authority_consumed | path_set((report["original_authority"]["path"],))
                      | public_paths(report["selected"], selected[1]))
    for item, expected in zip(report["policy_controls"], fixture["policy_cases"]):
        try:
            value = read_policy(capture, item, expected, report_with_policy, target, artifact_bytes["policy"])
            policy_reports.append({"id": expected["id"], "subcase": expected["subcase"], "report": value, "errors": []})
        except BaseException as error:
            policy_reports.append({"id": expected["id"], "subcase": expected["subcase"],
                                   "errors": [{"type": type(error).__name__, "message": str(error)}]})
        command, result = command_records[item["owned"]]
        successful = (type(result["exit_code"]) is int and result["exit_code"] == 0
                      and result["timed_out"] is False and result["interruption"] is None
                      and result["owned_cleanup"]["reaped"] is True
                      and result["owned_cleanup"]["after"] == []
                      and result["owned_cleanup"]["signals"] == [])
        require(type(item["successful_exit"]) is bool and item["successful_exit"] is successful,
                "actual policy success descriptor")
        require(command["started_monotonic_ns"] > selected[3]["ended_monotonic_ns"],
                "protocol controls started before selected full public lane finished")
        owner_consumed |= (path_set((Path(item["owned"]) / "result.json",))
                           | mapped_paths(item["directory"], item["files"]))
    all_ids = [row["id"] for row in outcomes] + [row["id"] for row in fixture["policy_cases"]]
    require(set(all_ids) == set(fixture["ordered_ids"]), "all36 actual controls present")
    consume_declared(capture, report["consumed"], owner_consumed, "complete CT36 owner")
    capture.unchanged()
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    differences_path = destination / "complete-raw-differences.json"
    differences_raw = (json.dumps(comparisons, ensure_ascii=True, sort_keys=True,
                                  separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    differences_path.write_bytes(differences_raw)
    capture.unchanged()
    success = not any(row["errors"] for row in outcomes + policy_reports)
    result = {"schema": "hepta.cold-native-transport.ct36-independent-readback.v4",
              "status": "CT36_CONTROL_ASSERTIONS_PASS" if success else "HOLD",
              "evidence_integrity": "PASS", "ordered_ids": fixture["ordered_ids"],
              "public_outcomes": outcomes, "public_subcase_count": len(outcomes),
              "policy_subcase_count": len(policy_reports), "policy_outcomes": policy_reports,
              "complete_raw_differences": {"path": str(differences_path), "pin": pin(differences_raw)},
              "actual_command_count": len(command_records),
              "actual_command_order": report["commands"],
              "owner_terminal_bound": owner_directory is not None,
              "raw_public_equivalence_proved": False, "whole_native": False,
              "qualification_complete": False,
              "required_independent_gates": ["original44", "HOF8", "REF18", "FD18",
                                             "original17references38phases", "cold180+3/outer240"],
              "consumed": capture.pins(), "source_stable": True}
    (destination / "READBACK.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    capture.unchanged()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--owner", type=Path)
    args = parser.parse_args()
    result = read(args.evidence, args.output, args.owner)
    print(json.dumps({"status": result["status"], "qualification_complete": False}, sort_keys=True))
    return 0 if result["status"] == "CT36_CONTROL_ASSERTIONS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
