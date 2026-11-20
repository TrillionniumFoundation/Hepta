"""Original-first public CT36 observations; no result normalization or GC intervention.

The observer calls the current default original or the actual selected public
execute. It does not use the original method as a selected fallback. Native
target bytes and complete original observer artifacts are immutable inputs.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_cold_native_transport_evidence import (
    Captures, data_pin, regular_bytes, parse, write_json, canonical)
from tools.hia_cold_native_transport_bridge import SELECTOR, DEVELOPMENT, SOURCE_INPUTS

FIXTURE = ROOT / "tests/fixtures/cold_native_transport_controls_v4.json"
NEW_INPUTS = (
    "tests/fixtures/cold_native_transport_controls_v4.json",
    "tools/hia_cold_native_transport_control_target.c",
    "tools/hia_cold_native_transport_policy_controls.c",
    "tests/hia_cold_native_transport_control_cases.py",
    "tools/qualify_hia_cold_native_transport_controls.py",
    "tools/read_hia_cold_native_transport_controls.py",
    "tests/test_hia_cold_native_transport_controls.py",
)


def source_capture(capture):
    from tools.hia_selfhost_contract import SOURCE_FILES, CONTRACT_PATH
    names = set(SOURCE_FILES) | {CONTRACT_PATH} | set(SOURCE_INPUTS) | set(NEW_INPUTS)
    names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / "hepta").rglob("*.py"))
    names.update(("tests/test_hia_selfhost_native_observer.py",
                  "tests/test_hia_selfhost_linked_observer.py",
                  "tests/test_hia_linked_observer_build_custody.py"))
    return {name: data_pin(capture.raw(ROOT / name)) for name in sorted(names)}


def tagged(value):
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return {"python_type": "bytes", "hex": value.hex()}
    if type(value) in (tuple, list):
        return {"python_type": type(value).__name__, "items": [tagged(item) for item in value]}
    if type(value) is dict:
        return {"python_type": "dict", "items": [[tagged(k), tagged(v)] for k, v in value.items()]}
    return {"python_type": type(value).__module__ + "." + type(value).__qualname__,
            "actual_identity": id(value)}


def exception_value(error, seen=None):
    seen = set() if seen is None else seen
    identity = id(error)
    if identity in seen:
        return {"cycle_identity": identity}
    seen.add(identity)
    frames, tb = [], error.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        frames.append({"filename": code.co_filename, "name": code.co_name,
                       "qualname": code.co_qualname, "line": tb.tb_lineno,
                       "lasti": tb.tb_lasti})
        tb = tb.tb_next
    cause, context = error.__cause__, error.__context__
    return {"identity": identity, "type": type(error).__module__ + "." + type(error).__qualname__,
            "args": tagged(error.args), "message": str(error),
            "name": tagged(getattr(error, "name", None)), "obj": tagged(getattr(error, "obj", None)),
            "errno": tagged(getattr(error, "errno", None)),
            "filename": tagged(getattr(error, "filename", None)),
            "filename2": tagged(getattr(error, "filename2", None)),
            "stdout": tagged(getattr(error, "stdout", None)),
            "stderr": tagged(getattr(error, "stderr", None)),
            "timeout": tagged(getattr(error, "timeout", None)),
            "cmd": tagged(getattr(error, "cmd", None)),
            "notes": tagged(getattr(error, "__notes__", None)),
            "suppress_context": error.__suppress_context__,
            "cause": None if cause is None else exception_value(cause, seen),
            "context": None if context is None else exception_value(context, seen),
            "traceback": frames}


def fd_snapshot():
    result = []
    for name in sorted(os.listdir("/proc/self/fd"), key=int):
        fd = int(name)
        try:
            info = os.fstat(fd)
            result.append({"fd": fd, "target": os.readlink("/proc/self/fd/" + name),
                           "dev": info.st_dev, "ino": info.st_ino, "mode": info.st_mode,
                           "flags": fcntl.fcntl(fd, fcntl.F_GETFD)})
        except OSError as error:
            result.append({"fd": fd, "error": exception_value(error)})
    return result


def children():
    return Path("/proc/self/task/" + str(os.getpid()) + "/children").read_bytes()


def files(capture, directory):
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = data_pin(capture.raw(path))
    return result


def build_observers(output):
    if SELECTOR in os.environ or DEVELOPMENT in os.environ:
        raise ValueError("independent references and original observer construction must be unselected")
    from tools import hia_selfhost_native_observer as flat
    from tools import hia_selfhost_linked_observer as linked
    from tools import qualify_hia_selfhost as original
    from tests.test_hia_selfhost_linked_observer import assemble, lifetime_source, foreign_bytes
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    captured = Captures()
    before = source_capture(captured)
    # Both actual independent references precede this new seed/B0.
    flat_reference = flat.independent_reference()
    linked_reference = linked.independent_reference(before_B0=True)
    write_json(output / "flat-reference.json", flat_reference)
    write_json(output / "linked-reference.json", linked_reference)
    seed, seed_receipt = original.build_seed(output)
    compiler, compiler_receipt = original.compile_stage(
        output, "ct36-B1", seed, original.SOURCE.read_bytes(), image_format="seed-shared")
    flat_path, flat_receipt = flat.build(output, compiler, flat_reference)
    linked_path, linked_receipt = linked.build(output, compiler, linked_reference)
    fixture = captured.json(FIXTURE)
    flat_word = output / "flat-word.bin"
    flat_word.write_bytes(bytes.fromhex(fixture["input_bytes"]["flat_word_hex"]))
    linked_word = foreign_bytes(output, "linked-word", flat_word.read_bytes())
    lifetime = assemble(output, "linked-lifetime", lifetime_source(), shared=True)
    images = {"flat-word": flat_word, "linked-word": linked_word, "linked-lifetime": lifetime}
    for where in (1, 2, 3):
        images["linked-noise-" + str(where)] = assemble(
            output, "linked-noise-" + str(where), lifetime_source(noise=where), shared=True)
    captured.unchanged()
    artifacts = {
        "flat": {"path": str(flat_path), "pin": data_pin(captured.raw(flat_path))},
        "linked": {"path": str(linked_path), "pin": data_pin(captured.raw(linked_path))},
        "images": {name: {"path": str(path), "pin": data_pin(captured.raw(path))}
                   for name, path in images.items()},
    }
    all_files = files(captured, output)
    captured.unchanged()
    write_json(output / "report.json", {
        "schema": "hepta.cold-native-transport.ct36-observers.v4",
        "status": "BUILT_NOT_QUALIFIED", "source_before": before,
        "source_after": source_capture(captured), "artifacts": artifacts,
        "flat_reference": flat_reference, "linked_reference": linked_reference,
        "seed_receipt": seed_receipt, "compiler_receipt": compiler_receipt,
        "flat_receipt": flat_receipt, "linked_receipt": linked_receipt,
        "files": all_files, "consumed": captured.pins(),
        "source_stable": True, "whole_native": False, "qualification_complete": False,
    })
    captured.unchanged()


def observed_call(function, *args, **kwargs):
    try:
        value = function(*args, **kwargs)
    except BaseException as error:
        return {"status": "raised", "exception": exception_value(error)}
    return {"status": "returned", "value": value}


def execute_case(case, module, target, directory, missing_cwd):
    raw = b"" if case.get("executable") == "empty" else (
        b"not-ELF\0\xff" if case.get("executable") == "invalid" else target)
    request = bytes(range(256)) * 1024 + b"\0\xffend" if case["request"] == "many" else b""
    arguments = tuple(case.get("arguments", ("--ct36", case.get("target_mode", "identity"))))
    borrowed, before, after = [], [], []
    try:
        for index in range(case.get("borrowed", 0)):
            fd = os.memfd_create("ct36-borrowed-" + str(index), os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            borrowed.append(fd)
            os.write(fd, b"Z" * 4096)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
            info = os.fstat(fd)
            before.append({"fd": fd, "dev": info.st_dev, "ino": info.st_ino,
                           "size": info.st_size, "offset": os.lseek(fd, 0, os.SEEK_CUR),
                           "raw": os.pread(fd, 4097, 0).hex()})
        if borrowed:
            arguments = ("--ct36", "borrowed", *map(str, borrowed))
        kwargs = {"cwd": missing_cwd if case.get("missing_cwd") else directory,
                  "timeout": case["timeout"], "arguments": arguments,
                  "output_fd": borrowed[0] if borrowed else None}
        if case["route"] == "linked":
            kwargs["snapshot_fd"] = borrowed[1] if len(borrowed) == 2 else None
        def actual():
            value = module.execute(raw, request, **kwargs)
            return {"returncode": value.returncode, "args": tagged(value.args),
                    "stdout_hex": value.stdout.hex(), "stderr_hex": value.stderr.hex(),
                    "completed_process_type": type(value).__module__ + "." + type(value).__qualname__}
        outcome = observed_call(actual)
        for fd in borrowed:
            try:
                info = os.fstat(fd)
                after.append({"fd": fd, "dev": info.st_dev, "ino": info.st_ino,
                              "size": info.st_size, "offset": os.lseek(fd, 0, os.SEEK_CUR),
                              "raw": os.pread(fd, 4097, 0).hex()})
            except BaseException as error:
                after.append({"fd": fd, "error": exception_value(error)})
        return {"outcome": outcome, "borrowed_before": before, "borrowed_after": after,
                "request_hex": request.hex(), "arguments": tagged(arguments),
                "executable": data_pin(raw)}
    finally:
        # Only these outer-created descriptors are owned by this observer.
        # A transport close is a failure, never silently repaired/reopened.
        for fd in reversed(borrowed):
            os.close(fd)


def invoke_case(case, module, build, directory, execute_records):
    image_raw = regular_bytes(build["images"][case["image"]]["path"])
    observer_raw = regular_bytes(build[case["route"]]["path"])
    image, observer = directory / "image.bin", directory / "observer.elf"
    image.write_bytes(image_raw)
    observer.write_bytes(observer_raw)
    source = bytes.fromhex(case["source_hex"])
    initial = None
    if case.get("output_fill_hex") is not None:
        initial = bytes.fromhex(case["output_fill_hex"]) * case["capacity"]
    elif case.get("output_initial_hex") is not None:
        initial = bytes.fromhex(case["output_initial_hex"])
    original_read = Path.read_bytes
    drift_reads, drift_hits = [], []
    drift_path = {"image": image, "observer": observer, "source": directory / "call.input.bin"}.get(case.get("drift"))
    trigger = 1 if case.get("drift") == "source" else 2
    count = 0
    def read(self):
        nonlocal count
        if drift_path is not None and self == drift_path:
            count += 1
            if count == trigger:
                before = original_read(self)
                self.write_bytes(before + b"x")
                drift_hits.append({"path": str(self), "read": count,
                                   "before": data_pin(before), "after": data_pin(before + b"x")})
            value = original_read(self)
            drift_reads.append({"path": str(self), "read": count, "actual": data_pin(value)})
            return value
        return original_read(self)
    if drift_path is not None:
        Path.read_bytes = read
    try:
        def actual():
            result, output = module.invoke(
                directory, "call", observer, image, source,
                capacity=case["capacity"], workspace_size=case["workspace_size"],
                workspace_fill=case["workspace_fill"], output_initial=initial,
                observe_trap_writes=case["observe_trap_writes"])
            return {"result": result, "output_hex": output.hex()}
        outcome = observed_call(actual)
    finally:
        Path.read_bytes = original_read
    return {"outcome": outcome, "drift_reads": drift_reads, "drift_hits": drift_hits}


def lane(lane_name, output, build_path, target_path, expected_path, manifest_path):
    selected = lane_name == "selected"
    if (SELECTOR in os.environ) is not selected:
        raise ValueError("actual selector differs from declared lane")
    if selected and os.environ.get(DEVELOPMENT) != "1":
        raise ValueError("selected CT36 is an explicit development scope")
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    capture = Captures()
    fixture = capture.json(FIXTURE)
    before = source_capture(capture)
    build_report = capture.json(build_path)
    if build_report["status"] != "BUILT_NOT_QUALIFIED":
        raise ValueError("actual independent observer build is incomplete")
    build = build_report["artifacts"]
    for kind in ("flat", "linked"):
        capture.raw(build[kind]["path"], build[kind]["pin"])
    for item in build["images"].values():
        capture.raw(item["path"], item["pin"])
    target = capture.raw(target_path)
    capture.raw(manifest_path)
    authority = None
    if selected:
        if expected_path is None:
            raise ValueError("selected lane needs both already frozen originals")
        authority = capture.json(expected_path)
        if authority.get("schema") != "hepta.cold-native-transport.ct36-original-authority.v4":
            raise ValueError("wrong original-first authority")
        for item in authority["lanes"]:
            original_report = capture.json(item["report"]["path"], item["report"]["pin"])
            for name, pin in original_report["files"].items():
                capture.raw(Path(item["directory"]) / name, pin)
    elif expected_path is not None:
        raise ValueError("original lane cannot consume a candidate or derived expectation")
    from tools import hia_selfhost_native_observer as flat
    from tools import hia_selfhost_linked_observer as linked
    modules = {"flat": flat, "linked": linked}
    profiles, actual_execute = {}, {}
    for kind, module in modules.items():
        execute = module.execute
        profile = getattr(execute, "hia_cold_native_profile", None)
        if (profile is not None) is not selected:
            raise ValueError("actual public execute route differs")
        profiles[kind], actual_execute[kind] = profile, execute
    # Both lanes execute with the same complete inherited environment. The
    # original bindings were established above without a selector; adding the
    # literal authority path now does not import or execute the candidate.
    os.environ[SELECTOR] = str(Path(manifest_path).resolve(strict=True))
    os.environ[DEVELOPMENT] = "1"
    os.environ["CT36_INHERITED_EXTRA"] = "retained-extra-value"
    poison_hits = []
    def forbidden(*args, **kwargs):
        poison_hits.append("old-whole-run")
        raise AssertionError("selected CT36 called a retired whole subprocess business method")
    saved = (subprocess.run, subprocess.Popen.__init__, subprocess.Popen.communicate)
    if selected:
        subprocess.run = forbidden
        subprocess.Popen.__init__ = forbidden
        subprocess.Popen.communicate = forbidden
    rows, started, stopped, audit_rows = [], [], [], []
    audit_active = False
    def audit(event, arguments):
        if audit_active and event in ("subprocess.Popen", "open"):
            audit_rows.append({"event": event, "arguments": tagged(arguments)})
    sys.addaudithook(audit)
    report = {"schema": "hepta.cold-native-transport.ct36-public.v4", "lane": lane_name,
              "status": "HOLD", "source_before": before,
              "planned": [case["subcase"] for case in fixture["public_cases"]],
              "started": started, "stopped": stopped, "poison_hits": poison_hits,
              "rows": rows, "whole_native": False, "qualification_complete": False}
    observation_path = output / "observations.jsonl"
    missing_cwd = output.parent.parent / "deliberately-nonexistent-ct36-cwd"
    if missing_cwd.exists():
        raise ValueError("missing cwd input unexpectedly exists")
    try:
        with observation_path.open("xb") as observations:
            for ordinal, case in enumerate(fixture["public_cases"]):
                started.append(case["subcase"])
                directory = output / ("%03d-" % ordinal + case["subcase"])
                directory.mkdir(mode=0o700)
                module = modules[case["route"]]
                execute_records = []
                actual = actual_execute[case["route"]]
                def recording_execute(executable_bytes, request, **kwargs):
                    entry = {"executable": data_pin(executable_bytes),
                             "request_hex": request.hex(), "kwargs": tagged(kwargs)}
                    execute_records.append(entry)
                    try:
                        value = actual(executable_bytes, request, **kwargs)
                    except BaseException as error:
                        entry["exception"] = exception_value(error)
                        raise
                    entry["returned"] = {"returncode": value.returncode, "args": tagged(value.args),
                                         "stdout_hex": value.stdout.hex(), "stderr_hex": value.stderr.hex()}
                    return value
                profile = profiles[case["route"]]
                statistics_before = None if profile is None else profile.statistics()
                row = {"ordinal": ordinal, "id": case["id"], "subcase": case["subcase"],
                       "case": case, "parent_pid": os.getpid(), "parent_pgid": os.getpgrp(),
                       "parent_sid": os.getsid(0), "children_before_hex": children().hex(),
                       "fds_before": fd_snapshot(), "execute": execute_records,
                       "statistics_before": statistics_before}
                audit_rows.clear()
                module.execute = recording_execute
                try:
                    audit_active = True
                    if case["kind"] == "execute":
                        row["actual"] = execute_case(case, module, target, directory, missing_cwd)
                    else:
                        row["actual"] = invoke_case(case, module, build, directory, execute_records)
                except BaseException as error:
                    row["observer_error"] = exception_value(error)
                finally:
                    audit_active = False
                    module.execute = actual
                row["audit"] = list(audit_rows)
                row["statistics_after"] = None if profile is None else profile.statistics()
                row["fds_after"] = fd_snapshot()
                row["children_after_hex"] = children().hex()
                identity = directory / "identity.bin"
                if identity.exists():
                    identity_raw = capture.raw(identity)
                    row["identity_raw_hex"] = identity_raw.hex()
                    if len(identity_raw) == 32:
                        pid, ppid, pgid, sid = struct.unpack("<4Q", identity_raw)
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            gone = True
                        else:
                            gone = False
                        row["target_identity"] = {"pid": pid, "ppid": ppid, "pgid": pgid,
                                                  "sid": sid, "gone": gone}
                row["files"] = files(capture, directory)
                row = parse(canonical(row))  # Freeze this observation before the next case.
                observations.write(canonical(row) + b"\n")
                observations.flush()
                rows.append(row)
                stopped.append(case["subcase"])
                if row["children_after_hex"] != row["children_before_hex"]:
                    report["live_child_boundary"] = case["subcase"]
                    break
        report["files"] = files(capture, output)
        capture.unchanged()
        report["source_after"] = source_capture(capture)
        report["source_stable"] = before == report["source_after"]
        if started == report["planned"] == stopped and not poison_hits and report["source_stable"]:
            report["status"] = "OBSERVATIONS_COMPLETE_NOT_QUALIFIED"
    finally:
        if selected:
            subprocess.run, subprocess.Popen.__init__, subprocess.Popen.communicate = saved
        report["consumed"] = capture.pins()
        write_json(output / "report.json", report)
    capture.unchanged()
    return report["status"] == "OBSERVATIONS_COMPLETE_NOT_QUALIFIED"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-observers")
    build.add_argument("--output", type=Path, required=True)
    observe = commands.add_parser("lane")
    observe.add_argument("--lane", choices=("original-1", "original-2", "selected"), required=True)
    observe.add_argument("--output", type=Path, required=True)
    observe.add_argument("--observers", type=Path, required=True)
    observe.add_argument("--target", type=Path, required=True)
    observe.add_argument("--build-manifest", type=Path, required=True)
    observe.add_argument("--original-authority", type=Path)
    args = parser.parse_args()
    if args.command == "build-observers":
        build_observers(args.output)
        return 0
    return 0 if lane(args.lane, args.output, args.observers, args.target, args.original_authority, args.build_manifest) else 1


if __name__ == "__main__":
    raise SystemExit(main())
