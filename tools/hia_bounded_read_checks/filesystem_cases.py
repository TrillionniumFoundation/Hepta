"""Nine real filesystem/default-boundary controls for new bounded-read HIA source.

No input cap is enlarged. Exact8MiB input and a stale-stat growth refusal are
compared to the complete original AST; original caller tests remain separate.
"""
from __future__ import annotations
import argparse
import ast
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import traceback
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import _create_directory, create, read, require, wire
from lifetime_cases import ORACLE_SHA256, oracle_nodes

LIMIT = 8 * 1024 * 1024
EXPECTED_IDS = (
    "empty_ordinary_file",
    "binary_ordinary_file",
    "exact_eight_MiB_default_input",
    "one_byte_above_eight_MiB_stat_refusal",
    "symbolic_link_refusal",
    "nonblocking_FIFO_refusal",
    "directory_refusal",
    "growth_after_stat_postread_refusal",
    "default_argument_survives_MAX_INPUT_BYTES_rebinding",
)


def fixture_file(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "mode": stat.S_IMODE(path.lstat().st_mode)}


def exception_value(error):
    return {"type": type(error).__name__, "args": list(error.args),
            "filename": getattr(error, "filename", None),
            "cause": None if error.__cause__ is None else exception_value(error.__cause__),
            "context": None if error.__context__ is None else exception_value(error.__context__),
            "suppress_context": error.__suppress_context__}


def observe(call):
    try:
        value = call()
    except BaseException as error:
        return {"kind": "exception", "value": exception_value(error)}
    require(type(value) is bytes, "ordinary filesystem read did not return exact bytes")
    return {"kind": "returned", "bytes": len(value), "sha256": sha256(value).hexdigest()}


def original_function(nodes, path, grow):
    namespace = {"MAX_INPUT_BYTES": LIMIT, "Path": Path, "stat": stat}
    descriptors, stats = [], []
    def observed_open(*args):
        descriptor = os.open(*args)
        value = os.fstat(descriptor)
        descriptors.append({"fd": descriptor, "device": value.st_dev,
                            "inode": value.st_ino, "mode": value.st_mode})
        return descriptor
    def observed_fstat(descriptor):
        value = os.fstat(descriptor)
        stats.append({"mode": value.st_mode, "bytes": value.st_size})
        if grow:
            with path.open("ab") as outgoing:
                outgoing.write(b"x")
                outgoing.flush()
                os.fsync(outgoing.fileno())
        return value
    namespace["os"] = SimpleNamespace(O_RDONLY=os.O_RDONLY,
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0), O_NONBLOCK=getattr(os, "O_NONBLOCK", 0),
        open=observed_open, fdopen=os.fdopen, fstat=observed_fstat)
    exec(compile(nodes, "exact-acffa-read-bounded-oracle", "exec"), namespace)
    return namespace["read_bounded"], descriptors, stats


def closed_descriptors(descriptors):
    # Observe the original behavior, including a possible fdopen failure leak;
    # do not add an IO policy that the oracle did not have. Any still-open
    # descriptor created by this fixture is closed only after its state is
    # recorded and its actual identity is checked.
    out = []
    for entry in descriptors:
        descriptor = entry["fd"]
        try:
            current = os.fstat(descriptor)
        except OSError as error:
            out.append({"descriptor": descriptor, "errno": error.errno,
                        "closed": error.errno == errno.EBADF})
        else:
            require((current.st_dev, current.st_ino, current.st_mode) ==
                    (entry["device"], entry["inode"], entry["mode"]),
                    "fixture descriptor was unexpectedly reused")
            out.append({"descriptor": descriptor, "closed": False,
                        "mode": current.st_mode, "bytes": current.st_size})
            os.close(descriptor)
    return out


def closure_shape(rows):
    return [{key: value for key, value in row.items() if key != "descriptor"}
            for row in rows]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(source != output and source not in output.parents, "filesystem evidence entered source")
    _create_directory(output)
    _create_directory(output / "fixtures")
    report = {"schema": "hepta.hia.bounded-read-filesystem-controls.v1", "status": "HOLD",
        "expected_ids": list(EXPECTED_IDS), "loaded_ids": list(EXPECTED_IDS),
        "executed_ids": [], "cases": [], "errors": [],
        "anomalies": {"skips": [], "expected_failures": [], "unexpected_successes": [],
                     "failures": [], "errors": []}, "default_limit_bytes": LIMIT,
        "new_UID_mode_parent_hardlink_policy_added": False,
        "cold_qualification": False, "whole_native_delivery_qualified": False}
    try:
        original_raw, original_pin = read(args.oracle, 1 << 20)
        require(original_pin["sha256"] == ORACLE_SHA256, "exact original oracle differs")
        nodes = oracle_nodes(original_raw)
        sys.path.insert(0, str(source))
        import hepta.hia_program_tools as public
        from hepta.hia_bounded_read_native import installed_bounded_read
        owner = installed_bounded_read(args.manifest)
        require(os.environ.get("HEPTA_HIA_BOUNDED_READ_MANIFEST") == str(args.manifest),
                "filesystem public selector differs")
        report["native_before"] = owner.identity()
        report["manifest_before"] = read(args.manifest, 16384)[1]
        for index, case_id in enumerate(EXPECTED_IDS):
            folder = output / "fixtures" / ("%02d" % index)
            _create_directory(folder)
            path = folder / "input"
            originals = []
            if case_id == "empty_ordinary_file":
                originals.append(fixture_file(path, b""))
            elif case_id == "binary_ordinary_file":
                originals.append(fixture_file(path, bytes(range(256)) * 7))
            elif case_id == "exact_eight_MiB_default_input":
                originals.append(fixture_file(path, b"x" * LIMIT))
            elif case_id == "one_byte_above_eight_MiB_stat_refusal":
                originals.append(fixture_file(path, b"x" * (LIMIT + 1)))
            elif case_id == "symbolic_link_refusal":
                originals.append(fixture_file(folder / "target", b"ordinary"))
                path.symlink_to("target")
                originals.append({"path": str(path), "type": "symlink",
                                  "target": os.readlink(path), "mode": path.lstat().st_mode})
            elif case_id == "nonblocking_FIFO_refusal":
                os.mkfifo(path, 0o600)
                originals.append({"path": str(path), "type": "FIFO", "mode": path.lstat().st_mode})
            elif case_id == "directory_refusal":
                path.mkdir(mode=0o700)
                originals.append({"path": str(path), "type": "directory", "mode": path.lstat().st_mode})
            elif case_id == "growth_after_stat_postread_refusal":
                originals.append(fixture_file(path, b"x" * LIMIT))
                originals.append(fixture_file(folder / "native-input", b"x" * LIMIT))
            elif case_id == "default_argument_survives_MAX_INPUT_BYTES_rebinding":
                originals.append(fixture_file(path, bytes(range(256))))
            grow = case_id == "growth_after_stat_postread_refusal"
            native_path = folder / "native-input" if grow else path
            oracle, reference_fds, reference_stats = original_function(nodes, path, grow)
            native_oracle, native_fds, native_stats = original_function(nodes, native_path, grow)
            reference = observe(lambda: oracle(path))
            reference_closed = closed_descriptors(reference_fds)
            before_calls, before_transitions = owner.calls, owner.transitions
            retained_calls = []
            previous_profile = sys.getprofile()
            require(previous_profile is None, "unexpected filesystem profiler")
            def forbid_original(frame, event, unused):
                if event == "call" and any(frame.f_code is code for code in (
                        native_oracle.__code__, public._READ_BOUNDED_REFERENCE.__code__)):
                    retained_calls.append(frame.f_code.co_name)
                    raise AssertionError("original Python reader entered during native boundary")
            sys.setprofile(forbid_original)
            try:
                if case_id == "default_argument_survives_MAX_INPUT_BYTES_rebinding":
                    previous_limit = public.MAX_INPUT_BYTES
                    public.MAX_INPUT_BYTES = 16
                    try:
                        native = observe(lambda: public.read_bounded(path))
                    finally:
                        public.MAX_INPUT_BYTES = previous_limit
                else:
                    native = observe(lambda: owner.read(native_path, LIMIT,
                        bindings=SimpleNamespace(read_bounded=native_oracle)))
            finally:
                sys.setprofile(previous_profile)
            native_closed = closed_descriptors(native_fds)
            # Both growth outcomes are post-read errors without OS filenames;
            # other reference/native calls use the same actual fixture path.
            closure_equal = (case_id == "default_argument_survives_MAX_INPUT_BYTES_rebinding"
                             or closure_shape(reference_closed) == closure_shape(native_closed))
            passed = (reference == native and owner.calls == before_calls + 1
                      and owner.transitions > before_transitions and not retained_calls and closure_equal)
            detail = {"id": case_id, "status": "PASS" if passed else "FAIL",
                "fixture_inputs": originals, "reference": reference, "native": native,
                "reference_stats": reference_stats, "native_stats": native_stats,
                "reference_descriptor_closure": reference_closed,
                "native_descriptor_closure": native_closed,
                "descriptor_observation_equal": closure_equal,
                "native_descriptor_spy_used": case_id != "default_argument_survives_MAX_INPUT_BYTES_rebinding",
                "retained_policy_calls": retained_calls,
                "actual_native_call_delta": owner.calls - before_calls,
                "actual_native_transition_delta": owner.transitions - before_transitions}
            if grow:
                detail["grown_files"] = [read(path, LIMIT + 1)[1], read(native_path, LIMIT + 1)[1]]
                require(all(row["bytes"] == LIMIT + 1 for row in detail["grown_files"]),
                        "controlled post-stat growth did not occur")
            record = create(output / (case_id + ".json"), wire(detail))
            report["cases"].append({"id": case_id, "status": detail["status"], "record": record})
            report["executed_ids"].append(case_id)
        report["native_after"] = owner.identity()
        report["manifest_after"] = read(args.manifest, 16384)[1]
        require(report["executed_ids"] == list(EXPECTED_IDS)
                and all(row["status"] == "PASS" for row in report["cases"])
                and report["native_before"] == report["native_after"]
                and report["manifest_before"] == report["manifest_after"],
                "complete filesystem result or source binding differs")
        report["status"] = "NINE_FILESYSTEM_BOUNDARIES_PASS_NOT_QUALIFICATION"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "text": str(error),
                                 "traceback": traceback.format_exc()})
        if "case_id" in locals():
            report["failure_case"] = {"id": case_id,
                "fixture_inputs": originals if "originals" in locals() else [],
                "reference": reference if "reference" in locals() else None,
                "native": native if "native" in locals() else None,
                "retained_policy_calls": retained_calls if "retained_calls" in locals() else []}
    finally:
        create(output / "report.json", wire(report))
    print(json.dumps({"status": report["status"], "executed": len(report["executed_ids"]),
                      "expected": len(EXPECTED_IDS)}))
    return 0 if report["status"] == "NINE_FILESYSTEM_BOUNDARIES_PASS_NOT_QUALIFICATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
