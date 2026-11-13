"""Read-only diagnostic of one fixed source tree; never a qualification gate."""
from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import os
from pathlib import Path
import pstats
import stat
import subprocess
import sys
import time
import traceback


def identity(raw):
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
    return identity(raw)


def git(source, *args):
    return subprocess.run(
        ["git", "-C", str(source), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=30,
    ).stdout


def snapshot(source, expected):
    head = git(source, "rev-parse", "HEAD").decode().strip()
    tree = git(source, "rev-parse", "HEAD^{tree}").decode().strip()
    if head != expected["source_commit"] or tree != expected["source_tree"]:
        raise ValueError(("wrong fixed source", head, tree))
    rows = {}
    for line in git(source, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not line:
            continue
        metadata, raw_path = line.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        name = raw_path.decode("utf-8", "strict")
        if kind != "blob" or mode not in ("100644", "100755", "120000"):
            raise ValueError(("unreviewed tree member", name, mode, kind))
        path = source / name
        if not name or name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/")):
            raise ValueError(("unsafe source path", name))
        for parent in path.parents:
            if parent == source:
                break
            if parent.is_symlink():
                raise ValueError(("symlink source parent", name))
        info = path.lstat()
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                raise ValueError(("source symlink changed", name))
            raw = os.fsencode(os.readlink(path))
        else:
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != int(mode[-3:], 8):
                raise ValueError(("source mode changed", name, info.st_mode, mode))
            raw = path.read_bytes()
        row = identity(raw)
        if row["git_blob"] != oid:
            raise ValueError(("source bytes changed", name, row["git_blob"], oid))
        rows[name] = {"mode": mode, **row}
    if len(rows) != expected["source_files"]:
        raise ValueError(("source count changed", len(rows)))
    untracked = git(source, "ls-files", "--others", "--exclude-standard", "-z")
    if untracked:
        raise ValueError(("unexpected untracked source", untracked.decode("utf-8", "backslashreplace")))
    return {"head": head, "tree": tree, "files": rows}


def protocol_observation(contract):
    pathlib = contract._source_pathlib
    concrete = pathlib.PosixPath
    names = ("read_bytes", "open", "__truediv__", "as_posix", "relative_to",
             "__fspath__", "__str__", "joinpath", "with_segments")
    result = {
        "pathlib_file": pathlib.__file__,
        "captured": contract._SOURCE_PATH_PROTOCOL is not None,
        "current": contract._source_protocol_current(contract.ROOT),
        "methods": [], "classes": [],
    }
    if result["captured"]:
        result["buffering"] = contract._SOURCE_PATH_PROTOCOL[4]
    for name in names:
        function = contract._source_static_member(concrete, name)
        row = {"name": name, "type": type(function).__name__}
        if type(function) is contract._source_types.FunctionType:
            row.update({
                "filename": function.__code__.co_filename,
                "module": function.__module__,
                "globals_are_public_pathlib": function.__globals__ is pathlib.__dict__,
                "code_bytes": identity(function.__code__.co_code),
                "co_names": list(function.__code__.co_names),
                "co_varnames": list(function.__code__.co_varnames),
                "matches_312": contract._source_same_protocol(function, contract._SourcePathProtocol312.__dict__[name]),
                "matches_314": contract._source_same_protocol(function, contract._SourcePathProtocol314.__dict__[name]),
            })
        result["methods"].append(row)
    for cls in concrete.__mro__:
        if cls is object:
            continue
        row = {"name": cls.__name__, "namespace_length": len(cls.__dict__), "function_origins": []}
        for name, value in cls.__dict__.items():
            function = value.__func__ if type(value) in (classmethod, staticmethod) else value
            if type(function) is contract._source_types.FunctionType:
                row["function_origins"].append({
                    "name": name, "filename": function.__code__.co_filename,
                    "globals_are_public_pathlib": function.__globals__ is pathlib.__dict__,
                })
        result["classes"].append(row)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    expected = json.loads(args.inputs.read_text())
    report = {
        "schema": "hepta.source-admission.actual-runtime-diagnostic.v1",
        "status": "INCOMPLETE", "inputs": expected, "python": sys.version,
        "started_utc_ns": time.time_ns(), "product_policy_edited": False,
        "product_tests_executed": 0, "native_compilations": 0,
        "qualification": False, "whole_native": False,
        "original_test_budget_modified": False,
        "methodological_limits": [
            "Descriptive fixed-order fresh scans, not a randomized improvement claim.",
            "Source snapshots read all tracked bytes before and after timing and therefore warm the filesystem cache.",
            "cProfile times include instrumentation overhead and are not original business deadline measurements.",
            "Every product scan rereads every file; no file, digest or inventory cache is introduced.",
            "No original business test, compiler or machine image runs in this diagnostic.",
        ],
    }
    before = None
    failure = None
    try:
        if tuple(sys.version_info[:3]) != tuple(expected["python_version"]):
            raise ValueError(("wrong Python runtime", sys.version))
        for name in tuple(os.environ):
            if name.startswith("HEPTA_HIA_"):
                del os.environ[name]
        sys.dont_write_bytecode = True
        before = snapshot(source, expected)
        report["before"] = write_json(out / "SOURCE-BEFORE.json", before)
        sys.path.insert(0, str(source))
        from tools import hia_selfhost_contract as contract
        from tools.build_hia_json_preflight import current_sources
        report["protocol"] = protocol_observation(contract)
        calls = []
        baseline = None
        for name, function in [("current_sources", current_sources)] * 4 + [("file_digests", contract.file_digests)] * 4:
            wall = time.perf_counter_ns()
            cpu = time.process_time_ns()
            result = function()
            cpu_elapsed = time.process_time_ns() - cpu
            elapsed = time.perf_counter_ns() - wall
            raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if name == "current_sources":
                if baseline is None:
                    baseline = result
                    (out / "CURRENT-SOURCES.json").write_bytes(raw)
                elif result != baseline:
                    raise ValueError("fresh source maps differ")
            elif result != {k: v for k, v in baseline.items() if k != contract.CONTRACT_PATH}:
                raise ValueError("fresh file map differs from contract")
            row = {"name": name, "wall_ns": elapsed, "process_cpu_ns": cpu_elapsed,
                   "returned_paths": len(result), "map": identity(raw)}
            calls.append(row)
            with (out / "CALLS.jsonl").open("a") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
        report["calls"] = calls
        report["source_paths_without_contract"] = len(baseline) - 1
        report["source_bytes_without_contract"] = sum((source / n).stat().st_size for n in baseline if n != contract.CONTRACT_PATH)
        prof = cProfile.Profile()
        prof.enable()
        observed = current_sources()
        prof.disable()
        if observed != baseline:
            raise ValueError("instrumented map differs")
        prof.dump_stats(str(out / "current-sources.prof"))
        rows = []
        for key, value in pstats.Stats(prof).stats.items():
            primitive, total, self_time, cumulative, callers = value
            rows.append({
                "file": key[0], "line": key[1], "function": key[2],
                "primitive_calls": primitive, "calls": total,
                "self_seconds": self_time, "cumulative_seconds": cumulative,
                "callers": [{"key": list(k), "value": v} for k, v in callers.items()],
            })
        rows.sort(key=lambda row: row["cumulative_seconds"], reverse=True)
        report["instrumented_cprofile"] = rows
        report["status"] = "OBSERVATIONS_COMPLETE"
    except BaseException:
        failure = traceback.format_exc()
        (out / "FAILURE.txt").write_text(failure)
        report["status"] = "DIAGNOSTIC_FAILURE"
    finally:
        try:
            after = snapshot(source, expected)
            report["after"] = write_json(out / "SOURCE-AFTER.json", after)
            report["source_unchanged"] = before is not None and before == after
            if not report["source_unchanged"]:
                report["status"] = "DIAGNOSTIC_FAILURE"
        except BaseException:
            report["source_unchanged"] = False
            report["source_after_failure"] = traceback.format_exc()
            report["status"] = "DIAGNOSTIC_FAILURE"
        report["finished_utc_ns"] = time.time_ns()
        write_json(out / "REPORT.json", report)
        print(json.dumps({key: value for key, value in report.items() if key not in ("instrumented_cprofile", "protocol")}, sort_keys=True), flush=True)
        if failure:
            print(failure, file=sys.stderr, flush=True)
    return 0 if report["status"] == "OBSERVATIONS_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
