"""Pure-data custody and owned-process support for bootstrap qualification."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hepta.hia.service-bootstrap"
CASE_TERMINAL_SCHEMA = "hepta.hia.service-bootstrap-case-terminal.v1"

def case_terminals(directory, report, cases):
    """Read every case boundary as data; never import an observer or product."""
    if report.get("case_terminal_protocol") != CASE_TERMINAL_SCHEMA:
        raise ValueError("bootstrap case-terminal protocol is missing or stale")
    names = {"schema", "id", "retained_worlds", "released_worlds",
             "collection_calls", "active_exception_before", "active_exception_after",
             "context", "main_thread", "gc_before", "gc_after"}
    expected_gc = None
    count = 0
    for ordinal, raw, row in json_lines(
            Path(directory) / "case-terminals.jsonl",
            report["files"]["case-terminals.jsonl"]):
        if ordinal >= len(cases) or type(row) is not dict or set(row) != names:
            raise ValueError("case-terminal record count or complete shape differs")
        case = cases[ordinal]
        parts = 2 if case["method"] == "generator_protocol" else 1
        if (row["schema"] != CASE_TERMINAL_SCHEMA or row["id"] != case["id"]
                or type(row["retained_worlds"]) is not int or row["retained_worlds"] != parts
                or type(row["released_worlds"]) is not int or row["released_worlds"] != parts
                or type(row["collection_calls"]) is not int or row["collection_calls"] != 1
                or row["active_exception_before"] is not None
                or row["active_exception_after"] is not None
                or row["context"] != "main" or row["main_thread"] is not True):
            raise ValueError("case-terminal identity, ownership, or context differs")
        for value in (row["gc_before"], row["gc_after"]):
            if (type(value) is not dict or set(value) != {"enabled", "thresholds"}
                    or value["enabled"] is not True
                    or type(value["thresholds"]) is not list or len(value["thresholds"]) != 3
                    or any(type(n) is not int or n < 0 for n in value["thresholds"])):
                raise ValueError("case-terminal GC state is not complete")
        if expected_gc is None:
            expected_gc = row["gc_before"]
        if row["gc_before"] != expected_gc or row["gc_after"] != expected_gc:
            raise ValueError("case-terminal GC configuration changed")
        count += 1
    if count != len(cases) or report["count"] != count:
        raise ValueError("case-terminal channel omitted an original input")
    return {"count": count, "gc": expected_gc}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
def same(left, right):
    return canonical(left) == canonical(right)
def require_pin(value):
    if (type(value) is not dict or set(value) != {"bytes", "sha256"}
            or type(value["bytes"]) is not int or value["bytes"] < 0
            or type(value["sha256"]) is not str or len(value["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in value["sha256"])):
        raise ValueError("a complete fixed bytes/SHA256 identity is required")
    return value
def bytes_pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON member: " + key)
        value[key] = item
    return value
def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)
def capture_json(path, expected=None):
    raw = Path(path).read_bytes()
    pin = bytes_pin(raw)
    if expected is not None and not same(pin, require_pin(expected)):
        raise ValueError("captured JSON identity differs: " + str(path))
    return raw, parse(raw), pin
def exact_reread(path, raw):
    if Path(path).read_bytes() != raw:
        raise ValueError("captured bytes changed: " + str(path))
def write_json(path, value):
    path = Path(path)
    raw = canonical(value) + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)
    return bytes_pin(raw)
def file_pin(path):
    digest, size = sha256(), 0
    with Path(path).open("rb") as stream:
        for raw in iter(lambda: stream.read(1 << 20), b""):
            digest.update(raw);size += len(raw)
    return {"bytes": size, "sha256": digest.hexdigest()}
def json_lines(path, expected):
    """Hash the exact bytes that are parsed, then compare to the prior fixed pin."""
    digest, size = sha256(), 0
    with Path(path).open("rb") as stream:
        for ordinal, raw in enumerate(stream):
            if not raw.endswith(b"\n"):
                raise ValueError("JSONL row is incomplete")
            digest.update(raw);size += len(raw)
            yield ordinal, raw, parse(raw)
    if not same({"bytes": size, "sha256": digest.hexdigest()}, require_pin(expected)):
        raise ValueError("consumed JSONL bytes differ from their prior fixed identity")
    if not same(file_pin(path), require_pin(expected)):
        raise ValueError("JSONL changed after its complete consumption")
def identical_files(left, right, left_pin, right_pin):
    require_pin(left_pin); require_pin(right_pin)
    if not same(left_pin, right_pin):
        return False
    dleft, dright, size = sha256(), sha256(), 0
    with Path(left).open("rb") as a, Path(right).open("rb") as b:
        while True:
            x, y = a.read(1 << 20), b.read(1 << 20)
            if x != y:
                return False
            if not x:
                break
            dleft.update(x);dright.update(y);size += len(x)
    expected = {"bytes":size,"sha256":dleft.hexdigest()}
    if not same(expected, left_pin) or dright.hexdigest() != right_pin["sha256"]:
        raise ValueError("bytes compared did not match the original lane pins")
    if not same(file_pin(left), left_pin) or not same(file_pin(right), right_pin):
        raise ValueError("original stream changed during its comparison")
    return True
def source_snapshot():
    path = ROOT / "tools/build_hia_service_bootstrap.py"
    raw = path.read_bytes()
    tree = ast.parse(raw)
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "INPUTS" for t in n.targets))
    names = ast.literal_eval(node.value)
    if type(names) is not tuple or any(type(name) is not str for name in names):
        raise ValueError("bootstrap INPUTS must be its explicit literal source tuple")
    result = {}
    for name in names:
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("bootstrap input leaves its source root")
        item = (ROOT / name).read_bytes()
        result[name] = bytes_pin(item)
    if result["tools/build_hia_service_bootstrap.py"] != bytes_pin(raw):
        raise ValueError("builder changed while reading its source closure")
    exact_reread(path, raw)
    return result
def assert_snapshot(before):
    if not same(source_snapshot(), before):
        raise ValueError("bootstrap component source changed")

def group_members(group):
    rows = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            text = (path / "stat").read_text()
            fields = text[text.rindex(")") + 2:].split()
            if int(fields[2]) == group:
                rows.append({"pid": int(path.name), "state": fields[0]})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(rows, key=lambda row: row["pid"])

def stop_owned(process):
    deadline = time.monotonic() + 3
    before = group_members(process.pid)
    signals = []
    if before:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signals.append("SIGKILL")
        except ProcessLookupError:
            pass
    process.wait(timeout=max(0.001, deadline-time.monotonic()))
    while time.monotonic() < deadline:
        after = group_members(process.pid)
        if not after:
            return {"before":before, "after":after, "signals":signals, "reaped":True}
        time.sleep(0.01)
    raise RuntimeError("owned bootstrap process group remained after three-second cleanup")


def run_child(parent, label, command, *, seconds, report_relative="report.json", env=None):
    if type(seconds) is not int or seconds <= 0:
        raise ValueError("a declared positive integer child budget is required")
    parent = Path(parent)
    if Path(label).name != label:
        raise ValueError("child label must be one basename")
    out_path, err_path = parent / (label + ".stdout.log"), parent / (label + ".stderr.log")
    start_path, result_path = parent / (label + ".start.json"), parent / (label + ".result.json")
    directory = parent / label
    started, start_ns = time.monotonic(), time.time_ns()
    process = None
    timed_out = False
    cleanup = cleanup_error = supervisor_error = None
    start = {"schema": SCHEMA + "-child-start.v1", "label": label,
             "command": list(command), "cwd": str(ROOT), "started_time_ns": start_ns,
             "timeout_seconds": seconds, "cleanup_seconds": 3}
    with out_path.open("xb") as out, err_path.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=os.environ.copy() if env is None else env,
                                       stdout=out, stderr=err, start_new_session=True)
            start["pid"] = process.pid
            start["pgid"] = os.getpgid(process.pid)
            if start["pgid"] != process.pid:
                raise RuntimeError("child is not in its independently owned process group")
            start["owned_group_at_start"] = group_members(process.pid)
            write_json(start_path, start)
            try:
                process.wait(timeout=max(0.001, seconds-(time.monotonic()-started)))
            except subprocess.TimeoutExpired:
                timed_out = True
        except BaseException as error:
            supervisor_error = {"type": type(error).__name__, "text": str(error)}
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = {"type": type(error).__name__, "text": str(error)}
    report_path = directory / report_relative
    report_raw = report = report_pin = None
    if report_path.is_file():
        try:
            report_raw, report, report_pin = capture_json(report_path)
        except BaseException as error:
            if supervisor_error is None:
                supervisor_error = {"type": type(error).__name__, "text": str(error)}
    result = {"schema":SCHEMA + "-child-result.v1", "label":label,
              "command": list(command), "cwd": str(ROOT),
              "pid": None if process is None else process.pid,
              "pgid": None if process is None else process.pid,
              "returncode": None if process is None else process.returncode,
              "timeout": timed_out, "timeout_seconds": seconds, "cleanup_seconds": 3,
              "reaped": process is not None and process.poll() is not None,
              "cleanup":cleanup, "cleanup_error":cleanup_error, "supervisor_error":supervisor_error,
              "started_time_ns":start_ns, "ended_time_ns":time.time_ns(),
              "elapsed_seconds":time.monotonic()-started,
              "report": None if report_pin is None else {"relative":report_relative, **report_pin},
              "stdout":file_pin(out_path), "stderr":file_pin(err_path)}
    write_json(result_path, result)
    if (process is None or process.returncode != 0 or timed_out or supervisor_error
            or cleanup_error or not result["reaped"] or cleanup is None or cleanup["after"]
            or report is None):
        raise RuntimeError("complete owned bootstrap child failed: " + label)
    if (type(report.get("pid")) is not int or type(report.get("pgid")) is not int
            or report["pid"] != process.pid or report["pgid"] != process.pid):
        raise ValueError("inner bootstrap report is not bound to the actual owned child")
    if report_raw is not None:
        exact_reread(report_path, report_raw)
    return result, report, report_raw

def child_identity():
    return {"pid":os.getpid(), "pgid":os.getpgrp(), "argv":sys.argv,
            "executable":sys.executable, "cwd":str(Path.cwd()),
            "runtime":sys.version, "runtime_version":list(sys.version_info[:3]),
            "implementation":sys.implementation.name}

def differences(expected, actual, path=""):
    if type(expected) is not type(actual):
        return [{"path":path, "expected":expected, "actual":actual}]
    if type(expected) is dict:
        rows = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                rows.append({"path":path+"/"+key, "expected_present":key in expected,
                             "actual_present":key in actual})
            else:
                rows.extend(differences(expected[key], actual[key], path+"/"+key))
        return rows
    if type(expected) is list:
        if len(expected) != len(actual):
            return [{"path":path, "expected":expected, "actual":actual}]
        rows = []
        for i, (left, right) in enumerate(zip(expected, actual)):
            rows.extend(differences(left,right,path+"/"+str(i)))
        return rows
    return [] if expected == actual else [{"path":path, "expected":expected, "actual":actual}]
