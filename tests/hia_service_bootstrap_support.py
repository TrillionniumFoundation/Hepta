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

def _stop_owned_group(process):
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


_ACTIVE_CHILD_TREE = None
_CHILD_TREE_ENV = "HIA_BOOTSTRAP_CHILD_TREE"

def _process_identity(pid):
    path = Path("/proc") / str(pid)
    text = (path / "stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    return {"pid":pid, "ppid":int(fields[1]), "pgid":int(fields[2]),
            "sid":int(fields[3]), "start_ticks":int(fields[19]),
            "state":fields[0], "uid":path.stat().st_uid}


class _OwnedChildTree:
    """Per-invocation nonce plus pidfds; never signal an unbound process."""
    def __init__(self, token):
        self.token = token
        self.children = {}
        self.reaped = {}
        self.signals = []
        self.unattributed = []
        self.baseline_children = {}
        for path in Path("/proc").iterdir():
            if path.name.isdigit():
                try:
                    row = _process_identity(int(path.name))
                    if row["ppid"] == os.getpid():
                        self.baseline_children[row["pid"]] = row["start_ticks"]
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue

    def capture(self, root_pid):
        rows = {}
        tagged = set()
        expected = (_CHILD_TREE_ENV + "=" + self.token).encode()
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            pid = int(path.name)
            if pid == os.getpid():
                continue
            try:
                row = _process_identity(pid)
                if row["uid"] != os.getuid():
                    continue
                rows[pid] = row
                if expected in (path / "environ").read_bytes().split(bytes([0])):
                    tagged.add(pid)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        owned = tagged | {pid for pid, (old, fd) in self.children.items()
                          if pid in rows and rows[pid]["start_ticks"] == old["start_ticks"]}
        while True:
            more = {pid for pid, row in rows.items() if row["ppid"] in owned}
            if more <= owned:
                break
            owned.update(more)
        unknown = [row for pid, row in rows.items()
                   if row["ppid"] == os.getpid() and pid != root_pid and pid not in owned
                   and self.baseline_children.get(pid) != row["start_ticks"]]
        if unknown:
            self.unattributed = unknown
            raise RuntimeError("an adopted child has no verified owned-tree identity")
        added = []
        for pid in sorted(owned):
            row = rows[pid]
            if pid in self.children:
                if self.children[pid][0]["start_ticks"] != row["start_ticks"]:
                    raise RuntimeError("owned child PID identity changed")
                continue
            descriptor = None
            saved = False
            try:
                descriptor = os.pidfd_open(pid)
                current = _process_identity(pid)
                if (current["start_ticks"] != row["start_ticks"]
                        or current["uid"] != row["uid"]):
                    raise RuntimeError("owned child changed during pidfd capture")
                self.children[pid] = (row, descriptor)
                saved = True
                added.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
            finally:
                if descriptor is not None and not saved:
                    os.close(descriptor)
        return added

    def stop(self, process):
        deadline = time.monotonic() + 3
        before = group_members(process.pid)
        self.capture(process.pid)
        first = [dict(row) for row, descriptor in self.children.values()]
        if process.poll() is None and process.pid not in self.children:
            raise RuntimeError("live suite has no verified nonce and pidfd identity")
        signaled = set()
        while True:
            self.capture(process.pid)
            for pid, (row, descriptor) in self.children.items():
                if pid in signaled:
                    continue
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    self.signals.append("SIGKILL_PIDFD:" + str(pid))
                except ProcessLookupError:
                    pass
                signaled.add(pid)
            if process.poll() is None:
                process.wait(timeout=max(0.001, deadline-time.monotonic()))
            for pid, (row, descriptor) in self.children.items():
                if pid == process.pid:
                    self.reaped[pid] = {"by":"Popen.wait", "returncode":process.returncode}
                    continue
                if pid in self.reaped:
                    continue
                try:
                    got, status = os.waitpid(pid, os.WNOHANG)
                    if got == pid:
                        self.reaped[pid] = {"by":"owned-subreaper", "wait_status":status}
                        continue
                except ChildProcessError:
                    pass
                try:
                    current = _process_identity(pid)
                    if current["start_ticks"] != row["start_ticks"]:
                        raise RuntimeError("owned child PID was reused before terminal verification")
                except (FileNotFoundError, ProcessLookupError):
                    self.reaped[pid] = {"by":"original-parent", "proc_absent":True}
            added = self.capture(process.pid)
            after = group_members(process.pid)
            if not added and not after and set(self.children) <= set(self.reaped):
                return {"before":before, "after":after, "signals":list(self.signals),
                        "reaped":True, "descendants_before":first,
                        "descendants_captured":[dict(row) for row, fd in self.children.values()],
                        "descendants_reaped":{str(pid):item for pid,item in self.reaped.items()},
                        "ownership":"per-invocation-environment-nonce-and-pidfd"}
            if time.monotonic() >= deadline:
                raise RuntimeError("owned bootstrap descendant tree remained after three-second cleanup")
            time.sleep(0.01)

    def close(self):
        for row, descriptor in self.children.values():
            os.close(descriptor)


def stop_owned(process):
    if _ACTIVE_CHILD_TREE is None:
        return _stop_owned_group(process)
    return _ACTIVE_CHILD_TREE.stop(process)


def run_owned_tree(parent, label, command, *, seconds, report_relative="report.json", env=None):
    """Contain the complete suite including descendants that call setsid().

    The unchanged run_child still enforces its original wait and three-second
    cleanup budget. Only the suite controller opts into this Linux containment;
    observer processes do not load this host interface.
    """
    import ctypes
    import secrets
    import threading
    global _ACTIVE_CHILD_TREE
    if (_ACTIVE_CHILD_TREE is not None
            or threading.current_thread() is not threading.main_thread()
            or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal")):
        raise RuntimeError("exclusive Linux owned-tree controller is required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p,
                          ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or previous.value not in (0,1):
        raise OSError(ctypes.get_errno(), "cannot capture child-subreaper state")
    if libc.prctl(36, ctypes.c_void_p(1), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot enable owned descendant reaping")
    tree = None
    try:
        tree = _OwnedChildTree(secrets.token_hex(24))
        child_env = dict(os.environ if env is None else env)
        child_env[_CHILD_TREE_ENV] = tree.token
        _ACTIVE_CHILD_TREE = tree
        write_json(Path(parent)/(label+".tree-start.json"), {
            "schema":SCHEMA+"-owned-tree.v1", "previous_subreaper":previous.value,
            "nonce_sha256":sha256(tree.token.encode()).hexdigest(),
            "command":list(command), "timeout_seconds":seconds, "cleanup_seconds":3})
        return run_child(parent,label,command,seconds=seconds,
                         report_relative=report_relative,env=child_env)
    finally:
        _ACTIVE_CHILD_TREE = None
        try:
            if libc.prctl(36, ctypes.c_void_p(previous.value), 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "cannot restore child-subreaper state")
            actual = ctypes.c_int()
            if libc.prctl(37, ctypes.byref(actual), 0, 0, 0) != 0 or actual.value != previous.value:
                raise RuntimeError("child-subreaper restoration differs")
            if tree is not None:
                write_json(Path(parent)/(label+".tree-terminal.json"), {
                    "schema":SCHEMA+"-owned-tree.v1", "restored_subreaper":actual.value,
                    "descendants_captured":[dict(row) for row,fd in tree.children.values()],
                    "descendants_reaped":{str(pid):item for pid,item in tree.reaped.items()},
                    "unattributed_children":list(tree.unattributed),
                    "all_captured_reaped":not tree.unattributed and set(tree.children)<=set(tree.reaped)})
        finally:
            if tree is not None:
                tree.close()


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
