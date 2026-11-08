"""Linux-only owner for one cold qualification and its ordinary descendants.

A fresh, single-threaded supervisor enables CHILD_SUBREAPER only in itself.
Reparented descendants remain owned across setsid(), as used by the normal
linker capture. This is lifecycle control, not a security sandbox: privileged
processes, PID-namespace changes and external interference are outside scope.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SCHEMA = "hepta.hia.selfhost-process-owner.v1"
QUALIFICATION_SECONDS = 180
CLEANUP_SECONDS = 3
MAX_REQUEST_BYTES = 262144
MAX_CHILDREN = 4096
MAX_EVENTS = 16384


class OwnerFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise OwnerFailure(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def require_linux():
    require(sys.platform == "linux" and all(hasattr(os, name) for name in (
        "waitid", "P_ALL", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
        "cold process ownership requires Linux waitid(WNOWAIT); no weaker fallback")


def children():
    # The dedicated supervisor never starts a thread. Its only spawned process
    # is the qualification leader; subsequent children are adopted descendants.
    tasks = list(Path("/proc/self/task").iterdir())
    require(len(tasks) == 1 and tasks[0].name == str(os.getpid()), "supervisor must remain single-threaded")
    # Some supported Linux executors omit task/<tid>/children. A bounded PPID
    # scan also discovers adopted live children in separate sessions. It is not
    # the completion proof: only waitid's final ECHILD establishes emptiness.
    entries = [p for p in Path("/proc").iterdir() if p.name.isdigit()]
    require(len(entries) <= 16384, "process metadata enumeration exceeds its bound")
    pids = []
    for entry in entries:
        try:
            item = process_identity(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue  # An unrelated process may exit during the metadata scan.
        if item["ppid"] == os.getpid():
            pids.append(item["pid"])
    require(len(pids) <= MAX_CHILDREN, "owned child listing exceeds its bound")
    return pids


def process_identity(pid):
    raw = Path("/proc/%d/stat" % pid).read_bytes()
    require(len(raw) <= 65536 and raw.startswith((str(pid) + " (").encode()), "invalid owned process stat")
    end = raw.rfind(b")")
    fields = raw[end + 2:].split()
    require(end >= 0 and len(fields) >= 20, "incomplete owned process stat")
    result = {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
              "sid": int(fields[3]), "start_ticks": int(fields[19])}
    return result


def identity(pid):
    result = process_identity(pid)
    require(result["ppid"] == os.getpid(), "process is not a direct owned child")
    return result


def configure_owner(parent_pid):
    require_linux()
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "supervisor requires default SIGCHLD disposition")
    require(not children(), "fresh supervisor unexpectedly owns children")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    # These attributes belong to this disposable supervisor, never its caller.
    require(libc.prctl(36, 1, 0, 0, 0) == 0, "PR_SET_CHILD_SUBREAPER unavailable")
    observed = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(observed), 0, 0, 0) == 0 and observed.value == 1,
            "subreaper readback failed")
    require(libc.prctl(1, signal.SIGTERM, 0, 0, 0) == 0, "parent-death notification unavailable")
    require(os.getppid() == parent_pid, "supervisor parent changed before qualification launch")


def observe(pid):
    info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    require(info is None or info.si_pid == pid, "wait observation names another child")
    return info


def supervise(request):
    interrupted = []
    def notice(number, _frame):
        interrupted.append(number)
    signal.signal(signal.SIGTERM, notice)
    signal.signal(signal.SIGINT, notice)
    report = {"schema": SCHEMA, "status": "OWNER_FAILED", "platform": sys.platform,
        "supervisor_pid": os.getpid(), "parent_pid": os.getppid(),
        "qualification_seconds": request["qualification_seconds"],
        "cleanup_seconds": request["cleanup_seconds"], "subreaper_enabled": False,
        "qualification_started": False, "qualification_pid": None,
        "returncode": None, "exit_observed_before_deadline": False,
        "timed_out": False, "interrupted_signals": interrupted,
        "direct_and_adopted_children": [], "events": [], "event_overflow": False,
        "child_enumeration": "bounded proc PPID scan; final kernel waitid ECHILD required",
        "historical_descendant_inventory_complete": False,
        "cleanup": {"attempted": False, "complete": False, "observed_echild": False,
                    "deadline_exceeded": False, "leader_reaped": False, "errors": []}}
    process = None
    known, signalled = {}, set()

    def event(kind, **values):
        if len(report["events"]) < MAX_EVENTS:
            report["events"].append({"kind": kind, "monotonic_ns": time.monotonic_ns(), **values})
        else:
            report["event_overflow"] = True

    def remember(pid):
        item = identity(pid)
        key = (pid, item["start_ticks"])
        if key not in known:
            known[key] = item
            report["direct_and_adopted_children"].append(item)
            event("owned_child_observed", **item)
        return key

    try:
        configure_owner(request["parent_pid"])
        report["subreaper_enabled"] = True
        require(not interrupted, "parent or operator interrupted before launch")
        now = time.monotonic_ns()
        require(request["started_ns"] <= now, "qualification clock is from the future")
        if now >= request["deadline_ns"]:
            report["timed_out"] = True
        else:
            with open(request["stdout_path"], "ab", buffering=0) as stdout, \
                    open(request["stderr_path"], "ab", buffering=0) as stderr:
                process = subprocess.Popen(request["command"], cwd=request["cwd"], env=request["env"],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True)
            report["qualification_started"] = True
            report["qualification_pid"] = process.pid
            event("qualification_started", pid=process.pid)
            remember(process.pid)
            while not interrupted:
                # Observe first, then enforce the deadline on that observation.
                info = observe(process.pid)
                now = time.monotonic_ns()
                if now >= request["deadline_ns"]:
                    report["timed_out"] = True
                    break
                if info is not None:
                    report["exit_observed_before_deadline"] = True
                    event("qualification_exit_observed", pid=info.si_pid,
                          si_code=info.si_code, si_status=info.si_status)
                    break
                time.sleep(min(0.01, (request["deadline_ns"] - now) / 1e9))
    except BaseException as error:
        report["owner_error"] = type(error).__name__ + ": " + str(error)[:256]
    finally:
        cleanup = report["cleanup"]
        cleanup["attempted"] = True
        cleanup_started = time.monotonic_ns()
        cleanup_deadline = cleanup_started + int(request["cleanup_seconds"] * 1e9)
        cleanup["started_ns"] = cleanup_started
        # Kill only actual direct children while their unreaped identity is held.
        # Killing a parent causes its children, including another session's
        # linker, to be adopted here. Repeat until waitid confirms ECHILD.
        while report["subreaper_enabled"]:
            if time.monotonic_ns() >= cleanup_deadline:
                cleanup["deadline_exceeded"] = True
                break
            try:
                for pid in children():
                    key = remember(pid)
                    info = observe(pid)
                    if info is None and key not in signalled:
                        try:
                            os.kill(pid, signal.SIGKILL)
                            signalled.add(key)
                            event("owned_child_sigkill", pid=pid, start_ticks=key[1])
                        except ProcessLookupError:
                            require(observe(pid) is not None, "owned child disappeared without terminal wait observation")
                while True:
                    try:
                        info = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        cleanup["observed_echild"] = True
                        break
                    if info is None:
                        break
                    key = remember(info.si_pid)
                    pid, status = os.waitpid(info.si_pid, os.WNOHANG)
                    require(pid == info.si_pid, "terminal child was not reaped")
                    code = os.waitstatus_to_exitcode(status)
                    event("owned_child_reaped", pid=pid, start_ticks=key[1], returncode=code)
                    if process is not None and pid == process.pid:
                        process.returncode = code
                        report["returncode"] = code
                        cleanup["leader_reaped"] = True
                if cleanup["observed_echild"]:
                    cleanup["deadline_exceeded"] = time.monotonic_ns() >= cleanup_deadline
                    cleanup["complete"] = (not cleanup["deadline_exceeded"] and not cleanup["errors"]
                                           and not children())
                    break
            except BaseException as error:
                cleanup["errors"].append(type(error).__name__ + ": " + str(error)[:256])
                break
            time.sleep(min(0.01, max(0, cleanup_deadline - time.monotonic_ns()) / 1e9))
        cleanup["elapsed_ns"] = time.monotonic_ns() - cleanup_started
        try:
            cleanup["remaining_direct_children"] = children()
        except BaseException as error:
            cleanup["remaining_direct_children"] = None
            cleanup["errors"].append(type(error).__name__)
            cleanup["complete"] = False
        if process is None:
            cleanup["leader_reaped"] = False
        if not cleanup["complete"] or report["event_overflow"]:
            report["status"] = "CLEANUP_HOLD"
        elif "owner_error" in report:
            report["status"] = "OWNER_FAILED"
        elif interrupted:
            report["status"] = "QUALIFICATION_INTERRUPTED"
        elif report["timed_out"]:
            report["status"] = "QUALIFICATION_TIMEOUT"
        elif report["returncode"] == 0 and report["exit_observed_before_deadline"]:
            report["status"] = "OWNED_PROCESS_COMPLETED"
        else:
            report["status"] = "QUALIFICATION_FAILED"
    return report


def run_owned(command, *, cwd, env, stdout_path, stderr_path, receipt_path,
              qualification_seconds=QUALIFICATION_SECONDS, cleanup_seconds=CLEANUP_SECONDS):
    """Launch the dedicated owner; never set subreaper attributes in this caller."""
    require_linux()
    for value, maximum in ((qualification_seconds, QUALIFICATION_SECONDS), (cleanup_seconds, CLEANUP_SECONDS)):
        require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum
                and int(value * 1e9) > 0,
                "fixed process/cleanup budget exceeded")
    require(type(command) is list and command and all(type(v) is str and v and "\0" not in v for v in command),
            "nonempty shell-free command required")
    require(type(env) is dict and all(type(k) is str and type(v) is str and k and "=" not in k
                                    and "\0" not in k + v for k, v in env.items()), "explicit environment required")
    paths = {key: str(Path(value).absolute()) for key, value in (
        ("stdout_path", stdout_path), ("stderr_path", stderr_path), ("receipt_path", receipt_path))}
    require(len(set(paths.values())) == 3, "distinct private output paths required")
    for key in ("stdout_path", "stderr_path"):
        create(paths[key], b"")
    require(not Path(paths["receipt_path"]).exists(), "new owner receipt required")
    started = time.monotonic_ns()
    implementation = Path(__file__).resolve()
    implementation_hash = sha256(implementation.read_bytes()).hexdigest()
    request = {"schema": SCHEMA, "command": list(command), "cwd": str(Path(cwd).absolute()),
        "env": dict(env), **paths, "parent_pid": os.getpid(), "started_ns": started,
        "deadline_ns": started + int(qualification_seconds * 1e9),
        "qualification_seconds": qualification_seconds, "cleanup_seconds": cleanup_seconds,
        "implementation_sha256": implementation_hash}
    raw = wire(request)
    require(len(raw) <= MAX_REQUEST_BYTES, "owner request exceeds its bound")
    request_path = Path(paths["receipt_path"] + ".request.json")
    create(request_path, raw)
    owner_out = Path(paths["receipt_path"] + ".stdout.log")
    owner_err = Path(paths["receipt_path"] + ".stderr.log")
    create(owner_out, b""); create(owner_err, b"")
    with owner_out.open("ab", buffering=0) as stdout, owner_err.open("ab", buffering=0) as stderr:
        owner = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(implementation),
            "--request", str(request_path), "--request-sha256", sha256(raw).hexdigest()],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True, start_new_session=True)
    bound = qualification_seconds + cleanup_seconds + 2
    try:
        owner.wait(timeout=max(0.001, bound - (time.monotonic_ns() - started) / 1e9))
    except subprocess.TimeoutExpired:
        # Do not kill a subreaper first and then claim its descendants are gone.
        owner.send_signal(signal.SIGTERM)
        try:
            owner.wait(timeout=cleanup_seconds)
        except subprocess.TimeoutExpired:
            return {"schema": SCHEMA, "status": "OWNER_UNCONFIRMED_HOLD", "supervisor_pid": owner.pid,
                    "returncode": None, "cleanup": {"complete": False},
                    "qualification_seconds": qualification_seconds, "cleanup_seconds": cleanup_seconds}
    if not Path(paths["receipt_path"]).is_file():
        return {"schema": SCHEMA, "status": "OWNER_RECEIPT_MISSING_HOLD", "supervisor_returncode": owner.returncode,
                "returncode": None, "cleanup": {"complete": False}}
    receipt_raw = Path(paths["receipt_path"]).read_bytes()
    require(len(receipt_raw) <= 4 * 1024 * 1024, "owner receipt exceeds its bound")
    result = json.loads(receipt_raw)
    require(result["schema"] == SCHEMA and result["request_sha256"] == sha256(raw).hexdigest()
            and result["implementation_sha256"] == implementation_hash
            and result["supervisor_pid"] == owner.pid
            and sha256(implementation.read_bytes()).hexdigest() == implementation_hash,
            "owner receipt or implementation identity changed")
    result["supervisor_returncode"] = owner.returncode
    result["receipt_sha256"] = sha256(receipt_raw).hexdigest()
    if owner.returncode != 0 and result["status"] == "OWNED_PROCESS_COMPLETED":
        result["status"] = "OWNER_EXIT_MISMATCH_HOLD"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args()
    raw = args.request.read_bytes()
    require(len(raw) <= MAX_REQUEST_BYTES and sha256(raw).hexdigest() == args.request_sha256,
            "owner request identity differs")
    request = json.loads(raw)
    require(request["schema"] == SCHEMA and request["implementation_sha256"] == sha256(Path(__file__).read_bytes()).hexdigest(),
            "owner implementation differs")
    result = supervise(request)
    result.update(request_sha256=args.request_sha256, implementation_sha256=request["implementation_sha256"])
    create(request["receipt_path"], wire(result))
    return 0 if result["status"] == "OWNED_PROCESS_COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
