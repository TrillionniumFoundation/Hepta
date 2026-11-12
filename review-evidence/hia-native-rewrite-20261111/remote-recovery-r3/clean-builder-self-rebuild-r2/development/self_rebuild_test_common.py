"""Mechanical local development subprocess and immutable-file evidence only."""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import resource
import signal
import stat
import struct
import subprocess
import time
import traceback

def digest(raw): return hashlib.sha256(raw).hexdigest()

def identity(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw), "mode": stat.S_IMODE(path.stat().st_mode)}

def unpack(raw):
    assert len(raw) >= 24
    magic, count, reserved = struct.unpack_from("<3Q", raw)
    assert magic == int.from_bytes(b"HIAREL01", "little") and count == 6 and reserved == 0
    at = 24
    files = {}
    for _ in range(count):
        assert at <= len(raw) - 24
        n, mode, size = struct.unpack_from("<3Q", raw, at)
        at += 24
        assert n <= len(raw) - at
        name = raw[at:at + n].decode("ascii")
        at += n
        assert size <= len(raw) - at and name not in files
        files[name] = mode, raw[at:at + size]
        at += size
    assert at == len(raw)
    assert set(files) == {"hia", "hia-release", "hia-build", "compiler.bin", "source-kit.hiabuild", "build.json"}
    return files

class Gate:
    """Each gate records its own full work; no old case counts are inherited."""
    def __init__(self, out, sources, scope, cpu=90, wall=150):
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=False)
        self.start = time.monotonic_ns()
        self.self0 = resource.getrusage(resource.RUSAGE_SELF)
        self.child0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        self.cpu = cpu
        self.wall = wall
        self.primary = None
        self.secondary = []
        self.live = {}
        self.summary = {"schema": "hia-self-rebuild-development-gate-r1", "scope": scope,
                        "status": "INCOMPLETE", "calls": [], "cpu_seconds_strict": cpu,
                        "wall_seconds_strict": wall, "address_bytes": 1 << 30,
                        "activation": False, "cold_qualification": False}
        self.before = [identity(p) for p in sorted(set(map(Path, sources)), key=str)]
        self.write("source-before.json", self.before)
        self.home = self.out / "empty-home"
        self.home.mkdir()
        self.environment = {"PATH": "", "HOME": str(self.home)}
        self.parent_pid = os.getpid()
        signal.signal(signal.SIGALRM, self.alarm)
        self.arm()

    def usage(self):
        s = resource.getrusage(resource.RUSAGE_SELF)
        c = resource.getrusage(resource.RUSAGE_CHILDREN)
        return {"elapsed_ns": time.monotonic_ns() - self.start,
                "aggregate_cpu_seconds": s.ru_utime + s.ru_stime - self.self0.ru_utime - self.self0.ru_stime +
                                         c.ru_utime + c.ru_stime - self.child0.ru_utime - self.child0.ru_stime,
                "self_maxrss_kib": s.ru_maxrss, "children_maxrss_kib": c.ru_maxrss}

    def alarm(self, signum, frame):
        raise TimeoutError("bounded native development gate exceeded its unchanged wall limit")

    def arm(self, call_wall=None):
        remaining = self.wall - (time.monotonic_ns() - self.start) / 1e9
        if remaining <= 0: raise TimeoutError("gate wall limit exhausted")
        signal.setitimer(signal.ITIMER_REAL, remaining if call_wall is None else min(remaining, call_wall))

    def setup(self):
        resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu, self.cpu))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == self.parent_pid
        assert libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0

    def write(self, name, value):
        path = self.out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def fail(self, exc):
        if self.primary is None:
            self.primary = exc
            self.summary["primary"] = {"class": type(exc).__name__, "error": str(exc),
                                       "traceback": traceback.format_exc()}
        else:
            self.secondary.append({"phase": "additional-exception", "class": type(exc).__name__, "error": str(exc)})
        self.summary["status"] = "FAIL"

    def record_secondary(self, phase, exc):
        self.secondary.append({"phase": phase, "class": type(exc).__name__, "error": str(exc)})
        self.summary["status"] = "FAIL"

    def run(self, label, executable, args, *, raw=None, input_path=None, expected=0, wall=20):
        folder = self.out / "calls" / label
        folder.mkdir(parents=True, exist_ok=False)
        if input_path is None:
            input_path = folder / "stdin.raw"
            input_path.write_bytes(b"" if raw is None else raw)
        else:
            assert raw is None
            input_path = Path(input_path)
        executable = Path(executable)
        before_exe, before_input = identity(executable), identity(input_path)
        request = {"executable": before_exe, "argv": list(args), "input": before_input,
                   "environment": self.environment, "wall_seconds": wall,
                   "cpu_seconds_per_process": self.cpu, "address_bytes": 1 << 30}
        self.write("calls/" + label + "/request.json", request)
        proc = None
        child_primary = None
        record = {"label": label, "status": "INCOMPLETE"}
        start = time.monotonic_ns()
        try:
            self.arm(wall)
            with input_path.open("rb") as src, (folder / "stdout.raw").open("xb") as out, (folder / "stderr.raw").open("xb") as err:
                proc = subprocess.Popen([str(executable), *map(str, args)], stdin=src, stdout=out, stderr=err,
                                        env=self.environment, start_new_session=True, preexec_fn=self.setup)
                self.live[proc.pid] = proc
                pid, status, observed = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                self.live.pop(proc.pid)
            record.update(status="RETURNED", returncode=proc.returncode, wait4_status=status,
                          user_seconds=observed.ru_utime, system_seconds=observed.ru_stime, maxrss_kib=observed.ru_maxrss)
        except BaseException as exc:
            child_primary = exc
            record.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if proc is not None and proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    pid, status, observed = os.wait4(proc.pid, 0)
                    proc.returncode = os.waitstatus_to_exitcode(status)
                    self.live.pop(proc.pid)
                    record["termination"] = {"returncode": proc.returncode, "user_seconds": observed.ru_utime,
                                               "system_seconds": observed.ru_stime, "maxrss_kib": observed.ru_maxrss}
                except BaseException as exc: self.record_secondary(label + "/cleanup", exc)
            record["elapsed_ns"] = time.monotonic_ns() - start
            for label2, path, prior in [("executable", executable, before_exe), ("input", input_path, before_input)]:
                try: assert identity(path) == prior
                except BaseException as exc: self.record_secondary(label + "/" + label2 + "-after", exc)
            for name in ("stdout", "stderr"):
                try: record[name] = identity(folder / (name + ".raw"))
                except BaseException as exc: self.record_secondary(label + "/" + name, exc)
            self.summary["calls"].append(record)
            try: self.write("calls/" + label + "/process.json", record)
            except BaseException as exc: self.record_secondary(label + "/process-receipt", exc)
        if child_primary is not None: raise child_primary
        self.arm()
        if expected is not None: assert proc.returncode == expected, record
        return record, (folder / "stdout.raw").read_bytes(), (folder / "stderr.raw").read_bytes()

    def finish(self):
        signal.setitimer(signal.ITIMER_REAL, 0)
        for pid, proc in list(self.live.items()):
            try:
                os.killpg(pid, signal.SIGKILL)
                _, status, observed = os.wait4(pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                self.live.pop(pid)
            except BaseException as exc: self.record_secondary("final-cleanup", exc)
        for prior in self.before:
            try: assert identity(prior["path"]) == prior
            except BaseException as exc: self.record_secondary("source-after:" + prior["path"], exc)
        self.summary["all_original_sources_unchanged"] = not any(x["phase"].startswith("source-after:") for x in self.secondary)
        def budget():
            measured = self.usage()
            assert 0 <= measured["aggregate_cpu_seconds"] < self.cpu, measured
            assert 0 <= measured["elapsed_ns"] < self.wall * 1000000000, measured
            return measured
        try: self.summary["usage_before_output"] = budget()
        except BaseException as exc: self.record_secondary("pre-output-budget", exc)
        self.summary["secondary_errors"] = self.secondary
        if self.primary is not None or self.secondary: self.summary["status"] = "FAIL"
        for phase, action in [
            ("summary", lambda: self.write("summary.json", self.summary)),
            ("stdout", lambda: print(json.dumps({k: v for k, v in self.summary.items() if k not in ("calls", "primary")}, sort_keys=True), flush=True)),
            ("post-output", lambda: self.write("post-output-budget.json", {"status": self.summary["status"], "usage": self.usage()})),
        ]:
            try: action()
            except BaseException as exc: self.record_secondary(phase, exc)
        try: self.summary["usage_after_all_output"] = budget()
        except BaseException as exc: self.record_secondary("post-output-budget", exc)
        if self.primary is not None or self.secondary:
            self.summary["status"] = "FAIL"
            self.summary["secondary_errors"] = self.secondary
            try: self.write("summary.json", self.summary)
            except BaseException as exc: self.record_secondary("fail-summary-rewrite", exc)
            try: self.write("finalization-failure.json", {"primary": self.summary.get("primary"), "secondary": self.secondary, "usage": self.usage()})
            except BaseException: pass
        if self.primary is not None: raise self.primary
        assert not self.secondary, self.secondary
        assert self.summary["status"] == "PASS"
        budget()
