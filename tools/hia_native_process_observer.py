"""Linux-only, measured native-process evidence for HIA full-cost studies.

Never an execution-admission authority, sandbox, whole-program resource proof,
or authentication of supplied one-time costs / reference outputs. Every ELF
is copied into a private directory and checked against its registered SHA-256
before any trial. Output mismatch, crash and timeout retain negative evidence.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

from hepta.hia_bounded_wire import WireBudgetExceeded, checked_utf8_wire
from hepta.hia_full_cost_gate import SCHEMA as COST_SCHEMA, assess_full_cost

SCHEMA = "hepta.hia.native-observation-registration.v1"
REPORT = "hepta.hia.native-observation.v1"
MAX_MANIFEST = 262_144
MAX_BINARY = 64 * 1024 * 1024
MAX_STDIN = 64 * 1024
MAX_INVOCATIONS = 4096
MAX_CAMPAIGN_DEADLINE_MS = 900_000
ARMS = ("baseline", "fixed", "dp", "ndu")
# All arms receive exactly the same non-shell, non-loader-injected environment.
# Custom dynamic-library paths are deliberately not supported in this profile.
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
COST_KEYS = ("toolchain", "dependencies", "controller_build", "candidate_build",
             "calibration", "search", "verification", "measurement",
             "publication", "switch", "rollback")
IDENTITY = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class NativeObservationRejected(ValueError):
    pass


def _reject(message):
    raise NativeObservationRejected("E_HIA_NATIVE_OBSERVER: " + message)


def _shape(value, keys, where):
    if type(value) is not dict or set(value) != set(keys):
        _reject(where + " requires exact fields")


def _int(value, where, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(where + " must be a bounded integer")
    return value


def _digest(value, where):
    if type(value) is not str or DIGEST.fullmatch(value) is None or value == "0" * 64:
        _reject(where + " is not a registered SHA-256")
    return value


def _pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            _reject("duplicate JSON field")
        output[key] = value
    return output


def _parse(raw):
    if type(raw) not in (str, bytes):
        _reject("immutable JSON bytes/text required")
    try:
        wire = raw if type(raw) is bytes else checked_utf8_wire(raw, MAX_MANIFEST)
        if len(wire) > MAX_MANIFEST:
            _reject("registration exceeds byte budget")
        data = json.loads(wire.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: _reject("nonfinite JSON"))
    except WireBudgetExceeded:
        _reject("registration exceeds byte budget")
    except NativeObservationRejected:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise NativeObservationRejected("E_HIA_NATIVE_OBSERVER: invalid JSON") from exc
    return data, sha256(wire).hexdigest()


def _registration(raw):
    data, digest = _parse(raw)
    _shape(data, {"schema", "source_digest", "objective_digest", "hardware_digest",
                  "workload_digest", "candidate_bank_digest", "generation", "trials",
                  "arms", "repetitions", "timeout_ms", "max_output_bytes",
                  "minimum_gain_ppm", "minimum_gain_ns",
                  "maximum_peak_rss_bytes", "maximum_p99_ns"}, "registration")
    if data["schema"] != SCHEMA:
        _reject("unknown registration version")
    for key in ("source_digest", "objective_digest", "hardware_digest",
                "workload_digest", "candidate_bank_digest"):
        _digest(data[key], key)
    _int(data["generation"], "generation", 1, (1 << 32) - 1)
    _int(data["repetitions"], "repetitions", 2, 128)
    _int(data["timeout_ms"], "timeout_ms", 1, 30_000)
    _int(data["max_output_bytes"], "max_output_bytes", 1, 65_536)
    _int(data["minimum_gain_ppm"], "minimum_gain_ppm", 1, 1_000_000)
    _int(data["minimum_gain_ns"], "minimum_gain_ns", 1, 10**17)
    _int(data["maximum_peak_rss_bytes"], "maximum_peak_rss_bytes", 1, 1 << 48)
    _int(data["maximum_p99_ns"], "maximum_p99_ns", 1, 10**17)
    if type(data["trials"]) is not list or not 8 <= len(data["trials"]) <= 128:
        _reject("8..128 registered trials required")
    trials = []
    for row in data["trials"]:
        _shape(row, {"id", "stdin_base64", "input_digest", "expected_result_digest"}, "trial")
        name = row["id"]
        if type(name) is not str or IDENTITY.fullmatch(name) is None:
            _reject("invalid trial identity")
        _digest(row["input_digest"], "trial input")
        _digest(row["expected_result_digest"], "trial reference")
        try:
            if type(row["stdin_base64"]) is not str or len(row["stdin_base64"]) > 90_000:
                _reject("invalid stdin encoding")
            payload = base64.b64decode(row["stdin_base64"], validate=True)
            if base64.b64encode(payload).decode("ascii") != row["stdin_base64"]:
                _reject("noncanonical stdin base64")
        except (ValueError, base64.binascii.Error) as exc:
            raise NativeObservationRejected("E_HIA_NATIVE_OBSERVER: bad stdin base64") from exc
        if len(payload) > MAX_STDIN or sha256(payload).hexdigest() != row["input_digest"]:
            _reject("stdin bytes differ from registered trial")
        trials.append((name, payload, row))
    ids = [r[0] for r in trials]
    if ids != sorted(set(ids)):
        _reject("trials must be uniquely registered in sorted order")
    invocations = len(trials) * data["repetitions"] * len(ARMS)
    if (invocations > MAX_INVOCATIONS
            or invocations * data["timeout_ms"] > MAX_CAMPAIGN_DEADLINE_MS):
        _reject("campaign exceeds total process/deadline budget")
    if type(data["arms"]) is not list or len(data["arms"]) != 4:
        _reject("four matched arms required")
    for index, arm in enumerate(data["arms"]):
        _shape(arm, {"strategy", "binary_path", "binary_digest", "core_digest",
                     "toolchain_digest", "argv", "one_time_ns", "unknown_costs"}, "arm")
        if arm["strategy"] != ARMS[index]:
            _reject("arm order must be baseline, fixed, dp, ndu")
        for key in ("binary_digest", "core_digest", "toolchain_digest"):
            _digest(arm[key], key)
        if (type(arm["binary_path"]) is not str or len(arm["binary_path"]) > 4096
                or not Path(arm["binary_path"]).is_absolute()):
            _reject("an absolute registered ELF path is required")
        if (type(arm["argv"]) is not list or len(arm["argv"]) > 16
                or any(type(v) is not str or len(v) > 1024 or "\0" in v
                       for v in arm["argv"])):
            _reject("invalid fixed process arguments")
        _shape(arm["one_time_ns"], COST_KEYS, "one-time costs")
        for key, value in arm["one_time_ns"].items():
            _int(value, key, 0, 10**17)
        unknown = arm["unknown_costs"]
        if (type(unknown) is not list or len(unknown) > 16
                or any(type(s) is not str or IDENTITY.fullmatch(s) is None for s in unknown)
                or len(unknown) != len(set(unknown))):
            _reject("unknown cost categories must be explicit unique IDs")
    return data, digest, trials


def _frozen_elf(arm, directory):
    path = Path(arm["binary_path"])
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            _reject("symlink or nonregular executable refused")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not 20 <= before.st_size <= MAX_BINARY:
                _reject("unsupported ELF file size/type")
            target = directory / (arm["strategy"] + ".elf")
            digest = sha256()
            with open(target, "xb") as sink:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                    sink.write(chunk)
                    if sink.tell() > MAX_BINARY:
                        _reject("binary grew past frozen size")
                sink.flush()
                os.fsync(sink.fileno())
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                _reject("executable changed during freezing")
            if digest.hexdigest() != arm["binary_digest"]:
                _reject("ELF bytes differ from preregistered digest")
            with open(target, "rb") as frozen:
                if frozen.read(4) != b"\x7fELF":
                    _reject("not an actual Linux ELF executable")
            os.chmod(target, 0o500)
            return str(target), digest.hexdigest()
    except OSError as exc:
        raise NativeObservationRejected("E_HIA_NATIVE_OBSERVER: could not freeze executable") from exc


def _run_once(executable, argv, payload, timeout_ms, max_output_bytes):
    """Use Linux wait4 for this child only; never a cumulative RUSAGE_CHILDREN max."""
    began = time.monotonic_ns()
    proc = None
    timeout = False
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stdin.write(payload)
        stdin.seek(0)

        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        try:
            proc = subprocess.Popen([executable, *argv], stdin=stdin, stdout=stdout, stderr=stderr,
                                    start_new_session=True, close_fds=True,
                                    env=SAFE_ENV, preexec_fn=limits)
            deadline = began + timeout_ms * 1_000_000
            while True:
                pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                if pid == proc.pid:
                    proc.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic_ns() >= deadline:
                    timeout = True
                    os.killpg(proc.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(proc.pid, 0)
                    proc.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.001)
        except BaseException as exc:
            if proc is None and isinstance(exc, (OSError, subprocess.SubprocessError)):
                return {"execution_ns": max(1, time.monotonic_ns() - began),
                        "exit_code": None, "spawn_error": type(exc).__name__,
                        "timed_out": False, "peak_rss_bytes": None,
                        "stdout_bytes": 0, "stderr_bytes": 0,
                        "stdout_digest": sha256(b"").hexdigest(),
                        "stderr_digest": sha256(b"").hexdigest()}
            if proc is not None and proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.wait4(proc.pid, 0)
                except ChildProcessError:
                    pass
                proc.returncode = -signal.SIGKILL
            raise
        # Reap stray process-group descendants where possible. A direct child's
        # rusage does NOT account for grandchildren; no tree-wide claim is made.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        elapsed = time.monotonic_ns() - began
        stdout.seek(0, os.SEEK_END)
        out_bytes = stdout.tell()
        stderr.seek(0, os.SEEK_END)
        err_bytes = stderr.tell()
        stdout.seek(0)
        stderr.seek(0)
        return {"execution_ns": max(1, elapsed), "exit_code": proc.returncode,
                "timed_out": timeout, "peak_rss_bytes": max(1, usage.ru_maxrss * 1024),
                "stdout_bytes": out_bytes, "stderr_bytes": err_bytes,
                "stdout_digest": sha256(stdout.read(max_output_bytes + 1)).hexdigest(),
                "stderr_digest": sha256(stderr.read(max_output_bytes + 1)).hexdigest()}


def observe(raw):
    """Execute a four-arm registration and preserve all negative observations."""
    if sys.platform != "linux" or not hasattr(os, "wait4"):
        _reject("only Linux per-process wait4 observations are qualified")
    data, manifest_digest, trials = _registration(raw)
    observer_identity = sha256((Path(__file__).read_bytes()
        + sys.version.encode() + platform.platform().encode())).hexdigest()
    with tempfile.TemporaryDirectory(prefix="hia-native-observer-") as dirname:
        directory = Path(dirname)
        frozen = []
        for arm in data["arms"]:
            started = time.monotonic_ns()
            executable, binary_digest = _frozen_elf(arm, directory)
            frozen.append((executable, binary_digest, time.monotonic_ns() - started))
        samples = {name: {tid: [] for tid, _, _ in trials} for name in ARMS}
        failures = []
        # Interleave arms on each repetition; do not benchmark the cheapest arm
        # once in a cold state and NDU once in a warmed state.
        for tid, payload, trial in trials:
            for repeat in range(data["repetitions"]):
                for index, arm in enumerate(data["arms"]):
                    sample = _run_once(frozen[index][0], arm["argv"], payload,
                                       data["timeout_ms"], data["max_output_bytes"])
                    sample["repetition"] = repeat
                    sample["valid"] = (not sample["timed_out"] and sample["exit_code"] == 0
                        and sample["stderr_bytes"] == 0
                        and sample["stdout_bytes"] <= data["max_output_bytes"]
                        and sample["stdout_digest"] == trial["expected_result_digest"])
                    samples[arm["strategy"]][tid].append(sample)
                    if not sample["valid"]:
                        failures.append({"strategy": arm["strategy"], "trial_id": tid,
                                         "repetition": repeat, "exit_code": sample["exit_code"],
                                         "timed_out": sample["timed_out"],
                                         "spawn_error": sample.get("spawn_error"),
                                         "stdout_digest": sample["stdout_digest"],
                                         "expected_digest": trial["expected_result_digest"]})
                        # Stop on the first actual failure, but keep the raw
                        # failure receipt. Never silently trim failing samples.
                        break
                if failures:
                    break
            if failures:
                break

        report = {"schema": REPORT, "registration_sha256": manifest_digest,
                  "observer_digest": observer_identity, "host": {
                      "system": platform.system(), "machine": platform.machine(),
                      "release": platform.release()},
                  "frozen_binaries": [{"strategy": a["strategy"], "sha256": row[1],
                                       "freeze_ns": row[2]} for a, row in zip(data["arms"], frozen)],
                  "raw_samples": samples, "failures": failures, "complete": not failures,
                  "authority": "DENY_ALL", "safety_certificate": False,
                  "production_activation_allowed": False,
                  "claims": {"registered_reference_independently_verified": False,
                             "one_time_costs_independently_attested": False,
                             "process_tree_resource_accounting": False,
                             "compiler_refinement_proved": False,
                             "future_performance_proved": False}}
        if failures:
            return report
        arms = []
        for index, arm in enumerate(data["arms"]):
            observations = []
            for tid, _, trial in trials:
                rows = samples[arm["strategy"]][tid]
                elapsed = sorted(row["execution_ns"] for row in rows)
                rank = (99 * len(elapsed) + 99) // 100
                observations.append({
                    "trial_id": tid, "input_digest": trial["input_digest"],
                    "result_digest": trial["expected_result_digest"],
                    "execution_ns": sum(elapsed), "controller_ns": 0,
                    "failed_attempt_ns": 0,
                    "peak_rss_bytes": max(row["peak_rss_bytes"] for row in rows),
                    "p99_ns": elapsed[rank - 1], "completed": True})
            # The observer's actual snapshot overhead is never free.
            costs = dict(arm["one_time_ns"])
            costs["measurement"] += frozen[index][2]
            arms.append({"strategy": arm["strategy"], "core_digest": arm["core_digest"],
                         "artifact_digest": frozen[index][1],
                         "toolchain_digest": arm["toolchain_digest"],
                         "observer_digest": observer_identity,
                         "candidate_bank_digest": data["candidate_bank_digest"],
                         "one_time_ns": costs, "unknown_costs": arm["unknown_costs"],
                         "observations": observations})
        cost_input = {"schema": COST_SCHEMA, "source_digest": data["source_digest"],
                      "objective_digest": data["objective_digest"],
                      "hardware_digest": data["hardware_digest"],
                      "workload_digest": data["workload_digest"],
                      "candidate_bank_digest": data["candidate_bank_digest"],
                      "generation": data["generation"],
                      "registered_trials": [
                          {"id": trial["id"], "input_digest": trial["input_digest"],
                           "expected_result_digest": trial["expected_result_digest"]}
                          for _, _, trial in trials],
                      "minimum_gain_ppm": data["minimum_gain_ppm"],
                      "minimum_gain_ns": data["minimum_gain_ns"],
                      "maximum_peak_rss_bytes": data["maximum_peak_rss_bytes"],
                      "maximum_p99_ns": data["maximum_p99_ns"],
                      "arms": arms}
        # This is arithmetic on actual child observations plus supplied costs,
        # not an authenticated economic or NDU superiority certificate.
        report["full_cost_input"] = cost_input
        report["full_cost_verdict"] = assess_full_cost(json.dumps(
            cost_input, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        return report


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with args.registration.open("rb") as source:
            registration = source.read(MAX_MANIFEST + 1)
        report = observe(registration)
        content = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(args.output, flags, 0o600)
        with os.fdopen(fd, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        print(json.dumps({"report": str(args.output), "complete": report["complete"],
                          "authority": report["authority"]}, sort_keys=True))
        return 0 if report["complete"] else 2
    except (OSError, NativeObservationRejected, ValueError) as exc:
        print("E_HIA_NATIVE_OBSERVER: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
