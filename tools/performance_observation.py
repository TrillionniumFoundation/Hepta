"""Observations around a complete driver invocation, never benchmark scores.

The native driver still owns its timed-loop clock. These counters include
startup, warmup, the timed loop, shutdown and output capture. RUSAGE_CHILDREN
can include other children reaped by this process, and cgroup/PSI counters can
include unrelated processes. Neither source establishes a cause or exclusive
CPU access. Missing counters and counter resets are explicit, never zero-filled.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import re
import time

try:
    import resource
except ImportError:  # Diagnostic helper remains importable on other hosts.
    resource = None

from tools.evidence_checks import normalized_errors, require, strict_equal

SCHEMA = "hepta.driver-process-observation.v1"
SCOPE = {
    "wall": "monotonic_ns around the complete capture call; startup, warmup, timed loop, shutdown and output capture",
    "children": "RUSAGE_CHILDREN cumulative differences; may include other children reaped by this process",
    "cpu_time_units": "nanoseconds converted from getrusage timeval seconds; units do not imply nanosecond resolution",
    "linux": "visible cgroup mount-root and host PSI snapshots; can include unrelated processes and are not per-driver counters",
    "native_elapsed_replaced": False,
    "sample_selection_or_threshold_adjustment": False,
    "exclusive_cpu_access_proved": False,
    "measurement_cause_proved": False,
}
RUSAGE_FIELDS = ("user_cpu_ns", "system_cpu_ns", "voluntary_context_switches",
                 "involuntary_context_switches", "minor_page_faults", "major_page_faults")
LINUX_FILES = {
    "visible_cgroup_cpu_stat": "/sys/fs/cgroup/cpu.stat",
    "visible_cgroup_cpu_pressure": "/sys/fs/cgroup/cpu.pressure",
    "host_cpu_pressure": "/proc/pressure/cpu",
}
MAX_COUNTER_BYTES = 16_384


def source_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _error(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None)}


def _children():
    try:
        if resource is None:
            raise OSError("getrusage is unavailable on this platform")
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        counters = dict(zip(RUSAGE_FIELDS, (
            round(usage.ru_utime * 1_000_000_000), round(usage.ru_stime * 1_000_000_000),
            usage.ru_nvcsw, usage.ru_nivcsw, usage.ru_minflt, usage.ru_majflt)))
        if not all(type(value) is int and value >= 0 for value in counters.values()):
            raise ValueError("getrusage returned invalid cumulative counters")
        return {"status": "observed", "counters": counters, "error": None}
    except (OSError, ValueError, OverflowError) as exc:
        return {"status": "unavailable", "counters": None, "error": _error(exc)}


def _parse_linux(name, raw):
    counters = {}
    for line in raw.splitlines():
        values = line.split()
        if name == "visible_cgroup_cpu_stat":
            if len(values) != 2 or not re.fullmatch(r"[A-Za-z0-9_.]+", values[0]) or not values[1].isdigit():
                raise ValueError("Invalid cpu.stat counter")
            key, count = values[0], int(values[1])
        else:
            if not values or values[0] not in {"some", "full"}:
                raise ValueError("Invalid CPU pressure row")
            fields = {}
            for token in values[1:]:
                field, separator, value = token.partition("=")
                if not separator or field in fields:
                    raise ValueError("Invalid CPU pressure fields")
                fields[field] = value
            if set(fields) != {"avg10", "avg60", "avg300", "total"} or not fields["total"].isdigit():
                raise ValueError("Missing CPU pressure fields")
            for field in ("avg10", "avg60", "avg300"):
                value = float(fields[field])
                if not math.isfinite(value) or value < 0:
                    raise ValueError("Invalid CPU pressure average")
            key, count = values[0] + ".total_us", int(fields["total"])
        if key in counters:
            raise ValueError("Duplicate cumulative counter")
        counters[key] = count
    if not counters:
        raise ValueError("Empty kernel counter file")
    return counters


def _linux(name, path):
    result = {"path": path, "status": "unavailable", "raw": None,
              "raw_sha256": None, "counters": None, "error": None}
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_COUNTER_BYTES + 1)
        if len(raw) > MAX_COUNTER_BYTES:
            raise ValueError("Kernel counter file exceeds diagnostic capture bound")
        result["raw"] = raw.decode("ascii")
        result["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        result["counters"] = _parse_linux(name, result["raw"])
        result["status"] = "observed"
    except (OSError, ValueError, UnicodeError) as exc:
        result["error"] = _error(exc)
    return result


def _difference(before, after):
    result = {"before": before, "after": after, "status": "unavailable",
              "delta": None, "decreased_counters": []}
    if before["status"] != "observed" or after["status"] != "observed":
        return result
    left, right = before["counters"], after["counters"]
    if set(left) != set(right):
        result["status"] = "counter_set_changed"
        return result
    decreased = sorted(key for key in left if right[key] < left[key])
    if decreased:
        result.update(status="counter_reset", decreased_counters=decreased)
        return result
    result.update(status="observed", delta={key: right[key] - left[key] for key in left})
    return result


def observe_call(records, command, sample, action):
    """Call action once, preserving a diagnostic row even if it raises.

    Collection reads happen outside the driver. The wall interval encloses
    action only, while cumulative counter snapshots also surround their
    neighbouring observation reads. There are no sleeps, retries, filters or
    decisions based on observations in this function.
    """
    row = {"schema": SCHEMA, "scope": dict(SCOPE), "sample": dict(sample),
           "command": list(map(str, command)), "state": "started"}
    records.append(row)
    children_before = _children()
    linux_before = {name: _linux(name, path) for name, path in LINUX_FILES.items()}
    begin = time.monotonic_ns()
    error = None
    try:
        return action()
    except BaseException as exc:
        error = type(exc).__name__
        raise
    finally:
        end = time.monotonic_ns()
        children_after = _children()
        linux_after = {name: _linux(name, path) for name, path in LINUX_FILES.items()}
        row.update(state="complete", capture_exception=error,
            clock={"start_monotonic_ns": begin, "end_monotonic_ns": end, "wall_ns": end - begin},
            children=_difference(children_before, children_after),
            linux={name: _difference(linux_before[name], linux_after[name]) for name in LINUX_FILES})


def _validate_error(error):
    require(isinstance(error, dict) and set(error) == {"type", "errno"}
            and isinstance(error["type"], str) and error["type"]
            and (error["errno"] is None or type(error["errno"]) is int),
            "Diagnostic availability error is malformed")


def _validate_counter_snapshot(snapshot, name=None):
    expected = {"status", "counters", "error"}
    if name is not None:
        expected |= {"path", "raw", "raw_sha256"}
    require(isinstance(snapshot, dict) and set(snapshot) == expected
            and snapshot["status"] in {"observed", "unavailable"}, "Counter snapshot fields differ")
    if name is not None:
        require(snapshot["path"] == LINUX_FILES[name], "Kernel diagnostic path differs")
        raw = snapshot["raw"]
        if raw is None:
            require(snapshot["raw_sha256"] is None, "Unavailable raw counter digest was fabricated")
        else:
            require(isinstance(raw, str) and len(raw.encode("ascii")) <= MAX_COUNTER_BYTES
                    and snapshot["raw_sha256"] == hashlib.sha256(raw.encode("ascii")).hexdigest(),
                    "Raw kernel counter identity differs")
    if snapshot["status"] == "unavailable":
        require(snapshot["counters"] is None, "Unavailable counters cannot claim measured zeroes")
        _validate_error(snapshot["error"])
        if name is not None and snapshot["raw"] is not None:
            try:
                _parse_linux(name, snapshot["raw"])
            except ValueError as exc:
                require(strict_equal(snapshot["error"], _error(exc)), "Kernel parse-error identity differs")
            else:
                raise ValueError("Readable valid kernel counters cannot be marked unavailable")
        return
    require(snapshot["error"] is None and isinstance(snapshot["counters"], dict)
            and snapshot["counters"] and all(type(value) is int and value >= 0
                                            for value in snapshot["counters"].values()),
            "Cumulative counters must be nonnegative integers")
    if name is None:
        require(set(snapshot["counters"]) == set(RUSAGE_FIELDS), "Child counter inventory differs")
    else:
        require(snapshot["raw"] is not None
                and strict_equal(snapshot["counters"], _parse_linux(name, snapshot["raw"])),
                "Kernel counters differ from retained raw text")


@normalized_errors
def validate_observations(records, expected):
    """Replay complete order, raw identities and arithmetic; execute nothing.

    expected contains sample identity and command only, never a native time.
    Thus diagnostics cannot replace, adjust or select any benchmark result.
    """
    require(isinstance(records, list) and len(records) == len(expected),
            "Complete process observation inventory required")
    previous_end = None
    for index, (row, wanted) in enumerate(zip(records, expected)):
        require(isinstance(row, dict) and set(row) == {"schema", "scope", "sample", "command", "state",
                "capture_exception", "clock", "children", "linux"}
                and row["schema"] == SCHEMA and row["state"] == "complete"
                and row["capture_exception"] is None and strict_equal(row["scope"], SCOPE)
                and strict_equal(row["sample"], wanted["sample"])
                and row["sample"]["sample_index"] == index
                and strict_equal(row["command"], list(map(str, wanted["command"]))),
                "Process observation order, command, capture or scope differs")
        clock = row["clock"]
        require(set(clock) == {"start_monotonic_ns", "end_monotonic_ns", "wall_ns"}
                and all(type(value) is int and value >= 0 for value in clock.values())
                and clock["end_monotonic_ns"] >= clock["start_monotonic_ns"]
                and clock["wall_ns"] == clock["end_monotonic_ns"] - clock["start_monotonic_ns"]
                and (previous_end is None or clock["start_monotonic_ns"] >= previous_end),
                "Process wall interval is malformed or out of order")
        previous_end = clock["end_monotonic_ns"]
        require(set(row["linux"]) == set(LINUX_FILES), "Optional Linux diagnostic inventory changed")
        for name, observation in [(None, row["children"]), *row["linux"].items()]:
            _validate_counter_snapshot(observation["before"], name)
            _validate_counter_snapshot(observation["after"], name)
            require(strict_equal(observation, _difference(observation["before"], observation["after"])),
                    "Counter difference, reset or availability record differs")
