"""Finite paired native observations for an optional NDU compiler search.

This instrument grants no selection or release authority and applies no speedup
threshold. It preserves all attempts, including slow/noisy or failed samples.
Only a Linux x86-64 (usize, usize, usize, usize) -> u8 entry is measured. Both
verified programs use the existing LLVM compiler; one dlopen C driver times the
entire loop. Python, compilation, loading and validation are outside that loop
but their paid wall time is retained for the caller's amortization decision.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.hia_program import VerifiedProgram, execute_program, verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.native_tool_identity import digest_executable


SCHEMA = "hepta.hia.ndu-native-pair.v1"
MAX_CASES = 64
MAX_CALLS = 100_000_000
DRIVER_SOURCE = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

typedef uint8_t (*entry_fn)(size_t, size_t, size_t, size_t);
typedef struct { size_t a[4]; uint8_t expected; } case_row;
_Static_assert(sizeof(size_t) == 8, "This profile requires 64-bit size_t");
_Static_assert(sizeof(entry_fn) == sizeof(void *), "POSIX dlsym representation");

static int fail(const char *code) {
    printf("{\"kind\":\"failure\",\"code\":\"%s\"}\n", code);
    return 90;
}
static int number(const char *text, uint64_t *out) {
    if (!*text || *text < '0' || *text > '9') return 0;
    char *end = NULL; errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end) return 0;
    *out = (uint64_t)value; return 1;
}
static int stamp(clockid_t clock_id, uint64_t *out) {
    struct timespec value;
    if (clock_gettime(clock_id, &value)) return 0;
    *out = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return 1;
}
static uint64_t run_loop(entry_fn fn, const case_row *rows, size_t count, uint64_t iterations) {
    uint64_t checksum = 0;
    for (uint64_t repeat = 0; repeat < iterations; ++repeat)
        for (size_t i = 0; i < count; ++i)
            checksum += fn(rows[i].a[0], rows[i].a[1], rows[i].a[2], rows[i].a[3]);
    return checksum;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 6) return fail("arguments");
    uint64_t samples, iterations;
    if (!number(argv[4], &samples) || samples < 15 || samples > 63 || !(samples & 1)
        || !number(argv[5], &iterations) || !iterations || iterations > 1000000)
        return fail("budget");
    struct rlimit no_core = {0, 0};
    struct rlimit address_space = {UINT64_C(268435456), UINT64_C(268435456)};
    struct rlimit cpu = {61, 61};
    if (setrlimit(RLIMIT_CORE, &no_core) || setrlimit(RLIMIT_AS, &address_space)
        || setrlimit(RLIMIT_CPU, &cpu)) return fail("resource_limit");
    struct timespec wall_resolution, cpu_resolution;
    if (clock_getres(CLOCK_MONOTONIC, &wall_resolution)
        || clock_getres(CLOCK_PROCESS_CPUTIME_ID, &cpu_resolution)) return fail("clock_resolution");
    printf("{\"kind\":\"clocks\",\"monotonic_resolution_ns\":%" PRIu64 ",\"process_cpu_resolution_ns\":%" PRIu64 "}\n",
           (uint64_t)wall_resolution.tv_sec * UINT64_C(1000000000) + (uint64_t)wall_resolution.tv_nsec,
           (uint64_t)cpu_resolution.tv_sec * UINT64_C(1000000000) + (uint64_t)cpu_resolution.tv_nsec);
    size_t count = 0;
    if (scanf("%zu", &count) != 1 || !count || count > 64
        || 2 * samples * iterations * count > UINT64_C(100000000)) return fail("case_count");
    case_row rows[64]; uint64_t case_sum = 0;
    for (size_t i = 0; i < count; ++i) {
        unsigned expected;
        if (scanf("%zu %zu %zu %zu %u", &rows[i].a[0], &rows[i].a[1], &rows[i].a[2],
                  &rows[i].a[3], &expected) != 5 || expected > 255) return fail("case_input");
        rows[i].expected = (uint8_t)expected; case_sum += expected;
    }
    char extra;
    if (scanf(" %c", &extra) != EOF) return fail("extra_input");
    void *handles[2]; entry_fn entries[2];
    const char *names[2] = {"baseline", "candidate"};
    for (size_t role = 0; role < 2; ++role) {
        handles[role] = dlopen(argv[role + 1], RTLD_NOW | RTLD_LOCAL);
        if (!handles[role]) { fprintf(stderr, "%s\n", dlerror()); return fail("dlopen"); }
        dlerror(); void *symbol = dlsym(handles[role], argv[3]);
        const char *error = dlerror();
        if (error || !symbol) { if (error) fprintf(stderr, "%s\n", error); return fail("dlsym"); }
        memcpy(&entries[role], &symbol, sizeof(symbol));
    }
    /* A complete untimed correctness sweep also warms each entry once per case. */
    for (size_t i = 0; i < count; ++i)
        for (size_t role = 0; role < 2; ++role) {
            unsigned actual = entries[role](rows[i].a[0], rows[i].a[1], rows[i].a[2], rows[i].a[3]);
            printf("{\"kind\":\"case\",\"case\":%zu,\"backend\":\"%s\",\"actual\":%u,\"expected\":%u}\n",
                   i, names[role], actual, (unsigned)rows[i].expected);
            if (actual != rows[i].expected) return fail("native_case_mismatch");
        }
    for (uint64_t pair = 0; pair < samples; ++pair)
        for (unsigned position = 0; position < 2; ++position) {
            unsigned role = (unsigned)((pair & 1) ^ position);
            uint64_t wall_start, wall_end, cpu_start, cpu_end;
            if (!stamp(CLOCK_PROCESS_CPUTIME_ID, &cpu_start) || !stamp(CLOCK_MONOTONIC, &wall_start))
                return fail("clock_start");
            uint64_t checksum = run_loop(entries[role], rows, count, iterations);
            if (!stamp(CLOCK_MONOTONIC, &wall_end) || !stamp(CLOCK_PROCESS_CPUTIME_ID, &cpu_end))
                return fail("clock_end");
            uint64_t expected = case_sum * iterations;
            printf("{\"kind\":\"sample\",\"pair\":%" PRIu64 ",\"position\":%u,\"backend\":\"%s\","
                   "\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ","
                   "\"expected_checksum\":%" PRIu64 "}\n", pair, position, names[role], wall_end-wall_start,
                   cpu_end-cpu_start, checksum, expected);
            if (wall_end < wall_start || cpu_end < cpu_start) return fail("clock_reversal");
            if (checksum != expected) return fail("native_checksum_mismatch");
        }
    if (dlclose(handles[0]) || dlclose(handles[1])) return fail("dlclose");
    return 0;
}
'''


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(value, message):
    if not value:
        raise ValueError("E_HIA_NDU_MEASURE: " + message)


def _requested_bound(value):
    # Invalid API requests must still produce bounded, strict-JSON diagnostics;
    # do not embed NaN or arbitrary objects in the returned protocol record.
    if type(value) is int and -1_000_000_000 <= value <= 1_000_000_000:
        return value
    return {"invalid_type_or_bound": type(value).__name__}


def _timed(report, key, operation):
    started = time.perf_counter_ns()
    try:
        return operation()
    finally:
        report["costs"][key] += time.perf_counter_ns() - started


def _process(report, stage, argv, directory, *, stdin=None, timeout=30):
    row = {"stage": stage, "argv": list(map(str, argv)), "cwd": str(directory),
           "timeout_seconds": timeout, "stdout_limit": 1_000_000, "stderr_limit": 65_536}
    if stdin is not None:
        row.update(stdin=stdin, stdin_sha256=_sha(stdin.encode()))
    report["processes"].append(row)
    started = time.perf_counter_ns()
    try:
        result = run_bounded(row["argv"], cwd=directory, input_text=stdin, timeout=timeout,
                             stdout_limit=row["stdout_limit"], stderr_limit=row["stderr_limit"])
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except CaptureRejected as error:
        row.update(capture_error=error.code, error=str(error), returncode=None, stdout="", stderr="")
        if error.capture is not None:
            capture = error.capture
            row.update(returncode=capture.returncode, stdout=capture.stdout.decode("utf-8", "replace"),
                       stderr=capture.stderr.decode("utf-8", "replace"),
                       stdout_base64=base64.b64encode(capture.stdout).decode("ascii"),
                       stderr_base64=base64.b64encode(capture.stderr).decode("ascii"),
                       stdout_total_bytes=capture.stdout_total_bytes, stderr_total_bytes=capture.stderr_total_bytes)
    finally:
        row["wall_ns"] = time.perf_counter_ns() - started
    return row


def _request(baseline, candidate, entry, cases, samples, iterations, timeout):
    _require(isinstance(baseline, VerifiedProgram) and isinstance(candidate, VerifiedProgram),
             "both inputs must be independently reverifiable VerifiedProgram values")
    _require(type(samples) is int and 15 <= samples <= 63 and samples % 2 == 1,
             "samples must be an odd integer between 15 and 63")
    _require(type(iterations) is int and 1 <= iterations <= 1_000_000,
             "iterations must be an integer between 1 and 1000000")
    _require(type(timeout) is int and 1 <= timeout <= 60, "timeout must be integer seconds in [1,60]")
    _require(type(cases) is list and 1 <= len(cases) <= MAX_CASES, "require 1..64 explicit cases")
    _require(all(type(row) is list and len(row) == 4 and
                 all(type(value) is int and 0 <= value < 1 << 64 for value in row) for row in cases),
             "each case must contain exactly four unsigned 64-bit integers")
    _require(2 * samples * iterations * len(cases) <= MAX_CALLS, "total native call budget exceeded")
    _require(type(entry) is str, "entry must name one public scalar function")
    checked = [verify_program(value) for value in (baseline, candidate)]
    for program in checked:
        _require(entry in program.scalar_entrypoints, "entry is not a public scalar function")
        function = next(fn for fn in program.as_dict()["functions"] if fn["name"] == entry)
        _require([p["type"] for p in function["params"]] == ["usize"] * 4 and function["returns"] == ["u8"],
                 "only (usize,usize,usize,usize)->u8 is admitted")
    return checked, [list(row) for row in cases]


def _observe_interpreters(report, programs, entry, cases):
    expected = []
    for index, arguments in enumerate(cases):
        observed = {"case": index, "arguments": arguments}
        report["correctness"]["interpreter_cases"].append(observed)
        for role, program in zip(("baseline", "candidate"), programs):
            result = execute_program(program, entry, arguments, max_steps=100_000, max_heap_bytes=1_048_576)
            observed[role] = result
            _require(result["status"] == "returned" and type(result["result"]) is int
                     and 0 <= result["result"] <= 255, "interpreter did not return a byte")
            resources = result["resources"]
            _require(resources["live_owners"] == 0 and resources["live_local_loans"] == 0,
                     "interpreter left a live owner or local loan")
        _require(observed["baseline"]["result"] == observed["candidate"]["result"],
                 "candidate differs from baseline on an explicit input")
        expected.append(observed["baseline"]["result"])
    return expected


def _events(report, row):
    """Retain completed events on failure, including an incomplete final pair."""
    events, pairs = [], {}
    for line in row.get("stdout", "").splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            event = {"kind": "unparsed", "raw": line}
        events.append(event)
        if isinstance(event, dict) and event.get("kind") == "sample":
            pair, role = event.get("pair"), event.get("backend")
            if type(pair) is int and role in ("baseline", "candidate"):
                record = pairs.setdefault(pair, {"pair": pair, "order": []})
                record["order"].append(role)
                record[role + "_ns"] = event.get("elapsed_ns")
                record[role + "_cpu_ns"] = event.get("process_cpu_ns")
                record[role + "_checksum"] = event.get("checksum")
    report["raw_events"] = events
    report["raw_samples"] = [pairs[key] for key in sorted(pairs)]
    report["correctness"]["native_cases"] = [item for item in events if isinstance(item, dict) and item.get("kind") == "case"]
    clocks = [item for item in events if isinstance(item, dict) and item.get("kind") == "clocks"]
    if len(clocks) == 1:
        report["clocks"] = clocks[0]


def _summarize(report, expected, samples, iterations):
    events = report["raw_events"]
    native_cases = report["correctness"]["native_cases"]
    clocks = report.get("clocks", {})
    _require(events and events[0] == clocks and all(type(clocks.get(key)) is int and clocks[key] > 0
             for key in ("monotonic_resolution_ns", "process_cpu_resolution_ns")), "missing native clock resolutions")
    required_cases = [(i, role) for i in range(len(expected)) for role in ("baseline", "candidate")]
    _require([(r.get("case"), r.get("backend")) for r in native_cases] == required_cases,
             "native correctness inventory is incomplete or out of order")
    _require(all(r.get("actual") == r.get("expected") == expected[r["case"]] for r in native_cases),
             "per-case native result differs from interpreter")
    raw = [row for row in events if isinstance(row, dict) and row.get("kind") == "sample"]
    _require(len(events) == 1 + len(required_cases) + 2 * samples and len(raw) == 2 * samples,
             "sample inventory contains missing, duplicated, malformed or failed rows")
    expected_checksum = iterations * sum(expected)
    for offset, row in enumerate(raw):
        pair, position = divmod(offset, 2)
        role = ("baseline", "candidate")[(pair % 2) ^ position]
        _require((row.get("pair"), row.get("position"), row.get("backend")) == (pair, position, role),
                 "native paired ordering differs from the fixed schedule")
        _require(row.get("checksum") == row.get("expected_checksum") == expected_checksum,
                 "timed checksum differs from explicit correctness outputs")
        _require(type(row.get("elapsed_ns")) is int and row["elapsed_ns"] > 0
                 and type(row.get("process_cpu_ns")) is int and row["process_cpu_ns"] >= 0,
                 "missing or invalid native clock observations")
    result = {}
    for role in ("baseline", "candidate"):
        values = [row[role + "_ns"] for row in report["raw_samples"]]
        median = statistics.median(values)
        result[role + "_median_ns"] = median
        result[role + "_mad_ns"] = statistics.median(abs(value - median) for value in values)
        result[role + "_median_ns_per_call"] = median / report["counts"]["calls_per_sample"]
    saving = [row["baseline_ns"] - row["candidate_ns"] for row in report["raw_samples"]]
    median = statistics.median(saving)
    result["paired_saving_median_ns"] = median
    result["paired_saving_mad_ns"] = statistics.median(abs(value - median) for value in saving)
    result["paired_saving_median_ns_per_call"] = median / report["counts"]["calls_per_sample"]
    result["samples_excluded"] = 0
    result["process_cpu_zero_increment_samples"] = sum(row["process_cpu_ns"] == 0 for row in raw)
    report["summary"] = result
    report["correctness"]["finite_cases_agree"] = True


def measure_pair(baseline: VerifiedProgram, candidate: VerifiedProgram, entry: str,
                 cases: list[list[int]], *, clang="clang", samples=31,
                 iterations=10_000, timeout=30) -> dict:
    """Measure once; the caller decides whether any paid optimization is useful.

    ``iterations`` repeats the complete case list, so calls_per_sample is
    iterations * len(cases), separately for each backend. Compile costs include
    emit_program_llvm and compile_program_llvm's re-verification, compilation,
    binary inspection and publication. MADs are descriptive, not confidence
    bounds. A false ``ok`` preserves all observations but cannot justify use.
    """
    started = time.perf_counter_ns()
    report = {"schema": SCHEMA, "ok": False, "status": "measurement_failed",
              "scope": "finite Linux x86-64 byte-return microbenchmark; not production efficacy",
              "protocol": {"samples": _requested_bound(samples), "iterations": _requested_bound(iterations), "ordering": "baseline,candidate on even pair; candidate,baseline on odd pair",
                           "warmup": "one untimed correctness call per case and backend",
                           "timed_boundary": "C loop including indirect calls, allocator work, case iteration and checksum; no Python, compile or dlopen",
                           "compile_boundary": "LLVM emission plus compiler re-verification, tool identity, compilation, inspection and publication",
                           "native_timeout_seconds": _requested_bound(timeout), "address_space_limit_bytes": 268435456,
                           "cpu_clock_usage": "informational; zero increments are retained, not evidence of zero CPU cost; wall time is the measured objective",
                           "sample_trimming": False, "adaptive_repetition": False},
              "counts": {}, "correctness": {"finite_cases_agree": False, "interpreter_cases": [], "native_cases": []},
              "raw_events": [], "raw_samples": [], "summary": None, "native": {}, "processes": [],
              "reproduction": {"driver_source": DRIVER_SOURCE, "driver_source_sha256": _sha(DRIVER_SOURCE.encode())},
              "costs": {key: 0 for key in ("validation_ns", "baseline_compile_ns", "candidate_compile_ns", "driver_compile_ns", "measurement_ns", "total_ns")},
              "diagnostics": [], "claims": {"performance_acceptance_decided": False, "selection_authority": False,
                  "backend_refinement_proved": False, "whole_program_equivalence_proved": False,
                  "production_gain_proved": False, "binary_artifacts_retained": False},
              "host": {"system": platform.system(), "machine": platform.machine(), "exclusive_cpu_ownership": False}}
    native_row = None
    try:
        programs, frozen_cases = _timed(report, "validation_ns", lambda: _request(
            baseline, candidate, entry, cases, samples, iterations, timeout))
        report["input"] = {"entry": entry, "cases": frozen_cases, "baseline_sha256": programs[0].sha256,
                           "candidate_sha256": programs[1].sha256}
        report["counts"] = {"cases": len(frozen_cases), "paired_samples": samples,
                            "calls_per_sample": iterations * len(frozen_cases),
                            "timed_calls_total": 2 * samples * iterations * len(frozen_cases),
                            "untimed_correctness_calls": 2 * len(frozen_cases)}
        expected = _timed(report, "validation_ns", lambda: _observe_interpreters(report, programs, entry, frozen_cases))
        with tempfile.TemporaryDirectory(prefix="hepta-ndu-pair-") as temporary:
            directory = Path(temporary)
            libraries = []
            for role, program in zip(("baseline", "candidate"), programs):
                output = directory / (role + ".so")
                libraries.append(output)
                def compile_one(role=role, program=program, output=output):
                    ir = emit_program_llvm(program)
                    report["reproduction"][role] = {"canonical_core": program.canonical_json,
                        "structured_input": program.structured_bytes.decode() if program.structured_bytes is not None else None,
                        "llvm_ir": ir.text, "llvm_ir_sha256": ir.sha256}
                    report["native"][role] = compile_program_llvm(ir, program=program, output=output, clang=clang, kind="shared")
                _timed(report, role + "_compile_ns", compile_one)
            tools = [report["native"][role]["toolchain"] for role in ("baseline", "candidate")]
            _require(tools[0] == tools[1], "baseline and candidate used different compiler identities")
            tool = tools[0]
            report["toolchain"] = tool
            driver_source, driver = directory / "driver.c", directory / "driver"
            driver_source.write_text(DRIVER_SOURCE, encoding="ascii")
            command = [tool["path"], "-std=c11", "-O3", "-fno-lto", "-Wall", "-Wextra", "-Werror",
                       str(driver_source), "-ldl", "-o", str(driver)]
            build = _timed(report, "driver_compile_ns", lambda: _process(report, "driver_compile", command, directory, timeout=60))
            _require(build.get("returncode") == 0 and "capture_error" not in build, "driver compilation failed")
            report["driver"] = {"source_sha256": _sha(DRIVER_SOURCE.encode()), "artifact_sha256": digest_executable(driver),
                                "artifact_bytes": driver.stat().st_size, "argv": command, "toolchain": tool}
            for role, path in zip(("baseline", "candidate"), libraries):
                _require(_sha(path.read_bytes()) == report["native"][role]["artifact_sha256"], "native bytes changed before measurement")
            _require(digest_executable(tool["path"]) == tool["sha256"], "compiler changed before driver execution")
            payload = str(len(frozen_cases)) + "\n" + "".join(
                " ".join(map(str, [*row, value])) + "\n" for row, value in zip(frozen_cases, expected))
            native_row = _timed(report, "measurement_ns", lambda: _process(report, "native_measurement",
                [str(driver), *map(str, libraries), entry, str(samples), str(iterations)], directory, stdin=payload, timeout=timeout))
            _events(report, native_row)
            _require(native_row.get("returncode") == 0 and "capture_error" not in native_row, "native driver failed or exceeded its bound")
            _summarize(report, expected, samples, iterations)
            for role, path in zip(("baseline", "candidate"), libraries):
                _require(_sha(path.read_bytes()) == report["native"][role]["artifact_sha256"], "native bytes changed during measurement")
            _require(digest_executable(driver) == report["driver"]["artifact_sha256"], "driver changed during measurement")
            _require(digest_executable(tool["path"]) == tool["sha256"], "compiler changed during measurement")
        report.update(ok=True, status="finite_pair_measured_no_selection_authority")
    except Exception as error:
        report["diagnostics"].append({"type": type(error).__name__, "code": getattr(error, "code", None), "message": str(error)})
    finally:
        report["costs"]["total_ns"] = time.perf_counter_ns() - started
    return report
