"""Closed two-u32 guarded-specialization qualification, without publication authority.

This research adapter composes the existing Core verifier, first-trap translation
check, selected LLVM check, compiler and finite native differential. It is not an
extension of PreparedArtifactSession or a general dynamic loader. Only internally
built, byte-bound images and the fixed batch driver are executed, in children.
"""
from __future__ import annotations

from contextlib import contextmanager
from base64 import b64encode
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import time

from .clang_capture import run_bounded
from .elf_shared_abi import inspect_owned_shared_elf
from .hia_adaptive import _NativeRelease
from .hia_native_differential import _pin_native_artifact, compare_verified_hia_program
from .hia_program import SCHEMA, verify_program
from .hia_program_llvm import compile_program_llvm, emit_program_llvm
from .hia_program_runtime import HIAProgramTrap, execute_program
from .hia_scalar_lowering_check import verify_scalar_lowering
from .hia_specialization import propose_guarded_specializations
from .hia_translation_validation import QUALIFIED_CORE_SCHEMAS, _OutsideProfile, _profile, validate_translation
from .native_tool_identity import digest_executable

PROFILE = "hepta.hia.guarded-u32-batch.v1"
PROTOCOL_SHA256 = "1b4d1818d7fa9aff079bf7b27220d9f4df2bc0668a52b827e8a0adbd1b8cebbf"
PROTOCOL_PATH = Path(__file__).resolve().parents[1] / "experiments/hia_guarded_opportunity/protocol_v1.json"
MAX_IMAGE_BYTES = 1024 * 1024
MAX_ITERATIONS = 1_000_000
MAX_SEED = (1 << 32) - 1
SOLVER_TIMEOUT_MS = 10_000
MASK32 = MAX_SEED
MASK64 = (1 << 64) - 1

DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
typedef uint32_t (*kernel_t)(uint32_t, uint32_t);
static uint64_t now(clockid_t kind) {
    struct timespec t;
    if (clock_gettime(kind, &t)) exit(81);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint32_t step(uint32_t x) { return x * UINT32_C(1664525) + UINT32_C(1013904223); }
static uint64_t integer(const char *text) {
    if (!*text) exit(82);
    uint64_t out = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || out > UINT64_C(429496729)) exit(82);
        out = out * 10 + (uint64_t)(*text - '0');
    }
    if (out > UINT32_MAX) exit(82);
    return out;
}
static void limit(int resource, rlim_t value) {
    struct rlimit l = {value, value};
    if (setrlimit(resource, &l)) exit(83);
}
static uint64_t batch(kernel_t kernel, uint32_t calls, uint32_t seed, uint32_t hot) {
    uint64_t checksum = 0;
    uint32_t x = seed;
    for (uint32_t i = 0; i < calls; ++i) {
        x = step(x);
        uint32_t denominator = i % 10 < 9 ? hot : (x >> 16) % 251 + 1;
        checksum += kernel(x, denominator);
    }
    return checksum;
}
int main(int argc, char **argv) {
    if (argc != 6) return 84;
    uint32_t calls = integer(argv[2]), warmup = integer(argv[3]);
    uint32_t seed = integer(argv[4]), hot = integer(argv[5]);
    if (!calls || calls > 1000000 || warmup > 100000 || (hot != 8 && hot != 10)) return 85;
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_CPU, 3);
    limit(RLIMIT_FSIZE, 4096);
    limit(RLIMIT_AS, (rlim_t)1024 * 1024 * 1024);
    uint64_t loading = now(CLOCK_MONOTONIC);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) return 86;
    kernel_t kernel = (kernel_t)dlsym(library, "calculate");
    if (!kernel) return 87;
    uint64_t load_ns = now(CLOCK_MONOTONIC) - loading;
    volatile uint64_t warming = batch(kernel, warmup, seed, hot);
    (void)warming;
    uint64_t cpu = now(CLOCK_PROCESS_CPUTIME_ID), start = now(CLOCK_MONOTONIC);
    uint64_t checksum = batch(kernel, calls, seed, hot);
    uint64_t elapsed_ns = now(CLOCK_MONOTONIC) - start;
    uint64_t cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    uint64_t closing = now(CLOCK_MONOTONIC);
    if (dlclose(library)) return 88;
    uint64_t close_ns = now(CLOCK_MONOTONIC) - closing;
    printf("{\"calls\":%" PRIu32 ",\"checksum\":%" PRIu64 ",\"close_ns\":%" PRIu64
           ",\"cpu_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"hot\":%" PRIu32
           ",\"load_ns\":%" PRIu64 ",\"seed\":%" PRIu32 "}\n",
           calls, checksum, close_ns, cpu_ns, elapsed_ns, hot, load_ns, seed);
    return 0;
}
'''


class GuardedBatchRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def load_protocol():
    data = PROTOCOL_PATH.read_bytes()
    _require(sha256(data).hexdigest() == PROTOCOL_SHA256, "registered protocol bytes changed")
    return json.loads(data)


def workload():
    params = [{"name": "x", "type": "u32"}, {"name": "denominator", "type": "u32"}]
    def op(name, args, out):
        return {"op": name, "args": args, "out": [{"name": out, "type": "u32"}], "attrs": {}}
    return {"schema": SCHEMA, "module": "guarded_u32", "functions": [{
        "name": "calculate", "params": params, "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": [{"id": "entry", "params": params,
        "ops": [op("int.div.checked", ["x", "denominator"], "quotient"),
                op("int.rem.checked", ["x", "denominator"], "remainder"),
                op("int.add.wrap", ["quotient", "remainder"], "answer")],
        "term": {"op": "ret", "values": ["answer"]}}]}]}


def checked_profile(document):
    checked = verify_program(document)
    data = checked.as_dict()
    _require(checked.structured_bytes is None and data["schema"] in QUALIFIED_CORE_SCHEMAS
             and len(data["functions"]) == 1, "one explicit primitive v1-v7 function required")
    fn = data["functions"][0]
    _require(fn["name"] == "calculate" and checked.scalar_entrypoints == frozenset({"calculate"})
             and [p["type"] for p in fn["params"]] == ["u32", "u32"]
             and fn["returns"] == ["u32"] and fn["effects"] == ["trap"],
             "only calculate(u32,u32)->u32 with the explicit trap effect is admitted")
    try:
        _profile(fn)
    except _OutsideProfile as error:
        raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: " + str(error)) from error
    _require(len(fn["blocks"]) <= 8 and sum(len(b["ops"]) for b in fn["blocks"]) <= 32,
             "guarded batch CFG budget exceeded")
    return checked


def candidates():
    baseline = workload()
    proposals = propose_guarded_specializations(baseline, function="calculate", assumptions=[
        {"parameter": "denominator", "value": 8}, {"parameter": "denominator", "value": 10}])
    return {"baseline": baseline, "guard_denominator_8": proposals[0]["program"],
            "guard_denominator_10": proposals[1]["program"]}


def formula(x, denominator):
    _require(type(x) is int and 0 <= x <= MASK32 and type(denominator) is int
             and 0 <= denominator <= MASK32, "exact u32 arguments required")
    if denominator == 0:
        return {"status": "trapped", "code": "division_by_zero"}
    return {"status": "returned", "values": [((x // denominator) + (x % denominator)) & MASK32]}


def expected_checksum(calls, seed, hot):
    validate_batch(calls, 0, seed, hot)
    x, total = seed, 0
    for index in range(calls):
        x = (x * 1664525 + 1013904223) & MASK32
        denominator = hot if index % 10 < 9 else (x >> 16) % 251 + 1
        total = (total + (((x // denominator) + (x % denominator)) & MASK32)) & MASK64
    return total


def validate_batch(calls, warmup, seed, hot):
    _require(type(calls) is int and 1 <= calls <= MAX_ITERATIONS
             and type(warmup) is int and 0 <= warmup <= 100_000
             and type(seed) is int and 0 <= seed <= MAX_SEED
             and type(hot) is int and hot in {8, 10}, "batch arguments outside the closed profile")


def export_code_identity(data):
    """Extract actual exported function bytes, excluding ELF metadata/source names.

    The checked ELF inspector runs first. Code identity is not an instruction
    semantics proof: the trusted native backend and loader remain explicit.
    """
    inspect_owned_shared_elf(data, ("calculate",))
    u = lambda at, size: int.from_bytes(data[at:at + size], "little")
    shoff, count = u(40, 8), u(60, 2)
    sections = [shoff + i * 64 for i in range(count)]
    dynamic = [at for at in sections if u(at + 4, 4) == 11]
    _require(len(dynamic) == 1, "ambiguous dynamic symbol table")
    table = dynamic[0]
    string_index = u(table + 40, 4)
    _require(string_index < count, "invalid symbol string section")
    strings = sections[string_index]
    string_offset, string_size = u(strings + 24, 8), u(strings + 32, 8)
    found = []
    start, size = u(table + 24, 8), u(table + 32, 8)
    for at in range(start, start + size, 24):
        name = u(at, 4)
        _require(name < string_size, "invalid symbol name")
        end = data.find(b"\0", string_offset + name, string_offset + string_size)
        _require(end >= 0, "unterminated symbol name")
        if data[string_offset + name:end] == b"calculate":
            found.append((u(at + 8, 8), u(at + 16, 8)))
    _require(len(found) == 1 and 0 < found[0][1] <= 65536, "bounded exported code required")
    address, length = found[0]
    phoff, nsegments = u(32, 8), u(56, 2)
    matches = []
    for i in range(nsegments):
        at = phoff + 56 * i
        vaddr, filesz = u(at + 16, 8), u(at + 32, 8)
        if u(at, 4) == 1 and u(at + 4, 4) & 1 and vaddr <= address and address + length <= vaddr + filesz:
            offset = u(at + 8, 8) + address - vaddr
            matches.append(data[offset:offset + length])
    _require(len(matches) == 1 and len(matches[0]) == length, "export code is not uniquely executable-mapped")
    return {"symbol": "calculate", "bytes": length, "sha256": sha256(matches[0]).hexdigest(),
            "hex": matches[0].hex(), "machine_code_semantics_proved": False}


EDGE_CASES = [[0, 1], [0, 8], [1, 10], [7, 8], [8, 8], [9, 8], [9, 10],
              [MASK32, 1], [MASK32, 8], [MASK32, 10], [MASK32, MASK32], [MASK32, 3],
              [0, 0], [MASK32, 0]]


def build_candidate(document, output, *, clang, report):
    """Recompute both proofs on exact bytes, then compile; never import a receipt."""
    started = time.monotonic_ns()
    checked = checked_profile(document)
    baseline = checked_profile(workload())
    report["core_sha256"] = checked.sha256
    report["abi"] = {"function": "calculate", "params": ["u32", "u32"], "returns": ["u32"],
                     "calling_convention": "C-Linux-x86_64", "persistent_state": []}
    try:
        proof_start = time.monotonic_ns()
        proof = validate_translation(baseline.as_dict(), checked.as_dict(), function="calculate", timeout_ms=SOLVER_TIMEOUT_MS)
        report["translation"] = proof
        report["translation_wall_ns"] = time.monotonic_ns() - proof_start
        _require(proof["status"] == "proved" and proof["before_sha256"] == baseline.sha256
                 and proof["after_sha256"] == checked.sha256, "all-input first-trap proof did not pass")
        llvm = emit_program_llvm(checked)
        proof_start = time.monotonic_ns()
        lowered = verify_scalar_lowering(checked.as_dict(), function="calculate", llvm_text=llvm.text, timeout_ms=SOLVER_TIMEOUT_MS)
        report["lowering"] = lowered
        report["lowering_wall_ns"] = time.monotonic_ns() - proof_start
        _require(lowered["status"] == "verified" and lowered["core_sha256"] == checked.sha256
                 and lowered["llvm_sha256"] == llvm.sha256, "selected LLVM proof did not pass")
        (Path(output).with_suffix(".ll")).write_text(llvm.text, encoding="ascii")
        compile_start = time.monotonic_ns()
        built = compile_program_llvm(llvm, program=checked, output=output, clang=clang)
        report["compilation"] = built
        report["compile_wall_ns"] = time.monotonic_ns() - compile_start
        _require(built["core_sha256"] == checked.sha256 and built["llvm_ir_sha256"] == llvm.sha256,
                 "compiled artifact binding differs")
        for args in EDGE_CASES:
            try:
                observation = execute_program(checked, "calculate", args, max_steps=100)
                observed = {"status": observation["status"], "values": observation["values"]}
            except HIAProgramTrap as error:
                observed = {"status": "trapped", "code": error.code}
            _require(observed == formula(*args), "VM differs from independent arithmetic/trap formula")
        differential = compare_verified_hia_program(checked, output, {"calculate": EDGE_CASES}, max_steps=100)
        report["native_differential"] = differential
        _require(differential["artifact_sha256"] == built["artifact_sha256"]
                 and differential["cases_executed"] == len(EDGE_CASES)
                 and differential["defined_traps_observed"] == 2, "finite native differential is incomplete")
        report["status"] = "qualified_for_finite_batch"
        return built["artifact_sha256"]
    finally:
        report["preparation_wall_ns"] = time.monotonic_ns() - started


@contextmanager
def pinned(path, expected_sha256, *, releases):
    """Hold one immutable byte image through the final owned child-group cleanup."""
    data, identity, fd = _pin_native_artifact(Path(path), maximum_bytes=MAX_IMAGE_BYTES)
    release = _NativeRelease(library=None, fd=fd)
    try:
        _require(sha256(data).hexdigest() == expected_sha256, "pinned image differs from internally built bytes")
        yield {"fd": fd, "path": f"/proc/{os.getpid()}/fd/{fd}", "sha256": expected_sha256,
               "bytes": data, "identity": identity}
    finally:
        record = release.attempt()
        releases.append(record)
        _require(record["native_release_succeeded"], "image descriptor close is uncertain; no retry or success")


def build_driver(directory, *, clang):
    source, output = Path(directory) / "driver.c", Path(directory) / "driver"
    _require(not source.exists() and not output.exists(), "driver output must be new")
    source.write_text(DRIVER, encoding="ascii")
    compiler = shutil.which(clang)
    _require(compiler is not None, "native compiler unavailable")
    compiler = Path(compiler).resolve()
    before = digest_executable(compiler)
    started = time.monotonic_ns()
    result = run_bounded([str(compiler), "-O3", "-std=c11", str(source), "-ldl", "-o", str(output)],
                         timeout=30, stdout_limit=16384, stderr_limit=65536)
    _require(result.returncode == 0 and digest_executable(compiler) == before, "driver compilation failed or compiler changed")
    return {"path": str(output), "sha256": digest_executable(output), "source_sha256": sha256(DRIVER.encode()).hexdigest(),
            "compiler_sha256": before, "compile_wall_ns": time.monotonic_ns() - started,
            "stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}


def sample(driver, artifact, *, calls, warmup, seed, hot, expected, report=None):
    validate_batch(calls, warmup, seed, hot)
    _require(type(expected) is int and 0 <= expected <= MASK64, "exact expected checksum required")
    started = time.monotonic_ns()
    row = {} if report is None else report
    row.update(artifact_sha256=artifact["sha256"], driver_sha256=driver["sha256"], expected_checksum=expected)
    # Both proc paths designate held sealed descriptors in this parent. They are
    # never closed/reused until synchronous run_bounded finishes owned cleanup.
    try:
        result = run_bounded([driver["path"], artifact["path"], str(calls), str(warmup), str(seed), str(hot)],
                             timeout=5, stdout_limit=4096, stderr_limit=4096)
        raw_stdout = getattr(result, "raw_stdout", None)
        raw_stderr = getattr(result, "raw_stderr", None)
        raw_stdout = result.stdout.encode() if raw_stdout is None else raw_stdout
        raw_stderr = result.stderr.encode() if raw_stderr is None else raw_stderr
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr,
                   raw_stdout_base64=b64encode(raw_stdout).decode("ascii"),
                   raw_stderr_base64=b64encode(raw_stderr).decode("ascii"))
        _require(result.returncode == 0 and raw_stderr == b"", "native batch failed or emitted unexpected stderr")
        value = json.loads(result.stdout)
        keys = {"calls", "checksum", "close_ns", "cpu_ns", "elapsed_ns", "hot", "load_ns", "seed"}
        _require(type(value) is dict and set(value) == keys and all(type(v) is int for v in value.values())
                 and value["calls"] == calls and value["seed"] == seed and value["hot"] == hot
                 and value["checksum"] == expected and value["elapsed_ns"] > 0 and value["cpu_ns"] >= 0
                 and value["load_ns"] >= 0 and value["close_ns"] >= 0
                 and raw_stdout == wire(value) + b"\n", "native batch record/checksum is malformed")
        row.update(value)
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error), "code": getattr(error, "code", None)}
        capture = getattr(error, "capture", None)
        if capture is not None:
            row["capture_failure"] = {"command": list(capture.command), "returncode": capture.returncode,
                "stdout_utf8_replacement": capture.stdout.decode("utf-8", errors="replace"),
                "stderr_utf8_replacement": capture.stderr.decode("utf-8", errors="replace"),
                "stdout_prefix_base64": b64encode(capture.stdout).decode("ascii"),
                "stderr_prefix_base64": b64encode(capture.stderr).decode("ascii"),
                "stdout_prefix_bytes": len(capture.stdout), "stderr_prefix_bytes": len(capture.stderr),
                "stdout_total_bytes": capture.stdout_total_bytes, "stderr_total_bytes": capture.stderr_total_bytes,
                "capture_error": getattr(error, "capture_error", None)}
        raise
    finally:
        # Complete future batch cost includes parsing, canonical bytes and
        # checksum validation. Failed attempts retain their actual elapsed cost.
        row["outer_wall_ns"] = time.monotonic_ns() - started
    return row


def assess_opportunities(protocol, samples, code, search_wall_ns):
    """A conservative observed-envelope gate; no controller ranking is inferred."""
    _require(type(search_wall_ns) is int and search_wall_ns >= 0, "invalid actual search cost")
    _require(protocol == load_protocol(), "economic request differs from the frozen protocol")
    count = len(protocol["modules"]) * len(protocol["actions"]) * sum(
        len(protocol[phase + "_seeds"]) for phase in ("training", "validation"))
    module_ids = {m["id"] for m in protocol["modules"]}
    _require(type(samples) is list and len(samples) == count and all(
        type(s) is dict and s.get("module") in module_ids and s.get("phase") in {"training", "validation"}
        and s.get("candidate") in protocol["actions"] and type(s.get("calls")) is int
        and type(s.get("seed")) is int and type(s.get("elapsed_ns")) is int
        and type(s.get("outer_wall_ns")) is int and s["outer_wall_ns"] >= s["elapsed_ns"]
        for s in samples),
        "complete exact frozen sample denominator required")
    results = []
    for module in protocol["modules"]:
        label = f"guard_denominator_{module['hot_denominator']}"
        row = {"module": module["id"], "candidate": label,
               "distinct_exported_code": code[label]["sha256"] != code["baseline"]["sha256"],
               "charged_search_wall_ns": search_wall_ns, "phases": {}}
        for phase in ("training", "validation"):
            seeds = protocol[phase + "_seeds"]
            selected = [s for s in samples if s["module"] == module["id"] and s["phase"] == phase]
            group = {}
            for action in protocol["actions"]:
                values = [s for s in selected if s["candidate"] == action]
                _require(len(values) == len(seeds) and {s["seed"] for s in values} == set(seeds)
                         and all(s["calls"] == protocol["iterations_per_batch"] and s["elapsed_ns"] > 0
                                 for s in values), "complete frozen sample denominator required")
                group[action] = values
            # Each future deployment unit is the SAME complete fresh-child
            # batch used here. A faster inner kernel cannot hide slower load,
            # startup, output validation or owned process-group cleanup.
            baseline_min = min(s["outer_wall_ns"] for s in group["baseline"])
            candidate_max = max(s["outer_wall_ns"] for s in group[label])
            saved_batch = baseline_min - candidate_max
            savings = saved_batch * protocol["expected_calls_per_module"] // protocol["iterations_per_batch"]
            row["phases"][phase] = {"baseline_min_batch_ns": baseline_min,
                "candidate_max_batch_ns": candidate_max,
                "batch_metric": "outer_wall_ns_complete_fresh_child",
                "kernel_saved_batch_ns_diagnostic": min(s["elapsed_ns"] for s in group["baseline"])
                    - max(s["elapsed_ns"] for s in group[label]),
                "conservative_saved_batch_ns": saved_batch, "prospective_savings_ns": savings,
                "net_savings_ns": savings - search_wall_ns,
                "break_even_calls_diagnostic": None if saved_batch <= 0 else
                    (search_wall_ns * protocol["iterations_per_batch"] // saved_batch + 1)}
        row["positive_after_all_costs"] = row["distinct_exported_code"] and all(
            p["net_savings_ns"] > 0 for p in row["phases"].values())
        results.append(row)
    result = {"module_opportunities": results,
              "max_selected_specializations": protocol["max_selected_specializations"],
              "future_batches_per_module": protocol["expected_calls_per_module"] // protocol["iterations_per_batch"],
              "gain_metric": "complete fresh-child batch outer wall time",
              "synthetic_horizon_not_application_trace": True, "NDU_gain_established": False,
              "statistical_superiority_established": False}
    return reprice_opportunities(protocol, result, search_wall_ns)


def reprice_opportunities(protocol, result, search_wall_ns):
    """Fill measured costs into an already computed observation table.

    The caller records this final report-accounting boundary separately from
    the actual complete analysis and final source hashing costs it includes.
    This pure calculation grants no execution/publication authority.
    """
    _require(type(search_wall_ns) is int and search_wall_ns >= 0, "invalid actual search cost")
    for row in result["module_opportunities"]:
        row["charged_search_wall_ns"] = search_wall_ns
        for phase in row["phases"].values():
            phase["net_savings_ns"] = phase["prospective_savings_ns"] - search_wall_ns
            saved_batch = phase["conservative_saved_batch_ns"]
            phase["break_even_calls_diagnostic"] = (None if saved_batch <= 0 else
                search_wall_ns * protocol["iterations_per_batch"] // saved_batch + 1)
        row["positive_after_all_costs"] = row["distinct_exported_code"] and all(
            phase["net_savings_ns"] > 0 for phase in row["phases"].values())
    within = search_wall_ns <= protocol["max_optimization_wall_ns"]
    eligible = within and sum(r["positive_after_all_costs"] for r in result["module_opportunities"]) >= 2
    result.update(status="opportunity_for_separate_controlled_study" if eligible else "no-economic-opportunity",
                  opportunity_gate_passed=eligible, within_wall_budget=within,
                  ndu_comparison_authorized_by_this_evidence=eligible)
    return result
