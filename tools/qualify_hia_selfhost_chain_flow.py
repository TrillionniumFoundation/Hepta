"""Finite ordinary-libc failure and destruction evidence for dynamic chains.

The companion chain ELF qualifier consumes the independent flow/refusal fixtures.
This executable adds exact allocator-call injection and allocation/free accounting.
Successor object bytes are emitted solely by the supplied HIA compiler. A small
host C witness is compiled AFTER B0 and linked into each explicitly named test
artifact. Python Core VM and direct backend are separate host-side references.
No production loader is modified and no hostile-loader behavior is exercised.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHILD = ROOT / "tools/hia_selfhost_chain_allocator_child.py"
WITNESS = ROOT / "tools/hia_selfhost_chain_allocator_witness.c"
EVENT_CAPACITY = 32768
STAT_FIELDS = (
    "allocation_attempts", "calloc_calls", "malloc_calls", "forced_failures",
    "allocations", "frees", "live_allocations", "live_bytes", "peak_bytes",
    "foreign_frees", "record_overflow", "zero_size_calls", "unexpected_libc_null",
    "event_count", "failure_index", "ready_magic",
)
MAGIC = 0x484941434841494e
SOURCE_FILES = (
    "tools/hia_selfhost_chain_flow_cases.py", "tools/qualify_hia_selfhost_chain_flow.py",
    "tools/hia_selfhost_chain_allocator_child.py", "tools/hia_selfhost_chain_allocator_witness.c",
    "tools/hia_selfhost_chain_cases.py", "tools/hia_selfhost_chain_elf.py",
    "tools/hia_selfhost_owned_elf.py", "tools/qualify_hia_selfhost.py",
    "tools/qualify_hia_selfhost_owned_elf.py", "tools/hia_selfhost_child.py",
    "hepta/hia_program_runtime.py", "hepta/hia_program_native.py",
    "examples/hia_bootstrap/selfhost.hepta",
)


def digest(data):
    return sha256(data).hexdigest()


def reference(case):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap
    checked = assemble_program(case["source"])
    # Deliberately ample finite limits; NULL is an explicit contract input,
    # never inferred from a step/heap/call-budget stop.
    fail_at = case["allocation_fail_at"] or None
    machine = _Machine(checked, 10_000_000, 16 << 20, fail_at, 256)
    roots = [_Owner(-1, bytearray()), _Owner(-2, bytearray([0xa5] * 8)), _Owner(-3, bytearray())]
    arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
    function = next(fn for fn in checked.as_dict()["functions"] if fn["name"] == "f0")
    try:
        values = machine.invoke(function, arguments)
    except HIAProgramTrap as error:
        observed = machine.report("f0", "trapped", error=error)
    else:
        observed = machine.report("f0", "returned", values=values)
        if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
            raise AssertionError("normal return leaves an owner, chain or local loan")
    observed["external_output_hex"] = roots[1].data.hex()
    observed["allocation_fail_at"] = fail_at
    observed["host_budget_is_not_allocator_null"] = True
    if "expected_trap" in case:
        assert observed["status"] == "trapped" and observed["error"]["code"] == case["expected_trap"], observed
    else:
        assert observed["status"] == "returned" and observed["result"] == case["expected_result"], observed
    assert observed["external_output_hex"] == case["expected_output_hex"], observed
    for field in ("allocation_attempts", "allocations", "frees"):
        assert observed["resources"][field] == case["expected_" + field], observed
    return checked, observed


def allocator_cases():
    from tools.hia_selfhost_chain_flow_cases import allocation_failure_cases
    from tools.hia_selfhost_chain_cases import loop_source
    rows = allocation_failure_cases()
    # The no-failure control verifies actual 5000-node destruction releases both
    # each payload and each node in ordinary native allocator observations.
    rows.append({"id": "chain-allocator-5000-node-drop-conservation",
        "source": loop_source(5000, drop=True).decode(), "expected_result": 5000,
        "expected_output_hex": (bytes([174]) + bytes([0xa5]) * 7).hex(),
        "allocation_fail_at": 0, "expected_allocation_attempts": 10000,
        "expected_allocations": 10000, "expected_frees": 10000,
        "expected_failed_allocations": 0})
    return rows


def counters(path):
    raw = path.read_bytes()
    expected_size = 16 * 8 + EVENT_CAPACITY * 4 * 8
    if len(raw) != expected_size:
        raise AssertionError("incomplete native allocator counter file")
    values = struct.unpack_from("<16Q", raw)
    report = dict(zip(STAT_FIELDS, values))
    if report["ready_magic"] != MAGIC or report["event_count"] > EVENT_CAPACITY:
        raise AssertionError(report)
    events = []
    live, attempts, allocations, frees, failures = {}, 0, 0, 0, 0
    seen_ids = set()
    for i in range(report["event_count"]):
        kind, size, logical_id, success = struct.unpack_from("<4Q", raw, 128 + i * 32)
        if kind not in (1, 2, 3) or success not in (0, 1):
            raise AssertionError("unexpected allocator event")
        row = {"operation": {1: "calloc", 2: "malloc", 3: "free"}[kind],
               "bytes": size, "logical_allocation_id": logical_id, "success": bool(success)}
        if kind in (1, 2):
            attempts += 1
            row["allocation_attempt"] = attempts
            if success:
                if not logical_id or logical_id in seen_ids:
                    raise AssertionError("allocator witness reused a logical identity")
                live[logical_id] = size; seen_ids.add(logical_id); allocations += 1
            else:
                if logical_id:
                    raise AssertionError("failed allocation has a nonempty identity")
                failures += 1
        else:
            if not success or logical_id not in live or live.pop(logical_id) != size:
                raise AssertionError("unmatched or duplicate native free")
            frees += 1
        events.append(row)
    if (attempts != report["allocation_attempts"] or allocations != report["allocations"]
            or frees != report["frees"] or len(live) != report["live_allocations"]
            or sum(live.values()) != report["live_bytes"]
            or failures != report["forced_failures"] + report["unexpected_libc_null"]):
        raise AssertionError("counter values disagree with actual allocator events")
    report["events"] = events
    report["events_replay_consistent"] = True
    report["counter_file_sha256"] = digest(raw)
    return report


def invoke(directory, label, library, case, *, direct):
    request_path = directory / (label + ".request.json")
    output_path = directory / (label + ".output.bin")
    stats_path = directory / (label + ".allocator.bin")
    image_hash, child_hash = digest(library.read_bytes()), digest(CHILD.read_bytes())
    request = {"image": str(library.resolve()), "image_sha256": image_hash,
        "allocation_fail_at": case["allocation_fail_at"], "event_capacity": EVENT_CAPACITY,
        "output": str(output_path.resolve()), "counters": str(stats_path.resolve()),
        "return_encoding": "packed-ABI-status-and-u32" if direct else "zero-extended-u32"}
    request_path.write_text(json.dumps(request, sort_keys=True) + "\n")
    argv = [sys.executable, "-I", "-B", str(CHILD.resolve()), str(request_path.resolve())]
    start = time.monotonic_ns()
    try:
        process = subprocess.run(argv, cwd=directory, capture_output=True, timeout=20)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        report = {"status": "timeout", "wall_limit_seconds": 20}
    else:
        stdout, stderr = process.stdout, process.stderr
        if process.returncode:
            report = {"status": "child_failed", "returncode": process.returncode}
        else:
            report = json.loads(stdout)
    elapsed = time.monotonic_ns() - start
    (directory / (label + ".stdout.log")).write_bytes(stdout)
    (directory / (label + ".stderr.log")).write_bytes(stderr)
    report.update({"wall_elapsed_ns": elapsed, "argv": argv,
                   "runner_sha256": child_hash, "image_sha256": image_hash,
                   "native_linkage": "explicit ld --wrap ordinary calloc/malloc/free witness"})
    if output_path.exists():
        report["output_hex"] = output_path.read_bytes().hex()
    if stats_path.exists():
        report["allocator"] = counters(stats_path)
    (directory / (label + ".receipt.json")).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if digest(library.read_bytes()) != image_hash or digest(CHILD.read_bytes()) != child_hash:
        raise AssertionError("own fixture or test helper changed during invocation")
    return report


def validate_native(observed, case, *, direct):
    if "expected_trap" in case:
        good = observed.get("status") == "child_failed" and observed.get("returncode") == (-6 if direct else -4)
    else:
        good = (observed.get("status") == "returned" and observed.get("abi_status") == 0
                and observed.get("core_u32") == case["expected_result"]
                and not observed.get("forbidden_compiler_modules_loaded"))
    stats = observed.get("allocator", {})
    good = bool(good and observed.get("output_hex") == case["expected_output_hex"]
        and stats.get("failure_index") == case["allocation_fail_at"]
        and stats.get("forced_failures") == case["expected_failed_allocations"]
        and stats.get("foreign_frees") == stats.get("record_overflow")
            == stats.get("unexpected_libc_null") == stats.get("zero_size_calls") == 0
        and stats.get("events_replay_consistent"))
    for field in ("allocation_attempts", "allocations", "frees"):
        good = good and stats.get(field) == case["expected_" + field]
    if "expected_trap" not in case:
        good = good and stats.get("live_allocations") == stats.get("live_bytes") == 0
    failures = [e for e in stats.get("events", []) if e["operation"] != "free" and not e["success"]]
    if case["allocation_fail_at"]:
        good = good and len(failures) == 1 and failures[0]["allocation_attempt"] == case["allocation_fail_at"]
        # Successor node storage uses calloc; the independent direct backend
        # uses malloc. Assert the selected point really reaches each route.
        expected_allocator = "malloc" if direct and "-node-null-" in case["id"] else "calloc"
        good = good and failures[0]["operation"] == expected_allocator
    else:
        good = good and not failures
    if not good:
        raise AssertionError({"case": case["id"], "direct": direct, "native": observed})
    return True


def qualify(directory, compiler):
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    from tools.qualify_hia_selfhost import compile_stage, observe_native_tool
    from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
    directory, compiler = Path(directory), Path(compiler)
    directory.mkdir(parents=True, exist_ok=False)
    frozen_sources = {path: (ROOT / path).read_bytes() for path in SOURCE_FILES}
    for path, raw in frozen_sources.items():
        destination = directory / "sources" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.selfhost-chain-allocator-qualification.v1",
        "status": "started", "compiler_sha256": digest(compiler.read_bytes()),
        "scope": "six explicit allocator failure paths and one 5000-node ordinary native destruction control",
        "allocator_contract": "fresh nonaliasing calloc/malloc storage or one selected NULL; free valid live allocations",
        "global_core_or_machine_refinement_proved": False,
        "production_loader_changed": False, "adversarial_loader_tests": False,
        "python_parser_or_codegen_after_B0": True,
        "python_parser_or_codegen_in_successor_compilation": False,
        "host_reference_codegen_after_B0": True,
        "external_assembler_after_B0": True,
        "external_assembler_scope": "host allocator qualification witness C object only; no successor compilation",
        "ordinary_linker_and_system_libc_trusted": True,
        "failure_is_explicit_allocator_return_not_budget_exhaustion": True,
        "general_multi_result_call_return_abi_supported": False,
        "whole_lifecycle_economic_cost_claimed": False,
        "tools": [], "cases": []}
    try:
        wrapper = directory / "allocator-witness.o"
        report["tools"].append(observe_native_tool(directory, "allocator-witness-compile", "cc", [
            "-std=c11", "-O2", "-fPIC", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
            "-c", WITNESS, "-o", wrapper]))
        if report["tools"][-1]["returncode"]:
            raise AssertionError(report["tools"][-1])
        report["allocator_witness"] = {"source_sha256": digest(WITNESS.read_bytes()),
            "object_sha256": digest(wrapper.read_bytes()), "compiled_after_B0": True}
        for case in allocator_cases():
            label, source = case["id"], case["source"].encode()
            (directory / (label + ".hepta")).write_bytes(source)
            checked, vm = reference(case)
            record = {"case": case, "reference": vm, "pass": False}
            report["cases"].append(record)
            obj, compilation = compile_stage(directory, label + "-object", compiler, source, output_extension=".o")
            record.update({"compilation": compilation, "inspection": inspect_owned_object(obj.read_bytes())})
            direct_image = emit_program_machine(checked, foreign_buffer_exports=(("f0", 1 << 20),))
            direct_object = directory / (label + "-direct.o")
            record["independent_direct_object_build"] = compile_program_machine(
                direct_image, program=checked, output=direct_object, kind="object")
            record["arms"] = []
            for direct, object_path in ((False, obj), (True, direct_object)):
                arm = "direct" if direct else "successor"
                linked = directory / (label + "-" + arm + ".so")
                tools = [observe_native_tool(directory, label + "-" + arm + "-readelf",
                    "readelf", ["-W", "-h", "-S", "-s", "-r", object_path])]
                tools.append(observe_native_tool(directory, label + "-" + arm + "-link", "ld", [
                    "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--build-id=none",
                    "--wrap=calloc", "--wrap=malloc", "--wrap=free",
                    object_path, wrapper, "-lc", "-o", linked]))
                arm_record = {"arm": arm, "object_sha256": digest(object_path.read_bytes()), "tools": tools}
                record["arms"].append(arm_record)
                if not all(row["returncode"] == 0 for row in tools):
                    raise AssertionError(tools)
                observed = invoke(directory, label + "-" + arm + "-run", linked, case, direct=direct)
                arm_record["native"] = observed
                arm_record["pass"] = validate_native(observed, case, direct=direct)
            record["pass"] = True
        report["status"] = "PASS_SCOPED_CHAIN_ALLOCATOR_CONTRACT"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["observed_qualification_wall_ns"] = time.monotonic_ns() - started
        report["source_files"] = {path: digest(raw) for path, raw in frozen_sources.items()}
        changed = [path for path, raw in frozen_sources.items() if (ROOT / path).read_bytes() != raw]
        report["source_files_unchanged"] = not changed
        if changed:
            report["status"] = "FAIL"
            report["changed_source_files"] = changed
        (directory / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if changed:
            raise AssertionError("qualification source changed during the run: " + repr(changed))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.output, args.compiler)
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]),
                      "native_invocations": sum(len(row["arms"]) for row in result["cases"])}))

