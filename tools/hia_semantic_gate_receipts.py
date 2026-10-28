"""Check retained finite semantic reports at unified-gate intake.

No compiler, VM, native executable or producer qualification is rerun here.
Core/LLVM regeneration checks retained source bindings. Compilation retains
its producer receipt boundary: internal compiler streams are not intercepted.
Every explicit command, output and allocator observation is checked separately.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from tools.release_check import MAX_RELEASE_EVIDENCE_BYTES, _evidence_state


def _require(condition, message):
    if not condition:
        raise ValueError("Partial-record receipt: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _equal(actual, expected, message):
    # Plain Python equality conflates True/1 and False/0 in nested reports.
    _require(_wire(actual) == _wire(expected), message)


def _json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result, "duplicate retained JSON key")
            result[name] = value
        return result
    def constant(_):
        raise ValueError("Partial-record receipt: nonfinite retained JSON number")
    def finite_float(token):
        value = float(token)
        _require(math.isfinite(value), "nonfinite retained JSON number")
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant,
                      parse_float=finite_float)


def _natural(value):
    return type(value) is int and value >= 0


def _read_retained_file(path):
    # Successful compiler/VM commands commonly have a zero-byte stderr. The
    # release report reader deliberately requires a nonempty JSON report, so
    # retain its stable no-follow discipline with an explicit empty-stream case.
    before = _evidence_state(path)
    _require(before is not None and stat.S_ISREG(before[2])
             and 0 <= before[3] <= MAX_RELEASE_EVIDENCE_BYTES, "unsafe retained file extent/type")
    _require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"), "no stable no-follow reader")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        def identity():
            info = os.fstat(stream.fileno())
            return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(identity() == before, "retained file changed before opening")
        raw = stream.read(before[3] + 1)
        _require(len(raw) == before[3] and identity() == before, "retained file changed during reading")
    _require(_evidence_state(path) == before, "retained path changed during reading")
    return raw


class _Retained:
    """Exact flat paths; every explicit process has one assigned ordered role."""
    def __init__(self, directory, processes):
        self.directory = Path(directory).resolve(strict=True)
        _require(type(processes) is list and bool(processes), "missing process inventory")
        self.processes, self.used, self.files = processes, [], {}

    def bytes(self, name):
        _require(type(name) is str and Path(name).name == name, "invalid retained basename")
        if name not in self.files:
            self.files[name] = _read_retained_file(self.directory / name)
        return self.files[name]

    def descriptor(self, name):
        raw = self.bytes(name)
        return {"path": str(self.directory / name), "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    def retained(self, item, name=None):
        _require(type(item) is dict and set(item) == {"path", "bytes", "sha256"},
                 "invalid retained descriptor")
        _require(type(item["path"]) is str and _natural(item["bytes"])
                 and type(item["sha256"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                 "invalid retained descriptor types")
        basename = Path(item["path"]).name
        _require(name is None or basename == name, "retained file role differs")
        _equal(item, self.descriptor(basename), "retained path or bytes differ: " + basename)
        return self.bytes(basename)

    def process(self, index, *, argv, expected=0, stdin=None):
        _require(type(index) is int and 0 <= index < len(self.processes), "process index differs")
        _require(index == len(self.used), "process role/order is missing, repeated or reordered")
        row = self.processes[index]
        _require(type(row) is dict and row["status"] == "completed"
                 and type(row["returncode"]) is int and row["returncode"] == expected,
                 "process did not complete with its declared outcome")
        _require(type(row["seconds"]) in (int, float) and math.isfinite(row["seconds"])
                 and row["seconds"] >= 0, "process duration is not finite")
        _equal(row["argv"], list(map(str, argv)), "process command differs")
        _require(row["stream_encoding"] == "utf8_universal_newlines", "process stream convention differs")
        prefix = f"process-{index:04d}"
        stdout = self.retained(row["stdout"], prefix + ".stdout")
        self.retained(row["stderr"], prefix + ".stderr")
        if stdin is None:
            _require("stdin" not in row, "unexpected process stdin")
        else:
            _require(self.retained(row["stdin"], prefix + ".stdin") == stdin, "process input differs")
        self.used.append(index)
        return stdout

    def executable(self, name, descriptor):
        raw = self.retained(descriptor, name)
        _require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                 and int.from_bytes(raw[16:18], "little") in (2, 3)
                 and int.from_bytes(raw[18:20], "little") == 62,
                 "retained native executable is not x86-64 ELF")

    def manifest(self):
        _require(self.used == list(range(len(self.processes))), "unassigned explicit process")
        manifest = _json(self.bytes("manifest.json"))
        _require(manifest["schema"] == "hepta.hia.partial-record-manifest.v1", "manifest schema differs")
        _require(type(manifest["files"]) is list, "invalid manifest file list")
        names = []
        for item in manifest["files"]:
            self.retained(item)
            names.append(Path(item["path"]).name)
        _require(len(names) == len(set(names)), "duplicate manifest file")
        children = list(self.directory.iterdir())
        _require(all(p.is_file() and not p.is_symlink() for p in children), "unexpected directory or symlink")
        _require(set(names) == {p.name for p in children if p.name != "manifest.json"},
                 "retained inventory differs")
        _require(set(self.files) <= set(names) | {"manifest.json"}, "required file missing from manifest")
        for name, captured in self.files.items():
            current = _read_retained_file(self.directory / name)
            _require(current == captured, "retained file changed during intake: " + name)


_RESOURCE_FIELDS = frozenset({
    "allocation_attempts", "allocations", "frees", "owners_created", "owners_dropped",
    "live_owners", "live_bytes", "peak_bytes", "loans_started", "loans_ended", "live_local_loans",
    "chains_created", "chains_consumed", "live_chains", "chain_nodes_created", "chain_nodes_dropped",
    "live_chain_nodes",
})
_RUST_CLAIMS = {
    "finite_scalar_execution": True, "finite_byte_owner_execution": True,
    "single_block_scalar_entry_only": False, "scalar_public_entry_and_results_only": True,
    "verified_resource_cfg_execution": True, "interprocedural_byte_owner_and_loan_execution": True,
    "chain_and_bulk_execution": False, "versioned_bulk_byte_execution": True,
    "chain_execution": False, "general_resource_execution": False,
    "production_admission_authorized": False, "whole_language_soundness_proved": False,
    "native_backend_refinement_proved": False, "abi_or_hardware_qualified": False,
}
_NATIVE_CLAIMS = {
    "standalone_core_reverified": True, "source_ast_required": False,
    "rust_reference_required": False, "rust_codegen_used": False, "c_codegen_used": False,
    "fallback_used": False, "native_execution_qualified": False, "backend_refinement_proved": False,
    "cross_target_execution_qualified": False, "whole_language_soundness_proved": False,
    "foreign_buffer_entrypoints_exposed": False,
}


def _ledger(ledger, *, returned, expected=None):
    _require(type(ledger) is dict and set(ledger) == _RESOURCE_FIELDS
             and all(_natural(value) for value in ledger.values()), "invalid exact resource ledger")
    for created, ended, live in (("owners_created", "owners_dropped", "live_owners"),
                                ("loans_started", "loans_ended", "live_local_loans"),
                                ("chains_created", "chains_consumed", "live_chains"),
                                ("chain_nodes_created", "chain_nodes_dropped", "live_chain_nodes")):
        _require(ledger[created] - ledger[ended] == ledger[live], "resource conservation differs")
    _require(ledger["allocation_attempts"] >= ledger["allocations"] >= ledger["frees"]
             and ledger["peak_bytes"] >= ledger["live_bytes"], "allocation ledger is inconsistent")
    if returned:
        _require(all(ledger[field] == 0 for field in
                     ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes")),
                 "returned program retains resources")
    if expected is not None:
        for observed, specified in (("allocation_attempts", "attempts"), ("allocations", "allocations"),
                                    ("frees", "frees"), ("live_bytes", "live_bytes"),
                                    ("peak_bytes", "peak_bytes"), ("owners_created", "logical_owners"),
                                    ("owners_dropped", "logical_owners")):
            _equal(ledger[observed], expected[specified], "independent resource count differs: " + observed)


def _execution(report, *, rust, core_sha, input_sha, function, options, returned, result=None, error=None):
    from tools import qualify_hia_partial_records as producer
    _require(type(report) is dict, "execution is not an object")
    _equal(report["program_sha256"], core_sha, "execution Core differs")
    _equal(report["function"], function, "execution entry differs")
    _require(_natural(report["steps"]) and report["steps"] <= options["max_steps"] + 1,
             "execution steps are outside policy")
    _equal(report["status"], "returned" if returned else "budget_exceeded", "execution status differs")
    if rust:
        _equal(report["schema"], producer.RUST_EXECUTION_SCHEMA, "Rust execution schema differs")
        _equal(report["profile"], producer.RUST_EXECUTION_PROFILE, "Rust execution profile differs")
        _equal(report["max_steps"], options["max_steps"], "Rust step limit differs")
        _equal(report["max_heap_bytes"], options["max_heap_bytes"], "Rust heap limit differs")
        _equal(report["max_call_depth"], 32, "Rust call-depth policy differs")
        _equal(report["allocation_fail_at"], options.get("allocation_fail_at"), "Rust allocation policy differs")
        _equal(report["claims"], _RUST_CLAIMS, "Rust execution claim scope differs")
    else:
        _equal(report["schema"], "hepta.hia.program-execution.v1", "Python execution schema differs")
        _equal(report["input_sha256"], input_sha, "Python input binding differs")
        _equal(report["word_bits"], 64, "Python word width differs")
        _require(report["source_used"] is False, "Python source authority differs")
        _equal(report["claims"], {"finite_core_execution": True, "whole_language_soundness_proved": False,
                                    "backend_refinement_proved": False}, "Python execution claim scope differs")
    if returned:
        _require("error" not in report, "returned execution carries an error")
        _equal(report["values"], [result], "returned value differs")
        if not rust:
            _equal(report["result"], result, "Python scalar result differs")
    else:
        _require("values" not in report and "result" not in report, "stopped execution invents return values")
        _equal(report["error"]["code"], error, "budget reason differs")
        if rust:
            _equal(report["error"], {"code": error}, "Rust error envelope differs")
        else:
            _require(type(report["error"]["message"]) is str and bool(report["error"]["message"]),
                     "Python budget diagnostic missing")
    _ledger(report["resources"], returned=returned)


def _object(reader, name, exports):
    from hepta.object_symbols import inspect_object_symbols
    artifact = reader.bytes(name + ".o")
    symbols = inspect_object_symbols(artifact, "ELF64", 62)
    _require(symbols["defined"] == frozenset(exports)
             and symbols["undefined"] <= {"abort", "calloc", "free", "malloc", "memset", "memcpy", "memmove"},
             "native object import/export boundary differs")
    return artifact, {key: sorted(value) for key, value in symbols.items()}


def _compilation(reader, receipt, *, name, ir, clang):
    artifact, symbols = _object(reader, name, ir.exports)
    expected = {"schema": "hepta.hia.program.native.v1", "ok": True,
                "status": "native_compiled_not_executed", "profile": ir.profile, "target": ir.target,
                "kind": "object", "output": str(reader.directory / (name + ".o")),
                "core_sha256": ir.core_sha256, "input_sha256": ir.input_sha256,
                "llvm_ir_sha256": ir.sha256, "implementation_sha256": ir.implementation_sha256,
                "artifact_sha256": hashlib.sha256(artifact).hexdigest(), "artifact_bytes": len(artifact),
                "exports": list(ir.exports), "binary_inventory": symbols,
                "flags": ["--target=" + ir.target, "-x", "ir", "-O3", "-fPIC", "-c"],
                "claims": _NATIVE_CLAIMS}
    for key, value in expected.items():
        _equal(receipt[key], value, "native compilation field differs: " + key)
    toolchain = receipt["toolchain"]
    _require(set(toolchain) == {"path", "sha256", "version", "default_target"}, "compiler identity shape differs")
    _equal(toolchain["path"], clang["path"], "native compiler path differs")
    _equal(toolchain["sha256"], clang["sha256"], "native compiler bytes differ")
    _require(type(toolchain["version"]) is str
             and re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", toolchain["version"]) is not None
             and toolchain["default_target"] in {"x86_64-unknown-linux-gnu", "x86_64-pc-linux-gnu"},
             "native toolchain profile differs")
    _equal(receipt["external_abi"], "scalar-only C functions; resource and multiple-result functions are internal",
           "native ABI claim differs")
    _equal(receipt["runtime_assumptions"], [
        "Linux LP64 target with 64-bit pointers and size_t",
        "C calloc returns null or an initialized nonaliasing allocation of the requested size",
        "C malloc returns null or a fresh nonaliasing allocation of the requested size; bytes are initialized before read or remain unobserved",
        "C free accepts a live allocation from calloc or malloc, or null",
        "abort terminates execution; no cleanup after traps is promised",
        "native compiler, linker, loader, libc and host hardware are trusted"], "native runtime scope differs")


def _link(reader, index, *, name, clang, producer, normal=False):
    command = [clang["path"], "-std=c11", "-O2"]
    if normal:
        command.append("-Werror=implicit-function-declaration")
    reader.process(index, argv=[*command, reader.directory / "observer.c",
                   reader.directory / (name + ".o"), *producer.WRAPS, "-o", reader.directory / name])


def _partial_bound_observation(receipt, static_row, observed, *, core_sha,
                               input_sha, function, arguments, limit_bytes):
    """Compare a bound's exact invocation with an independently retained run.

    Recomputing a producer's analysis alone does not establish that its actual
    VM/allocator observations satisfy the certificate. This check also covers
    interrupted prefixes, without treating a budget stop as completed cleanup.
    """
    _require(set(receipt) == {"schema", "profile", "status", "core_schema", "core_sha256",
             "input_sha256", "function", "arguments", "limit_bytes", "peak_bound_bytes",
             "max_vm_ticks", "max_allocator_interactions", "max_call_depth",
             "static_budget_sha256", "analysis_work", "claims", "sha256"},
             "invocation bound fields differ")
    _equal(receipt["schema"], "hepta.hia.finite-entry-live-heap-admission.v1", "invocation bound schema differs")
    _equal(receipt["profile"], "acyclic-byte-owner-transfer-v7", "invocation bound profile differs")
    _equal(receipt["status"], "qualified_exact_scalar_invocation_requested_payload_only",
           "invocation bound status differs")
    _equal(receipt["claims"], {
        "canonical_core_reverified": True, "whole_module_acyclic_byte_profile_checked": True,
        "exact_scalar_invocation_only": True, "owned_call_transfer_accounted": True,
        "external_borrow_payload_counted_in_caller": True,
        "allocation_failure_and_stop_prefixes_in_bound": True,
        "all_function_input_extents_bounded": False, "caller_supplied_resource_extents_trusted": False,
        "branch_reachability_proved": False, "cleanup_after_trap_or_budget_stop_proved": False,
        "recursive_chain_storage_bounded": False, "process_rss_or_native_stack_bytes_bounded": False,
        "source_or_native_backend_refinement_proved": False, "whole_language_soundness_proved": False,
    }, "invocation bound scope differs")
    _equal(receipt["sha256"], hashlib.sha256(_wire({k: v for k, v in receipt.items() if k != "sha256"})).hexdigest(),
           "invocation bound content identity differs")
    work = receipt["analysis_work"]
    _require(set(work) == {"contexts", "transfer_steps", "peak_analysis_call_depth",
                          "max_contexts", "max_transfer_steps", "max_analysis_call_depth"},
             "analysis work inventory differs")
    for count, ceiling, limit in (("contexts", "max_contexts", 1024),
                                   ("transfer_steps", "max_transfer_steps", 32768),
                                   ("peak_analysis_call_depth", "max_analysis_call_depth", 64)):
        _equal(work[ceiling], limit, "analysis work policy differs")
        _require(type(work[count]) is int and 0 < work[count] <= limit,
                 "analysis work exceeds its declared policy")
    for key, expected in (("core_schema", "hepta.hia.program.v7"),
                          ("core_sha256", core_sha), ("input_sha256", input_sha),
                          ("function", function), ("arguments", arguments),
                          ("limit_bytes", limit_bytes)):
        _equal(receipt[key], expected, "invocation bound " + key + " differs")
    for key in ("max_vm_ticks", "max_allocator_interactions", "max_call_depth"):
        _require(type(receipt[key]) is int and receipt[key] >= 0, "invalid invocation bound count")
        _equal(receipt[key], static_row[key], "invocation bound static summary differs")
    peak = receipt["peak_bound_bytes"]
    _require(type(peak) is int and 0 <= peak <= limit_bytes, "invalid invocation payload bound")
    steps, resources = observed["steps"], observed["resources"]
    _require(type(steps) is int and 0 <= steps <= receipt["max_vm_ticks"],
             "retained execution exceeds its static tick bound")
    for key in ("peak_bytes", "allocation_attempts", "frees"):
        _require(type(resources[key]) is int and resources[key] >= 0,
                 "invalid retained resource observation")
    _require(resources["peak_bytes"] <= peak, "retained execution exceeds its invocation payload bound")
    _require(resources["allocation_attempts"] + resources["frees"] <= receipt["max_allocator_interactions"],
             "retained execution exceeds its allocator interaction bound")


def validate_partial_records(report, directory):
    from hepta.hia_program import verify_core
    from hepta.hia_program_llvm import emit_program_llvm
    from tools import qualify_hia_partial_records as producer

    try:
        reader = _Retained(directory, report["processes"])
        _equal(_json(reader.bytes("report.json")), report, "caller report differs from retained original")
        _require(report["schema"] == producer.SCHEMA and report["status"] == "passed"
                 and report["passed"] is True and "error" not in report, "not a completed finite qualification")
        _equal(report["source_before"], report["source_after"], "source identity changed during qualification")
        _equal(report["source_before"], producer.source_identity(), "qualification source differs from current source")
        _equal(report["tools_before"], report["tools_after"], "tool identity changed")
        _require(set(report["tools_before"]) == {"clang", "rust_vm"}, "selected tool inventory differs")
        for item in report["tools_before"].values():
            _equal(item, producer.descriptor(item["path"]), "selected tool bytes changed")
        actual_cases = producer.cases()
        pair_scope = any(case["function"] == "partial_pair_task" for case in actual_cases)
        _equal(report["claims"], {
            "finite_partial_record_execution": True, "whole_language_soundness_proved": False,
            "llvm_refinement_proved": False, "real_concurrency_qualified": False,
            "gpu_or_physical_board_qualified": False, "two_live_payload_cancel_order_qualified": pair_scope,
        }, "scope changed")
        _equal(report["cases"], actual_cases, "case inventory differs")
        _require(type(report["differential"]) is list and len(report["differential"]) == len(actual_cases),
                 "incomplete differential denominator")
        _require(type(report["budgets"]) is list and len(report["budgets"]) == len(producer.budget_cases()),
                 "incomplete budget denominator")
        _require(set(report["native"]) == {"nominal", "core"}, "missing native lowering route")
        _equal(_json(reader.bytes("input.json")), producer.program(), "nominal corpus differs")
        nominal = verify_core(reader.bytes("input.json"))
        core_bytes = reader.bytes("core.json")
        core = verify_core(core_bytes)
        _require(core_bytes == nominal.canonical_bytes == core.canonical_bytes, "retained normalization differs")
        _equal(report["input_sha256"], nominal.input_sha256, "nominal input identity differs")
        _equal(report["core_sha256"], core.sha256, "Core identity differs")
        _equal(report["normalization_report"], nominal.normalization_report, "normalization report differs")
        _equal(report["analysis"], producer.analysis_receipts(nominal), "analysis differs")
        finite = report["analysis"]["finite_invocations"]
        _require(set(finite) == {"schema", "status", "core_sha256", "limit_bytes", "cases", "budgets"},
                 "finite invocation inventory fields differ")
        _equal(finite["schema"], "hepta.hia.partial-finite-invocations.v1", "finite invocation inventory schema differs")
        _equal(finite["status"], "qualified", "finite invocation inventory did not qualify")
        _equal(finite["core_sha256"], core.sha256, "finite invocation inventory Core differs")
        _equal(finite["limit_bytes"], 16 * 1024 * 1024, "finite invocation inventory policy differs")
        _require(type(finite["cases"]) is list and len(finite["cases"]) == len(actual_cases),
                 "finite invocation case denominator differs")
        _require(type(finite["budgets"]) is list and len(finite["budgets"]) == len(producer.budget_cases()),
                 "finite invocation budget denominator differs")
        static = report["analysis"]["static_budget"]
        _equal(static["status"], "qualified", "static tick/allocator analysis did not qualify")
        summaries = {row["function"]: row for row in static["receipt"]["functions"]}
        _require(len(summaries) == len(static["receipt"]["functions"]), "duplicate static function summary")
        _equal(_json(reader.bytes("plan.json")), {
            "schema": "hepta.hia.partial-record-plan.v1", "cases": actual_cases,
            "expected": [producer.independent_spec(case) for case in actual_cases],
            "source": report["source_before"], "tools": report["tools_before"],
            "max_steps": 100000, "max_heap_bytes": 16 * 1024 * 1024,
            "budget_cases": producer.budget_cases(),
            "budget_return_control": {"max_steps": 60, "max_heap_bytes": 1024},
            "process_timeout_seconds": 60, "explicit_process_attempts_retained": True,
            "production_compilation_evidence": "success receipt or reported exception; internal streams not intercepted"},
            "predeclared plan differs")
        clang = report["tools_before"]["clang"]
        rust_vm = report["tools_before"]["rust_vm"]["path"]
        for index, (case, row) in enumerate(zip(actual_cases, report["differential"])):
            _equal(row["index"], index, "differential order differs")
            _equal(row["case"], case, "differential case differs")
            options = {"max_steps": 100000, "max_heap_bytes": 16 * 1024 * 1024}
            if case["fail_at"]:
                options["allocation_fail_at"] = case["fail_at"]
            _equal(row["options"], options, "execution policy differs")
            raw = reader.process(row["rust_process"], argv=producer.rust_argv(
                rust_vm, case["function"], case["arguments"], options), stdin=core_bytes)
            _equal(_json(raw), row["rust"], "raw Rust observation differs")
            expected = producer.independent_spec(case)
            _equal(row["independent_expected"], expected, "independent scenario differs")
            bounded = finite["cases"][index]
            _require(set(bounded) == {"case_index", "receipt"}, "finite case fields differ")
            _equal(bounded["case_index"], index, "finite invocation case order differs")
            _equal(bounded["receipt"]["static_budget_sha256"], static["receipt"]["sha256"],
                   "finite invocation static budget identity differs")
            for name, input_sha in (("python_nominal", nominal.input_sha256), ("python_core", core.sha256), ("rust", None)):
                _execution(row[name], rust=name == "rust", core_sha=core.sha256, input_sha=input_sha,
                           function=case["function"], options=options, returned=True, result=expected["result"])
                _ledger(row[name]["resources"], returned=True, expected=expected)
                _partial_bound_observation(bounded["receipt"], summaries[case["function"]], row[name],
                    core_sha=core.sha256, input_sha=nominal.input_sha256,
                    function=case["function"], arguments=case["arguments"], limit_bytes=finite["limit_bytes"])
            for field in ("status", "steps", "resources", "program_sha256", "values"):
                _equal(row["python_nominal"][field], row["python_core"][field], "nominal/Core " + field + " differs")
                _equal(row["python_core"][field], row["rust"][field], "Core/Rust " + field + " differs")
        for index, (options, row) in enumerate(zip(producer.budget_cases(), report["budgets"])):
            _equal(row["options"], options, "budget order differs")
            raw = reader.process(row["rust_process"], argv=producer.rust_argv(
                rust_vm, "partial_case", [0, 7, 73], options), stdin=core_bytes)
            _equal(_json(raw), row["rust"], "raw budget observation differs")
            returned = options == {"max_steps": 60, "max_heap_bytes": 1024}
            error = None if returned else "steps" if options["max_steps"] < 100000 else "heap"
            bounded = finite["budgets"][index]
            _require(set(bounded) == {"budget_index", "options", "receipt"}, "finite budget fields differ")
            _equal(bounded["budget_index"], index, "finite invocation budget order differs")
            _equal(bounded["options"], options, "finite invocation budget policy differs")
            _equal(bounded["receipt"]["static_budget_sha256"], static["receipt"]["sha256"],
                   "finite budget static identity differs")
            for name in ("python", "rust"):
                _execution(row[name], rust=name == "rust", core_sha=core.sha256, input_sha=core.sha256,
                           function="partial_case", options=options, returned=returned, result=177, error=error)
                _partial_bound_observation(bounded["receipt"], summaries["partial_case"], row[name],
                    core_sha=core.sha256, input_sha=nominal.input_sha256,
                    function="partial_case", arguments=[0, 7, 73], limit_bytes=finite["limit_bytes"])
            for field in ("status", "steps", "resources", "program_sha256"):
                _equal(row["python"][field], row["rust"][field], "budget " + field + " differs")
        _require(reader.bytes("observer.c") == producer.observer_source().encode(), "allocator observer differs")
        normal_ir = {}
        for name, program in (("nominal", nominal), ("core", core)):
            group = report["native"][name]
            _require(type(group["cases"]) is list and len(group["cases"]) == len(actual_cases),
                     "incomplete native denominator")
            ir = normal_ir[name] = emit_program_llvm(program)
            _require(reader.bytes(name + ".ll") == ir.text.encode(), "retained LLVM differs from actual Core")
            _compilation(reader, group["compilation"], name=name, ir=ir, clang=clang)
            reader.executable(name, group["executable"])
            _link(reader, group["link_process"], name=name, clang=clang, producer=producer, normal=True)
            for index, (case, row) in enumerate(zip(actual_cases, group["cases"])):
                _equal(row["index"], index, "native case order differs")
                observed = _json(reader.process(row["process"], argv=[reader.directory / name, str(index)]))
                _equal(observed, row["observed"], "raw native observation differs")
                _equal(observed, producer.native_spec(case), "native allocator/value/order differs from scenario")
        _negative_controls(reader, report["negative_controls"], producer=producer, nominal_ir=normal_ir["nominal"],
                           clang=clang, pair_scope=pair_scope)
        reader.manifest()
        _equal(report["source_before"], producer.source_identity(), "source changed during receipt intake")
        for item in report["tools_before"].values():
            _equal(item, producer.descriptor(item["path"]), "selected tool changed during receipt intake")
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise ValueError("Malformed partial-record qualification receipt") from exc


def _negative_controls(reader, controls, *, producer, nominal_ir, clang, pair_scope):
    from hepta.hia_program import verify_core
    from hepta.hia_program_llvm import emit_program_llvm
    directory = reader.directory
    expected_names = ["missing_free", "wrong_byte"] + (["wrong_cleanup_order"] if pair_scope else [])
    _equal([row["name"] for row in controls], expected_names, "negative controls missing or reordered")
    selected = producer.cases().index({"function": "partial_case", "arguments": [0, 7, 73], "fail_at": 0})
    expected = producer.independent_spec(producer.cases()[selected])
    missing = "\n".join(line for line in nominal_ir.text.splitlines() if "call void @free(" not in line) + "\n"
    _require(missing != nominal_ir.text and reader.bytes("missing-free.ll") == missing.encode(),
             "missing-free control LLVM differs")
    row = controls[0]
    _require(row["qualified_hia_artifact"] is False and row["detected"] is True, "missing-free scope differs")
    reader.process(row["compile_process"], argv=[clang["path"], "-x", "ir", "-O3", "-c",
                   directory / "missing-free.ll", "-o", directory / "missing-free.o"])
    _object(reader, "missing-free", nominal_ir.exports)
    _link(reader, row["link_process"], name="missing-free", clang=clang, producer=producer)
    reader.executable("missing-free", reader.descriptor("missing-free"))
    observed = _json(reader.process(row["run_process"], argv=[directory / "missing-free", str(selected)], expected=91))
    _equal(observed, row["observed"], "raw missing-free observation differs")
    # A correct scalar result must still expose all three unreleased payloads.
    bad = {"result": expected["result"], "attempts": 3, "allocations": 3, "frees": 0,
           "live": 3, "live_bytes": 21, "peak_bytes": 21, "refusals": 0,
           "invalid_frees": 0, "null_frees": 0, "free_order": []}
    _equal(observed, bad, "missing-free control no longer exposes the actual leak")
    wrong_document = deepcopy(producer.program())
    replacements = 0
    for fn in wrong_document["functions"]:
        for block in fn["blocks"]:
            for op in block["ops"]:
                if op["op"] == "const" and op["out"][0]["name"] == "salt":
                    op["attrs"]["value"] = 18
                    replacements += 1
    _require(replacements == 1, "wrong-byte mutation is not unique")
    _equal(_json(reader.bytes("wrong-byte-input.json")), wrong_document, "wrong-byte input differs")
    wrong_core = verify_core(wrong_document)
    ir = emit_program_llvm(wrong_core)
    _require(reader.bytes("wrong-byte-core.json") == wrong_core.canonical_bytes, "wrong-byte Core differs")
    _require(reader.bytes("wrong-byte.ll") == ir.text.encode(), "wrong-byte LLVM differs")
    row = controls[1]
    _require(row["detected"] is True and row["equivalent_to_original"] is False, "wrong-byte scope differs")
    _compilation(reader, row["compilation"], name="wrong-byte", ir=ir, clang=clang)
    _link(reader, row["link_process"], name="wrong-byte", clang=clang, producer=producer)
    reader.executable("wrong-byte", reader.descriptor("wrong-byte"))
    observed = _json(reader.process(row["run_process"], argv=[directory / "wrong-byte", str(selected)]))
    _equal(observed, row["observed"], "raw wrong-byte observation differs")
    bad = producer.native_spec(producer.cases()[selected])
    bad["result"] += 1
    _equal(observed, bad, "wrong-byte control is not the expected clean-resource value error")
    if pair_scope:
        wrong_document = deepcopy(producer.program())
        definitions = [fn for fn in wrong_document["functions"] if fn["name"] == "dispose_full"]
        _require(len(definitions) == 1, "cleanup mutation is not unique")
        replacement = producer.cleanup("dispose_full", ["first", "second", "tag"], reverse=False)
        _require(replacement != definitions[0], "cleanup mutation made no change")
        wrong_document["functions"][wrong_document["functions"].index(definitions[0])] = replacement
        _equal(_json(reader.bytes("wrong-cleanup-order-input.json")), wrong_document, "cleanup control input differs")
        wrong_core = verify_core(wrong_document)
        ir = emit_program_llvm(wrong_core)
        _require(reader.bytes("wrong-cleanup-order-core.json") == wrong_core.canonical_bytes,
                 "cleanup control Core differs")
        _require(reader.bytes("wrong-cleanup-order.ll") == ir.text.encode(), "cleanup control LLVM differs")
        row = controls[2]
        selected = producer.cases().index({"function": "partial_pair_task", "arguments": [0, 7, 73], "fail_at": 0})
        _equal(row["case_index"], selected, "cleanup control case differs")
        _require(row["detected"] is True and row["equivalent_to_original"] is False, "cleanup control scope differs")
        _compilation(reader, row["compilation"], name="wrong-cleanup-order", ir=ir, clang=clang)
        _link(reader, row["link_process"], name="wrong-cleanup-order", clang=clang, producer=producer)
        reader.executable("wrong-cleanup-order", reader.descriptor("wrong-cleanup-order"))
        observed = _json(reader.process(row["run_process"], argv=[directory / "wrong-cleanup-order", str(selected)]))
        expected = producer.native_spec(producer.cases()[selected])
        _equal(row["expected"], expected, "cleanup control independent expectation differs")
        _equal(expected["free_order"], [2, 1], "cleanup control no longer selects two live owners")
        _equal(observed, row["observed"], "raw cleanup control observation differs")
        bad = dict(expected, free_order=[1, 2])
        _equal(observed, bad, "cleanup control no longer isolates the wrong release order")

