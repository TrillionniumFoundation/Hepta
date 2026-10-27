"""Real Rust qualification of the finite generic/view/Result/task composition.

Original generated code, allocator observation and induced-leak control are
different artifacts. Invalid Hepta candidates are never linked or executed.
This does not extend Executable Core, Resource IR or C to stored lifetimes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.executable_core import ExecutableCoreRejected, lower_executable_core
from hepta.pipeline import analyze, compiler_hash, resource_ir_analysis
from tools.qualify_borrowed_storage import native_diagnostics

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "examples/composition/lifecycle.hepta"
SCHEMA = "hepta.lifecycle-composition-qualification.v1"
EXPECTED_STDOUT = "136\n1013\n2253\n"
DENOMINATOR = {"original_executions": 1, "branches_per_execution": 3,
    "owner_observer_executions": 1, "induced_leak_control_executions": 1,
    "native_lifetime_rejections": 2, "frontend_rejections": 4,
    "invalid_hepta_candidate_executions": 0}
CLAIMS = {"original_generated_program_executed": True,
    "address_registered_owner_allocation_balance_observed": True,
    "induced_native_leak_detected": True,
    "invalid_hepta_candidates_executed": False,
    "frontend_independently_proves_stored_lifetimes": False,
    "composition_supported_by_executable_core": False,
    "composition_supported_by_independent_resource_ir": False,
    "composition_supported_by_c_backend": False,
    "all_runtime_allocations_balanced": False,
    "cancellation_latency_bounded": False,
    "already_blocked_worker_interrupted": False,
    "arbitrary_schedule_termination_proved": False,
    "general_lifetime_generic_composition_proved": False,
    "whole_language_soundness_proved": False,
    "performance_advantage_measured": False}
ASSURANCE_TABLE = [
    {"area": "Owned generics and Result", "scope": "forward<Buffer<u8>>, finish<Buffer<u8>,u8>",
     "static": "Hepta explicit transfers/consumption; Rust checks generated bodies",
     "runtime": "normal 136 and error 1013; corresponding registered buffers freed",
     "external": "correct Rust compiler, standard library, allocator and target execution"},
    {"area": "Stored views", "scope": "Bytes/Edit remain within a worker and borrow its owner",
     "static": "Hepta structural/affine checks; mandatory Rust regions and alias checks",
     "runtime": "mutable fill and copied shared-view sum produce expected results",
     "external": "Rust lifetime checker/backend; runtime results alone do not prove alias safety"},
    {"area": "Task cancellation", "scope": "three Buffer transfers and one join per task",
     "static": "owner reuse, missing join and duplicate join rejected",
     "runtime": "worker observes flag, frees owner and returns 2253 before join completes",
     "external": "host scheduling/progress; flag may be set before the worker's first poll"},
    {"area": "Allocator observation", "scope": "three registered Buffer addresses and allocation generations",
     "static": "separate instrumented Rust observer outside original Hepta semantics",
     "runtime": "GlobalAlloc callbacks show 3 allocations/3 frees; induced forget control exposes 2 leaks",
     "external": "System obeys GlobalAlloc contract; other process allocations are not qualified"},
    {"area": "Other compiler profiles", "scope": "entire unchanged composition module",
     "static": "C, independent Resource IR and Executable Core reject stored-view composition",
     "runtime": "no execution through these profiles",
     "external": "no cross-profile equivalence or universal core integration claim"},
]

# Bookkeeping has no allocation, formatting, unwinding or user callbacks while
# locked. Slots are never reused: allocator address reuse creates a generation.
ALLOCATOR_OBSERVER = r'''
mod __hepta_owner_observer {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    struct Slot { address: AtomicUsize, size: AtomicUsize, live: AtomicUsize,
                  begin: AtomicUsize, end: AtomicUsize, owner: AtomicUsize }
    impl Slot {
        const fn new() -> Self { Self { address: AtomicUsize::new(0), size: AtomicUsize::new(0),
            live: AtomicUsize::new(0), begin: AtomicUsize::new(0), end: AtomicUsize::new(0),
            owner: AtomicUsize::new(0) } }
    }
    static LOCK: AtomicBool = AtomicBool::new(false);
    static ERROR: AtomicUsize = AtomicUsize::new(0);
    static USED: AtomicUsize = AtomicUsize::new(0);
    static SLOTS: [Slot; 256] = [const { Slot::new() }; 256];
    static OWNERS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
    static REALLOCS: AtomicUsize = AtomicUsize::new(0);
    fn lock() { while LOCK.compare_exchange(false, true, SeqCst, SeqCst).is_err() { std::hint::spin_loop(); } }
    fn unlock() { LOCK.store(false, SeqCst); }
    fn error(code: usize) { let _ = ERROR.compare_exchange(0, code, SeqCst, SeqCst); }
    fn selected(size: usize) -> bool { size == 17 || size == 19 || size == 23 }
    fn begin(address: usize, size: usize, api: usize) {
        if address == 0 || !selected(size) { return; }
        let n = USED.load(SeqCst);
        if n == SLOTS.len() { error(1); return; }
        for slot in &SLOTS[..n] {
            if slot.address.load(SeqCst) == address && slot.live.load(SeqCst) == 1 { error(2); }
        }
        let slot = &SLOTS[n];
        slot.address.store(address, SeqCst); slot.size.store(size, SeqCst);
        slot.begin.store(api, SeqCst); slot.live.store(1, SeqCst);
        USED.store(n + 1, SeqCst);
    }
    fn end(address: usize, size: usize, api: usize) {
        for slot in &SLOTS[..USED.load(SeqCst)] {
            if slot.address.load(SeqCst) == address && slot.live.load(SeqCst) == 1 {
                if slot.size.load(SeqCst) != size { error(3); }
                if api == 2 && slot.owner.load(SeqCst) != 0 { REALLOCS.fetch_add(1, SeqCst); }
                slot.live.store(0, SeqCst); slot.end.store(api, SeqCst); return;
            }
        }
        if selected(size) { error(4); }
    }
    pub struct Observer;
    unsafe impl GlobalAlloc for Observer {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc(layout); lock(); begin(p as usize, layout.size(), 1); unlock(); p
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc_zeroed(layout); lock(); begin(p as usize, layout.size(), 2); unlock(); p
        }
        unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
            lock(); end(p as usize, layout.size(), 1); unlock(); System.dealloc(p, layout);
        }
        unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            lock();
            let next = System.realloc(p, layout, new_size);
            if !next.is_null() { end(p as usize, layout.size(), 2); begin(next as usize, new_size, 3); }
            unlock(); next
        }
    }
    pub fn register(mode: usize, value: &Vec<u8>) {
        lock();
        if mode >= 3 || value.len() != [17, 19, 23][mode] || value.capacity() != value.len() {
            error(5); unlock(); return;
        }
        if OWNERS[mode].load(SeqCst) != 0 { error(6); unlock(); return; }
        let address = value.as_ptr() as usize;
        let mut found = false;
        for (index, slot) in SLOTS[..USED.load(SeqCst)].iter().enumerate() {
            if slot.address.load(SeqCst) == address && slot.live.load(SeqCst) == 1 {
                if slot.owner.load(SeqCst) != 0 || slot.size.load(SeqCst) != value.capacity()
                    || ![1, 2].contains(&slot.begin.load(SeqCst)) { error(7); }
                slot.owner.store(mode + 1, SeqCst); OWNERS[mode].store(index + 1, SeqCst); found = true;
            }
        }
        if !found { error(8); }
        unlock();
    }
    pub fn report() {
        let mut rows = [[0usize; 7]; 3];
        lock();
        for mode in 0..3 {
            let generation = OWNERS[mode].load(SeqCst);
            if generation == 0 { error(9); continue; }
            let slot = &SLOTS[generation - 1];
            rows[mode] = [generation, slot.address.load(SeqCst), slot.size.load(SeqCst),
                          usize::from([1, 2].contains(&slot.begin.load(SeqCst))),
                          usize::from(slot.end.load(SeqCst) == 1), slot.live.load(SeqCst),
                          slot.begin.load(SeqCst)];
        }
        let code = ERROR.load(SeqCst); let reallocations = REALLOCS.load(SeqCst);
        unlock();
        let good = code == 0 && reallocations == 0 && rows.iter().all(|r| r[1] != 0 && r[3] == 1 && r[4] == 1 && r[5] == 0);
        eprint!("{{\"error_code\":{},\"owner_reallocations\":{},\"owners\":[", code, reallocations);
        for mode in 0..3 {
            let r = rows[mode];
            if mode != 0 { eprint!(","); }
            eprint!("{{\"mode\":{},\"generation\":{},\"address\":{},\"bytes\":{},\"allocations\":{},\"frees\":{},\"live\":{},\"allocation_api\":{}}}",
                    mode, r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
        }
        eprintln!("]}}");
        if !good { std::process::exit(91); }
    }
}
#[global_allocator]
static __HEPTA_OBSERVED_ALLOCATOR: __hepta_owner_observer::Observer = __hepta_owner_observer::Observer;
'''


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _replace_once(source, before, after):
    _require(source.count(before) == 1, "Frozen mutation target changed: " + before[:100])
    return source.replace(before, after, 1)


def rejection_candidates(source):
    return [
        {"name": "shared_view_live_after_owner_transfer", "stage": "rustc", "codes": ["E0505"],
         "source": _replace_once(source, "Result::Err(code) => { return 1000 + code as u64; }",
              "Result::Err(code) => { assert(len(snapshot.data) > 0); return 1000 + code as u64; }")},
        {"name": "owner_read_while_mutable_view_live", "stage": "rustc", "codes": ["E0502"],
         "source": _replace_once(source, "    drop(move changing);",
              "    assert(len(owner) > 0);\n    drop(move changing);")},
        {"name": "generic_error_branch_leaves_owner", "stage": "frontend", "codes": ["E_LINEAR_UNCONSUMED"],
         "source": _replace_once(source, "if !success { drop(move value); return Result::Err(error); }",
              "if !success { return Result::Err(error); }")},
        {"name": "owner_reused_after_spawn", "stage": "frontend", "codes": ["E_USE_AFTER_MOVE"],
         "source": _replace_once(source, "let normal = spawn(worker, move payload(0, 17));",
              "let sent = payload(0, 17); let normal = spawn(worker, move sent); assert(len(sent) == 17);")},
        {"name": "cancel_path_omits_join", "stage": "frontend", "codes": ["E_LINEAR_UNCONSUMED"],
         "source": _replace_once(source, "let cancelled_result = cancel_and_join(move pending);",
              "let cancelled_result: u64 = 2253;")},
        {"name": "task_joined_twice", "stage": "frontend", "codes": ["E_USE_AFTER_MOVE"],
         "source": _replace_once(source, "let cancelled_result = cancel_and_join(move pending);",
              "let cancelled_result = cancel_and_join(move pending); join(move pending);")},
    ]


def instrument_generated_rust(generated, *, leak=False):
    _require(generated.count("fn h_payload(h_mode: u8, h_size: usize)") == 1,
             "Expected generated payload signature changed")
    observed = _replace_once(generated, "    return h_data;\n",
        "    __hepta_owner_observer::register(h_mode as usize, &h_data);\n    return h_data;\n")
    observed = _replace_once(observed, "fn main() { h_main(); }",
                            "fn main() { h_main(); __hepta_owner_observer::report(); }")
    if leak:
        _require(observed.count("core::mem::drop(h_retained);") == 2, "Leak mutation target changed")
        observed = observed.replace("core::mem::drop(h_retained);", "core::mem::forget(h_retained);")
    return observed + "\n" + ALLOCATOR_OBSERVER


def _process(command, *, timeout=30):
    run = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return {"argv": list(map(str, command)), "returncode": run.returncode,
            "stdout": run.stdout, "stderr": run.stderr,
            "stdout_sha256": _sha(run.stdout.encode()), "stderr_sha256": _sha(run.stderr.encode())}


def _execute_rust(name, generated, folder, compiler):
    artifact = folder / name
    build = compile_rust(generated, rustc=compiler, crate_type="bin", output=artifact)
    _require(build.get("ok") is True, "Native Rust build failed: " + name + ": " + str(build))
    raw = artifact.read_bytes()
    _require(_sha(raw) == build.get("artifact_sha256"), "Build/artifact hash differs")
    execution = _process([str(artifact)], timeout=15)
    _require(artifact.read_bytes() == raw, "Native artifact changed during execution")
    return {"name": name, "generated_source": generated, "generated_source_sha256": _sha(generated.encode()),
            "build": build, "execution": execution, "artifact_retained": False,
            "artifact_sha256": _sha(raw), "artifact_bytes": len(raw)}


def _unsupported(source, source_path, frontend):
    c = analyze(source, source_path, native=False, backend="c", crate_type="bin")
    resource = resource_ir_analysis(frontend)
    try:
        lower_executable_core(frontend.program, frontend.checked)
    except ExecutableCoreRejected as exc:
        core = {"ok": False, "diagnostic": str(exc), "executed": False}
    else:
        raise ValueError("Composition unexpectedly entered Executable Core")
    _require(c.report.get("ok") is False and c.c is None and resource.get("ok") is False,
             "Unsupported stored-view backend unexpectedly accepted")
    return {"c_backend": c.report, "independent_resource_ir": resource, "executable_core": core}


def _check_observation(payload, *, leak):
    _require(type(payload) is dict and set(payload) == {"error_code", "owner_reallocations", "owners"},
             "Unexpected observer output")
    _require(type(payload["error_code"]) is int and payload["error_code"] == 0
             and type(payload["owner_reallocations"]) is int and payload["owner_reallocations"] == 0,
             "Observer errors or unreviewed reallocations")
    rows = payload["owners"]
    _require(type(rows) is list and len(rows) == 3, "Missing registered owners")
    for mode, (row, size) in enumerate(zip(rows, [17, 19, 23])):
        _require(type(row) is dict and set(row) == {"mode", "generation", "address", "bytes", "allocations", "frees", "live", "allocation_api"}
                 and all(type(value) is int for value in row.values()), "Malformed owner observation")
        frees = 0 if leak and mode in {0, 2} else 1
        _require(row["mode"] == mode and row["generation"] > 0 and row["address"] > 0
                 and row["bytes"] == size and row["allocations"] == 1
                 and row["frees"] == frees and row["live"] == 1 - frees
                 and row["allocation_api"] in {1, 2}, "Owner allocation/free balance differs")
    _require(len({r["generation"] for r in rows}) == 3, "Allocation generations were conflated")
    return {"registered_owners": 3, "owner_bytes": 59, "allocations": 3,
            "frees": 1 if leak else 3, "live_allocations": 2 if leak else 0,
            "live_bytes": 40 if leak else 0}


def qualify(output=None, *, rustc=None):
    output = Path(output).absolute() if output is not None else None
    if output is not None:
        _require(not output.exists() and not output.is_symlink() and output.parent.is_dir(),
                 "Report must be a new file in an existing directory")
    source = ENTRY.read_text()
    compiler_identity = compiler_hash()
    qualifier_identity = _sha(Path(__file__).read_bytes())
    report = {"schema": SCHEMA, "ok": False, "status": "running",
              "source_path": str(ENTRY), "source": source, "source_sha256": _sha(source.encode()),
              "compiler_sha256": compiler_identity, "qualifier_sha256": qualifier_identity,
              "scope_static_runtime_external": ASSURANCE_TABLE,
              "claims": {key: False for key in CLAIMS},
              "native_rejections": [], "frontend_rejections": []}
    try:
        toolchain = toolchain_info(find_rustc(rustc))
        compiler = toolchain["path"]
        _require("release: 1.90.0" in toolchain["version"].splitlines(), "Pinned Rust 1.90.0 required")
        report["rust_toolchain"] = toolchain
        frontend = analyze(source, str(ENTRY), native=False, crate_type="bin")
        _require(frontend.report.get("ok") is True and frontend.rust is not None, "Composition frontend rejected")
        report["frontend"] = frontend.report
        report["unsupported_profiles"] = _unsupported(source, str(ENTRY), frontend)
        with tempfile.TemporaryDirectory(prefix="hepta-lifecycle-composition-") as td:
            folder = Path(td)
            original = _execute_rust("original", frontend.rust, folder, compiler)
            report["original"] = original
            _require(original["execution"]["returncode"] == 0 and original["execution"]["stdout"] == EXPECTED_STDOUT
                     and original["execution"]["stderr"] == "", "Original composition results differ")
            report["branch_results"] = [136, 1013, 2253]
            for name, leak in [("owner_observation", False), ("induced_leak_control", True)]:
                row = _execute_rust(name, instrument_generated_rust(frontend.rust, leak=leak), folder, compiler)
                report[name] = row
                _require(row["execution"]["returncode"] == (91 if leak else 0)
                         and row["execution"]["stdout"] == EXPECTED_STDOUT, "Unexpected observer/control result")
                observation = json.loads(row["execution"]["stderr"])
                row["observation"] = observation
                row["balance"] = _check_observation(observation, leak=leak)
                row["instrumentation"] = {"registered_exact_owner_addresses": True,
                    "allocator": "std::alloc::System with fixed atomic event registry",
                    "observer_sha256": _sha(ALLOCATOR_OBSERVER.encode()), "generated_program_altered": True,
                    "alteration": "register payload addresses and observe post-join balances" +
                                  ("; replace both retained-owner drops with mem::forget" if leak else ""),
                    "all_process_allocations_measured": False}
            for case in rejection_candidates(source):
                path = folder / (case["name"] + ".hepta")
                result = analyze(case["source"], str(path), native=False, crate_type="bin")
                row = {**case, "source_path": str(path), "source_sha256": _sha(case["source"].encode()),
                       "frontend": result.report, "native_execution_attempted": False}
                if case["stage"] == "frontend":
                    report["frontend_rejections"].append(row)
                    row["native_compilation_attempted"] = False
                    _require(result.report.get("ok") is False and result.rust is None
                             and set(case["codes"]) <= {d["code"] for d in result.report["diagnostics"]},
                             "Frontend negative failed: " + case["name"])
                    continue
                report["native_rejections"].append(row)
                _require(result.report.get("ok") is True and result.rust is not None,
                         "Lifetime candidate did not reach Rust: " + case["name"])
                generated, metadata = folder / (case["name"] + ".rs"), folder / (case["name"] + ".rmeta")
                generated.write_text(result.rust)
                command = [compiler, str(generated), "--edition=2021", "--crate-name=hepta_lifecycle_candidate",
                           "--crate-type=lib", "--emit=metadata", "-C", "opt-level=0", "-C", "overflow-checks=yes",
                           "-C", "panic=abort", "--error-format=json", "-o", str(metadata)]
                if toolchain.get("sysroot"):
                    command += ["--sysroot", toolchain["sysroot"]]
                check = _process(command)
                row.update(native_compilation_attempted=True, generated_source=result.rust,
                           generated_source_sha256=_sha(result.rust.encode()), native_check=check,
                           metadata_emitted=metadata.exists(), native_link_attempted=False,
                           diagnostics=native_diagnostics(check["stderr"], result.rust, str(generated)))
                _require(check["returncode"] != 0 and not metadata.exists()
                         and set(case["codes"]) <= {d["code"] for d in row["diagnostics"]},
                         "Native lifetime rejection failed: " + case["name"])
        _require(ENTRY.read_text() == source and compiler_hash() == compiler_identity
                 and _sha(Path(__file__).read_bytes()) == qualifier_identity
                 and toolchain_info(compiler) == toolchain, "Source, qualifier or toolchain changed")
        report.update(ok=True, status="finite_rust_composition_passed", denominator=dict(DENOMINATOR), claims=dict(CLAIMS))
        report["sha256"] = _sha(_json(report))
        validate_report(report)
    except Exception as exc:
        report.pop("sha256", None)
        report.update(ok=False, status="rejected", claims={key: False for key in CLAIMS},
                      error={"type": type(exc).__name__, "message": str(exc)})
    if output is not None:
        with output.open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    return report


def _validate_process(process, expected_returncode, expected_stdout=None):
    _require(type(process) is dict and type(process.get("returncode")) is int
             and process["returncode"] == expected_returncode, "Unexpected process result")
    _require(type(process.get("argv")) is list and process["argv"]
             and all(type(item) is str for item in process["argv"]), "Missing process argv")
    for stream in ("stdout", "stderr"):
        _require(type(process.get(stream)) is str and process.get(stream + "_sha256") == _sha(process[stream].encode()),
                 "Process transcript hash differs")
    if expected_stdout is not None:
        _require(process["stdout"] == expected_stdout, "Program output differs")


def validate_report(report):
    """Replay source-derived evidence; this is not execution attestation."""
    _require(type(report) is dict and report.get("schema") == SCHEMA and report.get("ok") is True
             and report.get("status") == "finite_rust_composition_passed", "Not a passing composition report")
    _require(report.get("sha256") == _sha(_json({k: v for k, v in report.items() if k != "sha256"})), "Report digest differs")
    source = ENTRY.read_text()
    _require(report.get("source_path") == str(ENTRY) and report.get("source") == source
             and report.get("source_sha256") == _sha(source.encode())
             and report.get("compiler_sha256") == compiler_hash()
             and report.get("qualifier_sha256") == _sha(Path(__file__).read_bytes()), "Source/qualifier/compiler changed")
    _require(_json(report.get("claims")) == _json(CLAIMS)
             and _json(report.get("scope_static_runtime_external")) == _json(ASSURANCE_TABLE), "Assurance scope was inflated")
    _require(_json(report.get("denominator")) == _json(DENOMINATOR)
             and _json(report.get("branch_results")) == _json([136, 1013, 2253]), "Qualification denominator differs")
    frontend = analyze(source, str(ENTRY), native=False, crate_type="bin")
    _require(_json(report.get("frontend")) == _json(frontend.report), "Original frontend differs")
    _require(_json(report.get("unsupported_profiles")) == _json(_unsupported(source, str(ENTRY), frontend)), "Unsupported profile boundary changed")
    toolchain = report.get("rust_toolchain", {})
    _require(type(toolchain) is dict and "release: 1.90.0" in toolchain.get("version", "").splitlines()
             and toolchain.get("path") and toolchain == toolchain_info(toolchain["path"]), "Pinned Rust identity changed")
    for name, leak in [("original", None), ("owner_observation", False), ("induced_leak_control", True)]:
        row = report.get(name, {})
        generated = frontend.rust if leak is None else instrument_generated_rust(frontend.rust, leak=leak)
        _require(row.get("generated_source") == generated and row.get("generated_source_sha256") == _sha(generated.encode()),
                 "Generated program differs: " + name)
        build = row.get("build", {})
        _require(build.get("ok") is True and build.get("status") == "rustc_checked"
                 and build.get("check_only") is False and build.get("crate_type") == "bin"
                 and build.get("rust_sha256") == row["generated_source_sha256"]
                 and build.get("toolchain") == toolchain and build.get("target") == toolchain.get("host")
                 and build.get("artifact_sha256") == row.get("artifact_sha256") == build.get("validation_artifact_sha256")
                 and type(row.get("artifact_bytes")) is int and row["artifact_bytes"] > 0
                 and row["artifact_bytes"] == build.get("artifact_bytes")
                 and row.get("artifact_retained") is False, "Native build receipt differs: " + name)
        _require({"overflow-checks=yes", "panic=abort", "edition=2021"} <= set(build.get("flags", [])), "Native safety flags missing")
        process = row.get("execution")
        _validate_process(process, 91 if leak else 0, EXPECTED_STDOUT)
        _require(process["argv"] == [build["artifact"]], "Executed artifact differs")
        if leak is None:
            _require(process["stderr"] == "", "Original program unexpectedly produced observer output")
        else:
            _require(row.get("observation") == json.loads(process["stderr"]), "Observer output differs from native stderr")
            _require(_json(row.get("balance")) == _json(_check_observation(row["observation"], leak=leak)), "Owner totals differ")
            _require(row.get("instrumentation", {}).get("generated_program_altered") is True
                     and row["instrumentation"].get("observer_sha256") == _sha(ALLOCATOR_OBSERVER.encode())
                     and row["instrumentation"].get("all_process_allocations_measured") is False, "Observer scope differs")
    for stage, key in [("rustc", "native_rejections"), ("frontend", "frontend_rejections")]:
        expected = [case for case in rejection_candidates(source) if case["stage"] == stage]
        rows = report.get(key, [])
        _require(type(rows) is list and [r.get("name") for r in rows] == [r["name"] for r in expected], "Negative denominator differs")
        for row, case in zip(rows, expected):
            _require(all(row.get(k) == v for k, v in case.items()) and row.get("source_sha256") == _sha(case["source"].encode())
                     and row.get("native_execution_attempted") is False, "Negative source/execution claim differs")
            checked = analyze(case["source"], row["source_path"], native=False, crate_type="bin")
            _require(_json(row.get("frontend")) == _json(checked.report), "Negative frontend differs")
            if stage == "frontend":
                _require(checked.report["ok"] is False and checked.rust is None
                         and row.get("native_compilation_attempted") is False
                         and set(case["codes"]) <= {d["code"] for d in checked.report["diagnostics"]}, "Frontend negative accepted")
            else:
                _require(checked.report["ok"] is True and row.get("generated_source") == checked.rust
                         and row.get("generated_source_sha256") == _sha(checked.rust.encode())
                         and row.get("native_compilation_attempted") is True
                         and row.get("native_link_attempted") is False and row.get("metadata_emitted") is False,
                         "Native negative did not remain metadata-only")
                process = row.get("native_check", {})
                _validate_process(process, 1, "")
                _require(process["argv"][0] == toolchain["path"] and "--emit=metadata" in process["argv"]
                         and "--crate-type=lib" in process["argv"], "Native negative command differs")
                diagnostics = native_diagnostics(process["stderr"], checked.rust, process["argv"][1])
                _require(row.get("diagnostics") == diagnostics and set(case["codes"]) <= {d["code"] for d in diagnostics}, "Native diagnostics differ")
                _require(any(m.get("is_primary") and m.get("span", {}).get("path") == row["source_path"]
                             for d in diagnostics for m in d.get("source_mappings", [])), "Lost native diagnostic source mapping")
    return {"ok": True, "registered_owner_allocations": 3, "registered_owner_frees": 3,
            "registered_owner_live": 0, "rejected_candidates": 6, "invalid_candidate_executions": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "--report", dest="output", type=Path)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    args = parser.parse_args(argv)
    try:
        report = qualify(args.output, rustc=args.rustc)
    except (ValueError, OSError) as exc:
        parser.exit(1, str(exc) + "\n")
    if args.output is None:
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    else:
        print(json.dumps({"ok": report["ok"], "status": report["status"],
                          "output": str(args.output), "error": report.get("error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
