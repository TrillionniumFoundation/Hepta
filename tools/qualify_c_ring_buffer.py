"""Freeze, translate and execute a complete upstream stateful C ring-buffer.

The unchanged upstream C owns no allocation. Its caller-owned storage becomes
explicit borrowed Hepta slices, with a separately exercised Buffer owner client.
Finite differentials, ABI probes and fault controls do not prove equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_rust
from hepta.checker import check
from hepta.c_migrate import migrate_c_project
from hepta.parser import parse
from tools.qualify_c_migration import command, sha, RUST_FAULT_ALLOCATOR

FIXTURE = ROOT / "tests/fixtures/c_migration/ring_buffer"
UPSTREAM_COMMIT = "8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba"
EXPECTED_BLOBS = {'ringbuffer.c': '39fbea599e9e2c62561f1cd2e80bb08717e9e656', 'ringbuffer.h': '36da6eb18805853f79f5b558714204517fd969a0', 'LICENSE': '4e5491e49deef7fce4c58480177f501d8cc8dea9', 'UPSTREAM_README.md': '9936f6af274d25abdc0a87f77595df41d49a25d7'}
FLAGS = ["-std=c11", "-DNDEBUG", "-funsigned-char"]


class Ring(ctypes.Structure):
    _fields_ = [("buffer", ctypes.POINTER(ctypes.c_uint8)), ("buffer_mask", ctypes.c_size_t),
                ("tail_index", ctypes.c_size_t), ("head_index", ctypes.c_size_t)]


def verify_upstream():
    metadata = json.loads((FIXTURE / "UPSTREAM.json").read_text())
    if metadata["commit"] != UPSTREAM_COMMIT or {entry["local_path"]: entry["git_blob"] for entry in metadata["files"]} != EXPECTED_BLOBS:
        raise RuntimeError("Frozen upstream source identity or complete file inventory changed")
    for entry in metadata["files"]:
        data = (FIXTURE / entry["local_path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != entry["git_blob"] or hashlib.sha256(data).hexdigest() != entry["sha256"] or len(data) != entry["bytes"]:
            raise RuntimeError("Upstream file changed: " + entry["local_path"])
    return metadata


def capture_fixture(work):
    metadata = verify_upstream()
    for entry in metadata["files"]:
        shutil.copyfile(FIXTURE / entry["local_path"], work / entry["local_path"])
    database = work / "compile_commands.json"
    database.write_text(json.dumps([{"directory": str(work), "file": "ringbuffer.c",
                                     "arguments": ["clang", *FLAGS, "-O2", "-c", "ringbuffer.c"]}]))
    return database


def configure(path):
    lib = ctypes.CDLL(str(path))
    record, data, size = ctypes.POINTER(Ring), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
    declarations = {
        "init": ([record, data, size], None), "queue": ([record, ctypes.c_uint8], None),
        "queue_arr": ([record, data, size], None), "dequeue": ([record, data], ctypes.c_uint8),
        "dequeue_arr": ([record, data, size], size), "peek": ([record, data, size], ctypes.c_uint8),
        "is_empty": ([record], ctypes.c_uint8), "is_full": ([record], ctypes.c_uint8),
        "num_items": ([record], size)}
    for name, (arguments, result) in declarations.items():
        fn = getattr(lib, "ring_buffer_" + name)
        fn.argtypes, fn.restype = arguments, result
    return lib


def run_sequences(original, translated, *, seed=827203, steps=2048):
    c, h = configure(original), configure(translated)
    calls, observations, resets, zero_length = Counter(), 0, 0, 0
    capacities = [1, 2, 4, 8, 16, 32, 64, 256]
    for capacity in capacities:
        cb, hb = (ctypes.c_uint8 * capacity)(), (ctypes.c_uint8 * capacity)()
        cr, hr = Ring(), Ring()
        c.ring_buffer_init(ctypes.byref(cr), cb, capacity)
        h.ring_buffer_init(ctypes.byref(hr), hb, capacity)
        calls["init"] += 1
        expected = deque(maxlen=capacity - 1)
        rng = random.Random(seed + capacity)
        for step in range(steps):
            operation = step % 6 if step < 24 else rng.randrange(6)
            if operation == 0:
                value = rng.randrange(256)
                c.ring_buffer_queue(ctypes.byref(cr), value)
                h.ring_buffer_queue(ctypes.byref(hr), value)
                expected.append(value)
                calls["queue"] += 1
            elif operation == 1:
                count = 0 if step < 24 else rng.randrange(2 * capacity + 1)
                values = [rng.randrange(256) for _ in range(count)]
                source = (ctypes.c_uint8 * count)(*values)
                ptr = source if count else None
                c.ring_buffer_queue_arr(ctypes.byref(cr), ptr, count)
                h.ring_buffer_queue_arr(ctypes.byref(hr), ptr, count)
                if list(source) != values:
                    raise AssertionError("Read input mutated")
                expected.extend(values)
                calls["queue_arr"] += 1
                zero_length += count == 0
            elif operation == 2:
                co, ho = ctypes.c_uint8(173), ctypes.c_uint8(173)
                a, b = c.ring_buffer_dequeue(ctypes.byref(cr), ctypes.byref(co)), h.ring_buffer_dequeue(ctypes.byref(hr), ctypes.byref(ho))
                existed = bool(expected)
                value = expected.popleft() if existed else 173
                if (a, co.value) != (b, ho.value) or (b, ho.value) != (int(existed), value):
                    raise AssertionError(("dequeue", capacity, step, a, b, co.value, ho.value, value))
                calls["dequeue"] += 1
            elif operation == 3:
                count = 0 if step < 24 else rng.randrange(2 * capacity + 1)
                co, ho = (ctypes.c_uint8 * (count + 2))(*([173] * (count + 2))), (ctypes.c_uint8 * (count + 2))(*([173] * (count + 2)))
                a = c.ring_buffer_dequeue_arr(ctypes.byref(cr), co if count else None, count)
                b = h.ring_buffer_dequeue_arr(ctypes.byref(hr), ho if count else None, count)
                wanted = min(count, len(expected))
                values = [expected.popleft() for _ in range(wanted)] + [173] * (count + 2 - wanted)
                if a != b or b != wanted or list(co) != values or list(ho) != values:
                    raise AssertionError(("dequeue_arr", capacity, step, a, b, wanted))
                calls["dequeue_arr"] += 1
                zero_length += count == 0
            elif operation == 4:
                index = rng.randrange(capacity + 2)
                co, ho = ctypes.c_uint8(173), ctypes.c_uint8(173)
                a = c.ring_buffer_peek(ctypes.byref(cr), ctypes.byref(co), index)
                b = h.ring_buffer_peek(ctypes.byref(hr), ctypes.byref(ho), index)
                existed = index < len(expected)
                value = expected[index] if existed else 173
                if (a, co.value) != (b, ho.value) or (b, ho.value) != (int(existed), value):
                    raise AssertionError(("peek", capacity, step))
                calls["peek"] += 1
            else:
                # Reset retains the caller-owned backing storage and its bytes.
                c.ring_buffer_init(ctypes.byref(cr), cb, capacity)
                h.ring_buffer_init(ctypes.byref(hr), hb, capacity)
                expected.clear()
                calls["init"] += 1
                resets += 1
            if (cr.buffer_mask, cr.tail_index, cr.head_index) != (hr.buffer_mask, hr.tail_index, hr.head_index) or bytes(cb) != bytes(hb):
                raise AssertionError(("persistent state/physical bytes", capacity, step))
            if ctypes.addressof(cr.buffer.contents) != ctypes.addressof(cb) or ctypes.addressof(hr.buffer.contents) != ctypes.addressof(hb):
                raise AssertionError("Backing storage pointer changed")
            for name, wanted in (("num_items", len(expected)), ("is_empty", int(not expected)), ("is_full", int(len(expected) == capacity - 1))):
                a, b = getattr(c, "ring_buffer_" + name)(ctypes.byref(cr)), getattr(h, "ring_buffer_" + name)(ctypes.byref(hr))
                if a != b or b != wanted:
                    raise AssertionError((name, capacity, step, a, b, wanted))
                calls[name] += 1
            observations += 1
    if any(calls[name] == 0 for name in ("init", "queue", "queue_arr", "dequeue", "dequeue_arr", "peek", "is_empty", "is_full", "num_items")):
        raise AssertionError("Complete function coverage missing")
    return {"capacities": capacities, "steps_per_capacity": steps, "state_transitions": observations,
            "native_differential_calls": sum(calls.values()), "calls_by_function": dict(calls),
            "zero_length_null_slice_calls": zero_length, "resets": resets,
            "checks": ["C/Hepta returns", "independent bounded deque oracle", "all persistent scalar state", "every backing-store byte", "output sentinels", "unchanged source input", "backing-pointer identity"],
            "source_equivalence_proved": False}


def boundary_controls(translated):
    script = r'''import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class R(ctypes.Structure):
 _fields_=[('buffer',ctypes.POINTER(ctypes.c_uint8)),('buffer_mask',ctypes.c_size_t),('tail_index',ctypes.c_size_t),('head_index',ctypes.c_size_t)]
lib=ctypes.CDLL(sys.argv[1]);mode=sys.argv[2]
p=ctypes.POINTER(R);q=ctypes.POINTER(ctypes.c_uint8)
lib.ring_buffer_init.argtypes=[p,q,ctypes.c_size_t]
lib.ring_buffer_queue.argtypes=[p,ctypes.c_uint8]
lib.ring_buffer_queue_arr.argtypes=[p,q,ctypes.c_size_t]
lib.ring_buffer_dequeue.argtypes=[p,q]
b=(ctypes.c_uint8*8)();r=R();lib.ring_buffer_init(ctypes.byref(r),b,8)
if mode=='null_record':lib.ring_buffer_queue(None,1)
elif mode=='misaligned_record':lib.ring_buffer_queue(ctypes.cast(ctypes.addressof(r)+1,p),1)
elif mode=='record_buffer_overlap':r.buffer=ctypes.cast(ctypes.byref(r),q);lib.ring_buffer_queue(ctypes.byref(r),1)
elif mode=='output_buffer_overlap':lib.ring_buffer_queue(ctypes.byref(r),1);lib.ring_buffer_dequeue(ctypes.byref(r),b)
elif mode=='input_buffer_overlap':lib.ring_buffer_queue_arr(ctypes.byref(r),b,1)
elif mode=='extent_overflow':r.buffer_mask=ctypes.c_size_t(-1).value;lib.ring_buffer_queue(ctypes.byref(r),1)
elif mode=='bad_index':r.head_index=999;lib.ring_buffer_queue(ctypes.byref(r),1)
elif mode=='null_storage':lib.ring_buffer_init(ctypes.byref(r),None,8)
elif mode=='zero_capacity':lib.ring_buffer_init(ctypes.byref(r),None,0)
else:raise RuntimeError(mode)
'''
    results = []
    for mode in ("null_record", "misaligned_record", "record_buffer_overlap", "output_buffer_overlap", "input_buffer_overlap", "extent_overflow", "bad_index", "null_storage", "zero_capacity"):
        run = subprocess.run([sys.executable, "-c", script, str(translated), mode], capture_output=True, timeout=10)
        if run.returncode != -6:
            raise AssertionError((mode, run.returncode, run.stderr[-1000:]))
        results.append({"case": mode, "expected_exit": -6, "actual_exit": run.returncode,
                        "original_C_executed": False, "scope": "outside_qualified_view_contract"})
    return results


def owned_client(source, work, rustc):
    # This is an authored safe caller, not a claim that upstream owns allocations.
    caller = r'''
struct RingOwner { state: C_ring_buffer_t, bytes: Buffer<u8>, }
fn make_ring(size: usize) -> Result<RingOwner, u8> effects {alloc, block, panic, write} {
    let allocation: Result<Buffer<u8>, u8> = try_buffer(size);
    match move allocation {
        Result::Err(error) => { return Result::Err(error); },
        Result::Ok(storage) => {
            let mut bytes: Buffer<u8> = move storage;
            let mut state: C_ring_buffer_t = C_ring_buffer_t {f_buffer_mask: 0, f_tail_index: 0, f_head_index: 0};
            c_ring_buffer_init(mut state, mut bytes, 0, size);
            return Result::Ok(RingOwner {state: state, bytes: move bytes});
        },
    }
}
export "C" fn owned_ring_probe(size: usize, early: u8) -> i32 effects {alloc, block, panic, write} {
    let made: Result<RingOwner, u8> = make_ring(size);
    match move made {
        Result::Err(error) => { return -1; },
        Result::Ok(owner_value) => {
            let mut owner: RingOwner = move owner_value;
            if early != 0 { drop(move owner); return 7; }
            c_ring_buffer_queue(mut owner.state, mut owner.bytes, 23);
            let mut output: [u8; 1] = [0];
            let count: u8 = c_ring_buffer_dequeue(mut owner.state, mut owner.bytes, mut output, 0);
            assert(count == 1);
            assert(output[0] == 23);
            drop(move owner);
            return 0;
        },
    }
}
'''
    program = parse(source + caller, str(work / "owned_client.hepta"))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    generated = emit_rust(program, checked, crate_type="cdylib") + RUST_FAULT_ALLOCATOR
    built = compile_rust(generated, output=work / "owned_client.so", rustc=rustc, crate_type="cdylib")
    if not built["ok"]:
        raise AssertionError(built)
    lib = ctypes.CDLL(str(work / "owned_client.so"))
    lib.owned_ring_probe.argtypes, lib.owned_ring_probe.restype = [ctypes.c_size_t, ctypes.c_uint8], ctypes.c_int32
    lib.migration_live_allocations.argtypes, lib.migration_live_allocations.restype = [], ctypes.c_long
    results = []
    for size, early, expected in ((8, False, 0), (8, True, 7), (65519, False, -1), (16, False, 0), (65519, True, -1), (32, False, 0)):
        actual = lib.owned_ring_probe(size, early)
        live = lib.migration_live_allocations()
        if actual != expected or live != 0:
            raise AssertionError((size, early, actual, live))
        results.append({"size": size, "early_return": early, "result": actual, "live_allocations_after": live})
    return {"client_kind": "authored_Hepta_Buffer_owner_of_upstream_caller_owned_storage", "calls": results,
            "actual_allocator_refusal": True, "upstream_allocator_migration_claimed": False,
            "source_sha256": hashlib.sha256(caller.encode()).hexdigest(), "native_build": built}


def layout_probe(original, generated, work, compiler, rustc):
    fields = ["buffer", "buffer_mask", "tail_index", "head_index"]
    c = '#include "ringbuffer.h"\n#include <stddef.h>\n'
    c += "size_t probe_size(void){return sizeof(ring_buffer_t);}\nsize_t probe_align(void){return _Alignof(ring_buffer_t);}\n"
    c += "\n".join(f"size_t probe_{field}(void){{return offsetof(ring_buffer_t,{field});}}" for field in fields)
    (work / "layout.c").write_text(c)
    command([compiler, *FLAGS, "-shared", "-fPIC", str(work / "layout.c"), "-o", str(work / "c_layout.so")])
    rust = generated + '\n#[no_mangle] pub extern "C" fn probe_size()->usize {core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>()}\n#[no_mangle] pub extern "C" fn probe_align()->usize {core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>()}\n'
    rust += "\n".join(f'#[no_mangle] pub extern "C" fn probe_{field}()->usize {{core::mem::offset_of!(__HeptaAbi_C_ring_buffer_t,f_{field})}}' for field in fields)
    result = compile_rust(rust, output=work / "rust_layout.so", rustc=rustc, crate_type="cdylib")
    if not result["ok"]:
        raise AssertionError(result)
    c, h = ctypes.CDLL(str(work / "c_layout.so")), ctypes.CDLL(str(work / "rust_layout.so"))
    probes = {}
    for field in ("size", "align", *fields):
        cf, hf = getattr(c, "probe_" + field), getattr(h, "probe_" + field)
        cf.restype = hf.restype = ctypes.c_size_t
        a, b = cf(), hf()
        if a != b:
            raise AssertionError(("layout", field, a, b))
        probes[field] = {"gcc": a, "rust": b}
    return probes


def benchmark(original, translated, work, compiler, *, iterations=100000):
    source = ROOT / "tools/fixtures/c_ring_buffer_benchmark.c"
    executable = work / "ring-benchmark"
    build = command([compiler, *FLAGS, "-O2", "-I" + str(work), str(source), "-ldl", "-o", str(executable)])
    rows = []
    for mode, name, calls in ((0, "single_byte_enqueue_dequeue", 2), (1, "64_byte_enqueue_dequeue", 2), (2, "count_empty_full_queries", 3)):
        samples = {"original_C": [], "Hepta_C_ABI": []}
        checksums = set()
        order = []
        for sample in range(7):
            pair = [("original_C", original), ("Hepta_C_ABI", translated)]
            if sample % 2:
                pair.reverse()
            for label, library in pair:
                result = json.loads(command([str(executable), str(library), str(mode), str(iterations)])["stdout"])
                if result["iterations"] != iterations or result["mode"] != mode or result["nanoseconds"] <= 0:
                    raise AssertionError("Incomplete benchmark output")
                checksums.add(result["checksum"])
                samples[label].append(result["nanoseconds"])
                order.append(label)
        if len(checksums) != 1:
            raise AssertionError("Timed routes disagree on checksum")
        c_median, h_median = (statistics.median(samples[label]) / iterations for label in ("original_C", "Hepta_C_ABI"))
        rows.append({"case": name, "iterations_per_sample": iterations, "ABI_calls_per_iteration": calls,
                     "samples_nanoseconds": samples, "execution_order": order, "checksum": checksums.pop(),
                     "original_C_median_ns_per_iteration": c_median, "Hepta_C_ABI_median_ns_per_iteration": h_median,
                     "observed_Hepta_over_C_ratio": h_median / c_median})
    return {"status": "measured", "measurements": rows, "harness_sha256": sha(source), "build": build,
            "limitations": ["One shared x86-64 host, seven alternating-order samples, no affinity control", "GCC -O2 original and Hepta pinned Rust -O3 checked reference backend; no LTO", "Both routes use the same dlsym function-pointer dispatcher", "Source/core translation, scalar-state copying and pointer/bounds guards are measured together", "Object creation and allocator failure are outside timed loops; no whole-application or hardware superiority claim"]}


def checkpoint(report, output, stage):
    report["stage"] = stage
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def qualify(*, clang, rustc, output, seed=827203, steps=2048):
    started = time.perf_counter()
    from tools.release_check import snapshot
    source_before = snapshot()
    metadata = verify_upstream()
    compiler = shutil.which("gcc")
    if not compiler:
        raise RuntimeError("Independent GCC compiler is required")
    report = {"schema": "hepta.c-stateful-upstream-qualification.v1", "ok": False,
              "upstream": metadata, "seed": seed, "build_configuration": FLAGS,
              "assertions": "NDEBUG captured explicitly; other macro configurations unqualified",
              "scope": "complete_upstream_stateful_ring_module_not_general_C_ownership_translation",
              "source_equivalence_proved": False, "whole_project_blockers_closed": False,
              "source_snapshot_before": source_before,
              "foreign_pointer_validity_proved": False, "performance_parity_claimed": False,
              "implementation_files": {name: sha(ROOT / name) for name in ("hepta/c_record_views.py", "hepta/c_translation.py", "hepta/c_migration_project.py", "hepta/c_project.py", "tools/qualify_c_ring_buffer.py")},
              "original_compiler": {"path": compiler, "sha256": sha(Path(compiler)), "version": command([compiler, "--version"])["stdout"].splitlines()[0]}}
    checkpoint(report, output, "capture_and_migration")
    with tempfile.TemporaryDirectory(prefix="hepta-ring-qualification-") as temporary:
        work = Path(temporary)
        database = capture_fixture(work)
        migration = migrate_c_project(database, work / "translated", contracts=json.loads((FIXTURE / "contracts.json").read_text()), clang=clang, rustc=rustc, verify_native=True)
        report["migration"] = migration
        checkpoint(report, output, "native_original_build")
        if not migration["ok"] or not migration["declaration_inventory_complete"]:
            raise AssertionError(migration["diagnostics"])
        expected = {"function_converted": 9, "prototype_resolved": 9, "record_converted": 1, "record_forward_resolved": 1, "type_alias_resolved": 2}
        if migration["coverage"]["active_project_declarations"] != 22 or migration["coverage"]["status_counts"] != expected:
            raise AssertionError("Complete active declaration denominator changed")
        original, translated = work / "original.so", work / "translated/libtranslated.so"
        report["original_build"] = command([compiler, *FLAGS, "-O2", "-shared", "-fPIC", str(work / "ringbuffer.c"), "-o", str(original)])
        report["execution"] = run_sequences(original, translated, seed=seed, steps=steps)
        checkpoint(report, output, "adversarial_boundary_controls")
        report["boundary_controls"] = boundary_controls(translated)
        checkpoint(report, output, "owned_client")
        source = (work / "translated/source.hepta").read_text()
        generated = (work / "translated/generated.rs").read_text()
        report["owned_client"] = owned_client(source, work, rustc)
        report["layout_probe"] = layout_probe(original, generated, work, compiler, rustc)
        checkpoint(report, output, "wrong_implementation_control")
        # Execute the same full sequence oracle on a genuinely wrong generated
        # algorithm. A boolean comparison to a fabricated return is insufficient.
        wrong = source.replace("p_buffer.f_head_index == p_buffer.f_tail_index", "p_buffer.f_head_index != p_buffer.f_tail_index", 1)
        if wrong == source:
            raise AssertionError("Wrong-implementation mutation did not bind generated source")
        p = parse(wrong)
        c = check(p)
        if not c.ok:
            raise AssertionError("Wrong-result control should compile")
        wrong_build = compile_rust(emit_rust(p, c, crate_type="cdylib") + (work / "translated/bridge.rs").read_text(), output=work / "wrong.so", rustc=rustc, crate_type="cdylib")
        if not wrong_build["ok"]:
            raise AssertionError(wrong_build)
        try:
            run_sequences(original, work / "wrong.so", seed=seed, steps=24)
        except AssertionError as error:
            report["wrong_implementation_control"] = {"compiled": True, "rejected_by_full_oracle": True, "first_mismatch": str(error)}
        else:
            raise AssertionError("Wrong implementation escaped stateful oracle")
        checkpoint(report, output, "bridge_runtime_measurement")
        report["performance"] = benchmark(original, translated, work, compiler)
        output.parent.mkdir(parents=True, exist_ok=True)
        retained = output.parent / "ring-buffer-generated"
        retained.mkdir(exist_ok=True)
        report["retained_generated_sources"] = {}
        for name in ("source.hepta", "bridge.rs"):
            shutil.copyfile(work / "translated" / name, retained / name)
            report["retained_generated_sources"][name] = {"path": str(retained / name), "sha256": sha(retained / name)}
        shutil.copyfile(FIXTURE / "LICENSE", retained / "LICENSE")
        (retained / "NOTICE").write_text("Generated derivative of AndersKaloer/Ring-Buffer at " + UPSTREAM_COMMIT + ".\nOriginal upstream files are unchanged. See LICENSE for MIT terms.\nThe generated safe core uses caller-supplied record-view contracts, not inferred foreign ownership.\n")
    report["cost"] = {"elapsed_seconds": time.perf_counter() - started, "manual_review_hours": None, "model_tokens": None,
                       "generated_core_lines": len(source.splitlines()), "upstream_source_lines": len((FIXTURE / "ringbuffer.c").read_text().splitlines()),
                       "adapter_runtime_cost_measured": True, "model_runs": 0}
    report["source_snapshot_after"] = snapshot()
    if report["source_snapshot_after"] != source_before:
        checkpoint(report, output, "source_changed_rejected")
        raise RuntimeError("Implementation source changed during stateful C qualification")
    report["stage"] = "complete"
    report["ok"] = True
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/c-ring-buffer.json")
    args = parser.parse_args()
    try:
        report = qualify(clang=args.clang, rustc=args.rustc, output=args.output)
        print(json.dumps({"ok": report["ok"], "report": str(args.output), "execution": report["execution"]}, indent=2))
        return 0
    except Exception as error:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        partial = json.loads(args.output.read_text()) if args.output.is_file() else {"schema": "hepta.c-stateful-upstream-qualification.v1"}
        partial.update(ok=False, error=str(error))
        args.output.write_text(json.dumps(partial, indent=2, sort_keys=True) + "\n")
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
