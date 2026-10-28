"""Freeze, translate and execute a complete upstream stateful C ring-buffer.

The unchanged upstream C owns no allocation. Its caller-owned storage becomes
explicit borrowed Hepta slices, with a separately exercised Buffer owner client.
Finite differentials, ABI probes and fault controls do not prove equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_rust
from hepta.checker import check
from hepta.c_migrate import migrate_c_project
from hepta.c_contracts import contract_identity, decode_contracts, MAX_CONTRACT_BYTES
from hepta.hia_program_tools import read_bounded
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


def run_sequences(original, translated, *, seed=827203, steps=2048, evidence=None,
                  run_name="qualified"):
    c, h = configure(original), configure(translated)
    calls, observations, resets, zero_length = Counter(), 0, 0, 0
    capacities = [1, 2, 4, 8, 16, 32, 64, 256]
    first_observation = evidence.transition_count if evidence else 0

    def state(record, backing):
        actual = ctypes.cast(record.buffer, ctypes.c_void_p).value
        allocated = ctypes.addressof(backing)
        return {"scalars": {"buffer_mask": record.buffer_mask,
                            "tail_index": record.tail_index, "head_index": record.head_index},
                "backing_bytes": list(backing), "buffer_pointer": actual,
                "backing_address": allocated, "backing_pointer_unchanged": actual == allocated}

    def retain(row, cr, hr, cb, hb, error=None):
        row["original"].update(state(cr, cb))
        row["translated"].update(state(hr, hb))
        row["ok"] = error is None
        row["error"] = None if error is None else {"type": type(error).__name__, "message": str(error)}
        if evidence:
            evidence.transition(row)

    for capacity in capacities:
        cb, hb = (ctypes.c_uint8 * capacity)(), (ctypes.c_uint8 * capacity)()
        cr, hr = Ring(), Ring()
        initial = {"schema": "hepta.c-ring-transition.v2", "run": run_name,
                   "capacity": capacity, "step": -1, "phase": "initialization",
                   "operation": "init", "input": {"capacity": capacity},
                   "original": {"return": None, "output": None},
                   "translated": {"return": None, "output": None}, "query_probes": {}}
        c.ring_buffer_init(ctypes.byref(cr), cb, capacity)
        h.ring_buffer_init(ctypes.byref(hr), hb, capacity)
        calls["init"] += 1
        retain(initial, cr, hr, cb, hb)
        expected = deque(maxlen=capacity - 1)
        rng = random.Random(seed + capacity)
        for step in range(steps):
            operation = step % 6 if step < 24 else rng.randrange(6)
            row = {"schema": "hepta.c-ring-transition.v2", "run": run_name,
                   "capacity": capacity, "step": step, "phase": "transition",
                   "operation": ("queue", "queue_arr", "dequeue", "dequeue_arr", "peek", "init")[operation],
                   "input": {}, "original": {"return": None, "output": None},
                   "translated": {"return": None, "output": None}, "query_probes": {}}
            error = None
            try:
                if operation == 0:
                    value = rng.randrange(256)
                    row["input"] = {"value": value}
                    c.ring_buffer_queue(ctypes.byref(cr), value)
                    h.ring_buffer_queue(ctypes.byref(hr), value)
                    calls["queue"] += 1
                    expected.append(value)
                elif operation == 1:
                    count = 0 if step < 24 else rng.randrange(2 * capacity + 1)
                    values = [rng.randrange(256) for _ in range(count)]
                    source = (ctypes.c_uint8 * count)(*values)
                    ptr = source if count else None
                    row["input"] = {"count": count, "values": values, "null_pointer": not count}
                    c.ring_buffer_queue_arr(ctypes.byref(cr), ptr, count)
                    row["original"]["input_after"] = list(source)
                    h.ring_buffer_queue_arr(ctypes.byref(hr), ptr, count)
                    row["translated"]["input_after"] = list(source)
                    calls["queue_arr"] += 1
                    zero_length += count == 0
                    if row["original"]["input_after"] != values or list(source) != values:
                        raise AssertionError("Read input mutated")
                    expected.extend(values)
                elif operation == 2:
                    co, ho = ctypes.c_uint8(173), ctypes.c_uint8(173)
                    row["input"] = {"output_sentinel": 173}
                    a = c.ring_buffer_dequeue(ctypes.byref(cr), ctypes.byref(co))
                    b = h.ring_buffer_dequeue(ctypes.byref(hr), ctypes.byref(ho))
                    row["original"].update({"return": a, "output": co.value})
                    row["translated"].update({"return": b, "output": ho.value})
                    calls["dequeue"] += 1
                    existed = bool(expected)
                    value = expected.popleft() if existed else 173
                    if (a, co.value) != (b, ho.value) or (b, ho.value) != (int(existed), value):
                        raise AssertionError(("dequeue", capacity, step, a, b, co.value, ho.value, value))
                elif operation == 3:
                    count = 0 if step < 24 else rng.randrange(2 * capacity + 1)
                    co = (ctypes.c_uint8 * (count + 2))(*([173] * (count + 2)))
                    ho = (ctypes.c_uint8 * (count + 2))(*([173] * (count + 2)))
                    row["input"] = {"count": count, "output_sentinel": 173,
                                    "output_extent": count + 2, "null_pointer": not count}
                    a = c.ring_buffer_dequeue_arr(ctypes.byref(cr), co if count else None, count)
                    b = h.ring_buffer_dequeue_arr(ctypes.byref(hr), ho if count else None, count)
                    row["original"].update({"return": a, "output": list(co)})
                    row["translated"].update({"return": b, "output": list(ho)})
                    calls["dequeue_arr"] += 1
                    zero_length += count == 0
                    wanted = min(count, len(expected))
                    values = [expected.popleft() for _ in range(wanted)] + [173] * (count + 2 - wanted)
                    if a != b or b != wanted or list(co) != values or list(ho) != values:
                        raise AssertionError(("dequeue_arr", capacity, step, a, b, wanted))
                elif operation == 4:
                    index = rng.randrange(capacity + 2)
                    co, ho = ctypes.c_uint8(173), ctypes.c_uint8(173)
                    row["input"] = {"index": index, "output_sentinel": 173}
                    a = c.ring_buffer_peek(ctypes.byref(cr), ctypes.byref(co), index)
                    b = h.ring_buffer_peek(ctypes.byref(hr), ctypes.byref(ho), index)
                    row["original"].update({"return": a, "output": co.value})
                    row["translated"].update({"return": b, "output": ho.value})
                    calls["peek"] += 1
                    existed = index < len(expected)
                    value = expected[index] if existed else 173
                    if (a, co.value) != (b, ho.value) or (b, ho.value) != (int(existed), value):
                        raise AssertionError(("peek", capacity, step))
                else:
                    row["input"] = {"capacity": capacity}
                    c.ring_buffer_init(ctypes.byref(cr), cb, capacity)
                    h.ring_buffer_init(ctypes.byref(hr), hb, capacity)
                    calls["init"] += 1
                    expected.clear()
                    resets += 1
                if (cr.buffer_mask, cr.tail_index, cr.head_index) != (hr.buffer_mask, hr.tail_index, hr.head_index) or bytes(cb) != bytes(hb):
                    raise AssertionError(("persistent state/physical bytes", capacity, step))
                if ctypes.addressof(cr.buffer.contents) != ctypes.addressof(cb) or ctypes.addressof(hr.buffer.contents) != ctypes.addressof(hb):
                    raise AssertionError("Backing storage pointer changed")
                for name, wanted in (("num_items", len(expected)), ("is_empty", int(not expected)), ("is_full", int(len(expected) == capacity - 1))):
                    a = getattr(c, "ring_buffer_" + name)(ctypes.byref(cr))
                    b = getattr(h, "ring_buffer_" + name)(ctypes.byref(hr))
                    row["query_probes"][name] = {"original": a, "translated": b}
                    calls[name] += 1
                    if a != b or b != wanted:
                        raise AssertionError((name, capacity, step, a, b, wanted))
                observations += 1
            except BaseException as caught:
                error = caught
                raise
            finally:
                retain(row, cr, hr, cb, hb, error)
    if any(calls[name] == 0 for name in ("init", "queue", "queue_arr", "dequeue", "dequeue_arr", "peek", "is_empty", "is_full", "num_items")):
        raise AssertionError("Complete function coverage missing")
    result = {"capacities": capacities, "steps_per_capacity": steps, "state_transitions": observations,
            "native_differential_calls": sum(calls.values()), "calls_by_function": dict(calls),
            "paired_native_entry_comparisons": sum(calls.values()),
            "actual_native_entry_invocations": 2 * sum(calls.values()),
            "native_entry_invocations_by_route": {"original_C": sum(calls.values()), "Hepta_C_ABI": sum(calls.values())},
            "zero_length_null_slice_calls": zero_length, "resets": resets,
            "retained_observation_range": [first_observation, evidence.transition_count] if evidence else None,
            "checks": ["C/Hepta returns", "independent bounded deque oracle", "all persistent scalar state", "every backing-store byte", "output sentinels", "unchanged source input", "backing-pointer identity"],
            "source_equivalence_proved": False}
    if evidence:
        recorded = evidence.sequence_counts(run_name, first_observation)
        if any(result[key] != value for key, value in recorded.items()):
            raise AssertionError("Retained actual transition counts disagree with live observations")
        result.update(recorded)
    return result


def boundary_controls(translated, *, evidence=None):
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
    if evidence:
        script_path = evidence.retained / "workspace" / "boundary-control.py"
        script_path.write_text(script)
    results = []
    for mode in ("null_record", "misaligned_record", "record_buffer_overlap", "output_buffer_overlap", "input_buffer_overlap", "extent_overflow", "bad_index", "null_storage", "zero_capacity"):
        if evidence:
            run, process_index = evidence.process([sys.executable, str(script_path), str(translated), mode],
                role="boundary." + mode, capture_output=True, timeout=10, cwd=script_path.parent)
        else:
            run = subprocess.run([sys.executable, "-c", script, str(translated), mode], capture_output=True, timeout=10)
            process_index = None
        if run.returncode != -6:
            raise AssertionError((mode, run.returncode, run.stderr[-1000:]))
        results.append({"case": mode, "expected_exit": -6, "actual_exit": run.returncode,
                        "process_index": process_index,
                        "original_C_executed": False, "scope": "outside_qualified_view_contract"})
    return results


def owned_client(source, work, rustc, *, evidence=None):
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
    (work / "owned_client.hepta").write_text(source + caller)
    program = parse(source + caller, str(work / "owned_client.hepta"))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    generated = emit_rust(program, checked, crate_type="cdylib") + RUST_FAULT_ALLOCATOR
    built = (evidence.native_build(generated, output=work / "owned_client.so", rustc=rustc, role="owned_client")
             if evidence else compile_rust(generated, output=work / "owned_client.so", rustc=rustc, crate_type="cdylib"))
    if not built["ok"]:
        raise AssertionError(built)
    lib = ctypes.CDLL(str(work / "owned_client.so"))
    lib.owned_ring_probe.argtypes, lib.owned_ring_probe.restype = [ctypes.c_size_t, ctypes.c_uint8], ctypes.c_int32
    lib.migration_live_allocations.argtypes, lib.migration_live_allocations.restype = [], ctypes.c_long
    results = []
    for size, early, expected in ((8, False, 0), (8, True, 7), (65519, False, -1), (16, False, 0), (65519, True, -1), (32, False, 0)):
        actual = lib.owned_ring_probe(size, early)
        live = lib.migration_live_allocations()
        row = {"size": size, "early_return": early, "result": actual, "live_allocations_after": live}
        if evidence:
            row["observation_index"] = evidence.native_observation("owned_client", row)
        if actual != expected or live != 0:
            raise AssertionError((size, early, actual, live))
        results.append(row)
    return {"client_kind": "authored_Hepta_Buffer_owner_of_upstream_caller_owned_storage", "calls": results,
            "actual_allocator_refusal": True, "upstream_allocator_migration_claimed": False,
            "source_sha256": hashlib.sha256(caller.encode()).hexdigest(), "native_build": built}


def layout_probe(original, generated, work, compiler, rustc, *, evidence=None):
    fields = ["buffer", "buffer_mask", "tail_index", "head_index"]
    c = '#include "ringbuffer.h"\n#include <stddef.h>\n'
    c += "size_t probe_size(void){return sizeof(ring_buffer_t);}\nsize_t probe_align(void){return _Alignof(ring_buffer_t);}\n"
    c += "\n".join(f"size_t probe_{field}(void){{return offsetof(ring_buffer_t,{field});}}" for field in fields)
    (work / "layout.c").write_text(c)
    argv = [compiler, *FLAGS, "-shared", "-fPIC", str(work / "layout.c"), "-o", str(work / "c_layout.so")]
    if evidence:
        evidence.command(argv, role="layout.original_build", cwd=work)
    else:
        command(argv)
    rust = generated + '\n#[no_mangle] pub extern "C" fn probe_size()->usize {core::mem::size_of::<__HeptaAbi_C_ring_buffer_t>()}\n#[no_mangle] pub extern "C" fn probe_align()->usize {core::mem::align_of::<__HeptaAbi_C_ring_buffer_t>()}\n'
    rust += "\n".join(f'#[no_mangle] pub extern "C" fn probe_{field}()->usize {{core::mem::offset_of!(__HeptaAbi_C_ring_buffer_t,f_{field})}}' for field in fields)
    result = (evidence.native_build(rust, output=work / "rust_layout.so", rustc=rustc, role="layout.translated_build")
              if evidence else compile_rust(rust, output=work / "rust_layout.so", rustc=rustc, crate_type="cdylib"))
    if not result["ok"]:
        raise AssertionError(result)
    c, h = ctypes.CDLL(str(work / "c_layout.so")), ctypes.CDLL(str(work / "rust_layout.so"))
    probes = {}
    for field in ("size", "align", *fields):
        cf, hf = getattr(c, "probe_" + field), getattr(h, "probe_" + field)
        cf.restype = hf.restype = ctypes.c_size_t
        a, b = cf(), hf()
        if evidence:
            evidence.native_observation("layout", {"field": field, "original": a, "translated": b})
        if a != b:
            raise AssertionError(("layout", field, a, b))
        probes[field] = {"gcc": a, "rust": b}
    return probes


def benchmark(original, translated, work, compiler, *, iterations=100000, evidence=None):
    source = work / "c_ring_buffer_benchmark.c"
    shutil.copyfile(ROOT / "tools/fixtures/c_ring_buffer_benchmark.c", source)
    executable = work / "ring-benchmark"
    argv = [compiler, *FLAGS, "-O2", "-I" + str(work), str(source), "-ldl", "-o", str(executable)]
    build = evidence.command(argv, role="benchmark.build", cwd=work) if evidence else command(argv)
    rows = []
    for mode, name, calls in ((0, "single_byte_enqueue_dequeue", 2), (1, "64_byte_enqueue_dequeue", 2), (2, "count_empty_full_queries", 3)):
        samples = {"original_C": [], "Hepta_C_ABI": []}
        checksums = set()
        order = []
        process_indices = []
        for sample in range(7):
            pair = [("original_C", original), ("Hepta_C_ABI", translated)]
            if sample % 2:
                pair.reverse()
            for label, library in pair:
                argv = [str(executable), str(library), str(mode), str(iterations)]
                execution = (evidence.command(argv, role=f"benchmark.{mode}.{sample}.{label}", cwd=work)
                             if evidence else command(argv))
                result = json.loads(execution["stdout"])
                if evidence:
                    process_indices.append(execution["process_index"])
                if result["iterations"] != iterations or result["mode"] != mode or result["nanoseconds"] <= 0:
                    raise AssertionError("Incomplete benchmark output")
                checksums.add(result["checksum"])
                samples[label].append(result["nanoseconds"])
                order.append(label)
        if len(checksums) != 1:
            raise AssertionError("Timed routes disagree on checksum")
        c_median, h_median = (statistics.median(samples[label]) / iterations for label in ("original_C", "Hepta_C_ABI"))
        rows.append({"case": name, "iterations_per_sample": iterations, "ABI_calls_per_iteration": calls,
                     "process_indices": process_indices,
                     "samples_nanoseconds": samples, "execution_order": order, "checksum": checksums.pop(),
                     "original_C_median_ns_per_iteration": c_median, "Hepta_C_ABI_median_ns_per_iteration": h_median,
                     "observed_Hepta_over_C_ratio": h_median / c_median})
    return {"status": "measured", "measurements": rows, "harness_sha256": sha(source), "build": build,
            "retained_harness": evidence.retained_file(source) if evidence else None,
            "actual_sample_processes": sum(len(row["execution_order"]) for row in rows),
            "timed_ABI_invocations": sum(len(row["execution_order"]) * row["iterations_per_sample"]
                                          * row["ABI_calls_per_iteration"] for row in rows),
            "timed_invocation_scope": "timed_dispatch_loops_only_excludes_harness_initialization",
            "limitations": ["One shared x86-64 host, seven alternating-order samples, no affinity control", "GCC -O2 original and Hepta pinned Rust -O3 checked reference backend; no LTO", "Both routes use the same dlsym function-pointer dispatcher", "Source/core translation, scalar-state copying and pointer/bounds guards are measured together", "Object creation and allocator failure are outside timed loops; no whole-application or hardware superiority claim"]}


class QualificationEvidence:
    """Keep this invocation's reserved report inode; never overwrite a prior run.

    Checkpoints are flushed, not crash-atomic transactions. A replacement of
    the pathname is rejected; writing uses only the descriptor we created.
    """

    def __init__(self, path, stream):
        self.path, self.stream = path, stream
        info = os.fstat(stream.fileno())
        self.inode = (info.st_dev, info.st_ino)
        self.retained = path.with_name(path.name + ".generated")
        self.retained_owned = False
        self.started = time.perf_counter()
        self.previous = self.sample()
        self.process_count = 0
        self.transition_count = 0
        self.native_observation_count = 0

    def relative(self, path):
        return Path(path).absolute().relative_to(self.path.parent).as_posix()

    def retained_file(self, path):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Evidence artifact must be an ordinary file: " + str(path))
        return {"path": self.relative(path), "sha256": sha(path), "bytes": path.stat().st_size}

    def append(self, name, row):
        path = self.retained / name
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()

    def transition(self, row):
        self.append("state-transitions.jsonl", {"index": self.transition_count, **row})
        self.transition_count += 1

    def sequence_counts(self, run_name, first):
        calls, transitions, resets, zero_length = Counter(), 0, 0, 0
        with (self.retained / "state-transitions.jsonl").open() as stream:
            for line in stream:
                row = json.loads(line)
                if row["index"] < first or row["run"] != run_name:
                    continue
                if row["ok"] is not True:
                    raise AssertionError("A failed native observation cannot enter a passing summary")
                calls[row["operation"]] += 1
                calls.update(row["query_probes"].keys())
                if row["phase"] == "transition":
                    transitions += 1
                    resets += row["operation"] == "init"
                    zero_length += row["operation"] in {"queue_arr", "dequeue_arr"} and row["input"]["count"] == 0
        pairs = sum(calls.values())
        return {"state_transitions": transitions, "native_differential_calls": pairs,
                "calls_by_function": dict(calls), "paired_native_entry_comparisons": pairs,
                "actual_native_entry_invocations": pairs * 2,
                "native_entry_invocations_by_route": {"original_C": pairs, "Hepta_C_ABI": pairs},
                "zero_length_null_slice_calls": zero_length, "resets": resets}

    def native_observation(self, role, value):
        index = self.native_observation_count
        self.append("native-observations.jsonl", {"index": index, "role": role, **value})
        self.native_observation_count += 1
        return index

    def process(self, argv, *, role, require_success=False, **kwargs):
        """Observe one actual subprocess; preserve helper argv and staging names.

        Backend-generated temporary sources are copied before execution and
        bound to their observed original path. The recorded argv is never
        rewritten to pretend the compiler used a different persistent path.
        """
        index = self.process_count
        self.process_count += 1
        directory = self.retained / "processes" / f"{index:04d}"
        directory.mkdir(parents=True)
        command_line = [os.fspath(item) for item in argv]
        row = {"index": index, "role": role, "argv": command_line,
               "cwd": str(Path(kwargs.get("cwd") or Path.cwd()).resolve()),
               "status": "attempted", "returncode": None,
               "observed_input_files": [], "observed_output_files": []}
        source = None
        artifact = None
        if "--crate-name=hepta_program" in command_line:
            source = Path(command_line[1])
            retained_source = directory / "program.rs"
            shutil.copyfile(source, retained_source)
            row["observed_input_files"].append({"original_path": str(source),
                                                  **self.retained_file(retained_source)})
            artifact = Path(command_line[command_line.index("-o") + 1])
        attempted = directory / "command.json"
        attempted.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
        tick = time.perf_counter()
        result, failure = None, None
        try:
            result = subprocess.run(argv, **kwargs)
            stdout, stderr = result.stdout or b"", result.stderr or b""
            row.update(status="completed", returncode=result.returncode)
        except subprocess.TimeoutExpired as error:
            stdout, stderr, failure = error.stdout or b"", error.stderr or b"", error
            row["status"] = "timeout"
        except subprocess.CalledProcessError as error:
            stdout, stderr, failure = error.stdout or b"", error.stderr or b"", error
            row.update(status="completed", returncode=error.returncode)
        except BaseException as error:
            stdout, stderr, failure = b"", str(error).encode("utf-8", errors="replace"), error
            row["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "spawn_failed"
        row["elapsed_seconds"] = time.perf_counter() - tick
        row["timeout_seconds"] = kwargs.get("timeout")
        for name, value in (("stdout", stdout), ("stderr", stderr)):
            # compile_rust requests text=True; retain its original decoded
            # stream as UTF-8 before diagnostic filtering. Direct commands use
            # bytes, preserving their captured streams byte for byte.
            data = value.encode("utf-8") if isinstance(value, str) else value
            target = directory / name
            target.write_bytes(data)
            row[name] = {**self.retained_file(target),
                         "representation": "decoded_text_utf8" if isinstance(value, str) else "raw_bytes"}
        if artifact is not None and artifact.is_file():
            retained_artifact = directory / artifact.name
            shutil.copyfile(artifact, retained_artifact)
            row["observed_output_files"].append({"original_path": str(artifact),
                                                   **self.retained_file(retained_artifact)})
        attempted.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
        self.append("processes.jsonl", row)
        if failure is not None:
            raise failure
        if require_success and result.returncode:
            raise RuntimeError("Native process failed; retained process index " + str(index))
        return result, index

    def command(self, argv, *, role, timeout=60, cwd=None, require_success=True):
        result, index = self.process(argv, role=role, require_success=require_success,
                                     capture_output=True, timeout=timeout, cwd=cwd)
        return {"argv": list(argv), "cwd": str(Path(cwd or Path.cwd()).resolve()),
                "exit_code": result.returncode, "process_index": index,
                "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8")}

    @contextmanager
    def backend_processes(self, role):
        # Only the backend module's subprocess reference is replaced. Other
        # frontends keep their bounded capture runner and capture receipts.
        # The proxy calls the original stdlib module once with unchanged args.
        import hepta.backend as backend
        evidence, previous = self, backend.subprocess

        class ObservedBackendProcesses:
            def __getattr__(self, name):
                return getattr(previous, name)

            def run(self, argv, *args, **kwargs):
                if args:
                    raise RuntimeError("Unmodeled positional backend subprocess arguments")
                suffix = "compile" if "--crate-name=hepta_program" in argv else "toolchain_identity"
                result, _ = evidence.process(argv, role=role + "." + suffix, **kwargs)
                return result

        backend.subprocess = ObservedBackendProcesses()
        try:
            yield
        finally:
            backend.subprocess = previous

    def native_build(self, source, *, output, rustc, role):
        retained_source = Path(output).with_suffix(".rs")
        retained_source.write_text(source)
        start = self.process_count
        with self.backend_processes(role):
            result = compile_rust(source, output=output, rustc=rustc, crate_type="cdylib")
        result = {**result, "retained_source": self.retained_file(retained_source),
                  "process_range": [start, self.process_count]}
        Path(output).with_suffix(".build.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return result

    def inventory(self):
        artifacts = {}
        if self.retained_owned:
            for path in sorted(self.retained.rglob("*")):
                if path.is_symlink():
                    raise RuntimeError("Retained evidence contains a symlink")
                if path.is_file():
                    info = self.retained_file(path)
                    artifacts[info.pop("path")] = info
        def stream(name, count):
            path = self.retained / name
            return {**self.retained_file(path), "rows": count} if self.retained_owned and path.is_file() else None
        return {"schema": "hepta.c-ring-retained-evidence.v2",
                "workspace": str((self.retained / "workspace").resolve()),
                "path_base": "report_parent", "artifacts": artifacts,
                "processes": stream("processes.jsonl", self.process_count),
                "state_transitions": stream("state-transitions.jsonl", self.transition_count),
                "native_observations": stream("native-observations.jsonl", self.native_observation_count),
                "process_scope": "native_builds_version_queries_boundary_controls_and_benchmark; frontend_capture_in_migration_receipt",
                "temporary_backend_input_paths_preserved_in_argv_with_bound_retained_copies": True}

    @staticmethod
    def sample():
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        return (time.perf_counter(), time.process_time(), children.ru_utime, children.ru_stime)

    def write(self, report):
        current = self.path.lstat()
        if (current.st_dev, current.st_ino) != self.inode:
            raise RuntimeError("Qualification output path no longer refers to this run's reserved report")
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        self.stream.seek(0)
        self.stream.write(payload)
        self.stream.truncate()
        self.stream.flush()
        os.fsync(self.stream.fileno())


def checkpoint(report, output, stage):
    now = output.sample()
    before = output.previous
    report["cost"]["automatic_tool_stages"].append({
        "stage": report["stage"], "wall_seconds": now[0] - before[0],
        "coordinator_cpu_seconds": now[1] - before[1],
        "completed_child_user_cpu_seconds": now[2] - before[2],
        "completed_child_system_cpu_seconds": now[3] - before[3]})
    output.previous = now
    report["cost"]["elapsed_seconds"] = now[0] - output.started
    report["evidence"] = output.inventory()
    report["cost"]["retained_native_processes"] = output.process_count
    report["cost"]["retained_state_observations"] = output.transition_count
    report["cost"]["retained_other_native_observations"] = output.native_observation_count
    report["stage"] = stage
    output.write(report)


def qualify(*, clang, rustc, output, seed=827203, steps=2048, benchmark_iterations=100000):
    path = Path(output).absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL rejects existing regular files, symlinks and special path entries
    # before source snapshots, compiler probes, or any other paid qualification.
    with path.open("x", encoding="utf-8") as stream:
        evidence = QualificationEvidence(path, stream)
        report = {"schema": "hepta.c-stateful-upstream-qualification.v1", "ok": False,
                  "stage": "source_identity_and_contract_intake",
                  "evidence_publication": "reserved_new_report_inode_checkpoints_not_crash_atomic",
                  "cost": {"automatic_tool_stages": [], "manual_contract_authoring_hours": None,
                           "manual_review_hours": None, "maintenance_hours": None,
                           "model_tokens": None, "model_runs": 0,
                           "scope": "automatic_tools_only_not_total_migration_or_human_cost"}}
        evidence.write(report)
        try:
            evidence.retained.mkdir()
            evidence.retained_owned = True
            if type(steps) is not int or steps < 6 or type(benchmark_iterations) is not int or benchmark_iterations < 1:
                raise ValueError("Need at least six steps per capacity and positive benchmark iterations")
            return _qualify(clang=clang, rustc=rustc, output=evidence, report=report,
                            seed=seed, steps=steps, benchmark_iterations=benchmark_iterations)
        except BaseException as error:
            report.update(ok=False, error=str(error), failed_stage=report["stage"],
                          failure_type=type(error).__name__)
            checkpoint(report, evidence, "failed")
            raise


def _qualify(*, clang, rustc, output, report, seed, steps, benchmark_iterations):
    from tools.release_check import snapshot
    source_before = snapshot()
    metadata = verify_upstream()
    authored_contract = read_bounded(FIXTURE / "contracts.json", limit=MAX_CONTRACT_BYTES)
    contracts = decode_contracts(authored_contract)
    (output.retained / "contracts.json").write_bytes(authored_contract)
    compiler = shutil.which("gcc")
    if not compiler:
        raise RuntimeError("Independent GCC compiler is required")
    report.update({
              "upstream": metadata, "seed": seed, "build_configuration": FLAGS,
              "assertions": "NDEBUG captured explicitly; other macro configurations unqualified",
              "scope": "complete_upstream_stateful_ring_module_not_general_C_ownership_translation",
              "source_equivalence_proved": False, "whole_project_blockers_closed": False,
              "source_snapshot_before": source_before,
              "foreign_pointer_validity_proved": False, "performance_parity_claimed": False,
              "implementation_files": {name: sha(ROOT / name) for name in ("hepta/c_record_views.py", "hepta/c_translation.py", "hepta/c_contracts.py", "hepta/c_migration_project.py", "hepta/c_project.py", "tools/qualify_c_ring_buffer.py")},
              "authored_contract_input": {"path": str(FIXTURE / "contracts.json"),
                                          "raw_sha256": hashlib.sha256(authored_contract).hexdigest(),
                                          "raw_bytes": len(authored_contract),
                                          "identity": contract_identity(contracts),
                                          "origin": "existing_caller_authored_repository_contract_not_generated_or_inferred",
                                          "authoring_time_measured": False},
              "original_compiler": {"path": compiler, "sha256": sha(Path(compiler)), "version": output.command([compiler, "--version"], role="original_compiler_identity")["stdout"].splitlines()[0]}})
    checkpoint(report, output, "capture_and_migration")
    work = output.retained / "workspace"
    work.mkdir()
    shutil.copyfile(FIXTURE / "UPSTREAM.json", work / "UPSTREAM.json")
    database = capture_fixture(work)
    migration_start = output.process_count
    with output.backend_processes("migration_native"):
        migration = migrate_c_project(database, work / "translated", contracts=contracts, clang=clang, rustc=rustc, verify_native=True)
    report["migration_native_process_range"] = [migration_start, output.process_count]
    (work / "migration-attempt.json").write_text(json.dumps(migration, sort_keys=True, indent=2) + "\n")
    report["migration"] = migration
    checkpoint(report, output, "native_original_build")
    if not migration["ok"] or not migration["declaration_inventory_complete"]:
        raise AssertionError(migration["diagnostics"])
    expected = {"function_converted": 9, "prototype_resolved": 9, "record_converted": 1, "record_forward_resolved": 1, "type_alias_resolved": 2}
    if migration["coverage"]["active_project_declarations"] != 22 or migration["coverage"]["status_counts"] != expected:
        raise AssertionError("Complete active declaration denominator changed")
    if migration["contract_identity"] != report["authored_contract_input"]["identity"]:
        raise AssertionError("Migration consumed a different caller-authored contract")
    functions = migration["functions"]
    report["migration_disposition"] = {
        "scope": "this_complete_pinned_upstream_module_and_one_listed_build_configuration_only",
        "production_project_migration_rate_claimed": False,
        "source_translation_units": 1, "active_source_headers": 1,
        "listed_compile_commands": len(migration["build"]["configurations"]),
        "function_definition_denominator": len(functions),
        "function_bodies_converted": expected["function_converted"],
        "function_bodies_left_in_C_behind_a_bridge": 0,
        "function_bodies_rejected": 0, "function_bodies_unaccounted": 0,
        "original_C_ABI_entry_wrappers": sum(fn["external_symbol"] for fn in functions),
        "ABI_wrappers_are_not_additional_or_untranslated_functions": True,
        "active_declaration_denominator": 22,
        "active_declaration_dispositions": expected,
        "input_disposition_scope": "module_source_and_local_migration_inputs; compiler/system dependencies remain in the captured build inventory",
        "input_dispositions": {
            "ringbuffer.c": "unchanged_upstream_translation_unit_converted",
            "ringbuffer.h": "unchanged_upstream_active_declarations_and_inline_bodies_converted",
            "LICENSE": "upstream_license_preserved",
            "UPSTREAM_README.md": "upstream_context_identity_verified_not_compiled",
            "UPSTREAM.json": "local_pinned_upstream_identity_manifest_checked_not_upstream_source",
            "contracts.json": "caller_authored_resource_obligations_frozen_and_retained",
            "compile_commands.json": "one_generated_listed_command_captured_and_replayed"},
        "excluded_denominators": ["system_or_compiler_declarations", "inactive_preprocessor_branches",
                                  "unlisted_build_configurations", "other_upstream_repositories_or_modules"],
    }
    original, translated = work / "original.so", work / "translated/libtranslated.so"
    report["original_build"] = output.command([compiler, *FLAGS, "-O2", "-shared", "-fPIC", str(work / "ringbuffer.c"), "-o", str(original)], role="original_build", cwd=work)
    checkpoint(report, output, "original_C_vs_translated_native_execution")
    report["execution"] = run_sequences(original, translated, seed=seed, steps=steps, evidence=output)
    checkpoint(report, output, "adversarial_boundary_controls")
    report["boundary_controls"] = boundary_controls(translated, evidence=output)
    checkpoint(report, output, "owned_client_and_native_layout")
    source = (work / "translated/source.hepta").read_text()
    generated = (work / "translated/generated.rs").read_text()
    report["owned_client"] = owned_client(source, work, rustc, evidence=output)
    report["layout_probe"] = layout_probe(original, generated, work, compiler, rustc, evidence=output)
    checkpoint(report, output, "wrong_implementation_control")
    # Execute the same full sequence oracle on a genuinely wrong generated
    # algorithm. A boolean comparison to a fabricated return is insufficient.
    wrong = source.replace("p_buffer.f_head_index == p_buffer.f_tail_index", "p_buffer.f_head_index != p_buffer.f_tail_index", 1)
    if wrong == source:
        raise AssertionError("Wrong-implementation mutation did not bind generated source")
    (work / "wrong.hepta").write_text(wrong)
    p = parse(wrong, str(work / "wrong.hepta"))
    c = check(p)
    if not c.ok:
        raise AssertionError("Wrong-result control should compile")
    wrong_build = output.native_build(emit_rust(p, c, crate_type="cdylib") + (work / "translated/bridge.rs").read_text(), output=work / "wrong.so", rustc=rustc, role="wrong_candidate")
    if not wrong_build["ok"]:
        raise AssertionError(wrong_build)
    wrong_start = output.transition_count
    try:
        run_sequences(original, work / "wrong.so", seed=seed, steps=24, evidence=output, run_name="wrong_candidate")
    except AssertionError as error:
        report["wrong_implementation_control"] = {"compiled": True, "rejected_by_full_oracle": True, "first_mismatch": str(error), "native_build": wrong_build,
                                                   "retained_observation_range": [wrong_start, output.transition_count]}
    else:
        raise AssertionError("Wrong implementation escaped stateful oracle")
    checkpoint(report, output, "bridge_runtime_measurement")
    report["performance"] = benchmark(original, translated, work, compiler, iterations=benchmark_iterations, evidence=output)
    checkpoint(report, output, "retention_and_source_revalidation")
    retained = output.retained
    report["retained_generated_sources"] = {}
    for name in ("source.hepta", "bridge.rs"):
        shutil.copyfile(work / "translated" / name, retained / name)
        report["retained_generated_sources"][name] = {"path": str(retained / name), "sha256": sha(retained / name)}
    shutil.copyfile(FIXTURE / "LICENSE", retained / "LICENSE")
    (retained / "contracts.json").write_bytes(authored_contract)
    report["authored_contract_input"]["retained_path"] = str(retained / "contracts.json")
    shutil.copyfile(database, retained / "compile_commands.json")
    shutil.copyfile(work / "translated/migration.json", retained / "migration.json")
    (retained / "NOTICE").write_text("Generated derivative of AndersKaloer/Ring-Buffer at " + UPSTREAM_COMMIT + ".\nOriginal upstream files are unchanged. See LICENSE for MIT terms.\nThe generated safe core uses caller-supplied record-view contracts, not inferred foreign ownership.\n")
    report["cost"].update({"generated_core_lines": len(source.splitlines()),
                          "upstream_source_lines": len((FIXTURE / "ringbuffer.c").read_text().splitlines()),
                          "adapter_runtime_cost_measured": True})
    report["source_snapshot_after"] = snapshot()
    if report["source_snapshot_after"] != source_before:
        checkpoint(report, output, "source_changed_rejected")
        raise RuntimeError("Implementation source changed during stateful C qualification")
    report["ok"] = True
    checkpoint(report, output, "complete")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/c-ring-buffer.json")
    parser.add_argument("--steps", type=int, default=2048)
    parser.add_argument("--benchmark-iterations", type=int, default=100000)
    args = parser.parse_args()
    try:
        report = qualify(clang=args.clang, rustc=args.rustc, output=args.output, steps=args.steps, benchmark_iterations=args.benchmark_iterations)
        print(json.dumps({"ok": report["ok"], "report": str(args.output), "execution": report["execution"]}, indent=2))
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
