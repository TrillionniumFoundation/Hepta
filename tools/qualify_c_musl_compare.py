"""Qualify unchanged musl 1.2.5 generic memcmp/bcmp as an explicit component.

The platform headers and contracts are authored adapters. This is not a musl
libc build, an architecture-specific assembly migration or an equivalence proof.
Original inputs, generated code, native binaries and per-case observations are
retained in a new output directory, including a failed attempt's report.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_rust
from hepta.c_migrate import migrate_c_project
from hepta.checker import check
from hepta.parser import parse
from tools.qualify_c_migration import sha

FIXTURE = ROOT / "tests/fixtures/c_migration/musl_compare"
SOURCE_FILES = ("memcmp.c", "bcmp.c")
FLAGS = ("-std=c11", "-fPIC", "-fno-builtin", "-Iplatform")
EXPECTED = {
    "memcmp.c": "826b1b5e84d3c0fb68be827c051f6dc0d67da17ee3a444e94be0e5360586916f",
    "bcmp.c": "15cf97fb0fbba4f484ad6bbafdf7df0e6772658e83cb26668df793726f66a167",
    "COPYRIGHT": "f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af",
    "UPSTREAM_README": "99be6432b41de50d702dbee423149c8abcd52d06e29dc1715013c25865a2eda8",
}


def verify_upstream():
    metadata = json.loads((FIXTURE / "UPSTREAM.json").read_text())
    if (metadata["version"] != "1.2.5"
            or metadata["tag_commit"] != "0784374d561435f7c787a555aeab8ede699ed298"
            or metadata["release_archive"]["sha256"] != "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
            or {row["local_path"]: row["sha256"] for row in metadata["files"]} != EXPECTED):
        raise AssertionError("Frozen upstream component inventory changed")
    for name, expected in EXPECTED.items():
        if sha(FIXTURE / name) != expected:
            raise AssertionError("Unchanged upstream source required: " + name)
    return metadata


def capture_fixture(work, optimization="-O2"):
    work.mkdir(parents=True)
    for name in (*EXPECTED, "contracts.json", "UPSTREAM.json"):
        shutil.copyfile(FIXTURE / name, work / name)
    shutil.copytree(FIXTURE / "platform", work / "platform")
    database = work / "compile_commands.json"
    database.write_text(json.dumps([{
        "directory": str(work), "file": name,
        "arguments": ["clang", *FLAGS, optimization, "-c", name, "-o", name + ".o"],
    } for name in SOURCE_FILES], indent=2) + "\n")
    return database


def command(argv, directory, *, timeout=60):
    start = time.perf_counter()
    process = subprocess.run(list(map(str, argv)), cwd=directory, text=True,
                             capture_output=True, timeout=timeout)
    result = {"argv": list(map(str, argv)), "cwd": str(directory),
              "returncode": process.returncode, "stdout": process.stdout,
              "stderr": process.stderr, "seconds": time.perf_counter() - start}
    if process.returncode:
        raise RuntimeError(json.dumps(result))
    return result


def configure(path):
    library = ctypes.CDLL(str(path))
    for name in ("memcmp", "bcmp"):
        function = getattr(library, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_int
    return library


def corpus(seed=1282026):
    for a in range(256):
        for b in range(256):
            yield "all_single_byte_pairs", bytes([a]), bytes([b]), 0, 0, 1, False
    for length in range(129):
        data = bytes((index * 17 + 9) % 256 for index in range(length))
        yield "equal_lengths", data, data, 0, 0, length, False
    for length in (1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128):
        for position in range(length):
            for left, right in ((0, 255), (255, 0)):
                a, b = bytearray([93] * length), bytearray([93] * length)
                a[position], b[position] = left, right
                yield "each_first_difference_position", bytes(a), bytes(b), 0, 0, length, False
    rng = random.Random(seed)
    for _ in range(512):
        length = rng.randrange(513)
        a = bytes(rng.randrange(256) for _ in range(length))
        b = bytearray(a)
        if length and rng.randrange(2):
            for _ in range(1 + rng.randrange(4)):
                b[rng.randrange(length)] = rng.randrange(256)
        yield "seeded_long_inputs", a, bytes(b), 0, 0, length, False
    for length in range(129):
        data = bytes((index * 13 + 5) % 256 for index in range(length + 2))
        for left, right in ((0, 0), (0, 1), (1, 0)):
            yield "shared_read_storage", data, data, left, right, length, True


def expected_compare(left, right):
    for a, b in zip(left, right):
        if a != b:
            return a - b
    return 0


def run_oracle(libraries, output, *, seed=1282026):
    """Every route uses separate equal buffers; only declared read aliases share."""
    counts = Counter()
    routes = {label: configure(path) for label, path in libraries.items()}
    observations = 0
    with output.open("x") as stream:
        for index, (category, left, right, lo, ro, length, shared) in enumerate(corpus(seed)):
            expected = expected_compare(left[lo:lo + length], right[ro:ro + length])
            values = {}
            for label, library in routes.items():
                a = (ctypes.c_ubyte * max(1, len(left)))(*left)
                b = a if shared else (ctypes.c_ubyte * max(1, len(right)))(*right)
                before = bytes(a), bytes(b)
                values[label] = {}
                for name in ("memcmp", "bcmp"):
                    actual = getattr(library, name)(ctypes.addressof(a) + lo,
                                                     ctypes.addressof(b) + ro, length)
                    observations += 1
                    values[label][name] = actual
                    # musl's exact difference is stronger than the public bcmp
                    # zero/nonzero convention and is retained by this source.
                    if actual != expected or (bytes(a), bytes(b)) != before:
                        raise AssertionError(json.dumps({"case": index, "category": category,
                            "route": label, "function": name, "expected": expected,
                            "actual": actual, "storage_unchanged": (bytes(a), bytes(b)) == before}))
            stream.write(json.dumps({"case": index, "category": category,
                "left_hex": left.hex(), "right_hex": right.hex(), "left_offset": lo,
                "right_offset": ro, "length": length, "shared_storage": shared,
                "expected": expected, "observed": values, "storage_unchanged": True},
                separators=(",", ":")) + "\n")
            counts[category] += 1
    return {"input_cases": sum(counts.values()), "input_categories": dict(counts),
            "functions_per_case": 2, "routes": list(routes),
            "native_function_observations": observations,
            "case_log": {"path": str(output), "sha256": sha(output)},
            "result_policy": "exact_original_musl_byte_difference_including_bcmp",
            "read_storage_unchanged": True, "read_aliases_executed": True}


def boundary_controls(library):
    script = r'''import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=ctypes.CDLL(sys.argv[1]); mode=sys.argv[2]; name=sys.argv[3]
fn=getattr(lib,name); fn.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t];fn.restype=ctypes.c_int
n=0 if mode=='empty_null' else 1 if mode=='nonempty_null' else 1<<(8*ctypes.sizeof(ctypes.c_size_t)-1)
if fn(None,None,n)!=0: raise AssertionError(name)
'''
    rows = []
    for name in ("memcmp", "bcmp"):
        for mode, expected in (("empty_null", 0), ("nonempty_null", -6), ("unrepresentable_length", -6)):
            process = subprocess.run([sys.executable, "-c", script, str(library), mode, name],
                                     capture_output=True, text=True, timeout=15)
            if process.returncode != expected:
                raise AssertionError((name, mode, process.returncode, process.stderr))
            rows.append({"function": name, "case": mode, "expected_exit": expected,
                         "exit_code": process.returncode, "original_c_executed": False,
                         "process": {"argv": process.args, "cwd": str(Path.cwd()),
                                     "returncode": process.returncode,
                                     "stdout": process.stdout, "stderr": process.stderr},
                         "scope": "generated_bridge_policy_not_a_general_C_library_contract"})
    return rows


RESOURCE_ALLOCATOR = r'''
struct CompareAllocator;
static LIVE: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(0);
static ALLOC: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FREE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FAIL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for CompareAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::Ordering::SeqCst;
        if layout.size() == 65519 { FAIL.fetch_add(1,SeqCst); return core::ptr::null_mut(); }
        let p=std::alloc::System.alloc(layout);
        if !p.is_null() { LIVE.fetch_add(1,SeqCst); ALLOC.fetch_add(1,SeqCst); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: std::alloc::Layout) {
        use core::sync::atomic::Ordering::SeqCst;
        std::alloc::System.dealloc(p,layout); LIVE.fetch_sub(1,SeqCst); FREE.fetch_add(1,SeqCst);
    }
}
#[global_allocator] static COMPARE_ALLOCATOR: CompareAllocator = CompareAllocator;
#[no_mangle] pub extern "C" fn allocation_event(which:u8)->isize {
    use core::sync::atomic::Ordering::SeqCst;
    match which {0=>LIVE.load(SeqCst),1=>ALLOC.load(SeqCst) as isize,
                 2=>FREE.load(SeqCst) as isize,_=>FAIL.load(SeqCst) as isize}
}
'''


def owned_client(source, work, rustc):
    caller = r'''
export "C" fn owned_compare_probe(size: usize, early: u8) -> i32 effects {alloc, block, panic, write} {
    let allocation: Result<Buffer<u8>, u8> = try_buffer(size);
    match move allocation {
        Result::Err(error) => { return -1; },
        Result::Ok(storage) => {
            let bytes: Buffer<u8> = move storage;
            if early != 0 { drop(move bytes); return 7; }
            let first: i32 = c_memcmp(read bytes, 0, read bytes, 0, size);
            let second: i32 = c_bcmp(read bytes, 0, read bytes, 0, size);
            assert(first == 0 && second == 0);
            drop(move bytes);
            return first + second;
        },
    }
}
'''
    path = work / "owned_client.hepta"
    path.write_text(source + caller)
    program = parse(path.read_text(), str(path))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    generated = emit_rust(program, checked, crate_type="cdylib") + RESOURCE_ALLOCATOR
    (work / "owned_client.rs").write_text(generated)
    build = compile_rust(generated, output=work / "owned_client.so", rustc=rustc, crate_type="cdylib")
    if not build["ok"]:
        raise AssertionError(build)
    lib = ctypes.CDLL(str(work / "owned_client.so"))
    lib.owned_compare_probe.argtypes, lib.owned_compare_probe.restype = [ctypes.c_size_t, ctypes.c_ubyte], ctypes.c_int
    lib.allocation_event.argtypes, lib.allocation_event.restype = [ctypes.c_ubyte], ctypes.c_ssize_t
    rows = []
    for size, early, expected in ((32, 0, 0), (32, 1, 7), (65519, 0, -1),
                                  (64, 0, 0), (0, 0, 0), (65519, 1, -1), (16, 0, 0)):
        before = [lib.allocation_event(i) for i in range(4)]
        value = lib.owned_compare_probe(size, early)
        after = [lib.allocation_event(i) for i in range(4)]
        delta = [a - b for a, b in zip(after, before)]
        expected_events = [0, int(size not in (0, 65519)), int(size not in (0, 65519)), int(size == 65519)]
        if value != expected or before[0] != 0 or after[0] != 0 or delta != expected_events:
            raise AssertionError((size, early, expected, value, before, after))
        rows.append({"size": size, "early_return": bool(early), "result": value,
                     "live_allocations_after": after[0], "event_delta": dict(zip(
                         ("live", "allocated", "freed", "refused"), delta))})
    return {"scope": "authored_safe_Hepta_caller_owns_storage_for_unmodified_borrowing_component",
            "upstream_allocation_migration": False, "source": str(path), "source_sha256": sha(path),
            "native_build": build, "calls": rows, "actual_allocator_refusals": 2,
            "remaining_live_allocations": 0}


def reject_controls(work, clang):
    controls = [
        ("missing_slice", None, "E_C_POINTER_CONTRACT"),
        ("unsupported_global", "unsigned unsupported_global = 1u;\n", "E_C_TOPLEVEL"),
        ("unsupported_pointer_result",
         "const void *escape(const void *p, unsigned n) { return p; }\n", "E_C_TYPE"),
    ]
    rows = []
    for label, extra, expected in controls:
        directory = work / label
        database = capture_fixture(directory)
        contracts = json.loads((FIXTURE / "contracts.json").read_text())
        if label == "missing_slice":
            del contracts["functions"]["memcmp"]["slices"]["vr"]
        else:
            (directory / "extra.c").write_text(extra)
            entries = json.loads(database.read_text())
            entries.append({"directory": str(directory), "file": "extra.c",
                            "arguments": ["clang", *FLAGS, "-O2", "-c", "extra.c"]})
            database.write_text(json.dumps(entries))
            if label == "unsupported_pointer_result":
                contracts["functions"]["escape"] = {"records": {}, "slices": {
                    "p": {"access": "read", "element": "unsigned char", "length": "n"}}}
        destination = directory / "translated"
        report = migrate_c_project(database, destination, contracts=contracts, clang=clang)
        (directory / "rejection.json").write_text(json.dumps(report, indent=2) + "\n")
        if report["ok"] or destination.exists() or expected not in [d["code"] for d in report["diagnostics"]]:
            raise AssertionError((label, report))
        rows.append({"case": label, "expected_diagnostic": expected,
                     "report": str(directory / "rejection.json"), "output_published": False,
                     "authored_negative_control": True})
    return rows


def qualify(*, clang, rustc, output, seed=1282026):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata = verify_upstream()
    compiler = shutil.which("gcc")
    if not compiler:
        raise RuntimeError("Independent GCC is required")
    files = ("hepta/c_migrate.py", "hepta/c_project.py", "hepta/c_translation.py",
             "hepta/c_record_views.py", "hepta/c_migration_project.py", "hepta/backend.py",
             "tools/qualify_c_musl_compare.py")
    before = {name: sha(ROOT / name) for name in files}
    start = time.perf_counter()
    report = {"schema": "hepta.musl-compare-qualification.v1", "ok": False,
              "scope": "two_complete_generic_source_files_not_libc_or_arch_assembly",
              "upstream": metadata, "source_bytes": 319, "source_lines": 16,
              "original_c_functions": 2, "source_modified": False, "seed": seed,
              "implementation_files": before,
              "pipeline": "captured_Clang_AST_to_Hepta_checker_to_Rust_native_reference_backend",
              "source_equivalence_proved": False, "HIA_LLVM_slice_lowering_qualified": False,
              "performance_parity_claimed": False, "new_cross_platform_ABI_qualified": False,
              "target": command([clang, "-dumpmachine"], output)["stdout"].strip(),
              "toolchains": {label: {"path": path, "version": command([path, "--version"], output)["stdout"].splitlines()[0]}
                             for label, path in (("clang", clang), ("gcc", compiler), ("rustc", rustc))},
              "caller_contract": "initialized live bytes; no concurrent writes; shared read aliases permitted; representable length",
              "adapters": {name: sha(FIXTURE / name) for name in ("platform/string.h", "platform/strings.h", "contracts.json")},
              "configurations": []}
    report_path = output / "qualification.json"

    def checkpoint(stage):
        report["stage"] = stage
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    try:
        for optimization in ("-O0", "-O2"):
            work = output / optimization[1:]
            database = capture_fixture(work, optimization)
            row = {"optimization": optimization, "work": str(work)}
            report["configurations"].append(row)
            checkpoint("migration_" + optimization)
            bundle = work / "translated"
            migration = migrate_c_project(database, bundle,
                contracts=json.loads((FIXTURE / "contracts.json").read_text()),
                clang=clang, rustc=rustc, verify_native=True)
            row["migration"] = migration
            if (not migration["ok"] or not migration["declaration_inventory_complete"]
                    or migration["coverage"]["status_counts"] != {"function_converted": 2, "prototype_resolved": 3}
                    or migration["coverage"]["active_project_declarations"] != 5):
                raise AssertionError(migration)
            for name in ("COPYRIGHT", "UPSTREAM.json"):
                shutil.copyfile(FIXTURE / name, bundle / name)
            (bundle / "NOTICE").write_text("Generated derivative of musl 1.2.5 generic memcmp/bcmp.\n"
                "Original upstream source bytes unchanged; explicit authored platform adapter.\n"
                "Full upstream terms and copyright attribution retained in COPYRIGHT.\n")
            libraries = {"generated_Hepta": bundle / "libtranslated.so"}
            row["original_builds"] = {}
            for label, cc in (("gcc", compiler), ("clang", clang)):
                builds = []
                objects = []
                for name in SOURCE_FILES:
                    obj = label + "-" + name + ".o"
                    builds.append(command([cc, *FLAGS, optimization, "-c", name, "-o", obj], work))
                    objects.append(obj)
                library = work / (label + "-original.so")
                builds.append(command([cc, "-shared", "-Wl,-Bsymbolic", *objects, "-o", library], work))
                row["original_builds"][label] = builds
                libraries[label + "_original"] = library
            row["symbols"] = {label: command(["nm", "-D", "--defined-only", str(path)], work)
                              for label, path in libraries.items()}
            for label, symbols in row["symbols"].items():
                actual = {line.split()[-1] for line in symbols["stdout"].splitlines() if line.strip()}
                if not {"memcmp", "bcmp"} <= actual:
                    raise AssertionError((label, actual))
            row["translated_link_input"] = "generated_Rust_only_no_original_C_object_or_library"
            checkpoint("native_oracle_" + optimization)
            row["execution"] = run_oracle(libraries, work / "cases.jsonl", seed=seed)
            row["bridge_controls"] = boundary_controls(libraries["generated_Hepta"])
            caller = work / "caller.c"
            caller.write_text('#include "string.h"\n#include "strings.h"\n'
                'int main(void) { unsigned char a[3]={1,2,3}, b[3]={1,4,3}; '
                'return memcmp(a,b,3)==-2 && bcmp(a,b,3)==-2 && memcmp(a,a,3)==0 ? 0 : 1; }\n')
            row["native_C_caller_build"] = command([compiler, *FLAGS, optimization, caller.name,
                "-L" + str(bundle), "-ltranslated", "-Wl,-rpath," + str(bundle), "-o", "native-caller"], work)
            row["native_C_caller_run"] = command([str(work / "native-caller")], work)
        work = output / "O2"
        source = (work / "translated/source.hepta").read_text()
        row = report["configurations"][-1]
        checkpoint("caller_resources")
        report["caller_resources"] = owned_client(source, work, rustc)
        checkpoint("wrong_implementation_control")
        wrong = source.replace("return ((p_vl[cursor_l_1_offset] as i32) - (p_vr[cursor_r_2_offset] as i32));",
                               "return (0 as i32);", 1)
        if wrong == source:
            raise AssertionError("Wrong-implementation control did not bind the translated source")
        (work / "wrong.hepta").write_text(wrong)
        program = parse(wrong)
        checked = check(program)
        if not checked.ok:
            raise AssertionError("Wrong-result candidate must remain resource-legal")
        generated = emit_rust(program, checked, crate_type="cdylib") + (work / "translated/bridge.rs").read_text()
        (work / "wrong.rs").write_text(generated)
        build = compile_rust(generated, output=work / "wrong.so", rustc=rustc, crate_type="cdylib")
        if not build["ok"]:
            raise AssertionError(build)
        try:
            run_oracle({"wrong_generated_Hepta": work / "wrong.so"}, work / "wrong-cases.jsonl", seed=seed)
        except AssertionError as error:
            report["wrong_implementation"] = {"resource_legal": True, "native_build": build,
                "rejected_by_same_oracle": True, "first_mismatch": str(error)}
        else:
            raise AssertionError("The wrong algorithm escaped the oracle")
        checkpoint("whole_bundle_rejection_controls")
        report["rejection_controls"] = reject_controls(output / "rejections", clang)
        after = {name: sha(ROOT / name) for name in files}
        if before != after:
            raise AssertionError("Migration implementation changed during qualification")
        report.update(ok=True, elapsed_seconds=time.perf_counter() - start,
                      total_input_cases=sum(row["execution"]["input_cases"] for row in report["configurations"]),
                      total_native_observations=sum(row["execution"]["native_function_observations"] for row in report["configurations"]))
        checkpoint("complete")
    except Exception as exc:
        report["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        checkpoint("failed")
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(clang=args.clang, rustc=args.rustc, output=args.output_directory)
    print(json.dumps({key: report[key] for key in ("ok", "source_bytes", "total_input_cases",
                                                 "total_native_observations", "elapsed_seconds")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
