"""Execute a complete upstream C resource module in two cross-TU builds.

The exact Ring-Buffer source remains unchanged. An explicitly authored second
translation unit composes its mutable record and slice contracts. The target
contains translated safe Hepta and the generated Rust ABI edge, not upstream C
objects. This qualification does not claim standalone HIA support for records.
"""
from __future__ import annotations

import argparse
from collections import deque
from copy import deepcopy
import ctypes
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.c_resource_matrix import migrate_c_resource_matrix
from hepta.c_project_matrix import verify_project_matrix
from tools.qualify_c_ring_buffer import (FIXTURE, FLAGS, Ring, configure,
                                         layout_probe, run_sequences, verify_upstream)
from tools.qualify_cpp_upgrade import _run, digest, _dependency_paths

EXAMPLE = ROOT / "examples/c/resource_matrix"
VARIANTS = (("plain", "c11", 0), ("masked", "c17", 90))


def contracts():
    value = json.loads((FIXTURE / "contracts.json").read_text())
    value["functions"]["ring_transfer"] = {
        "records": {"buffer": {"access": "mut"}},
        "slices": {"input": {"access": "read", "length": "input_len"},
                   "output": {"access": "mut", "length": "output_len"}},
    }
    return value


def make_inputs(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "source"
    source.mkdir()
    metadata = verify_upstream()
    for entry in metadata["files"]:
        shutil.copyfile(FIXTURE / entry["local_path"], source / entry["local_path"])
    for name in ("client.c", "client.h"):
        shutil.copyfile(EXAMPLE / name, source / name)
    commands, selections = [], []
    for name, standard, mask in VARIANTS:
        indices = []
        for unit in ("ringbuffer.c", "client.c"):
            indices.append(len(commands))
            commands.append({"directory": str(source), "file": unit,
                             "arguments": ["clang", "-std=" + standard, "-DNDEBUG", "-funsigned-char",
                                           "-DHEPTA_RING_OUTPUT_MASK=" + str(mask), "-O2", "-c", unit]})
        selections.append({"name": name, "command_indices": indices})
    (directory / "compile_commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    manifest = directory / "matrix.json"
    manifest.write_text(json.dumps({"schema": "hepta.build-matrix.v1", "language": "c",
                                    "database": "compile_commands.json", "variants": selections}, indent=2) + "\n")
    return manifest


def transfer_sequences(original, translated, mask, *, steps=256):
    libraries = [configure(path) for path in (original, translated)]
    for library in libraries:
        library.ring_transfer.argtypes = [ctypes.POINTER(Ring), ctypes.POINTER(ctypes.c_uint8),
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        library.ring_transfer.restype = ctypes.c_size_t
    observations, digest_state = 0, hashlib.sha256()
    for capacity in (1, 2, 4, 8, 32, 128):
        stores = [(ctypes.c_uint8 * capacity)() for _ in libraries]
        records = [Ring() for _ in libraries]
        for lib, record, store in zip(libraries, records, stores):
            lib.ring_buffer_init(ctypes.byref(record), store, capacity)
        expected = deque(maxlen=capacity - 1)
        rng = random.Random(0xC270000 + capacity)
        for step in range(steps):
            incoming = [rng.randrange(256) for _ in range(step % (capacity * 2 + 1))]
            output_len = step % (capacity + 3)
            expected.extend(incoming)
            count = min(output_len, len(expected))
            wanted = [expected.popleft() ^ mask for _ in range(count)]
            wanted += [173] * (output_len + 2 - count)
            observed = []
            for lib, record, store in zip(libraries, records, stores):
                data = (ctypes.c_uint8 * len(incoming))(*incoming)
                out = (ctypes.c_uint8 * (output_len + 2))(*([173] * (output_len + 2)))
                result = lib.ring_transfer(ctypes.byref(record), data if incoming else None,
                                           len(incoming), out if output_len else None, output_len)
                if result != count or list(out) != wanted or list(data) != incoming:
                    raise AssertionError(("cross-TU transfer", capacity, step, result, count))
                observed.append((record.buffer_mask, record.tail_index, record.head_index, bytes(store)))
                if lib.ring_buffer_num_items(ctypes.byref(record)) != len(expected):
                    raise AssertionError("Cross-TU resource state differs from independent deque")
            if observed[0] != observed[1]:
                raise AssertionError("Cross-TU persistent state/backing bytes differ")
            digest_state.update(bytes(wanted))
            observations += 1
    return {"state_transitions": observations, "native_transfer_calls": observations * 2,
            "native_followup_query_calls": observations * 2,
            "native_initialization_calls": 12,
            "oracle": "independent Python deque plus configured output XOR",
            "output_digest": digest_state.hexdigest(), "mask": mask,
            "checks": ["return", "output and sentinels", "input not mutated", "persistent scalar state",
                       "all backing bytes", "cross-function query after transfer"]}


BOUNDARY_SCRIPT = r'''import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class R(ctypes.Structure):
 _fields_=[('buffer',ctypes.POINTER(ctypes.c_uint8)),('buffer_mask',ctypes.c_size_t),('tail_index',ctypes.c_size_t),('head_index',ctypes.c_size_t)]
p=ctypes.POINTER(R);q=ctypes.POINTER(ctypes.c_uint8)
lib=ctypes.CDLL(sys.argv[1]);lib.ring_buffer_init.argtypes=[p,q,ctypes.c_size_t]
lib.ring_transfer.argtypes=[p,q,ctypes.c_size_t,q,ctypes.c_size_t]
store=(ctypes.c_uint8*8)();data=(ctypes.c_uint8*2)(17,29);out=(ctypes.c_uint8*2)();r=R()
lib.ring_buffer_init(ctypes.byref(r),store,8)
mode=sys.argv[2]
if mode=='input_output_alias':out=data
elif mode=='output_storage_alias':out=store
elif mode=='null_input':data=None
elif mode=='null_output':out=None
elif mode=='bad_cross_module_index':r.head_index=999
else:raise RuntimeError(mode)
lib.ring_transfer(ctypes.byref(r),data,2,out,2)
'''


def _symbols(text):
    return sorted({line.split()[-1] for line in text.splitlines()
                   if len(line.split()) >= 2 and line.split()[-2] in {"T", "W"}})


def qualify(directory, *, clang, rustc, steps=256):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("Qualification directory must be new")
    work.mkdir(parents=True)
    report = {"schema": "hepta.c-resource-matrix-qualification.v1", "ok": False,
              "upstream": verify_upstream(), "variants": [], "negative_contracts": [],
              "native_hia_implementations": 0, "native_safe_hepta_rust_variants": 0,
              "original_c_objects_in_targets": False, "source_equivalence_proved": False,
              "foreign_pointer_provenance_proved": False,
              "performance": {"status": "not_measured", "performance_floor_established": False}}
    def checkpoint():
        (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    try:
        manifest = make_inputs(work / "inputs")
        source = manifest.parent / "source"
        before = {str(p): digest(p) for p in source.iterdir() if p.is_file()}
        started = time.monotonic()
        matrix = migrate_c_resource_matrix(manifest, work / "translated", clang=clang, rustc=rustc,
                                           contracts_by_variant={name: contracts() for name, _, _ in VARIANTS},
                                           verify_native=True)
        report["migration"] = matrix
        report["migration_seconds"] = time.monotonic() - started
        checkpoint()
        if not matrix["ok"]:
            raise AssertionError("Contracted matrix migration failed; retained variant diagnostics")
        compiler = shutil.which(clang) or clang
        nm = shutil.which("nm")
        for variant, (name, standard, mask) in zip(matrix["variants"], VARIANTS):
            row = {"name": name, "ok": False, "processes": []}
            report["variants"].append(row)
            out = work / name
            out.mkdir()
            flags = ["-std=" + standard, "-DNDEBUG", "-funsigned-char", "-O2", "-fPIC",
                     "-DHEPTA_RING_OUTPUT_MASK=" + str(mask)]
            objects, defined = [], set()
            for unit in ("ringbuffer", "client"):
                obj = out / (unit + ".o")
                _run([compiler, *flags, "-MD", "-MF", out / (unit + ".d"), "-c", source / (unit + ".c"), "-o", obj],
                     owner=row, directory=out, stage="compile_" + unit)
                symbols = _run([nm, "--defined-only", "--extern-only", obj], owner=row, directory=out, stage="symbols_" + unit)
                defined.update(_symbols(symbols["stdout"]))
                objects.append(obj)
            original = out / "original.so"
            _run([compiler, "-shared", *objects, "-o", original], owner=row, directory=out, stage="link_original")
            translated = work / "translated" / name / "libtranslated.so"
            target_symbols = _run([nm, "-D", "--defined-only", translated], owner=row, directory=out, stage="symbols_target")
            expected = sorted(fn["name"] for fn in variant["migration"]["functions"] if fn["external_symbol"])
            if sorted(defined) != expected or _symbols(target_symbols["stdout"]) != expected:
                raise AssertionError(("actual ABI export inventory differs", sorted(defined), expected,
                                      _symbols(target_symbols["stdout"])))
            row["actual_export_symbols"] = expected
            row["all_original_object_exports_accounted"] = True
            row["upstream_sequences"] = run_sequences(original, translated, steps=steps)
            row["upstream_sequences"]["counter_unit"] = "paired_original_and_translated_operation_observations"
            row["upstream_sequences"]["actual_native_calls"] = row["upstream_sequences"]["native_differential_calls"] * 2
            row["cross_module_sequences"] = transfer_sequences(original, translated, mask, steps=steps)
            # Both actual native language representations expose layout probes.
            for leaf in ("ringbuffer.h", "ringbuffer.c"):
                shutil.copyfile(source / leaf, out / leaf)
            layout = layout_probe(original, (work / "translated" / name / "generated.rs").read_text(),
                                  out, compiler, rustc)
            # The historical helper labels its C route "gcc". This qualifier
            # selected the actual Clang driver above; do not inherit that label.
            row["layout"] = {field: {"original_c": values["gcc"], "rust": values["rust"]}
                             for field, values in layout.items()}
            row["boundary_controls"] = []
            for mode in ("input_output_alias", "output_storage_alias", "null_input", "null_output", "bad_cross_module_index"):
                observed = _run([sys.executable, "-c", BOUNDARY_SCRIPT, translated, mode], owner=row, directory=out,
                                stage="boundary_" + mode, allow_failure=True)
                if observed["exit_code"] != -6:
                    raise AssertionError((mode, observed["exit_code"]))
                row["boundary_controls"].append({"case": mode, "exit_code": -6,
                                                 "original_c_executed_outside_contract": False})
            row["artifacts"] = {str(p): digest(p) for p in [*objects, original, translated,
                out / "layout.c", out / "c_layout.so", out / "rust_layout.so"]}
            row["dependencies"] = {unit: {p: digest(p) for p in _dependency_paths((out / (unit + ".d")).read_text())}
                                   for unit in ("ringbuffer", "client")}
            row["ok"] = True
            report["native_safe_hepta_rust_variants"] += 1
            checkpoint()
        for mode in ("caller_read_only", "missing_callee_contract", "missing_variant_contract"):
            candidates = {name: contracts() for name, _, _ in VARIANTS}
            if mode == "caller_read_only":
                for value in candidates.values():
                    value["functions"]["ring_transfer"]["records"]["buffer"]["access"] = "read"
            elif mode == "missing_callee_contract":
                for value in candidates.values():
                    del value["functions"]["ring_buffer_queue_arr"]
            else:
                del candidates["masked"]
            refused = migrate_c_resource_matrix(manifest, work / ("negative_" + mode), clang=clang, rustc=rustc,
                                                 contracts_by_variant=candidates)
            report["negative_contracts"].append({"case": mode, "report": refused})
            if refused["ok"]:
                raise AssertionError("Invalid cross-module resource contract admitted: " + mode)
        verify_project_matrix(matrix["matrix_capture"])
        after = {str(p): digest(p) for p in source.iterdir() if p.is_file()}
        if before != after:
            raise AssertionError("Real module sources changed during qualification")
        report["source_snapshot"] = before
        report["source_unchanged"] = True
        report["all_activity_dispositions"] = [row["migration"]["coverage"] for row in matrix["variants"]]
        report["ok"] = True
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        report["error"] = str(exc)
    finally:
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    args = parser.parse_args()
    result = qualify(args.workdir, clang=args.clang, rustc=args.rustc)
    print(json.dumps({"ok": result["ok"], "report": str(args.workdir / "qualification.json"),
                      "error": result.get("error")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
