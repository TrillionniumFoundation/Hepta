"""Replay native differential qualification of complete frozen upstream modules.

The two C Algorithms integer-key modules retain their upstream bytes and ISC
notices. The scope is those complete modules, not the full upstream library.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.c_migrate import migrate_c_project
from tools.qualify_c_migration import command, sha

FIXTURE = ROOT / "tests/fixtures/c_migration/c_algorithms"


def verify_upstream() -> dict:
    metadata = json.loads((FIXTURE / "UPSTREAM.json").read_text())
    if metadata["commit"] != "23d453792ed89a28ed7d2c8d4311a4d9f7822edd":
        raise RuntimeError("The qualified upstream commit changed")
    expected = {
        "compare-int.c": "6a40430ebc990fd1b386cf792e13a33887379b59",
        "compare-int.h": "4307451fc1bbb43f13fba098f183b9d950cf3c25",
        "hash-int.c": "9a4acb8a6362f29b01fbb2117ef230fa20244e31",
        "hash-int.h": "8caa4ab6dde9ea6a3f8340585c7050f0d47f1071",
        "COPYING.md": "bbcd965967d96d26a04710d59029dc96f63e30f4",
        "UPSTREAM_README.md": "317e5d09aab346bad84c27903882cf85e7d55be9",
    }
    if {item["local_path"]: item["git_blob"] for item in metadata["files"]} != expected:
        raise RuntimeError("The complete frozen module inventory changed")
    for item in metadata["files"]:
        data = (FIXTURE / item["local_path"]).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != item["git_blob"]:
            raise RuntimeError("Upstream bytes changed: " + item["local_path"])
        item.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    return metadata


def configure(path: Path):
    library = ctypes.CDLL(str(path))
    for name in ("int_equal", "int_compare"):
        function = getattr(library, name)
        function.argtypes, function.restype = [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int32
    library.int_hash.argtypes, library.int_hash.restype = [ctypes.c_void_p], ctypes.c_uint32
    return library


def boundary_rejection(library: Path, mode: str) -> dict:
    source = """import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=ctypes.CDLL(sys.argv[1]); lib.int_hash.argtypes=[ctypes.c_void_p];lib.int_hash.restype=ctypes.c_uint32
buf=(ctypes.c_uint8*16)()
p=None if sys.argv[2]=='null' else ctypes.addressof(buf)+1
lib.int_hash(p)
"""
    process = subprocess.run([sys.executable, "-c", source, str(library), mode], capture_output=True, timeout=10)
    if process.returncode != -6:
        raise AssertionError((mode, process.returncode, process.stderr))
    return {"input": mode, "exit_code": process.returncode, "expected": "SIGABRT_before_slice_construction",
            "original_c_executed": False, "reason": "outside_defined_annotated_input_domain"}


def qualify(*, clang: str, rustc: str | None, output: Path, seed: int = 231024) -> dict:
    started = time.perf_counter()
    metadata = verify_upstream()
    original_compiler = shutil.which("gcc")
    if original_compiler is None:
        raise RuntimeError("Independent original C compiler GCC is required")
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    report = {"schema": "hepta.c-upstream-qualification.v1", "ok": False,
              "scope": "two_complete_upstream_integer_key_modules_not_the_whole_library",
              "source_equivalence_proved": False, "performance_parity_claimed": False,
              "runtime_artifacts_retained": False, "upstream": metadata, "seed": seed,
              "implementation_commit": git.stdout.strip() if git.returncode == 0 else None,
              "implementation_files": {name: sha(ROOT / name) for name in [
                  "hepta/c_migrate.py", "hepta/c_project.py", "hepta/c_translation.py", "hepta/c_aliases.py",
                  "hepta/c_allocation.py", "hepta/c_migration_project.py", "tools/qualify_c_migration.py",
                  "tools/qualify_c_algorithms.py"]},
              "original_compiler": {"path": original_compiler, "sha256": sha(Path(original_compiler)),
                                    "version": command([original_compiler, "--version"])["stdout"].splitlines()[0]},
              "caller_contracts": {"sha256": sha(FIXTURE / "contracts.json"),
                                   "origin": "explicit_human_authored_not_inferred_or_proved",
                                   "void_pointer_element": "one_initialized_live_aligned_C_int_32",
                                   "read_aliasing": "equal_pointer_addresses_are_allowed_and_executed",
                                   "concurrent_foreign_writes": "excluded_by_read_slice_contract"}}
    with tempfile.TemporaryDirectory(prefix="hepta-c-algorithms-") as temporary:
        work = Path(temporary)
        for item in metadata["files"]:
            shutil.copyfile(FIXTURE / item["local_path"], work / item["local_path"])
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": name,
                                         "arguments": ["clang", "-std=c11", "-O2", "-c", name, "-o", name + ".o"]}
                                        for name in ("compare-int.c", "hash-int.c")]))
        bundle = work / "translated"
        migration = migrate_c_project(database, bundle, contracts=json.loads((FIXTURE / "contracts.json").read_text()),
                                      clang=clang, rustc=rustc, verify_native=True)
        report["migration"] = migration
        if not migration["ok"] or not migration["declaration_inventory_complete"]:
            raise RuntimeError(json.dumps(migration["diagnostics"]))
        if migration["coverage"]["active_project_declarations"] != 6 or migration["coverage"]["status_counts"] != {"function_converted": 3, "prototype_resolved": 3}:
            raise AssertionError("Unexpected full-module declaration denominator")
        original = work / "original.so"
        report["original_build"] = command([original_compiler, "-std=c11", "-O2", "-shared", "-fPIC",
                                            str(work / "compare-int.c"), str(work / "hash-int.c"), "-o", str(original)])
        c, h = configure(original), configure(bundle / "libtranslated.so")
        edges = [-(1 << 31), -(1 << 31) + 1, -100000, -256, -1, 0, 1, 255, 65535, (1 << 31) - 2, (1 << 31) - 1]
        pairs = [(a, b) for a in edges for b in edges]
        rng = random.Random(seed)
        pairs += [(rng.randrange(-(1 << 31), 1 << 31), rng.randrange(-(1 << 31), 1 << 31)) for _ in range(4096)]
        comparisons = {"int_compare": 0, "int_equal": 0, "int_hash": 0}
        same_address = 0
        for left, right in pairs:
            ca, cb, ha, hb = [ctypes.c_int32(value) for value in (left, right, left, right)]
            for name in ("int_compare", "int_equal"):
                a, b = getattr(c, name)(ctypes.byref(ca), ctypes.byref(cb)), getattr(h, name)(ctypes.byref(ha), ctypes.byref(hb))
                expected = ((left > right) - (left < right)) if name == "int_compare" else int(left == right)
                if a != b or b != expected:
                    raise AssertionError((name, left, right, a, b))
                comparisons[name] += 1
                a, b = getattr(c, name)(ctypes.byref(ca), ctypes.byref(ca)), getattr(h, name)(ctypes.byref(ha), ctypes.byref(ha))
                if a != b or b != (0 if name == "int_compare" else 1):
                    raise AssertionError("Read alias mismatch")
                comparisons[name] += 1
                same_address += 1
            for original_value, translated_value in ((ca, ha), (cb, hb)):
                a, b = c.int_hash(ctypes.byref(original_value)), h.int_hash(ctypes.byref(translated_value))
                if a != b or b != original_value.value % (1 << 32):
                    raise AssertionError("Hash conversion mismatch")
                comparisons["int_hash"] += 1
            if (ca.value, cb.value, ha.value, hb.value) != (left, right, left, right):
                raise AssertionError("Read-only integer storage was mutated")
        value = ctypes.c_int32(13)
        negative = c.int_hash(ctypes.byref(value)) != h.int_hash(ctypes.byref(value)) + 1
        if not negative:
            raise AssertionError("Wrong-result control escaped")
        report["execution"] = {"input_pairs": len(pairs), "edge_pairs": len(edges) ** 2, "random_pairs": 4096,
                               "differential_cases": comparisons, "total_differential_cases": sum(comparisons.values()),
                               "same_address_read_alias_cases": same_address,
                               "checks": ["C return values", "independent arithmetic expectations", "input bytes unchanged", "read aliasing"],
                               "wrong_result_control_rejected": negative,
                               "invalid_bridge_inputs": [boundary_rejection(bundle / "libtranslated.so", mode) for mode in ("null", "misaligned")]}
        output.parent.mkdir(parents=True, exist_ok=True)
        generated = output.parent / "c-algorithms-generated"
        generated.mkdir(exist_ok=True)
        report["retained_generated_sources"] = {}
        for name in ("source.hepta", "bridge.rs"):
            shutil.copyfile(bundle / name, generated / name)
            report["retained_generated_sources"][name] = {"path": str(generated / name), "sha256": sha(generated / name)}
        # Preserve the upstream terms with the translated derivative files.
        shutil.copyfile(FIXTURE / "COPYING.md", generated / "COPYING.md")
        (generated / "NOTICE").write_text("Translated from fragglet/c-algorithms integer-key modules.\nCopyright (c) 2005-2008, Simon Howard\nUpstream commit: " + metadata["commit"] + "\nThe ISC terms in COPYING.md apply to the retained translated derivatives.\n")
    report.update(ok=True, seconds=time.perf_counter() - started)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(clang=args.clang, rustc=args.rustc, output=args.output)
    print(json.dumps({"ok": report["ok"], "output": str(args.output), "execution": report["execution"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
