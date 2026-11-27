"""Freeze an explicitly reviewed current native source authority.

Development serialization and receipt checks happen here. The frozen contract is
produced by a native HIA executable. Whole cold qualification is a later step.
"""
from pathlib import Path
from hashlib import sha256
from collections import Counter
import argparse
import json
import os
import struct
import subprocess
import sys
import time
import traceback

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--preseed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output
    env = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source, env=env, text=True, timeout=20).strip()
    assert head == args.base, (head, args.base)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        "schema": "hepta.hia.current-native-source-preparation.v1",
        "passed": False, "source": str(source), "base_commit": head,
        "whole_cold_qualified": False, "whole_native_delivery_qualified": False,
        "target_or_successor_compiler_used": False,
        "development_authoring": True, "calls": [],
    }
    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    def invoke(label, command, raw=None, timeout=120, child_env=None):
        started = time.monotonic_ns()
        process = subprocess.run(command, input=raw, cwd=source, env=env if child_env is None else child_env,
                                 capture_output=True, timeout=timeout)
        (output / (label + ".stdout")).write_bytes(process.stdout)
        (output / (label + ".stderr")).write_bytes(process.stderr)
        row = {"label": label, "argv": command, "returncode": process.returncode,
               "stdout": pin(process.stdout), "stderr": pin(process.stderr),
               "wall_elapsed_ns": time.monotonic_ns() - started}
        if raw is not None:
            row["input"] = pin(raw)
        report["calls"].append(row)
        save()
        print("SOURCE_PREP_STEP", label, process.returncode, flush=True)
        assert process.returncode == 0, row
        return process.stdout
    def module(label, name, arguments):
        code = ("import sys,runpy;sys.path.insert(0," + repr(str(source)) +
                ");sys.argv=[" + repr(name) + "]+ " + repr(arguments) +
                ";runpy.run_module(" + repr(name) + ",run_name='__main__')")
        return invoke(label, [sys.executable, "-I", "-B", "-c", code])
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")
    try:
        module("release-source-dependencies", "tools.hia_native_release_dependencies", ["--check-source-files"])
        sys.path.insert(0, str(source))
        from tools.hia_native_worker_source_authority import load_native_source_authority, _object
        from tools.generate_hia_cold_toolchain_build import generate, encode_metadata, phase_sources, AUTHORITY, RECIPE, POST_RECIPE, BUNDLE_RECIPE
        from tools.generate_hia_cold_source_bootstrap import build_plans
        from tools.generate_hia_cold_report_admit import render, validate_catalog, CHECKS
        from tools.generate_hia_source_release_cold_admit import native_authority_contract, CONTRACT_PATH
        from tools.hia_release_contract import validate_release_contract
        authority_path = source / "docs/HIA_NATIVE_SOURCE_AUTHORITY.json"
        authority_raw = authority_path.read_bytes()
        paths = load_native_source_authority(authority_path)
        assert list(paths) == sorted(set(paths)) and CONTRACT_PATH in paths
        extras = ["examples/hia_bootstrap/cold_build_plans/build-plan.json",
                  "examples/hia_bootstrap/cold_source_bootstrap_plans/build-plan.json"]
        assert not set(paths).intersection(extras), "development plan metadata is outside the native authority"
        before = {name: pin((source / name).read_bytes()) for name in paths}
        before.update({name: (pin((source / name).read_bytes()) if (source / name).exists() else None)
                       for name in extras})
        write_json(output / "before-source-pins.json", before)
        preseed = json.loads((args.preseed / "report.json").read_bytes(), object_pairs_hook=_object)
        assert preseed["passed"] and preseed["target_or_successor_compiler_used"] is False
        for name, expected in preseed["sources"].items():
            assert pin((source / name).read_bytes()) == expected, ("changed preseed source", name)
        module("worker-native-authority", "tools.generate_hia_native_worker_sources",
               ["--native-source-authority", str(authority_path)])
        assert authority_path.read_bytes() == authority_raw
        plan_output_names = {AUTHORITY, RECIPE, POST_RECIPE, *extras}
        first_plan_outputs = None
        for repetition in range(2):
            pre = generate(source)
            post = build_plans(source)
            assert len(pre["stages"]) == 7 and len(post["stages"]) == 1
            assert pre["maximum_stage_imports"] <= 64 and post["maximum_stage_imports"] <= 64
            missing = (set(pre["source_paths"]) | set(post["source_paths"])) - set(paths)
            assert not missing, ("reviewed authority omits actual construction sources", sorted(missing))
            pre_meta = encode_metadata(source, pre, paths, recipe_path=RECIPE)
            authority_bytes = (source / AUTHORITY).read_bytes()
            post_meta = encode_metadata(source, post, paths, recipe_path=POST_RECIPE)
            assert (source / AUTHORITY).read_bytes() == authority_bytes
            assert pre_meta["sources"] == post_meta["sources"] == len(paths)
            plan_output_names.update(row["plan"] for row in pre["stages"] + post["stages"])
            actual = {name: (source / name).read_bytes() for name in sorted(plan_output_names)}
            if first_plan_outputs is None:
                first_plan_outputs = actual
            else:
                assert actual == first_plan_outputs, "native construction serializer is not byte deterministic"
            print("NATIVE_RECIPE_REGENERATION", repetition + 1, len(paths), flush=True)
        assert authority_path.read_bytes() == authority_raw
        source_files = {"schema": "hepta.hia.native-source-files.v1", "mode": "native_only",
                        "files": [name for name in paths if name != CONTRACT_PATH]}
        write_json(source / "docs/HIA_COLD_NATIVE_SOURCE_FILES.json", source_files)
        catalog = validate_catalog(json.loads((source / "docs/HIA_COLD_PLAN_CATALOG.json").read_bytes(), object_pairs_hook=_object))
        assert len(catalog) == 60
        actual_plans = phase_sources((source / BUNDLE_RECIPE).read_bytes())
        actual_catalog = []
        for name in actual_plans:
            raw = (source / name).read_bytes()
            assert raw[:8] == b"HIAQPL01" and struct.unpack_from("<2Q", raw, 16) == (0, 0)
            actual_catalog.append((sha256(raw).hexdigest(), struct.unpack_from("<Q", raw, 8)[0]))
        assert Counter(actual_catalog) == Counter((r["plan_sha256"], r["node_count"]) for r in catalog)
        metadata_path = source / "docs/HIA_NATIVE_SELFHOST_METADATA.json"
        metadata_raw = metadata_path.read_bytes()
        metadata = json.loads(metadata_raw, object_pairs_hook=_object)
        assert metadata["source_identity"]["files"] == {}
        assert metadata["native_cold_qualification"] == {
            "schema": "hepta.hia.selfhost-cold-replay.v2",
            "runtime": "native HIA with explicit mechanical syscall and ELF ABI capsules",
            "phase_plan_catalog": catalog, "checks": CHECKS,
            "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
            "scheduler": {"phase_workers": 2, "archive_workers": 1,
                          "max_pending_archives": 2, "max_unsealed_phases": 4},
            "all_input_correctness_proved": False,
        }
        gate_text, gate_record, _ = render(source, catalog, native_source_authority=authority_path)
        for role in ("cold_report_admit", "source_release_cold_admit"):
            (source / "examples/hia_bootstrap" / (role + ".hepta")).write_text(gate_text)
        expected = native_authority_contract(source, authority_path)
        files = {name: sha256((source / name).read_bytes()).hexdigest() for name in paths}
        assert expected["source_identity"]["files"] == {name: digest for name, digest in files.items() if name != CONTRACT_PATH}
        inventory = b"HIASPI01" + struct.pack("<Q", len(files)) + b"".join(
            struct.pack("<Q", len(name.encode("ascii"))) + bytes.fromhex(digest) + name.encode("ascii")
            for name, digest in sorted(files.items()))
        wire = b"HIASCG01" + struct.pack("<3Q", len(metadata_raw), len(inventory), 0) + metadata_raw + inventory
        (output / "contract-producer-input.hiascg").write_bytes(wire)
        product = preseed["products"]["hia-source-contract"]
        producer = Path(product["path"])
        assert pin(producer.read_bytes()) == {k: product[k] for k in ("bytes", "sha256")}
        native_contract = invoke("native-contract-producer", [str(producer)], wire, timeout=30, child_env={"PATH": ""})
        assert json.loads(native_contract, object_pairs_hook=_object) == expected
        (source / CONTRACT_PATH).write_bytes(native_contract)
        assert validate_release_contract(source) == expected
        module("worker-native-authority-check", "tools.generate_hia_native_worker_sources",
               ["--native-source-authority", str(authority_path), "--check"])
        for name in ("source_release_cold_admit", "cold_report_admit"):
            module(name + "-check", "tools.generate_hia_" + name,
                   ["--contract-root", str(source), "--native-source-authority", str(authority_path), "--check"])
        module("release-contract-check", "tools.generate_hia_selfhost_contract", ["--check"])
        assert authority_path.read_bytes() == authority_raw and metadata_path.read_bytes() == metadata_raw
        files = {}
        for name in paths:
            path = source / name
            assert path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, name
            raw = path.read_bytes()
            assert path.suffix.lower() not in (".py", ".pyc", ".rs", ".elf", ".so", ".o", ".flat", ".whl")
            assert raw[:4] != b"\x7fELF"
            files[name] = sha256(raw).hexdigest()
        manifest = b"HIASXM01" + struct.pack("<3Q", len(files), 1, 0) + b"".join(
            struct.pack("<2Q", len(name.encode("ascii")), (source / name).stat().st_size) +
            bytes.fromhex(digest) + name.encode("ascii") for name, digest in sorted(files.items()))
        (output / "source-manifest.hiasxm").write_bytes(manifest)
        write_json(output / "source-manifest.json", files)
        after = {name: pin((source / name).read_bytes()) for name in sorted(set(paths) | set(extras))}
        write_json(output / "after-source-pins.json", after)
        report.update(
            passed=True, source_count=len(paths), source_bytes=sum((source / p).stat().st_size for p in paths),
            changed_sources=[name for name in paths if after[name] != before[name]],
            changed_development_artifacts=[name for name in extras if after[name] != before[name]],
            source_authority=pin(authority_raw), pre_recipe=pre_meta, post_recipe=post_meta,
            plan_regeneration_twice_exact=True, phase_count=len(catalog),
            qualification_nodes=sum(r["node_count"] for r in catalog),
            gate=gate_record, native_producer=product,
            native_contract=pin(native_contract), metadata=pin(metadata_raw),
            source_manifest=pin(manifest),
        )
        save()
        print("CURRENT_NATIVE_SOURCE_PREPARATION_PASS", len(paths), json.dumps(report["changed_sources"]), flush=True)
    except BaseException:
        report["error"] = traceback.format_exc()
        save()
        raise

if __name__ == "__main__":
    main()
