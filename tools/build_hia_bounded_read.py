"""Build an explicitly selected HIA bounded-file reader.

The default build entry requires a completed cold report for this exact current
source closure. --development is a separate, explicit non-qualification entry.
Neither entry activates public reads or proves arbitrary foreign-object behavior.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE = "examples/hia_bootstrap/bounded_read.hiaasm"
ABI = "hepta/hia_bounded_read_abi.json"
SCHEMA = "hepta.hia.bounded-read-native.v3"
CHECK_ROOT = "tools/hia_bounded_read_checks"
OWNED_SOURCE_FILES = (
    SOURCE, ABI, "hepta/hia_bounded_read_native.py", "hepta/hia_program_tools.py",
    "hepta/hia_json_preflight_native.py", "hepta/hia_worker_report_native.py",
    "tools/generate_hia_bounded_read.py", "tools/build_hia_bounded_read.py",
    "tools/qualify_hia_bounded_read.py", "tools/hia_selfhost_process_owner.py",
    "tools/qualify_hia_selfhost.py", "tools/hia_selfhost_child.py",
    "tests/test_hia_bounded_read_source.py", "tests/test_hia_program_tools.py",
    "tests/fixtures/hia_program_tools_acffa.py.txt", "tools/hia_core_reference.py",
    "hepta/hia_agent_contract.py", "MANIFEST.in", "setup.py", "pyproject.toml",
    "docs/HIA_BOUNDED_READ_NATIVE.md",
    CHECK_ROOT + "/source_common.py", CHECK_ROOT + "/populations.json",
    CHECK_ROOT + "/reject_cases.py", CHECK_ROOT + "/lifetime_cases.py",
    CHECK_ROOT + "/permission_cases.py", CHECK_ROOT + "/filesystem_cases.py",
    CHECK_ROOT + "/original_eight.py", CHECK_ROOT + "/caller_observer.py",
)
PRODUCER_FIELDS = {
    "case", "input_sha256", "input_bytes", "artifact_sha256", "format",
    "runner_sha256", "wall_elapsed_ns", "produced_image", "produced_bytes",
    "produced_sha256",
}
NATIVE_LIMITS = {
    "cpu_seconds": 10, "address_bytes": 256 << 20, "core_dumpable": False,
    "stack_bytes": 8 << 20, "output_capacity": 1 << 20, "workspace_bytes": 1 << 20,
}


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
    return pin(raw)


def source_inputs():
    return {name: (ROOT / name).read_bytes() for name in OWNED_SOURCE_FILES}


def observe_compile(directory, compiler, compiler_raw, source, image, receipt):
    """Join the original child request/stdout/receipt and full output bytes."""
    directory, compiler, image = Path(directory), Path(compiler), Path(image)
    label = "bounded-read"
    originals = {}
    def actual(name, maximum):
        path = directory / name
        raw = path.read_bytes()
        if len(raw) > maximum:
            raise ValueError("bounded-read compile original exceeds its fixed bound: " + name)
        originals[name] = pin(raw)
        return raw
    request = json.loads(actual(label + ".request.json", 1 << 20))
    wanted = {
        "format": "flat-x86-64", "image": str(compiler),
        "image_sha256": sha256(compiler_raw).hexdigest(),
        "source": str(directory / (label + ".input.bin")),
        "source_sha256": sha256(source).hexdigest(),
        "capacity": 1 << 20, "workspace_size": 1 << 20,
        "workspace_fill": 0, "output": str(directory / (label + ".output.bin")),
    }
    child = json.loads(actual(label + ".stdout.log", 4 << 20))
    raw_receipt = json.loads(actual(label + ".receipt.json", 4 << 20))
    output = actual(label + ".output.bin", 1 << 20)
    produced = actual(label + ".image.bin", 1 << 20)
    actual(label + ".stderr.log", 4 << 20)
    child_source = (ROOT / "tools/hia_selfhost_child.py").read_bytes()
    if (request != wanted or actual(label + ".input.bin", 1 << 20) != source
            or raw_receipt != receipt or type(child) is not dict
            or not PRODUCER_FIELDS <= set(receipt)
            or child != {key: value for key, value in receipt.items()
                         if key not in PRODUCER_FIELDS}
            or receipt.get("case") != label or receipt.get("status") != "returned"
            or type(receipt.get("abi_status")) is not int or receipt["abi_status"] != 0
            or receipt.get("source_unchanged") is not True
            or receipt.get("forbidden_compiler_modules_loaded") != []
            or receipt.get("limits") != NATIVE_LIMITS
            or receipt.get("format") != "flat-x86-64"
            or receipt.get("runner_sha256") != sha256(child_source).hexdigest()
            or receipt.get("artifact_sha256") != wanted["image_sha256"]
            or receipt.get("image_sha256") != wanted["image_sha256"]
            or receipt.get("source_sha256") != wanted["source_sha256"]
            or receipt.get("input_sha256") != wanted["source_sha256"]
            or receipt.get("input_bytes") != len(source)
            or receipt.get("output_sha256") != sha256(output).hexdigest()
            or receipt.get("produced_image") != str(image)
            or image != directory / (label + ".image.bin")
            or type(receipt.get("core_u32")) is not int
            or not 0 < receipt["core_u32"] == receipt.get("produced_bytes") == len(produced) <= 1 << 20
            or receipt.get("produced_sha256") != sha256(produced).hexdigest()
            or len(output) != 1 << 20 or output[:len(produced)] != produced
            or image.read_bytes() != produced):
        raise ValueError("bounded-read actual native compile originals disagree")
    return produced, originals


def _build(output, compiler, *, cold_report):
    output, compiler = Path(output).resolve(), Path(compiler).resolve(strict=True)
    cold_report = None if cold_report is None else Path(cold_report).resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    cold_raw = None if cold_report is None else cold_report.read_bytes()
    # Every mode binds current source; only this exact cold gate permits the
    # matching-cold label. No outputs exist when that gate refuses.
    sources = (current_sources() if cold_raw is None
               else admit_cold_build(compiler_raw, cold_raw))
    inputs = source_inputs()
    hashes = {name: sha256(raw).hexdigest() for name, raw in inputs.items()}
    if any(sources.get(name) != digest for name, digest in hashes.items()):
        raise ValueError("bounded-read build input is outside the current source closure")
    from tools.generate_hia_bounded_read import entry_abi
    if inputs[ABI] != wire(entry_abi(inputs[SOURCE])):
        raise ValueError("bounded-read source-owned entry ABI differs")
    output.mkdir(mode=0o700)
    report = {
        "schema": "hepta.hia.bounded-read-build.v1", "status": "HOLD",
        "scope": ("MATCHING_SOURCE_COLD_BUILD" if cold_raw is not None
                  else "DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD"),
        "source_manifest": sources, "owned_source_sha256": hashes,
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
        "cold_report_sha256": None if cold_raw is None else sha256(cold_raw).hexdigest(),
        "source_owned_abi": json.loads(inputs[ABI]),
        "source_owned_abi_sha256": hashes[ABI],
        "production_activated": False, "all_input_equivalence_proved": False,
        "whole_native_delivery_qualified": False,
        "filesystem_and_context_operations_remain_hosted": True,
    }
    try:
        image, receipt = compile_stage(output, "bounded-read", compiler, inputs[SOURCE])
        image_raw, originals = observe_compile(
            output, compiler, compiler_raw, inputs[SOURCE], image, receipt)
        if (compiler.read_bytes() != compiler_raw or source_inputs() != inputs
                or current_sources() != sources
                or (cold_report is not None and cold_report.read_bytes() != cold_raw)):
            raise ValueError("bounded-read build inputs changed")
        manifest = {
            "schema": SCHEMA, "source_sha256": hashes[SOURCE],
            "image_path": image.name, "image_sha256": sha256(image_raw).hexdigest(),
            "compiler_sha256": report["compiler_sha256"],
        }
        raw_manifest = wire(manifest)
        report.update(status="NATIVE_CANDIDATE_BUILT", manifest=manifest,
                      manifest_sha256=sha256(raw_manifest).hexdigest(),
                      native_compile_receipt=receipt, compiler_originals=originals,
                      build_inputs_stable=True)
        write_new(output / "build.json", wire(report))
        # Publish the selectable manifest only after a complete build record.
        write_new(output / "manifest.json", raw_manifest)
    except BaseException as error:
        report["status"] = "HOLD"
        report["failure"] = {"type": type(error).__name__, "text": str(error)}
        if not (output / "build.json").exists():
            write_new(output / "build.json", wire(report))
        raise
    return output / "manifest.json"


def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report=cold_report)


def build_development(output, compiler):
    return _build(output, compiler, cold_report=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cold-report", type=Path)
    mode.add_argument("--development", action="store_true")
    args = parser.parse_args()
    path = (build_development(args.output, args.compiler) if args.development
            else build(args.output, args.compiler, args.cold_report))
    print(path)


if __name__ == "__main__":
    main()
