"""Build the HIA lexical JSON layout component from current physical inputs."""
from __future__ import annotations
import argparse
from contextlib import nullcontext
from hashlib import sha256
import json
from pathlib import Path
from tools.build_hia_json_preflight import ROOT, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.hia_cold_compiler import read_cold_build_inputs
from tools.hia_component_input_custody import verify_component_custody
from tools.qualify_hia_selfhost import compile_stage, release_compiler_calls

SOURCE = "examples/hia_bootstrap/json_pretty.hepta"
INPUTS = (
    SOURCE, "hepta/hia_json_pretty_native.py", "tools/build_hia_json_pretty.py",
    "hepta/hia_json_preflight_native.py", "tools/hia_cold_compiler.py",
    "tools/hia_component_input_custody.py", "tools/build_hia_json_preflight.py",
    "tools/build_hia_source_build.py", "tools/qualify_hia_selfhost.py",
)

def _build(output, compiler, cold_report):
    output, compiler = Path(output), Path(compiler)
    compiler_raw = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold = None if cold_report is None else read_cold_build_inputs(cold_report)
    sources = current_sources() if cold is None else cold.sources
    if any(sources.get(name) != sha256(raw).hexdigest() for name, raw in captured.items()):
        raise ValueError("JSON layout input is outside current source custody")
    if cold is not None and compiler_raw != cold.compiler_bytes:
        raise ValueError("JSON layout compiler differs from physical cold B3")
    custody = None if cold is None else cold.capture_custody(captured, root=ROOT)
    with nullcontext() if cold is None else release_compiler_calls(cold.report_bytes):
        output.mkdir(mode=0o700)
        image, receipt = compile_stage(output, "json-pretty", compiler, captured[SOURCE])
    image_raw = image.read_bytes()
    packed = _check_pack_output(receipt, (output / "json-pretty.output.bin").read_bytes(),
                                artifact=compiler_raw, source=captured[SOURCE])
    if (packed != image_raw or compiler.read_bytes() != compiler_raw
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or current_sources() != sources):
        raise ValueError("JSON layout build inputs or output changed")
    if cold is not None:
        cold.unchanged()
        verify_component_custody(custody, compiler_raw, cold.report_bytes,
                                  sources, captured, root=ROOT)
    manifest = {
        "schema": "hepta.hia.json-pretty-native.v1",
        "source_sha256": sha256(captured[SOURCE]).hexdigest(),
        "image_path": image.name, "image_sha256": sha256(image_raw).hexdigest(),
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
    }
    report = {
        "schema": "hepta.hia.json-pretty-build.v2",
        "scope": "DEVELOPMENT_ONLY" if cold is None else "MATCHING_SOURCE_COLD_COMPONENT",
        "source_manifest": sources,
        "component_inputs": {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        "manifest": manifest, "native_compile_receipt": receipt,
        "component_input_custody": custody,
        "cold_report_sha256": None if cold is None else sha256(cold.report_bytes).hexdigest(),
        "source_initial_and_terminal_identical": True,
        "lexical_bytes_preserved": True, "appends_newline": False,
        "input_profile_bytes": 8 << 20, "workspace_bytes": 161,
        "extra_output_size_cap": None, "production_activated": False,
        "whole_stack_qualification_claimed": False,
    }
    (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return output / "manifest.json"

def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report)

def build_development(output, compiler):
    return _build(output, compiler, None)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--cold-report", type=Path)
    choice.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(_build(args.output, args.compiler, args.cold_report))

if __name__ == "__main__":
    main()
