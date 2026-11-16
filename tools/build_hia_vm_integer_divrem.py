"""Build only the explicit HIA VM div/rem component, with current-source custody."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_vm_integer_divrem_protocol import (SCHEMA, SOURCE_NAME,
    IMAGE_NAME, COMPONENT_INPUTS)
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

INPUTS = (*COMPONENT_INPUTS, "setup.py", "MANIFEST.in",
          "tests/test_hia_agent_installed_resources.py", "tools/build_hia_vm_integer_divrem.py",
          "tools/qualify_hia_vm_integer_divrem.py",
          "tools/read_hia_vm_integer_divrem.py",
          "tests/hia_vm_integer_divrem_controls.py",
          "tests/test_hia_program.py",
          "review-evidence/hia-native-rewrite-20261111/workflow_process.py",
          "tests/hia_vm_integer_divrem_cases.py",
          "tests/test_hia_vm_integer_divrem_native.py",
          "tests/fixtures/vm_integer_divrem_inputs_v1.json",
          "tests/fixtures/vm_integer_divrem_runtime_ce39.py.txt")


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError("choose exactly one current cold report or explicit development mode")
    compiler, output = Path(compiler), Path(output)
    compiler_bytes = compiler.read_bytes()
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = None if development else admit_cold_build(compiler_bytes, cold_bytes)
    if sources is not None and any(sources.get(name) != sha256(raw).hexdigest()
                                   for name, raw in captured.items()):
        raise ValueError("div/rem inputs are not in the actual current cold source")
    output.mkdir(mode=0o700)
    source = captured[SOURCE_NAME]
    image, receipt = compile_stage(output, "vm-integer-divrem", compiler, source)
    image_bytes = image.read_bytes()
    if image.name != IMAGE_NAME:
        raise ValueError("div/rem compiler output name differs")
    full_output = (output / "vm-integer-divrem.output.bin").read_bytes()
    packed = _check_pack_output(receipt, full_output, artifact=compiler_bytes, source=source)
    if (packed != image_bytes or compiler.read_bytes() != compiler_bytes
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or sources is not None and (Path(cold_report).read_bytes() != cold_bytes
                                       or current_sources() != sources)):
        raise ValueError("div/rem build inputs or complete output changed")
    scope = "DEVELOPMENT_COMPONENT" if development else "MATCHING_SOURCE_COLD_COMPONENT"
    manifest = {
        "schema": SCHEMA, "scope": scope, "source_sha256": sha256(source).hexdigest(),
        "image_path": image.name, "image_sha256": sha256(image_bytes).hexdigest(),
        "compiler_sha256": sha256(compiler_bytes).hexdigest(),
        "component_inputs": {name: sha256(captured[name]).hexdigest() for name in COMPONENT_INPUTS},
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (output / "manifest.json").write_bytes(manifest_raw)
    report = {
        "schema": "hepta.hia.vm-integer-divrem-build.v1", "scope": scope,
        "component_inputs": {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        "source_manifest": sources, "manifest": manifest,
        "manifest_sha256": sha256(manifest_raw).hexdigest(),
        "native_compile_receipt": receipt,
        "cold_report_sha256": None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        "whole_vm_native": False, "whole_stack_rewritten_in_hia": False,
        "all_input_equivalence_proved": False,
    }
    (output / "build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return output / "manifest.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--cold-report", type=Path)
    choice.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == "__main__":
    main()
