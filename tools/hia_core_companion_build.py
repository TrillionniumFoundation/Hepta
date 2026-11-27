"""Build a Core value companion from the actual matching-source cold compiler.

The old source corpus is never a compiler input. This module only binds physical
.hepta, ABI and executing host files to the strict cold receipt and Git tree.
"""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = "tools/hia_core_companion_build.py"
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()
FAMILIES = ("compare", "integer", "unpack")


def build(family, output, compiler, cold_report):
    if type(family) is not str or family not in FAMILIES:
        raise ValueError("unknown Core companion")
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.build_hia_source_build import _check_pack_output
    from tools.hia_component_input_custody import (
        capture_component_custody,
        verify_component_custody,
    )
    from tools.hia_native_cold_admission import SCHEMA as NATIVE_SCHEMA, read_json
    from tools.hia_selfhost_contract import PROFILE
    from tools.qualify_hia_selfhost import compile_stage

    selection = importlib.import_module("hepta.hia_core_" + family + "_selection")
    output, compiler, cold_report = Path(output), Path(compiler), Path(cold_report)
    compiler_raw, cold_raw = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_raw, cold_raw)
    selected = selection.current_inputs()
    selection.checked_abi(selected[selection.ABI_SOURCE])
    names = (
        SELF,
        "tools/build_hia_core_" + family + ".py",
        "tools/generate_hia_core_" + family + ".py",
        "tools/hia_component_input_custody.py",
        "hepta/hia_core_lowering_native.py",
        "hepta/hia_core_lowering_selection.py",
        "hepta/hia_json_preflight_native.py",
    )
    if family == "unpack":
        names += ("tools/hia_core_unpack_transaction.S",)
    captured = {**selected, **{name: (ROOT / name).read_bytes() for name in names}}
    if captured[SELF] != _EXECUTED_SOURCE:
        raise ValueError("Core companion executing builder source changed")
    cold_inputs, custody_inputs = None, {}
    if read_json(cold_raw).get("schema") == NATIVE_SCHEMA:
        from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS, read_cold_build_inputs

        cold_inputs = read_cold_build_inputs(cold_report)
        if cold_inputs.compiler_bytes != compiler_raw or cold_inputs.sources != sources:
            raise ValueError("Core companion compiler differs from its matching cold receipt")
        custody_inputs = {name: (ROOT / name).read_bytes() for name in NATIVE_CUSTODY_INPUTS}
        custody = cold_inputs.capture_custody({**captured, **custody_inputs}, root=ROOT)
    else:
        custody = capture_component_custody(
            compiler_raw, cold_raw, sources, captured, root=ROOT
        )

    def unchanged():
        if (
            compiler.read_bytes() != compiler_raw
            or cold_report.read_bytes() != cold_raw
            or selection.current_inputs() != selected
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or current_sources() != sources
        ):
            raise ValueError("Core companion construction source or compiler changed")
        verify_component_custody(
            custody, compiler_raw, cold_raw, sources,
            {**captured, **custody_inputs}, root=ROOT,
        )
        if cold_inputs is not None:
            cold_inputs.unchanged()

    unchanged()
    output.mkdir(mode=0o700)
    source = selected[selection.HIA_SOURCE]
    stem = "core-" + family
    image, receipt = compile_stage(output, stem, compiler, source)
    image_raw = image.read_bytes()
    packed = _check_pack_output(
        receipt, (output / (stem + ".output.bin")).read_bytes(),
        artifact=compiler_raw, source=source,
    )
    if packed != image_raw:
        raise ValueError("Core companion complete compiler output differs")
    unchanged()
    if image.read_bytes() != image_raw:
        raise ValueError("Core companion image changed before publication")
    manifest = {
        "schema": selection.SCHEMA,
        "source_sha256": sha256(source).hexdigest(),
        "abi_sha256": sha256(selected[selection.ABI_SOURCE]).hexdigest(),
        "bridge_sha256": sha256(selected[selection.BRIDGE_SOURCE]).hexdigest(),
        "selection_sha256": sha256(selected[selection.SELECTION_SOURCE]).hexdigest(),
        "image_path": image.name,
        "image_sha256": sha256(image_raw).hexdigest(),
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
    }
    report = {
        "schema": "hepta.hia.core-" + family + "-build.v2",
        "status": "NATIVE_CANDIDATE_BUILT",
        "scope": "MATCHING_SOURCE_COLD_COMPONENT",
        "profile": PROFILE,
        "manifest": manifest,
        "source_manifest": sources,
        "component_inputs": {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        "component_input_custody": custody,
        "development_inputs": {
            name: sha256(raw).hexdigest() for name, raw in custody_inputs.items()
        },
        "cold_report_sha256": sha256(cold_raw).hexdigest(),
        "native_compile_receipt": receipt,
        "canonical_source_path": selection.HIA_SOURCE,
        "historical_source_used_for_compilation": False,
        "CPython_primitives_still_hosted": True,
        "whole_stack_rewritten_in_hia": False,
        "all_input_equivalence_proved": False,
    }
    path = output / "manifest.json"
    with path.open("x") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    with (output / "build.json").open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    unchanged()
    if image.read_bytes() != image_raw:
        raise ValueError("Core companion image changed at terminal readback")
    return path
