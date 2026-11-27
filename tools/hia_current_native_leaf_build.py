"""Build one current native leaf with physical cold and separate Git custody.

The explicit development entry is component evidence only.  Neither entry
changes helper selection, the native authority, or an installed release.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, current_sources
from tools.hia_cold_compiler import read_cold_build_inputs
from tools.hia_component_input_custody import verify_component_custody
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def build_leaf(output, compiler, *, cold_report, source_path, schema, inputs, label):
    output, compiler = Path(output), Path(compiler)
    compiler_raw = compiler.read_bytes()
    cold = None
    if cold_report is not None:
        try:
            cold = read_cold_build_inputs(cold_report)
            if compiler.absolute() != cold.compiler or compiler_raw != cold.compiler_bytes:
                raise ValueError("explicit compiler differs from physical cold B3")
        except (ValueError, OSError) as error:
            raise ValueError(label + ": a completed matching native cold qualification is required") from error
    captured = {name: (ROOT / name).read_bytes() for name in inputs}
    custody = None if cold is None else cold.capture_custody(captured, root=ROOT)
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, label, compiler, captured[source_path])
    image_raw = image.read_bytes()
    complete_path = output / (label + ".output.bin")
    complete_raw = complete_path.read_bytes()
    if _check_pack_output(receipt, complete_raw, artifact=compiler_raw,
                          source=captured[source_path]) != image_raw:
        raise ValueError(label + " native compile receipt/output differs")
    if not 0 < len(image_raw) <= 1048576:
        raise ValueError(label + " exceeds the original native image budget")
    portable_image = output / (label + ".image.bin")
    _write(portable_image, image_raw)
    manifest = {
        "schema": schema,
        "source_sha256": sha256(captured[source_path]).hexdigest(),
        "image_path": portable_image.name,
        "image_sha256": sha256(image_raw).hexdigest(),
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
    }
    manifest_path = output / "manifest.json"
    manifest_raw = _json(manifest)
    _write(manifest_path, manifest_raw)
    report = {
        "schema": schema.replace("-native.", "-build."),
        "scope": ("DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD" if cold is None
                  else "MATCHING_SOURCE_COLD_BUILD"),
        "manifest": manifest,
        "native_compile_receipt": receipt,
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
        "compiler_path": str(compiler.absolute()),
        "component_inputs": {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        "component_input_custody": custody,
        "source_manifest": None if cold is None else cold.sources,
        "cold_report_sha256": None if cold is None else sha256(cold.report_bytes).hexdigest(),
        "cold_generation_inputs": None if cold is None else [
            {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
            for path, raw in cold.files],
        "whole_native_delivery_qualified": False,
        "production_activated_by_build": False,
    }
    report_path = output / "build.json"
    report_raw = _json(report)
    _write(report_path, report_raw)
    if compiler.read_bytes() != compiler_raw or any(
            (ROOT / name).read_bytes() != raw for name, raw in captured.items()):
        raise ValueError(label + " build inputs changed")
    if cold is not None:
        if current_sources() != cold.sources:
            raise ValueError(label + " native source map changed")
        verify_component_custody(custody, compiler_raw, cold.report_bytes,
                                 cold.sources, captured, root=ROOT)
        cold.unchanged()
    for path, expected in ((compiler, compiler_raw), (image, image_raw),
                           (portable_image, image_raw), (complete_path, complete_raw),
                           (manifest_path, manifest_raw), (report_path, report_raw)):
        if path.read_bytes() != expected:
            raise ValueError(label + " actual output changed before publication")
    return manifest_path
