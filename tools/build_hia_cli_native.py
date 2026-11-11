"""Build the source-bound CLI control/format companion bundle.

Development compilation is explicit. A qualified bundle still requires the
matching full-source cold report; neither mode expands the native profile.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCES = {
    "control": "examples/hia_bootstrap/cli_control.hiaasm",
    "format": "examples/hia_bootstrap/cli_format.hiaasm",
}
SCHEMAS = {
    "control": "hepta.hia.cli-control-native.v1",
    "format": "hepta.hia.cli-format-native.v1",
}
OWNER_FILES = (
    "hepta/cli.py", "hepta/hia_cli_native.py", "tools/build_hia_cli_native.py",
    "tools/generate_hia_cli_control.py", "tools/hia_cli_control_phases.py",
    "tools/generate_hia_cli_format.py", "tools/hia_cli_unicode_tables.json",
    *SOURCES.values(),
)


def owner_sources():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in OWNER_FILES}


def _build(output, compiler, *, cold_report=None):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes() if cold_report is not None else None
    sources = admit_cold_build(compiler_raw, cold_raw) if cold_raw is not None else None
    before = owner_sources()
    inputs = {name: (ROOT / path).read_bytes() for name, path in SOURCES.items()}
    if sources is not None and any(sources.get(name) != digest for name, digest in before.items()):
        raise ValueError("CLI bundle inputs are outside the matching current cold closure")
    output.mkdir(mode=0o700)
    bundle = {"schema": "hepta.hia.cli-native-bundle.v1"}
    receipts = {}
    for name, raw in inputs.items():
        directory = output / name
        directory.mkdir(mode=0o700)
        image, receipt = compile_stage(directory, "cli-" + name, compiler, raw)
        manifest = {"schema": SCHEMAS[name], "source_sha256": sha256(raw).hexdigest(),
                    "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                    "compiler_sha256": sha256(compiler_raw).hexdigest()}
        target = directory / "manifest.json"
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        bundle[name + "_manifest"] = name + "/manifest.json"
        bundle[name + "_manifest_sha256"] = sha256(target.read_bytes()).hexdigest()
        receipts[name] = {"manifest": manifest, "native_compile_receipt": receipt}
    after = owner_sources()
    if (before != after or compiler.read_bytes() != compiler_raw
            or any((ROOT / SOURCES[name]).read_bytes() != raw for name, raw in inputs.items())
            or (cold_report is not None
                and (cold_report.read_bytes() != cold_raw or current_sources() != sources))):
        raise ValueError("CLI bundle build inputs changed")
    target = output / "manifest.json"
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    (output / "build.json").write_text(json.dumps({
        "schema": "hepta.hia.cli-native-build.v1",
        "scope": "MATCHING_SOURCE_COLD_BUILD" if cold_raw is not None else "DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD",
        "source_manifest": sources, "owner_sources_before": before, "owner_sources_after": after,
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
        "cold_report_sha256": sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        "children": receipts, "bundle": bundle,
        "native_compiler_profile_expanded": False,
        "retained_foreign_owners": ["semantic action bodies", "read_bounded file policy",
                                    "publication bodies", "ordinary successful pretty-JSON presentation"],
        "production_activated": False, "whole_cli_native": False,
        "whole_native_delivery_qualified": False,
    }, indent=2, sort_keys=True) + "\n")
    return target


def build(output, compiler, cold_report):
    return _build(Path(output), Path(compiler), cold_report=Path(cold_report))


def build_development(output, compiler):
    return _build(Path(output), Path(compiler))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--cold-report", type=Path)
    selection.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))
