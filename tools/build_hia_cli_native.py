"""Build the explicit HIA CLI pair with current-cold or separate development provenance.

The public default is unchanged. Every compiled image, native receipt, source
and output is read back; a selected failure cannot choose the retained parser.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_core_json_bytes import admit_compile_receipt
from tools.qualify_hia_selfhost import compile_stage

SOURCES = {
    "control": "examples/hia_bootstrap/cli_control.hepta",
    "format": "examples/hia_bootstrap/cli_format.hepta",
}
SCHEMAS = {
    "control": "hepta.hia.cli-control-native.v1",
    "format": "hepta.hia.cli-format-native.v1",
}
OWNER_FILES = (
    "hepta/cli.py", "hepta/hia_cli_native.py", "tools/build_hia_cli_native.py",
    "tools/generate_hia_cli_control.py", "tools/hia_cli_control_phases.py",
    "tools/generate_hia_cli_format.py", "tools/hia_cli_unicode_tables.json",
    *SOURCES.values(), "hepta/hia_program_selfhost.py",
    "hepta/hia_json_preflight_native.py", "tools/build_hia_core_json_bytes.py",
    "tests/test_hia_cli_native.py", "tests/test_hia_cli_continuation_native.py",
    "docs/HIA_CLI_NATIVE.md",
)


def owner_sources():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in OWNER_FILES}


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate native CLI build receipt field")
        value[key] = item
    return value


def _encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _publish(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError("native CLI published bytes differ: " + path.name)


def _build(output, compiler, *, cold_report=None):
    compiler, output = Path(compiler), Path(output)
    cold_report = None if cold_report is None else Path(cold_report)
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes() if cold_report is not None else None
    # This complete current-source admission precedes any output mutation.
    sources = admit_cold_build(compiler_raw, cold_raw) if cold_raw is not None else None
    source_bytes = {name: (ROOT / name).read_bytes() for name in OWNER_FILES}
    before = {name: sha256(raw).hexdigest() for name, raw in source_bytes.items()}
    if sources is not None and any(sources.get(name) != digest for name, digest in before.items()):
        raise ValueError("CLI bundle inputs are outside the matching current cold closure")
    consumed = {compiler: compiler_raw,
                **{ROOT / name: raw for name, raw in source_bytes.items()}}
    if cold_report is not None:
        consumed[cold_report] = cold_raw

    def recheck():
        if (any(path.read_bytes() != raw for path, raw in consumed.items())
                or sources is not None and current_sources() != sources):
            raise ValueError("CLI bundle source, compiler, receipt or output changed")

    recheck()
    output.mkdir(mode=0o700)
    bundle = {"schema": "hepta.hia.cli-native-bundle.v1"}
    receipts = {}
    for name, source_name in SOURCES.items():
        raw = source_bytes[source_name]
        directory = output / name
        directory.mkdir(mode=0o700)
        label = "cli-" + name
        image, receipt = compile_stage(directory, label, compiler, raw)
        image = Path(image)
        if image.parent != directory or image.name != label + ".image.bin":
            raise ValueError("CLI compiler returned an unexpected image path")
        image_raw = image.read_bytes()
        admit_compile_receipt(receipt, compiler_bytes=compiler_raw,
                              source_bytes=raw, image_bytes=image_raw)
        receipt_path = directory / (label + ".receipt.json")
        receipt_raw = receipt_path.read_bytes()
        recorded = json.loads(receipt_raw, object_pairs_hook=_pairs)
        admit_compile_receipt(recorded, compiler_bytes=compiler_raw,
                              source_bytes=raw, image_bytes=image_raw)
        if _encoded(recorded) != _encoded(receipt):
            raise ValueError("CLI compiler receipt readback differs")
        consumed[image], consumed[receipt_path] = image_raw, receipt_raw
        recheck()
        manifest = {"schema": SCHEMAS[name], "source_sha256": sha256(raw).hexdigest(),
                    "image_path": image.name, "image_sha256": sha256(image_raw).hexdigest(),
                    "compiler_sha256": sha256(compiler_raw).hexdigest()}
        target = directory / "manifest.json"
        encoded = _encoded(manifest)
        _publish(target, encoded)
        consumed[target] = encoded
        bundle[name + "_manifest"] = name + "/manifest.json"
        bundle[name + "_manifest_sha256"] = sha256(encoded).hexdigest()
        receipts[name] = {"manifest": manifest, "native_compile_receipt": receipt}
        recheck()
    target = output / "manifest.json"
    bundle_raw = _encoded(bundle)
    recheck()
    _publish(target, bundle_raw)
    consumed[target] = bundle_raw
    report = {
        "schema": "hepta.hia.cli-native-build.v1",
        "scope": "MATCHING_SOURCE_COLD_BUILD" if cold_raw is not None else "DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD",
        "source_manifest": sources, "owner_sources_before": before, "owner_sources_after": owner_sources(),
        "compiler_sha256": sha256(compiler_raw).hexdigest(),
        "cold_report_sha256": sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        "children": receipts, "bundle": bundle,
        "native_compiler_profile_expanded": False,
        "retained_foreign_owners": ["semantic action bodies", "read_bounded file policy",
                                    "publication bodies", "ordinary successful pretty-JSON presentation"],
        "default_changed": False, "production_activated": False, "whole_cli_native": False,
        "whole_native_delivery_qualified": False,
    }
    report_path, report_raw = output / "build.json", _encoded(report)
    recheck()
    _publish(report_path, report_raw)
    consumed[report_path] = report_raw
    recheck()
    return target


def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report=cold_report)


def build_development(output, compiler):
    return _build(output, compiler)


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
