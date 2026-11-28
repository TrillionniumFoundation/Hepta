"""Construct the HIA Page/wire bundle from an exact native cold campaign.

Python authoring and test inputs are Git-bound separately. The native source
map never treats those authoring files as native implementation.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, current_sources
from tools.hia_cold_compiler import read_cold_build_inputs, NATIVE_CUSTODY_INPUTS
from tools.hia_component_input_custody import verify_component_custody
from tools.build_hia_source_build import _check_pack_output
from tools.qualify_hia_selfhost import compile_stage

SOURCE_PATH = 'examples/hia_bootstrap/artifact_page.hepta'
WIRE_SOURCE_PATH = 'examples/hia_bootstrap/json_wire.hepta'
POLICY_SCHEMA = 'hepta.hia.artifact-page-native.v2'
BUNDLE_SCHEMA = 'hepta.hia.artifact-page-bundle.v2'
INPUTS = (
    SOURCE_PATH, WIRE_SOURCE_PATH, *NATIVE_CUSTODY_INPUTS,
    'tools/build_hia_artifact_page.py', 'tools/generate_hia_artifact_page.py',
    'tools/generate_hia_selfhost.py', 'tools/generate_hia_sha256.py',
    'tools/generate_hia_worker_request.py', 'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py', 'tools/build_hia_json_preflight.py',
    'hepta/hia_artifact_page_native.py', 'hepta/hia_artifact_page_policy_native.py',
    'hepta/hia_artifact_page_worker_bundle.py', 'tools/build_hia_artifact_page_worker.py',
    'hepta/hia_worker_bundle.py', 'hepta/hia_json_wire_native.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_native_delivery.py',
    'hepta/hia_agent_store.py', 'hepta/hia_agent_store_native.py',
    'hepta/hia_agent_service.py', 'hepta/hia_agent_contract.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_store_lifecycle_native.py',
    'tools/qualify_hia_artifact_read_callers.py',
    'tests/test_hia_artifact_read_native.py', 'tests/hia_artifact_read_cases.py',
    'tests/test_hia_artifact_page_service_boundary.py',
    'tests/fixtures/hia_artifact_page_service_admission_v1.json',
)


def _json(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def _private_write(path, raw):
    # All outputs are new files inside the newly created private build root.
    # Explicit mode retains ordinary-file custody even under a group umask.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _build(output, compiler, cold_report=None):
    output, compiler = Path(output), Path(compiler)
    compiler_raw = compiler.read_bytes()
    cold = None
    if cold_report is not None:
        try:
            cold = read_cold_build_inputs(cold_report)
            if compiler.absolute() != cold.compiler or compiler_raw != cold.compiler_bytes:
                raise ValueError('explicit compiler differs from physical cold B3')
        except (ValueError, OSError) as error:
            raise ValueError('artifact page requires a completed matching native cold build') from error
    captured = {name: (ROOT / name).read_bytes() for name in INPUTS}
    custody = None if cold is None else cold.capture_custody(captured, root=ROOT)
    output.mkdir(mode=0o700)
    observed = {}
    children = {}
    receipts = {}
    for name, source_name, schema in (
        ('policy', SOURCE_PATH, POLICY_SCHEMA),
        ('wire', WIRE_SOURCE_PATH, 'hepta.hia.json-wire-native.v1'),
    ):
        target = output / name
        target.mkdir(mode=0o700)
        image, receipt = compile_stage(target, name, compiler, captured[source_name])
        image_raw = image.read_bytes()
        full_path = target / (name + '.output.bin')
        full = full_path.read_bytes()
        if _check_pack_output(receipt, full, artifact=compiler_raw,
                              source=captured[source_name]) != image_raw:
            raise ValueError('artifact-page native compile output differs')
        installed_name = ('artifact-page-policy' if name == 'policy' else 'json-wire') + '.image.bin'
        installed_image = target / installed_name
        _private_write(installed_image, image_raw)
        observed[installed_image] = image_raw
        manifest = {
            'schema': schema, 'source_sha256': sha256(captured[source_name]).hexdigest(),
            'image_path': installed_image.name, 'image_sha256': sha256(image_raw).hexdigest(),
            'compiler_sha256': sha256(compiler_raw).hexdigest(),
        }
        path = target / 'manifest.json'
        raw = _json(manifest)
        _private_write(path, raw)
        observed.update({image: image_raw, full_path: full, path: raw})
        children[name] = path
        receipts[name] = receipt
    bundle = {'schema': BUNDLE_SCHEMA}
    for name, child in children.items():
        bundle[name + '_manifest'] = child.relative_to(output).as_posix()
        bundle[name + '_manifest_sha256'] = sha256(observed[child]).hexdigest()
    path = output / 'manifest.json'
    bundle_raw = _json(bundle)
    _private_write(path, bundle_raw)
    observed[path] = bundle_raw
    report = {
        'schema': 'hepta.hia.artifact-page-build.v2',
        'scope': ('DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD' if cold is None
                  else 'MATCHING_SOURCE_COLD_BUILD'),
        'bundle': bundle, 'compile_receipts': receipts,
        'component_inputs': {name: sha256(raw).hexdigest() for name, raw in captured.items()},
        'source_manifest': None if cold is None else cold.sources,
        'cold_report_sha256': None if cold is None else sha256(cold.report_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'compiler_path': str(compiler.absolute()),
        'cold_generation_inputs': (None if cold is None else [
            {'path': str(p), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for p, raw in cold.files]),
        'component_input_custody': custody,
        'native_owners': [
            'ordered page continuation and cursor binding',
            'whole-artifact UTF-8, page trim and base64',
            'three ordered wire calls and original 230000 double-wire budget',
            'cursor canonical digest, insertion and result graph',
            'single foreign exception terminal acknowledgement',
        ],
        'hosted_boundaries': [
            'opaque object and actual SQL/file operations',
            'native Store cursor resource interface',
            'foreign observation and native delivery custody',
            'installation and compiler orchestration',
        ],
        'whole_native_delivery_qualified': False,
        'whole_store_or_durability_native': False,
        'production_activated_by_build': False,
    }
    report_path = output / 'build.json'
    report_raw = _json(report)
    _private_write(report_path, report_raw)
    observed[report_path] = report_raw
    if (compiler.read_bytes() != compiler_raw
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())):
        raise ValueError('artifact-page build inputs changed')
    if cold is not None:
        if current_sources() != cold.sources:
            raise ValueError('artifact-page native source map changed')
        verify_component_custody(custody, compiler_raw, cold.report_bytes,
                                 cold.sources, captured, root=ROOT)
        cold.unchanged()
    if any(p.read_bytes() != raw for p, raw in observed.items()):
        raise ValueError('artifact-page actual output changed before publication')
    return path


def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report)


def build_development(output, compiler):
    return _build(output, compiler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
