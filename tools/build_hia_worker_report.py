"""Build matching-source HIA worker report/control and native wire companions."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCES = {'policy': 'examples/hia_bootstrap/worker_report.hiaasm',
           'wire': 'examples/hia_bootstrap/json_wire.hiaasm'}
SCHEMAS = {'policy': 'hepta.hia.worker-report-native.v1', 'wire': 'hepta.hia.json-wire-native.v1'}


def _build(output, compiler, *, cold_report=None):
    compiler_raw = compiler.read_bytes()
    cold_raw = cold_report.read_bytes() if cold_report is not None else None
    sources = admit_cold_build(compiler_raw, cold_raw) if cold_raw is not None else None
    inputs = {name: (ROOT / path).read_bytes() for name, path in SOURCES.items()}
    if sources is not None and any(sources.get(SOURCES[name]) != sha256(raw).hexdigest() for name, raw in inputs.items()):
        raise ValueError('worker report bundle sources are outside current cold closure')
    output.mkdir(mode=0o700)
    bundle = {'schema': 'hepta.hia.worker-report-bundle.v1'}
    receipts = {}
    for name, raw in inputs.items():
        directory = output / name
        directory.mkdir(mode=0o700)
        protocol = 'worker-report' if name == 'policy' else 'json-wire'
        image, receipt = compile_stage(directory, protocol, compiler, raw)
        manifest = {'schema': SCHEMAS[name], 'source_sha256': sha256(raw).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(compiler_raw).hexdigest()}
        target = directory / 'manifest.json'
        target.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        bundle[name + '_manifest'] = name + '/manifest.json'
        bundle[name + '_manifest_sha256'] = sha256(target.read_bytes()).hexdigest()
        receipts[name] = {'manifest': manifest, 'native_compile_receipt': receipt}
    if (compiler.read_bytes() != compiler_raw
            or any((ROOT / SOURCES[name]).read_bytes() != raw for name, raw in inputs.items())
            or (cold_report is not None and (cold_report.read_bytes() != cold_raw or current_sources() != sources))):
        raise ValueError('worker report bundle build inputs changed')
    target = output / 'manifest.json'
    target.write_text(json.dumps(bundle, sort_keys=True, indent=2) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.worker-report-build.v1',
        'scope': 'MATCHING_SOURCE_COLD_BUILD' if cold_raw is not None else 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD',
        'source_manifest': sources, 'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'cold_report_sha256': sha256(cold_raw).hexdigest() if cold_raw is not None else None,
        'children': receipts, 'bundle': bundle, 'production_activated': False,
        'request_admission_independently_selected': True, 'unselected_request_admission_is_hosted': True,
        'service_journal_installation_IO_and_runtime_process_owner_remain_foreign': True,
        'whole_worker_native': False,
    }, sort_keys=True, indent=2) + '\n')
    return target


def build(output, compiler, cold_report):
    return _build(Path(output), Path(compiler), cold_report=Path(cold_report))


def build_development(output, compiler):
    return _build(Path(output), Path(compiler))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))
