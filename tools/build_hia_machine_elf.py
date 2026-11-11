"""Build the explicit HIA ELF owner with full current cold-source admission.

Development builds are a separate explicit entry. Neither entry promotes the
image or establishes equivalence for arbitrary foreign comparison schedules.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SOURCE = 'examples/hia_bootstrap/machine_elf.hiaasm'
SCHEMA = 'hepta.hia.machine-elf-native.v1'
OWNED_SOURCE_FILES = (
    SOURCE, 'tools/generate_hia_machine_elf.py',
    'hepta/hia_machine_elf.py', 'hepta/hia_machine_elf_native.py',
    'hepta/hia_json_preflight_native.py',
    'tools/build_hia_machine_elf.py', 'tools/qualify_hia_machine_elf.py',
    'tests/test_hia_machine_elf_native.py', 'tests/hia_machine_elf_cases.json',
    'hepta/hia_program_native.py', 'hepta/hia_agent_contract.py',
    'setup.py', 'pyproject.toml', 'MANIFEST.in',
)


def _source_inputs():
    return {name: (ROOT / name).read_bytes() for name in OWNED_SOURCE_FILES}


def _write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def _wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def _build(output, compiler, *, cold_report):
    output, compiler = Path(output), Path(compiler)
    cold_report = None if cold_report is None else Path(cold_report)
    compiler_raw = compiler.read_bytes()
    cold_raw = None if cold_report is None else cold_report.read_bytes()
    sources = None if cold_report is None else admit_cold_build(compiler_raw, cold_raw)
    inputs = _source_inputs()
    input_hashes = {name: sha256(raw).hexdigest() for name, raw in inputs.items()}
    if sources is not None and any(sources.get(name) != digest
                                   for name, digest in input_hashes.items()):
        raise ValueError('machine ELF build inputs are outside the current cold closure')
    output.mkdir(mode=0o700)
    report = {
        'schema': 'hepta.hia.machine-elf-build.v1', 'status': 'HOLD',
        'scope': ('MATCHING_SOURCE_COLD_BUILD' if cold_report is not None
                  else 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'),
        'source_manifest': sources, 'owned_source_sha256': input_hashes,
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'cold_report_sha256': None if cold_raw is None else sha256(cold_raw).hexdigest(),
        'production_activated': False,
        'whole_writer_qualified': False,
        'whole_native_delivery_qualified': False,
        'foreign_timsort_schedule_closed': False,
        'foreign_object_observation_and_runtime_remain_hosted': True,
    }
    manifest_path = output / 'manifest.json'
    try:
        image, receipt = compile_stage(output, 'machine-elf', compiler, inputs[SOURCE])
        image_raw = image.read_bytes()
        image_sha = sha256(image_raw).hexdigest()
        if (receipt.get('input_sha256') != input_hashes[SOURCE]
                or receipt.get('artifact_sha256') != report['compiler_sha256']
                or receipt.get('produced_sha256') != image_sha):
            raise ValueError('machine ELF native compile receipt identity differs')
        if (compiler.read_bytes() != compiler_raw or _source_inputs() != inputs
                or (cold_report is not None and (
                    cold_report.read_bytes() != cold_raw or current_sources() != sources))):
            raise ValueError('machine ELF build inputs changed')
        manifest = {
            'schema': SCHEMA, 'source_sha256': input_hashes[SOURCE],
            'image_path': image.name, 'image_sha256': image_sha,
            'compiler_sha256': report['compiler_sha256'],
        }
        manifest_raw = _wire(manifest)
        report.update(
            status='NATIVE_CANDIDATE_BUILT', manifest=manifest,
            manifest_sha256=sha256(manifest_raw).hexdigest(),
            native_compile_receipt=receipt, build_inputs_stable=True,
        )
        _write_new(output / 'build.json', _wire(report))
        # The loadable selection is published only after the completed build
        # record exists. Failed compilation or identity checks leave no manifest.
        _write_new(manifest_path, manifest_raw)
    except BaseException as exc:
        if not (output / 'build.json').exists():
            report['failure'] = {'type': type(exc).__name__, 'text': str(exc)}
            _write_new(output / 'build.json', _wire(report))
        raise
    return manifest_path


def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report=cold_report)


def build_development(output, compiler):
    return _build(output, compiler, cold_report=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--cold-report', type=Path)
    mode.add_argument('--development', action='store_true')
    args = parser.parse_args()
    target = (build_development(args.output, args.compiler) if args.development
              else build(args.output, args.compiler, args.cold_report))
    print(target)


if __name__ == '__main__':
    main()
