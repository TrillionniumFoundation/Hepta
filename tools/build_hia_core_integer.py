"""Build the optional integer companion only from a matching-source cold B3.

This future build entry does not make the present static candidate qualified.
The Core39 bundle keeps its own admission; its compiler identity must match.
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


def build(output, compiler, cold_report):
    from hepta.hia_core_integer_selection import (
        SCHEMA, ABI_SOURCE, HIA_SOURCE, BRIDGE_SOURCE, SELECTION_SOURCE, current_inputs, checked_abi)
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_selfhost_contract import PROFILE
    compiler_raw, cold_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, cold_raw)
    inputs = current_inputs()
    checked_abi(inputs[ABI_SOURCE])
    for path, raw in inputs.items():
        if admitted.get(path) != sha256(raw).hexdigest():
            raise ValueError('exact integer input is outside matching-source cold: ' + path)
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'core-integer', compiler, inputs[HIA_SOURCE])
    image_raw = image.read_bytes()
    compiler_sha = sha256(compiler_raw).hexdigest()
    manifest = {'schema': SCHEMA, 'source_sha256': sha256(inputs[HIA_SOURCE]).hexdigest(),
                'abi_sha256': sha256(inputs[ABI_SOURCE]).hexdigest(),
                'bridge_sha256': sha256(inputs[BRIDGE_SOURCE]).hexdigest(),
                'selection_sha256': sha256(inputs[SELECTION_SOURCE]).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image_raw).hexdigest(),
                'compiler_sha256': compiler_sha}
    if (compiler.read_bytes() != compiler_raw or cold_report.read_bytes() != cold_raw
            or current_inputs() != inputs or current_sources() != admitted
            or image.read_bytes() != image_raw):
        raise ValueError('exact integer build input or image changed')
    path = output / 'manifest.json'
    with path.open('x') as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    with (output / 'build.json').open('x') as stream:
        stream.write(json.dumps({'schema': 'hepta.hia.core-integer-build.v1',
            'status': 'NATIVE_CANDIDATE_BUILT', 'profile': PROFILE,
            'manifest': manifest, 'source_manifest': admitted,
            'cold_report_sha256': sha256(cold_raw).hexdigest(),
            'native_compile_receipt': receipt, 'original_Core_39_units_unchanged': True,
            'integer_arithmetic_control_in_HIA': True, 'CPython_primitives_still_hosted': True,
            'whole_stack_rewritten_in_hia': False, 'production_activated': False},
            indent=2, sort_keys=True) + '\n')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
