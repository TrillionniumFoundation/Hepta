"""Build the explicit HIA byte encoder after complete current cold admission."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.hia_selfhost_contract import PROFILE
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    relative = 'examples/hia_bootstrap/machine_encoding.hiaasm'
    source = (ROOT / relative).read_bytes()
    if sources.get(relative) != sha256(source).hexdigest():
        raise ValueError('machine encoding source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'machine-encoding', compiler, source)
    image_bytes = image.read_bytes()
    if ((ROOT / relative).read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('machine encoding build inputs changed')
    manifest = {'schema': 'hepta.hia.machine-encoding-native.v2',
                'source_sha256': sha256(source).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image_bytes).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.machine-encoding-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'profile': PROFILE, 'source_manifest': sources, 'manifest': manifest,
        'cold_report_sha256': sha256(cold_bytes).hexdigest(), 'native_compile_receipt': receipt,
        'native_instruction_byte_commands': 37,
        'separate_state_and_instruction_owners_required_for_complete_Code_policy': True,
        'general_backend_and_ELF_writer_retained': True,
        'production_activated': False, 'all_input_equivalence_proved': False,
        'whole_stack_rewritten_in_hia': False}, sort_keys=True, indent=2) + '\n')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
