"""Build an explicit syscall-only JSON snapshot filter with a cold compiler."""
from pathlib import Path
from hashlib import sha256
import argparse, json, struct
from tools.generate_hia_agent_snapshot_json_cli import MAGIC
from tools.build_hia_json_preflight import (admit_cold_build, current_sources,
                                           build as build_kernel)
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract

ROOT = Path(__file__).resolve().parents[1]
PACKER_SOURCE = ROOT / 'examples/hia_bootstrap/agent_snapshot_json_packer.hiaasm'


def build(output, compiler, cold_report):
    inputs = {p: p.read_bytes() for p in [compiler, cold_report, PACKER_SOURCE,
        ROOT / 'examples/hia_bootstrap/agent_snapshot_json.hiaasm']}
    qualification = json.loads(inputs[cold_report])
    if type(qualification) is not dict or qualification.get('status') != 'COLD_SELFHOST_REPLAY_PASS':
        raise ValueError('a completed matching native cold qualification is required')
    contract = validate_contract()
    expected_sources = {**contract['source_identity']['files'],
                        CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}
    if qualification.get('profile') != PROFILE or qualification.get('source_manifest') != expected_sources:
        raise ValueError('cold qualification source identity does not match current source')
    admitted_sources = admit_cold_build(inputs[compiler], inputs[cold_report])
    if any(admitted_sources.get(p.relative_to(ROOT).as_posix()) != sha256(raw).hexdigest()
           for p, raw in inputs.items() if p not in (compiler, cold_report)):
        raise ValueError('native snapshot JSON source differs from admitted cold source')
    output.mkdir(mode=0o700)
    manifest = build_kernel(output / 'kernel', compiler, cold_report, candidate='agent-snapshot-json')
    manifest_raw = manifest.read_bytes()
    metadata = json.loads(manifest_raw); image = manifest.parent / metadata['image_path']
    application = image.read_bytes()
    if sha256(application).hexdigest() != metadata['image_sha256']:
        raise ValueError('native snapshot JSON kernel image identity changed')
    packer, receipt = compile_stage(output, 'snapshot-json-packer', compiler, inputs[PACKER_SOURCE])
    packer_raw = packer.read_bytes()
    frame = struct.pack('<QQ', MAGIC, len(application)) + application
    actual, packed = invoke(output, 'snapshot-json-pack', packer, frame)
    size = actual['core_u32']
    if not 0 < size <= 1 << 20:
        raise ValueError('native snapshot JSON packer refused image frame')
    executable = packed[:size]; inspection = inspect_executable(executable)
    if (any(p.read_bytes() != raw for p, raw in inputs.items()) or image.read_bytes() != application
            or packer.read_bytes() != packer_raw or manifest.read_bytes() != manifest_raw
            or current_sources() != admitted_sources):
        raise ValueError('native snapshot JSON build inputs changed')
    path = output / 'hia-snapshot-json'; path.write_bytes(executable); path.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.agent-snapshot-json-cli-build.v1', 'status': 'NATIVE_SNAPSHOT_JSON_FILTER_BUILT',
        'executable': inspection, 'executable_sha256': sha256(executable).hexdigest(),
        'input_sha256': {str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else p.name: sha256(raw).hexdigest() for p, raw in inputs.items()},
        'kernel_image_sha256': sha256(application).hexdigest(), 'native_packer_compile_receipt': receipt,
        'native_pack_receipt': actual, 'runtime_foreign_JSON_decoder_or_second_executable_required': False,
        'host_build_and_custody_driver': True, 'whole_native_delivery_qualified': False,
        'production_activated': False}, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
