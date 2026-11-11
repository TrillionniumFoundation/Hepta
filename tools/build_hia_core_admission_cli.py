"""Build the standalone complete Core checker using matching-source cold B3.

This is a Unix stdin admission command, not a replacement for all existing
Agent, inspect, execute or persistence CLI commands. No runtime Python needed.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_core_admission import build as build_kernel
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_core_admission_cli import MAGIC
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/core_admission.hepta'
PACKER = ROOT / 'examples/hia_bootstrap/core_admission_cli_packer.hepta'


def build(output, compiler, cold_report):
    pins = {p: p.read_bytes() for p in (compiler, cold_report, SOURCE, PACKER)}
    report = json.loads(pins[cold_report])
    contract = validate_contract()
    expected = {**contract['source_identity']['files'],
                CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}
    if (type(report) is not dict or report.get('profile') != PROFILE
            or report.get('source_manifest') != expected or report.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or str(SOURCE.relative_to(ROOT)) not in expected or str(PACKER.relative_to(ROOT)) not in expected):
        raise ValueError('completed matching-source cold qualification required for complete Core CLI')
    admitted_sources = admit_cold_build(pins[compiler], pins[cold_report])
    output.mkdir(mode=0o700)
    manifest = build_kernel(output / 'kernel', compiler, cold_report)
    metadata = json.loads(manifest.read_bytes())
    image = manifest.parent / metadata['image_path']
    application = image.read_bytes()
    assert sha256(application).hexdigest() == metadata['image_sha256']
    packer, compiled = compile_stage(output, 'core-admission-cli-packer', compiler, pins[PACKER])
    packed, arena = invoke(output, 'core-admission-cli-pack', packer,
                           struct.pack('<QQ', MAGIC, len(application)) + application)
    size = packed['core_u32']
    if not 0 < size <= 1 << 20:
        raise ValueError('complete Core native CLI packer refused image')
    executable = arena[:size]
    inspection = inspect_executable(executable)
    if (any(p.read_bytes() != raw for p, raw in pins.items()) or image.read_bytes() != application
            or current_sources() != admitted_sources):
        raise ValueError('complete Core CLI build inputs changed')
    target = output / 'hia-verify-core'
    target.write_bytes(executable)
    target.chmod(0o700)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.core-admission-cli-build.v1', 'status': 'NATIVE_CORE_ADMISSION_CLI_BUILT',
        'executable': inspection, 'executable_sha256': sha256(executable).hexdigest(),
        'kernel_image_sha256': sha256(application).hexdigest(),
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'source_sha256': {str(p.relative_to(ROOT)): sha256(raw).hexdigest()
                          for p, raw in pins.items() if p.is_relative_to(ROOT)},
        'native_packer_compile_receipt': compiled, 'native_pack_receipt': packed,
        'runtime_host_payload_parser_or_interpreter': False,
        'input': 'raw primitive Core JSON on stdin',
        'exit_codes': {'0': 'admitted', '2': 'refused', '3': 'input budget', '4': 'descriptor I/O', '64': 'usage'},
        'host_build_driver': True, 'whole_CLI_replaced': False,
        'default_changed': False, 'whole_native_delivery_qualified': False,
    }, indent=2, sort_keys=True) + '\n')
    return target


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--cold-report', type=Path, required=True)
    a = p.parse_args()
    print(build(a.output.resolve(), a.compiler.resolve(), a.cold_report.resolve()))
