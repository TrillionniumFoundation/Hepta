"""Build the standalone Core checker or normalizer using matching-source cold B3.

This is a Unix stdin admission command, not a replacement for all existing
Agent, inspect, execute or persistence CLI commands. No runtime Python needed.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_core_admission import build as build_kernel
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_core_admission_cli import MAGIC, NORMALIZE_MAGIC
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE = ROOT / 'examples/hia_bootstrap/core_admission.hepta'
PACKER = ROOT / 'examples/hia_bootstrap/core_admission_cli_packer.hepta'


def build(output, compiler, cold_report, *, normalize=False):
    packer_source = PACKER.with_name('core_normalize_cli_packer.hepta') if normalize else PACKER
    formatter_source = SOURCE.with_name('core_pretty_json.hepta')
    sources = (SOURCE, packer_source, formatter_source) if normalize else (SOURCE, packer_source)
    pins = {p: p.read_bytes() for p in (compiler, cold_report, *sources)}
    report = json.loads(pins[cold_report])
    contract = validate_contract()
    expected = {**contract['source_identity']['files'],
                CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}
    if (type(report) is not dict or report.get('profile') != PROFILE
            or report.get('source_manifest') != expected or report.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or any(p.relative_to(ROOT).as_posix() not in expected for p in sources)):
        raise ValueError('completed matching-source cold qualification required for complete Core CLI')
    admitted_sources = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted_sources.get(p.relative_to(ROOT).as_posix()) != sha256(pins[p]).hexdigest()
           for p in sources):
        raise ValueError('complete Core CLI source differs from admitted cold source')
    output.mkdir(mode=0o700)
    manifest = build_kernel(output / 'kernel', compiler, cold_report)
    manifest_raw = manifest.read_bytes()
    metadata = json.loads(manifest_raw)
    image = manifest.parent / metadata['image_path']
    application = image.read_bytes()
    if sha256(application).hexdigest() != metadata['image_sha256']:
        raise ValueError('Core CLI admission image differs from its build manifest')
    formatter_inputs = {}
    formatter_receipt = None
    if normalize:
        formatter, formatter_receipt = compile_stage(output, 'core-pretty-json', compiler, pins[formatter_source])
        formatter_raw = formatter.read_bytes()
        if sha256(formatter_raw).hexdigest() != formatter_receipt['produced_sha256']:
            raise ValueError('Core CLI formatter image differs from its compile receipt')
        formatter_inputs[formatter] = formatter_raw
        frame = struct.pack('<3Q', NORMALIZE_MAGIC, len(application), len(formatter_raw))
        frame += application + formatter_raw
    else:
        frame = struct.pack('<QQ', MAGIC, len(application)) + application
    packer_label = 'core-normalize-cli-packer' if normalize else 'core-admission-cli-packer'
    packer, compiled = compile_stage(output, packer_label, compiler, pins[packer_source])
    packer_raw = packer.read_bytes()
    packed, arena = invoke(output, 'core-admission-cli-pack', packer, frame)
    size = packed['core_u32']
    if not 0 < size <= 1 << 20:
        raise ValueError('complete Core native CLI packer refused image')
    executable = arena[:size]
    inspection = inspect_executable(executable)
    if (any(p.read_bytes() != raw for p, raw in {**pins, **formatter_inputs}.items())
            or image.read_bytes() != application
            or packer.read_bytes() != packer_raw or manifest.read_bytes() != manifest_raw
            or current_sources() != admitted_sources):
        raise ValueError('complete Core CLI build inputs changed')
    target = output / ('hia-normalize-core' if normalize else 'hia-verify-core')
    target.write_bytes(executable)
    target.chmod(0o700)
    receipt = {
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
    }
    if normalize:
        receipt.update(status='NATIVE_CORE_NORMALIZE_CLI_BUILT',
                       formatter_image_sha256=formatter_receipt['produced_sha256'],
                       native_formatter_compile_receipt=formatter_receipt,
                       output='admitted primitive Core as sorted indented UTF-8 JSON')
    (output / 'build.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return target


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--cold-report', type=Path, required=True)
    p.add_argument('--normalize', action='store_true', help='build hia-normalize-core instead of hia-verify-core')
    a = p.parse_args()
    print(build(a.output.resolve(), a.compiler.resolve(), a.cold_report.resolve(), normalize=a.normalize))
