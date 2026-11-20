"""Build the standalone Core checker, normalizer or inspector using matching-source cold B3.

These are Unix admission commands, not a replacement for all existing
Agent, composite, execute or persistence CLI commands. No runtime Python needed.
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
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_core_admission_cli import INSPECT_MAGIC, MAGIC, NORMALIZE_MAGIC
from tools.generate_hia_core_suite import SUITE_MAGIC
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract
from tools.qualify_hia_selfhost import compile_stage, invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE = ROOT / 'examples/hia_bootstrap/core_admission.hepta'
PACKER = ROOT / 'examples/hia_bootstrap/core_admission_cli_packer.hepta'


MODES = {
    'verify': (MAGIC, PACKER.name, ()),
    'normalize': (NORMALIZE_MAGIC, 'core_normalize_cli_packer.hepta', ('core_pretty_json.hepta',)),
    'inspect': (INSPECT_MAGIC, 'core_inspect_cli_packer.hepta', ('core_inspect_json.hepta',)),
    'suite': (SUITE_MAGIC, 'core_suite_packer.hepta',
              ('core_suite_dispatch.hepta', 'core_pretty_json.hepta', 'core_inspect_json.hepta')),
}


def build(output, compiler, cold_report, *, normalize=False, inspect=False, suite=False):
    selected = [name for name, enabled in (('normalize', normalize), ('inspect', inspect), ('suite', suite))
                if enabled]
    if len(selected) > 1:
        raise ValueError('select only one Core CLI output mode')
    action = selected[0] if selected else 'verify'
    magic, packer_name, component_names = MODES[action]
    packer_source = PACKER.with_name(packer_name)
    component_sources = tuple(SOURCE.with_name(name) for name in component_names)
    sources = (SOURCE, packer_source, *component_sources)
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
    component_inputs = {}
    component_receipts = {}
    for source in component_sources:
        label = source.stem.replace('_', '-')
        path, receipt = compile_stage(output, label, compiler, pins[source])
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != receipt['produced_sha256']:
            raise ValueError('Core CLI component image differs from its compile receipt')
        component_inputs[path] = raw
        component_receipts[label] = receipt
    components = list(component_inputs.values())
    if suite:
        # The dispatcher precedes the kernel; both output actions share it.
        components.insert(1, application)
    else:
        components.insert(0, application)
    frame = struct.pack('<' + 'Q' * (1 + len(components)), magic, *map(len, components))
    frame += b''.join(components)
    packer_label = packer_source.stem.replace('_', '-')
    packer, compiled = compile_stage(output, packer_label, compiler, pins[packer_source])
    packer_raw = packer.read_bytes()
    packed, arena = invoke(output, 'core-admission-cli-pack', packer, frame)
    executable = _check_pack_output(packed, arena, artifact=packer_raw, source=frame)
    inspection = inspect_executable(executable)
    if (any(p.read_bytes() != raw for p, raw in {**pins, **component_inputs}.items())
            or image.read_bytes() != application
            or packer.read_bytes() != packer_raw or manifest.read_bytes() != manifest_raw
            or current_sources() != admitted_sources):
        raise ValueError('complete Core CLI build inputs changed')
    target = output / ('hia-core' if suite else f'hia-{action}-core')
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
    if suite:
        receipt.update(status='NATIVE_CORE_SUITE_CLI_BUILT', commands=['verify', 'normalize', 'inspect', 'verify-report'],
                       input='raw primitive Core JSON on stdin or from an ordinary file',
                       native_component_compile_receipts=component_receipts)
    elif component_receipts:
        formatter_receipt, = component_receipts.values()
        description = ('primitive Core inspection and canonical identity as UTF-8 JSON' if inspect
                       else 'admitted primitive Core as sorted indented UTF-8 JSON')
        receipt.update(status=f'NATIVE_CORE_{action.upper()}_CLI_BUILT',
                       formatter_image_sha256=formatter_receipt['produced_sha256'],
                       native_formatter_compile_receipt=formatter_receipt,
                       output=description)
    (output / 'build.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return target


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--cold-report', type=Path, required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--normalize', action='store_true', help='build hia-normalize-core instead of hia-verify-core')
    mode.add_argument('--inspect', action='store_true', help='build hia-inspect-core instead of hia-verify-core')
    mode.add_argument('--suite', action='store_true', help='build hia-core with the verification and view commands')
    a = p.parse_args()
    print(build(a.output.resolve(), a.compiler.resolve(), a.cold_report.resolve(), normalize=a.normalize, inspect=a.inspect, suite=a.suite))
