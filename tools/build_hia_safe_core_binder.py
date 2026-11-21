"""Build the independent HIA Safe Core two-ELF binder from a cold compiler."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import verify_placement
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_native_filter import read_adapter_binding
from tools.generate_hia_safe_core_binder import SOURCE_PATH
from tools.generate_hia_safe_core_binder_packer import ADAPTER, CALLS, MAGIC, PACKER
from tools.generate_hia_safe_core_machine_observe import SOURCE_PATH as MACHINE_SOURCE
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
PARTS = {
    'binder': SOURCE_PATH,
    'elf': 'examples/hia_bootstrap/safe_core_elf_inventory.hepta',
    'wire': 'examples/hia_bootstrap/core_elf_binding_wire.hepta',
}


MACHINE_PARTS = {**PARTS, 'binder': MACHINE_SOURCE,
                 'elf': 'examples/hia_bootstrap/safe_core_x64_decode.hepta'}


def build(output, compiler, cold_report, *, observe_machine=False):
    parts = MACHINE_PARTS if observe_machine else PARTS
    product = 'hia-safe-core-machine-observe' if observe_machine else 'hia-safe-core-bind'
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admission = admit_cold_build(compiler_raw, report_raw)
    source_paths = (*parts.values(), ADAPTER, PACKER, 'tools/build_hia_safe_core_binder.py',
                    'tools/generate_hia_safe_core_binder.py', 'tools/generate_hia_safe_core_binder_packer.py',
                    'tools/generate_hia_safe_core_machine_observe.py')
    sources = {name: (ROOT / name).read_bytes() for name in source_paths}
    if any(admission.get(name) != sha256(raw).hexdigest() for name, raw in sources.items()):
        raise ValueError('Safe Core binder input differs from admitted cold source')
    binding = read_adapter_binding(sources[PACKER], sources[ADAPTER], calls=len(CALLS))
    output.mkdir(mode=0o700)
    images = {}
    receipts = {}
    for label, source in {**parts, 'packer': PACKER}.items():
        path, receipt = compile_stage(output, label, compiler, sources[source])
        data = path.read_bytes()
        if sha256(data).hexdigest() != receipt['produced_sha256']:
            raise ValueError('Safe Core binder image identity changed')
        images[label] = path, data
        receipts[label] = receipt
    applications = {label: images[label][1] for label in parts}
    frame = MAGIC + struct.pack('<3Q', *(len(image) for image in applications.values()))
    frame += b''.join(applications.values())
    packed, receipt = compile_stage(output, 'binder-executable', images['packer'][0], frame,
                                    output_extension='.elf')
    binary = packed.read_bytes()
    if sha256(binary).hexdigest() != receipt['produced_sha256']:
        raise ValueError('Safe Core binder executable identity changed')
    verify_placement(binary, binding, applications)
    inspection = inspect_executable(binary)
    if (current_sources() != admission or compiler.read_bytes() != compiler_raw
            or cold_report.read_bytes() != report_raw
            or any(path.read_bytes() != before for path, before in images.values())):
        raise ValueError('Safe Core binder changed before publication')
    executable = output / product
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': ('hepta.hia.safe-core-machine-observe-build.v1' if observe_machine
                   else 'hepta.hia.safe-core-binder-build.v1'),
        'compiler_sha256': sha256(compiler_raw).hexdigest(),
        'cold_report_sha256': sha256(report_raw).hexdigest(),
        'native_executable_sha256': sha256(binary).hexdigest(),
        'executable': inspection,
        'application_receipts': receipts,
        'native_packer_receipt': receipt,
    }, indent=2, sort_keys=True) + '\n')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--observe-machine', action='store_true',
                        help='build the independent scalar machine-observation stage')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                observe_machine=args.observe_machine))
