"""Cold build the standalone HIA scalar-reference packet executor."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import adapter_layout
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_native_filter import (
    REFERENCE_CLI_ADAPTER, REFERENCE_CLI_MAGIC, REFERENCE_CLI_PACKER, elf_header,
)
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable


ROOT = Path(__file__).resolve().parents[1]
REFERENCE_SOURCE = 'examples/hia_bootstrap/scalar_reference.hepta'
DRIVER = 'tools/build_hia_scalar_reference_cli.py'


def digest(raw):
    return sha256(raw).hexdigest()


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    sources = (REFERENCE_SOURCE, REFERENCE_CLI_ADAPTER, REFERENCE_CLI_PACKER, DRIVER)
    source_bytes = {name: (ROOT / name).read_bytes() for name in sources}
    if any(admitted.get(name) != digest(raw) for name, raw in source_bytes.items()):
        raise ValueError('standalone reference executable needs a matching cold source')
    output.mkdir(mode=0o700)
    image, image_receipt = compile_stage(output, 'scalar-reference', compiler, source_bytes[REFERENCE_SOURCE])
    packer, packer_receipt = compile_stage(output, 'scalar-reference-packer', compiler,
                                           source_bytes[REFERENCE_CLI_PACKER])
    image_bytes, packer_bytes = image.read_bytes(), packer.read_bytes()
    for raw, receipt in ((image_bytes, image_receipt), (packer_bytes, packer_receipt)):
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('compiled reference input changed')
    payload = struct.pack('<2Q', REFERENCE_CLI_MAGIC, len(image_bytes)) + image_bytes
    exe, receipt = compile_stage(output, 'reference-executable', packer, payload, output_extension='.elf')
    binary = exe.read_bytes()
    if digest(binary) != receipt['produced_sha256']:
        raise ValueError('compiled reference executable changed')
    inspected = inspect_executable(binary)
    stub, holes, adapter_identity = adapter_layout(
        output, REFERENCE_CLI_ADAPTER, source_bytes[REFERENCE_CLI_ADAPTER], {'reference': 'reference_call_hole'})
    prefix = bytearray(elf_header() + stub)
    struct.pack_into('<2Q', prefix, 96, len(binary), len(binary))
    hole = len(elf_header()) + holes['reference']
    struct.pack_into('<i', prefix, hole, len(prefix) - hole - 4)
    if binary != prefix + image_bytes:
        raise ValueError('native packer altered the admitted transport or reference image')
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or image.read_bytes() != image_bytes
            or packer.read_bytes() != packer_bytes or exe.read_bytes() != binary):
        raise ValueError('standalone reference build input changed before publication')
    executable = output / 'hia-reference-wire'
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report = {'schema': 'hepta.hia.reference-wire-build.v1', 'executable_path': executable.name,
              'source_sha256': {name: digest(raw) for name, raw in source_bytes.items()},
              'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(cold_bytes),
              'transport_object_sha256': adapter_identity, 'executable_sha256': digest(binary),
              'executable': inspected, 'native_compile_receipt': image_receipt,
              'native_packer_receipt': packer_receipt, 'native_pack_receipt': receipt}
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
