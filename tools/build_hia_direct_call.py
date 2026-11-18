"""Build the standalone direct-ELF call executable using a matching cold HIA compiler."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import adapter_layout
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_direct_load_plan import (
    ADAPTER_PATH, CALL_SYMBOLS, PACKER_MAGIC, PACKER_PATH, ROOT, SOURCE_PATH,
)
from tools.generate_hia_native_filter import elf_header
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

DRIVER = 'tools/build_hia_direct_call.py'


def digest(raw):
    return sha256(raw).hexdigest()


def assemble(output, compiler, sources):
    image, image_receipt = compile_stage(output, 'direct-load-plan', compiler, sources[SOURCE_PATH])
    packer, packer_receipt = compile_stage(output, 'direct-call-packer', compiler, sources[PACKER_PATH])
    code, packer_bytes = image.read_bytes(), packer.read_bytes()
    if digest(code) != image_receipt['produced_sha256'] or digest(packer_bytes) != packer_receipt['produced_sha256']:
        raise ValueError('direct call source or packer identity changed')
    request = struct.pack('<2Q', PACKER_MAGIC, len(code)) + code
    path, receipt = compile_stage(output, 'direct-call-executable', packer, request, output_extension='.elf')
    binary = path.read_bytes()
    stub, holes, adapter_identity = adapter_layout(output, ADAPTER_PATH, sources[ADAPTER_PATH], CALL_SYMBOLS)
    header = elf_header()
    prefix = bytearray(header + stub)
    struct.pack_into('<2Q', prefix, 96, len(binary), len(binary))
    hole = len(header) + holes['plan']
    struct.pack_into('<i', prefix, hole, len(prefix) - hole - 4)
    if (digest(binary) != receipt['produced_sha256'] or binary != prefix + code
            or image.read_bytes() != code or packer.read_bytes() != packer_bytes):
        raise ValueError('HIA packer changed the admitted direct load plan or syscall adapter')
    return binary, {'executable': inspect_executable(binary), 'transport_object_sha256': adapter_identity,
                    'native_compile_receipt': image_receipt, 'native_packer_receipt': packer_receipt,
                    'native_pack_receipt': receipt}


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    paths = (SOURCE_PATH, PACKER_PATH, ADAPTER_PATH, DRIVER)
    sources = {name: (ROOT / name).read_bytes() for name in paths}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('standalone direct call needs matching cold source')
    output.mkdir(mode=0o700)
    binary, report = assemble(output, compiler, sources)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes):
        raise ValueError('direct call inputs changed before publication')
    executable = output / 'hia-direct-call'
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report.update({'schema': 'hepta.hia.direct-call-build.v1',
                   'source_sha256': {name: digest(raw) for name, raw in sources.items()},
                   'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(cold_bytes),
                   'executable_path': executable.name, 'executable_sha256': digest(binary)})
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
