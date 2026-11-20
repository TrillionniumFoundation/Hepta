"""Build the standalone direct-ELF call executable using a matching cold HIA compiler."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_direct_load_plan import (
    ADAPTER_PATH, PACKER_MAGIC, PACKER_PATH, ROOT, SOURCE_PATH, read_adapter_binding,
)
from tools.generate_hia_native_filter import elf_header
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

DRIVER = 'tools/build_hia_direct_call.py'


def digest(raw):
    return sha256(raw).hexdigest()


def verify_adapter(binary, code, binding):
    adapter_digest, size, hole = binding
    header = bytearray(elf_header())
    end = len(header) + size
    length = end + len(code)
    struct.pack_into('<2Q', header, 96, length, length)
    if len(binary) != length or binary[:len(header)] != header or binary[end:] != code:
        raise ValueError('HIA packer changed the ELF envelope or direct load plan')
    adapter = bytearray(binary[len(header):end])
    if adapter[hole - 1:hole + 4] != b'\xe8' + struct.pack('<i', size - hole - 4):
        raise ValueError('HIA packer changed the admitted direct call relocation')
    adapter[hole:hole + 4] = bytes(4)
    if sha256(adapter).digest() != adapter_digest:
        raise ValueError('HIA packer changed the admitted direct call syscall adapter')


def assemble(output, compiler, sources, binding):
    image, image_receipt = compile_stage(output, 'direct-load-plan', compiler, sources[SOURCE_PATH])
    packer, packer_receipt = compile_stage(output, 'direct-call-packer', compiler, sources[PACKER_PATH])
    code, packer_bytes = image.read_bytes(), packer.read_bytes()
    if digest(code) != image_receipt['produced_sha256'] or digest(packer_bytes) != packer_receipt['produced_sha256']:
        raise ValueError('direct call source or packer identity changed')
    request = struct.pack('<2Q', PACKER_MAGIC, len(code)) + code
    path, receipt = compile_stage(output, 'direct-call-executable', packer, request, output_extension='.elf')
    binary = path.read_bytes()
    verify_adapter(binary, code, binding)
    if (digest(binary) != receipt['produced_sha256']
            or image.read_bytes() != code or packer.read_bytes() != packer_bytes):
        raise ValueError('HIA packer changed the admitted direct load plan or syscall adapter')
    return binary, {'executable': inspect_executable(binary), 'transport_adapter_sha256': binding[0].hex(),
                    'transport_assembled_during_build': False,
                    'native_compile_receipt': image_receipt, 'native_packer_receipt': packer_receipt,
                    'native_pack_receipt': receipt}


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    paths = (SOURCE_PATH, PACKER_PATH, ADAPTER_PATH, DRIVER)
    sources = {name: (ROOT / name).read_bytes() for name in paths}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('standalone direct call needs matching cold source')
    binding = read_adapter_binding(sources[PACKER_PATH], sources[ADAPTER_PATH])
    output.mkdir(mode=0o700)
    binary, report = assemble(output, compiler, sources, binding)
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
