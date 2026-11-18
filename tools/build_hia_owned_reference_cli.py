"""Cold-build the standalone Linux x86-64 HIA owned-buffer reference executor."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import adapter_layout
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_native_filter import elf_header
from tools.generate_hia_owned_reference import (
    ADAPTER_CALLS, ADAPTER_PATH, PACKER_MAGIC, PACKER_PATH, ROOT, RUN_FUNCTION, SOURCE_PATH,
)
from tools.generate_hia_selfhost import FBASE, FSTRIDE
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

DRIVER = 'tools/build_hia_owned_reference_cli.py'


def digest(raw):
    return sha256(raw).hexdigest()


def assemble(output, compiler, sources):
    """Execute the admitted compiler and packer; independently verify placement."""
    record = FBASE + FSTRIDE * RUN_FUNCTION
    image, image_receipt = compile_stage(output, 'owned-reference', compiler, sources[SOURCE_PATH],
                                        compiler_function_offsets=(240, record))
    packer, packer_receipt = compile_stage(output, 'owned-reference-packer', compiler, sources[PACKER_PATH])
    image_bytes, packer_bytes = image.read_bytes(), packer.read_bytes()
    for raw, receipt in ((image_bytes, image_receipt), (packer_bytes, packer_receipt)):
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('compiled HIA owned reference input changed')
    workspace = image_receipt['workspace_header']
    entry = workspace[str(record)]
    if (type(entry) is not int or not workspace['240'] <= entry < len(image_bytes)
            or workspace['1024'] <= RUN_FUNCTION
            or image_bytes[entry:entry + 4] != b'\x55\x48\x89\xe5'):
        raise ValueError('native compiler did not emit the expected owned reference entry')
    payload = struct.pack('<3Q', PACKER_MAGIC, len(image_bytes), entry) + image_bytes
    exe, receipt = compile_stage(output, 'owned-reference-executable', packer, payload, output_extension='.elf')
    binary = exe.read_bytes()
    if digest(binary) != receipt['produced_sha256']:
        raise ValueError('compiled HIA owned reference executable changed')
    inspected = inspect_executable(binary)
    stub, holes, identity = adapter_layout(output, ADAPTER_PATH, sources[ADAPTER_PATH], ADAPTER_CALLS)
    header = elf_header()
    prefix = bytearray(header + stub)
    struct.pack_into('<2Q', prefix, 96, len(binary), len(binary))
    for name, offset in (('plan', 0), ('run', entry)):
        hole = len(header) + holes[name]
        struct.pack_into('<i', prefix, hole, len(prefix) + offset - hole - 4)
    if (binary != prefix + image_bytes or image.read_bytes() != image_bytes
            or packer.read_bytes() != packer_bytes or exe.read_bytes() != binary):
        raise ValueError('native packer altered the verified owned reference transport or image')
    return binary, {'executable': inspected, 'transport_object_sha256': identity,
                    'private_entry_offset': entry, 'native_compile_receipt': image_receipt,
                    'native_packer_receipt': packer_receipt, 'native_pack_receipt': receipt}


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    sources = {name: (ROOT / name).read_bytes() for name in (SOURCE_PATH, ADAPTER_PATH, PACKER_PATH, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('standalone HIA owned reference needs matching cold source')
    output.mkdir(mode=0o700)
    binary, report = assemble(output, compiler, sources)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes):
        raise ValueError('owned reference inputs changed before publication')
    executable = output / 'hia-owned-reference-wire'
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report.update({'schema': 'hepta.hia.owned-reference-wire-build.v1',
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
