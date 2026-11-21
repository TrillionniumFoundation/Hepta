"""Pack the HIA read reactor's Linux/x86-64 descriptor carrier.

The carrier is fixed platform code, not a compiler or an alternate read policy.
The normal build compiles the checked-in HIA packer and needs no C toolchain,
assembler, oracle, runtime interpreter, or mutable link inputs.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.generate_hia_agent_stdio import document, writes
from tools.generate_hia_core_json_cli import source_program
from tools.generate_hia_mcp_stdio_packer import elf_prefix
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE = 'examples/hia_bootstrap/agent_read_carrier_packer.hepta'
MAGIC = b'HIARCK01'
CODE_DIGEST = 'be9ab7d04b011004ff47c2b39a805d28b70278a7887e76342b02ac06c151096f'
CODE_SIZE = 9048
HEADER_SIZE = 176
# Offsets in the audited ISA profile. Each group owns only delivery mechanics.
CARRIER_SECTIONS = (
    ('entry_and_abi', 0, 550),
    ('read_lease', 550, 917),
    ('extent_and_io', 917, 1249),
    ('child_closeout', 1249, 1702),
    ('immutable_buffers', 1702, 2256),
    ('child_execution', 2256, 3159),
    ('store_startup', 3159, 3661),
    ('store_transport_and_feedback', 3661, 4513),
    ('descriptor_relay_and_store_custody', 4513, CODE_SIZE),
)


def author(platform_code):
    """Render the canonical HIA source from separately reviewed ISA bytes."""
    if len(platform_code) != CODE_SIZE or sha256(platform_code).hexdigest() != CODE_DIGEST:
        raise ValueError('unrecognized read carrier ISA profile')
    prefix = elf_prefix(platform_code)
    size = len(prefix)
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 8 or read_word(s, 0) != {int.from_bytes(MAGIC, 'little')}:
        return 4294967295
    if length(o) < {size}:
        return 4294967294
    elf_header(o)
"""
    sections = {'elf_header': (0, HEADER_SIZE)}
    for name, start, end in CARRIER_SECTIONS:
        for begin in range(start, end, 512):
            chunk = f'{name}_{begin}'
            sections[chunk] = (HEADER_SIZE + begin, HEADER_SIZE + min(end, begin + 512))
            source += f'    {chunk}(o)\n'
    source += f"""    put_word(o, 96, {size})
    put_word(o, 104, {size})
    return {size}
"""
    for label, (begin, end) in sections.items():
        source += f'\ndef {label}(o:mutbuf) -> u64:\n'
        source += writes(prefix[begin:end], offset=begin)
        source += '    return 0\n'
    helpers = source_program()
    source += helpers[helpers.index('\ndef read_word('):helpers.index('\ndef put_four(')]
    return render_assembly(document(source, 'agent_read_carrier_packer'))


def build(output, compiler, cold_report):
    """Use the cold compiler to pack the exact admitted native carrier ELF."""
    report, seed, source = cold_report.read_bytes(), compiler.read_bytes(), (ROOT / SOURCE).read_bytes()
    admitted = admit_cold_build(seed, report)
    if admitted[SOURCE] != sha256(source).hexdigest():
        raise ValueError('read carrier must use the cold-admitted HIA source')
    output.mkdir(mode=0o700)
    packer, receipt = compile_stage(output, 'read-carrier-packer', compiler, source)
    packed_program = packer.read_bytes()
    program = NativeHiaJsonImage(packed_program, receipt['produced_sha256'])
    size = HEADER_SIZE + CODE_SIZE
    request = ctypes.create_string_buffer(MAGIC)
    result = ctypes.create_string_buffer(size)
    count = program._entry(request, len(MAGIC), result, size, None, 0)
    executable = result.raw
    if (count != size or request.raw != MAGIC + b'\0'
            or sha256(executable[HEADER_SIZE:]).hexdigest() != CODE_DIGEST):
        raise ValueError('read carrier packer did not produce the admitted platform image')
    expected_header = bytearray(elf_prefix(b''))
    for offset in (96, 104):
        expected_header[offset:offset + 8] = size.to_bytes(8, 'little')
    if executable[:HEADER_SIZE] != expected_header or author(executable[HEADER_SIZE:]).encode() != source:
        raise ValueError('read carrier platform header or source is noncanonical')
    elf = inspect_executable(executable)
    if (current_sources() != admitted or (ROOT / SOURCE).read_bytes() != source
            or compiler.read_bytes() != seed or cold_report.read_bytes() != report
            or packer.read_bytes() != packed_program):
        raise ValueError('read carrier inputs changed before publication')
    target = output / 'hia-agent-read-carrier'
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    with (output / 'build.json').open('x') as stream:
        json.dump({
            'schema': 'hepta.hia.agent-read-carrier-stdio-build.v1',
            'source_sha256': admitted[SOURCE], 'platform_sha256': CODE_DIGEST,
            'executable_sha256': sha256(executable).hexdigest(),
            'packer_compilation': receipt, 'elf': elf,
        }, stream, indent=2)
        stream.write('\n')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))
