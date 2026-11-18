"""Build the explicit Linux x86-64 retained Pager from matching cold source."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage


PAGER = 'examples/hia_bootstrap/sqlite_pager_retained.hepta'
LINKER = 'examples/hia_bootstrap/sqlite_pager_elf_linker.hepta'
ADAPTERS = ('tools/hia_sqlite_pager_start.S', 'tools/hia_sqlite_pager_os.S',
            'tools/hia_sqlite_pager_image.S')
DRIVER = 'tools/build_hia_sqlite_pager.py'
OBJECT_LIMIT = 1 << 20
EXECUTABLE_LIMIT = 4 << 20
LINK_OUTPUT = 8 << 20
LINK_WORKSPACE = 16 << 20
CANARY = b'\xd7' * 32


def digest(data):
    return sha256(data).hexdigest()


def write_new(path, data):
    with path.open('xb') as stream:
        stream.write(data)


def assemble(directory, name, source):
    filename = Path(name).name
    write_new(directory / filename, source)
    object_path = directory / (filename + '.o')
    command = ['/usr/bin/prlimit', '--cpu=10:10', '--as=268435456:268435456',
               '--stack=8388608:8388608', '--fsize=1048576:1048576', '--core=0:0',
               '--', '/usr/bin/as', '--64', '-o', object_path.name, filename]
    with (directory / (filename + '.stderr')).open('xb') as errors:
        subprocess.run(command, input=b'', stdout=subprocess.DEVNULL, stderr=errors,
                       cwd=directory, env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'},
                       timeout=20, check=True)
    if not 0 < object_path.stat().st_size <= OBJECT_LIMIT:
        raise ValueError('Pager adapter object exceeds its bounded extent')
    if (directory / filename).read_bytes() != source:
        raise ValueError('Pager adapter source changed during assembly')
    return object_path.read_bytes()


def verify_executable(elf, pager):
    if (len(elf) < 232 or elf[:16] != b'\x7fELF\x02\x01\x01' + bytes(9)
            or elf.count(pager) != 1):
        raise ValueError('Pager ELF must contain exactly its admitted HIA image')
    fields = struct.unpack_from('<HHIQQQIHHHHHH', elf, 16)
    entry = fields[3]
    if fields != (2, 62, 1, entry, 64, 0, 0, 64, 56, 3, 0, 0, 0):
        raise ValueError('unexpected Pager ELF header')
    rx = struct.unpack_from('<II6Q', elf, 64)
    rw = struct.unpack_from('<II6Q', elf, 120)
    stack = struct.unpack_from('<II6Q', elf, 176)
    rx_size, rw_offset = rx[5], rw[2]
    if (rx != (1, 5, 0, 0x400000, 0x400000, rx_size, rx_size, 4096)
            or not 232 <= rx_size <= len(elf)
            or not 0x400000 + 232 <= entry < 0x400000 + rx_size
            or not 232 <= elf.index(pager) <= rx_size - len(pager)
            or rw_offset != (rx_size + 4095) // 4096 * 4096
            or rw[:5] != (1, 6, rw_offset, 0x400000 + rw_offset, 0x400000 + rw_offset)
            or rw[5] != len(elf) - rw_offset or rw[6] < rw[5] or rw[7] != 4096
            or stack != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError('unexpected Pager ELF load segment or stack permissions')


def link(directory, linker, pager, objects):
    packet = struct.pack('<8s3Q', b'HIAPGLK2', len(objects), 6, 0) + b'_start'
    packet += b''.join(struct.pack('<Q', len(obj)) + obj for obj in objects)
    write_new(directory / 'link.input.bin', packet)
    input_bytes = bytearray(CANARY + packet + CANARY)
    output_bytes = bytearray(CANARY + bytes(LINK_OUTPUT) + CANARY)
    workspace = bytearray(CANARY + bytes(LINK_WORKSPACE) + CANARY)
    buffers = (input_bytes, output_bytes, workspace)
    pointers = [ctypes.addressof(ctypes.c_ubyte.from_buffer(buf)) + len(CANARY)
                for buf in buffers]
    image = NativeHiaJsonImage(linker, digest(linker))
    result = int(image._entry(pointers[0], len(packet), pointers[1], LINK_OUTPUT,
                              pointers[2], LINK_WORKSPACE))
    receipt = {'status': result, 'input_sha256': digest(packet),
               'buffer_sha256': [digest(buf) for buf in buffers]}
    write_new(directory / 'link.json', (json.dumps(receipt, indent=2) + '\n').encode())
    if (not 0 < result <= EXECUTABLE_LIMIT
            or any(buf[:len(CANARY)] != CANARY or buf[-len(CANARY):] != CANARY
                   for buf in buffers)
            or input_bytes[len(CANARY):-len(CANARY)] != packet
            or any(memoryview(output_bytes)[len(CANARY) + result:-len(CANARY)])):
        raise ValueError('native Pager link refused or changed protected bytes')
    binary = bytes(output_bytes[len(CANARY):len(CANARY) + result])
    verify_executable(binary, pager)
    return binary, receipt


def build(output, compiler, cold_report):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    sources = {name: (ROOT / name).read_bytes() for name in (PAGER, LINKER, *ADAPTERS, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('Pager build source differs from admitted cold source')
    output.mkdir(mode=0o700)
    pager_path, pager_receipt = compile_stage(output, 'pager', compiler, sources[PAGER])
    linker_path, linker_receipt = compile_stage(output, 'linker', compiler, sources[LINKER])
    pager, linker = pager_path.read_bytes(), linker_path.read_bytes()
    if digest(pager) != pager_receipt['produced_sha256'] or digest(linker) != linker_receipt['produced_sha256']:
        raise ValueError('compiled Pager or linker image drift')
    write_new(output / 'pager_read_owner.image.bin', pager)
    objects = [assemble(output, name, sources[name]) for name in ADAPTERS]
    if (output / 'pager_read_owner.image.bin').read_bytes() != pager:
        raise ValueError('Pager wrapper image changed during assembly')
    binary, link_receipt = link(output, linker, pager, objects)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or pager_path.read_bytes() != pager
            or linker_path.read_bytes() != linker
            or any((output / Path(name).name).read_bytes() != sources[name] for name in ADAPTERS)):
        raise ValueError('Pager build inputs changed during assembly or linking')
    executable = output / 'hia-sqlite-pager'
    with executable.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    report = {'schema': 'hepta.hia.sqlite-pager-build.v1', 'status': 'NATIVE_RETAINED_PAGER_BUILT',
              'source_sha256': {name: digest(raw) for name, raw in sources.items()},
              'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(cold_bytes),
              'object_sha256': [digest(obj) for obj in objects],
              'executable_sha256': digest(binary), 'executable_bytes': len(binary),
              'link_receipt': link_receipt, 'runtime_python_or_libc': False,
              'agent_store_replaced': False}
    write_new(output / 'build.json', (json.dumps(report, indent=2) + '\n').encode())
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
