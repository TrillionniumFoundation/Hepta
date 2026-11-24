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
from tools.generate_hia_elf_embed import EMBED_MAGIC, EMBED_SOURCE
from tools.qualify_hia_selfhost import compile_stage


PAGER = 'examples/hia_bootstrap/sqlite_pager_retained.hepta'
STREAM = 'examples/hia_bootstrap/sqlite_pager_stream.hepta'
STATIC_LINKER = 'examples/hia_bootstrap/elf_static_linker.hepta'
ADAPTERS = ('tools/hia_sqlite_pager_start.S', 'tools/hia_sqlite_pager_os.S')
TEMPLATES = 'examples/hia_bootstrap/sqlite_pager_adapters.hepta'
DRIVER = 'tools/build_hia_sqlite_pager.py'
OBJECT_LIMIT = 1 << 20
STATIC_OBJECT_LIMIT = 65536
STATIC_OBJECT_RECORD = struct.Struct('<32s32sQ')
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


def build_embedder(directory, compiler, source, *, label='elf-embed'):
    image, receipt = compile_stage(directory, label, compiler, source)
    return NativeHiaJsonImage(image.read_bytes(), receipt['produced_sha256'])


def _read_static_object_part(template, packet):
    request = ctypes.create_string_buffer(packet, len(packet))
    result = ctypes.create_string_buffer(STATIC_OBJECT_RECORD.size + STATIC_OBJECT_LIMIT)
    count = template._entry(request, len(request), result, len(result), None, 0)
    if not 0 < count <= len(result) or request.raw != packet or any(result.raw[count:]):
        raise ValueError('native static adapter refused or changed the transport')
    return result.raw[:count]


def load_static_object(template, role, source, *, continuations=()):
    packet = struct.pack('<Q', role)
    record = b''.join(_read_static_object_part(part, packet) for part in (template, *continuations))
    if not STATIC_OBJECT_RECORD.size < len(record) <= STATIC_OBJECT_RECORD.size + STATIC_OBJECT_LIMIT:
        raise ValueError('native static adapter exceeds the bounded record extent')
    source_sha, object_sha, size = STATIC_OBJECT_RECORD.unpack_from(record)
    raw = record[STATIC_OBJECT_RECORD.size:]
    if (source_sha != sha256(source).digest() or size != len(raw)
            or not raw.startswith(b'\x7fELF\x02\x01\x01') or sha256(raw).digest() != object_sha):
        raise ValueError('native static adapter differs from its admitted source or object')
    return raw


def embed(output, label, name, raw, embedder):
    """Wrap an opaque image in the HIA-generated read-only relocatable object."""
    label_bytes = label.encode('ascii')
    packet = struct.pack('<8s3Q', EMBED_MAGIC, len(label_bytes), len(raw), 0) + label_bytes + raw
    source = ctypes.create_string_buffer(packet, len(packet))
    target = ctypes.create_string_buffer(OBJECT_LIMIT)
    size = embedder._entry(source, len(packet), target, len(target), None, 0)
    if (not 64 <= size <= len(target) or source.raw != packet
            or target.raw[64:64 + len(raw)] != raw or any(target.raw[size:])):
        raise ValueError('HIA embedder refused or changed immutable image bytes')
    obj = target.raw[:size]
    write_new(output / (name + '.embedded.elf'), raw)
    write_new(output / ('embed_' + label + '.o'), obj)
    return obj


def inspect_static_executable(elf):
    """Inspect the existing static linker's RX/RW/stack executable profile."""
    if len(elf) < 232 or elf[:16] != b'\x7fELF\x02\x01\x01' + bytes(9):
        raise ValueError('unexpected Pager ELF header')
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
            or rw_offset != (rx_size + 4095) // 4096 * 4096
            or rw[:5] != (1, 6, rw_offset, 0x400000 + rw_offset, 0x400000 + rw_offset)
            or rw[5] != len(elf) - rw_offset or rw[6] < rw[5] or rw[7] != 4096
            or stack != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError('unexpected Pager ELF load segment or stack permissions')
    return {'elf_type': 'ET_EXEC', 'machine': 'EM_X86_64', 'entry': entry,
            'program_headers': ['PT_LOAD_RX', 'PT_LOAD_RW', 'PT_GNU_STACK_RW'],
            'interpreter': None, 'dynamic_loader': False,
            'rx_file_bytes': rx_size, 'rw_file_bytes': rw[5], 'rw_memory_bytes': rw[6],
            'bytes': len(elf), 'sha256': digest(elf)}


def verify_executable(elf, pager):
    if (len(elf) < 232 or elf[:16] != b'\x7fELF\x02\x01\x01' + bytes(9)
            or elf.count(pager) != 1):
        raise ValueError('Pager ELF must contain exactly its admitted HIA image')
    inspection = inspect_static_executable(elf)
    if not 232 <= elf.index(pager) <= inspection['rx_file_bytes'] - len(pager):
        raise ValueError('unexpected Pager ELF load segment or stack permissions')


def link(directory, linker, pager, objects, *, wire_magic=b'HIAPGLK2',
         executable_limit=EXECUTABLE_LIMIT):
    packet = struct.pack('<8s3Q', wire_magic, len(objects), 6, 0) + b'_start'
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
    if (not 0 < result <= min(executable_limit, LINK_OUTPUT)
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
    sources = {name: (ROOT / name).read_bytes()
               for name in (PAGER, STREAM, STATIC_LINKER, TEMPLATES, EMBED_SOURCE, *ADAPTERS, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('Pager build source differs from admitted cold source')
    output.mkdir(mode=0o700)
    compiled = {}
    for role, name in (('pager', PAGER), ('stream', STREAM), ('linker', STATIC_LINKER),
                       ('adapters', TEMPLATES), ('elf-embed', EMBED_SOURCE)):
        path, receipt = compile_stage(output, role, compiler, sources[name])
        raw = path.read_bytes()
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('compiled Pager build image drift: ' + role)
        compiled[role] = (path, raw)
    pager, stream, linker = (compiled[role][1] for role in ('pager', 'stream', 'linker'))
    templates, embedder = (NativeHiaJsonImage(raw, digest(raw))
                           for _, raw in (compiled['adapters'], compiled['elf-embed']))
    objects = [load_static_object(templates, role, sources[name]) for role, name in enumerate(ADAPTERS)]
    objects.extend((embed(output, 'retained_pager', 'pager-owner', pager, embedder),
                    embed(output, 'retained_pager_stream', 'migration-stream', stream, embedder)))
    binary, link_receipt = link(output, linker, pager, objects, wire_magic=b'HIALNK01')
    verify_executable(binary, stream)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes
            or any(path.read_bytes() != raw for path, raw in compiled.values())
            or any((ROOT / name).read_bytes() != raw for name, raw in sources.items())):
        raise ValueError('Pager build inputs changed before native publication')
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
