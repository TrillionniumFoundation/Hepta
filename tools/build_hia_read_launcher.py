"""Cold-pack a freestanding read Worker launcher and its HIA authority image."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_journal_native import _catalog_bytes
from hepta.hia_agent_store import wire
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_native_helpers import _read
from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.generate_hia_agent_stdio import document, writes
from tools.generate_hia_core_json_cli import source_program
from tools.generate_hia_mcp_stdio_packer import elf_prefix
from tools.generate_hia_read_capsule import (
    DOSSIER_MAGIC, MANIFEST_MAGIC, MAX_ROLE_BYTES, ROLES, SOURCE as AUTHORITY,
)
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE = 'examples/hia_bootstrap/agent_read_launcher_packer.hepta'
MAGIC = b'HIARLK01'
PLATFORM_SHA256 = '3f0463c32d607c007e3367662f0f813df604bf95ae5dd3aadf1dfa90edf3f8b2'
PLATFORM_SIZE = 6192
HEADER_SIZE = 176
IMAGE_LIMIT = 1 << 20
SEGMENTS = (
    ('platform_io_and_custody', 0, 1779),
    ('stable_role_capture', 1779, 2461),
    ('native_authority_call', 2461, 2849),
    ('capsule_launcher', 2849, 6032),
    ('fixed_role_directory', 6032, PLATFORM_SIZE),
)


def author(platform_code):
    if len(platform_code) != PLATFORM_SIZE or sha256(platform_code).hexdigest() != PLATFORM_SHA256:
        raise ValueError('unrecognized read launcher platform profile')
    prefix = elf_prefix(platform_code)
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = length(s)
    if count <= 8 or count > {IMAGE_LIMIT + 8} or read_word(s, 0) != {int.from_bytes(MAGIC, 'little')}:
        return 4294967295
    size = {len(prefix)} + count - 8
    if length(o) < size:
        return 4294967294
    header(o)
"""
    pieces = {'header': (0, HEADER_SIZE)}
    for role, start, end in SEGMENTS:
        for begin in range(start, end, 512):
            label = f'{role}_{begin}'
            pieces[label] = (HEADER_SIZE + begin, HEADER_SIZE + min(end, begin + 512))
            source += f'    {label}(o)\n'
    source += f"""    put_word(o, 96, size)
    put_word(o, 104, size)
    index = 8
    while index < count:
        store(o, {len(prefix) - 8} + index, byte(s, index))
        index = index + 1
    return size
"""
    for label, (begin, end) in pieces.items():
        source += f'\ndef {label}(o:mutbuf) -> u64:\n'
        source += writes(prefix[begin:end], offset=begin)
        source += '    return 0\n'
    helpers = source_program()
    source += helpers[helpers.index('\ndef read_word('):helpers.index('\ndef put_four(')]
    return render_assembly(document(source, 'agent_read_launcher_packer'))


def build(output, compiler, cold_report):
    pins = {path: path.read_bytes() for path in (compiler, cold_report, ROOT / SOURCE, ROOT / AUTHORITY)}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    for name in (SOURCE, AUTHORITY):
        if admitted[name] != sha256(pins[ROOT / name]).hexdigest():
            raise ValueError('native read launcher sources differ from the cold contract')
    output.mkdir(mode=0o700)
    authority, authority_receipt = compile_stage(output, 'read-capsule-authority', compiler, pins[ROOT / AUTHORITY])
    packer, packer_receipt = compile_stage(output, 'read-launcher-packer', compiler, pins[ROOT / SOURCE])
    for path, receipt in ((authority, authority_receipt), (packer, packer_receipt)):
        pins[path] = path.read_bytes()
        if sha256(pins[path]).hexdigest() != receipt['produced_sha256']:
            raise ValueError('read launcher build image does not match the cold execution receipt')
    image = pins[authority]
    if not 0 < len(image) <= IMAGE_LIMIT:
        raise ValueError('native read capsule authority exceeds the pack bound')
    raw = MAGIC + image
    request = ctypes.create_string_buffer(raw)
    program = NativeHiaJsonImage(pins[packer], packer_receipt['produced_sha256'])
    size = HEADER_SIZE + PLATFORM_SIZE + len(image)
    result = ctypes.create_string_buffer(size)
    count = program._entry(request, len(raw), result, size, None, 0)
    executable = result.raw
    header = bytearray(elf_prefix(b''))
    struct.pack_into('<2Q', header, 96, size, size)
    platform = executable[HEADER_SIZE:HEADER_SIZE + PLATFORM_SIZE]
    if (count != size or request.raw != raw + b'\0' or executable[:HEADER_SIZE] != header
            or executable[HEADER_SIZE + PLATFORM_SIZE:] != image
            or author(platform).encode() != pins[ROOT / SOURCE]):
        raise ValueError('native read launcher output differs from its compiled source and authority image')
    elf = inspect_executable(executable)
    if current_sources() != admitted or any(path.read_bytes() != before for path, before in pins.items()):
        raise ValueError('native read launcher inputs changed before publication')
    target = output / 'hia-agent-read-launcher'
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    with (output / 'build.json').open('x') as stream:
        json.dump({
            'schema': 'hepta.hia.agent-read-launcher-build.v1', 'source_sha256': admitted[SOURCE],
            'authority_source_sha256': admitted[AUTHORITY], 'platform_sha256': PLATFORM_SHA256,
            'executable_sha256': sha256(executable).hexdigest(), 'elf': elf,
            'authority_compilation': authority_receipt, 'packer_compilation': packer_receipt,
        }, stream, indent=2)
        stream.write('\n')
    return target


def bind_release(target, release, expected_launcher, profile_pin):
    """Write the capability capsule after the installed Worker pins exist.

    The caller owns the selected Worker scope. Keeping the capsule outside
    the Store package avoids a cycle through the package and Worker digests.
    """
    launcher = release / 'hia-agent-read-launcher'
    expected = expected_launcher.read_bytes()
    if _read(launcher, HEADER_SIZE + PLATFORM_SIZE + IMAGE_LIMIT).raw != expected:
        raise ValueError('installed read launcher differs from the cold build')
    raw_authority = expected[HEADER_SIZE + PLATFORM_SIZE:]
    authority = NativeHiaJsonImage(raw_authority, sha256(raw_authority).hexdigest())
    roles = [_read(release / name, MAX_ROLE_BYTES) for name in ROLES]
    identities = installation_manifest()
    catalog = _catalog_bytes()
    if (identities.get('native_helpers_sha256') != profile_pin
            or identities['catalog_sha256'] != sha256(catalog).hexdigest()):
        raise ValueError('read capsule does not match the installed Worker scope')
    pins = (identities[key].encode('ascii') for key in (
        'catalog_sha256', 'backend_sha256', 'worker_sha256', 'native_helpers_sha256'))
    observed = wire(identities)
    dossier = struct.pack('<8s6Q64s64s64s64s', DOSSIER_MAGIC, sys.get_int_max_str_digits(),
                          1, len(catalog), len(observed), len(observed), 0, *pins)
    dossier += catalog + observed + observed

    def verify(raw, mode, ordinal):
        digest = sha256(raw).digest()
        flags = struct.pack('<32s3Q', digest, mode, ordinal, len(raw))
        source = ctypes.create_string_buffer(raw, len(raw))
        checked = ctypes.create_string_buffer(bytes(32) + flags, 88)
        scratch = ctypes.create_string_buffer(1088)
        status = authority._entry(source, len(raw), checked, 88, scratch, 1088)
        if status != 1 or checked.raw != digest + flags or source.raw != raw:
            raise ValueError('installed read capability failed native capsule admission')
        return digest

    manifest = struct.pack('<8s4Q', MANIFEST_MAGIC, 1, len(roles), len(dossier), 0)
    manifest += b''.join(struct.pack('<2Q32s', ordinal, len(role.raw),
                                    verify(role.raw, 2, ordinal))
                         for ordinal, role in enumerate(roles, 1))
    manifest += dossier
    capsule_pin = verify(manifest, 1, 0).hex()
    for role in roles:
        if _read(role.path, MAX_ROLE_BYTES) != role:
            raise ValueError('installed read capability changed before capsule publication')
    with target.open('xb') as stream:
        target.chmod(0o400)
        stream.write(manifest)
    return capsule_pin


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report))
