"""Cold-pack a descriptor carrier and its native HIA authority."""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import platform
from pathlib import Path
import struct
import sys

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_discovery_native import installed_agent_discovery
from hepta.hia_agent_journal_native import _catalog_bytes
from hepta.hia_agent_store import _agent_resource_path, wire
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_native_helpers import _read
from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.build_hia_worker_flow import build as build_worker_flow, launcher_authority
from tools.generate_hia_agent_stdio import document, writes
from tools.generate_hia_core_json_cli import source_program
from tools.generate_hia_mcp_stdio_packer import elf_prefix
from tools.generate_hia_discovery_bootstrap_plan import BOOTSTRAP_FILES
from tools.generate_hia_read_capsule import (
    DOSSIER_MAGIC, MANIFEST_MAGIC, MAX_ROLE_BYTES, ROLES, SOURCE as AUTHORITY,
)
from tools.generate_hia_readonly_worker_capsule import (
    ARTIFACT_CONFIG, BOOTSTRAP_MAGIC, CAPSULE_MAX, MANIFEST_MAGIC as READONLY_MANIFEST,
    NATIVE_MANIFEST, NATIVE_ROLES, NATIVE_SOURCE, PROOF_TRUST_CHECKERS, PROOF_TRUST_MAGIC,
    PROOF_TRUST_NATIVE_BYTES, PROOF_TRUST_NATIVE_OFFSET, PROOF_TRUST_RUNTIME_MAX, RESOURCES_MAGIC,
    ROLES as READONLY_ROLES, SOURCE as READONLY_AUTHORITY,
)
from tools.generate_hia_worker_flow_packer import LAUNCHER_KIND
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


@dataclass(frozen=True)
class Launcher:
    source: str
    authority: str
    magic: bytes
    size: int
    sha256: str
    segments: tuple


LAUNCHERS = {
    'read': Launcher(SOURCE, AUTHORITY, MAGIC, PLATFORM_SIZE, PLATFORM_SHA256, SEGMENTS),
    'context-control': Launcher(
        'examples/hia_bootstrap/service_context_control_packer.hepta',
        'examples/hia_bootstrap/service_context.hepta',
        b'HIACTL01', 272,
        '9b0abde5eefcd699db58f7cd21144aaa1344e12a68631903bd92393565c1c637',
        (('linux_entry_and_checked_io', 0, 272),),
    ),
    'native': Launcher(
        'examples/hia_bootstrap/agent_native_launcher_packer.hepta', NATIVE_SOURCE,
        b'HIANLK01', 11648,
        'f4f191daf0d9bacf546f8e628ac233ba6366d2192587581491f8952320c48f8c',
        (('bounded_worker_launch_and_role_tables', 0, 11648),),
    ),
    'readonly': Launcher(
        'examples/hia_bootstrap/agent_readonly_launcher_packer.hepta', READONLY_AUTHORITY,
        b'HIADLK01', 10624,
        '9ed4eaee5ecd255df7bc81df34d586a3238661188b1ed72f9d12d2a1882920af',
        (('descriptor_io', 0, 1712), ('sealed_children', 1712, 3216),
         ('installed_role_capture', 3216, 4432), ('native_authority_call', 4432, 5280),
         ('worker_launch_and_closeout', 5280, 10064), ('bound_role_tables', 10064, 10624)),
    ),
}


def author(platform_code, *, kind='read'):
    launcher = LAUNCHERS[kind]
    if len(platform_code) != launcher.size or sha256(platform_code).hexdigest() != launcher.sha256:
        raise ValueError('unrecognized Worker launcher platform profile')
    prefix = elf_prefix(platform_code)
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = length(s)
    if count <= 8 or count > {IMAGE_LIMIT + 8} or read_word(s, 0) != {int.from_bytes(launcher.magic, 'little')}:
        return 4294967295
    size = {len(prefix)} + count - 8
    if length(o) < size:
        return 4294967294
    header(o)
"""
    pieces = {'header': (0, HEADER_SIZE)}
    for role, start, end in launcher.segments:
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
    return render_assembly(document(source, Path(launcher.source).stem))


def build(output, compiler, cold_report, *, kind='read'):
    if kind == 'native':
        return build_worker_flow(output, compiler, cold_report, kind=LAUNCHER_KIND)
    launcher = LAUNCHERS[kind]
    pins = {path: path.read_bytes() for path in (compiler, cold_report, ROOT / launcher.source, ROOT / launcher.authority)}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    for name in (launcher.source, launcher.authority):
        if admitted[name] != sha256(pins[ROOT / name]).hexdigest():
            raise ValueError('native read launcher sources differ from the cold contract')
    output.mkdir(mode=0o700)
    authority, authority_receipt = compile_stage(output, kind + '-capsule-authority', compiler, pins[ROOT / launcher.authority])
    packer, packer_receipt = compile_stage(output, kind + '-launcher-packer', compiler, pins[ROOT / launcher.source])
    for path, receipt in ((authority, authority_receipt), (packer, packer_receipt)):
        pins[path] = path.read_bytes()
        if sha256(pins[path]).hexdigest() != receipt['produced_sha256']:
            raise ValueError('read launcher build image does not match the cold execution receipt')
    image = pins[authority]
    if not 0 < len(image) <= IMAGE_LIMIT:
        raise ValueError('native read capsule authority exceeds the pack bound')
    raw = launcher.magic + image
    request = ctypes.create_string_buffer(raw)
    program = NativeHiaJsonImage(pins[packer], packer_receipt['produced_sha256'])
    size = HEADER_SIZE + launcher.size + len(image)
    result = ctypes.create_string_buffer(size)
    count = program._entry(request, len(raw), result, size, None, 0)
    executable = result.raw
    header = bytearray(elf_prefix(b''))
    struct.pack_into('<2Q', header, 96, size, size)
    platform = executable[HEADER_SIZE:HEADER_SIZE + launcher.size]
    if (count != size or request.raw != raw + b'\0' or executable[:HEADER_SIZE] != header
            or executable[HEADER_SIZE + launcher.size:] != image
            or author(platform, kind=kind).encode() != pins[ROOT / launcher.source]):
        raise ValueError('native read launcher output differs from its compiled source and authority image')
    elf = inspect_executable(executable)
    if current_sources() != admitted or any(path.read_bytes() != before for path, before in pins.items()):
        raise ValueError('native read launcher inputs changed before publication')
    target = output / ('hia-agent-' + kind + '-launcher')
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    with (output / 'build.json').open('x') as stream:
        json.dump({
            'schema': 'hepta.hia.agent-' + kind + '-launcher-build.v1', 'source_sha256': admitted[launcher.source],
            'authority_source_sha256': admitted[launcher.authority], 'platform_sha256': launcher.sha256,
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
    digest_role, dossier, _, _ = _installed_authority(release, expected_launcher, profile_pin, 'read')
    roles = [_read(release / name, MAX_ROLE_BYTES) for name in ROLES]

    manifest = struct.pack('<8s4Q', MANIFEST_MAGIC, 1, len(roles), len(dossier), 0)
    manifest += b''.join(struct.pack('<2Q32s', ordinal, len(role.raw),
                                    digest_role(role.raw, 2, ordinal))
                         for ordinal, role in enumerate(roles, 1))
    manifest += dossier
    capsule_pin = digest_role(manifest, 1, 0).hex()
    for role in roles:
        if _read(role.path, MAX_ROLE_BYTES) != role:
            raise ValueError('installed read capability changed before capsule publication')
    with target.open('xb') as stream:
        target.chmod(0o400)
        stream.write(manifest)
    return capsule_pin


def _installed_authority(release, expected_launcher, profile_pin, kind):
    launcher = release / ('hia-agent-' + kind + '-launcher')
    expected = expected_launcher.read_bytes()
    if _read(launcher, len(expected)).raw != expected:
        raise ValueError('installed Worker launcher differs from its cold build')
    if kind == 'native':
        raw_authority = launcher_authority(expected)
    else:
        raw_authority = expected[HEADER_SIZE + LAUNCHERS[kind].size:]
    authority = NativeHiaJsonImage(raw_authority, sha256(raw_authority).hexdigest())
    identities = installation_manifest()
    catalog = _catalog_bytes()
    if (identities.get('native_helpers_sha256') != profile_pin
            or identities['catalog_sha256'] != sha256(catalog).hexdigest()):
        raise ValueError('Worker capsule does not match the installed scope')
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
            raise ValueError('installed Worker capability failed native capsule admission')
        return digest

    return verify, dossier, observed, identities['catalog_sha256'].encode('ascii')


def bind_readonly_release(target, release, expected_launcher, profile_pin, *, artifact_roots=(), kind='readonly'):
    """Bind installed startup, discovery and Worker role capabilities."""
    if kind not in ('readonly', 'native'):
        raise ValueError('unknown Worker capability inventory')
    if len(artifact_roots) > 32:
        raise ValueError('read-only Worker exceeds the configured provider root limit')
    roots = tuple(Path(root).absolute().resolve(strict=True) for root in artifact_roots)
    if any(not root.is_dir() for root in roots):
        raise ValueError('read-only Worker artifact roots must be directories')
    verify, dossier, observed, catalog_pin = _installed_authority(
        release, expected_launcher, profile_pin, kind)
    digits = wire(len(roots))
    roots_pin = sha256(wire([str(root) for root in roots])).hexdigest().encode('ascii')
    config = struct.pack('<8s5Q', BOOTSTRAP_MAGIC, 0, len(observed), len(digits), 0, 0)
    config += catalog_pin + roots_pin + observed + digits

    resources = [(filename.encode('ascii'), _read(_agent_resource_path('docs/' + filename), 1 << 20))
                 for _, filename in BOOTSTRAP_FILES]
    documents = struct.pack('<8sQ', RESOURCES_MAGIC, len(resources))
    documents += b''.join(struct.pack('<2Q', len(name), len(file.raw)) + name + file.raw
                          for name, file in resources)

    artifact = b''
    native = kind == 'native'
    manifest_magic, names = (NATIVE_MANIFEST, NATIVE_ROLES) if native else (READONLY_MANIFEST, READONLY_ROLES)
    roles = {name: _read(release / name, MAX_ROLE_BYTES) for name in names}
    if native:
        # The old verifier issued these exact checker identities. Pin them
        # in the authenticated capsule before processing any request.
        selection = wire(sha256(wire({
            'native_helpers_sha256': profile_pin,
            'schema': 'hepta.hia.agent.proof-native-selection.v1',
        })).hexdigest())
        runtime = wire({'implementation': platform.python_implementation(), 'version': platform.python_version()})
        if len(selection) != 66 or not 2 <= len(runtime) <= PROOF_TRUST_RUNTIME_MAX:
            raise ValueError('legacy verifier identity differs from the capsule proof trust format')
        trust = struct.pack('<8sQ', PROOF_TRUST_MAGIC, len(runtime)) + selection + runtime
        checker_pins = wire([sha256(roles[name].raw).hexdigest() for name in PROOF_TRUST_CHECKERS])
        if len(checker_pins) != PROOF_TRUST_NATIVE_BYTES:
            raise ValueError('native verifier identity differs from the capsule proof trust format')
        dossier += trust.ljust(PROOF_TRUST_NATIVE_OFFSET, b'\0') + checker_pins
        discovery = installed_agent_discovery(str(release / 'agent-discovery-manifest.json'))
        document = discovery.profile_bodies(json.loads(observed), catalog_pin.decode('ascii'),
                                            len(roots), roots_pin.decode('ascii'))['artifact']
        digest = sha256(document).hexdigest()
        profile = wire({'id': 'hia-artifact-v1', 'sha256': digest})
        artifact = struct.pack('<8s64s2Q', ARTIFACT_CONFIG, digest.encode('ascii'), len(profile), len(roots))
        artifact += profile
        for root in roots:
            raw = os.fsencode(root)
            if len(raw) > 4095:
                raise ValueError('configured root exceeds native Worker path bound')
            artifact += struct.pack('<Q', len(raw)) + raw
    rows = b''.join(struct.pack('<2Q32s', ordinal, len(role.raw), verify(role.raw, 2, ordinal))
                    for ordinal, role in enumerate(roles.values(), 1))
    manifest = struct.pack('<8s6Q', manifest_magic, 1, len(roles), len(dossier), len(config),
                           len(documents), len(artifact)) + rows + dossier + config + documents + artifact
    if len(manifest) > CAPSULE_MAX:
        raise ValueError('read-only Worker capsule exceeds its admitted size')
    capsule_pin = verify(manifest, 1, 0).hex()
    for file in (*roles.values(), *(file for _, file in resources)):
        if _read(file.path, MAX_ROLE_BYTES) != file:
            raise ValueError('installed read-only capability changed before capsule publication')
    with target.open('xb') as stream:
        target.chmod(0o400)
        stream.write(manifest)
    return capsule_pin


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--kind', choices=LAUNCHERS, default='read')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, kind=args.kind))
