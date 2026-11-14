"""Build an explicitly selected three-image Linux file/render process, without executing it.

This v2 entry is an explicit bounded primitive-v6/v8 policy; it does not implement
the old full render-assembly CLI or its Python diagnostics/canonical roundtrip.

All machine code and the ELF layout are emitted by the actual HIA compiler and
HIA packer. Python captures inputs, checks receipts and publishes the result.
The caller's compiler digest is a development pin, never cold qualification.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_file_render import (
    PROFILE, COMPONENT_PINS, _checked_components, profile_resource_path,
    require_profile, verify_linux_file_render_program,
)
from tools.build_hia_linux_process_program import _pinned_digest, _receipt
from tools.qualify_hia_selfhost import CAPACITY, compile_stage

PACKER_SOURCE = 'examples/hia_bootstrap/linux_file_render_entry_packer.hepta'
COMPILER_SOURCE = 'examples/hia_bootstrap/selfhost_linux_file_render.hepta'
PACK_MAGIC = int.from_bytes(b'HFLRPAK1', 'little')
LABELS = ('controller', 'frontend', 'checker')


def _digest(raw):
    return sha256(raw).hexdigest()


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def _frame(images):
    if type(images) is not tuple or len(images) != 3 or any(type(x) is not bytes for x in images):
        raise TypeError('exact controller/frontend/semantic-checker image tuple required')
    if any(not 0 < len(x) <= CAPACITY - 1024 for x in images):
        raise ValueError('each nonempty component must leave room for the ELF entry')
    raw = struct.pack('<6Q', PACK_MAGIC, 1, *(len(x) for x in images), 0) + b''.join(images)
    if len(raw) > CAPACITY:
        raise ValueError('the complete three-image frame exceeds the original 1 MiB bound')
    return raw


def _elf_structure(elf, images):
    """Inspect actual HIA output; this function emits no instruction or ELF byte."""
    _frame(images)
    offsets = []
    cursor = 1024
    for image in images:
        offsets.append(cursor)
        cursor = (cursor + len(image) + 15) & -16
    size = (offsets[-1] + len(images[-1]) + 4095) & -4096
    if (type(elf) is not bytes or not 4096 <= len(elf) <= CAPACITY or len(elf) != size
            or struct.unpack_from('<16sHHIQQQIHHHHHH', elf) !=
               (b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1, 0x400000 + 232,
                64, 0, 0, 64, 56, 3, 0, 0, 0)
            or struct.unpack_from('<IIQQQQQQ', elf, 64) !=
               (1, 5, 0, 0x400000, 0x400000, size, size, 4096)
            or struct.unpack_from('<IIQQQQQQ', elf, 120) !=
               (1, 6, size, 0x600000, 0x600000, 0, 0x1204000, 4096)
            or struct.unpack_from('<IIQQQQQQ', elf, 176) !=
               (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError('HIA-produced ELF differs from the fixed entry/segment contract')
    regions = []
    for i, (label, offset, image) in enumerate(zip(LABELS, offsets, images, strict=True)):
        end = offset + len(image)
        next_offset = offsets[i + 1] if i < 2 else size
        if elf[offset:end] != image or any(elf[end:next_offset]):
            raise ValueError('actual HIA image bytes or alignment padding differ')
        regions.append({'label': label, 'offset': offset, 'bytes': len(image), 'sha256': _digest(image)})
    return {'file_bytes': size, 'entry_offset': 232, 'regions': regions,
        'elf_interpreter': False, 'writable_executable_segment': False, 'executable_stack': False,
        'buffer_extents': [8388609, CAPACITY, CAPACITY], 'buffer_addresses': [0x602000, 0xe03000, 0xf03000],
        'startup_capability_page': 0x600000, 'stack_guard_address': 0x1003000,
        'stack_extent': 8 * CAPACITY,
        'resident_call_targets': [0x400000 + x for x in offsets[1:]],
        'component_authority': 'two fixed captured images; no arbitrary call target'}


def build_linux_file_render_program(program, output, *, profile, compiler, compiler_sha256, components):
    require_profile(profile)
    checked = verify_linux_file_render_program(program)
    source = render_assembly(checked, profile=PROFILE).encode('utf-8')
    _checked_components(components)
    compiler_path = Path(compiler)
    expected = _pinned_digest(compiler_sha256)
    compiler_raw = compiler_path.read_bytes()
    if not 0 < len(compiler_raw) <= CAPACITY or _digest(compiler_raw) != expected:
        raise ValueError('caller compiler bytes differ from the explicit development pin')
    packer_path = Path(profile_resource_path(PACKER_SOURCE))
    profile_path = Path(profile_resource_path(COMPILER_SOURCE))
    packer_source, profile_source = packer_path.read_bytes(), profile_path.read_bytes()
    packer_checked = assemble_program(packer_source)
    sources = (source, *components)
    root = Path(output)
    root.mkdir(parents=False, exist_ok=False)
    report = {'schema': 'hepta.hia.linux-file-render-build.v2', 'profile': PROFILE,
        'scope': 'EXPLICIT_PINNED_DEVELOPMENT_COMPILER',
        'matching_cold': False, 'whole': False, 'compiler_provenance_qualified': False,
        'public_core_or_code_authority': False, 'author_and_supervisor_python': True,
        'program_sha256': checked.sha256, 'source_sha256': _digest(source),
        'compiler_sha256': expected, 'profile_compiler_source_sha256': _digest(profile_source),
        'packer_source_sha256': _digest(packer_source), 'packer_core_sha256': packer_checked.sha256,
        'components': [{'label': label, 'bytes': len(raw), 'sha256': _digest(raw)}
                       for label, raw in zip(LABELS, sources, strict=True)],
        'limits': {'compile_seconds': 20, 'output_bytes': CAPACITY, 'workspace_bytes': CAPACITY},
        'stages': []}
    captured = root / 'captured-compiler.image.bin'
    captured.write_bytes(compiler_raw)
    captured.chmod(0o400)
    for label, raw in zip(LABELS, sources, strict=True):
        (root / (label + '.hepta')).write_bytes(raw)
    (root / 'packer.hepta').write_bytes(packer_source)
    (root / 'profile-compiler.hepta').write_bytes(profile_source)
    try:
        image_paths, images = [], []
        for label, raw in zip(LABELS, sources, strict=True):
            path, receipt = compile_stage(root, label, captured, raw)
            image = path.read_bytes()
            _receipt(receipt, provider=compiler_raw, source=raw, produced=image)
            image_paths.append(path)
            images.append(image)
            report['stages'].append(receipt)
            _save(root / 'PARTIAL.json', report)
        images = tuple(images)
        package = _frame(images)
        (root / 'packer-input.bin').write_bytes(package)
        packer, receipt = compile_stage(root, 'packer', captured, packer_source)
        packer_raw = packer.read_bytes()
        _receipt(receipt, provider=compiler_raw, source=packer_source, produced=packer_raw)
        report['stages'].append(receipt)
        _save(root / 'PARTIAL.json', report)
        packed, receipt = compile_stage(root, 'packed', packer, package, output_extension='.elf.bin')
        elf = packed.read_bytes()
        _receipt(receipt, provider=packer_raw, source=package, produced=elf)
        report['stages'].append(receipt)
        report['elf_inspection'] = _elf_structure(elf, images)
        if (compiler_path.read_bytes() != compiler_raw or captured.read_bytes() != compiler_raw
                or packer_path.read_bytes() != packer_source or profile_path.read_bytes() != profile_source
                or verify_linux_file_render_program(checked).canonical_bytes != checked.canonical_bytes
                or packer.read_bytes() != packer_raw or packed.read_bytes() != elf
                or any(path.read_bytes() != raw for path, raw in zip(image_paths, images, strict=True))
                or any((root / (label + '.hepta')).read_bytes() != raw
                       for label, raw in zip(LABELS, sources, strict=True))):
            raise ValueError('captured public build inputs or actual images changed')
        _checked_components(components)
        destination = root / 'hia-native-file-render'
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, 'wb', closefd=False) as stream:
                stream.write(elf)
                stream.flush()
                os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
        finally:
            os.close(descriptor)
        if destination.read_bytes() != elf:
            raise ValueError('ELF publication differs from actual HIA output')
        report.update(status='DEVELOPMENT_BUILD', executable=str(destination.resolve()),
            executable_bytes=len(elf), executable_sha256=_digest(elf),
            inputs_unchanged=True, payload_executed=False)
        return report
    except BaseException as exc:
        report.update(status='FAIL', error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        _save(root / 'REPORT.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--profile', required=True, choices=[PROFILE])
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--compiler-sha256', required=True)
    parser.add_argument('--frontend-source', required=True, type=Path)
    parser.add_argument('--semantic-checker-source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    checked = assemble_program(args.source.read_bytes(), profile=args.profile)
    components = tuple(path.read_bytes() for path in
                       (args.frontend_source, args.semantic_checker_source))
    report = build_linux_file_render_program(checked, args.output, profile=args.profile,
        compiler=args.compiler, compiler_sha256=args.compiler_sha256, components=components)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
