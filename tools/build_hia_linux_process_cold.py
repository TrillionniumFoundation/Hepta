"""Build explicit Linux process compilers/programs from matching current cold B3.

The original caller-pinned development builder remains a separate entry point.
This builder never executes its produced ELF or promotes a default selection.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_process import PROFILE, require_profile, verify_linux_process_program
from tools.build_hia_linux_process_program import PACK_MAGIC, _elf_structure
from tools.hia_linux_process_cold import (
    CAPACITY, COMPILER_SOURCE, PACKER_SOURCE, ORDINARY_SOURCE,
    admit_cold, capture, check_bindings, compile_bound, decode, digest,
    guard_authority, observation, pin, publish, re_admit_authority, require,
)

TOOLCHAIN_SCHEMA = 'hepta.hia.linux-process-cold-toolchain.v1'
TOOLCHAIN_STATUS = 'MATCHING_SOURCE_COLD_LINUX_PROCESS_COMPILER_BUILT'
PROGRAM_SCHEMA = 'hepta.hia.linux-process-cold-program-build.v1'
PROGRAM_STATUS = 'MATCHING_SOURCE_COLD_LINUX_PROCESS_PROGRAM_BUILT'
LABELS = ('process-P1', 'process-P2', 'process-P3', 'ordinary-B3-regression', 'entry-packer')


def _sources():
    return {name: (ROOT / name).read_bytes()
            for name in (COMPILER_SOURCE, ORDINARY_SOURCE, PACKER_SOURCE)}


def _capture_names(folder):
    return {'compiler': folder / 'captured-cold-B3.image.bin',
            COMPILER_SOURCE: folder / 'captured-linux-compiler.hepta',
            ORDINARY_SOURCE: folder / 'captured-ordinary-compiler.hepta',
            PACKER_SOURCE: folder / 'captured-entry-packer.hepta'}


def _stages(folder, authority, sources):
    captures = _capture_names(folder)
    records = []
    images = {}
    provider = captures['compiler']
    for label in LABELS[:3]:
        path, raw, receipt = observation(folder, label, provider, sources[COMPILER_SOURCE])
        images[label] = path
        records.append(receipt)
        provider = path
    path, raw, receipt = observation(folder, LABELS[3], provider, sources[ORDINARY_SOURCE])
    images[LABELS[3]] = path
    records.append(receipt)
    path, raw, receipt = observation(folder, LABELS[4], provider, sources[PACKER_SOURCE])
    images[LABELS[4]] = path
    records.append(receipt)
    linux_bytes = [images[label].read_bytes() for label in LABELS[:3]]
    require(linux_bytes[0] == linux_bytes[1] == linux_bytes[2], 'Linux P1/P2/P3 fixed point differs')
    original = Path(authority['compiler']).read_bytes()
    require(captures['compiler'].read_bytes() == original
            and images[LABELS[3]].read_bytes() == original,
            'profile compiler changes the complete ordinary B3 compiler')
    require(all(captures[name].read_bytes() == raw for name, raw in sources.items()),
            'captured compiler/packer sources changed')
    return images, records


def _all_files(folder, exclude=()):
    return [pin(p) for p in sorted(Path(folder).rglob('*'))
            if p.is_file() and str(p.relative_to(folder)) not in exclude]


def build_toolchain(output, cold_report, *, compiler=None):
    """Five actual original-budget stages, with exact cold and full receipts."""
    authority = admit_cold(cold_report, compiler=compiler)
    sources = _sources()
    require(all(digest(raw) == authority['source_manifest'][name]
                for name, raw in sources.items()), 'compiler/packer capture differs from cold source')
    # Both author assets are ordinary pure HIA. The physical profile remains
    # explicit only for programs compiled by the resulting Linux compiler.
    pure = {name: assemble_program(raw).sha256 for name, raw in sources.items()}
    folder = Path(output).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': TOOLCHAIN_SCHEMA, 'status': 'FAIL', 'profile': PROFILE,
        'scope': 'MATCHING_CURRENT_SOURCE_COLD', 'authority': authority,
        'source_manifest': authority['source_manifest'],
        'source_sha256': {name: digest(raw) for name, raw in sources.items()},
        'pure_core_sha256': pure, 'compiler_sha256': authority['compiler_sha256'],
        'cold_report_sha256': authority['cold_report_sha256'],
        'matching_cold': True, 'qualification_complete': False,
        'whole_native_delivery_qualified': False, 'default_activated': False,
        'author_and_supervisor_python': True,
        'compile_seconds': 20, 'output_bytes': CAPACITY, 'workspace_bytes': CAPACITY,
        'stage_labels': list(LABELS), 'stages': []}
    try:
        captures = _capture_names(folder)
        capture(captures['compiler'], Path(authority['compiler']).read_bytes())
        for name, raw in sources.items():
            capture(captures[name], raw)
        provider = captures['compiler']
        for label in LABELS[:3]:
            path, raw, receipt = compile_bound(folder, label, provider, sources[COMPILER_SOURCE], authority)
            report['stages'].append(receipt)
            provider = path
        for label, name in ((LABELS[3], ORDINARY_SOURCE), (LABELS[4], PACKER_SOURCE)):
            path, raw, receipt = compile_bound(folder, label, provider, sources[name], authority)
            report['stages'].append(receipt)
        images, observed = _stages(folder, authority, sources)
        require(observed == report['stages'], 'actual full compiler receipts differ')
        require(_sources() == sources, 'source changed during toolchain build')
        guard_authority(authority)
        report.update(status=TOOLCHAIN_STATUS, inputs_unchanged=True,
            process_P1_P2_P3_equal=True, ordinary_B3_byte_exact=True,
            compiler_image=str(images['process-P3']), packer_image=str(images['entry-packer']),
            image_sha256={name: digest(path.read_bytes()) for name, path in images.items()},
            input_bindings=_all_files(folder))
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc())
        raise
    finally:
        publish(folder / 'BUILD.json', report)
    return folder / 'BUILD.json'


def admit_toolchain(path, *, authority=None):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    report = decode(raw)
    require(type(report) is dict and report.get('schema') == TOOLCHAIN_SCHEMA
            and report.get('status') == TOOLCHAIN_STATUS
            and report.get('scope') == 'MATCHING_CURRENT_SOURCE_COLD'
            and report.get('profile') == PROFILE and report.get('matching_cold') is True
            and report.get('qualification_complete') is False
            and report.get('whole_native_delivery_qualified') is False
            and report.get('default_activated') is False,
            'strict cold toolchain record required; development records are not authority')
    fresh = re_admit_authority(report.get('authority'))
    if authority is not None:
        require(fresh == authority, 'toolchain belongs to different cold authority')
    sources = _sources()
    check_bindings(report.get('input_bindings'))
    require(report['input_bindings'] == _all_files(path.parent, exclude=(path.name,)),
            'toolchain file inventory differs')
    images, receipts = _stages(path.parent, fresh, sources)
    require(report.get('source_manifest') == fresh['source_manifest']
            and report.get('source_sha256') == {name: digest(value) for name, value in sources.items()}
            and report.get('pure_core_sha256') == {name: assemble_program(value).sha256 for name, value in sources.items()}
            and report.get('compiler_sha256') == fresh['compiler_sha256']
            and report.get('cold_report_sha256') == fresh['cold_report_sha256']
            and report.get('stage_labels') == list(LABELS) and report.get('stages') == receipts
            and report.get('compiler_image') == str(images['process-P3'])
            and report.get('packer_image') == str(images['entry-packer'])
            and report.get('image_sha256') == {name: digest(p.read_bytes()) for name, p in images.items()}
            and report.get('inputs_unchanged') is True and report.get('process_P1_P2_P3_equal') is True
            and report.get('ordinary_B3_byte_exact') is True
            and type(report.get('compile_seconds')) is int and report['compile_seconds'] == 20
            and type(report.get('output_bytes')) is int and report['output_bytes'] == CAPACITY
            and type(report.get('workspace_bytes')) is int and report['workspace_bytes'] == CAPACITY,
            'actual cold compiler chain or original limits differ')
    guard_authority(fresh)
    require(path.read_bytes() == raw, 'toolchain report changed during admission')
    return report


def _publish_executable(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, 0o500)
    finally:
        os.close(fd)
    require(path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == 0o500,
            'published ELF bytes or mode differ')


def build_program(program, output, *, profile, cold_report, compiler=None, toolchain=None):
    """Compile and pack one checked program. Execution is a separate action."""
    require_profile(profile)
    checked = verify_linux_process_program(program)
    source = render_assembly(checked, profile=PROFILE).encode()
    authority = admit_cold(cold_report, compiler=compiler)
    admitted = None if toolchain is None else admit_toolchain(toolchain, authority=authority)
    folder = Path(output).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': PROGRAM_SCHEMA, 'status': 'FAIL', 'profile': PROFILE,
        'scope': 'MATCHING_CURRENT_SOURCE_COLD', 'authority': authority,
        'source_manifest': authority['source_manifest'],
        'program_sha256': checked.sha256, 'source_sha256': digest(source),
        'cold_report_sha256': authority['cold_report_sha256'],
        'matching_cold': True, 'qualification_complete': False,
        'whole_native_delivery_qualified': False, 'default_activated': False,
        'payload_executed': False, 'author_and_supervisor_python': True,
        'compile_seconds': 20, 'output_bytes': CAPACITY, 'workspace_bytes': CAPACITY,
        'stages': []}
    try:
        if admitted is None:
            toolchain = build_toolchain(folder / 'toolchain', cold_report, compiler=authority['compiler'])
            admitted = admit_toolchain(toolchain, authority=authority)
        toolchain_path = Path(toolchain).resolve(strict=True)
        compiler_raw = Path(admitted['compiler_image']).read_bytes()
        packer_raw = Path(admitted['packer_image']).read_bytes()
        local_compiler = folder / 'captured-linux-compiler.image.bin'
        local_packer = folder / 'captured-entry-packer.image.bin'
        capture(local_compiler, compiler_raw)
        capture(local_packer, packer_raw)
        capture(folder / 'program.hepta', source)
        program_path, program_raw, first = compile_bound(folder, 'program', local_compiler, source, authority)
        report['stages'].append(first)
        require(len(program_raw) <= CAPACITY - 1024, 'program leaves no fixed ELF entry space')
        frame = struct.pack('<QQQQ', PACK_MAGIC, 1, len(program_raw), 0) + program_raw
        packed_path, elf, second = compile_bound(folder, 'packed', local_packer, frame, authority,
                                                  extension='.elf.bin')
        report['stages'].append(second)
        inspected = _elf_structure(elf, program_raw)
        require(admit_toolchain(toolchain_path, authority=authority) == admitted
                and local_compiler.read_bytes() == compiler_raw and local_packer.read_bytes() == packer_raw
                and (folder / 'program.hepta').read_bytes() == source
                and verify_linux_process_program(checked).canonical_bytes == checked.canonical_bytes,
                'captured program or cold toolchain changed')
        guard_authority(authority)
        destination = folder / 'program.elf'
        _publish_executable(destination, elf)
        report.update(status=PROGRAM_STATUS, inputs_unchanged=True,
            toolchain=pin(toolchain_path), compiler_sha256=digest(compiler_raw),
            packer_sha256=digest(packer_raw), elf_inspection=inspected,
            executable=pin(destination), input_bindings=_all_files(folder))
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc())
        raise
    finally:
        publish(folder / 'BUILD.json', report)
    return folder / 'BUILD.json'


def admit_program(path, *, authority=None):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    report = decode(raw)
    require(type(report) is dict and report.get('schema') == PROGRAM_SCHEMA
            and report.get('status') == PROGRAM_STATUS
            and report.get('scope') == 'MATCHING_CURRENT_SOURCE_COLD'
            and report.get('profile') == PROFILE and report.get('matching_cold') is True
            and report.get('qualification_complete') is False
            and report.get('whole_native_delivery_qualified') is False
            and report.get('default_activated') is False and report.get('payload_executed') is False,
            'strict cold program build required; development records cannot qualify')
    fresh = re_admit_authority(report.get('authority'))
    if authority is not None:
        require(fresh == authority, 'program belongs to different cold source authority')
    folder = path.parent
    check_bindings(report.get('input_bindings'))
    require(report['input_bindings'] == _all_files(folder, exclude=(path.name,)),
            'program file inventory differs')
    tc = report.get('toolchain')
    require(type(tc) is dict and pin(tc['path']) == tc, 'toolchain record identity changed')
    chain = admit_toolchain(tc['path'], authority=fresh)
    source = (folder / 'program.hepta').read_bytes()
    checked = assemble_program(source, profile=PROFILE)
    local_compiler, local_packer = folder / 'captured-linux-compiler.image.bin', folder / 'captured-entry-packer.image.bin'
    require(local_compiler.read_bytes() == Path(chain['compiler_image']).read_bytes()
            and local_packer.read_bytes() == Path(chain['packer_image']).read_bytes(),
            'program uses a different compiler or packer')
    _, program, first = observation(folder, 'program', local_compiler, source)
    frame = struct.pack('<QQQQ', PACK_MAGIC, 1, len(program), 0) + program
    _, elf, second = observation(folder, 'packed', local_packer, frame, extension='.elf.bin')
    exe = folder / 'program.elf'
    require(report.get('source_manifest') == fresh['source_manifest']
            and report.get('program_sha256') == checked.sha256 and report.get('source_sha256') == digest(source)
            and report.get('cold_report_sha256') == fresh['cold_report_sha256']
            and report.get('compiler_sha256') == digest(local_compiler.read_bytes())
            and report.get('packer_sha256') == digest(local_packer.read_bytes())
            and report.get('stages') == [first, second]
            and report.get('elf_inspection') == _elf_structure(elf, program)
            and report.get('executable') == pin(exe) and exe.read_bytes() == elf
            and stat.S_IMODE(exe.stat().st_mode) == 0o500
            and report.get('inputs_unchanged') is True
            and type(report.get('compile_seconds')) is int and report['compile_seconds'] == 20
            and type(report.get('output_bytes')) is int and report['output_bytes'] == CAPACITY
            and type(report.get('workspace_bytes')) is int and report['workspace_bytes'] == CAPACITY,
            'actual program receipt, pack frame, ELF or original limit differs')
    guard_authority(fresh)
    require(path.read_bytes() == raw, 'program report changed during admission')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--compiler', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--profile', choices=[PROFILE])
    parser.add_argument('--toolchain', type=Path)
    args = parser.parse_args(argv)
    if args.source is None:
        require(args.profile is None and args.toolchain is None, 'toolchain-only arguments cannot select a program')
        path = build_toolchain(args.output, args.cold_report, compiler=args.compiler)
    else:
        require_profile(args.profile)
        checked = assemble_program(args.source.read_bytes(), profile=args.profile)
        path = build_program(checked, args.output, profile=args.profile, cold_report=args.cold_report,
                             compiler=args.compiler, toolchain=args.toolchain)
    print(json.dumps({'build': str(path), 'status': decode(path.read_bytes())['status']}, sort_keys=True))


if __name__ == '__main__':
    main()
