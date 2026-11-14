"""Build explicit roundtrip payloads from actual matching-current-cold B3.

The public development builder is unchanged. This separate owner proves its
own compiler lineage, fixed-point profile compiler, actual full compile frames,
three actual payloads and HIA-produced ELF. It never activates a default or
executes the produced program. The postreturn observer is a distinct test ELF.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_linux_file_roundtrip import PROFILE, _checked_components
from tools.build_hia_linux_file_roundtrip_program import _frame, _elf_structure, LABELS
from tools.hia_linux_file_roundtrip_cold import (
    CAPACITY, COMPILER_SOURCE, PACKER_SOURCE, CONTROLLER_SOURCE,
    REPRESENTATION_SOURCE, SEMANTIC_SOURCE, ORDINARY_SOURCE,
    admit_cold, re_admit_authority, guard_authority, compile_bound, observation,
    capture, pin, publish, decode, digest, require, check_bindings, all_files, profile_capture,
)

TOOLCHAIN_SCHEMA = 'hepta.hia.linux-file-roundtrip-cold-toolchain.v1'
PROGRAM_SCHEMA = 'hepta.hia.linux-file-roundtrip-cold-build.v1'
OBSERVER_SCHEMA = 'hepta.hia.linux-file-roundtrip-cold-observer.v1'
BUNDLE_SCHEMA = 'hepta.hia.linux-file-roundtrip-portable-bundle.v1'
SCOPE = 'MATCHING_CURRENT_SOURCE_COLD_EXPLICIT_BOUNDED_ROUNDTRIP'
CHAIN_LABELS = ('roundtrip-P1', 'roundtrip-P2', 'roundtrip-P3', 'ordinary-B3-regression')
LIMITS = {'compile_seconds': 20, 'output_bytes': CAPACITY, 'workspace_bytes': CAPACITY}


def _new(folder):
    folder = Path(folder).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    return folder


def _record(schema, authority):
    return {'schema': schema, 'status': 'FAIL', 'scope': SCOPE, 'profile': PROFILE,
            'authority': authority, 'limits': LIMITS, 'matching_cold': True,
            'qualification_complete': False, 'whole_native': False, 'default_activated': False,
            'payload_executed': False, 'author_and_supervisor_python': True, 'stages': []}


def _finish(folder, report):
    try:
        report['retained_files'] = all_files(folder)
    except BaseException:
        report['retention_scan_error'] = traceback.format_exc()
        report['status'] = 'FAIL'
    publish(folder / 'BUILD.json', report)


def _header(report, schema, authority):
    require(type(report) is dict and report.get('schema') == schema
            and report.get('status') == 'ACTUAL_COLD_BUILD_READ_BACK'
            and report.get('scope') == SCOPE and report.get('profile') == PROFILE
            and report.get('authority') == authority and report.get('matching_cold') is True
            and report.get('qualification_complete') is False
            and report.get('whole_native') is False and report.get('default_activated') is False
            and report.get('payload_executed') is False
            and report.get('limits') == LIMITS
            and all(type(v) is int for v in report['limits'].values()),
            'complete actual cold build record required')


def _saved(path, report):
    check_bindings(report['retained_files'])
    require(report['retained_files'] == all_files(path.parent, (path.name,)),
            'complete build files changed or were added')


def publish_executable(path, raw):
    require(type(raw) is bytes and 0 < len(raw) <= CAPACITY, 'bounded actual HIA ELF required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
        os.fchmod(fd, 0o500)
    finally:
        os.close(fd)
    require(Path(path).read_bytes() == raw and stat.S_IMODE(Path(path).stat().st_mode) == 0o500,
            'actual executable publication bytes or mode differ')


def build_toolchain(output, cold_report):
    authority = admit_cold(cold_report)
    _, captured_sources = profile_capture()
    compiler_source = captured_sources[COMPILER_SOURCE]
    ordinary_source = (ROOT / ORDINARY_SOURCE).read_bytes()
    folder = _new(output); report = _record(TOOLCHAIN_SCHEMA, authority)
    try:
        provider = folder / 'captured-cold-B3.image.bin'
        capture(provider, Path(authority['compiler']).read_bytes())
        capture(folder / 'profile-compiler.hepta', compiler_source)
        capture(folder / 'ordinary-compiler.hepta', ordinary_source)
        paths = []
        for label in CHAIN_LABELS[:3]:
            provider, _, receipt = compile_bound(folder, label, provider, compiler_source, authority)
            paths.append(provider); report['stages'].append(receipt)
        ordinary, _, receipt = compile_bound(folder, CHAIN_LABELS[3], provider, ordinary_source, authority)
        report['stages'].append(receipt)
        require(paths[0].read_bytes() == paths[1].read_bytes() == paths[2].read_bytes(),
                'roundtrip profile compiler P1/P2/P3 differ')
        require(ordinary.read_bytes() == Path(authority['compiler']).read_bytes(),
                'roundtrip compiler changed the complete ordinary cold B3')
        guard_authority(authority)
        report.update(status='ACTUAL_COLD_BUILD_READ_BACK', compiler_image=pin(provider),
                      actual_profile_fixed_point=True, ordinary_B3_byte_exact=True,
                      source_manifest=authority['source_manifest'])
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc()); raise
    finally:
        _finish(folder, report)
    admit_toolchain(folder / 'BUILD.json')
    return folder / 'BUILD.json'


def admit_toolchain(path, *, authority=None):
    path = Path(path).resolve(strict=True); raw = path.read_bytes(); report = decode(raw)
    fresh = re_admit_authority(report.get('authority'))
    require(authority is None or fresh == authority, 'different current cold compiler authority')
    _header(report, TOOLCHAIN_SCHEMA, fresh); _saved(path, report)
    _, captured_sources = profile_capture()
    source, ordinary = captured_sources[COMPILER_SOURCE], (ROOT / ORDINARY_SOURCE).read_bytes()
    require((path.parent / 'profile-compiler.hepta').read_bytes() == source
            and (path.parent / 'ordinary-compiler.hepta').read_bytes() == ordinary,
            'captured compiler source differs')
    provider = path.parent / 'captured-cold-B3.image.bin'
    cold = Path(fresh['compiler']).read_bytes()
    require(provider.read_bytes() == cold, 'captured B3 differs from actual current cold')
    images, receipts = [], []
    for label in CHAIN_LABELS[:3]:
        provider, image, receipt = observation(path.parent, label, provider, source)
        images.append(image); receipts.append(receipt)
    _, produced, receipt = observation(path.parent, CHAIN_LABELS[3], provider, ordinary)
    receipts.append(receipt)
    require(images[0] == images[1] == images[2] and produced == cold
            and report['stages'] == receipts and report.get('compiler_image') == pin(provider)
            and report.get('actual_profile_fixed_point') is True
            and report.get('ordinary_B3_byte_exact') is True
            and report.get('source_manifest') == fresh['source_manifest'],
            'actual fixed-point compiler lineage differs')
    guard_authority(fresh); require(path.read_bytes() == raw, 'toolchain record changed')
    return report


def _payload_sources(captured_sources):
    raw = captured_sources[CONTROLLER_SOURCE]
    checked = assemble_program(raw, profile=PROFILE)
    controller = render_assembly(checked, profile=PROFILE).encode('utf-8')
    components = tuple(captured_sources[name] for name in (REPRESENTATION_SOURCE, SEMANTIC_SOURCE))
    _checked_components(components)
    return (controller, *components)


def build_program(output, toolchain):
    chain = admit_toolchain(toolchain); authority = chain['authority']
    folder = _new(output); report = _record(PROGRAM_SCHEMA, authority)
    try:
        provider = Path(chain['compiler_image']['path'])
        _, captured_sources = profile_capture()
        sources = _payload_sources(captured_sources); paths, images = [], []
        for label, source in zip(LABELS, sources, strict=True):
            capture(folder / (label + '.hepta'), source)
            path, image, receipt = compile_bound(folder, label, provider, source, authority)
            paths.append(path); images.append(image); report['stages'].append(receipt)
        images = tuple(images); frame = _frame(images)
        capture(folder / 'packer-input.bin', frame)
        source = captured_sources[PACKER_SOURCE]; capture(folder / 'packer.hepta', source)
        packer, _, receipt = compile_bound(folder, 'packer', provider, source, authority)
        report['stages'].append(receipt)
        _, elf, receipt = compile_bound(folder, 'packed', packer, frame, authority, extension='.elf.bin')
        report['stages'].append(receipt)
        inspected = _elf_structure(elf, images)
        executable = folder / 'hia-native-file-roundtrip'; publish_executable(executable, elf)
        _, ending_sources = profile_capture()
        require(_payload_sources(ending_sources) == sources, 'actual roundtrip inputs changed')
        guard_authority(authority)
        report.update(status='ACTUAL_COLD_BUILD_READ_BACK', toolchain=pin(toolchain),
                      components=[pin(path) for path in paths], executable=pin(executable),
                      elf_inspection=inspected)
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc()); raise
    finally:
        _finish(folder, report)
    admit_program(folder / 'BUILD.json')
    return folder / 'BUILD.json'


def admit_program(path, *, authority=None):
    path = Path(path).resolve(strict=True); raw = path.read_bytes(); report = decode(raw)
    fresh = re_admit_authority(report.get('authority'))
    require(authority is None or authority == fresh, 'program belongs to different cold source')
    _header(report, PROGRAM_SCHEMA, fresh); _saved(path, report)
    check_bindings([report['toolchain']]); chain = admit_toolchain(report['toolchain']['path'], authority=fresh)
    _, captured_sources = profile_capture()
    provider = Path(chain['compiler_image']['path']); sources = _payload_sources(captured_sources)
    images, paths, receipts = [], [], []
    for label, source in zip(LABELS, sources, strict=True):
        require((path.parent / (label + '.hepta')).read_bytes() == source, 'captured payload source differs')
        image_path, image, receipt = observation(path.parent, label, provider, source)
        paths.append(image_path); images.append(image); receipts.append(receipt)
    images = tuple(images); frame = _frame(images); source = captured_sources[PACKER_SOURCE]
    require((path.parent / 'packer-input.bin').read_bytes() == frame
            and (path.parent / 'packer.hepta').read_bytes() == source, 'actual packer input changed')
    packer, _, receipt = observation(path.parent, 'packer', provider, source); receipts.append(receipt)
    _, elf, receipt = observation(path.parent, 'packed', packer, frame, extension='.elf.bin'); receipts.append(receipt)
    executable = path.parent / 'hia-native-file-roundtrip'
    require(report['stages'] == receipts and report['components'] == [pin(p) for p in paths]
            and report['executable'] == pin(executable) and report['executable']['mode'] == 0o500
            and executable.read_bytes() == elf and report['elf_inspection'] == _elf_structure(elf, images),
            'actual payload/ELF publication differs')
    guard_authority(fresh); require(path.read_bytes() == raw, 'program build record changed')
    return report


def build_observer(output, program_build):
    from tests.hia_linux_file_roundtrip_observer import generated
    production = admit_program(program_build); authority = production['authority']
    chain = admit_toolchain(production['toolchain']['path'], authority=authority)
    folder = _new(output); report = _record(OBSERVER_SCHEMA, authority)
    try:
        source = generated(); capture(folder / 'observer-packer.hepta', source)
        packer, _, receipt = compile_bound(folder, 'observer-packer', chain['compiler_image']['path'], source, authority)
        report['stages'].append(receipt)
        images = tuple(Path(row['path']).read_bytes() for row in production['components'])
        frame = _frame(images); capture(folder / 'packer-input.bin', frame)
        _, elf, receipt = compile_bound(folder, 'observer-packed', packer, frame, authority, extension='.elf.bin')
        report['stages'].append(receipt)
        inspected = _elf_structure(elf, images)
        executable = folder / 'hia-roundtrip-postreturn-observer'; publish_executable(executable, elf)
        require(generated() == source, 'observer author projection changed')
        guard_authority(authority)
        report.update(status='ACTUAL_COLD_BUILD_READ_BACK', production=pin(program_build),
                      executable=pin(executable), elf_inspection=inspected,
                      test_only=True, actual_payloads_identical=True,
                      complete_buffer_extents=[8388609, CAPACITY, CAPACITY],
                      observer_fds=[29, 30, 31], host_writes_observed_buffers=False)
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc()); raise
    finally:
        _finish(folder, report)
    admit_observer(folder / 'BUILD.json')
    return folder / 'BUILD.json'


def admit_observer(path, *, authority=None):
    from tests.hia_linux_file_roundtrip_observer import generated
    path = Path(path).resolve(strict=True); raw = path.read_bytes(); report = decode(raw)
    fresh = re_admit_authority(report.get('authority'))
    require(authority is None or fresh == authority, 'observer current source differs')
    _header(report, OBSERVER_SCHEMA, fresh); _saved(path, report)
    check_bindings([report['production']]); production = admit_program(report['production']['path'], authority=fresh)
    chain = admit_toolchain(production['toolchain']['path'], authority=fresh)
    images = tuple(Path(row['path']).read_bytes() for row in production['components'])
    source = generated(); frame = _frame(images)
    require((path.parent / 'observer-packer.hepta').read_bytes() == source
            and (path.parent / 'packer-input.bin').read_bytes() == frame,
            'observer source or actual payload frame changed')
    packer, _, a = observation(path.parent, 'observer-packer', chain['compiler_image']['path'], source)
    _, elf, b = observation(path.parent, 'observer-packed', packer, frame, extension='.elf.bin')
    executable = path.parent / 'hia-roundtrip-postreturn-observer'
    require(report['stages'] == [a, b] and report['executable'] == pin(executable)
            and report['executable']['mode'] == 0o500 and executable.read_bytes() == elf
            and report['elf_inspection'] == _elf_structure(elf, images)
            and report.get('test_only') is True and report.get('actual_payloads_identical') is True
            and report.get('host_writes_observed_buffers') is False
            and report.get('complete_buffer_extents') == [8388609, CAPACITY, CAPACITY]
            and report.get('observer_fds') == [29, 30, 31], 'actual observer build differs')
    guard_authority(fresh); require(path.read_bytes() == raw, 'observer record changed')
    return report


def build_portable_bundle(output, program_build):
    """Publish the actual cold-built ELF and its explicit five-source profile.

    This is an installation artifact, not a serialized execution capability.
    Its static ELF runs directly on Linux without importing this Python owner.
    Requalification still requires the original current-cold source admission.
    """
    from hepta.hia_linux_file_roundtrip import PROFILE_SOURCE_FILES
    from hepta.hia_optional_profiles import guard_profile_identity
    production = admit_program(program_build); authority = production['authority']
    folder = _new(output); report = _record(BUNDLE_SCHEMA, authority)
    try:
        _, captured_sources = profile_capture()
        resource_root = folder / 'resources'; resource_root.mkdir(mode=0o700)
        for name in PROFILE_SOURCE_FILES:
            target = resource_root / name; target.parent.mkdir(parents=True, exist_ok=True)
            capture(target, captured_sources[name])
        identity, bundle_sources = profile_capture(resource_root=resource_root)
        require(bundle_sources == captured_sources, 'portable captured profile bytes differ')
        require(identity == authority['optional_profile'], 'portable profile bytes differ')
        binary_root = folder / 'bin'; binary_root.mkdir(mode=0o700)
        executable = binary_root / 'hia-native-file-roundtrip'
        publish_executable(executable, Path(production['executable']['path']).read_bytes())
        capture(folder / 'SOURCE-BUILD.json', Path(program_build).read_bytes())
        guard_profile_identity(PROFILE, identity, resource_root=resource_root)
        guard_authority(authority)
        report.update(status='ACTUAL_COLD_BUILD_READ_BACK', production=pin(program_build),
            executable=pin(executable), resources=identity, resource_root=str(resource_root),
            installed_payload_requires_python=False, installed_payload_requires_libc=False,
            explicit_profile_only=True)
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc()); raise
    finally:
        _finish(folder, report)
    return folder / 'BUILD.json'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--portable', action='store_true')
    args = parser.parse_args(argv)
    authority = admit_cold(args.cold_report)
    output = _new(args.output)
    chain = build_toolchain(output / 'toolchain', authority['cold_report'])
    program = build_program(output / 'program', chain)
    if args.portable:
        build_portable_bundle(output / 'portable', program)
    print(program)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
