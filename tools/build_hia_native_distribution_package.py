"""Build the ordinary distribution's complete package through the native owner.

Python performs cold bootstrap and byte custody for the packaging frontend.
The same installed HIA release command owns every release stage. No external
package pathname, fallback staging implementation, or unqualified seed is accepted.
"""
from __future__ import annotations

from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_source_build import (
    _build_captured, _check_pack_output, _compiled_sources, _named_source_request,
    _run_captured,
)
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'hepta.hia.native-production-package-build.v1'
BOOTSTRAP_ROLES = (
    'subprocess', 'subprocess_packer', 'source_capture', 'source_capture_packer',
    'release_owner', 'release_dag', 'release_owner_packer', 'sha256_stream',
    'release_build_entry', 'release_build_entry_packer', 'release_build_entry_bind',
    'source_build_packer', 'selfhost',
)
ENTRY_PROGRAMS = ('hia-release-build', 'hia-release-owner', 'hia-subprocess',
                  'hia-source-build', 'hia-source-capture')
SPECIAL_MEMBERS = ('compiler-manifest.json', 'hia-release-build', 'hia-release-cold-admit',
                   'hia-source-build', 'hia-worker-install')
MANDATORY_PROGRAMS = (
    'hia', 'hia-release', 'hia-worker-install', 'hia-worker-install-owner',
    'hia-controller-install', 'hia-ndu-scalar', 'hia-mcp-request-audit',
    'hia-mcp-job-bridge', 'hia-mcp-service', 'hepta-runtime-jobctl', 'hia-source-contract',
)
STATIC_PROGRAMS = frozenset((
    'hia-sqlite-pager', 'hia-sqlite-table-walk', 'hia-sqlite-agent-import-batch',
    'hia-sqlite-agent-row-import', 'hia-agent-artifact-capture', 'hia-sqlite-rowid-lookup',
    'hia-nominal-constructor', 'hia-sqlite-agent-artifact-catalog', 'hia-sqlite-record-layout',
    'hia-worker-scalar-implementation', 'hia-nominal-packet', 'hia-sqlite-agent-cost-sequence',
    'hia-sqlite-migration-publish', 'hia-sqlite-agent-catalog', 'hia-sqlite-migration-plan',
    'hia-sqlite-migration-projection', 'hia-sqlite-migrate',
))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode()


def regular_bytes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('native package custody requires an ordinary file: ' + str(path))
        raw = stream.read()
        after = os.fstat(stream.fileno())
    # Reading may update atime; identity, authority and content metadata must stay fixed.
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, name) != getattr(after, name) for name in fields) or len(raw) != before.st_size:
        raise ValueError('native package input changed during capture: ' + str(path))
    return raw


def expected_member_names(sources):
    """Use the exact source declarations consumed by the native release owner."""
    from tools.build_hia_native_store_release import RESOURCES

    def capture(name):
        raw = regular_bytes(ROOT / name)
        if sources.get(name) != sha256(raw).hexdigest():
            raise ValueError('release member declaration differs from cold source: ' + name)
        return raw

    lines = capture('examples/hia_bootstrap/release_member_sources.tsv').decode('ascii').splitlines()
    kind, count = lines[0].split('\t')
    ordinary = [line.split('\t')[0] for line in lines[1:]]
    if kind != 'members' or int(count) != len(ordinary) or len(ordinary) != len(set(ordinary)):
        raise ValueError('release member declaration has inconsistent identities')
    rows = capture('examples/hia_bootstrap/release_stage_sources.tsv').decode('ascii').splitlines()
    magic, _stages, count = rows[0].split('\t')
    stage = [row.split('\t')[2] for row in rows[1:] if row.startswith('output\t')]
    if magic != 'HIASTG01' or int(count) != len(stage) or len(stage) != len(set(stage)):
        raise ValueError('release stage declaration has inconsistent outputs')
    names = ordinary + stage + [Path(name).name for name in RESOURCES] + list(SPECIAL_MEMBERS)
    if len(names) != len(set(names)):
        raise ValueError('native package declarations duplicate a role or resource')
    if any(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,126}', name) is None for name in names):
        raise ValueError('native package declarations contain an invalid member name')
    return set(names)


def unpack_package(raw):
    """Independent mechanical framing check before the native installer readback."""
    from tools.generate_hia_release_install import (
        BUNDLE_MAGIC, EXTENDED_BUNDLE_MAGIC, MAX_RELEASE_MEMBERS, V1_WIRE_LIMIT, WIRE_LIMIT,
    )
    if type(raw) is not bytes or not 24 <= len(raw) <= WIRE_LIMIT:
        raise ValueError('native package has an invalid total extent')
    stream = io.BytesIO(raw)
    magic, count, reserved = struct.unpack('<3Q', stream.read(24))
    wanted = EXTENDED_BUNDLE_MAGIC if count > 256 or len(raw) > V1_WIRE_LIMIT else BUNDLE_MAGIC
    if magic != wanted or reserved or not 1 <= count <= MAX_RELEASE_MEMBERS:
        raise ValueError('native package has an invalid canonical header')
    members = {}
    previous = ''
    for _ in range(count):
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError('native package member header is truncated')
        size, mode, extent = struct.unpack('<3Q', header)
        if not 1 <= size <= 127 or mode not in (0o400, 0o500) or extent > len(raw):
            raise ValueError('native package member extent or mode is invalid')
        name = stream.read(size)
        if len(name) != size or re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._-]*', name) is None:
            raise ValueError('native package member name is invalid')
        name = name.decode('ascii')
        if name <= previous:
            raise ValueError('native package members are duplicated or not in canonical order')
        previous = name
        data = stream.read(extent)
        if len(data) != extent:
            raise ValueError('native package member bytes are truncated')
        members[name] = mode, data
    if stream.read():
        raise ValueError('native package has unbound trailing bytes')
    return members


def inspect_member_executable(name, raw):
    if name in STATIC_PROGRAMS:
        from tools.build_hia_sqlite_pager import inspect_static_executable
        return inspect_static_executable(raw)
    return inspect_executable(raw)


def member_inventory(members, sources):
    from tools.build_hia_native_store_release import RESOURCES

    if set(members) != expected_member_names(sources) or not set(MANDATORY_PROGRAMS) <= set(members):
        raise ValueError('native package is missing or substituting a declared release role')
    resources = {Path(name).name: name for name in RESOURCES}
    inventory = {}
    for name, (mode, raw) in sorted(members.items()):
        if (type(raw) is not bytes or type(mode) is not int or mode not in (0o400, 0o500)
                or (mode == 0o500) != raw.startswith(b'\x7fELF')
                or Path(name).suffix in {'.py', '.pyc', '.pyo', '.pth', '.rs', '.c', '.so', '.sh'}):
            raise ValueError('native package contains an invalid runtime member: ' + name)
        if mode == 0o500:
            inspect_member_executable(name, raw)
        if name in resources and sha256(raw).hexdigest() != sources.get(resources[name]):
            raise ValueError('native package resource differs from admitted source: ' + name)
        inventory[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'mode': mode}
    if any(members[name][0] != 0o500 for name in MANDATORY_PROGRAMS):
        raise ValueError('native package installer or public command is not executable')
    return inventory


def _bootstrap(directory, compiler, cold_report, sources):
    directory.mkdir(mode=0o700)
    compiler_raw, cold_raw = regular_bytes(compiler), regular_bytes(cold_report)
    _, seed_raw = _build_captured(directory / 'seed', compiler, cold_report)
    source_bytes = {name + '.hepta': regular_bytes(ROOT / 'examples/hia_bootstrap' / (name + '.hepta'))
                    for name in BOOTSTRAP_ROLES}
    pins = {'examples/hia_bootstrap/' + name: sha256(raw).hexdigest()
            for name, raw in source_bytes.items()}
    if any(sources.get(name) != pin for name, pin in pins.items()):
        raise ValueError('release bootstrap is outside complete cold admission')
    compiled = _run_captured(seed_raw, 'sources', _named_source_request(source_bytes), directory)
    if compiled.returncode or compiled.stderr:
        raise ValueError('native release bootstrap compilation failed: ' + str(compiled.returncode))
    images = _compiled_sources(compiled.stdout, source_bytes)
    if images['selfhost.hepta'] != compiler_raw:
        raise ValueError('release bootstrap did not reproduce the admitted cold compiler')
    observer = bytes.fromhex(json.loads(cold_raw)['native_flat_observer_hex'])

    def packed(name, parts, packer, magic):
        pieces = [images[part + '.hepta'] for part in parts]
        wire = struct.pack('<8s' + 'Q' * len(pieces), magic, *map(len, pieces)) + b''.join(pieces)
        image = images[packer + '.hepta']
        flat = directory / (name + '.packer.bin')
        flat.write_bytes(image)
        receipt, produced = invoke(directory, name + '-pack', flat, wire, flat_observer=observer)
        raw = _check_pack_output(receipt, produced, artifact=image, source=wire)
        inspect_executable(raw)
        return raw

    binaries = {
        'hia-subprocess': packed('runner', ('subprocess',), 'subprocess_packer', b'HIASUPK1'),
        'hia-source-capture': packed('capture', ('source_capture', 'sha256_stream'),
                                     'source_capture_packer', b'HIACAPK1'),
        'hia-release-owner': packed('owner', ('release_owner', 'release_dag', 'sha256_stream'),
                                    'release_owner_packer', b'HIAOWPK1'),
        'hia-source-build': seed_raw,
    }
    unbound = packed('unbound-entry', ('release_build_entry', 'sha256_stream'),
                     'release_build_entry_packer', b'HIAENPK1')
    binder = packed('entry-binder', ('release_build_entry_bind', 'selfhost', 'source_build_packer'),
                    'source_build_packer', b'HIASBL01')
    bindings = b''.join(sha256(binaries[name]).digest() for name in
                        ('hia-release-owner', 'hia-subprocess', 'hia-source-build', 'hia-source-capture'))
    bound = _run_captured(binder, 'build', b'HIAENBD1' + bindings + unbound, directory, timeout=30)
    if (bound.returncode or bound.stderr or len(bound.stdout) != len(unbound)
            or unbound[824:952] != bytes(128) or bound.stdout[:824] != unbound[:824]
            or bound.stdout[824:952] != bindings or bound.stdout[952:] != unbound[952:]):
        raise ValueError('native release frontend did not bind exactly the four cold capabilities')
    binaries['hia-release-build'] = bound.stdout
    for name, raw in binaries.items():
        inspect_executable(raw)
        target = directory / name
        target.write_bytes(raw)
        target.chmod(0o500)
    if current_sources() != sources or regular_bytes(compiler) != compiler_raw or regular_bytes(cold_report) != cold_raw:
        raise ValueError('release bootstrap cold inputs changed')
    report = {'source_sha256': pins, 'compiler_sha256': sha256(compiler_raw).hexdigest(),
              'cold_report_sha256': sha256(cold_raw).hexdigest(),
              'programs': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                           for name, raw in sorted(binaries.items())}}
    (directory / 'build.json').write_bytes(encoded(report))
    return directory / 'hia-release-build', binaries, report


def validate_build(package_raw, report, sources, compiler_raw, cold_raw):
    """Reject a package or receipt detached from the admitted complete build."""
    if (type(report) is not dict or report.get('schema') != SCHEMA
            or report.get('matching_source_cold_build') is not True
            or report.get('build_inputs_unchanged') is not True
            or report.get('native_install_and_verify_completed') is not True
            or report.get('source_manifest') != sources
            or report.get('compiler_sha256') != sha256(compiler_raw).hexdigest()
            or report.get('cold_report_sha256') != sha256(cold_raw).hexdigest()):
        raise ValueError('native distribution package has a different cold build identity')
    members = unpack_package(package_raw)
    inventory = member_inventory(members, sources)
    package = {'name': 'store.hiapack', 'bytes': len(package_raw), 'sha256': sha256(package_raw).hexdigest(),
               'files': len(members)}
    final = {'schema': 'hepta.hia.release-finalize.v1', 'sha256': package['sha256'],
             'bytes': package['bytes'], 'files': package['files'], 'published': True, 'source_attested': True}
    final_record = report.get('native_final_receipt')
    if (report.get('package') != package or final_record != final or report.get('members') != inventory
            or type(final_record) is not dict or final_record.get('published') is not True
            or final_record.get('source_attested') is not True
            or type(final_record.get('bytes')) is not int or type(final_record.get('files')) is not int
            or type(report['package'].get('bytes')) is not int or type(report['package'].get('files')) is not int):
        raise ValueError('native distribution package receipt differs from its complete actual bytes')
    bootstrap = report.get('bootstrap', {})
    if (bootstrap.get('compiler_sha256') != report['compiler_sha256']
            or bootstrap.get('cold_report_sha256') != report['cold_report_sha256']
            or bootstrap.get('programs') != {
                name: {'bytes': inventory[name]['bytes'], 'sha256': inventory[name]['sha256']}
                for name in ENTRY_PROGRAMS}
            or bootstrap.get('source_sha256') != {
                'examples/hia_bootstrap/' + name + '.hepta': sources.get('examples/hia_bootstrap/' + name + '.hepta')
                for name in BOOTSTRAP_ROLES}):
        raise ValueError('native package bootstrap is not bound to the current cold sources')
    return members


def build(output, compiler, cold_report):
    """Automatically produce one complete native package; retain all build evidence."""
    from tools.build_hia_release_install import build as build_installer

    output, compiler, cold_report = Path(output).absolute(), Path(compiler).resolve(strict=True), Path(cold_report).resolve(strict=True)
    compiler_raw, cold_raw = regular_bytes(compiler), regular_bytes(cold_report)
    sources = admit_cold_build(compiler_raw, cold_raw)
    if not set(MANDATORY_PROGRAMS) <= expected_member_names(sources):
        raise ValueError('ordinary native release declarations omit a mandatory product')
    output.mkdir(mode=0o700)
    entry, captured, bootstrap = _bootstrap(output / 'bootstrap', compiler, cold_report, sources)
    command = [str(entry), '--source', str(ROOT), '--output', str(output / 'release'),
               '--compiler', str(compiler), '--cold-report', str(cold_report), '--timeout-seconds', '1800']
    result = subprocess.run(command, cwd=output, env={'PATH': ''}, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=1830)
    (output / 'native-release.stdout').write_bytes(result.stdout)
    (output / 'native-release.stderr').write_bytes(result.stderr)
    if result.returncode or result.stderr:
        raise ValueError('ordinary native release owner failed: ' + str(result.returncode))
    final = json.loads(result.stdout)
    package = output / 'release/store.hiapack'
    package_raw = regular_bytes(package)
    members = unpack_package(package_raw)
    inventory = member_inventory(members, sources)
    identity = {'name': package.name, 'bytes': len(package_raw),
                'sha256': sha256(package_raw).hexdigest(), 'files': len(members)}
    expected_final = {'schema': 'hepta.hia.release-finalize.v1', 'sha256': identity['sha256'],
                      'bytes': identity['bytes'], 'files': identity['files'], 'published': True, 'source_attested': True}
    if final != expected_final:
        raise ValueError('native finalization does not bind the actual complete package')

    # Independently build the same installer, then have its native parser install
    # and verify the actual archive. No Python extraction supplies executable files.
    installer = build_installer(output / 'installer', compiler, cold_report)
    installer_raw = regular_bytes(installer)
    if members['hia-release'] != (0o500, installer_raw):
        raise ValueError('package installer differs from the independently cold-built installer')
    depot = output / 'depot'
    depot.mkdir(mode=0o700)
    for action in ('install', 'verify'):
        checked = _run_captured(installer_raw, (action, str(depot), identity['sha256']),
                                package_raw, output, timeout=180)
        (output / (action + '.stdout')).write_bytes(checked.stdout)
        (output / (action + '.stderr')).write_bytes(checked.stderr)
        expected = {'schema': 'hepta.hia.release-install.v1', 'sha256': identity['sha256'],
                    'bytes': identity['bytes'], 'files': identity['files'], 'published': action == 'install'}
        if checked.returncode or checked.stderr or json.loads(checked.stdout) != expected:
            raise ValueError('native package installation or verification failed: ' + action)
    installed = depot / identity['sha256']
    if {path.name for path in installed.iterdir()} != set(members):
        raise ValueError('native installed package inventory is not complete')
    for name, (mode, raw) in members.items():
        path = installed / name
        if regular_bytes(path) != raw or stat.S_IMODE(path.stat().st_mode) != mode:
            raise ValueError('native installed package differs from its original bytes or mode: ' + name)
    if (current_sources() != sources or regular_bytes(compiler) != compiler_raw or regular_bytes(cold_report) != cold_raw
            or regular_bytes(package) != package_raw
            or any(regular_bytes(entry.parent / name) != raw for name, raw in captured.items())):
        raise ValueError('native package inputs changed before distribution publication')
    report = {'schema': SCHEMA, 'matching_source_cold_build': True, 'build_inputs_unchanged': True,
              'source_manifest': sources, 'compiler_sha256': sha256(compiler_raw).hexdigest(),
              'cold_report_sha256': sha256(cold_raw).hexdigest(), 'bootstrap': bootstrap,
              'package': identity, 'members': inventory, 'native_final_receipt': final,
              'native_install_and_verify_completed': True, 'whole_native_delivery_qualified': False,
              'production_activated': False}
    validate_build(package_raw, report, sources, compiler_raw, cold_raw)
    (output / 'build.json').write_bytes(encoded(report))
    return package
