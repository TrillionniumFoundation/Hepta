"""Admit a freshly prepared, source-bound full-regression environment.

This is hosted qualification control code. It does not create fixtures, modify
system tools, install packages, or turn historical observations into test PASS.
The preparation program and this module run beneath the external guardian.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat


REQUIRED_CHECKS = (
    'python', 'clang', 'clangxx', 'lld', 'lean', 'qemu_aarch64',
    'ndu_ranking', 'ndu_raw', 'ndu_dynamic',
    'ndu_recursive', 'ndu_finite', 'ndu_stream',
)
REQUIRED_INPUTS = (
    'CLANG', 'CLANGXX', 'HEPTA_CLANG', 'HIA_TEST_CLANG20',
    'HEPTA_QEMU_AARCH64', 'HEPTA_LLD', 'LEAN',
    'HEPTA_NDU_BRIDGE', 'HEPTA_NDU_BUILD', 'HEPTA_NDU_UPSTREAM',
    'HEPTA_RAW_MODEL_BRIDGE', 'HEPTA_RAW_MODEL_BUILD',
    'HEPTA_DYNAMIC_POLICY_BINARY', 'HEPTA_DYNAMIC_POLICY_MANIFEST',
    'HEPTA_RECURSIVE_NDU_BRIDGE', 'HEPTA_RECURSIVE_NDU_IDENTITY',
    'HEPTA_RECURSIVE_NDU_UPSTREAM',
    'HEPTA_FINITE_NDU_BRIDGE', 'HEPTA_FINITE_NDU_IDENTITY',
    'HEPTA_FINITE_NDU_UPSTREAM',
    'HEPTA_NDU_STREAM_BRIDGE', 'HEPTA_NDU_STREAM_IDENTITY',
    'HEPTA_NDU_STREAM_UPSTREAM',
)
FRESH_OUTPUTS = (
    'CARGO_TARGET_DIR', 'HEPTA_RAW_MODEL_TRANSCRIPT',
    'HEPTA_STB_UPDATE_TEST_EVIDENCE',
    'HEPTA_RUST_SCOPED_CLEANUP_EVIDENCE_DIR',
    'HEPTA_RUST_FINITE_HEAP_EVIDENCE_DIR',
    'HEPTA_BORROWED_EXTENT_EVIDENCE_DIR',
    'HEPTA_FINITE_V8_EVIDENCE_DIR',
    'HEPTA_FILECHECK_TARGET_EVIDENCE',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    requested = Path(path).absolute()
    resolved = requested.resolve(strict=True)
    result = sha256()
    with resolved.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 1 << 30,
                'prerequisite is not a bounded regular file: ' + str(path))
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
        after = os.fstat(stream.fileno())
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(fields(before) == fields(after) and requested.resolve(strict=True) == resolved,
            'prerequisite changed while reading: ' + str(path))
    return result.hexdigest()


def json_file(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= 4 << 20, 'preparation JSON exceeds its bound')
    value = json.loads(raw)
    require(type(value) is dict, 'preparation JSON must be an object')
    return value, {'path': str(Path(path).resolve()), 'sha256': sha256(raw).hexdigest()}


def source_literal(path, name):
    for node in ast.parse(Path(path).read_text()).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('source tool pin is missing: ' + name)


def filesystem_record(path):
    target = Path(path).resolve()
    observed = target
    while not observed.exists():
        require(observed != observed.parent, 'no existing filesystem ancestor')
        observed = observed.parent
    info = observed.stat()
    capacity = os.statvfs(observed)
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields, tail = left.split(), right.split()
        mount = Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4]))
        if target == mount or target.is_relative_to(mount):
            mounts.append((len(mount.parts), mount, tail[0], fields[5].split(',')))
    require(bool(mounts), 'filesystem mount identity is unavailable')
    _, mount, kind, options = max(mounts, key=lambda row: row[0])
    return {'path': str(target), 'observed_ancestor': str(observed),
            'device': info.st_dev, 'mount': str(mount), 'filesystem': kind,
            'noexec': 'noexec' in options, 'readonly': 'ro' in options,
            'free_bytes': capacity.f_bavail * capacity.f_frsize,
            'free_inodes': capacity.f_favail,
            'volatile': kind in ('tmpfs', 'ramfs')}


def admit(source, environment_path, preparation_path, executable, inherited, output):
    source = Path(source).resolve(strict=True)
    environment_path = Path(environment_path).resolve(strict=True)
    preparation_path = Path(preparation_path).resolve(strict=True)
    preparation_root = environment_path.parent
    require(preparation_path.parent == preparation_root
            and not preparation_root.is_relative_to(source),
            'preparation files must be adjacent and outside the source checkout')
    environment, environment_record = json_file(environment_path)
    preparation, preparation_record = json_file(preparation_path)
    require(environment.get('schema') == 'hepta.hia.qualification-environment.v2'
            and preparation.get('schema') == 'hepta.hia.remote-qualification-preparation.v2',
            'unexpected freshly prepared prerequisite schemas')
    require(environment.get('source') == str(source)
            and preparation.get('source') == str(source),
            'prerequisites were prepared for another source checkout')
    require(preparation.get('status') == 'READY'
            and preparation.get('missing') == []
            and preparation.get('qualification_executed') is False,
            'current preparation is incomplete; no historical READY substitution')
    require(Path(preparation.get('environment_file', '')).resolve() == environment_path,
            'preparation report names another environment')
    require(environment.get('python') == str(Path(executable).absolute())
            and preparation.get('python') == environment.get('python'),
            'full regression must execute in the actually prepared venv')

    settings = environment.get('set')
    bindings = environment.get('recheck_sha256')
    require(type(settings) is dict and all(
        type(k) is str and type(v) is str and '\0' not in k + v
        for k, v in settings.items()), 'invalid explicit prerequisite environment')
    require(type(bindings) is dict and 0 < len(bindings) <= 20000,
            'nonempty bound prerequisite inventory required')
    checks = preparation.get('checks', {})
    require(type(checks) is dict and all(
        type(checks.get(name)) is dict and checks[name].get('available') is True
        for name in REQUIRED_CHECKS), 'all tool and six NDU profiles must be available')
    require(checks.get('ptrace', {}).get('returncode') == 0
            and checks.get('sealed_memfd', {}).get('returncode') == 0,
            'actual tracing and sealed-image prerequisites were not observed')
    require(settings.get('HEPTA_RUN_ARTIFACT_SESSION') == '1',
            'actual artifact-session regressions must be enabled')
    for name in REQUIRED_INPUTS:
        require(type(settings.get(name)) is str and Path(settings[name]).is_absolute()
                and Path(settings[name]).exists(),
                'missing named full-regression prerequisite: ' + name)
    for name in ('CLANG', 'HEPTA_CLANG', 'HIA_TEST_CLANG20'):
        require(settings[name] == checks['clang']['path'],
                'Clang selectors do not select the same reviewed compiler')
    require(settings['HEPTA_LLD'] == checks['lld']['path']
            and settings['HEPTA_QEMU_AARCH64'] == checks['qemu_aarch64']['path']
            and settings['LEAN'] == checks['lean']['path'],
            'selected tool paths differ from their actual preparation probes')
    require(digest(settings['HEPTA_QEMU_AARCH64']) == source_literal(
        source / 'hepta/hia_program_aarch64.py', 'QEMU_SHA256'),
        "QEMU differs from this candidate's reviewed executable")
    lean_lock, _ = json_file(source / 'formal/toolchain-lock.json')
    require(digest(settings['LEAN']) == lean_lock['lean_binary_sha256'],
            "Lean differs from this candidate's proof checker pin")
    for name, value in bindings.items():
        require(type(name) is str and Path(name).is_absolute()
                and type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
                'invalid bound prerequisite file')
        require(digest(name) == value, 'prepared prerequisite bytes changed: ' + name)
    required_source = [source / 'tools/build_hia_ndu_bridge.py',
                       source / 'formal/toolchain-lock.json']
    for adapter in ('hia-ndu-bridge', 'hia-ndu-raw-model', 'hia-ndu-dynamic-model'):
        required_source.extend(p for p in (source / 'rust' / adapter).rglob('*') if p.is_file())
    require(all(str(path) in bindings for path in required_source),
            'current candidate adapter, builder and tool-pin sources are not bound')
    require(all(settings[name] in bindings for name in (
        'CLANG', 'HEPTA_LLD', 'HEPTA_QEMU_AARCH64', 'LEAN',
        'HEPTA_NDU_BRIDGE', 'HEPTA_RAW_MODEL_BRIDGE', 'HEPTA_RAW_MODEL_BUILD',
        'HEPTA_DYNAMIC_POLICY_BINARY', 'HEPTA_DYNAMIC_POLICY_MANIFEST',
        'HEPTA_RECURSIVE_NDU_BRIDGE', 'HEPTA_RECURSIVE_NDU_IDENTITY',
        'HEPTA_FINITE_NDU_BRIDGE', 'HEPTA_FINITE_NDU_IDENTITY',
        'HEPTA_NDU_STREAM_BRIDGE', 'HEPTA_NDU_STREAM_IDENTITY')),
        'selected tool or fixture input is not bound to its fresh observation')

    temporary = environment.get('temporary_directory', {})
    path = Path(temporary.get('path', ''))
    require(path.is_absolute() and path.is_dir()
            and temporary.get('no_git_or_symlink_ancestors') is True
            and temporary.get('actual_AF_UNIX_round_trip') is True,
            'fresh private short temporary directory required')
    require(not any(p.is_symlink() or (p / '.git').exists()
                    or (p / '.git').is_symlink() for p in (path, *path.parents)),
            'temporary directory gained a symlink or Git ancestor')
    current = path.stat()
    require(temporary.get('identity') == {
        'device': current.st_dev, 'inode': current.st_ino,
        'uid': current.st_uid, 'mode': current.st_mode},
        'temporary directory identity changed after preparation')
    require(current.st_uid == os.geteuid() and stat.S_IMODE(current.st_mode) == 0o700
            and len(os.fsencode(path)) <= 40,
            'temporary directory no longer satisfies the private short-path contract')
    require(all(settings.get(name) == str(path) for name in ('TMPDIR', 'TMP', 'TEMP')),
            'temporary selectors do not name the freshly observed directory')
    for name in FRESH_OUTPUTS:
        require(type(settings.get(name)) is str
                and Path(settings[name]).resolve().is_relative_to(preparation_root),
                'test output could append to an old or foreign run: ' + name)
    for name in ('output', 'temporary'):
        observed = preparation.get('storage', {}).get(name, {})
        require(type(observed.get('free_bytes')) is int
                and observed['free_bytes'] >= 8 << 30
                and type(observed.get('free_inodes')) is int
                and observed['free_inodes'] >= 100000,
                'existing preparation storage gate was not satisfied')
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    filesystems = {name: filesystem_record(value) for name, value in (
        ('operator_home', home), ('source', source),
        ('preparation', preparation_root), ('qualification_output', output),
        ('test_temporary', path), ('cargo_cache', settings['CARGO_TARGET_DIR']))}
    # Ordinary persistence, SQLite, journal and installer tests share TMPDIR.
    # They therefore require the ordinary home device, never a tmpfs or an old
    # task's loop mount. No tmpfs fsync observation is reported as disk durability.
    ordinary = filesystems['operator_home']
    require(ordinary['filesystem'] == 'ext4' and not ordinary['volatile'],
            'this ROG qualification requires the ordinary ext4 home filesystem')
    for name in ('qualification_output', 'test_temporary'):
        observed = filesystems[name]
        require(observed['device'] == ordinary['device']
                and observed['filesystem'] == ordinary['filesystem']
                and not observed['noexec'] and not observed['readonly'],
                'persistent-state tests and raw reports must use the ordinary home device')

    discard = environment.get('unset')
    prefixes = environment.get('unset_prefixes')
    require(type(discard) is list and all(type(k) is str for k in discard)
            and type(prefixes) is list and 'HEPTA_HIA_' in prefixes
            and all(type(k) is str for k in prefixes),
            'explicit prepared-environment removal rules required')
    configured = {key: value for key, value in inherited.items()
                  if key not in discard and not key.startswith(tuple(prefixes))}
    configured.update(settings)
    configured['PYTHONNOUSERSITE'] = '1'
    require(not any(key.startswith('HEPTA_HIA_') for key in settings),
            'preparation must not inject a product or development selector')
    aliases = preparation_root / 'bin'
    require(configured.get('PATH', '').split(os.pathsep)[0] == str(aliases),
            'private explicit tool aliases must precede ambient tool discovery')
    alias_bindings = {}
    for name, check in (('clang', 'clang'), ('clang++', 'clangxx'),
                        ('ld.lld', 'lld'), ('cargo', 'cargo'),
                        ('rustc', 'rustc'), ('lean', 'lean')):
        alias = aliases / name
        require(alias.is_symlink() and alias.resolve(strict=True)
                == Path(checks[check]['path']).resolve(strict=True),
                'private executable alias differs: ' + name)
        alias_bindings[str(alias)] = digest(alias)
    receipt = {
        'schema': 'hia.full-regression-prerequisite-admission.v1',
        'status': 'CURRENT_SOURCE_PREREQUISITES_ADMITTED_NOT_TEST_PASS',
        'environment': environment_record, 'preparation': preparation_record,
        'source': str(source), 'python': environment['python'],
        'required_checks': list(REQUIRED_CHECKS),
        'selected_inputs': {name: settings[name] for name in REQUIRED_INPUTS},
        'actual_artifact_sessions_enabled': True,
        'temporary_directory': temporary,
        'filesystem_observation': filesystems,
        'state_and_fault_tests_use_ordinary_home_device': True,
        'tmpfs_fsync_is_disk_durability_evidence': False,
        'bound_files': bindings, 'alias_bindings': alias_bindings,
        'existing_storage_gate_preserved': True,
        'test_or_whole_native_pass_claimed': False,
    }
    return configured, receipt


def recheck(receipt):
    require(receipt.get('status') == 'CURRENT_SOURCE_PREREQUISITES_ADMITTED_NOT_TEST_PASS',
            'no prior admitted prerequisite observation')
    for kind in ('environment', 'preparation'):
        row = receipt[kind]
        require(digest(row['path']) == row['sha256'], kind + ' changed during qualification')
    for group in ('bound_files', 'alias_bindings'):
        for path, expected in receipt[group].items():
            require(digest(path) == expected, 'prerequisite changed during qualification: ' + path)
    return {'status': 'PREREQUISITE_IDENTITIES_PRESERVED',
            'bound_files_checked': len(receipt['bound_files']),
            'aliases_checked': len(receipt['alias_bindings'])}
