"""Evidence-only helpers for three fresh, offline NDU fixture builds.

This controller is hosted supply machinery. It does not run qualification,
change its gates, activate an NDU service, or modify the old fixture roots.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import types

ROOT = Path('/home/qian-qi/he26v67fixturesr1')
SOURCE = Path('/home/qian-qi/he26v67r1/s')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
BUILDER_SHA = 'c4702a063f45b8a75973dc2978c38f414d43121dde7968af165c51b43241e6e8'
IDENTITY_SHA = '24d88246cac15b63ec93203cf8789742cd801f7dc12c335aba81becddbbd1a87'
KEY = 'hia-e26e-desktop-v67-608-three-ndu-fixtures-supply-r1'
SCHEMA = 'hia.v67.ndu-fixture-supply.v1'
PROFILES = ('ranking', 'raw', 'dynamic')
FIXED_HELPERS = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def no_duplicates(items):
    result = {}
    for name, value in items:
        require(name not in result, 'duplicate JSON key: ' + name)
        result[name] = value
    return result


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def stable_file(path, expected=None, *, collect=False, executable=False, owned=True,
                resolve=False, max_bytes=None, independent=True):
    requested = Path(path)
    path = requested.resolve(strict=True) if resolve else requested
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
            'ordinary absolute input required: ' + str(path))
    before_path = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    parts = [] if collect else None
    digest, count = sha256(), 0
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and (not independent or before.st_nlink == 1)
                and (not owned or before.st_uid == os.geteuid())
                and (not executable or before.st_mode & stat.S_IXUSR)
                and identity(before) == identity(before_path), 'ordinary input identity differs: ' + str(path))
        require(max_bytes is None or before.st_size <= max_bytes, 'input exceeds explicit bound')
        if collect:
            require(before.st_size <= 8 << 20, 'collected input exceeds 8 MiB control bound')
        for part in iter(lambda: stream.read(1 << 20), b''):
            count += len(part)
            require(count <= before.st_size, 'input grew during read')
            digest.update(part)
            if parts is not None:
                parts.append(part)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                'input changed during read')
    require(identity(before) == identity(path.lstat()), 'input replaced during read')
    if resolve:
        require(requested.resolve(strict=True) == path, 'input symlink resolution changed')
    checksum = digest.hexdigest()
    require(expected is None or checksum == expected, 'input digest differs: ' + str(path))
    return {'path': str(requested), 'resolved': str(path), 'sha256': checksum,
            'bytes': count, 'identity': list(identity(before))}, (b''.join(parts) if parts is not None else None)


def create(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return stable_file(path, sha256(raw).hexdigest())[0]


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_json(path, expected=None):
    pin, raw = stable_file(path, expected, collect=True)
    return json.loads(raw, object_pairs_hook=no_duplicates), pin


def load_exact(name, path, expected):
    _, raw = stable_file(path, expected, collect=True)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def config():
    value, _ = read_json(Path(__file__).parent / 'source-inputs.json')
    require(value['schema'] == 'hia.v67.ndu-fixture-supply-inputs.v1'
            and value['root'] == str(ROOT) and value['source'] == str(SOURCE)
            and value['head'] == HEAD and value['tree'] == TREE
            and value['stable_key'] == KEY and value['builder_sha256'] == BUILDER_SHA
            and set(value['profiles']) == set(PROFILES)
            and len(value['fixed_tools']) == 12 and len(value['old_fixture_receipts']) == 6,
            'frozen supply input configuration differs')
    return value


def environment(cfg, *, target=None):
    # A whitelist, not a dump of the ambient environment or credentials.
    rust_bin = str(Path(cfg['tools']['cargo']).parent)
    result = {
        'HOME': '/home/qian-qi', 'PATH': rust_bin + ':/usr/bin:/bin',
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1', 'PYTHONNOUSERSITE': '1',
        'TMPDIR': str(ROOT / 't'), 'TMP': str(ROOT / 't'), 'TEMP': str(ROOT / 't'),
        'CARGO_HOME': cfg['cargo_home'], 'CARGO_NET_OFFLINE': 'true',
        'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0', 'CARGO_PROFILE_DEV_DEBUG': '0',
        'RUSTC': cfg['tools']['rustc'], 'GIT_OPTIONAL_LOCKS': '0',
        'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '1',
        'GIT_CONFIG_KEY_0': 'protocol.allow', 'GIT_CONFIG_VALUE_0': 'never',
    }
    if target is not None:
        result['CARGO_TARGET_DIR'] = str(target)
    return result


def source_state():
    module = load_exact('exact_608_source_identity', SOURCE / 'tools/hia_core_source_identity.py', IDENTITY_SHA)
    value = module._source_state()
    require(value.get('head') == HEAD and value.get('tree') == TREE
            and value.get('status') == '' and len(value.get('files', {})) == 3925,
            'complete exact 608 source custody differs')
    return value


def pinned_inputs(cfg):
    tools = []
    for pin in [{'path': str(PYTHON), 'sha256': PYTHON_SHA}, *cfg['fixed_tools']]:
        tools.append(stable_file(pin['path'], pin['sha256'], executable=True, resolve=True,
                                 independent=False)[0])
    old = {name: stable_file(name, digest)[0] for name, digest in cfg['old_inputs'].items()}
    old_receipts = {p['profile']: stable_file(p['path'], p['sha256'])[0]
                    for p in cfg['old_fixture_receipts']}
    manifest, manifest_pin = read_json(cfg['cache_manifest']['path'], cfg['cache_manifest']['sha256'])
    require(set(manifest) == {'archives', 'offline_full_regression_not_yet_executed', 'path', 'schema'}
            and manifest['schema'] == 'hia.private-cargo-cache-observation.v1'
            and manifest['path'] == cfg['cargo_home']
            and manifest['offline_full_regression_not_yet_executed'] is True
            and type(manifest['archives']) is dict and len(manifest['archives']) == 55,
            'original actual 55-archive manifest grammar differs')
    cache = Path(cfg['cargo_home'])
    require(cache.resolve(strict=True) == cache
            and not any(p.is_symlink() for p in (cache, *cache.parents)), 'private cache has a symlink')
    item = cache.lstat()
    require(stat.S_ISDIR(item.st_mode) and item.st_uid == os.geteuid()
            and not stat.S_IMODE(item.st_mode) & 0o022, 'private cache owner/mode differs')
    archives = {}
    for name, digest in sorted(manifest['archives'].items()):
        path = Path(name)
        require(path.is_relative_to(cache / 'registry/cache') and path.suffix == '.crate',
                'crate path is outside original private archive root')
        archives[name] = stable_file(path, digest, max_bytes=1 << 30)[0]
    missing_targets = {}
    for profile in PROFILES:
        path = Path(cfg['prerequisite_root']) / 'targets' / profile
        require(not os.path.lexists(path), 'old missing target unexpectedly changed: ' + str(path))
        missing_targets[str(path)] = 'ABSENT_OBSERVED_NO_MUTATION'
    return {'tools': tools, 'old_inputs': old, 'old_fixture_receipts': old_receipts,
            'cache_manifest': manifest_pin, 'crate_archives': archives,
            'old_missing_targets': missing_targets,
            'cache_scope': '55 fixed archive bytes only; Cargo locks/index/cache metadata may change'}


def upstream_state(cfg):
    upstream = Path(cfg['upstream'])
    require(upstream.resolve(strict=True) == upstream, 'upstream symlink refused')
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', *args],
                                       cwd=upstream, timeout=30)
    result = {'path': str(upstream), 'head_tree': git('rev-parse', 'HEAD', 'HEAD^{tree}').decode(),
              'status': git('status', '--porcelain=v1', '--untracked-files=all').decode(), 'commits': {}}
    for profile in PROFILES:
        pin = cfg['profiles'][profile]
        commit = pin['upstream_commit']
        require(git('rev-parse', commit + '^{commit}').decode().strip() == commit,
                'upstream pinned commit differs')
        raw = git('ls-tree', '-r', '-z', commit, 'codex-rs/hepta-ndu', 'codex-rs/hepta-contracts',
                  'codex-rs/hepta-types', 'codex-rs/Cargo.toml')
        result['commits'][commit] = {'tree_inventory_sha256': sha256(raw).hexdigest(),
                                    'tree_inventory_bytes': len(raw)}
    return result


def natural_guardian(value):
    life = value.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events', [])
    return (value.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and value.get('input_identity_preserved') is True
            and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0 and life.get('timed_out') is False
            and life.get('exit_observed_before_deadline') is True
            and life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and not life.get('interrupted_signals') and not life.get('owner_error')
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False
            and cleanup.get('errors') == [] and isinstance(events, list) and bool(events)
            and all(event.get('kind') in {'qualification_started', 'owned_child_observed',
                        'qualification_exit_observed', 'owned_child_reaped'} for event in events))


def validate_receipt(cfg, profile, receipt):
    pin = cfg['profiles'][profile]
    directory = ROOT / 'fixtures' / profile
    binary = ROOT / 'targets' / profile / ('release' if pin['release'] else 'debug') / 'hia-ndu-bridge'
    require(receipt.get('schema') == 'hepta.hia.ndu-build.v1'
            and receipt.get('builder_sha256') == BUILDER_SHA
            and receipt.get('binary') == str(binary)
            and receipt.get('cargo_lock_sha256') == pin['cargo_lock_sha256']
            and receipt.get('upstream', {}).get('commit') == pin['upstream_commit']
            and receipt.get('production_activation') is False,
            'fresh builder receipt identity differs: ' + profile)
    for field in ('original_rust_sources_unchanged', 'all_original_non_manifest_inputs_unchanged',
                  'build_inputs_unchanged', 'locked_dependencies', 'isolated_production_manifests'):
        require(receipt.get(field) is True, 'fresh build did not preserve ' + field)
    require(receipt.get('build_cost', {}).get('completed') is True
            and receipt['build_cost'].get('target_cache_at_start') == 'absent'
            and receipt.get('build_command_evidence', {}).get('returncode') == 0
            and receipt['build_command_evidence'].get('launch_error') is None,
            'fresh target build did not complete')
    expected_command = [cfg['tools']['cargo'], 'build', '--manifest-path', str(directory / 'Cargo.toml'),
                        '-p', 'hia-ndu-bridge', '--locked'] + (['--release'] if pin['release'] else [])
    require(receipt.get('build_command') == expected_command, 'original Cargo command differs')
    old, _ = read_json(pin['old_receipt'], pin['old_receipt_sha256'])
    require(receipt.get('original_source_files') == old.get('original_source_files')
            and receipt.get('adapter_files') == pin['adapter_files'], 'actual upstream or adapter input differs')
    for name, expected in receipt['build_inputs'].items():
        path = Path(name)
        require(not path.is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
                'unsafe builder input receipt path')
        stable_file(directory / path, expected)
    stable_file(binary, receipt['binary_sha256'], executable=True, independent=False)
    for stream in ('stdout', 'stderr'):
        observed = receipt['build_command_evidence'][stream]
        stable_file(directory / observed['path'], observed['sha256'])
    stable_file(directory / 'command-evidence/cargo.json')
    return {'receipt': str(directory / 'build-receipt.json'),
            'receipt_sha256': stable_file(directory / 'build-receipt.json')[0]['sha256'],
            'binary': str(binary), 'binary_sha256': receipt['binary_sha256'],
            'cargo_lock_sha256': receipt['cargo_lock_sha256'], 'builder_sha256': BUILDER_SHA,
            'upstream_commit': pin['upstream_commit'], 'build_cost': receipt['build_cost']}
