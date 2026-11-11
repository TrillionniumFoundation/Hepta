"""Consume an exact source package, observe prerequisites, then exec v9 --full.

Hosted qualification control only. The unmodified external guardian owns this
process from its first archive read through exec of the original launcher and
v9 runner. This module never downloads, retries a job, installs dependencies,
modifies an old checkout, changes a product gate, or claims whole-native release.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import types
import zipfile

import workflow_process


ROOT = Path('/home/qian-qi/he26stackv9r1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA256 = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
SOURCE_PIN = {
    "cold_source_count": 780,
    "commit": "acffa9262f31d073f8f0a6f0201eae201039f619",
    "contract_bytes": 170736,
    "contract_sha256": "745f466a9f695d698ec5d6004e781183924cc7590153f85a911004fa2dd9e074",
    "coverage_bytes": 176633,
    "coverage_sha256": "806c0ab57e62cc50c440d2d55812625638ce135bacdc5655578dd5ef48d55f0d",
    "declared_source_count": 779,
    "leaf_count": 4023,
    "profile": "selfhost-core-linux-x86_64-v74-native-stack-development",
    "tree": "22a095436c94efc87b1a89aca912c8caab2eed80"
}
CONTRACT = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
COVERAGE = 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'
SOURCE_PACKAGE_PATH = 'experiments/hia_git_source_package_20261111/source_package.py'
RUNNER_PREFIX = 'experiments/hia_native_successor_runner_20261111/'
PACKAGE_FILES = frozenset(('source.pack', 'manifest.json', 'source-package.py',
                          'export-report.json', 'source-state-before.json',
                          'source-state-after.json'))
EXPORT_RECEIPTS = frozenset(('IDENTITY.json', 'reconstruction.json'))
DEPENDENCIES = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
    'qualification_prerequisites.py': '352e537de1ca6962d6d8bafa6ac9dea61c83f0d30c5d9c75bce50088fefadead',
    'run_hia_qualification_v9.py': 'd27763b58297a70363250e38d564ee603aac9f7304c710a559bc37057817c8d0',
    'native_owner_gates.py': 'a2d2a8f1ffcdf9032efc98f774f2f4e23bc94aaceb56f95a359b7d4442a1eb30',
    'source-package.py': 'af243e692ee5b6e9289f6226a0269ae40b02e1b460521471e199dfb8981dca5a',
    'prepare_remote_qualification_v2.py': '972dffc85f53093aa8d06f53a1a2154dc1731e7ad93c0ca39c93f0b03a91ffbc',
    'prepare_v67_cargo_environment.py': 'afb64c7dce8354f656ea151a7b8495bd4374ea929d6dfe41282598b6f2ce2c82',
}
LIMITS = {
    'controller_seconds': 10800, 'source_materialization_seconds': 900,
    'preparation_seconds': 900, 'cold_seconds': 180, 'cold_workers': 2,
    'cold_phases': 38, 'full_suite_seconds': 5400,
    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
}
REQUIRED_PREPARATION_CHECKS = (
    'python', 'clang', 'clangxx', 'lld', 'objdump', 'profdata', 'readobj',
    'gcc', 'qemu_x86_64', 'qemu_riscv64', 'qemu_aarch64', 'rustc', 'cargo',
    'lean', 'strace', 'boost', 'ndu_ranking', 'ndu_raw', 'ndu_dynamic',
    'ndu_recursive', 'ndu_finite', 'ndu_stream',
)
ORIGINAL_TOOL_KEYS = {
    'clang': 'clang', 'clangxx': 'clang++', 'lld': 'ld.lld',
    'objdump': 'llvm-objdump', 'profdata': 'llvm-profdata', 'readobj': 'llvm-readobj',
    'qemu_x86_64': 'qemu-x86_64-static', 'qemu_riscv64': 'qemu-riscv64-static',
    'qemu_aarch64': 'qemu-aarch64-static', 'rustc': 'rustc', 'cargo': 'cargo', 'lean': 'lean',
}
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
SUPPLY_ROOT = Path('/home/qian-qi/he26v67fixturesr1')
SUPPLY_KEY = 'hia-e26e-desktop-v67-608-three-ndu-fixtures-supply-r1'
SUPPLY_REQUEST_SHA256 = '9384034cc1b5ab24c382049fef3f404e4c57ec4aca81063ab670dc5039b688e8'
SUPPLY_CONTROL_FILES = {
    'bootstrap.py': 'caff48a0f36499aebcd68455fba147cd17a2ee29ba78b7080ddae013419445ea',
    'common.py': '850e8da5adcae0b0835719c37deacbc64833f453caf19574b997833530c7170a',
    'driver.py': '33ea7d7922d0522d9ba670b542b6e07304acd676512b7490b8284cae24807c76',
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'producer.py': 'e7ff8586c2c06d05cf579029bab905c35a437c1c5ae3136a2ad7734e3f47e452',
    'source-inputs.json': 'dbc760cb306f9cca40c7240fcb0782fcfed3e6335ac9309402fbcfe45fa3497e',
    'verify_terminal.py': 'f7a4ee8b896844a57e5699adc6d11276a59d059188b30c848c64aa3a71b7c4bd',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
}
SUPPLY_PROFILES = {
    'ranking': ('debug', '912c2f5520311284a89e452670415404523b8a5ffa18246f2ec3e2e727a0cf37',
                'd3c2d760eca5065fc966820379c35c6e8d56e855'),
    'raw': ('release', '46186790dd9ba0607ac4b3125cb21fefedc0256e24256e7220dff2c828c1c3df',
            '8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'),
    'dynamic': ('release', '46186790dd9ba0607ac4b3125cb21fefedc0256e24256e7220dff2c828c1c3df',
                '8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'),
}
SUPPLY_BUILDER_SHA256 = 'c4702a063f45b8a75973dc2978c38f414d43121dde7968af165c51b43241e6e8'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON member: ' + key)
        result[key] = value
    return result


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def stable_file(path, expected=None, *, collect=False, owned=True):
    """Read/hash actual regular bytes, with no final symlink and stable binding."""
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    chunks = [] if collect else None
    digest = sha256()
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'ordinary input required: ' + str(path))
        require(not owned or (before.st_uid == os.geteuid() and before.st_nlink == 1),
                'owned independent input required: ' + str(path))
        if collect:
            require(before.st_size <= 16 << 20, 'control JSON/source exceeds 16 MiB')
        count = 0
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            count += len(chunk)
            require(count <= before.st_size, 'input grew while reading: ' + str(path))
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        require(count == before.st_size
                and identity(before) == identity(os.fstat(stream.fileno())),
                'input changed while reading: ' + str(path))
    require(identity(before) == identity(path.lstat()), 'input binding changed: ' + str(path))
    result = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
              'identity': list(identity(before))}
    require(expected is None or result['sha256'] == expected, 'input SHA differs: ' + str(path))
    return result, b''.join(chunks) if chunks is not None else None


def read_json(path, expected=None):
    record, raw = stable_file(path, expected, collect=True)
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(type(value) is dict, 'JSON object required: ' + str(path))
    return value, record


def private_directory(path):
    path = Path(path)
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            'symlink directory ancestor refused: ' + str(path))
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            'owned 0700 directory required: ' + str(path))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create(path, raw, mode=0o400):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    row, actual = stable_file(path, sha256(raw).hexdigest(), collect=True)
    require(actual == raw, 'create-only readback differs: ' + str(path))
    return row


def validate_fixture_supply_pins(request):
    """External frozen receipt pins, never values inferred from an unverified report."""
    spec = request.get('fixture_supply')
    require(type(spec) is dict and spec.get('schema') == 'hia.v67.full-qualification-fixture-supply-pins.v1'
            and spec.get('root') == str(SUPPLY_ROOT) and spec.get('stable_key') == SUPPLY_KEY
            and spec.get('head') == '608157e52b0b94e0d294f6b99c4e809869f183aa'
            and spec.get('tree') == 'e7c29a60796a1a78946a2c667aa80df86529e532'
            and spec.get('builder_sha256') == SUPPLY_BUILDER_SHA256,
            'three-fixture supply has not been externally pinned')
    readonly = request['readonly_inputs']
    for name, digest in SUPPLY_CONTROL_FILES.items():
        require(readonly.get(str(SUPPLY_ROOT / 'control' / name)) == digest,
                'reviewed supply controller is not an immutable formal input: ' + name)
    require(readonly.get(str(SUPPLY_ROOT / 'control/request.json')) == SUPPLY_REQUEST_SHA256,
            'actual supply request is not an immutable formal input')
    for field, path in (('report', SUPPLY_ROOT / 'report.json'),
                        ('outer_guardian', SUPPLY_ROOT / 'guard/guardian.json')):
        row = spec.get(field, {})
        require(type(row) is dict and set(row) == {'path', 'sha256', 'bytes'}
                and row['path'] == str(path) and type(row['bytes']) is int and row['bytes'] > 0
                and type(row['sha256']) is str and HEX64.fullmatch(row['sha256'])
                and readonly.get(str(path)) == row['sha256'],
                'actual complete supply record is not externally pinned: ' + field)
    fixtures = spec.get('fixtures')
    require(type(fixtures) is dict and set(fixtures) == set(SUPPLY_PROFILES),
            'exactly the three newly supplied fixtures are required')
    for profile, (mode, lock, upstream) in SUPPLY_PROFILES.items():
        row = fixtures[profile]
        require(type(row) is dict and set(row) == {'receipt', 'receipt_sha256', 'binary',
                    'binary_sha256', 'cargo_lock_sha256', 'builder_sha256', 'upstream_commit'}
                and row['receipt'] == str(SUPPLY_ROOT / 'fixtures' / profile / 'build-receipt.json')
                and row['binary'] == str(SUPPLY_ROOT / 'targets' / profile / mode / 'hia-ndu-bridge')
                and row['cargo_lock_sha256'] == lock and row['upstream_commit'] == upstream
                and row['builder_sha256'] == SUPPLY_BUILDER_SHA256
                and all(type(row[key]) is str and HEX64.fullmatch(row[key])
                        for key in ('receipt_sha256', 'binary_sha256'))
                and readonly.get(row['receipt']) == row['receipt_sha256'],
                'actual fresh receipt/binary binding differs: ' + profile)
    return spec


def verify_fixture_supply(request):
    """Reuse the immutable supplier's exact read-only verifier inside this owner.

    No process or effect is launched. The held source bytes are compiled in
    private modules; only the verifier's explicit adjacent common import is
    temporarily bound, then restored even if its original verification raises.
    This preserves the supplier's actual binary/link and natural-reap checks.
    """
    spec = validate_fixture_supply_pins(request)
    controls = {}
    source_bytes = {}
    for name, digest in SUPPLY_CONTROL_FILES.items():
        collect = name in ('common.py', 'verify_terminal.py')
        controls[name], raw = stable_file(SUPPLY_ROOT / 'control' / name, digest, collect=collect)
        if collect:
            source_bytes[name] = raw
    read_json(SUPPLY_ROOT / 'control/request.json', SUPPLY_REQUEST_SHA256)
    for field in ('report', 'outer_guardian'):
        pin = spec[field]
        _, observed = read_json(pin['path'], pin['sha256'])
        require(observed['bytes'] == pin['bytes'], 'supply record size differs: ' + field)
    common = types.ModuleType('_fixed_v67_supply_common')
    common.__file__ = str(SUPPLY_ROOT / 'control/common.py')
    exec(compile(source_bytes['common.py'], common.__file__, 'exec'), common.__dict__)
    verifier = types.ModuleType('_fixed_v67_supply_verifier')
    verifier.__file__ = str(SUPPLY_ROOT / 'control/verify_terminal.py')
    absent = object()
    previous = sys.modules.get('common', absent)
    try:
        sys.modules['common'] = common
        exec(compile(source_bytes['verify_terminal.py'], verifier.__file__, 'exec'), verifier.__dict__)
    finally:
        if previous is absent:
            sys.modules.pop('common', None)
        else:
            sys.modules['common'] = previous
    observed = verifier.verify()
    require(observed.get('schema') == 'hia.v67.ndu-fixture-supply-acceptance.v1'
            and observed.get('status') == 'THREE_FIXTURES_READY_NOT_TEST_PASS'
            and observed.get('head') == spec['head'] and observed.get('tree') == spec['tree']
            and observed.get('root') == str(SUPPLY_ROOT) and observed.get('stable_key') == SUPPLY_KEY
            and observed.get('builder_sha256') == SUPPLY_BUILDER_SHA256
            and observed.get('qualification_executed') is False
            and observed.get('whole_native_delivery_qualified') is False
            and observed.get('old_formal_hold_preserved') is True,
            'original supply terminal verifier did not admit these exact fixtures')
    for field in ('report', 'outer_guardian'):
        require(all(observed[field].get(key) == value for key, value in spec[field].items()),
                'original verifier consumed a different supply record: ' + field)
    require(set(observed.get('fixtures', {})) == set(SUPPLY_PROFILES), 'actual fixture population differs')
    for profile, expected in spec['fixtures'].items():
        require(all(observed['fixtures'][profile].get(key) == value for key, value in expected.items()),
                'actual supply verifier receipt/binary differs from external pins: ' + profile)
    for name, digest in SUPPLY_CONTROL_FILES.items():
        require(stable_file(SUPPLY_ROOT / 'control' / name, digest)[0] == controls[name],
                'supply controller changed during read-only verification: ' + name)
    return dict(observed, immutable_verifier_source_sha256=SUPPLY_CONTROL_FILES['verify_terminal.py'],
                immutable_common_source_sha256=SUPPLY_CONTROL_FILES['common.py'],
                read_only_reverification_not_a_build_or_test=True)


def validate_request(value):
    require(value.get('schema') == 'hia.stack-v9.full-qualification-launch.v1'
            and value.get('frozen') is True and not value.get('pending'),
            'final external launch pins have not been frozen')
    require(value.get('host') == 'desktop' and value.get('root') == str(ROOT),
            'new v9 private desktop root differs')
    require(value.get('scope') == 'FULL_RETAINED_QUALIFICATION_OF_EXACT_SOURCE_NOT_WHOLE_NATIVE_DELIVERY',
            'qualification scope differs')
    require(value.get('limits') == LIMITS, 'existing deadlines, resources or denominator changed')
    source = value.get('source', {})
    require(source == SOURCE_PIN, 'exact new source pin differs')
    for name in ('commit', 'tree'):
        require(type(source.get(name)) is str and HEX40.fullmatch(source[name]), 'full source pin required: ' + name)
    for name in ('contract_sha256', 'coverage_sha256'):
        require(type(source.get(name)) is str and HEX64.fullmatch(source[name]), 'source digest required: ' + name)
    require(type(source.get('profile')) is str and source['profile']
            and source.get('declared_source_count') == 779
            and source.get('cold_source_count') == 780
            and source.get('leaf_count') == 4023
            and source.get('contract_bytes') == 170736
            and source.get('coverage_bytes') == 176633, 'frozen source population differs')
    require(value.get('stable_key') == 'hia-e26e-desktop-v9-' + source['commit'][:8] + '-full-qualification-r1',
            'stable new-operation key differs')
    artifact = value.get('artifact', {})
    require(type(artifact.get('workflow_run_id')) is int and artifact['workflow_run_id'] > 0
            and type(artifact.get('artifact_id')) is int and artifact['artifact_id'] > 0
            and type(artifact.get('run_attempt')) is int and artifact['run_attempt'] > 0,
            'original official workflow/artifact identity required')
    require(type(artifact.get('archive_path')) is str and Path(artifact['archive_path']).is_absolute()
            and not Path(artifact['archive_path']).is_relative_to(ROOT),
            'verified original archive must be outside new qualification root')
    require(type(artifact.get('archive_bytes')) is int and artifact['archive_bytes'] > 0,
            'verified original archive size required')
    for name in ('archive_sha256', 'manifest_sha256'):
        require(type(artifact.get(name)) is str and HEX64.fullmatch(artifact[name]), 'external artifact digest required: ' + name)
    require(artifact.get('member_prefix') == 'package/', 'official source package member prefix differs')
    files = artifact.get('package_files')
    require(type(files) is dict and set(files) == PACKAGE_FILES, 'all six externally verified package files required')
    for name, row in files.items():
        require(type(row) is dict and set(row) == {'bytes', 'sha256'}
                and type(row['bytes']) is int and row['bytes'] > 0
                and type(row['sha256']) is str and HEX64.fullmatch(row['sha256']),
                'invalid external package file pin: ' + name)
    receipts = artifact.get('receipt_files')
    require(type(receipts) is dict and set(receipts) == EXPORT_RECEIPTS,
            'both externally verified Actions export/reconstruction receipts required')
    for name, row in receipts.items():
        require(type(row) is dict and set(row) == {'bytes', 'sha256'}
                and type(row['bytes']) is int and row['bytes'] > 0
                and type(row['sha256']) is str and HEX64.fullmatch(row['sha256']),
                'invalid external export receipt pin: ' + name)
    require(files['manifest.json']['sha256'] == artifact['manifest_sha256']
            and files['source-package.py']['sha256'] == DEPENDENCIES['source-package.py'],
            'manifest/consumer pin mismatch')
    runtime = value.get('runtime', {})
    require(runtime.get('python') == str(PYTHON) and runtime.get('python_sha256') == PYTHON_SHA256
            and runtime.get('python_version') == [3, 14, 4]
            and runtime.get('prerequisite_root') == '/home/qian-qi/hia-e26e-v64-prerequisites',
            'existing prepared runtime paths/pins differ')
    controls = value.get('control_files')
    require(type(controls) is dict and set(DEPENDENCIES) <= set(controls)
            and {'driver.py', 'bootstrap.py', 'verify_terminal.py', 'desktop-v67-input-hints.json'} <= set(controls),
            'complete frozen control inventory required')
    for name, expected in controls.items():
        require(Path(name).name == name and type(expected) is str and HEX64.fullmatch(expected),
                'invalid control identity')
    require(all(controls[name] == expected for name, expected in DEPENDENCIES.items()),
            'previously reviewed dependency bytes changed')
    old = value.get('readonly_inputs')
    require(type(old) is dict and bool(old), 'original immutable input pins required')
    for name, expected in old.items():
        require(type(name) is str and Path(name).is_absolute()
                and not Path(name).is_relative_to(ROOT)
                and type(expected) is str and HEX64.fullmatch(expected), 'invalid original read-only input')
    validate_fixture_supply_pins(value)
    return value


def materialization_ok(result, request):
    source, artifact = request['source'], request['artifact']
    require(result.get('schema') == 'hepta.hia.git-source-materialization.v1'
            and result.get('status') == 'PASS'
            and result.get('commit') == source['commit'] and result.get('tree') == source['tree']
            and result.get('manifest_sha256') == artifact['manifest_sha256']
            and result.get('destination') == str(ROOT / 's')
            and result.get('qualification_executed') is False,
            'exact source materialization did not pass')
    for name in ('fsck_full_strict', 'exact_object_database', 'all_leaves_bytes_modes_verified',
                 'original_source_state_matches_export', 'original_parent_headers_preserved'):
        require(result.get(name) is True, 'missing actual source custody check: ' + name)
    require(result.get('ancestor_history_included') is False
            and result.get('counts', {}).get('leaves') == source['leaf_count'], 'source closure population/scope differs')
    before = result.get('original_source_state_before')
    require(type(before) is dict and result.get('original_source_state_after') == before
            and before.get('head') == source['commit'] and before.get('tree') == source['tree']
            and not before.get('status'), 'complete original source state is inconsistent')
    clone = result.get('clone_reproduction', {})
    require(clone.get('status') == 'PASS' and clone.get('destination') == str(ROOT / 'source-clone-control')
            and clone.get('fsck_full_strict') is True and clone.get('exact_object_database') is True
            and clone.get('all_leaves_bytes_modes_verified') is True
            and clone.get('object_storage_hardlinks') == 0
            and clone.get('original_source_state_before') == before
            and clone.get('original_source_state_after') == before
            and clone.get('ancestor_history_included') is False
            and clone.get('shallow_boundary') == result.get('shallow_boundary'),
            'actual independent clone reproduction is incomplete')


def preparation_ok(preparation, environment, request):
    require(preparation.get('schema') == 'hepta.hia.remote-qualification-preparation.v2'
            and preparation.get('status') == 'READY' and preparation.get('missing') == []
            and preparation.get('source') == str(ROOT / 's')
            and preparation.get('python') == str(PYTHON)
            and preparation.get('qualification_executed') is False,
            'fresh exact-source prerequisite observation did not pass')
    checks = preparation.get('checks', {})
    require(all(checks.get(name, {}).get('available') is True for name in REQUIRED_PREPARATION_CHECKS),
            'one original tool or NDU fixture is unavailable')
    require(checks.get('ptrace', {}).get('returncode') == 0
            and checks.get('sealed_memfd', {}).get('returncode') == 0,
            'actual tracing/sealed-image probes did not pass')
    require(environment.get('schema') == 'hepta.hia.qualification-environment.v2'
            and environment.get('source') == str(ROOT / 's')
            and environment.get('python') == str(PYTHON), 'fresh environment binding differs')
    settings = environment.get('set', {})
    require(settings.get('CARGO_NET_OFFLINE') == 'true'
            and settings.get('CARGO_HOME') == request['runtime']['prerequisite_root'] + '/cargo-home'
            and settings.get('CARGO_TARGET_DIR') == str(ROOT / 'p/cargo-target')
            and settings.get('HEPTA_RUN_ARTIFACT_SESSION') == '1'
            and all(settings.get(name) == str(ROOT / 't') for name in ('TMPDIR', 'TMP', 'TEMP')),
            'original explicit offline/private environment differs')
    for name in ('output', 'temporary'):
        row = preparation.get('storage', {}).get(name, {})
        require(type(row.get('free_bytes')) is int and row['free_bytes'] >= 8 << 30
                and type(row.get('free_inodes')) is int and row['free_inodes'] >= 100000,
                'original storage/inode gate did not pass')
    # This is an explicit new adapter, not a reconstruction of the inaccessible
    # c127 source. It delegates all original 972d run/save gates and adds only
    # the private Cargo choice plus exact candidate/archive admission.
    adapter = preparation.get('v67_adapter', {})
    require(adapter.get('revision') == 'new-private-cargo-v67-r2-three-fresh-fixtures'
            and adapter.get('original_adapter_c127_recovered') is False
            and adapter.get('original_preparer_sha256') == DEPENDENCIES['prepare_remote_qualification_v2.py']
            and adapter.get('original_run_and_save_unchanged') is True
            and adapter.get('archive_manifest_structure_observed_before_freeze') is True
            and adapter.get('cache_metadata_may_change') is True
            and adapter.get('cache_tree_immutability_claimed') is False
            and adapter.get('offline_build_completeness_claimed') is False,
            'new prerequisite adapter scope or original-gate delegation differs')
    fixed = adapter.get('current_fixed_inputs', {})
    require(len(fixed.get('executables', [])) == 13 and len(fixed.get('fixture_receipts', [])) == 6
            and fixed.get('hints', {}).get('sha256') == request['control_files']['desktop-v67-input-hints.json'],
            'new explicit prerequisite inventory is incomplete')
    archives = adapter.get('current_crate_archives', {})
    rows = archives.get('archives')
    require(archives.get('manifest', {}).get('sha256') ==
            '83efd48f22248a3381d084fff3551f4475c4d0c2e589acc737d3d03007a50c33'
            and archives.get('count') == 55 and type(rows) is list and len(rows) == 55
            and len({row['path'] for row in rows}) == 55
            and all(environment.get('recheck_sha256', {}).get(row['path']) == row['sha256'] for row in rows),
            'all fixed crate archives must be admitted and retained for the unchanged prerequisite recheck in v9')


def original_prerequisite_selection(preparation, request):
    """Old receipts identify candidates only; fresh original probes must match."""
    base = Path(request['runtime']['prerequisite_root'])
    tools, tool_pin = read_json(base / 'fixed-tools-ready-report.json',
        '103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770')
    fixtures, fixture_pin = read_json(base / 'fixture-build-report-r2.json',
        '04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406')
    checks = preparation['checks']
    actual = {}
    for check_name, retained_name in ORIGINAL_TOOL_KEYS.items():
        expected, current = tools['tools'][retained_name], checks[check_name]
        require(current.get('path') == expected['path'] and current.get('sha256') == expected['sha256']
                and current.get('available') is True, 'fresh tool differs from the original explicit candidate: ' + check_name)
        actual[check_name] = {'path': current['path'], 'sha256': current['sha256']}
    supplied = validate_fixture_supply_pins(request)['fixtures']
    for name in ('ranking', 'raw', 'dynamic', 'recursive', 'finite', 'stream'):
        expected, current = supplied.get(name, fixtures['fixtures'][name]), checks['ndu_' + name]
        require(current.get('path') == expected['receipt']
                and current.get('sha256') == expected['receipt_sha256']
                and current.get('available') is True, 'fresh source-bound fixture differs: ' + name)
        if name in supplied:
            require(current.get('binary', {}).get('path') == expected['binary']
                    and current['binary'].get('sha256') == expected['binary_sha256'],
                    'original current gate admitted a different fresh binary: ' + name)
    return {'original_tool_candidates': tool_pin, 'original_fixture_candidates': fixture_pin,
            'twelve_actual_tool_paths_and_hashes': actual,
            'three_new_fixture_candidates': supplied,
            'three_other_fixture_candidates_unchanged': True,
            'six_fixtures_freshly_reobserved_by_original_preparer': True,
            'historical_READY_counted_as_current_test_pass': False}


def extract_original_archive(request, destination):
    artifact = request['artifact']
    path = Path(artifact['archive_path'])
    before, _ = stable_file(path, artifact['archive_sha256'])
    require(before['bytes'] == artifact['archive_bytes'], 'official artifact size differs')
    destination.mkdir(mode=0o700, exist_ok=False)
    receipt_destination = ROOT / 'source-export-originals'
    receipt_destination.mkdir(mode=0o700, exist_ok=False)
    expected = {artifact['member_prefix'] + name: (destination / name, artifact['package_files'][name])
                for name in PACKAGE_FILES}
    expected.update({name: (receipt_destination / name, artifact['receipt_files'][name])
                     for name in EXPORT_RECEIPTS})
    allowed_directories = {'package/'}
    copied = {}
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        require(list(identity(os.fstat(stream.fileno()))) == before['identity'], 'artifact inode changed before extraction')
        with zipfile.ZipFile(stream) as archive:
            names = set()
            for member in archive.infolist():
                require(member.filename not in names, 'duplicate artifact member')
                names.add(member.filename)
                require(not member.flag_bits & 1, 'encrypted artifact member refused')
                kind = stat.S_IFMT(member.external_attr >> 16)
                if member.is_dir():
                    require(member.filename in allowed_directories and kind in (0, stat.S_IFDIR),
                            'unexpected artifact directory')
                    continue
                require(member.filename in expected and kind in (0, stat.S_IFREG),
                        'unexpected/symlink/special artifact member: ' + member.filename)
                name = member.filename
                target, pin = expected[name]
                require(member.file_size == pin['bytes'], 'package member length differs: ' + name)
                output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
                digest, count = sha256(), 0
                with os.fdopen(output_fd, 'wb') as output, archive.open(member) as source:
                    for block in iter(lambda: source.read(1 << 20), b''):
                        count += len(block)
                        require(count <= pin['bytes'], 'package member grew: ' + name)
                        digest.update(block)
                        output.write(block)
                    require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'],
                            'package member digest differs: ' + name)
                    output.flush()
                    os.fsync(output.fileno())
                copied[name], _ = stable_file(target, pin['sha256'])
        require(list(identity(os.fstat(stream.fileno()))) == before['identity'], 'artifact changed during extraction')
    require(set(copied) == set(expected), 'artifact omitted one of the eight original files')
    require(stable_file(path, artifact['archive_sha256'])[0] == before, 'original artifact binding changed')
    sync_directory(destination)
    sync_directory(receipt_destination)
    sync_directory(destination.parent)
    return {'original_archive': before, 'members': copied, 'every_member_independently_read_back': True}


def verify_export_receipts(request):
    source, artifact = request['source'], request['artifact']
    manifest, _ = read_json(ROOT / 'package/manifest.json', artifact['manifest_sha256'])
    exported, export_pin = read_json(ROOT / 'source-export-originals/IDENTITY.json',
                                     artifact['receipt_files']['IDENTITY.json']['sha256'])
    reconstructed, reconstruction_pin = read_json(ROOT / 'source-export-originals/reconstruction.json',
                              artifact['receipt_files']['reconstruction.json']['sha256'])
    require(exported.get('schema') == 'hepta.hia.actions-source-custody.v1'
            and exported.get('status') == 'PASS' and exported.get('qualification_executed') is False
            and exported.get('repository') == 'TrillionniumFoundation/Hepta'
            and exported.get('commit') == source['commit'] and exported.get('tree') == source['tree']
            and exported.get('workflow_sha') == source['commit']
            and exported.get('run_id') == str(artifact['workflow_run_id'])
            and exported.get('run_attempt') == str(artifact['run_attempt'])
            and exported.get('manifest_sha256') == artifact['manifest_sha256']
            and exported.get('counts') == manifest.get('counts')
            and exported.get('pack') == manifest.get('pack')
            and exported.get('ancestor_history_included') is False,
            'official Actions source identity receipt differs from external pins')
    require(reconstructed.get('schema') == 'hepta.hia.git-source-materialization.v1'
            and reconstructed.get('status') == 'PASS' and reconstructed.get('qualification_executed') is False
            and reconstructed.get('commit') == source['commit'] and reconstructed.get('tree') == source['tree']
            and reconstructed.get('manifest_sha256') == artifact['manifest_sha256']
            and reconstructed.get('counts') == manifest.get('counts')
            and reconstructed.get('pack') == manifest.get('pack'),
            'original Actions reconstruction receipt differs')
    for name in ('fsck_full_strict', 'exact_object_database', 'all_leaves_bytes_modes_verified',
                 'original_source_state_matches_export', 'original_parent_headers_preserved'):
        require(reconstructed.get(name) is True, 'original Actions reconstruction check missing: ' + name)
    state = reconstructed.get('original_source_state_before')
    clone = reconstructed.get('clone_reproduction', {})
    require(type(state) is dict and state == reconstructed.get('original_source_state_after')
            and state.get('head') == source['commit'] and state.get('tree') == source['tree']
            and not state.get('status')
            and clone.get('status') == 'PASS' and clone.get('fsck_full_strict') is True
            and clone.get('exact_object_database') is True and clone.get('all_leaves_bytes_modes_verified') is True
            and clone.get('object_storage_hardlinks') == 0
            and clone.get('original_source_state_before') == state
            and clone.get('original_source_state_after') == state
            and reconstructed.get('ancestor_history_included') is False
            and clone.get('ancestor_history_included') is False
            and clone.get('shallow_boundary') == reconstructed.get('shallow_boundary')
            == exported.get('shallow_boundary') == manifest.get('shallow', {}).get('exported_boundary'),
            'original Actions source or clone custody is incomplete')
    return {'identity': export_pin, 'reconstruction': reconstruction_pin,
            'original_actions_receipts_checked_not_qualification_pass': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request, request_record = read_json(args.request, args.request_sha256)
    validate_request(request)
    control = ROOT / 'control'
    require(args.request == control / 'request.json', 'request is not the installed private control')
    require(Path(sys.executable).resolve() == PYTHON.resolve()
            and list(sys.version_info[:3]) == [3, 14, 4], 'wrong prepared Python')
    for directory in (ROOT, control, ROOT / 'guard'):
        private_directory(directory)
    for name in ('s', 'source-clone-control', 'package', 'source-export-originals', 'p', 't', 'q', 'preparation-logs'):
        require(not os.path.lexists(ROOT / name), 'fresh destination already exists: ' + name)
    controls = {name: stable_file(control / name, expected)[0]
                for name, expected in request['control_files'].items()}
    require(Path(workflow_process.__file__).resolve() == control / 'workflow_process.py',
            'workflow process helper is not the reviewed adjacent file')
    logs = ROOT / 'preparation-logs'
    logs.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('HEPTA_HIA_', 'GIT_'))
                   and key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE',
                                   'LD_PRELOAD', 'CARGO_HOME', 'CARGO_TARGET_DIR')}
    environment.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                       PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', PYTHONNOUSERSITE='1',
                       GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0',
                       CARGO_BUILD_JOBS='2')
    report = {'schema': 'hia.stack-v9.full-qualification-preparation.v1', 'status': 'PREPARATION_HOLD',
              'request': request_record, 'head': request['source']['commit'], 'tree': request['source']['tree'],
              'source': str(ROOT / 's'), 'qualification_output': str(ROOT / 'q'),
              'control_files_before': controls, 'steps': [], 'started_unix_ns': time.time_ns(),
              'whole_native_delivery_qualified': False, 'qualification_executed': False,
              'old_job_replayed': False, 'old_source_checkout_accessed': False,
              'network_requested': False, 'original_limits': LIMITS}

    def checkpoint():
        temporary = ROOT / 'preparation.next.json'
        create(temporary, wire(report), 0o600)
        os.replace(temporary, ROOT / 'preparation.json')
        sync_directory(ROOT)

    def run(label, command, seconds):
        print(json.dumps({'stage': 'STACK_V9_PREPARATION', 'step': label}), flush=True)
        owner = workflow_process.run_workflow_step(
            list(map(str, command)), cwd=ROOT, env=environment,
            stdout_path=logs / (label + '.stdout.log'), stderr_path=logs / (label + '.stderr.log'),
            receipt_path=logs / (label + '.owner.json'), seconds=seconds)
        report['steps'].append({'label': label, 'owner': owner})
        checkpoint()
        cleanup = owner.get('cleanup', {})
        require(owner.get('timed_out') is False and cleanup.get('complete') is True
                and cleanup.get('errors') == [] and cleanup.get('signalled') == [],
                'original owned preparation step did not close naturally: ' + label)
        require(owner.get('status') == 'WORKFLOW_STEP_COMPLETED' and owner.get('returncode') == 0,
                'original preparation command rejected its inputs or failed: ' + label)

    def readonly_inputs():
        return {path: stable_file(path, expected)[0] for path, expected in request['readonly_inputs'].items()}

    def check_declared_source():
        source = request['source']
        contract, contract_record = read_json(ROOT / 's' / CONTRACT, source['contract_sha256'])
        coverage, coverage_record = read_json(ROOT / 's' / COVERAGE, source['coverage_sha256'])
        require(contract_record['bytes'] == source['contract_bytes']
                and coverage_record['bytes'] == source['coverage_bytes'], 'checked source document size differs')
        pins = contract['source_identity']['files']
        require(contract.get('profile') == source['profile'] and len(pins) == source['declared_source_count'],
                'frozen contract profile/population differs')
        for name, expected in pins.items():
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and str(relative) == name
                    and all(part not in ('.', '..') for part in relative.parts), 'source member path escapes checkout')
            stable_file(ROOT / 's' / name, expected)
        return {**pins, CONTRACT: source['contract_sha256']}

    try:
        report['original_inputs_before'] = readonly_inputs()
        report['fixture_supply_before'] = verify_fixture_supply(request)
        runtime = request['runtime']
        report['python_binary'], _ = stable_file(PYTHON.resolve(), PYTHON_SHA256)
        python_report, _ = read_json(runtime['python_preparation'], runtime['python_preparation_sha256'])
        python_guard, _ = read_json(runtime['python_guardian'], runtime['python_guardian_sha256'])
        require(python_report.get('status') == 'CPYTHON_LINUX_AND_LOCKED_DEPS_READY_NOT_QUALIFICATION'
                and python_report.get('qualification_executed') is False
                and python_report.get('original_sealed_memfd_gate_passed') is True
                and python_report.get('venv_actual_linux_apis', {}).get('sealed_memfd_ok') is True
                and python_report.get('python', {}).get('path') == str(PYTHON)
                and python_report['python'].get('sha256') == PYTHON_SHA256,
                'original Linux Python preparation differs')
        require(python_guard.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
                and python_guard.get('input_identity_preserved') is True
                and python_guard.get('lifecycle', {}).get('cleanup', {}).get('complete') is True
                and python_guard['lifecycle']['cleanup'].get('observed_echild') is True,
                'original Python preparation owner was not closed')
        report['source_package_ingress'] = extract_original_archive(request, ROOT / 'package')
        report['original_actions_receipts'] = verify_export_receipts(request)
        checkpoint()
        source = request['source']
        run('exact-source-materialization', [PYTHON, '-I', '-S', '-B', ROOT / 'package/source-package.py',
            'materialize', '--package', ROOT / 'package', '--destination', ROOT / 's',
            '--reproduction-destination', ROOT / 'source-clone-control',
            '--expected-commit', source['commit'], '--expected-tree', source['tree'],
            '--manifest-sha256', request['artifact']['manifest_sha256'],
            '--report', ROOT / 'source-materialization.json'], LIMITS['source_materialization_seconds'])
        materialized, report['materialization_receipt'] = read_json(ROOT / 'source-materialization.json')
        materialization_ok(materialized, request)
        for name in ('run_hia_qualification_v9.py', 'qualification_prerequisites.py', 'native_owner_gates.py',
                     'guardian.py', 'process_owner_impl.py', 'workflow_process.py'):
            stable_file(ROOT / 's' / RUNNER_PREFIX / name, DEPENDENCIES[name])
        stable_file(ROOT / 's' / SOURCE_PACKAGE_PATH, DEPENDENCIES['source-package.py'])
        stable_file(ROOT / 's/review-evidence/hia-native-rewrite-20261111/prepare_remote_qualification_v2.py',
                    DEPENDENCIES['prepare_remote_qualification_v2.py'])
        # Historical supplier identity remains exact 608. The current source's
        # builder and all six adapter/lock/input inventories are independently
        # admitted by the unchanged original fresh prerequisite probes below.
        stable_file(ROOT / 's/tools/build_hia_ndu_bridge.py', SUPPLY_BUILDER_SHA256)
        cold_sources = check_declared_source()
        report['cold_source_manifest'] = cold_sources
        create(ROOT / 'cold-source-manifest-before.json', wire(cold_sources))
        checkpoint()
        run('fresh-source-bound-prerequisites', [PYTHON, '-B', control / 'prepare_v67_cargo_environment.py',
            control / 'prepare_remote_qualification_v2.py', '--source', ROOT / 's', '--output', ROOT / 'p', '--temporary-root', ROOT / 't',
            '--prereq-root', runtime['prerequisite_root'], '--python', PYTHON,
            '--candidate-environment', control / 'desktop-v67-input-hints.json'], LIMITS['preparation_seconds'])
        preparation, report['prerequisite_report'] = read_json(ROOT / 'p/preparation.json')
        prepared_environment, report['prerequisite_environment'] = read_json(ROOT / 'p/environment.json')
        preparation_ok(preparation, prepared_environment, request)
        report['exact_original_prerequisite_selection'] = original_prerequisite_selection(preparation, request)
        report['fixture_supply_after'] = verify_fixture_supply(request)
        require(report['fixture_supply_after'] == report['fixture_supply_before'],
                'supplied fixture identity changed during original fresh probes')
        require(check_declared_source() == cold_sources, 'source changed during prerequisite preparation')
        report['original_inputs_after'] = readonly_inputs()
        require(report['original_inputs_after'] == report['original_inputs_before'], 'old input identity changed')
        report['control_files_after'] = {name: stable_file(control / name, expected)[0]
                                         for name, expected in request['control_files'].items()}
        require(report['control_files_after'] == controls, 'controller changed during preparation')
        require(stable_file(request['artifact']['archive_path'], request['artifact']['archive_sha256'])[0]
                == report['source_package_ingress']['original_archive'], 'original artifact changed during preparation')
        command = [str(PYTHON), '-B', str(ROOT / 'p/launch.py'), str(control / 'run_hia_qualification_v9.py'),
                   '--source', str(ROOT / 's'), '--output', str(ROOT / 'q'),
                   '--prerequisite-environment', str(ROOT / 'p/environment.json'),
                   '--prerequisite-report', str(ROOT / 'p/preparation.json'), '--full']
        report.update(status='FRESH_SOURCE_AND_PREREQUISITES_READY_V9_FULL_EXEC_REQUESTED',
                      qualification_exec_requested=True, qualification_command=command)
        checkpoint()
        print(json.dumps({'stage': report['status'], 'head': source['commit'], 'tree': source['tree']}), flush=True)
        os.execve(str(PYTHON), command, environment)
    except BaseException as error:
        report.update(status='PREPARATION_HOLD', error_type=type(error).__name__, error=str(error),
                      failed_unix_ns=time.time_ns())
        checkpoint()
        raise


if __name__ == '__main__':
    main()
