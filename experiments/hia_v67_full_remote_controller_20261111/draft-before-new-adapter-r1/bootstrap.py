"""Create one new v67 qualification root, then exec the frozen guardian.

The immutable launch payload is supplied on stdin and bound by the external
--payload-sha256 argument. No network, package install, Git command, source
materialization or product test runs before guardian ownership begins.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path('/home/qian-qi/he26v67r1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA256 = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
FIXED = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
    'qualification_prerequisites.py': '352e537de1ca6962d6d8bafa6ac9dea61c83f0d30c5d9c75bce50088fefadead',
    'run_hia_qualification_v8.py': '5b7a2dfb32fd7767c3c402d84b61c2773f7d863bd116c9a5ce28c4176c96d310',
    'native_owner_gates.py': 'a2d2a8f1ffcdf9032efc98f774f2f4e23bc94aaceb56f95a359b7d4442a1eb30',
    'source-package.py': 'af243e692ee5b6e9289f6226a0269ae40b02e1b460521471e199dfb8981dca5a',
    'prepare_remote_qualification_v2.py': '972dffc85f53093aa8d06f53a1a2154dc1731e7ad93c0ca39c93f0b03a91ffbc',
    'prepare_private_cargo_environment.py': 'c127a44848a795807282082c0cf7737752b8a1a357dfff3f0cbd280f1d0d2082',
}
LIMITS = {
    'controller_seconds': 10800, 'source_materialization_seconds': 900,
    'preparation_seconds': 900, 'cold_seconds': 180, 'cold_workers': 2,
    'cold_phases': 38, 'full_suite_seconds': 5400,
    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate launch JSON member: ' + key)
        result[key] = value
    return result


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_original(path, expected, *, collect=False):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digest, count = sha256(), 0
    parts = [] if collect else None
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1,
                'owned independent ordinary input required: ' + str(path))
        if collect:
            require(before.st_size <= 2 << 20, 'control input exceeds bound')
        for part in iter(lambda: stream.read(1 << 20), b''):
            count += len(part)
            require(count <= before.st_size, 'input grew while reading')
            digest.update(part)
            if parts is not None:
                parts.append(part)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                'input changed while reading')
    require(identity(before) == identity(path.lstat()) and digest.hexdigest() == expected,
            'input binding or digest differs: ' + str(path))
    return b''.join(parts) if parts is not None else None


def create(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    require(read_original(path, sha256(content).hexdigest(), collect=True) == content,
            'new control readback differs')


def validate_payload(payload):
    require(type(payload) is dict and set(payload) == {'schema', 'request', 'files'}
            and payload['schema'] == 'hia.v67.full-qualification-bootstrap-payload.v1',
            'unexpected immutable launch payload')
    request = payload['request']
    require(type(request) is dict and request.get('schema') == 'hia.v67.full-qualification-launch.v1'
            and request.get('frozen') is True and not request.get('pending'),
            'final pins not frozen; remote mutation is not permitted')
    require(request.get('host') == 'desktop' and request.get('root') == str(ROOT)
            and request.get('limits') == LIMITS, 'fixed new root or original limits differ')
    source = request.get('source', {})
    for key, count in (('commit', 40), ('tree', 40), ('contract_sha256', 64), ('coverage_sha256', 64)):
        require(type(source.get(key)) is str and re.fullmatch('[0-9a-f]{' + str(count) + '}', source[key]),
                'required full source pin missing: ' + key)
    require(source.get('declared_source_count') == 681 and source.get('cold_source_count') == 682
            and source.get('leaf_count') == 3925 and source.get('profile'), 'frozen source population differs')
    require(request.get('stable_key') == 'hia-e26e-desktop-v67-' + source['commit'][:8] + '-full-qualification-r1',
            'new original-operation key differs')
    artifact = request.get('artifact', {})
    require(type(artifact.get('workflow_run_id')) is int and artifact['workflow_run_id'] > 0
            and type(artifact.get('artifact_id')) is int and artifact['artifact_id'] > 0
            and type(artifact.get('archive_bytes')) is int and artifact['archive_bytes'] > 0,
            'official exact-head artifact observation is incomplete')
    for key in ('archive_sha256', 'manifest_sha256'):
        require(type(artifact.get(key)) is str and re.fullmatch('[0-9a-f]{64}', artifact[key]),
                'official artifact digest is not externally pinned')
    require(type(artifact.get('archive_path')) is str and Path(artifact['archive_path']).is_absolute()
            and not Path(artifact['archive_path']).is_relative_to(ROOT), 'original artifact path is invalid')
    require(type(artifact.get('package_files')) is dict and set(artifact['package_files']) == {
        'source.pack', 'manifest.json', 'source-package.py', 'export-report.json',
        'source-state-before.json', 'source-state-after.json'}, 'six package inputs required')
    require(artifact.get('member_prefix') == 'package/'
            and type(artifact.get('receipt_files')) is dict
            and set(artifact['receipt_files']) == {'IDENTITY.json', 'reconstruction.json'}
            and type(artifact.get('run_attempt')) is int and artifact['run_attempt'] > 0,
            'official artifact must retain all eight original files')
    controls = request.get('control_files', {})
    expected_names = set(FIXED) | {'driver.py', 'bootstrap.py', 'verify_terminal.py', 'desktop-retained-input-hints.json'}
    require(type(controls) is dict and set(controls) == expected_names
            and type(payload['files']) is dict and set(payload['files']) == expected_names,
            'frozen control payload inventory differs')
    for name, content in payload['files'].items():
        require(type(content) is str and sha256(content.encode()).hexdigest() == controls[name],
                'control payload SHA differs: ' + name)
    require(all(controls[name] == expected for name, expected in FIXED.items()),
            'previously reviewed prerequisite, runner or owner changed')
    runtime = request.get('runtime', {})
    require(runtime.get('python') == str(PYTHON) and runtime.get('python_sha256') == PYTHON_SHA256
            and runtime.get('python_version') == [3, 14, 4], 'runtime identity differs')
    old = request.get('readonly_inputs')
    require(type(old) is dict and bool(old), 'old immutable inputs missing')
    for path, expected in old.items():
        require(type(path) is str and Path(path).is_absolute() and not Path(path).is_relative_to(ROOT)
                and type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected),
                'invalid read-only original input identity')
    return request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload-sha256', required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read((2 << 20) + 1)
    require(len(raw) <= 2 << 20 and sha256(raw).hexdigest() == args.payload_sha256,
            'complete immutable bootstrap payload differs')
    payload = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    request = validate_payload(payload)
    # Support a normal pinned file or the exact -c source retained in h's
    # original launch request. Never accept an unobserved third bootstrap.
    if sys.argv[0] == '-c':
        original = sys.orig_argv
        require(original.count('-c') == 1, 'ambiguous Python source argument')
        executed = original[original.index('-c') + 1].encode()
    else:
        executed = Path(__file__).read_bytes()
    require(sha256(executed).hexdigest() == request['control_files']['bootstrap.py'],
            'executing bootstrap differs from reviewed payload')
    os.umask(0o077)
    require(list(sys.version_info[:3]) == [3, 14, 4]
            and Path(sys.executable).resolve() == PYTHON.resolve(), 'wrong formal Python')
    require(not os.path.lexists(ROOT), 'new root already exists; reconcile original operation, never replay')
    require(not any(path.is_symlink() for path in (ROOT.parent, *ROOT.parent.parents)), 'symlink ancestor refused')
    home = ROOT.parent.lstat()
    require(stat.S_ISDIR(home.st_mode) and home.st_uid == os.geteuid()
            and not stat.S_IMODE(home.st_mode) & 0o022, 'private operator home identity differs')
    capacity = os.statvfs(ROOT.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            'original full-suite storage/inode minimum unavailable')
    identities = dict(request['readonly_inputs'])
    identities[str(PYTHON.resolve())] = PYTHON_SHA256
    runtime = request['runtime']
    identities[runtime['python_preparation']] = runtime['python_preparation_sha256']
    identities[runtime['python_guardian']] = runtime['python_guardian_sha256']
    for path, expected in identities.items():
        read_original(path, expected)
    # The original archive is hashed by the frozen guardian before child
    # dispatch and again, via a held descriptor, by the owned consumer driver.
    archive = Path(request['artifact']['archive_path'])
    item = archive.lstat()
    require(stat.S_ISREG(item.st_mode) and item.st_uid == os.geteuid() and item.st_nlink == 1
            and item.st_size == request['artifact']['archive_bytes'], 'original archive stat differs')
    identities[str(archive)] = request['artifact']['archive_sha256']
    ROOT.mkdir(mode=0o700, exist_ok=False)
    for name in ('control', 'guard'):
        (ROOT / name).mkdir(mode=0o700, exist_ok=False)
    for name, content in payload['files'].items():
        path = ROOT / 'control' / name
        create(path, content.encode())
        identities[str(path)] = request['control_files'][name]
    request_raw = wire(request)
    create(ROOT / 'control/request.json', request_raw)
    identities[str(ROOT / 'control/request.json')] = sha256(request_raw).hexdigest()
    guardian_request = {
        'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 10800,
        'command': [str(PYTHON), '-B', str(ROOT / 'control/driver.py'),
                    '--request', str(ROOT / 'control/request.json'),
                    '--request-sha256', sha256(request_raw).hexdigest()],
        'cwd': str(ROOT), 'source_identities': identities,
        'expected_qualification': {
            'path': str(ROOT / 'q/QUALIFICATION.json'), 'head': request['source']['commit'],
            'tree': request['source']['tree'], 'cold_source_count': 682,
            'contract_sha256': request['source']['contract_sha256'],
        },
    }
    guardian_raw = wire(guardian_request)
    create(ROOT / 'guard/request.json', guardian_raw)
    create(ROOT / 'launch-intent.json', wire({
        'schema': 'hia.v67.full-qualification-launch-intent.v1', 'status': 'GUARDIAN_EXEC_REQUESTED_NOT_PASS',
        'stable_key': request['stable_key'], 'root': str(ROOT), 'host': 'desktop',
        'head': request['source']['commit'], 'tree': request['source']['tree'],
        'payload_sha256': args.payload_sha256, 'request_sha256': sha256(request_raw).hexdigest(),
        'guardian_request_sha256': sha256(guardian_raw).hexdigest(), 'control_files': request['control_files'],
        'artifact': request['artifact'], 'limits': LIMITS,
        'new_source_root': str(ROOT / 's'), 'preparation_root': str(ROOT / 'p'),
        'temporary_root': str(ROOT / 't'), 'qualification_root': str(ROOT / 'q'),
        'source_package_consumer_and_prereparation_inside_guardian': True,
        'existing_job_replayed': False, 'whole_native_delivery_qualified': False,
        'capacity_before': {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                            'free_inodes': capacity.f_favail},
    }))
    for directory in (ROOT / 'control', ROOT / 'guard', ROOT, ROOT.parent):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for name in list(os.environ):
        if name.startswith(('HEPTA_HIA_', 'GIT_')) or name in (
                'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'LD_PRELOAD'):
            os.environ.pop(name, None)
    os.environ.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', PYTHONNOUSERSITE='1')
    print(json.dumps({'stage': 'V67_FULL_GUARDIAN_EXEC', 'root': str(ROOT),
                      'head': request['source']['commit'], 'controller_seconds': 10800}), flush=True)
    os.execv(str(PYTHON), [str(PYTHON), '-B', str(ROOT / 'control/guardian.py'),
              '--config', str(ROOT / 'guard/request.json'), '--config-sha256', sha256(guardian_raw).hexdigest(),
              '--implementation', str(ROOT / 'control/process_owner_impl.py')])


if __name__ == '__main__':
    main()
