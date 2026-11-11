"""Create one private artifact-ingress root and exec the unchanged guardian.

The complete stdin payload is a private transport record. Only its SHA is
public; a signed URL is never copied into source or public launch summaries.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path('/home/qian-qi/he26v67-source-original-r1')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
KEY = 'hia-e26e-desktop-v67-source-13870963554-original-ingress-r1'
FIXED = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'artifact-pins.json': 'ed40b484eeee3d87d376c72e6cec62a35d837dd89c8e2059f7a49d19f671e05c',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_original(path, expected, max_bytes=1 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= max_bytes, 'owned regular input required')
        raw = stream.read(max_bytes + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'input identity changed')
    require(sha256(raw).hexdigest() == expected, 'input SHA differs')
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(read_original(path, sha256(raw).hexdigest()) == raw, 'created control readback differs')


def main():
    require(len(sys.argv) == 2, 'complete private payload SHA argument required')
    raw = sys.stdin.buffer.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20 and sha256(raw).hexdigest() == sys.argv[1], 'complete stdin binding differs')
    payload = json.loads(raw)
    require(payload.get('schema') == 'hia.v67.official-source-original-bootstrap.v1', 'payload schema differs')
    request = payload['request']
    require(request.get('schema') == 'hia.v67.official-source-original-private-request.v1'
            and request.get('stable_key') == KEY and request.get('artifact_pins_sha256') == FIXED['artifact-pins.json'],
            'private ingress request differs')
    expected_names = set(FIXED) | {'download_original.py', 'bootstrap.py'}
    require(set(payload['files']) == set(request['control_files']) == expected_names, 'control inventory differs')
    for name, content in payload['files'].items():
        require(type(content) is str and sha256(content.encode()).hexdigest() == request['control_files'][name],
                'control SHA differs')
    require(all(request['control_files'][name] == value for name, value in FIXED.items()), 'original input changed')
    if sys.argv[0] == '-c':
        require(sys.orig_argv.count('-c') == 1, 'ambiguous bootstrap source')
        executing = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
    else:
        executing = Path(__file__).read_bytes()
    require(sha256(executing).hexdigest() == request['control_files']['bootstrap.py'], 'executing bootstrap differs')
    os.umask(0o077)
    require(list(sys.version_info[:3]) == [3, 14, 4] and Path(sys.executable).resolve() == PYTHON.resolve(),
            'formal Python identity differs')
    require(not os.path.lexists(ROOT), 'new ingress root exists; reconcile the original operation')
    require(not any(path.is_symlink() for path in (ROOT.parent, *ROOT.parent.parents)), 'symlink ancestor refused')
    home = ROOT.parent.lstat()
    require(stat.S_ISDIR(home.st_mode) and home.st_uid == os.geteuid() and not home.st_mode & 0o022,
            'owned operator home required')
    capacity = os.statvfs(ROOT.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            'original storage reserve not available')
    read_original(PYTHON.resolve(), PYTHON_SHA, 64 << 20)
    ROOT.mkdir(mode=0o700, exist_ok=False)
    for name in ('control', 'guard', 'original'):
        (ROOT / name).mkdir(mode=0o700, exist_ok=False)
    identities = {str(PYTHON.resolve()): PYTHON_SHA}
    for name, content in payload['files'].items():
        path = ROOT / 'control' / name
        create(path, content.encode())
        identities[str(path)] = request['control_files'][name]
    request_raw = wire(request)
    create(ROOT / 'control/request.private.json', request_raw)
    identities[str(ROOT / 'control/request.private.json')] = sha256(request_raw).hexdigest()
    create(ROOT / 'control/bootstrap-stdin.private.json', raw)
    identities[str(ROOT / 'control/bootstrap-stdin.private.json')] = sha256(raw).hexdigest()
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
              'command': [str(PYTHON), '-I', '-S', '-B', str(ROOT / 'control/download_original.py')],
              'cwd': str(ROOT), 'source_identities': identities}
    config_raw = wire(config)
    create(ROOT / 'guard/request.json', config_raw)
    create(ROOT / 'launch-intent.json', wire({
        'schema': 'hia.v67.official-source-original-ingress-intent.v1',
        'stable_key': KEY, 'status': 'GUARDIAN_EXEC_REQUESTED_NOT_VERIFIED',
        'root': str(ROOT), 'host': 'desktop', 'artifact_id': 13870963554,
        'source_commit': '608157e52b0b94e0d294f6b99c4e809869f183aa',
        'source_tree': 'e7c29a60796a1a78946a2c667aa80df86529e532',
        'stdin_payload_sha256': sha256(raw).hexdigest(),
        'private_request_sha256': sha256(request_raw).hexdigest(),
        'guardian_request_sha256': sha256(config_raw).hexdigest(),
        'control_files': request['control_files'], 'controller_seconds': 900,
        'capacity_before': {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                            'free_inodes': capacity.f_favail},
        'signed_url_in_public_source_or_receipt': False,
        'qualification_executed': False, 'old_jobs_replayed': False,
        'consumer_clone_prerequisites_or_tests_requested': False}))
    for path in (ROOT / 'control', ROOT / 'guard', ROOT / 'original', ROOT, ROOT.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('HEPTA_HIA_', 'GIT_', 'PYTHON')) and key not in {'LD_PRELOAD', 'LD_LIBRARY_PATH'}}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', LANG='C.UTF-8', LC_ALL='C.UTF-8')
    print(json.dumps({'stage': 'OFFICIAL_SOURCE_ORIGINAL_INGRESS_GUARDIAN_LAUNCH',
                      'root': str(ROOT), 'stable_key': KEY}), flush=True)
    os.execve(str(PYTHON), [str(PYTHON), '-I', '-S', '-B', str(ROOT / 'control/guardian.py'),
                          '--config', str(ROOT / 'guard/request.json'),
                          '--config-sha256', sha256(config_raw).hexdigest(),
                          '--implementation', str(ROOT / 'control/process_owner_impl.py')], env)


if __name__ == '__main__':
    raise SystemExit(main())
