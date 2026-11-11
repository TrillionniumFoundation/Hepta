"""Create-only package development root and exec the unchanged owned guardian."""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys

os.umask(0o077)
ROOT = Path('/home/qian-qi/he26v66devr2')
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
B3 = Path('/home/qian-qi/he26v65r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
ARCHIVE = Path('/home/qian-qi/he26v66devr2-ingress-r1/inputs/e09-program-and-declared-source.tar.xz')
MANIFEST = Path('/home/qian-qi/he26v66devr2-ingress-r1/inputs/canonical-e09-development-package.json')
ARCHIVE_SHA = 'f0f0a0fd570fa2d260d95f25193b1d9571d9614bbc7ab1c22607f23112ae5428'
MANIFEST_SHA = '7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af'
STABLE_KEY = 'hia-e26e-desktop-e09-package-development-prepare-r2'
HEAD = 'e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
TREE = 'bfcbb39e22371cbb2292c89a2fa1ca010353a56f'
required = {
    'prepare_development_package.py': 'e2dac046fb3c7d4e072ec4293f780b190ee8c653208894c1ad8841bff7654bf4',
    'old-input-pins.json': 'abff0927d89f94bfdac0d600315e45dca0ceb719b7d3c28c0af17a7e270c1ffc',
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'workflow_process.py': 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
}
recovery_blobs = {
    'generate_hia_json_wire.py': 'f4e2648158896f26e46a2e8a7a0b22f94de50e7e',
    'test_hia_json_wire_native.py': 'f4ece1f7d8e61d4e19c98b43a44843525a6b8eb8',
}
raw_payload = sys.stdin.buffer.read(1048577)
assert len(raw_payload) <= 1048576
payload = json.loads(raw_payload)
assert payload['stable_key'] == STABLE_KEY and payload['head'] == HEAD and payload['tree'] == TREE
assert set(payload['files']) == set(required) | {'bootstrap.py'}
assert set(payload['recovery']) == set(recovery_blobs)
assert not any(p.is_symlink() for p in (ROOT, *ROOT.parents))
assert not os.path.lexists(ROOT)
parent = ROOT.parent.lstat()
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022
capacity = os.statvfs(ROOT.parent)
assert capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000


def identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def read_input(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
        raw = stream.read()
        assert identity(before) == identity(os.fstat(stream.fileno()))
    assert identity(before) == identity(path.lstat())
    assert sha256(raw).hexdigest() == expected
    return raw


for name, item in payload['files'].items():
    assert Path(name).name == name
    raw = item['source'].encode()
    assert sha256(raw).hexdigest() == item['sha256']
    if name in required:
        assert item['sha256'] == required[name]
for name, item in payload['recovery'].items():
    raw = item['source'].encode()
    assert sha256(raw).hexdigest() == item['sha256']
    assert sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == recovery_blobs[name] == item['blob_sha']
pins = json.loads(payload['files']['old-input-pins.json']['source'])
assert len(pins) == 12
for path, expected in pins.items():
    read_input(Path(path), expected)
assert Path(sys.executable).resolve() == PYTHON.resolve()
read_input(PYTHON.resolve(), 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493')
compiler = read_input(B3, B3_SHA)
archive_raw = read_input(ARCHIVE, ARCHIVE_SHA)
manifest_raw = read_input(MANIFEST, MANIFEST_SHA)
assert len(archive_raw) == 5829996 and len(manifest_raw) == 473051
assert sha1(b'blob ' + str(len(archive_raw)).encode() + b'\0' + archive_raw).hexdigest() == 'ff3ff3b9fe91d76952d2a4e84e0f33c5a09a1ede'
manifest = json.loads(manifest_raw)
assert manifest['canonical_commit'] == HEAD and manifest['canonical_tree'] == TREE
assert manifest['member_count'] == 1666 and manifest['complete_git_object_closure'] is False

ROOT.mkdir(mode=0o700)
directories = ['control', 'guard', 'inputs', 'evidence', 'preparation-evidence',
               'recovery', 'recovery/r7-candidate', 'wire-r7', 'cli']
for name in directories:
    (ROOT / name).mkdir(mode=0o700)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == raw


identities = dict(pins)
identities.update({str(B3): B3_SHA, str(ARCHIVE): ARCHIVE_SHA, str(MANIFEST): MANIFEST_SHA})
for name, raw, expected in [('B3.image.bin', compiler, B3_SHA),
                            ('e09-program-and-declared-source.tar.xz', archive_raw, ARCHIVE_SHA),
                            ('canonical-e09-development-package.json', manifest_raw, MANIFEST_SHA)]:
    path = ROOT / 'inputs' / name
    create(path, raw)
    identities[str(path)] = expected
for name, item in payload['files'].items():
    path = ROOT / 'control' / name
    create(path, item['source'].encode())
    identities[str(path)] = item['sha256']
for name, item in payload['recovery'].items():
    path = ROOT / 'recovery/r7-candidate' / name
    create(path, item['source'].encode())
    identities[str(path)] = item['sha256']
recovery = {'schema': 'hia.remote-wire-r7-candidate-custody.v1',
            'scope': 'NEW_REMOTE_CANDIDATE_NOT_ORIGINAL_LOCAL_R7_RECOVERY',
            'source_commit': 'aef3b5813aa49b2356fbd4dd7314e40737b3e4cf',
            'files': {name: {'sha256': item['sha256'], 'git_blob': item['blob_sha']}
                      for name, item in payload['recovery'].items()},
            'whole_native_delivery_qualified': False}
create(ROOT/'recovery/r7-candidate/MANIFEST.json',
       (json.dumps(recovery, indent=2, sort_keys=True)+'\n').encode())
config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 1800,
          'command': [str(PYTHON), '-B', str(ROOT/'control/prepare_development_package.py')],
          'cwd': str(ROOT), 'source_identities': identities}
raw = (json.dumps(config, indent=2, sort_keys=True)+'\n').encode()
create(ROOT/'guard/request.json', raw)
intent = {'schema': 'hia.desktop-package-development-preparation-intent.v1',
          'stable_key': STABLE_KEY, 'canonical_commit': HEAD, 'canonical_tree': TREE,
          'package_publication_commit': 'fdb40f161907d0c4722ea14ca933945d33ec4990',
          'root': str(ROOT), 'source': str(ROOT/'s'),
          'wire_candidate_source': str(ROOT/'wire-r7/s'), 'cli_candidate_source': str(ROOT/'cli/s'),
          'capacity_before': {'available_bytes': capacity.f_bavail*capacity.f_frsize,
                              'free_inodes': capacity.f_favail, 'device': parent.st_dev},
          'source_manifest_sha256': MANIFEST_SHA, 'source_archive_sha256': ARCHIVE_SHA,
          'control_files': {name: item['sha256'] for name, item in payload['files'].items()},
          'recovery_files': recovery['files'], 'complete_git_object_closure': False,
          'source_contract_checked_document_current': False, 'network_or_git_requested': False,
          'tests_requested': False, 'qualification_requested': False, 'final_full_root_touched': False,
          'whole_native_delivery_qualified': False, 'outer_guardian_acceptance_required': True,
          'hard_sigkill_or_host_loss_cleanup_claimed': False}
create(ROOT/'launch-intent.json', (json.dumps(intent, indent=2, sort_keys=True)+'\n').encode())
for path in [ROOT/name for name in reversed(directories)] + [ROOT, ROOT.parent]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print(json.dumps({'stage': 'PACKAGE_DEVELOPMENT_PREPARATION_GUARDIAN_LAUNCH',
                  'root': str(ROOT), 'controller_seconds': 1800,
                  'network_or_git_requested': False}), flush=True)
os.execv(str(PYTHON), [str(PYTHON), '-B', str(ROOT/'control/guardian.py'),
                     '--config', str(ROOT/'guard/request.json'),
                     '--config-sha256', sha256(raw).hexdigest(),
                     '--implementation', str(ROOT/'control/process_owner_impl.py')])
