"""Launch exactly one frozen Core development phase with the unchanged 180-second owner."""
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

encoded = sys.stdin.buffer.read(1048577)
if len(encoded) > 1048576:
    raise ValueError('request exceeds the original stdin bound')
payload = json.loads(encoded)
request = payload['request']
phase = request['phase']
roots = {
    'prepare': '/home/qian-qi/he26corelowering-native-r1',
    'component': '/home/qian-qi/he26corelowering-component-r1',
    'original-machine': '/home/qian-qi/he26corelowering-machine-callers-r1',
    'original-core': '/home/qian-qi/he26corelowering-core-callers-r1',
}
if phase not in roots or request['root'] != roots[phase]:
    raise ValueError('fixed development phase/root differs')
if (request['schema'] != 'hia.core-lowering-owned-development-request.v1'
        or request['candidate_commit'] != '9b350732ce1dac60ec5689838ab80b853d700751'
        or request['candidate_tree'] != '7191e2e9926d0c1f653e775e891c35d48efeb46f'
        or request['candidate_leaf_count'] != 3984
        or request['qualification_seconds'] != 180 or request['cleanup_seconds'] != 3
        or request['compile_wall_seconds'] != 20 or request['compile_CPU_seconds'] != 10
        or request['matching_current_cold'] is not False):
    raise ValueError('frozen identity, original limits, or development scope differs')
actual = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
if sha256(actual).hexdigest() != request['bootstrap_sha256']:
    raise ValueError('actual launcher source differs')
binary = Path(sys.executable).resolve()
if sha256(binary.read_bytes()).hexdigest() != request['python_binary_sha256']:
    raise ValueError('actual interpreter binary differs')
files = {}
for key, name in [('common', 'development_common.py'), ('worker', 'worker.py')]:
    raw = payload[key].encode()
    identity = request[key]
    git_blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if (len(raw) != identity['bytes'] or sha256(raw).hexdigest() != identity['sha256']
            or git_blob != identity['git_blob']):
        raise ValueError('frozen control source differs: ' + key)
    files[name] = raw
if phase == 'prepare':
    expected = {r['path']: r for r in request['core_overlay'] if r['origin'] == 'stdin'}
    if set(payload['source_files']) != set(expected):
        raise ValueError('inline source population differs')
    for name, text in payload['source_files'].items():
        raw = text.encode()
        identity = expected[name]
        git_blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if (len(raw) != identity['bytes'] or sha256(raw).hexdigest() != identity['sha256']
                or git_blob != identity['git_blob']):
            raise ValueError('inline candidate source differs: ' + name)
else:
    if payload['source_files'] or not request.get('preparation_job_id') or not request.get('input_bindings'):
        raise ValueError('actual completed preparation bindings are required before group root creation')
    for identity in request['input_bindings']:
        path = Path(identity['path'])
        info = path.lstat()
        raw = path.read_bytes()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or len(raw) != identity['bytes'] or sha256(raw).hexdigest() != identity['sha256']
                or stat.S_IMODE(info.st_mode) != identity['posix_mode']
                or sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != identity['git_blob']):
            raise ValueError('actual preparation input changed before group launch')
owner = Path('/home/qian-qi/he26v67r2/s/tools/hia_selfhost_process_owner.py')
owner_raw = owner.read_bytes()
if sha256(owner_raw).hexdigest() != request['owner_sha256']:
    raise ValueError('unchanged process owner differs')
root = Path(request['root'])
root.mkdir(mode=0o700)
for name, raw in files.items():
    (root / name).write_bytes(raw)
(root / 'launch-payload.original.json').write_bytes(encoded)
(root / 'request.json').write_text(json.dumps(request, sort_keys=True, indent=2) + '\n')
(root / 'source-files.json').write_text(json.dumps(payload['source_files'], sort_keys=True) + '\n')
(root / 'tmp').mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location('_hia_original_process_owner', owner)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.insert(0, str(root))
from development_common import natural_owner, save
env = {
    'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
    'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
    'TMPDIR': str(root / 'tmp'),
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
}
started = time.monotonic()
life = module.run_owned(
    [sys.executable, '-B', str(root / 'worker.py'), str(root)],
    cwd=root, env=env, stdout_path=root / 'child.stdout', stderr_path=root / 'child.stderr',
    receipt_path=root / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
natural = natural_owner(life)
okay = (natural and life.get('status') == 'OWNED_PROCESS_COMPLETED'
        and life.get('returncode') == 0)
expected = ('EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED' if phase == 'prepare'
            else 'EXPLICIT_DEVELOPMENT_GROUP_PASS_NOT_COMPLETE_QUALIFICATION')
inner_path = root / 'report.json'
inner_raw = inner_path.read_bytes() if inner_path.is_file() else None
try:
    inner = json.loads(inner_raw) if inner_raw is not None else None
except (ValueError, UnicodeError):
    inner = None
stable = owner.read_bytes() == owner_raw
result = {
    'schema': 'hia.core-lowering-owned-development.v1',
    'status': 'PASS' if okay and inner and inner.get('status') == expected and stable else 'HOLD',
    'scope': 'EXPLICIT_DEVELOPMENT_ONLY', 'phase': phase,
    'candidate_commit': request['candidate_commit'], 'candidate_tree': request['candidate_tree'],
    'lifecycle': life, 'natural_owner_cleanup': natural, 'natural_owner_success': okay,
    'inner_status': inner.get('status') if inner else None,
    'inner_report_sha256': sha256(inner_raw).hexdigest() if inner_raw is not None else None,
    'seconds': time.monotonic() - started, 'owner_source_stable': stable,
    'matching_current_cold': False, 'whole_native_delivery': False, 'default_activated': False,
    'default_complete_qualifier_executed': False, 'default_180_second_qualification_pass': False,
    'original_compile_wall_seconds': 20, 'original_compile_CPU_seconds': 10,
    'original_owner_wall_seconds': 180, 'original_cleanup_seconds': 3,
    'original_caller_budgets_unchanged': True,
}
save(root, 'control.json', result)
print(json.dumps({k: result[k] for k in (
    'status', 'scope', 'phase', 'natural_owner_cleanup', 'natural_owner_success',
    'inner_status', 'seconds')}, sort_keys=True), flush=True)
raise SystemExit(0 if result['status'] == 'PASS' else 1)
