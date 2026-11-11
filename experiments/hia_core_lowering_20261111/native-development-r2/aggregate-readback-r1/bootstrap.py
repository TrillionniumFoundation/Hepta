"""Freeze one read-only aggregate of the three actual Core development originals.

This process does not compile or run product tests. It verifies already-recorded
bytes and writes a new derived receipt under a create-only private root.
"""
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import traceback

ROOT = Path('/home/qian-qi/he26corelowering-aggregate-r1')
SOURCE = '9b350732ce1dac60ec5689838ab80b853d700751'
TREE = '7191e2e9926d0c1f653e775e891c35d48efeb46f'
OWNER = Path('/home/qian-qi/he26v67r2/s/tools/hia_selfhost_process_owner.py')
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
GROUP_ROOTS = {
    'component': '/home/qian-qi/he26corelowering-component-r1',
    'original-machine': '/home/qian-qi/he26corelowering-machine-callers-r1',
    'original-core': '/home/qian-qi/he26corelowering-core-callers-r1',
}
NAMES = {'control.json', 'report.json', 'lifecycle.json', 'request.json',
         'qualifier/report.json', 'source-before.json', 'source-after.json'}

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def original(pin):
    path = Path(pin['path'])
    info = path.lstat()
    raw = path.read_bytes()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == pin['posix_mode']
            and identity(raw) == {k: pin[k] for k in ('bytes', 'sha256', 'git_blob')},
            'original aggregate input differs: ' + str(path))
    return raw

encoded = sys.stdin.buffer.read(1048577)
require(len(encoded) <= 1048576, 'aggregate control stdin exceeded original bound')
payload = json.loads(encoded)
request = payload['request']
require(request['schema'] == 'hia.core-lowering-development-aggregate-request.v1'
        and request['candidate_commit'] == SOURCE and request['candidate_tree'] == TREE
        and request['root'] == str(ROOT)
        and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
        and request['matching_source_cold'] is False
        and request['single_complete_180_qualification'] is False,
        'aggregate source, scope, or unchanged owner limits differ')
actual = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
require(sha256(actual).hexdigest() == request['bootstrap_sha256'],
        'actual aggregate bootstrap differs')
require(sha256(Path(sys.executable).resolve().read_bytes()).hexdigest() == PYTHON_SHA,
        'actual interpreter identity differs')
owner_raw = OWNER.read_bytes()
require(sha256(owner_raw).hexdigest() == OWNER_SHA, 'unchanged original owner differs')
require([p['group'] for p in request['phases']] == list(GROUP_ROOTS),
        'all three development groups are required')
for phase in request['phases']:
    root = Path(GROUP_ROOTS[phase['group']])
    require(phase['root'] == str(root) and phase['job_id'], 'actual original phase identity differs')
    require(len(phase['files']) == 7, 'exact original receipt population required')
    names = set()
    for pin in phase['files']:
        path = Path(pin['path'])
        require(root in path.parents, 'original phase input escapes its fixed root')
        names.add(path.relative_to(root).as_posix())
        original(pin)
    require(names == NAMES, 'exact seven original receipt names differ')
files = {}
for key, filename in [('common', 'development_common.py'), ('aggregate', 'aggregate.py')]:
    raw = payload[key].encode()
    require(identity(raw) == request[key], 'frozen aggregate controller differs: ' + key)
    files[filename] = raw
os.umask(0o077)
ROOT.mkdir(mode=0o700)
for filename, raw in files.items():
    with (ROOT / filename).open('xb') as stream:
        stream.write(raw)
with (ROOT / 'launch-payload.original.json').open('xb') as stream:
    stream.write(encoded)
with (ROOT / 'request.json').open('xb') as stream:
    stream.write(wire(request))
(ROOT / 'tmp').mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location('_hia_original_process_owner', OWNER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.insert(0, str(ROOT))
from development_common import natural_owner

started = time.monotonic()
result = {
    'schema': 'hia.core-lowering-owned-aggregate-readback.v1',
    'status': 'HOLD', 'scope': 'READ_ONLY_DEVELOPMENT_ORIGINALS',
    'candidate_commit': SOURCE, 'candidate_tree': TREE,
    'product_tests_repeated': False, 'source_generation_repeated': False,
    'native_compilation_repeated': False,
    'single_default_qualifier_executed': False,
    'default_complete_qualifier_once_180_seconds_pass': False,
    'matching_source_cold_qualified': False,
    'whole_native_delivery': False, 'default_activated': False,
    'original_owner_wall_seconds': 180, 'original_cleanup_seconds': 3,
}
try:
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
        'TMPDIR': str(ROOT / 'tmp'),
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    }
    life = module.run_owned(
        [sys.executable, '-B', str(ROOT / 'aggregate.py'),
         '--request', str(ROOT / 'request.json'), '--output', str(ROOT / 'result')],
        cwd=ROOT, env=env, stdout_path=ROOT / 'child.stdout', stderr_path=ROOT / 'child.stderr',
        receipt_path=ROOT / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
    result['lifecycle'] = life
    require(natural_owner(life) and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0 and life.get('supervisor_returncode') == 0,
            'aggregate owner did not finish naturally')
    inner_raw = (ROOT / 'result/report.json').read_bytes()
    inner = json.loads(inner_raw)
    result['inner_report'] = {'path': str(ROOT / 'result/report.json'), **identity(inner_raw)}
    require(inner.get('status') == 'EXPLICIT_DEVELOPMENT_THREE_GROUPS_PASS_NOT_COLD_QUALIFIED'
            and inner.get('actual_methods') == 113
            and len(inner.get('actual_modes', [])) == 28
            and inner.get('candidate_commit') == SOURCE and inner.get('candidate_tree') == TREE
            and inner.get('single_default_qualifier_executed') is False
            and inner.get('default_complete_qualifier_once_180_seconds_pass') is False
            and inner.get('matching_source_cold_qualified') is False,
            'complete actual development aggregate differs')
    for phase in request['phases']:
        for pin in phase['files']:
            original(pin)
    require(OWNER.read_bytes() == owner_raw, 'original owner changed')
    require(all((ROOT / name).read_bytes() == raw for name, raw in files.items()),
            'aggregate controller source changed')
    require((ROOT / 'request.json').read_bytes() == wire(request)
            and (ROOT / 'launch-payload.original.json').read_bytes() == encoded,
            'aggregate frozen request changed')
    for key in ('actual_methods', 'actual_modes', 'actual_native_step_statuses',
                'actual_owner_seconds_sum', 'actual_qualifier_seconds_sum', 'readback_seconds'):
        result[key] = inner[key]
    result['originals_stable'] = True
    result['status'] = 'READ_ONLY_DEVELOPMENT_AGGREGATE_PASS'
except BaseException:
    result['status'] = 'HOLD'
    result['exception'] = traceback.format_exc()
finally:
    result['seconds'] = time.monotonic() - started
    with (ROOT / 'control.json').open('xb') as stream:
        stream.write(wire(result))
    print(json.dumps({k: result.get(k) for k in (
        'schema', 'status', 'scope', 'actual_methods', 'actual_native_step_statuses',
        'actual_owner_seconds_sum', 'actual_qualifier_seconds_sum', 'seconds',
        'exception')}, sort_keys=True), flush=True)
raise SystemExit(0 if result['status'] == 'READ_ONLY_DEVELOPMENT_AGGREGATE_PASS' else 1)
