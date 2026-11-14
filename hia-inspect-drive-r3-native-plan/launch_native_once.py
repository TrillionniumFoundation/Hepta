"""Outer recorder for the uniquely authorized, frozen Source18 launch."""
from pathlib import Path
import hashlib, json, os, stat, subprocess, time, traceback

HERE = Path(__file__).absolute().parent
ROOT = Path('/dev/shm/hia-inspect-drive-r3-dda7')
PINS = {'run_inspect_stages.py': (41247, 'cd9cecf3321a0b7a1e1a8717e08962deeca487e6', 'ed6c75539b02d2d444eb41b69c2df9241c4f35b6a97e5925a311a68a45d683b5'), 'NATIVE-PLAN.json': (74027, '9cb9a6a75238a000a3a723841b478db4424b441d', '74eae79fa8d26b5f6d9e0959adab97303568f415a9071cd44cbbf0c7eef62772'), 'NATIVE-LAUNCH.json': (2604, 'c3f27425d75ecb1fbb46312ef13ada3ed6030cc3', 'f515619f7055db11067edc6ce2085823e9513160fc9da0aeec08feb57d87de7b')}

def seven(value):
    return (value.st_dev, value.st_ino, value.st_nlink, value.st_mode,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def full(path, expected):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o644
    raw = path.read_bytes()
    actual = (len(raw), hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
              hashlib.sha256(raw).hexdigest())
    assert actual == expected and seven(path.lstat()) == seven(before)
    return raw

def write(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)

captured = {name: full(HERE / name, expected) for name, expected in PINS.items()}
launch = json.loads(captured['NATIVE-LAUNCH.json'])
plan = json.loads(captured['NATIVE-PLAN.json'])
assert launch['plan']['pin']['sha256'] == PINS['NATIVE-PLAN.json'][2]
assert launch['runner']['pin']['sha256'] == PINS['run_inspect_stages.py'][2]
assert plan['limits'] == {'qualification_seconds': 180, 'cleanup_seconds': 3, 'minimum_free_bytes': 1073741824}
assert plan['active_phase'] == 'native-vm' and plan['source_predecessor'] == launch['actual_Source18_result']
assert plan['source_predecessor']['pin']['git_blob'] == '66a7fcb126e87224d171b6869be08e28e2d1cec6'
assert launch['Native_declared'] == 17 and launch['VM_declared'] == 12 and launch['owner_count'] == 10
assert launch['compile_declared'] == 1 and launch['Source_old3_CLI43_generation_declared'] == 0
assert launch['evidence_authority'] == plan['evidence_authority']
assert ROOT.resolve(strict=True) == ROOT
fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    current, named, space = os.fstat(fd), ROOT.lstat(), os.fstatvfs(fd)
    authority = {'schema': plan['evidence_authority']['schema'], 'path': str(ROOT),
                 'device': current.st_dev, 'inode': current.st_ino, 'mode': stat.S_IMODE(current.st_mode),
                 'uid': current.st_uid, 'gid': current.st_gid}
    assert seven(current) == seven(named) and authority == plan['evidence_authority']
    assert not (space.f_flag & os.ST_NOEXEC)
    available = space.f_bavail * space.f_frsize
    assert available >= 1073741824
finally:
    os.close(fd)
attempt, outer = Path(plan['attempt']), Path(launch['outer_directory'])
assert attempt == ROOT / 'native-vm-attempt-r1' and outer == ROOT / 'native-vm-outer-r1'
assert not os.path.lexists(attempt) and not os.path.lexists(outer)
assert not Path('/workspace/scratch/dda74a4fae35/v132-inspect-machine-entry-r1/successor-r2/source-controls-attempt-r1').exists()
outer.mkdir(mode=0o700)
started = time.time_ns()
record = {'schema': 'hepta.hia.inspect-drive-r3-native-outer.v1', 'status': 'FAIL',
          'argv': launch['argv'], 'cwd': launch['cwd'], 'launch_git': PINS['NATIVE-LAUNCH.json'][1],
          'plan_sha256': PINS['NATIVE-PLAN.json'][2], 'started_ns': started,
          'output_filesystem': authority, 'entry_available_bytes': available,
          'qualification_seconds_per_owner': 180, 'cleanup_seconds_per_owner': 3,
          'automatic_retry': False, 'allowed_maximum_counts': {'compile': 1, 'Native': 17, 'VM': 12, 'owners': 10}, 'returncode': None,
          'separate_parent_execution_authorization_required': True}
write(outer / 'STARTED.json', record)
process = None
try:
    with (outer / launch['outer_stdout']).open('xb') as out, (outer / launch['outer_stderr']).open('xb') as err:
        process = subprocess.Popen(launch['argv'], cwd=launch['cwd'], stdout=out, stderr=err)
        record['pid'] = process.pid
        write(outer / 'PROCESS.json', {'pid': process.pid, 'observed_ns': time.time_ns(), 'argv': launch['argv']})
        print(json.dumps({'phase': 'NATIVE_VM_STARTED', 'pid': process.pid, 'outer': str(outer), 'entry_available_bytes': available}), flush=True)
        record['returncode'] = process.wait()
    if record['returncode'] == 0:
        record['status'] = 'OUTER_EXIT_ZERO'
except BaseException:
    record['traceback'] = traceback.format_exc()
    if process is not None and process.poll() is None:
        record['returncode'] = process.wait()
finally:
    record['finished_ns'] = time.time_ns()
    record['elapsed_ns'] = record['finished_ns'] - started
    record['stdout'] = {}
    for key in ('outer_stdout', 'outer_stderr'):
        path = outer / launch[key]
        if path.exists():
            raw = path.read_bytes()
            record[key] = {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    write(outer / launch['outer_result'], record)
print(json.dumps({'phase': 'NATIVE_VM_TERMINAL', 'status': record['status'], 'returncode': record['returncode'],
                  'elapsed_ns': record['elapsed_ns'], 'outer': str(outer)}), flush=True)
raise SystemExit(0 if record['status'] == 'OUTER_EXIT_ZERO' else 1)
