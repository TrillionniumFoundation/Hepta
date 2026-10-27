"""Capture the exact held-canceller boundary before changing the observation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

repo = Path('/workspace/scratch/c7c6ee414a6c/hepta-task-io-fix')
sys.path.insert(0, str(repo))
from tools import qualify_task_io as q

out = Path('/tmp/hepta-task-io-observation-fix-20261027/baseline')
out.mkdir(parents=True, exist_ok=False)
rustc = Path('/tmp/hepta-ai-rust-1.90.0/bin/rustc')
cc = Path(shutil.which('gcc'))

def ident(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def run(name, argv):
    before = time.monotonic_ns()
    value = subprocess.run([str(arg) for arg in argv], cwd=repo, capture_output=True, timeout=30)
    streams = {}
    for channel in ('stdout', 'stderr'):
        path = out / (name + '.' + channel + '.bin')
        path.write_bytes(getattr(value, channel))
        streams[channel] = {**ident(path), 'text': getattr(value, channel).decode('utf-8')}
    return {'command': [str(arg) for arg in argv], 'returncode': value.returncode,
            'elapsed_ns': time.monotonic_ns() - before, **streams}

report = {'schema': 'hepta.task-io-observation-counterexample.v1',
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
    'compiler_sha256': q.compiler_hash(), 'source_files': q.identities(),
    'rustc': ident(rustc), 'cc': ident(cc), 'runs': {}}
report['rustc_version'] = run('rustc-version', [rustc, '--version'])
c_source = out / 'faults.c'
c_source.write_bytes((repo / 'tools/fixtures/task_io_faults.c').read_bytes())
obj = out / 'faults.o'
report['c_build'] = run('compile-c', [cc, *q.C_FLAGS, '-c', c_source, '-o', obj])
assert report['c_build']['returncode'] == 0
render = q.controls_source('positive')
main = 'fn main(){__hepta_task_io_controls("positive")}'
assert render.count(main) == 1
render = render.replace(main, 'fn main(){__hepta_task_io_controls("drop_lock_inversion")}')
predicate = 'assert_eq!(unsafe{hepta_task_io_fd_open(wake_fd)},1);'
assert render.count(predicate) == 1
for name in ('held_arc_boundary', 'unfenced_closed_assertion'):
    source = render
    if name == 'unfenced_closed_assertion':
        source = source.replace(predicate, 'assert_eq!(unsafe{hepta_task_io_fd_open(wake_fd)},0,"unfenced wake reader checked before canceller completion");')
    path, binary = out / (name + '.rs'), out / (name + '.bin')
    path.write_text(source)
    links = ['-C', 'link-arg=' + str(obj), '-C', 'link-arg=-Wl,--wrap=poll',
             '-C', 'link-arg=-Wl,--wrap=socketpair', '-C', 'link-arg=-Wl,--wrap=ioctl']
    build = run(name + '-build', [rustc, *q.RUST_FLAGS, path, '-o', binary, *links])
    assert build['returncode'] == 0
    execution = run(name + '-run', [binary])
    report['runs'][name] = {'source': ident(path), 'binary': ident(binary), 'build': build, 'execution': execution}
    expected = 0 if name == 'held_arc_boundary' else -6
    assert execution['returncode'] == expected
    if expected:
        assert 'unfenced wake reader checked before canceller completion' in execution['stderr']['text']
        assert 'left: 1' in execution['stderr']['text'] and 'right: 0' in execution['stderr']['text']
report['observed_boundary'] = {'held_canceller_arc_wake_fd_open': True,
    'unfenced_closed_assertion_aborted': True, 'after_last_arc_release_fd_and_all_io_reservations_zero': True,
    'scope': 'controlled fixture ordering with original runtime; no resource leak inferred from the early observation'}
(out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'output': str(out / 'report.json'), 'source_commit': report['source_commit'],
    'runs': {name: value['execution']['returncode'] for name, value in report['runs'].items()}}, indent=2))
