"""Replay all completed edit panels against the newly composed actual ELF."""
from hashlib import sha256
import json
from pathlib import Path
import resource
import subprocess
import time
import traceback
import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
OUT = ROOT / 'development/retained-complete-replay-r1'
OUT.mkdir(exist_ok=False)
EMPTY = OUT / 'empty'
EMPTY.mkdir()
bundle_path = ROOT / 'development/build-r2/bundle.json'
bundle_raw = bundle_path.read_bytes()
bundle = json.loads(bundle_raw)
assert bundle['status'] == 'PASS'
exe = Path(bundle['executable']['path'])
exe_raw = exe.read_bytes()
assert sha256(exe_raw).hexdigest() == bundle['executable']['sha256']
FIXTURES = BASE.parent / 'application-reference-r1/fixtures/native-edit-apply-next/development'
restore_path = BASE.parent / 'application-reference-r1/restore.json'
restore_raw = restore_path.read_bytes()
assert json.loads(restore_raw)['status'] == 'PASS'
panels = [FIXTURES / 'complete-native-r1', FIXTURES / 'complete-native-panel-r2',
    BASE / 'native-edit-json-next/development/json-native-r2',
    BASE / 'native-edit-json-next/development/raw-prefix-native-r1']
pins = {Path(__file__): Path(__file__).read_bytes(), bundle_path: bundle_raw, exe: exe_raw, restore_path: restore_raw}
rows = []
started = time.monotonic_ns()
summary = dict(status='INCOMPLETE', scope='ACTUAL_NATIVE_RETAINED_87_EDIT_CASES_WITH_CANDIDATE_SNAPSHOT_AND_BYTE_LIMIT_WITNESSES',
               whole_stack_closed=False, cold_qualification=False, host_semantic_runtime=False)


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


try:
    for panel in panels:
        original_summary = (panel / 'summary.json').read_bytes()
        assert json.loads(original_summary)['status'] == 'PASS'
        pins[panel / 'summary.json'] = original_summary
        for original in sorted(panel.glob('case-*')):
            raw = (original / 'input.bin').read_bytes()
            expected_stdout = (original / 'stdout.bin').read_bytes()
            expected_stderr = (original / 'stderr.bin').read_bytes()
            original_process = json.loads((original / 'process.json').read_text())
            expected_exit = original_process.get('returncode', original_process.get('exitcode'))
            assert expected_exit in (0, 2), (original, original_process)
            case = OUT / ('case-' + str(len(rows)).zfill(3))
            case.mkdir()
            source_pins = {p.name: dict(bytes=p.stat().st_size, sha256=sha256(p.read_bytes()).hexdigest())
                           for p in original.iterdir() if p.is_file()}
            start = time.monotonic_ns()
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            done = subprocess.run([str(exe)], input=raw, capture_output=True, cwd=EMPTY,
                                  env={'PATH': str(EMPTY), 'HOME': str(EMPTY), 'LANG': 'C'},
                                  preexec_fn=limits, timeout=180)
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            (case / 'stdout.bin').write_bytes(done.stdout)
            (case / 'stderr.bin').write_bytes(done.stderr)
            row = dict(original_case=str(original), original_files=source_pins,
                       actual_exitcode=done.returncode, expected_exitcode=expected_exit,
                       wall_ns=time.monotonic_ns()-start,
                       child_cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                       stdout_bytes=len(done.stdout), stdout_sha256=sha256(done.stdout).hexdigest(),
                       stderr_bytes=len(done.stderr), stderr_sha256=sha256(done.stderr).hexdigest(),
                       full_stdout_equal=done.stdout == expected_stdout,
                       full_stderr_equal=done.stderr == expected_stderr,
                       source_before_after_equal=all((original / name).stat().st_size == pin['bytes'] and
                           sha256((original / name).read_bytes()).hexdigest() == pin['sha256'] for name, pin in source_pins.items()))
            (case / 'observed.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
            assert row['source_before_after_equal']
            assert done.returncode == expected_exit and row['full_stdout_equal'] and row['full_stderr_equal'], row
            row['status'] = 'PASS'
            rows.append(row)
            print(json.dumps({k: v for k, v in row.items() if k != 'original_files'}, sort_keys=True), flush=True)
    assert len(rows) == 87, len(rows)
    summary.update(status='PASS', case_count=len(rows), results=rows)
except BaseException as exc:
    summary.update(status='FAIL', completed_cases=rows, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary.update(elapsed_ns=time.monotonic_ns()-started, source_before_after_equal=all(p.read_bytes() == raw for p, raw in pins.items()),
                   cpu_limit_s=90, address_space_limit_bytes=1 << 30, per_case_wall_timeout_s=180,
                   bundle_sha256=sha256(bundle_raw).hexdigest(), executable_sha256=sha256(exe_raw).hexdigest())
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('results', 'completed_cases')}, sort_keys=True), flush=True)
    assert summary['source_before_after_equal']
