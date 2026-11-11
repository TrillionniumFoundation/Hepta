"""Run every actual workflow generator against this explicit integration state."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).with_name('generators-r1')


def snapshot():
    raw = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z'])
    files = {}
    absent = []
    for name in raw.decode().split('\0'):
        if not name:
            continue
        path = ROOT / name
        if path.is_file() and not path.is_symlink():
            files[name] = sha256(path.read_bytes()).hexdigest()
        else:
            absent.append(name)
    return {'materialized_tracked_regular_files': files, 'absent_or_nonregular_index_paths': absent}


def main():
    OUT.mkdir(exist_ok=False)
    workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
    match = re.findall(r'for component in ([^;\n]+); do', workflow)
    if len(match) != 1:
        raise ValueError('expected one actual workflow generator list')
    components = match[0].split()
    before = snapshot()
    (OUT / 'before.json').write_text(json.dumps(before, indent=2, sort_keys=True) + '\n')
    steps = []
    started = time.monotonic_ns()
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for component in components:
        command = [sys.executable, '-B', '-m', 'tools.generate_hia_' + component]
        step_started = time.monotonic_ns()
        child = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, timeout=180)
        for kind in ('stdout', 'stderr'):
            (OUT / (component + '.' + kind + '.log')).write_bytes(getattr(child, kind))
        steps.append({'component': component, 'command': command,
                      'returncode': child.returncode, 'elapsed_ns': time.monotonic_ns() - step_started,
                      'stdout_sha256': sha256(child.stdout).hexdigest(),
                      'stderr_sha256': sha256(child.stderr).hexdigest()})
        if child.returncode:
            break
    after = snapshot()
    (OUT / 'after.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n')
    passed = (bool(components) and len(steps) == len(components)
              and all(row['returncode'] == 0 for row in steps) and before == after)
    report = {'schema': 'hepta.hia.v66-generator-controls.v1',
              'scope': 'ACTUAL_WORKFLOW_GENERATORS_NOT_COLD_OR_FULL_QUALIFICATION',
              'status': 'PASS' if passed else 'FAIL_OR_INCOMPLETE',
              'head': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
              'tracked_worktree_changes': subprocess.check_output(['git', '-C', str(ROOT), 'diff', '--name-only'], text=True).splitlines(),
              'workflow_sha256': sha256(workflow.encode()).hexdigest(),
              'loaded_components': components, 'steps': steps,
              'all_materialized_tracked_bytes_preserved': before == after,
              'elapsed_ns': time.monotonic_ns() - started,
              'python': sys.version,
              'whole_native_delivery_qualified': False}
    (OUT / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'elapsed_ns', 'all_materialized_tracked_bytes_preserved')}, sort_keys=True))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
