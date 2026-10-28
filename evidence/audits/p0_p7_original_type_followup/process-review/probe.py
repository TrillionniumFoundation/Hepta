#!/usr/bin/env python3
"""Small process-budget probes. Fixture executables are not compiler evidence."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/tmp/hepta-vla-resource-review-20261028')
REPO = Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
sys.path.insert(0, str(REPO))
from hepta.clang_capture import CaptureRejected, run_bounded


def main():
    root = ROOT
    helper = REPO / 'hepta/c_parameter_types.py'
    executable = Path(sys.executable).resolve()
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    loader = ('import json,runpy,sys; '
              'module=runpy.run_path(sys.argv[1],run_name="isolated_probe"); '
              'module["_emit_ast"](json.loads(sys.stdin.buffer.read()))')
    results = []
    for mode in ('success', 'timeout'):
        observation = root / (mode + '-process.json')
        delayed = root / (mode + '-surviving-child.txt')
        code = (
            'import json,os,resource,time,pathlib; '
            'child=os.fork(); '
            'data={"pid":os.getpid(),"pgid":os.getpgrp(),"child":child,'
            '"rlimit_as":resource.getrlimit(resource.RLIMIT_AS),'
            '"rlimit_fsize":resource.getrlimit(resource.RLIMIT_FSIZE)}; '
            f'pathlib.Path({str(observation)!r}).write_text(json.dumps(data)) if child else None; '
            f'time.sleep(1) if child==0 else None; '
            f'pathlib.Path({str(delayed)!r}).write_text("survived") if child==0 else None; '
            f'time.sleep(5) if child and {mode!r}=="timeout" else None'
        )
        request = {
            'compiler': {'path': str(executable), 'executable_sha256': executable_sha},
            'directory': str(root), 'arguments': ['-c', code],
            'source_argument': 'fixture.c',
            'argv': [str(executable), '-c', code, '-Werror', '-emit-ast', 'fixture.c', '-o', str(root / (mode + '-unused.ast'))],
        }
        command = [str(executable), '-I', '-B', '-c', loader, str(helper)]
        try:
            response = run_bounded(command, cwd=root, input_text=json.dumps(request),
                                   timeout=.25 if mode == 'timeout' else 3,
                                   stdin_limit=8000000, stdout_limit=1000000, stderr_limit=1000000)
            outcome = {'returncode': response.returncode, 'stdout': response.stdout, 'stderr': response.stderr}
        except CaptureRejected as error:
            outcome = {'code': error.code, 'message': str(error),
                       'returncode': error.capture.returncode if error.capture else None}
        time.sleep(1.1)
        observed = json.loads(observation.read_text())
        assert observed['rlimit_as'] == [2147483648, 2147483648]
        assert observed['rlimit_fsize'] == [32000000, 32000000]
        assert observed['pid'] == observed['pgid'], observed
        assert observed['child'] > 0
        assert not delayed.exists(), 'Descendant survived ' + mode
        if mode == 'timeout':
            assert outcome['code'] == 'E_CAPTURE_TIMEOUT'
        else:
            assert outcome['returncode'] == 0
        results.append({'mode': mode, 'observed': observed, 'outcome': outcome,
                        'delayed_descendant_marker_exists': delayed.exists(),
                        'scope': 'Actual _emit_ast execv and actual run_bounded cleanup, with a tiny Python fixture in place of the compiler.'})
    head = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'], text=True)
    result = {'schema': 'hepta.audit.vla-process-budget-probes.v1', 'status': 'passed',
              'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'reviewed_commit': head, 'tracked_worktree_dirty': bool(dirty.strip()),
              'helper_path': str(helper), 'helper_sha256': hashlib.sha256(helper.read_bytes()).hexdigest(),
              'capture_path': str(REPO/'hepta/clang_capture.py'),
              'capture_sha256': hashlib.sha256((REPO/'hepta/clang_capture.py').read_bytes()).hexdigest(),
              'results': results, 'compiler_semantics_qualified': False,
              'large_suite_executed': False, 'performance_experiment_executed': False}
    with (root/'report.json').open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'modes': [r['mode'] for r in results],
                      'report': str(root/'report.json'), 'commit': head, 'dirty': bool(dirty.strip())}))


if __name__ == '__main__':
    main()
