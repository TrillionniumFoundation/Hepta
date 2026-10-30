#!/usr/bin/env python3
"""Probe detached stdlib readers; never execute a tar member or native target."""
from hashlib import sha256
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
GUARD = r'''
import os,runpy,sys
def guard(event,args):
    if event == "open" and isinstance(args[0], (str,bytes,os.PathLike)):
        value=os.path.abspath(os.fsdecode(args[0]))
        if value == "/workspace" or value.startswith("/workspace/"):
            raise PermissionError("portable verifier may not open original workspace files")
sys.addaudithook(guard)
target=sys.argv[1]
sys.argv=sys.argv[1:]
runpy.run_path(target,run_name="__main__")
'''


def identity(data):
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def main():
    started = time.monotonic_ns()
    output = HERE / 'portability-attempt-001'
    output.mkdir(exist_ok=False)
    (output / 'workspace_read_guard.py').write_text(GUARD)
    receipt = {'schema': 'hepta.cpp-json-checkpoint.detached-reader-probe.v1',
               'status': 'started', 'stages': [], 'copied_inputs': {},
               'native_model_or_archive_member_execution': False,
               'standalone_reviewed_verifier_scripts_executed': True,
               'original_workspace_open_refused_in_reader_children': True,
               'original_payloads_modified': False}
    try:
        with tempfile.TemporaryDirectory(prefix='hepta-p3-detached-', dir='/tmp') as temporary:
            detached = Path(temporary)
            names = ['verify_evidence.py', 'MANIFEST.json', 'p3-p6-json-checkpoint-953fa62.tar.xz']
            prior_delivery = json.loads((HERE / 'prior-3533/DELIVERY.json').read_bytes())
            names += ['prior-3533/DELIVERY.json', *('prior-3533/' + name for name in prior_delivery['files'])]
            for name in names:
                data = (HERE / name).read_bytes()
                target = detached / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                receipt['copied_inputs'][name] = identity(data)
            commands = [
                ('953', detached, ['verify_evidence.py', '--archive', 'p3-p6-json-checkpoint-953fa62.tar.xz',
                  '--manifest', 'MANIFEST.json', '--archive-sha256', '3702dadead10feafb7de0ad7788aca5f8c4e1ed79d8e434a2bfb6cbdb0b33ad8',
                  '--manifest-sha256', '4d21b4ff124005d40818248e617018441a8a49a473f443979aa5fde92a8658e0',
                  '--prior-directory', 'prior-3533']),
                ('3533', detached / 'prior-3533', ['verify_evidence.py', '--archive', 'p3-p6-json-checkpoint-3533.tar.xz',
                  '--manifest', 'MANIFEST.json', '--archive-sha256', '5e69e0790bead8d54a9c9126b34d8bc7bb8ca7f133a75bfdf905d8d2724e9ace',
                  '--manifest-sha256', '2479de679af9ec53928d4a74dcf565c64f68f48cd020651a88a683457cb6b1d8'])]
            environment = {k: v for k, v in os.environ.items()
                           if k not in {'PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'LD_AUDIT'}}
            for name, cwd, args in commands:
                argv = [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c', GUARD, *args]
                row = {'id': name, 'argv': argv, 'cwd': str(cwd), 'status': 'registered'}
                receipt['stages'].append(row)
                begin = time.monotonic_ns()
                result = subprocess.run(argv, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=60)
                row.update(returncode=result.returncode, wall_ns=time.monotonic_ns() - begin,
                           stdout=identity(result.stdout), stderr=identity(result.stderr),
                           status='completed' if result.returncode == 0 else 'failed')
                (output / (name + '.stdout')).write_bytes(result.stdout)
                (output / (name + '.stderr')).write_bytes(result.stderr)
                if result.returncode != 0:
                    raise RuntimeError('detached reader failed: ' + name)
            receipt['copied_input_bytes'] = sum(row['bytes'] for row in receipt['copied_inputs'].values())
            receipt['status'] = 'completed'
        receipt['temporary_detached_copies_removed'] = True
    except BaseException as error:
        receipt.update(status='failed', error=type(error).__name__ + ': ' + str(error))
    finally:
        receipt['wall_ns'] = time.monotonic_ns() - started
        receipt['cost_scope'] = 'temporary copy, both detached reader waits, raw persistence and temporary cleanup; final receipt write excluded'
        (output / 'EXECUTION.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: receipt.get(key) for key in ('status', 'wall_ns', 'copied_input_bytes', 'error')}, sort_keys=True))
    return 0 if receipt['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
