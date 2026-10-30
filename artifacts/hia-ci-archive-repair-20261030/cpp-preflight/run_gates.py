"""Replay exactly four existing C++ CI qualifications against one Git checkout."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

OUT = Path(__file__).resolve().parent
BASE = Path('/dev/shm/hepta-convergence-793cbcdf54ed/cpp-postgate-46d88')
SOURCE = BASE / 'source'
REVISION = '46d88bd18b1b3dadb246e92eb22c49fe44ec2d72'
RUSTC = '/workspace/scratch/cd43ab608057/toolchains/rust-1.90.0/bin/rustc'
ENV = os.environ.copy()
ENV.update(HEPTA_RUN_ARTIFACT_SESSION='1', HEPTA_SOURCE_SHA=REVISION,
           CLANG='/usr/bin/clang-20', CLANGXX='/usr/bin/clang++-20',
           HEPTA_CLANG='/usr/bin/clang-20', RUSTC=RUSTC,
           PYTHONDONTWRITEBYTECODE='1', GIT_NO_LAZY_FETCH='1',
           PYTHONPATH=str(SOURCE))
ENV['PATH'] = str(Path(RUSTC).parent) + ':/usr/lib/llvm-20/bin:' + ENV['PATH']


def checked(argv):
    return subprocess.check_output(argv, cwd=SOURCE, env=ENV, text=True).strip()


def bindings():
    rows = checked(['git', 'ls-files', '--stage', 'hepta', 'tools', 'examples'])
    out = {}
    for row in rows.splitlines():
        prefix, name = row.split('\t', 1)
        mode, git_hash, stage = prefix.split()
        path = SOURCE / name
        raw = path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if actual != git_hash or stage != '0':
            raise RuntimeError(f'Checkout bytes differ from fixed Git source: {name}')
        out[name] = {'git_blob': git_hash, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    return out


def main():
    assert checked(['git', 'rev-parse', 'HEAD']) == REVISION
    assert not checked(['git', 'status', '--porcelain'])
    before = bindings()
    (OUT / 'source-bindings.json').write_text(json.dumps(before, indent=2, sort_keys=True) + '\n')
    identities = {}
    for name, argv in {'python': [sys.executable, '--version'],
                       'clang': ['/usr/bin/clang-20', '--version'],
                       'clangxx': ['/usr/bin/clang++-20', '--version'],
                       'gcc': ['gcc', '--version'], 'g++': ['g++', '--version'],
                       'rustc': [RUSTC, '-vV']}.items():
        identities[name] = {'command': argv, 'version': checked(argv)}
    rows = []
    result = {'schema': 'hepta.cpp-ci-postgate-replay.v1', 'source_commit': REVISION,
              'source_tree': checked(['git', 'rev-parse', 'HEAD^{tree}']),
              'scope': 'Four existing step-21 CI qualifications; no formal-study rerun or changed budget.',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'toolchains': identities, 'runs': rows, 'source_bindings_unchanged': None,
              'all_passed': False}
    gates = [('cpp-scoped', 'tools/qualify_cpp_scoped_ownership.py', ['--rustc', RUSTC]),
             ('cpp-composed-project', 'tools/qualify_cpp_composed_project.py', []),
             ('cpp-unique-project', 'tools/qualify_cpp_unique_project.py', []),
             ('cpp-unique-assignment-project', 'tools/qualify_cpp_unique_assignment_project.py', [])]
    for name, script, extra in gates:
        target = BASE / name
        argv = [sys.executable, script, '--workdir', str(target),
                '--clangxx', '/usr/bin/clang++-20', '--clang', '/usr/bin/clang-20',
                *extra, '--cc', 'gcc']
        row = {'name': name, 'command': argv, 'cwd': str(SOURCE), 'workdir': str(target),
               'returncode': None, 'qualification_ok': None}
        rows.append(row)
        print(json.dumps({'event': 'start', 'name': name}), flush=True)
        start = time.perf_counter_ns()
        with (OUT / (name + '.stdout.log')).open('wb') as stdout, (OUT / (name + '.stderr.log')).open('wb') as stderr:
            process = subprocess.run(argv, cwd=SOURCE, env=ENV, stdout=stdout, stderr=stderr)
        row.update(returncode=process.returncode, elapsed_ns=time.perf_counter_ns()-start)
        report = target / 'qualification.json'
        if report.exists():
            saved = OUT / (name + '.qualification.json')
            shutil.copyfile(report, saved)
            record = json.loads(report.read_text())
            row.update(qualification_ok=record.get('ok'), error=record.get('error'),
                       report=saved.name, report_sha256=hashlib.sha256(saved.read_bytes()).hexdigest(),
                       status=record.get('status'), case_count=record.get('case_count'),
                       variants=[{'name': v.get('name'), 'case_count': v.get('case_count')}
                                 for v in record.get('variants', [])],
                       negative_control_names=list(record.get('negative_controls', {})))
        else:
            row['error'] = 'No qualification report produced; see retained stdout/stderr.'
        (OUT / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'event': 'complete', **row}), flush=True)
    result['source_bindings_unchanged'] = bindings() == before
    result['final_tracked_status'] = checked(['git', 'status', '--porcelain', '--untracked-files=no'])
    result['all_passed'] = all(row['returncode'] == 0 and row['qualification_ok'] is True for row in rows)
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (OUT / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'event': 'finished', 'all_passed': result['all_passed'],
                      'source_bindings_unchanged': result['source_bindings_unchanged']}), flush=True)
    return 0 if result['all_passed'] and result['source_bindings_unchanged'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
