"""Native compilation and private out-of-process scoring for paired tasks."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import platform

import hepta
from hepta.backend import find_rustc, toolchain_info
from hepta.pipeline import compiler_hash

from .tasks import ROOT, TASK_IDS, digest, materialize
from .sandbox import run_bounded
from ._private.oracles import expected, hidden_cases


def compiler_identity(rustc=None):
    path = find_rustc(rustc)
    gcc = shutil.which('gcc')
    return {'rustc': toolchain_info(path), 'hepta_compiler_sha256': compiler_hash(),
            'gcc_path': gcc, 'gcc_executable_sha256': digest(Path(gcc).read_bytes()) if gcc else None,
            'python_version': platform.python_version(), 'system': platform.system(),
            'architecture': platform.machine(),
            'native_profile': {'edition': '2021', 'opt_level': 3, 'overflow_checks': True,
                               'panic': 'abort', 'codegen_units': 1,
                               'candidate_paths_remapped_to': '/candidate'}}


def compile_candidate(request, body, directory: Path, *, rustc=None, fixture=False, timeout=30.0):
    deadline = time.monotonic() + timeout
    source = materialize(request, body)
    selected = Path(find_rustc(rustc)).resolve()
    rust_source = source
    if request['language'] == 'hepta':
        # Bound frontend CPU, memory, and wall time too. Only the compiler package
        # enters this capsule; private tests and oracle code never do.
        shutil.copytree(Path(hepta.__file__).parent, directory / 'hepta',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(ROOT / '_frontend.py', directory / 'frontend.py')
        (directory / 'candidate.hepta').write_text(source)
        frontend = run_bounded([sys.executable, str(directory / 'frontend.py')], cwd=directory,
                               timeout=max(0.001, deadline - time.monotonic()), fixture=fixture,
                               max_output=1024**2)
        if frontend['returncode'] or frontend['status'] != 'exited':
            return {'ok': False, 'stage': 'frontend', 'status': frontend['status'],
                    'diagnostics': frontend['stderr'][:32768]}
        try:
            checked = json.loads(frontend['stdout'])
        except ValueError:
            return {'ok': False, 'stage': 'frontend', 'diagnostics': 'invalid frontend response'}
        if not checked['ok']:
            return {'ok': False, 'stage': 'frontend', 'diagnostics': checked['diagnostics']}
        rust_source = checked['rust']
    if time.monotonic() >= deadline:
        return {'ok': False, 'stage': 'compile', 'status': 'timeout', 'diagnostics': 'shared tool deadline exhausted'}
    rust_path = directory / 'candidate.rs'
    rust_path.write_text(rust_source)
    library = directory / 'candidate.a'
    compile_run = run_bounded([str(selected), '--crate-name', 'agent_candidate', '--crate-type', 'staticlib',
                              '--edition', '2021', '-C', 'opt-level=3', '-C', 'overflow-checks=yes',
                              '-C', 'panic=abort', '-C', 'codegen-units=1',
                              '--remap-path-prefix', str(directory) + '=/candidate',
                              str(rust_path), '-o', str(library)],
                             cwd=directory, timeout=max(0.001, deadline - time.monotonic()), fixture=fixture,
                             read_only=[selected.parent.parent], max_output=1024**2)
    if compile_run['returncode'] or compile_run['status'] != 'exited' or not library.is_file():
        return {'ok': False, 'stage': 'rustc', 'status': compile_run['status'],
                'diagnostics': compile_run['stderr'][:32768]}
    driver = directory / 'driver.c'
    driver.write_bytes((ROOT / 'driver.c').read_bytes())
    output = directory / 'candidate'
    gcc = shutil.which('gcc')
    if not gcc: raise ValueError('E_TOOLCHAIN: gcc is required by the native RPC wrapper')
    if time.monotonic() >= deadline:
        return {'ok': False, 'stage': 'link', 'status': 'timeout', 'diagnostics': 'shared tool deadline exhausted'}
    link_run = run_bounded([gcc, '-std=c11', '-O2', '-DTASK_KIND=' + str(TASK_IDS.index(request['task_id']) + 1),
                           str(driver), str(library), '-ldl', '-lpthread', '-lm', '-o', str(output)],
                          cwd=directory, timeout=max(0.001, deadline - time.monotonic()), fixture=fixture, max_output=1024**2)
    if link_run['returncode'] or link_run['status'] != 'exited' or not output.is_file():
        return {'ok': False, 'stage': 'link', 'status': link_run['status'], 'diagnostics': link_run['stderr'][:32768]}
    return {'ok': True, 'source_sha256': digest(source.encode()), 'rust_sha256': digest(rust_source.encode()),
            'artifact_sha256': digest(output.read_bytes()), 'executable': str(output)}


def _wire(cases):
    lines = []
    for case in cases:
        lines.append(f"{case['id']} {len(case['input'])} {case.get('capacity', 0)} {case.get('parameter', 0)} {int(case.get('alias', False))}")
        lines.append(' '.join(map(str, case['input'])))
    return ('\n'.join(lines) + '\n').encode()


def score_candidate(request, body, *, public=False, rustc=None, fixture=False, timeout=30.0):
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix='hepta-agent-candidate-') as temporary:
        directory = Path(temporary)
        built = compile_candidate(request, body, directory, rustc=rustc, fixture=fixture, timeout=timeout)
        if not built['ok']:
            return {'ok': False, 'compiled': False, 'passed': 0, 'total': None, 'build': built}
        cases = [entry['input'] for entry in request['public_tests']] if public else hidden_cases(request['task_id'])
        if time.monotonic() >= deadline:
            return {'ok': False, 'compiled': True, 'passed': 0, 'total': len(cases),
                    'native_status': 'timeout', 'protocol_error': 'shared tool deadline exhausted'}
        run = run_bounded([built['executable']], cwd=directory, input_bytes=_wire(cases),
                          timeout=min(max(0.001, deadline - time.monotonic()), 15.0), fixture=fixture)
        passed = 0
        protocol_error = None
        try:
            lines = run['stdout'].splitlines()
            if len(lines) != len(cases):
                protocol_error = 'native output count does not match case count'
            parsed = [json.loads(line) for line in lines]
            if len({item.get('id') for item in parsed}) != len(parsed):
                protocol_error = 'duplicate native case identifier'
            for index, case in enumerate(cases):
                if index < len(parsed) and parsed[index] == expected(request['task_id'], case):
                    passed += 1
        except (ValueError, TypeError, AttributeError):
            protocol_error = 'invalid native response protocol'
        if protocol_error or run['returncode'] or run['status'] != 'exited':
            passed = 0
        return {'ok': passed == len(cases), 'compiled': True, 'passed': passed, 'total': len(cases),
                'native_status': run['status'], 'native_returncode': run['returncode'],
                'protocol_error': protocol_error, 'native_stderr_sha256': digest(run['stderr'].encode()),
                'source_sha256': built['source_sha256'], 'rust_sha256': built['rust_sha256'],
                'artifact_sha256': built['artifact_sha256'],
                'visibility': 'public' if public else 'private_after_final_response'}


def check_candidate(request, body, *, rustc=None, fixture=False, timeout=30.0):
    with tempfile.TemporaryDirectory(prefix='hepta-agent-check-') as temporary:
        result = compile_candidate(request, body, Path(temporary), rustc=rustc, fixture=fixture, timeout=timeout)
        result.pop('executable', None)
        return result
