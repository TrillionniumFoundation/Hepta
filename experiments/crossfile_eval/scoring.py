"""Native multi-module scoring with parent-only independent expectations."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import hepta
from hepta.backend import find_rustc
from experiments.agent_eval.sandbox import run_bounded
from experiments.agent_eval.scoring import compiler_identity as base_compiler_identity

from ._private.oracles import contract_probe, expected, hidden_cases
from .tasks import ROOT, canonical, digest, snapshot_id, validate_files


def python_read_only():
    """Expose only interpreter prefixes outside the sandbox's system mounts."""
    system = [Path(p).resolve() for p in ('/usr', '/bin', '/lib', '/lib64') if Path(p).exists()]
    prefixes = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    extra = [p for p in prefixes if not any(p == base or p.is_relative_to(base) for base in system)]
    for prefix in extra:
        if prefix == Path('/') or ROOT.is_relative_to(prefix):
            raise ValueError('E_PYTHON_PREFIX: refusing to mount a broad interpreter prefix containing evaluator inputs')
    return [str(p) for p in sorted(extra)]


def rust_profile_arguments(selected):
    prefix = Path(selected).resolve().parent.parent
    args = ['--sysroot', str(prefix)] if (prefix / 'lib/rustlib').is_dir() else []
    gcc = shutil.which('gcc')
    if not gcc: raise ValueError('E_TOOLCHAIN: gcc is required as the explicit host linker')
    # The toolchain's lld wrapper consults /proc/self/exe. Choose the installed
    # GNU linker explicitly in both modes so an empty procfs changes no flags.
    args += ['-C', 'linker=' + str(Path(gcc).resolve()), '-C', 'link-arg=-fuse-ld=bfd']
    return args


def _copy_frontend_support(directory):
    if not (directory / 'hepta').exists():
        shutil.copytree(Path(hepta.__file__).parent, directory / 'hepta',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    support = directory / 'study_support'
    support.mkdir(exist_ok=True)
    (support / '__init__.py').write_text('')
    for name in ('tasks.py', 'semantic.py'):
        shutil.copyfile(ROOT / name, support / name)
    shutil.copyfile(ROOT / '_study_frontend.py', directory / 'study_frontend.py')


def _run_study_frontend(directory, request, operation, *, fixture, timeout, contracts=False, edits=None):
    _copy_frontend_support(directory)
    message = {'request': request, 'operation': operation, 'contracts': contracts}
    if edits is not None: message['edits'] = edits
    process = run_bounded([sys.executable, str(directory / 'study_frontend.py')], cwd=directory,
                          timeout=max(0.001, timeout), input_bytes=canonical(message), fixture=fixture,
                          read_only=python_read_only(), max_output=2 * 1024 * 1024)
    if process['status'] != 'exited' or process['returncode']:
        return {'ok': False, 'status': process['status'], 'diagnostics': process['stderr'][:32768]}
    try: return json.loads(process['stdout'])
    except ValueError: return {'ok': False, 'diagnostics': 'invalid study frontend response'}


def study_frontend(request, files, operation='profile', *, fixture=False, timeout=30.0, edits=None):
    files = validate_files(request, files)
    with tempfile.TemporaryDirectory(prefix='hepta-crossfile-profile-') as temporary:
        directory = Path(temporary)
        for name, source in files.items():
            path = directory / 'candidate' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        return _run_study_frontend(directory, request, operation, fixture=fixture, timeout=timeout, edits=edits)


def _native_tool(name):
    executable = shutil.which(name)
    if not executable: raise ValueError('E_TOOLCHAIN: required native compiler is missing: ' + name)
    path = Path(executable).resolve()
    result = subprocess.run([str(path), '--version'], capture_output=True, text=True, timeout=5)
    if result.returncode: raise ValueError('E_TOOLCHAIN: cannot identify ' + name)
    target = subprocess.run([str(path), '-dumpmachine'], capture_output=True, text=True, timeout=5)
    return {'path': str(path), 'executable_sha256': digest(path.read_bytes()),
            'version': result.stdout.splitlines()[0], 'target': target.stdout.strip()}


def compiler_identity(rustc=None):
    identity = base_compiler_identity(rustc)
    identity.update(gcc=_native_tool('gcc'), gxx=_native_tool('g++'), archiver=_native_tool('ar'),
                    native_instrumentation='byte_layout_allocator_and_linker_pthread_wrap_v2_separate_candidate_crate',
                    ffi_profile='c11_cpp17_static_objects_exceptions_caught_at_c_abi',
                    target_support='linux_pthreads_gnu_linker_host_only',
                    native_support_link='ar_rcs_static_whole_archive_before_runtime_libraries')
    identity['crossfile_rust_argv'] = rust_profile_arguments(find_rustc(rustc))
    return identity


def compile_candidate(request, files, directory, *, rustc=None, fixture=False, timeout=30.0, contracts=True):
    deadline = time.monotonic() + timeout
    files = validate_files(request, files)
    selected = Path(find_rustc(rustc)).resolve()
    directory = Path(directory)
    source_hash = snapshot_id(files)
    candidate = directory / 'candidate'
    candidate.mkdir(parents=True, exist_ok=True)
    for name, source in files.items():
        path = candidate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    source_profile = _run_study_frontend(directory, request, 'profile', fixture=fixture,
                                        timeout=deadline - time.monotonic(), contracts=contracts)
    if not source_profile['ok']:
        return {'ok': False, 'stage': 'study_profile', 'status': source_profile.get('status', 'rejected'),
                'diagnostics': source_profile.get('diagnostics')}
    probe = contract_probe(request['task_id'], request['language']) if contracts else ''
    entry = candidate / request['entry']
    entry.write_text(files[request['entry']] + probe)

    def run(command, *, reads=()):
        return run_bounded(command, cwd=directory, timeout=max(0.001, deadline - time.monotonic()),
                           fixture=fixture, read_only=reads, max_output=1024 * 1024)

    if request['language'] == 'hepta':
        shutil.copyfile(ROOT / '_frontend.py', directory / 'frontend.py')
        front = run([sys.executable, str(directory / 'frontend.py')], reads=python_read_only())
        if front['status'] != 'exited' or front['returncode']:
            return {'ok': False, 'stage': 'frontend', 'status': front['status'], 'diagnostics': front['stderr'][:32768]}
        try: checked = json.loads(front['stdout'])
        except ValueError: return {'ok': False, 'stage': 'frontend', 'status': 'rejected', 'diagnostics': 'invalid frontend response'}
        if not checked['ok']:
            return {'ok': False, 'stage': 'frontend', 'status': 'rejected', 'diagnostics': checked['diagnostics']}
        rust_source = checked['rust']
    else:
        rust_source = entry.read_text()
    (candidate / 'entry.rs').write_text(rust_source)
    # A separate crate is essential: private root items are visible to child
    # modules in Rust, so making the submission a driver submodule would expose
    # allocator state and let it forge observations without allocating anything.
    facade = 'h_task' if request['language'] == 'hepta' else 'task'
    (directory / 'submission.rs').write_text('#[path = "candidate/entry.rs"] pub mod candidate;\n'
        + 'pub fn evaluate(a: i64, b: i64) -> i64 { candidate::' + facade + '(a, b) }\n')
    library = directory / 'libcf_submission.rlib'
    profile = ['--edition', '2021', '-C', 'opt-level=3', '-C', 'overflow-checks=yes',
               '-C', 'panic=abort', '-C', 'codegen-units=1', '--remap-path-prefix', str(directory) + '=/candidate']
    profile += rust_profile_arguments(selected)
    built = run([str(selected), '--crate-name', 'cf_submission', '--crate-type', 'rlib', *profile,
                 str(directory / 'submission.rs'), '-o', str(library)], reads=[selected.parent.parent])
    if built['status'] != 'exited' or built['returncode'] or not library.is_file():
        return {'ok': False, 'stage': 'candidate_rustc', 'status': built['status'], 'diagnostics': built['stderr'][:32768]}
    driver = (ROOT / 'driver.rs').read_text()
    driver = driver.replace('__TRACK_BUFFER__', str(request['task_id'] in {'owned_result', 'resource_cancel'}).lower())
    (directory / 'driver.rs').write_text(driver)
    shutil.copyfile(ROOT / 'monitor.c', directory / 'monitor.c')
    native_sources = [directory / 'monitor.c']
    if request['task_id'] == 'native_bridge':
        native_sources += [candidate / 'native/arith.c', candidate / 'native/meter.cpp']
    else:
        shutil.copyfile(ROOT / 'native_stub.c', directory / 'native_stub.c')
        native_sources += [directory / 'native_stub.c']
    objects = []
    for index, source in enumerate(native_sources):
        cxx = source.suffix == '.cpp'
        compiler = shutil.which('g++' if cxx else 'gcc')
        if not compiler: raise ValueError('E_TOOLCHAIN: gcc and g++ are required')
        output = directory / ('native_' + str(index) + '.o')
        built = run([compiler, '-std=c++17' if cxx else '-std=c11', '-O2', '-fPIC', '-c', str(source), '-o', str(output)])
        if built['status'] != 'exited' or built['returncode']:
            return {'ok': False, 'stage': 'native_support', 'status': built['status'], 'diagnostics': built['stderr'][:32768]}
        objects.append(output)
    # GNU ld must see our pthread observation definitions before libgcc's
    # split-stack wrapper of the same symbol. A named whole static archive
    # enters rustc's native-library section before runtime libraries; late raw
    # link-arg objects would make GNU ld pull its own wrapper first. No symbol
    # is discarded or multiply defined to hide instrumentation failures.
    archive = directory / 'libcf_native_support.a'
    archiver = shutil.which('ar')
    if not archiver: raise ValueError('E_TOOLCHAIN: ar is required for native observation support')
    built = run([archiver, 'rcs', str(archive), *[str(obj) for obj in objects]])
    if built['status'] != 'exited' or built['returncode'] or not archive.is_file():
        return {'ok': False, 'stage': 'native_archive', 'status': built['status'], 'diagnostics': built['stderr'][:32768]}
    output = directory / 'candidate_program'
    command = [str(selected), '--crate-name', 'crossfile_driver', '--crate-type', 'bin', *profile,
               '--extern', 'cf_submission=' + str(library), str(directory / 'driver.rs'), '-o', str(output)]
    command += ['-L', 'native=' + str(directory), '-l', 'static:+whole-archive=cf_native_support']
    command += ['-C', 'link-arg=-Wl,--wrap=pthread_create', '-C', 'link-arg=-Wl,--wrap=pthread_join', '-l', 'stdc++']
    built = run(command, reads=[selected.parent.parent])
    if built['status'] != 'exited' or built['returncode'] or not output.is_file():
        return {'ok': False, 'stage': 'rustc', 'status': built['status'], 'diagnostics': built['stderr'][:32768]}
    return {'ok': True, 'source_sha256': source_hash, 'rust_sha256': digest(rust_source.encode()),
            'artifact_sha256': digest(output.read_bytes()), 'executable': str(output),
            'candidate_rlib_sha256': digest(library.read_bytes()),
            'interface_sha256': source_profile['interface_sha256'],
            'interface_basis': source_profile['interface_basis'],
            'native_objects_sha256': [digest(obj.read_bytes()) for obj in objects],
            'compile_seconds': round(time.monotonic() - (deadline - timeout), 6)}


def check_candidate(request, files, *, rustc=None, fixture=False, timeout=30.0, contracts=True):
    with tempfile.TemporaryDirectory(prefix='hepta-crossfile-check-') as temporary:
        result = compile_candidate(request, files, Path(temporary), rustc=rustc, fixture=fixture,
                                   timeout=timeout, contracts=contracts)
        result.pop('executable', None)
        return result


def score_candidate(request, files, *, public=False, rustc=None, fixture=False, timeout=30.0, native_timeout=5.0):
    deadline = time.monotonic() + timeout
    cases = request['public_tests'] if public else hidden_cases(request['task_id'])
    with tempfile.TemporaryDirectory(prefix='hepta-crossfile-score-') as temporary:
        directory = Path(temporary)
        built = compile_candidate(request, files, directory, rustc=rustc, fixture=fixture, timeout=timeout)
        if not built['ok']:
            return {'ok': False, 'compiled': False, 'passed': 0, 'total': len(cases), 'build': built}
        wire = ''.join(f"{c['id']} {c['a']} {c['b']} {int(c['refuse'])}\n" for c in cases).encode()
        ran = run_bounded([built['executable']], cwd=directory, input_bytes=wire, fixture=fixture,
                          timeout=max(0.001, min(native_timeout, deadline - time.monotonic())), max_output=1024 * 1024)
        matched, mismatches, protocol_error = 0, [], None
        try:
            rows = [json.loads(line) for line in ran['stdout'].splitlines()]
            if len(rows) != len(cases): protocol_error = 'native response count differs from case count'
            if any(not isinstance(row, dict) for row in rows): raise ValueError('invalid row')
            if any(any(type(value) is not int for value in row.values()) for row in rows):
                raise ValueError('native protocol requires exact integer fields')
            if len({row.get('id') for row in rows}) != len(rows): protocol_error = 'duplicate native case identity'
            for index, case in enumerate(cases):
                want = expected(request['task_id'], case)
                actual = rows[index] if index < len(rows) else None
                if actual == want: matched += 1
                elif public: mismatches.append({'input': case, 'expected': want, 'actual': actual})
        except (ValueError, TypeError, KeyError):
            protocol_error = 'invalid native response protocol'
        passed = matched if ran['status'] == 'exited' and ran['returncode'] == 0 and protocol_error is None else 0
        return {'ok': passed == len(cases), 'compiled': True, 'passed': passed, 'total': len(cases),
                'native_status': ran['status'], 'native_returncode': ran['returncode'], 'protocol_error': protocol_error,
                'native_stderr_sha256': digest(ran['stderr'].encode()), 'source_sha256': built['source_sha256'],
                'rust_sha256': built['rust_sha256'], 'artifact_sha256': built['artifact_sha256'],
                'candidate_rlib_sha256': built['candidate_rlib_sha256'],
                'native_objects_sha256': built['native_objects_sha256'], 'public_mismatches': mismatches,
                'visibility': 'public' if public else 'parent_private_after_adapter_exit',
                'scoring_seconds': round(time.monotonic() - (deadline - timeout), 6)}
