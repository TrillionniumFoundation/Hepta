"""Execute an exact two-version upstream C++ library upgrade through Hepta.

The JSON library and the explicitly counted adapter remain C++. This measures
one real upgrade, including regeneration, native calls and failure cleanup;
it does not turn runtime timing into development-cost or memory-safety proof.
"""
from __future__ import annotations

import argparse
import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import signal
import shlex
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import _Generator, bridge_cpp_contracts
from hepta.pipeline import analyze_project, compiler_hash
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal

EXAMPLE = ROOT / 'examples/cpp/upgrade'
FIXTURES = ROOT / 'tests/fixtures/cpp_upgrade'
VERSIONS = ('3.11.3', '3.12.0')
PINNED_HEADERS = (
    '9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6',
    'aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63',
)
SENTINEL = 9223372036854775807
SCHEMA = 'hepta.cpp-upgrade-qualification.v2'
CLAIMS = {'foreign_library_rewritten': False, 'foreign_memory_safety_proved': False,
          'general_upgrade_compatibility_proved': False, 'total_development_cost_measured': False,
          'actual_ai_model_runs': 0, 'hermetic_toolchain_lock': False}
COST_SCOPE = 'one unchanged-consumer upstream upgrade; wall times include actual tool executions, not initial development effort'
PROTOCOL = {
    'id': 'hepta.cpp-upgrade-json.v3', 'versions': list(VERSIONS),
    'maximum_array_items': 64, 'integer_magnitude_limit': 1000000,
    'operation': 'parse object; replace one integer array element; sum; destroy',
    'routes': ['native C++ adapter', 'C caller -> Hepta -> generated scoped C++ bridge'],
    'upgrade_source_policy': 'same adapter, contract and Hepta caller; no per-version patch',
    'failure_policy': 'isolate every observed allocation site; catchable failures must preserve output and allocation baseline; actual std::bad_alloc SIGABRT is recorded as unqualified recovery, never as a catchable success',
    'revision_reason': 'v1 actually terminated during foreign allocation refusal; retain that failure and observe each site independently rather than losing the remaining denominator',
    'measurement': 'actual regeneration/build/execution wall time and source changes; no performance threshold',
    'calibration': 'separate process on the same executable; immutable retained stdout supplies the fault denominator',
    'evidence': 'current file and process consistency; not authentication of arbitrary third-party JSON',
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def value_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_inputs():
    paths = [Path(__file__), *EXAMPLE.iterdir(), *FIXTURES.rglob('*')]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths) if p.is_file()}


def locked_libraries(directory=FIXTURES):
    directory = Path(directory)
    lock = json.loads((directory / 'lock.json').read_text())
    rows = lock.get('versions', [])
    if lock.get('schema') != 'hepta.cpp-upgrade-inputs.v1' or lock.get('library') != 'nlohmann/json' or len(rows) != 2:
        raise ValueError('E_CPP_UPGRADE_INPUT: exact two-version input lock required')
    for row, version, expected in zip(rows, VERSIONS, PINNED_HEADERS):
        if row.get('version') != version or row.get('header') != version + '/json.hpp' or row.get('sha256') != expected:
            raise ValueError('E_CPP_UPGRADE_INPUT: upstream version/header identity differs')
        header = directory / row['header']
        license_path = directory / (version + '/LICENSE.MIT')
        if (header.is_symlink() or license_path.is_symlink() or digest(header) != expected
                or type(row.get('bytes')) is not int or header.stat().st_size != row['bytes']):
            raise ValueError('E_CPP_UPGRADE_INPUT: upstream header content differs')
        if row.get('license') != version + '/LICENSE.MIT' or digest(license_path) != row.get('license_sha256'):
            raise ValueError('E_CPP_UPGRADE_INPUT: license identity differs')
    return rows


def cases():
    result = []
    for size in (1, 2, 4, 8, 64):
        values = [((i * 17) % 31) - 15 for i in range(size)]
        for index in sorted({0, size // 2, size - 1, size}):
            for replacement in (-1000000, -1, 0, 1000000, 1000001):
                result.append({'text': json.dumps({'values': values}, separators=(',', ':')),
                               'index': index, 'value': replacement})
    for text in ('', '{', 'null', '[]', '{}', '{"values":{}}', '{"values":[]}',
                 '{"values":[true]}', '{"values":[1.5]}', '{"values":[1000001]}',
                 '{"values":[-1000001]}', '{"values":[1,2,3],"ignored":{"nested":true}}',
                 json.dumps({'values': [0] * 65})):
        result.append({'text': text, 'index': 0, 'value': 7})
    return result


def expected_rows():
    result = []
    for number, case in enumerate(cases()):
        status, value = 0, SENTINEL
        try:
            doc = json.loads(case['text'])
            if not isinstance(doc, dict) or not isinstance(doc.get('values'), list):
                raise ValueError('object/array required')
            values = doc['values']
            if len(values) > 64 or any(type(x) is not int or abs(x) > 1000000 for x in values):
                raise ValueError('bounded integer array required')
            if not 0 <= case['index'] < len(values) or abs(case['value']) > 1000000:
                raise ValueError('index/replacement outside domain')
            values[case['index']] = case['value']
            value = sum(values)
        except (ValueError, TypeError):
            status = 3
        result.append({'id': number, 'direct_status': status, 'direct_value': value,
                       'hepta_status': status, 'hepta_value': value, 'live_delta': 0})
    return result


def _run(argv, *, owner, directory, stage, allow_failure=False, timeout=120):
    """Append the attempt before executing and retain exact streams on failure."""
    argv = [str(v) for v in argv]
    streams = Path(directory) / 'processes'
    streams.mkdir(exist_ok=True)
    row = {'stage': stage, 'argv': argv, 'exit_code': None, 'status': 'running', 'seconds': 0,
           'executable_sha256': None}
    owner.setdefault('processes', []).append(row)
    started = time.monotonic()
    stdout, stderr = b'', b''
    try:
        row['executable_sha256'] = digest(argv[0])
        completed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
        stdout, stderr = completed.stdout, completed.stderr
        row.update(exit_code=completed.returncode, status='exited')
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b'', exc.stderr or b''
        row.update(status='timeout', error=str(exc))
        raise
    except OSError as exc:
        row.update(status='launch_failed', error=str(exc))
        raise
    finally:
        row['seconds'] = time.monotonic() - started
        for name, data in (('stdout', stdout), ('stderr', stderr)):
            data = data.encode() if isinstance(data, str) else data
            path = streams / (stage + '.' + name)
            with path.open('xb') as destination:
                destination.write(data)
            row[name] = data.decode('utf-8', errors='replace')
            row[name + '_path'] = str(path)
            row[name + '_sha256'] = hashlib.sha256(data).hexdigest()
            row[name + '_bytes_base64'] = base64.b64encode(data).decode()
        try:
            row['executable_unchanged'] = digest(argv[0]) == row['executable_sha256']
        except OSError:
            row['executable_unchanged'] = False
    if row['exit_code'] and not allow_failure:
        raise RuntimeError('E_CPP_UPGRADE_NATIVE: ' + json.dumps(row))
    return row


def _dependency_paths(text):
    rule = text.replace('\\\n', ' ')
    require(':' in rule, 'dependency rule missing its target')
    paths = shlex.split(rule.split(':', 1)[1])
    require(paths and all(p for p in paths), 'empty dependency closure')
    return sorted({str((ROOT / p).resolve()) if not Path(p).is_absolute() else str(Path(p).resolve()) for p in paths})


def _dependencies(compiler, header, *, owner, directory, stage):
    result = _run([compiler, '-std=c++20', '-M', '-MT', 'hepta_headers', '-x', 'c++', header],
                  owner=owner, directory=directory, stage=stage)
    return {'process': result, 'files': {p: digest(p) for p in _dependency_paths(result['stdout'])}}


def _runtime_paths(text):
    require('not found' not in text, 'runtime dependency is unresolved')
    paths = sorted({str(Path(p).resolve()) for p in re.findall(r'(?:=>\s+)?(/[^\s]+)\s+\(', text)})
    require(paths, 'runtime dependency closure is empty')
    return paths


def _runtime_dependencies(executable, *, owner, directory, ldd):
    process = _run([ldd, executable], owner=owner, directory=directory, stage='ldd')
    return {'process': process, 'files': {p: digest(p) for p in _runtime_paths(process['stdout'])}}


def _case_source():
    return ('#pragma once\nstruct Case { const char* text; std::size_t index; std::int64_t value; };\n'
            'constexpr Case cases[] = {\n' + ''.join('{' + json.dumps(c['text']) + ',' +
            str(c['index']) + ',' + str(c['value']) + '},\n' for c in cases()) + '};\n')


def _selected_source(locked):
    return ('#pragma once\n#include ' + json.dumps(str(FIXTURES / locked['header'])) + '\n#include ' +
            json.dumps(str(EXAMPLE / 'adapter.hpp')) + '\n')


def _flags(directory):
    return ['-std=c++20', '-O2', '-fPIC', '-pthread', '-Werror', '-I' + str(directory / 'bridge'), '-I' + str(directory)]


def _compile_argv(compiler, directory, source):
    output = directory / (source.stem + '.o')
    return [compiler, *_flags(directory), '-MD', '-MF', str(directory / (source.stem + '.d')),
            '-MT', str(output), '-c', str(source), '-o', str(output)]


def _generated_identity(directory):
    # Only the version-specific selected.hpp location differs. Generated ABI,
    # contract and actual Hepta text are compared byte-for-byte.
    cpp = (directory / 'bridge/bridge.cpp').read_text().replace(str(directory), '<VERSION_DIRECTORY>')
    return {'normalized_cpp_sha256': hashlib.sha256(cpp.encode()).hexdigest(),
            **{name: digest(directory / 'bridge' / name) for name in ('bridge.h', 'bridge.hepta', 'contract.json')}}


def build_json_checkpoint_image(directory, version, *, cxx='g++', rustc=None, receipt=None):
    """Build the unchanged scoped ABI as a bounded, one-invocation worker.

    The caller receives an opaque immutable image, never a pathname-based
    execution permission. This reuses the original pinned library, adapter,
    contract, Hepta consumer, C++ generator and existing object-code route.
    It does not claim that the retained C++ implementation has been rewritten.
    """
    from hepta.cpp_json_checkpoint import _issue_worker_image
    directory = Path(directory).absolute()
    require(not directory.exists(), 'checkpoint worker requires a new build directory')
    directory.mkdir(parents=True)
    receipt = {} if receipt is None else receipt
    receipt.update(version=version, directory=str(directory), status='building', processes=[],
                   claims={'foreign_library_rewritten': False, 'foreign_memory_safety_proved': False,
                           'general_foreign_recovery_proved': False})
    started = time.monotonic_ns()
    try:
        locked = next((row for row in locked_libraries() if row['version'] == version), None)
        require(locked is not None, 'unsupported exact JSON version')
        compiler = shutil.which(cxx)
        require(compiler is not None, 'actual C++ compiler is unavailable')
        compiler = str(Path(compiler).resolve())
        receipt['source_inputs_before'] = source_inputs()
        selected = directory / 'selected.hpp'
        selected.write_text(_selected_source(locked))
        generated = directory / 'bridge'
        bridge = bridge_cpp_contracts(selected, EXAMPLE / 'contract.json', generated,
                                      cxx=compiler, rustc=rustc)
        receipt['bridge'] = bridge
        require(bridge.get('ok') is True, 'actual scoped C++ ABI generation failed')
        shutil.copyfile(EXAMPLE / 'consumer.hepta', generated / 'consumer.hepta')
        checked = analyze_project(generated / 'consumer.hepta', native=False, crate_type='obj')
        receipt['frontend'] = checked.report
        require(checked.report.get('ok') is True, 'actual Hepta consumer check failed')
        exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
        (generated / 'hepta.h').write_text(emit_header(exports))
        (generated / 'consumer.rs').write_text(checked.rust)
        consumer = directory / 'consumer.o'
        native = compile_rust(checked.rust, rustc=rustc, crate_type='obj', output=consumer)
        receipt['native'] = native
        require(native.get('ok') is True, 'actual Hepta consumer object build failed')
        objects = []
        for source in (generated / 'bridge.cpp', EXAMPLE / 'recovery_worker.cpp'):
            _run(_compile_argv(compiler, directory, source), owner=receipt, directory=directory,
                 stage='compile-' + source.stem)
            objects.append(directory / (source.stem + '.o'))
        executable = directory / 'json-checkpoint-worker'
        _run([compiler, *objects, consumer, '-pthread', '-ldl', '-lm', '-o', executable],
             owner=receipt, directory=directory, stage='link')
        receipt['source_inputs_after'] = source_inputs()
        require(receipt['source_inputs_after'] == receipt['source_inputs_before'],
                'scoped JSON build source changed')
        receipt['upstream_pin'] = locked
        receipt['generated_identity'] = _generated_identity(directory)
        receipt['artifacts'] = {str(p.relative_to(directory)): {'sha256': digest(p), 'bytes': p.stat().st_size}
                                for p in (executable, consumer, *objects,
                                          generated / 'bridge.cpp', generated / 'bridge.h',
                                          generated / 'bridge.hepta', generated / 'consumer.rs',
                                          generated / 'consumer.hepta', generated / 'hepta.h')}
        binding = value_digest({'version': version, 'sources': receipt['source_inputs_before'],
                                'artifacts': receipt['artifacts'], 'generated_identity': receipt['generated_identity']})
        image = _issue_worker_image(executable.read_bytes(), version, binding)
        receipt.update(status='built', image_sha256=image.sha256, build_sha256=binding)
        return image
    except BaseException as error:
        receipt.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        receipt['wall_ns'] = time.monotonic_ns() - started


def _native_version(root, locked, compiler, rustc, *, receipt, native_tools):
    started = time.monotonic()
    directory = root / locked['version']
    directory.mkdir()
    receipt.update(status='running', directory=str(directory), processes=[], commands=[], allocation_failures=[],
                   compile_dependencies={})
    selected = directory / 'selected.hpp'
    selected.write_text(_selected_source(locked))
    receipt['headers_before'] = _dependencies(compiler, selected, owner=receipt, directory=directory, stage='headers-before')
    generation_started = time.monotonic()
    generated = directory / 'bridge'
    bridge = bridge_cpp_contracts(selected, EXAMPLE / 'contract.json', generated, cxx=compiler, rustc=rustc)
    receipt['bridge'] = bridge
    generation_seconds = time.monotonic() - generation_started
    if bridge.get('ok') is not True:
        raise RuntimeError('E_CPP_UPGRADE_BRIDGE: ' + json.dumps(bridge))
    shutil.copyfile(EXAMPLE / 'consumer.hepta', generated / 'consumer.hepta')
    hepta_started = time.monotonic()
    checked = analyze_project(generated / 'consumer.hepta', rustc=rustc, crate_type='staticlib')
    receipt['hepta_check'] = checked.report
    (generated / 'consumer.check.json').write_text(json.dumps(checked.report, indent=2, sort_keys=True) + '\n')
    if checked.report.get('ok') is not True:
        raise RuntimeError('E_CPP_UPGRADE_HEPTA: ' + json.dumps(checked.report))
    exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
    (generated / 'hepta.h').write_text(emit_header(exports))
    (generated / 'consumer.rs').write_text(checked.rust)
    library = directory / 'consumer.a'
    native = compile_rust(checked.rust, rustc=rustc, crate_type='staticlib', output=library)
    receipt['hepta_native'] = native
    (generated / 'consumer.native.json').write_text(json.dumps(native, indent=2, sort_keys=True) + '\n')
    if native.get('ok') is not True:
        raise RuntimeError('E_CPP_UPGRADE_RUST: ' + json.dumps(native))
    hepta_seconds = time.monotonic() - hepta_started
    (directory / 'cases.hpp').write_text(_case_source())
    objects = []
    for source in (generated / 'bridge.cpp', EXAMPLE / 'harness.cpp'):
        output = directory / (source.stem + '.o')
        command = _run(_compile_argv(compiler, directory, source), owner=receipt, directory=directory, stage='compile-' + source.stem)
        receipt['commands'].append(command)
        depfile = directory / (source.stem + '.d')
        receipt['compile_dependencies'][source.stem] = {'path': str(depfile), 'sha256': digest(depfile),
            'files': {path: digest(path) for path in _dependency_paths(depfile.read_text())}}
        objects.append(output)
    executable = directory / 'json-upgrade'
    receipt['commands'].append(_run([compiler, *objects, library, '-pthread', '-ldl', '-lm', '-o', executable],
        owner=receipt, directory=directory, stage='link'))
    execution = _run([executable], owner=receipt, directory=directory, stage='cases', timeout=30)
    receipt['execution_process'] = execution
    observed = json.loads(execution['stdout'])
    receipt['execution'] = observed
    if not strict_equal(observed.get('cases'), expected_rows()) or observed.get('version') != locked['version']:
        raise ValueError('E_CPP_UPGRADE_DIFFERENTIAL: native JSON observations differ from Python oracle')
    calibration = _run([executable, '--calibrate'], owner=receipt, directory=directory, stage='calibration', timeout=30)
    receipt['calibration'] = {'process': calibration, 'observation': json.loads(calibration['stdout'])}
    sites = receipt['calibration']['observation'].get('allocation_sites')
    require(type(sites) is int and 0 < sites < 128 and sites == observed.get('allocation_sites'), 'invalid actual allocation denominator')
    receipt['allocation_failures'] = [{'site': site, 'status': 'not_run', 'observation': None, 'recovery_qualified': None}
                                      for site in range(1, sites + 1)]
    for fault in receipt['allocation_failures']:
        site = fault['site']
        fault['status'] = 'running'
        try:
            attempt = _run([executable, str(site)], owner=receipt, directory=directory, stage=f'fault-{site:04d}', allow_failure=True, timeout=30)
            fault['process'] = attempt
            if attempt['exit_code'] == 0:
                outcome = json.loads(attempt['stdout'])
                if not strict_equal(outcome, {'site': site, 'status': 3, 'output_preserved': True, 'live_delta': 0, 'recovered_value': 9}):
                    raise ValueError('E_CPP_UPGRADE_ALLOCATION: catchable failure observations differ')
                status = 'caught_and_recovered'
            elif attempt['exit_code'] == -signal.SIGABRT and 'std::bad_alloc' in attempt['stderr']:
                outcome, status = None, 'foreign_noexcept_termination'
            else:
                raise RuntimeError('E_CPP_UPGRADE_ALLOCATION: unexpected failure ' + json.dumps(attempt))
            fault.update(status=status, observation=outcome, recovery_qualified=status == 'caught_and_recovered')
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            fault.update(status='failed', error=str(exc), recovery_qualified=False)
    if any(f['status'] == 'failed' for f in receipt['allocation_failures']):
        raise ValueError('E_CPP_UPGRADE_ALLOCATION: one or more isolated attempts failed; all attempts retained')
    receipt['all_allocation_failure_paths_recovered'] = all(r['recovery_qualified'] for r in receipt['allocation_failures'])
    symbols = _run([native_tools['nm']['path'], '-g', '--defined-only', directory / 'bridge.o'],
                   owner=receipt, directory=directory, stage='symbols')
    receipt['symbol_process'] = symbols
    receipt['c_symbols'] = sorted(line.split()[-1] for line in symbols['stdout'].splitlines()
                                 if line.split() and line.split()[-1].startswith('hepta_cpp_json_upgrade_'))
    receipt['headers_after'] = _dependencies(compiler, selected, owner=receipt, directory=directory, stage='headers-after')
    if receipt['headers_before']['files'] != receipt['headers_after']['files']:
        raise ValueError('E_CPP_UPGRADE_DEPENDENCY: headers changed during execution')
    for dependency in receipt['compile_dependencies'].values():
        require(all(digest(path) == identity for path, identity in dependency['files'].items()), 'compiled dependency changed during execution')
    artifacts = {str(p.relative_to(directory)): {'sha256': digest(p), 'bytes': p.stat().st_size}
                 for p in (selected, directory / 'cases.hpp', directory / 'bridge.d', directory / 'harness.d', *objects, library, executable,
                           *(generated / name for name in ('bridge.cpp', 'bridge.h', 'bridge.hepta', 'consumer.hepta', 'consumer.rs', 'hepta.h', 'contract.json',
                                                         'report.json', 'consumer.check.json', 'consumer.native.json')))}
    receipt.update(runtime_dependencies=_runtime_dependencies(executable, owner=receipt, directory=directory, ldd=native_tools['ldd']['path']),
                   generated_identity=_generated_identity(directory), artifacts=artifacts)
    receipt['cost'] = {'bridge_generation_seconds': generation_seconds,
            'hepta_check_and_build_seconds': hepta_seconds,
            'cpp_compile_link_seconds': sum(p['seconds'] for p in receipt['commands']),
            'native_case_execution_seconds': execution['seconds'],
            'failure_observation_seconds': calibration['seconds'] + sum(f['process']['seconds'] for f in receipt['allocation_failures']),
            'dependency_observation_seconds': sum(p['seconds'] for p in receipt['processes'] if p['stage'] in {'headers-before', 'headers-after', 'symbols', 'ldd'}),
            'total_seconds': time.monotonic() - started}
    receipt['status'] = 'passed'
    return receipt


def _negative_controls(root, compiler, rustc, *, receipt):
    receipt.update(status='running', processes=[])
    selected_version = root / VERSIONS[-1]
    bad = root / 'bad-contract'
    contract = json.loads((EXAMPLE / 'contract.json').read_text())
    contract['handles'][0]['methods'][1]['returns'] = 'u32'
    (root / 'incompatible-contract.json').write_text(json.dumps(contract, indent=2, sort_keys=True) + '\n')
    rejected = bridge_cpp_contracts(selected_version / 'selected.hpp', contract, bad, cxx=compiler, rustc=rustc)
    receipt['incompatible_signature'] = {'report': rejected, 'output_published': bad.exists(),
        'contract_path': str(root / 'incompatible-contract.json'), 'contract_sha256': digest(root / 'incompatible-contract.json')}
    if rejected.get('ok') is not False or bad.exists() or [d.get('code') for d in rejected.get('diagnostics', [])] != ['E_CPP_NATIVE']:
        raise ValueError('E_CPP_UPGRADE_CONTROL: actual incompatible method signature was not rejected')
    cpp = (selected_version / 'bridge/bridge.cpp').read_text()
    needle = '*out = _hepta_scoped_result;'
    if cpp.count(needle) != 1:
        raise ValueError('E_CPP_UPGRADE_CONTROL: unique scoped publication site missing')
    wrong_source = selected_version / 'wrong-bridge.cpp'
    wrong_source.write_text(cpp.replace(needle, '*out = _hepta_scoped_result + 1;'))
    wrong_object = selected_version / 'wrong-bridge.o'
    compile_process = _run([compiler, '-std=c++20', '-O2', '-pthread', '-Werror',
                           '-I' + str(selected_version / 'bridge'), '-c', wrong_source, '-o', wrong_object],
                          owner=receipt, directory=root, stage='negative-compile')
    wrong_executable = selected_version / 'wrong-json-upgrade'
    link_process = _run([compiler, wrong_object, selected_version / 'harness.o', selected_version / 'consumer.a',
                         '-pthread', '-ldl', '-lm', '-o', wrong_executable],
                        owner=receipt, directory=root, stage='negative-link')
    execution = _run([wrong_executable], owner=receipt, directory=root, stage='negative-execute', allow_failure=True)
    receipt['wrong_implementation'] = {'source_sha256': digest(wrong_source), 'object_sha256': digest(wrong_object),
        'executable_sha256': digest(wrong_executable), 'compile_process': compile_process,
        'link_process': link_process, 'execution_process': execution}
    if execution['exit_code'] != 2 or execution['stderr'] != 'allocation calibration call\n':
        raise ValueError('E_CPP_UPGRADE_CONTROL: wrong compiled implementation did not fail native observations')
    wrong_rows = json.loads(execution['stdout'] + ']}')['cases']
    mismatch = next((row for row, expected in zip(wrong_rows, expected_rows()) if row != expected), None)
    if mismatch is None or mismatch['hepta_value'] != mismatch['direct_value'] + 1:
        raise ValueError('E_CPP_UPGRADE_CONTROL: no actual wrong implementation value observed')
    receipt['wrong_implementation']['first_mismatch'] = mismatch
    receipt['status'] = 'passed'
    return receipt


def qualify_cpp_upgrade(directory, *, cxx='g++', rustc=None):
    directory = Path(directory).resolve()
    if directory.exists() or directory.is_symlink():
        raise ValueError('E_CPP_UPGRADE_PATH: a new work directory is required')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('E_CPP_UPGRADE_HOST: this observed-dependency profile is Linux x86_64')
    before = source_inputs()
    identity = compiler_hash()
    directory.mkdir(parents=True)
    report = {'schema': SCHEMA, 'ok': False, 'status': 'running', 'workdir': str(directory), 'processes': [],
              'started_utc': datetime.now(timezone.utc).isoformat(), 'protocol': PROTOCOL,
              'protocol_sha256': value_digest(PROTOCOL), 'compiler_sha256': identity, 'inputs': before,
              'case_count_per_version': len(cases()), 'oracle_sha256': value_digest(expected_rows()),
              'versions': [{'version': version, 'status': 'not_run'} for version in VERSIONS], 'claims': dict(CLAIMS),
              'negative_controls': {'status': 'not_run'}, 'native_tools': {}}
    errors = (ValueError, RuntimeError, OSError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired)
    try:
        libraries = locked_libraries()
        for name, requested in (('cxx', cxx), ('nm', 'nm'), ('ldd', 'ldd')):
            found = shutil.which(requested)
            if found is None:
                raise ValueError('E_CPP_UPGRADE_ENV: required native tool missing: ' + name)
            path = str(Path(found).resolve())
            report['native_tools'][name] = {'path': path, 'sha256': digest(path)}
        compiler = report['native_tools']['cxx']['path']
        version = _run([compiler, '--version'], owner=report, directory=directory, stage='cxx-version')
        report['cxx'] = {**report['native_tools']['cxx'], 'version': version['stdout']}
        for receipt, locked in zip(report['versions'], libraries):
            receipt['upstream'] = locked
            try:
                _native_version(directory, locked, compiler, rustc, receipt=receipt, native_tools=report['native_tools'])
            except errors as exc:
                receipt.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
        if any(row['status'] != 'passed' for row in report['versions']):
            raise ValueError('E_CPP_UPGRADE_VERSION: one or more versions failed; completed stages and both version rows retained')
        _negative_controls(directory, compiler, rustc, receipt=report['negative_controls'])
        first, second = report['versions']
        report['upgrade'] = {'from': VERSIONS[0], 'to': VERSIONS[1], 'source_files_patched': [],
            'source_lines_changed': 0, 'contract_changes': 0, 'hepta_caller_changes': 0,
            'generated_identity_equal': first['generated_identity'] == second['generated_identity'],
            'c_export_symbols_equal': first['c_symbols'] == second['c_symbols'],
            'c_boundary_executed_on_both_versions': True,
            'authored_initial_adapter_lines': len((EXAMPLE / 'adapter.hpp').read_text().splitlines()),
            'authored_initial_contract_lines': len((EXAMPLE / 'contract.json').read_text().splitlines()),
            'authored_initial_hepta_lines': len((EXAMPLE / 'consumer.hepta').read_text().splitlines()),
            'human_review_hours': None, 'agent_tokens': None,
            'cost_scope': COST_SCOPE}
        report['inputs_unchanged'] = before == source_inputs() and identity == compiler_hash()
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report.update(ok=True, status='passed')
        validate_report(report)
        return report
    except errors as exc:
        report.update(ok=False, status="failed", error=str(exc), finished_utc=datetime.now(timezone.utc).isoformat())
        return report




def _fields(value, fields, context):
    require(isinstance(value, dict) and set(value) == set(fields), context + ' fields differ')


def _json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('invalid JSON constant: ' + value)
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid)


def _file_bytes(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'retained evidence must be a regular nonsymlink file')
    return path.read_bytes()


def _process_evidence(value, argv, directory, stage, expected=0):
    fields = {'stage', 'argv', 'exit_code', 'status', 'seconds', 'executable_sha256', 'executable_unchanged'}
    fields |= {name + suffix for name in ('stdout', 'stderr') for suffix in ('', '_path', '_sha256', '_bytes_base64')}
    _fields(value, fields, 'successful process')
    require(strict_equal(value['argv'], [str(v) for v in argv]) and value['stage'] == stage,
            'process does not identify the exact stage command')
    require(type(value['exit_code']) is int and value['exit_code'] == expected and value['status'] == 'exited',
            'actual process exit status differs')
    require(type(value['seconds']) in (int, float) and math.isfinite(value['seconds']) and value['seconds'] >= 0,
            'process elapsed time is invalid')
    require(value['executable_unchanged'] is True and is_sha(value['executable_sha256'])
            and value['executable_sha256'] == digest(argv[0]), 'process executable differs from current retained binary/tool')
    for name in ('stdout', 'stderr'):
        expected_path = Path(directory) / 'processes' / (stage + '.' + name)
        require(value[name + '_path'] == str(expected_path), 'process stream path differs')
        data = _file_bytes(expected_path)
        require(value[name] == data.decode('utf-8', errors='replace')
                and value[name + '_sha256'] == hashlib.sha256(data).hexdigest()
                and value[name + '_bytes_base64'] == base64.b64encode(data).decode(), 'retained process bytes differ')


def _file_closure(files, paths):
    require(isinstance(files, dict) and set(files) == set(paths), 'complete parsed dependency denominator differs')
    require(all(is_sha(h) and h == digest(path) for path, h in files.items()), 'current dependency file identity differs')


def _native_source(actual, expected):
    require(set(actual) == set(expected) | {'backend'}, 'native frontend fields differ')
    for key in expected:
        if key not in {'status', 'checks'}:
            require(strict_equal(actual[key], expected[key]), 'native frontend source or scope differs: ' + key)
    status = 'checked_with_external_assumptions' if expected['assumptions'] else 'checked'
    require(actual['status'] == status and strict_equal(actual['checks'], dict(expected['checks'], rust_borrows_types='rustc_checked')),
            'current source native checking did not run')
    native_build(actual['backend'], 'rust', check_only=True, crate_type='staticlib', source_sha256=expected['rust_sha256'])


def _artifact_evidence(directory, artifacts, expected_names):
    require(isinstance(artifacts, dict) and set(artifacts) == set(expected_names), 'retained native artifact denominator differs')
    for name, artifact in artifacts.items():
        _fields(artifact, {'sha256', 'bytes'}, 'artifact')
        data = _file_bytes(directory / name)
        require(type(artifact['bytes']) is int and artifact['bytes'] == len(data) and len(data) > 0
                and is_sha(artifact['sha256']) and artifact['sha256'] == hashlib.sha256(data).hexdigest(),
                'actual retained native artifact differs: ' + name)


def _validate_version(row, locked, root, tools):
    fields = {'version', 'upstream', 'status', 'directory', 'processes', 'commands', 'allocation_failures',
              'compile_dependencies', 'headers_before', 'bridge', 'hepta_check', 'hepta_native', 'execution_process',
              'execution', 'calibration', 'all_allocation_failure_paths_recovered', 'symbol_process', 'c_symbols',
              'headers_after', 'runtime_dependencies', 'generated_identity', 'artifacts', 'cost'}
    _fields(row, fields, 'version')
    require(row['status'] == 'passed' and row['version'] == locked['version'] and strict_equal(row['upstream'], locked),
            'upstream identity/status differs')
    directory = root / locked['version']
    generated = directory / 'bridge'
    require(row['directory'] == str(directory), 'version directory differs')
    compiler = tools['cxx']['path']
    executable, library = directory / 'json-upgrade', directory / 'consumer.a'
    names = {'selected.hpp', 'cases.hpp', 'bridge.d', 'harness.d', 'bridge.o', 'harness.o', 'consumer.a', 'json-upgrade'}
    names |= {'bridge/' + name for name in ('bridge.cpp', 'bridge.h', 'bridge.hepta', 'consumer.hepta', 'consumer.rs',
                                          'hepta.h', 'contract.json', 'report.json', 'consumer.check.json', 'consumer.native.json')}
    _artifact_evidence(directory, row['artifacts'], names)
    require((directory / 'selected.hpp').read_text() == _selected_source(locked)
            and (directory / 'cases.hpp').read_text() == _case_source()
            and (generated / 'consumer.hepta').read_bytes() == (EXAMPLE / 'consumer.hepta').read_bytes(),
            'compiled version selector, cases or Hepta caller differs from current source')
    bridge = row['bridge']
    require(strict_equal(bridge, _json((generated / 'report.json').read_text()))
            and strict_equal(row['hepta_check'], _json((generated / 'consumer.check.json').read_text()))
            and strict_equal(row['hepta_native'], _json((generated / 'consumer.native.json').read_text())),
            'original generated/native receipts differ from retained bytes')
    require(bridge.get('ok') is True and bridge.get('status') == 'cpp_object_and_hepta_native_checked'
            and bridge.get('header') == str(directory / 'selected.hpp')
            and bridge.get('header_sha256') == row['artifacts']['selected.hpp']['sha256'], 'current generated bridge missing')
    for key in ('native_link_qualified', 'paired_toolchain_abi_qualified', 'foreign_library_soundness_proved',
                'borrow_retention_proved', 'foreign_thread_safety_proved', 'caller_pointer_validity_proved'):
        require(bridge.get(key) is False, 'bridge claims exceed its compile-only qualification')
    require(bridge.get('execution') == 'not_run' and bridge.get('diagnostics') == []
            and bridge.get('compiler', {}).get('path') == compiler
            and bridge['compiler'].get('executable_sha256') == tools['cxx']['sha256'], 'bridge/compiler identity differs')
    contract = _json((EXAMPLE / 'contract.json').read_text())
    generator = _Generator(directory / 'selected.hpp', contract)
    cpp, header, hepta = generator.render()
    fresh = {'bridge.cpp': cpp, 'bridge.h': header, 'bridge.hepta': hepta,
             'contract.json': json.dumps(contract, indent=2, sort_keys=True) + '\n'}
    require(bridge.get('contract_schema') == 'hepta.cpp-contract.v3' and bridge.get('contract_sha256') == value_digest(contract),
            'bridge contract identity differs')
    for name, value in fresh.items():
        require((generated / name).read_text() == value and strict_equal(bridge.get('outputs', {}).get(name),
                {'path': str(generated / name), 'sha256': hashlib.sha256(value.encode()).hexdigest()}),
                'bridge source differs from the current exact rendering')
    require(set(bridge.get('outputs', {})) == set(fresh)
            and strict_equal(bridge.get('constructor_checks'), generator.constructor_checks)
            and strict_equal(bridge.get('scoped_lifetime_checks'), generator.scoped_checks)
            and strict_equal(bridge.get('cost_accounting'), generator.costs), 'bridge checks/cost scope differs')
    require(strict_equal(row['generated_identity'], _generated_identity(directory)), 'generated source identity differs')
    fresh_check = analyze_project(generated / 'consumer.hepta', native=False, crate_type='staticlib')
    require(fresh_check.report['ok'] is True and (generated / 'consumer.rs').read_text() == fresh_check.rust,
            'retained Rust does not come from the current Hepta project')
    exports = replace(fresh_check.program, functions=[fn for fn in fresh_check.program.functions if fn.export_c])
    require((generated / 'hepta.h').read_text() == emit_header(exports), 'executed consumer C ABI header differs')
    _native_source(row['hepta_check'], fresh_check.report)
    native = row['hepta_native']
    native_build(native, 'rust', check_only=False, crate_type='staticlib', source_sha256=fresh_check.report['rust_sha256'])
    require(native['artifact'] == str(library) and native['artifact_sha256'] == row['artifacts']['consumer.a']['sha256']
            and native['artifact_bytes'] == row['artifacts']['consumer.a']['bytes'], 'compiled Rust static library differs')
    require(strict_equal(native['toolchain'], row['hepta_check']['backend']['toolchain'])
            and native['target'] == row['hepta_check']['backend']['target'] == 'x86_64-unknown-linux-gnu'
            and native['toolchain']['version'].startswith('rustc 1.90.0 ')
            and native['toolchain']['executable_sha256'] == digest(native['toolchain']['path']), 'pinned native Rust identity differs')
    execution = row['execution_process']
    _process_evidence(execution, [executable], directory, 'cases')
    observed = _json(execution['stdout'])
    _fields(observed, {'version', 'cases', 'allocation_sites', 'pointer_guards', 'ordinary_live_delta'}, 'native observations')
    require(strict_equal(row['execution'], observed) and observed['version'] == locked['version']
            and strict_equal(observed['cases'], expected_rows()) and type(observed['pointer_guards']) is int
            and observed['pointer_guards'] == 2 and type(observed['ordinary_live_delta']) is int
            and observed['ordinary_live_delta'] == 0, 'native cases, guards or lifecycle results differ')
    calibration = row['calibration']
    _fields(calibration, {'process', 'observation'}, 'calibration')
    _process_evidence(calibration['process'], [executable, '--calibrate'], directory, 'calibration')
    calibrated = _json(calibration['process']['stdout'])
    sites = calibrated.get('allocation_sites')
    require(type(sites) is int and 0 < sites < 128 and type(observed['allocation_sites']) is int
            and observed['allocation_sites'] == sites and strict_equal(calibration['observation'], calibrated)
            and strict_equal(calibrated, {'version': locked['version'], 'allocation_sites': sites, 'value': 9, 'live_delta': 0}),
            'independently retained calibration denominator differs')
    faults = row['allocation_failures']
    require(isinstance(faults, list) and len(faults) == sites, 'every calibrated allocation site must be retained')
    for index, fault in enumerate(faults, 1):
        _fields(fault, {'site', 'status', 'observation', 'recovery_qualified', 'process'}, 'allocation observation')
        require(type(fault['site']) is int and fault['site'] == index, 'allocation index differs')
        if fault['status'] == 'caught_and_recovered':
            _process_evidence(fault['process'], [executable, str(index)], directory, f'fault-{index:04d}')
            expected = {'site': index, 'status': 3, 'output_preserved': True, 'live_delta': 0, 'recovered_value': 9}
            require(strict_equal(fault['observation'], expected) and strict_equal(_json(fault['process']['stdout']), expected)
                    and fault['recovery_qualified'] is True, 'catchable refusal/recovery observation differs')
        else:
            require(fault['status'] == 'foreign_noexcept_termination', 'unknown allocation outcome')
            _process_evidence(fault['process'], [executable, str(index)], directory, f'fault-{index:04d}', -signal.SIGABRT)
            require('std::bad_alloc' in fault['process']['stderr'] and fault['observation'] is None
                    and fault['recovery_qualified'] is False, 'termination cannot be credited as recovery')
    require(row['all_allocation_failure_paths_recovered'] is all(f['recovery_qualified'] for f in faults), 'recovery claim enlarged')
    commands = row['commands']
    require(isinstance(commands, list) and len(commands) == 3, 'compile/link command denominator differs')
    sources = (generated / 'bridge.cpp', EXAMPLE / 'harness.cpp')
    require(set(row['compile_dependencies']) == {'bridge', 'harness'}, 'actual compilation dependency denominator differs')
    for process, source in zip(commands[:2], sources):
        _process_evidence(process, _compile_argv(compiler, directory, source), directory, 'compile-' + source.stem)
        depfile = directory / (source.stem + '.d')
        dep = row['compile_dependencies'][source.stem]
        _fields(dep, {'path', 'sha256', 'files'}, 'compilation dependency file')
        require(dep['path'] == str(depfile) and dep['sha256'] == digest(depfile), 'actual compiler depfile differs')
        _file_closure(dep['files'], _dependency_paths(depfile.read_text()))
        require(str(source.resolve()) in dep['files'] and str((directory / 'selected.hpp').resolve()) in dep['files']
                and str((FIXTURES / locked['header']).resolve()) in dep['files'], 'compiled source/upstream omitted from dependency closure')
    _process_evidence(commands[2], [compiler, directory / 'bridge.o', directory / 'harness.o', library,
                                   '-pthread', '-ldl', '-lm', '-o', executable], directory, 'link')
    for name, stage in (('headers_before', 'headers-before'), ('headers_after', 'headers-after')):
        dependency = row[name]
        _fields(dependency, {'process', 'files'}, 'header dependency snapshot')
        _process_evidence(dependency['process'], [compiler, '-std=c++20', '-M', '-MT', 'hepta_headers', '-x', 'c++',
                                                directory / 'selected.hpp'], directory, stage)
        _file_closure(dependency['files'], _dependency_paths(dependency['process']['stdout']))
        require(dependency['files'].get(str((FIXTURES / locked['header']).resolve())) == locked['sha256']
                and dependency['files'].get(str((EXAMPLE / 'adapter.hpp').resolve())) == digest(EXAMPLE / 'adapter.hpp'), 'selected source closure missing')
    require(strict_equal(row['headers_before']['files'], row['headers_after']['files']), 'headers changed during execution')
    runtime = row['runtime_dependencies']
    _fields(runtime, {'process', 'files'}, 'runtime dependency snapshot')
    _process_evidence(runtime['process'], [tools['ldd']['path'], executable], directory, 'ldd')
    _file_closure(runtime['files'], _runtime_paths(runtime['process']['stdout']))
    symbols = row['symbol_process']
    _process_evidence(symbols, [tools['nm']['path'], '-g', '--defined-only', directory / 'bridge.o'], directory, 'symbols')
    actual_symbols = sorted(line.split()[-1] for line in symbols['stdout'].splitlines()
                            if line.split() and line.split()[-1].startswith('hepta_cpp_json_upgrade_'))
    expected_symbols = sorted(set(re.findall(r'\b(hepta_cpp_json_upgrade_[A-Za-z0-9_]+)\(', header)))
    require(actual_symbols == row['c_symbols'] == expected_symbols and bool(actual_symbols), 'observed C ABI symbols differ')
    ledger = [row['headers_before']['process'], *commands, execution, calibration['process'],
              *(f['process'] for f in faults), symbols, row['headers_after']['process'], runtime['process']]
    require(strict_equal(row['processes'], ledger), 'complete process ledger differs from required stages')
    cost = row['cost']
    cost_fields = {'bridge_generation_seconds', 'hepta_check_and_build_seconds', 'cpp_compile_link_seconds',
                   'native_case_execution_seconds', 'failure_observation_seconds', 'dependency_observation_seconds', 'total_seconds'}
    _fields(cost, cost_fields, 'cost')
    require(all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in cost.values()), 'invalid timing measurement')
    require(math.isclose(cost['cpp_compile_link_seconds'], sum(p['seconds'] for p in commands))
            and cost['native_case_execution_seconds'] == execution['seconds']
            and math.isclose(cost['failure_observation_seconds'], calibration['process']['seconds'] + sum(f['process']['seconds'] for f in faults))
            and math.isclose(cost['dependency_observation_seconds'], sum(p['seconds'] for p in ledger if p['stage'] in {'headers-before', 'headers-after', 'symbols', 'ldd'})),
            'cost observations differ from actual process timings')
    require(cost['bridge_generation_seconds'] > 0 and cost['hepta_check_and_build_seconds'] > 0
            and cost['total_seconds'] >= sum(v for k, v in cost.items() if k != 'total_seconds'), 'total timing omits measured work')
    require(fresh_check.project.unchanged(), 'current consumer project changed during validation')


@normalized_errors
def validate_report(report):
    """Check current retained artifacts and observations, without native reruns.

    This is an internal consistency gate. A party able to rewrite the complete
    file set and invent all observations is not authenticated by these hashes.
    """
    fields = {'schema', 'ok', 'status', 'workdir', 'processes', 'started_utc', 'finished_utc', 'protocol', 'protocol_sha256',
              'compiler_sha256', 'inputs', 'case_count_per_version', 'oracle_sha256', 'versions', 'claims',
              'negative_controls', 'native_tools', 'cxx', 'upgrade', 'inputs_unchanged'}
    _fields(report, fields, 'qualification')
    require(report['schema'] == SCHEMA and report['ok'] is True and report['status'] == 'passed', 'not a passing qualification')
    require(strict_equal(report['protocol'], PROTOCOL) and report['protocol_sha256'] == value_digest(PROTOCOL)
            and strict_equal(report['claims'], CLAIMS), 'protocol/closed claims differ')
    require(report['compiler_sha256'] == compiler_hash() and strict_equal(report['inputs'], source_inputs())
            and report['inputs_unchanged'] is True, 'current compiler/source inputs differ')
    require(type(report['case_count_per_version']) is int and report['case_count_per_version'] == len(cases())
            and report['oracle_sha256'] == value_digest(expected_rows()), 'independent oracle denominator differs')
    require(isinstance(report['started_utc'], str) and isinstance(report['finished_utc'], str)
            and datetime.fromisoformat(report['finished_utc']) >= datetime.fromisoformat(report['started_utc']), 'qualification timestamps differ')
    root = Path(report['workdir'])
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'retained work directory missing')
    tools = report['native_tools']
    _fields(tools, {'cxx', 'nm', 'ldd'}, 'native tool inventory')
    for tool in tools.values():
        _fields(tool, {'path', 'sha256'}, 'native tool')
        require(isinstance(tool['path'], str) and Path(tool['path']).is_absolute() and is_sha(tool['sha256'])
                and tool['sha256'] == digest(tool['path']), 'current native tool identity differs')
    _fields(report['cxx'], {'path', 'sha256', 'version'}, 'C++ compiler')
    require(len(report['processes']) == 1, 'compiler version process missing')
    _process_evidence(report['processes'][0], [tools['cxx']['path'], '--version'], root, 'cxx-version')
    require(strict_equal(report['cxx'], dict(tools['cxx'], version=report['processes'][0]['stdout'])), 'C++ version observation differs')
    rows = report['versions']
    require(isinstance(rows, list) and len(rows) == len(VERSIONS), 'two exact upstream versions required')
    for row, locked in zip(rows, locked_libraries()):
        _validate_version(row, locked, root, tools)
    upgrade = report['upgrade']
    expected_upgrade = {'from': VERSIONS[0], 'to': VERSIONS[1], 'source_files_patched': [], 'source_lines_changed': 0,
        'contract_changes': 0, 'hepta_caller_changes': 0, 'generated_identity_equal': True, 'c_export_symbols_equal': True,
        'c_boundary_executed_on_both_versions': True,
        'authored_initial_adapter_lines': len((EXAMPLE / 'adapter.hpp').read_text().splitlines()),
        'authored_initial_contract_lines': len((EXAMPLE / 'contract.json').read_text().splitlines()),
        'authored_initial_hepta_lines': len((EXAMPLE / 'consumer.hepta').read_text().splitlines()),
        'human_review_hours': None, 'agent_tokens': None, 'cost_scope': COST_SCOPE}
    require(strict_equal(upgrade, expected_upgrade) and strict_equal(rows[0]['generated_identity'], rows[1]['generated_identity'])
            and rows[0]['c_symbols'] == rows[1]['c_symbols'], 'upgrade modification or development-cost claims differ')
    controls = report['negative_controls']
    _fields(controls, {'status', 'processes', 'incompatible_signature', 'wrong_implementation'}, 'negative controls')
    require(controls['status'] == 'passed', 'negative controls did not finish')
    incompatible = controls['incompatible_signature']
    _fields(incompatible, {'report', 'output_published', 'contract_path', 'contract_sha256'}, 'incompatible signature')
    bad_contract = _json((EXAMPLE / 'contract.json').read_text())
    bad_contract['handles'][0]['methods'][1]['returns'] = 'u32'
    contract_path = root / 'incompatible-contract.json'
    require(incompatible['contract_path'] == str(contract_path) and incompatible['contract_sha256'] == digest(contract_path)
            and contract_path.read_text() == json.dumps(bad_contract, indent=2, sort_keys=True) + '\n'
            and incompatible['output_published'] is False and not (root / 'bad-contract').exists()
            and incompatible['report'].get('ok') is False and incompatible['report'].get('status') == 'rejected'
            and [d.get('code') for d in incompatible['report'].get('diagnostics', [])] == ['E_CPP_NATIVE'], 'actual incompatible signature rejection missing')
    wrong = controls['wrong_implementation']
    _fields(wrong, {'source_sha256', 'object_sha256', 'executable_sha256', 'compile_process', 'link_process', 'execution_process', 'first_mismatch'},
            'wrong implementation control')
    directory = root / VERSIONS[-1]
    wrong_source, wrong_object, wrong_executable = (directory / name for name in ('wrong-bridge.cpp', 'wrong-bridge.o', 'wrong-json-upgrade'))
    cpp = (directory / 'bridge/bridge.cpp').read_text()
    needle = '*out = _hepta_scoped_result;'
    require(cpp.count(needle) == 1 and wrong_source.read_text() == cpp.replace(needle, '*out = _hepta_scoped_result + 1;')
            and wrong['source_sha256'] == digest(wrong_source) and wrong['object_sha256'] == digest(wrong_object)
            and wrong['executable_sha256'] == digest(wrong_executable), 'negative implementation artifacts differ')
    compiler = tools['cxx']['path']
    _process_evidence(wrong['compile_process'], [compiler, '-std=c++20', '-O2', '-pthread', '-Werror', '-I' + str(directory / 'bridge'),
                                               '-c', wrong_source, '-o', wrong_object], root, 'negative-compile')
    _process_evidence(wrong['link_process'], [compiler, wrong_object, directory / 'harness.o', directory / 'consumer.a',
                                            '-pthread', '-ldl', '-lm', '-o', wrong_executable], root, 'negative-link')
    _process_evidence(wrong['execution_process'], [wrong_executable], root, 'negative-execute', 2)
    require(strict_equal(controls['processes'], [wrong['compile_process'], wrong['link_process'], wrong['execution_process']]),
            'negative process ledger differs')
    require(wrong['execution_process']['stderr'] == 'allocation calibration call\n', 'wrong implementation failed a different check')
    observations = _json(wrong['execution_process']['stdout'] + ']}')['cases']
    mismatch = next((r for r, e in zip(observations, expected_rows()) if not strict_equal(r, e)), None)
    require(len(observations) == len(cases()) and mismatch is not None and strict_equal(wrong['first_mismatch'], mismatch)
            and type(mismatch['hepta_value']) is int and type(mismatch['direct_value']) is int
            and mismatch['hepta_value'] == mismatch['direct_value'] + 1, 'wrong actual native value was not observed')
    require(report['compiler_sha256'] == compiler_hash() and strict_equal(report['inputs'], source_inputs()), 'inputs changed during validation')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--rustc')
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error('qualification output must not exist')
    try:
        report = qualify_cpp_upgrade(args.workdir, cxx=args.cxx, rustc=args.rustc)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        report = {'schema': SCHEMA, 'ok': False, 'status': 'failed', 'error': str(exc),
                  'versions': [{'version': version, 'status': 'not_run'} for version in VERSIONS]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as destination:
        json.dump(report, destination, indent=2)
        destination.write('\n')
    print(json.dumps({'ok': report['ok'], 'status': report['status'], 'output': str(args.output)}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
