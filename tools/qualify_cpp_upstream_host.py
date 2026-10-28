"""Execute two pinned upstream C++ library versions through actual Hepta on one host.

Library reuse is qualified separately from source translation. This finite
profile adds persistent handle lifetime and between-call cancellation to the
existing scoped nlohmann/json upgrade; foreign UB/termination stay unproved.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import _Generator, _validate, bridge_cpp_contracts
from hepta.cpp_host_toolchain import PROBE, parse_probe, compiler_identity, compile_command, link_command
from hepta.pipeline import analyze_project, compiler_hash
from tools.qualify_cpp_upgrade import (EXAMPLE, FIXTURES, VERSIONS, _case_source,
    _selected_source, _run, digest, expected_rows, locked_libraries)
from tools.validate_native_host import target_shape
from tools.evidence_checks import native_build, normalized_errors, strict_equal

HOST_EXAMPLE = ROOT / 'examples/cpp/upstream_host'
SCHEMA = 'hepta.cpp-upstream-host.v1'
CLAIMS = {
    'actual_reported_host_executed': True, 'cross_host_results_inferred': False,
    'actual_hepta_consumer_executed': True, 'unchanged_upstream_library_reused': True,
    'foreign_library_rewritten': False, 'foreign_memory_safety_proved': False,
    'all_foreign_allocation_failures_recovered': False, 'general_upgrade_compatibility_proved': False,
    'asynchronous_foreign_call_cancellation': False, 'general_borrow_retention_proved': False,
    'total_development_cost_measured': False,
}
SIGNATURE_MARKER = 'HEPTA_CPP_METHOD_RESULT:hepta_cpp_json_upgrade_Document_sum'


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def source_inputs():
    paths = [*ROOT.glob('hepta/*.py'), Path(__file__), ROOT / 'tools/qualify_cpp_upgrade.py',
             ROOT / 'tools/validate_native_host.py', ROOT / 'tools/evidence_checks.py',
             *HOST_EXAMPLE.iterdir(), *EXAMPLE.iterdir(),
             *FIXTURES.rglob('*')]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths)) if p.is_file()}


def inspect_executable(path, system, machine):
    data = Path(path).read_bytes()
    if system == 'Linux':
        valid = (len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01'
                 and struct.unpack_from('<H', data, 16)[0] in {2, 3}
                 and struct.unpack_from('<H', data, 18)[0] == {'x86_64': 62, 'aarch64': 183}[machine])
        fmt = 'ELF64'
    elif system == 'Darwin':
        valid = (len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe'
                 and struct.unpack_from('<I', data, 4)[0] == {'x86_64': 0x1000007, 'aarch64': 0x100000c}[machine]
                 and struct.unpack_from('<I', data, 12)[0] == 2)
        fmt = 'Mach-O64'
    elif system == 'Windows':
        offset = struct.unpack_from('<I', data, 60)[0] if len(data) >= 64 else len(data)
        valid = (data[:2] == b'MZ' and offset + 26 <= len(data) and data[offset:offset+4] == b'PE\0\0'
                 and struct.unpack_from('<H', data, offset+4)[0] == {'x86_64': 0x8664, 'aarch64': 0xaa64}[machine]
                 and struct.unpack_from('<H', data, offset+24)[0] == 0x20b)
        fmt = 'PE32+'
    else:
        valid, fmt = False, None
    if not valid:
        raise ValueError('Executable bytes disagree with the actual requested native host')
    return {'format': fmt, 'machine': machine, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def check_observation(observed, version):
    fixed = {'version': version, 'cases': expected_rows(), 'lifecycle_cases': 32,
             'borrowed_input_overwritten': 32, 'stale_reads': 32, 'duplicate_destroys': 32,
             'refused_mutations': 64, 'pointer_guards': 4, 'malformed_constructor': 1,
             'cancellation': {'requested': 7, 'committed': 3, 'value': 107, 'replayed': 0},
             'concurrent_calls': 1024, 'ordinary_live_delta': 0}
    if (not isinstance(observed, dict)
            or set(observed) != set(fixed) | {'registry_ordinary_allocations_retained'}
            or any(not strict_equal(observed[k], v) for k, v in fixed.items())
            or type(observed['registry_ordinary_allocations_retained']) is not int
            or observed['registry_ordinary_allocations_retained'] <= 0):
        raise ValueError('Actual upstream host observations differ from independent finite oracle')


def retain_signature_failure(directory, rejected):
    """Retain exact bounded diagnostic bytes and the actually rejected source."""
    work = directory / 'rejected-signature'
    work.mkdir()
    failure = rejected.get('failure', {})
    process = failure.get('process') or {}
    generated = failure.get('generated_inputs') or {}
    if (failure.get('phase') != 'cpp_compile' or process.get('status') != 'exited'
            or type(process.get('exit_code')) is not int or process['exit_code'] <= 0
            or process.get('raw_streams_available') is not True
            or SIGNATURE_MARKER not in (process.get('stdout', '') + process.get('stderr', ''))
            or set(generated.get('files', {})) != {'bridge.cpp', 'bridge.h', 'bridge.hepta'}):
        raise ValueError('Negative signature control did not reach the expected actual C++ assertion')
    paths = {}
    for name, record in generated['files'].items():
        data = record['text'].encode()
        if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('Rejected generated source identity differs')
        path = work / name
        path.write_bytes(data)
        paths[name] = str(path)
    for name in ['stdout', 'stderr']:
        raw = base64.b64decode(process[name + '_raw_base64'], validate=True)
        if len(raw) != process[name + '_raw_bytes'] or hashlib.sha256(raw).hexdigest() != process[name + '_raw_sha256']:
            raise ValueError('Rejected native diagnostic identity differs')
        path = work / (name + '.bin')
        path.write_bytes(raw)
        paths[name] = str(path)
    write_json(work / 'report.json', rejected)
    paths['report'] = str(work / 'report.json')
    return paths


def qualify(directory, *, cxx='g++', cxx_family='auto', rustc=None, linker=None,
            expected_system=None, expected_machine=None):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    system = platform.system()
    machine = {'AMD64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    report = {'schema': SCHEMA, 'status': 'failed', 'ok': False,
              'created_utc': datetime.now(timezone.utc).isoformat(), 'directory': str(directory),
              'host': {'system': system, 'machine': machine, 'execution': 'native_host_process',
                       'python': platform.python_version(), 'kernel': platform.release()},
              'versions': [], 'processes': [], 'claims': {**CLAIMS, 'actual_reported_host_executed': False,
                  'actual_hepta_consumer_executed': False, 'unchanged_upstream_library_reused': False}}
    try:
        if (system not in {'Linux', 'Darwin', 'Windows'} or machine not in {'x86_64', 'aarch64'}
                or expected_system is not None and expected_system != system
                or expected_machine is not None and expected_machine != machine):
            raise ValueError('Actual host differs from explicitly requested host')
        report['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['tracked_source_status'] = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, text=True)
        before = source_inputs()
        report['source_inputs'] = before
        report['compiler_sha256'] = compiler_hash()
        locked = locked_libraries()
        counter = 0
        def run_probe(argv):
            nonlocal counter
            counter += 1
            row = _run(argv, owner=report, directory=directory, stage=f'cxx-identity-{counter}')
            return subprocess.CompletedProcess(argv, row['exit_code'], row['stdout'], row['stderr'])
        compiler = compiler_identity(cxx, run_probe, family=cxx_family)
        report['cxx'] = compiler
        if (compiler['identity']['system'], compiler['identity']['machine']) != (system, machine):
            raise ValueError('Actual C++ compiler target differs from executing host')
        if target_shape(compiler['target']) != (system, machine):
            raise ValueError('C++ target triple and actual macro identity disagree')
        for item in locked:
            work = directory / item['version']
            work.mkdir()
            row = {'version': item['version'], 'status': 'running', 'processes': [], 'directory': str(work)}
            report['versions'].append(row)
            selected = work / 'selected.hpp'
            selected.write_text(_selected_source(item), encoding='utf-8', newline='\n')
            (work / 'cases.hpp').write_text(_case_source(), encoding='utf-8', newline='\n')
            generated = work / 'bridge'
            bridge = bridge_cpp_contracts(selected, EXAMPLE / 'contract.json', generated,
                cxx=compiler['path'], cxx_family=compiler['identity']['family'], rustc=rustc)
            row['bridge'] = bridge
            if not bridge['ok']:
                raise ValueError('Real native bridge generation failed: ' + json.dumps(bridge))
            shutil.copyfile(HOST_EXAMPLE / 'consumer.hepta', generated / 'consumer.hepta')
            checked = analyze_project(generated / 'consumer.hepta', native=False, crate_type='obj')
            row['frontend'] = checked.report
            write_json(generated / 'consumer.frontend.json', checked.report)
            if not checked.report['ok']:
                raise ValueError('Actual Hepta consumer frontend rejected')
            (generated / 'consumer.rs').write_text(checked.rust, encoding='utf-8', newline='\n')
            exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
            (generated / 'hepta.h').write_text(emit_header(exports), encoding='utf-8', newline='\n')
            suffix = '.obj' if system == 'Windows' else '.o'
            consumer = work / ('consumer' + suffix)
            native = compile_rust(checked.rust, rustc=rustc, crate_type='obj', output=consumer, linker=linker)
            row['native'] = native
            write_json(generated / 'consumer.native.json', native)
            if not native.get('ok') or target_shape(native['target']) != (system, machine):
                raise ValueError('Compiled Hepta consumer does not match actual host')
            objects = []
            for source in (generated / 'bridge.cpp', HOST_EXAMPLE / 'harness.cpp'):
                obj = work / (source.stem + suffix)
                dep = work / (source.stem + '.d')
                _run(compile_command(compiler, source, obj, includes=[generated, work], dependency=dep),
                     owner=row, directory=work, stage='compile-' + source.stem)
                objects.append(obj)
            executable = work / ('upstream-host.exe' if system == 'Windows' else 'upstream-host')
            row['link'] = _run(link_command(compiler, [*objects, consumer], executable),
                               owner=row, directory=work, stage='link')
            row['executable'] = inspect_executable(executable, system, machine)
            run = _run([executable], owner=row, directory=work, stage='execute', timeout=45)
            row['execution'] = run
            observed = json.loads(run['stdout'])
            check_observation(observed, item['version'])
            row['observed'] = observed
            row['source_and_license'] = item
            row['generated_identity'] = {name: digest(generated / name)
                for name in ['bridge.hepta', 'bridge.h', 'contract.json', 'consumer.hepta']}
            row['status'] = 'passed'
        if report['versions'][0]['generated_identity'] != report['versions'][1]['generated_identity']:
            raise ValueError('Upstream upgrade silently changed the public bridge/consumer contract')
        # Same oracle must reject a genuinely compiled wrong implementation.
        latest = report['versions'][-1]
        work = Path(latest['directory'])
        generated = work / 'bridge'
        wrong = (generated / 'bridge.cpp').read_text(encoding='utf-8')
        needle = '*out = _hepta_scoped_result;'
        if wrong.count(needle) != 1:
            raise ValueError('Unique scoped native publication site missing')
        wrong_source = work / 'wrong.cpp'
        wrong_source.write_text(wrong.replace(needle, '*out = _hepta_scoped_result + 1;'), encoding='utf-8', newline='\n')
        wrong_object = work / ('wrong' + suffix)
        _run(compile_command(compiler, wrong_source, wrong_object, includes=[generated, work]),
             owner=report, directory=directory, stage='wrong-compile')
        wrong_exe = work / ('wrong.exe' if system == 'Windows' else 'wrong')
        _run(link_command(compiler, [wrong_object, work / ('harness' + suffix), work / ('consumer' + suffix)], wrong_exe),
             owner=report, directory=directory, stage='wrong-link')
        wrong_run = _run([wrong_exe], owner=report, directory=directory, stage='wrong-execute', allow_failure=True)
        if wrong_run['exit_code'] != 2 or 'actual direct/Hepta result mismatch' not in wrong_run['stderr']:
            raise ValueError('Independent native oracle failed to reject the actual wrong implementation')
        report['wrong_code'] = {'status': 'rejected', 'process': wrong_run,
                                'artifact': inspect_executable(wrong_exe, system, machine)}
        # Changing a result type must fail at real C++ compilation before publication.
        bad_contract = json.loads((EXAMPLE / 'contract.json').read_text())
        bad_contract['handles'][0]['methods'][1]['returns'] = 'u32'
        write_json(directory / 'bad-contract.json', bad_contract)
        bad_dir = directory / 'bad-bridge'
        rejected = bridge_cpp_contracts(work / 'selected.hpp', bad_contract, bad_dir,
            cxx=compiler['path'], cxx_family=compiler['identity']['family'], rustc=rustc)
        report['incompatible_signature'] = rejected
        if rejected['ok'] or bad_dir.exists() or [x['code'] for x in rejected['diagnostics']] != ['E_CPP_NATIVE']:
            raise ValueError('Actual incompatible C++ return type was not rejected before publication')
        report['incompatible_signature_evidence'] = retain_signature_failure(directory, rejected)
        if before != source_inputs() or report['compiler_sha256'] != compiler_hash():
            raise ValueError('Source or upstream input changed during host qualification')
        if digest(compiler['path']) != compiler['executable_sha256']:
            raise ValueError('Actual C++ compiler changed during qualification')
        report['inputs_unchanged'] = True
        report['claims'] = CLAIMS.copy()
        report['status'], report['ok'] = 'passed', True
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        report['error'] = str(exc)
    finally:
        report['retained_files'] = {str(p.relative_to(directory)): {'sha256': digest(p), 'bytes': p.stat().st_size}
            for p in sorted(directory.rglob('*')) if p.is_file()}
        write_json(directory / 'qualification.json', report)
    return report


@normalized_errors
def validate_report(report):
    """Read-only byte and original-observation check; never rebuild native code."""
    if (report.get('schema') != SCHEMA or report.get('status') != 'passed' or report.get('ok') is not True
            or report.get('claims') != CLAIMS or report.get('inputs_unchanged') is not True
            or report.get('compiler_sha256') != compiler_hash() or report.get('source_inputs') != source_inputs()
            or [v.get('version') for v in report.get('versions', [])] != list(VERSIONS)):
        raise ValueError('Upstream host qualification scope or source differs')
    directory = Path(report['directory'])
    if (report.get('source_commit') != subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            or report.get('tracked_source_status') != subprocess.check_output(
                ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, text=True)):
        raise ValueError('Original Git source identity or tracked working state differs')
    retained = report['retained_files']
    actual_names = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()
                    and p not in {directory / 'qualification.json', directory / 'audit.json'}}
    if set(retained) != actual_names:
        raise ValueError('Retained host evidence file set changed')
    for name, identity in retained.items():
        p = directory / name
        if (p.is_symlink() or not p.resolve().is_relative_to(directory.resolve())
                or digest(p) != identity['sha256'] or p.stat().st_size != identity['bytes']):
            raise ValueError('Retained upstream host artifact differs: ' + name)
    host = report['host']
    compiler = report['cxx']
    if ((host['system'], host['machine']) != (compiler['identity']['system'], compiler['identity']['machine'])
            or digest(compiler['path']) != compiler['executable_sha256']
            or parse_probe(compiler['macro_probe']['stdout']) != compiler['identity']
            or compiler['macro_probe']['source'] != PROBE
            or compiler['macro_probe']['exit_code'] != 0
            or target_shape(compiler['target']) != (host['system'], host['machine'])):
        raise ValueError('Native host and compiler identity differ')

    def process_evidence(process, argv, *, code=0):
        if (process['argv'] != list(map(str, argv)) or process['exit_code'] != code
                or process['status'] != 'exited' or process['executable_unchanged'] is not True
                or digest(process['argv'][0]) != process['executable_sha256']):
            raise ValueError('Original executable, command or exit status differs')
        for channel in ['stdout', 'stderr']:
            path = Path(process[channel + '_path'])
            raw = path.read_bytes()
            if (not path.resolve().is_relative_to(directory.resolve())
                    or hashlib.sha256(raw).hexdigest() != process[channel + '_sha256']
                    or base64.b64decode(process[channel + '_bytes_base64'], validate=True) != raw
                    or raw.decode('utf-8', errors='replace') != process[channel]):
                raise ValueError('Original native process stream differs')

    identity_count = 1 if compiler['driver'] == 'msvc' else 3
    expected_stages = [f'cxx-identity-{i+1}' for i in range(identity_count)] + ['wrong-compile', 'wrong-link', 'wrong-execute']
    if [p['stage'] for p in report['processes']] != expected_stages:
        raise ValueError('Actual compiler identity/control process set differs')
    identity_rows = report['processes'][:identity_count]
    original_probe = identity_rows[0]
    probe_source = Path(compiler['macro_probe']['argv'][-1])
    expected_probe = ([compiler['path'], '/nologo', '/std:c++20', '/Zc:__cplusplus', '/EP', '/TP', str(probe_source)]
        if compiler['driver'] == 'msvc' else
        [compiler['path'], '-std=c++20', '-E', '-P', '-x', 'c++', str(probe_source)])
    if probe_source.name != 'identity.cpp' or not probe_source.parent.name.startswith('hepta-cxx-identity-'):
        raise ValueError('Unexpected actual C++ identity source path')
    process_evidence(original_probe, expected_probe)
    if (compiler['macro_probe']['argv'] != original_probe['argv']
            or compiler['macro_probe']['stdout'] != original_probe['stdout']
            or compiler['macro_probe']['stderr'] != original_probe['stderr']
            or parse_probe(original_probe['stdout']) != compiler['identity']):
        raise ValueError('C++ family/target identity differs from its actual original raw process')
    if compiler['driver'] != 'msvc':
        process_evidence(identity_rows[1], [compiler['path'], '--version'])
        process_evidence(identity_rows[2], [compiler['path'], '-dumpmachine'])
        if (compiler['version'] != identity_rows[1]['stdout'].splitlines()[0]
                or compiler['target'] != identity_rows[2]['stdout'].strip()):
            raise ValueError('C++ version/target metadata differs from actual original process')
    else:
        a, b = compiler['identity']['version_components']
        if (compiler['version'] != f'MSVC _MSC_FULL_VER={a} _MSC_BUILD={b}'
                or compiler['target'] != compiler['identity']['machine'] + '-pc-windows-msvc'):
            raise ValueError('MSVC identity differs from actual predefined macros')

    def same_compiler(nested):
        fields = ['path', 'version', 'target', 'executable_sha256', 'driver', 'identity']
        if (any(not strict_equal(nested[k], compiler[k]) for k in fields)
                or nested['macro_probe']['source'] != PROBE
                or nested['macro_probe']['exit_code'] != 0
                or parse_probe(nested['macro_probe']['stdout']) != compiler['identity']):
            raise ValueError('Nested bridge compiler differs from actually observed host compiler')

    locked = locked_libraries()
    suffix = '.obj' if host['system'] == 'Windows' else '.o'
    actual_rust = None
    for row in report['versions']:
        work = Path(row['directory'])
        generated = work / 'bridge'
        selected = work / 'selected.hpp'
        lock = next(item for item in locked if item['version'] == row['version'])
        if (row['source_and_license'] != lock or selected.read_text() != _selected_source(lock)
                or (work / 'cases.hpp').read_text() != _case_source()
                or (generated / 'consumer.hepta').read_bytes() != (HOST_EXAMPLE / 'consumer.hepta').read_bytes()):
            raise ValueError('Executed upstream input or actual Hepta caller differs')
        contract = _validate(json.loads((EXAMPLE / 'contract.json').read_text()))
        cpp, header, hp = _Generator(selected, contract).render()
        for name, expected in [('bridge.cpp', cpp), ('bridge.h', header), ('bridge.hepta', hp)]:
            if (generated / name).read_bytes() != expected.encode():
                raise ValueError('Compiled bridge differs from current checked contract')
        fresh = analyze_project(generated / 'consumer.hepta', native=False, crate_type='obj')
        if (not fresh.report['ok'] or not strict_equal(fresh.report, row['frontend'])
                or (generated / 'consumer.rs').read_bytes() != fresh.rust.encode()):
            raise ValueError('Executed consumer differs from actual Hepta frontend lowering')
        exports = replace(fresh.program, functions=[f for f in fresh.program.functions if f.export_c])
        if (generated / 'hepta.h').read_bytes() != emit_header(exports).encode():
            raise ValueError('Actual consumer C ABI header differs')
        if (json.loads((generated / 'consumer.native.json').read_text()) != row['native']
                or json.loads((generated / 'report.json').read_text()) != row['bridge']
                or row['bridge']['ok'] is not True):
            raise ValueError('Original native build receipts differ')
        same_compiler(row['bridge']['compiler'])
        consumer = work / ('consumer' + suffix)
        native_build(row['native'], 'rust', check_only=False, crate_type='obj', source_sha256=fresh.report['rust_sha256'])
        rust = row['native']['toolchain']
        if (digest(rust['path']) != rust['executable_sha256']
                or row['bridge']['hepta_validation']['backend']['toolchain'] != rust
                or actual_rust is not None and rust != actual_rust):
            raise ValueError('Actual Rust tool identity differs across builds or current executable bytes')
        actual_rust = rust
        if (row['native']['artifact'] != str(consumer)
                or target_shape(row['native']['target']) != (host['system'], host['machine'])):
            raise ValueError('Actual Hepta native object has a different target or path')
        check_observation(row['observed'], row['version'])
        if row['status'] != 'passed' or json.loads(Path(row['execution']['stdout_path']).read_text()) != row['observed']:
            raise ValueError('Original native observations differ')
        exe = Path(row['execution']['argv'][0])
        if inspect_executable(exe, host['system'], host['machine']) != row['executable']:
            raise ValueError('Actual executed host binary differs')
        if row['native']['artifact_sha256'] != digest(row['native']['artifact']):
            raise ValueError('Actual compiled Hepta object differs')
        if [p['stage'] for p in row['processes']] != ['compile-bridge', 'compile-harness', 'link', 'execute']:
            raise ValueError('Actual native command denominator differs')
        objects = [work / ('bridge' + suffix), work / ('harness' + suffix), consumer]
        process_evidence(row['processes'][0], compile_command(compiler, generated / 'bridge.cpp', objects[0],
            includes=[generated, work], dependency=work / 'bridge.d'))
        process_evidence(row['processes'][1], compile_command(compiler, HOST_EXAMPLE / 'harness.cpp', objects[1],
            includes=[generated, work], dependency=work / 'harness.d'))
        process_evidence(row['processes'][2], link_command(compiler, objects, exe))
        process_evidence(row['processes'][3], [exe])
        if row['link'] != row['processes'][2] or row['execution'] != row['processes'][3]:
            raise ValueError('Executed records differ from original command records')
        if set(row['generated_identity']) != {'bridge.hepta', 'bridge.h', 'contract.json', 'consumer.hepta'}:
            raise ValueError('Generated ABI/source identity set differs')
        for name, identity in row['generated_identity'].items():
            if digest(generated / name) != identity:
                raise ValueError('Upstream ABI/source identity differs')
    if report['versions'][0]['generated_identity'] != report['versions'][1]['generated_identity']:
        raise ValueError('Upstream upgrade changed the consumer contract')
    work = Path(report['versions'][-1]['directory'])
    wrong_exe = work / ('wrong.exe' if host['system'] == 'Windows' else 'wrong')
    controls = [p for p in report['processes'] if p['stage'].startswith('wrong-')]
    if [p['stage'] for p in controls] != ['wrong-compile', 'wrong-link', 'wrong-execute']:
        raise ValueError('Missing actual wrong-code commands')
    original_cpp = (work / 'bridge/bridge.cpp').read_text()
    wrong_needle = '*out = _hepta_scoped_result;'
    if (original_cpp.count(wrong_needle) != 1
            or (work / 'wrong.cpp').read_text() != original_cpp.replace(wrong_needle, '*out = _hepta_scoped_result + 1;')):
        raise ValueError('Actually compiled wrong-code source is not the declared unique mutation')
    process_evidence(controls[0], compile_command(compiler, work / 'wrong.cpp', work / ('wrong' + suffix),
        includes=[work / 'bridge', work]))
    process_evidence(controls[1], link_command(compiler,
        [work / ('wrong' + suffix), work / ('harness' + suffix), work / ('consumer' + suffix)], wrong_exe))
    process_evidence(controls[2], [wrong_exe], code=2)
    if (report['wrong_code']['process'] != controls[2]
            or 'actual direct/Hepta result mismatch' not in controls[2]['stderr']
            or inspect_executable(wrong_exe, host['system'], host['machine']) != report['wrong_code']['artifact']
            or report['incompatible_signature']['ok'] is not False
            or [d['code'] for d in report['incompatible_signature']['diagnostics']] != ['E_CPP_NATIVE']
            or (directory / 'bad-bridge').exists()):
        raise ValueError('Required negative control absent')
    rejected = report['incompatible_signature']
    paths = report['incompatible_signature_evidence']
    if (set(paths) != {'bridge.cpp', 'bridge.h', 'bridge.hepta', 'stdout', 'stderr', 'report'}
            or json.loads(Path(paths['report']).read_text()) != rejected):
        raise ValueError('Original bad-signature receipt differs')
    same_compiler(rejected['compiler'])
    failure = rejected['failure']
    process = failure['process']
    inputs = failure['generated_inputs']
    bad_contract = json.loads((EXAMPLE / 'contract.json').read_text())
    bad_contract['handles'][0]['methods'][1]['returns'] = 'u32'
    if (failure['phase'] != 'cpp_compile' or process['status'] != 'exited'
            or type(process['exit_code']) is not int or process['exit_code'] <= 0
            or process['raw_streams_available'] is not True or process['executable_unchanged'] is not True
            or process['executable_sha256'] != compiler['executable_sha256']
            or process['timeout_seconds'] != 90 or process['stdout_limit'] != 64000 or process['stderr_limit'] != 256000
            or inputs['contract'] != bad_contract
            or json.loads((directory / 'bad-contract.json').read_text()) != bad_contract
            or inputs['contract_sha256'] != hashlib.sha256(json.dumps(bad_contract, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            or inputs['header'] != str(work / 'selected.hpp') or inputs['header_sha256'] != digest(work / 'selected.hpp')):
        raise ValueError('Bad-signature refusal lacks the actual expected compile/input binding')
    source_path, object_path, dependency_path = map(Path, [inputs['source_path'], inputs['object_path'], inputs['dependency_path']])
    if (source_path.name != 'bridge.cpp' or object_path != source_path.with_name('bridge.o')
            or dependency_path != source_path.with_name('bridge.d')
            or not source_path.parent.name.startswith('hepta-cpp-contract-')
            or process['argv'] != compile_command(compiler, source_path, object_path, dependency=dependency_path)):
        raise ValueError('Bad-signature control executed a different native command or phase')
    bad_cpp, bad_h, bad_hp = _Generator(work / 'selected.hpp', _validate(bad_contract)).render()
    if set(inputs['files']) != {'bridge.cpp', 'bridge.h', 'bridge.hepta'}:
        raise ValueError('Rejected-source denominator differs')
    for name, source in [('bridge.cpp', bad_cpp), ('bridge.h', bad_h), ('bridge.hepta', bad_hp)]:
        data = source.encode()
        if (Path(paths[name]).read_bytes() != data
                or inputs['files'][name] != {'text': source, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}):
            raise ValueError('Actually rejected generated source differs from the bound bad contract')
    for name, limit in [('stdout', 64000), ('stderr', 256000)]:
        raw = Path(paths[name]).read_bytes()
        normalized = raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')
        if (len(raw) > limit or len(raw) != process[name + '_raw_bytes']
                or hashlib.sha256(raw).hexdigest() != process[name + '_raw_sha256']
                or base64.b64decode(process[name + '_raw_base64'], validate=True) != raw
                or process[name] != normalized):
            raise ValueError('Actual rejected compiler raw diagnostic bytes differ')
    if SIGNATURE_MARKER not in process['stdout'] + process['stderr']:
        raise ValueError('Compilation failed for a reason other than the required method result assertion')
    return {'status': 'passed', 'versions': len(report['versions']), 'retained_files': len(retained),
            'native_routes_per_version': 2, 'cases_per_version': len(expected_rows()),
            'claims': 'read_only_evidence_check_not_new_execution'}


def negative_evidence_controls(report):
    """Adversarial metadata copies must not replace the original native proof."""
    def relabel_compiler(value):
        old = value['cxx']['identity']['family']
        new = 'clang' if old == 'gcc' else 'gcc'
        value['cxx']['identity']['family'] = new
        value['cxx']['macro_probe']['stdout'] = value['cxx']['macro_probe']['stdout'].replace(
            'HEPTA_CXX_FAMILY ' + old, 'HEPTA_CXX_FAMILY ' + new)
    changes = {
        'compiler_family_and_inline_probe_relabelled': relabel_compiler,
        'original_identity_process_removed': lambda r: r['processes'].pop(0),
        'failed_identity_probe_substituted': lambda r: r['incompatible_signature']['failure'].update(phase='compiler_identity'),
        'missing_compiler_substituted': lambda r: r['incompatible_signature']['failure'].update(
            phase='compiler_identity', process=None),
        'version_command_substituted_for_compile': lambda r: r['incompatible_signature']['failure']['process'].update(
            argv=[r['cxx']['path'], '--version']),
        'forged_bad_contract': lambda r: r['incompatible_signature']['failure']['generated_inputs']['contract']['handles'][0]['methods'][1].update(returns='u64'),
        'raw_diagnostic_bytes_missing': lambda r: r['incompatible_signature']['failure']['process'].update(raw_streams_available=False),
        'rust_tool_identity_drift': lambda r: r['versions'][0]['native']['toolchain'].update(executable_sha256='0' * 64),
    }
    results = []
    for name, mutate in changes.items():
        changed = deepcopy(report)
        mutate(changed)
        try:
            validate_report(changed)
        except ValueError as exc:
            results.append({'name': name, 'rejected': True, 'reason': str(exc)})
        else:
            raise ValueError('Native evidence validator accepted metadata substitution: ' + name)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--cxx-family', choices=['auto', 'gcc', 'clang', 'msvc'], default='auto')
    parser.add_argument('--rustc')
    parser.add_argument('--linker')
    parser.add_argument('--expected-system')
    parser.add_argument('--expected-machine')
    args = parser.parse_args(argv)
    report = qualify(args.output_directory, cxx=args.cxx, cxx_family=args.cxx_family, rustc=args.rustc,
        linker=args.linker, expected_system=args.expected_system, expected_machine=args.expected_machine)
    if report['ok']:
        audit = validate_report(report)
        audit['negative_evidence_controls'] = negative_evidence_controls(report)
        write_json(args.output_directory / 'audit.json', audit)
    print(json.dumps({'status': report['status'], 'directory': report['directory'],
                      'versions_passed': sum(x['status'] == 'passed' for x in report['versions']),
                      'error': report.get('error')}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
