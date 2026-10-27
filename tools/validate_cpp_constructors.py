"""Qualify typed constructor bridges against installed Boost.Math and STL.

The real libraries remain C++. Authored span/POD/noexcept probes are identified
separately. Construction/destruction and steady-state methods have separate
observed timing rows; there is no universal zero-overhead claim.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import bridge_cpp_contracts
from hepta.pipeline import analyze_project, compiler_hash
from tools.validate_cpp import _digest, _run

EXAMPLE = ROOT / 'examples/cpp/constructors'
PAIRS = [('native_vector_create_destroy', 'handle_vector_create_destroy'),
         ('native_student_create_destroy', 'handle_student_create_destroy'),
         ('native_vector_size', 'handle_vector_size'),
         ('native_student_degrees', 'handle_student_degrees')]
NEGATIVE_CONTROLS = ('empty_constructors', 'retained_constructor_borrow', 'constructor_method_name_collision',
                     'constructor_local_name_collision', 'missing_borrow_retention', 'false_constructor_noexcept',
                     'nondefault_type_without_arguments', 'wrong_constructor_arity')


def qualification_sources():
    return {name: _digest(ROOT / name) for name in ('tools/validate_cpp_constructors.py', 'tools/validate_cpp.py')}


def _dependencies(compiler):
    output = _run([compiler, '-std=c++20', '-M', '-MT', 'hepta_headers', '-x', 'c++', str(EXAMPLE / 'foreign.hpp')]).stdout
    body = output.replace('\\\n', ' ').split(':', 1)[1]
    paths = sorted({str(Path(token).resolve()) for token in shlex.split(body)})
    return {path: _digest(Path(path)) for path in paths}


def _negative_controls(root, cxx, rustc):
    original = json.loads((EXAMPLE / 'contract.json').read_text())
    results = []
    for name in NEGATIVE_CONTROLS:
        contract = copy.deepcopy(original)
        student, span = contract['handles'][1], contract['handles'][2]
        if name == 'empty_constructors': student['constructors'] = []
        elif name == 'retained_constructor_borrow': span['constructors'][0]['params'][1]['retention'] = 'object_lifetime'
        elif name == 'constructor_method_name_collision': student['constructors'][0]['name'] = 'degrees'
        elif name == 'constructor_local_name_collision': student['constructors'][0]['params'][0]['name'] = 'entry'
        elif name == 'missing_borrow_retention': del span['constructors'][0]['params'][1]['retention']
        elif name == 'false_constructor_noexcept': student['constructors'][0]['exception'] = 'noexcept'
        elif name == 'nondefault_type_without_arguments': student['constructors'][0]['params'] = []
        elif name == 'wrong_constructor_arity': student['constructors'][0]['params'].append({'name': 'extra', 'type': 'u64', 'mode': 'value'})
        expected = 'E_CPP_NATIVE' if name in NEGATIVE_CONTROLS[-3:] else 'E_CPP_CONTRACT'
        target = root / ('negative-' + name)
        report = bridge_cpp_contracts(EXAMPLE / 'foreign.hpp', contract, target, cxx=cxx, rustc=rustc)
        rejected = report.get('ok') is False and not target.exists() and [d.get('code') for d in report.get('diagnostics', [])] == [expected]
        results.append({'id': name, 'rejected': rejected, 'expected_code': expected,
                        'output_directory_created': target.exists(), 'diagnostics': report.get('diagnostics'),
                        'contract_sha256': hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()})
    return results


def qualify_cpp_constructors(directory, *, cxx='g++', rustc=None, benchmark=True, iterations=100000, negative_controls=True):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    result = {'schema': 'hepta.cpp-constructor-qualification.v1', 'ok': False,
              'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'compiler_sha256': compiler_hash(),
              'scope': 'installed_Boost_Math_Student_and_std_vector_with_separate_authored_constructor_probes',
              'contract_version': 'hepta.cpp-contract.v2', 'foreign_cpp_library_rewritten': False,
              'whole_library_memory_safety_proved': False, 'borrow_retention_proved': False,
              'exact_constructor_parameter_signature_proved': False, 'universal_performance_advantage_proved': False,
              'actual_ai_model_runs': 0, 'execution': None, 'native_link_qualified': False,
              'qualification_sources': qualification_sources(),
              'negative_controls': [], 'performance': {'status': 'not_run'}}
    compiler = shutil.which(cxx)
    if not compiler:
        raise ValueError('C++ compiler is unavailable')
    before_inputs = {str(p.relative_to(ROOT)): _digest(p) for p in sorted(EXAMPLE.iterdir()) if p.is_file()}
    before_headers = _dependencies(compiler)
    generated = root / 'bridge'
    bridge = bridge_cpp_contracts(EXAMPLE / 'foreign.hpp', EXAMPLE / 'contract.json', generated, cxx=cxx, rustc=rustc)
    result['bridge_generation'] = bridge
    if not bridge['ok']:
        return result
    shutil.copyfile(EXAMPLE / 'consumer.hepta', generated / 'consumer.hepta')
    checked = analyze_project(generated / 'consumer.hepta', rustc=rustc, crate_type='staticlib')
    result['hepta_consumer'] = checked.report
    if not checked.report['ok']:
        return result
    exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
    (generated / 'hepta.h').write_text(emit_header(exports))
    library = root / 'consumer.a'
    native = compile_rust(checked.rust, rustc=rustc, crate_type='staticlib', output=library)
    result['hepta_native_library'] = native
    if not native['ok']:
        return result
    flags = ['-std=c++20', '-O2', '-fPIC', '-pthread', '-Werror', '-I' + str(generated), '-I' + str(EXAMPLE)]
    objects = []
    for source in (generated / 'bridge.cpp', EXAMPLE / 'foreign.cpp', EXAMPLE / 'harness.cpp'):
        obj = root / (source.stem + '.o')
        _run([compiler, *flags, '-c', str(source), '-o', str(obj)])
        objects.append(obj)
    executable = root / 'cpp-constructor-check'
    _run([compiler, *(str(p) for p in objects), str(library), '-pthread', '-ldl', '-lm', '-o', str(executable)])
    run = _run([str(executable)], timeout=30)
    result.update(execution=json.loads(run.stdout), native_link_qualified=True,
                  execution_process={'returncode': run.returncode, 'stdout_sha256': hashlib.sha256(run.stdout.encode()).hexdigest(),
                                     'stderr_sha256': hashlib.sha256(run.stderr.encode()).hexdigest()},
                  executable_sha256=_digest(executable), build_flags=flags,
                  object_sha256={p.name: _digest(p) for p in objects},
                  platform={'system': platform.system(), 'machine': platform.machine(), 'release': platform.release()})
    macros = _run([compiler, '-std=c++20', '-dM', '-E', '-x', 'c++', '-include', 'boost/version.hpp', '/dev/null']).stdout
    version = re.search(r'^#define BOOST_VERSION (\d+)$', macros, re.MULTILINE)
    library = re.search(r'^#define BOOST_LIB_VERSION "([0-9_]+)"$', macros, re.MULTILINE)
    if not version or not library:
        raise RuntimeError('Installed Boost identity macros were not observed')
    result['boost'] = {'version': int(version.group(1)), 'library_version': library.group(1),
                       'students_t_headers': {p: value for p, value in before_headers.items() if p.endswith('/boost/math/distributions/students_t.hpp')},
                       'version_headers': {p: value for p, value in before_headers.items() if p.endswith('/boost/version.hpp')},
                       'identity_basis': 'actual_selected_compiler_preprocessor_and_execution_macros',
                       'upstream_api_reference': 'https://www.boost.org/doc/libs/1_83_0/libs/math/doc/html/math_toolkit/dist_ref/dists/students_t_dist.html'}
    if negative_controls:
        result['negative_controls'] = _negative_controls(root, cxx, rustc)
    if benchmark:
        if type(iterations) is not int or not 0 < iterations <= 1000000:
            raise ValueError('iterations must be in 1..1000000')
        timing = root / 'cpp-constructor-benchmark'
        _run([compiler, *flags, str(EXAMPLE / 'benchmark.cpp'), str(root / 'bridge.o'), str(root / 'foreign.o'), '-o', str(timing)])
        rows = [json.loads(line) for line in _run([str(timing), str(iterations)], timeout=60).stdout.splitlines()]
        by_name = {row['case']: row for row in rows}
        if set(by_name) != {name for pair in PAIRS for name in pair} or len(rows) != 8:
            raise RuntimeError('Constructor benchmark case denominator differs')
        for row in rows:
            if row['iterations'] != iterations or len(row['samples_ns']) != 7 or any(type(v) is not int or v <= 0 for v in row['samples_ns']):
                raise RuntimeError('Constructor benchmark samples incomplete')
            row['median_ns_per_operation'] = statistics.median(row['samples_ns']) / iterations
        for base, route in PAIRS:
            if by_name[base]['checksum'] != by_name[route]['checksum']:
                raise RuntimeError('Native and bridge benchmark observations differ')
        result['performance'] = {'status': 'measured', 'benchmark_sha256': _digest(timing), 'measurements': rows,
            'comparison': [{'baseline': base, 'route': route,
                            'observed_median_ratio': by_name[route]['median_ns_per_operation'] / by_name[base]['median_ns_per_operation']} for base, route in PAIRS],
            'scope': 'lifecycle_pairs_and_separate_steady_state_methods',
            'limitations': ['One host/compiler/library build, sequential case order, seven samples, no LTO.',
                            'Lifecycle rows include one creation and one destruction; they do not isolate constructor latency alone.',
                            'Lifecycle rows call no getter; native and bridge allocate the same kind and size of foreign object.',
                            'Per-method rows exclude object and registry creation/destruction.',
                            'Warmup precedes measurements; first-use registry and allocation-refusal paths are outside timed loops.',
                            'No language productivity, whole-library memory safety, or universal performance claim.']}
    after_headers = _dependencies(compiler)
    after_inputs = {str(p.relative_to(ROOT)): _digest(p) for p in sorted(EXAMPLE.iterdir()) if p.is_file()}
    result['inputs'] = before_inputs
    result['headers'] = {'method': 'selected_C++_compiler_M_including_system_headers_then_SHA256_before_and_after',
                         'before': before_headers, 'after': after_headers, 'unchanged': before_headers == after_headers,
                         'snapshot_sha256': hashlib.sha256(json.dumps(before_headers, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                         'scope': 'observed_header_content_snapshot_not_hermetic_compiler_runtime_or_dynamic_library_lock'}
    result['inputs_unchanged'] = before_inputs == after_inputs
    result['qualification_sources_unchanged'] = result['qualification_sources'] == qualification_sources()
    result['ok'] = before_inputs == after_inputs and before_headers == after_headers and result['qualification_sources_unchanged']
    if negative_controls:
        result['ok'] = result['ok'] and all(c['rejected'] for c in result['negative_controls'])
    return result


def _validate_constructor_qualification(report, *, require_benchmark=True, require_controls=True):
    """Fail closed on a missing library, actual failure site, or timing row."""
    def require(condition, message):
        if not condition:
            raise ValueError('E_CPP_CONSTRUCTOR_EVIDENCE: ' + message)

    def sha(value):
        return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None

    require(report.get('schema') == 'hepta.cpp-constructor-qualification.v1' and report.get('ok') is True
            and report.get('contract_version') == 'hepta.cpp-contract.v2', 'successful typed-constructor qualification required')
    require(report.get('compiler_sha256') == compiler_hash(), 'compiler identity changed since qualification')
    require(report.get('qualification_sources_unchanged') is True
            and report.get('qualification_sources') == qualification_sources(), 'qualification implementation changed')
    for key in ('foreign_cpp_library_rewritten', 'whole_library_memory_safety_proved', 'borrow_retention_proved',
                'exact_constructor_parameter_signature_proved', 'universal_performance_advantage_proved'):
        require(report.get(key) is False, 'unproved claim: ' + key)
    require(type(report.get('actual_ai_model_runs')) is int and report['actual_ai_model_runs'] == 0,
            'native constructor qualification does not measure AI')
    process = report.get('execution_process', {})
    require(report.get('native_link_qualified') is True and type(process.get('returncode')) is int
            and process['returncode'] == 0 and sha(process.get('stdout_sha256')) and sha(process.get('stderr_sha256'))
            and sha(report.get('executable_sha256')), 'actual linked native execution missing')
    bridge = report.get('bridge_generation', {})
    require(bridge.get('ok') is True and bridge.get('contract_schema') == 'hepta.cpp-contract.v2'
            and bridge.get('status') == 'cpp_object_and_hepta_native_checked'
            and type(bridge.get('object_bytes')) is int and bridge['object_bytes'] > 0
            and sha(bridge.get('object_sha256')), 'completed C++ bridge object validation required')
    objects = report.get('object_sha256', {})
    require(set(objects) == {'bridge.o', 'foreign.o', 'harness.o'} and all(sha(value) for value in objects.values())
            and objects['bridge.o'] == bridge['object_sha256'], 'all three linked object identities must be present and consistent')
    contract = json.loads((EXAMPLE / 'contract.json').read_text())
    expected_symbols = {'hepta_cpp_' + contract['module'] + '_' + h['name'] + '_' + c['name']
                        for h in contract['handles'] for c in h['constructors']}
    prefix = 'hepta_cpp_' + contract['module'] + '_'
    extern_symbols = expected_symbols | {prefix + f['name'] for f in contract['functions']}
    extern_symbols |= {prefix + h['name'] + '_' + name for h in contract['handles']
                       for name in ['destroy', *(m['name'] for m in h['methods'])]}
    checks = {'syntax': 'passed', 'types_effects_resources': 'passed_in_supported_subset', 'rust_borrows_types': 'rustc_checked'}
    consumer = report.get('hepta_consumer', {})
    bridge_frontend = bridge.get('hepta_validation', {})
    for name, frontend, crate_type in (('bridge', bridge_frontend, 'rlib'), ('consumer', consumer, 'staticlib')):
        backend = frontend.get('backend', {})
        require(frontend.get('schema') == 'hepta.check.v1' and frontend.get('ok') is True
                and frontend.get('status') == 'checked_with_external_assumptions'
                and frontend.get('compiler_sha256') == report['compiler_sha256']
                and all(frontend.get('checks', {}).get(key) == value for key, value in checks.items()),
                name + ' frontend checks must complete with external assumptions')
        assumptions = frontend.get('assumptions', [])
        externs = [a for a in assumptions if a.get('kind') == 'extern_contract']
        require(len(externs) == len(extern_symbols) and {a.get('function') for a in externs} == extern_symbols
                and all(a.get('status') == 'assumed_not_verified' and a.get('abi') == 'C'
                        and isinstance(a.get('obligations'), list) and a['obligations'] for a in externs)
                and all(a.get('kind') == 'extern_contract' or (a.get('kind') == 'unsafe_obligation'
                        and a.get('status') == 'not_proved_by_frontend') for a in assumptions)
                and (name != 'consumer' or any(a.get('kind') == 'unsafe_obligation' for a in assumptions)),
                name + ' external and unsafe obligations must remain explicit')
        require(backend.get('ok') is True and backend.get('status') == 'rustc_checked'
                and backend.get('check_only') is True and backend.get('crate_type') == crate_type
                and backend.get('rustc_crate_type') == 'lib' and sha(backend.get('validation_artifact_sha256'))
                and sha(frontend.get('rust_sha256')) and backend.get('rust_sha256') == frontend['rust_sha256'],
                name + ' check-only Rust backend and matching source/artifact identities required')
    bridge_source = bridge.get('outputs', {}).get('bridge.hepta', {}).get('sha256')
    require(sha(bridge_source) and bridge_frontend.get('source_sha256') == bridge_source
            and consumer.get('source_sha256') == _digest(EXAMPLE / 'consumer.hepta'),
            'checked Hepta sources must match the generated bridge and consumer')
    native = report.get('hepta_native_library', {})
    require(native.get('ok') is True and native.get('status') == 'rustc_checked'
            and native.get('check_only') is False and native.get('crate_type') == 'staticlib'
            and native.get('rustc_crate_type') == 'staticlib'
            and isinstance(native.get('artifact'), str) and bool(native['artifact'])
            and type(native.get('artifact_bytes')) is int and native['artifact_bytes'] > 0
            and sha(native.get('artifact_sha256')) and native['artifact_sha256'] == native.get('validation_artifact_sha256')
            and native.get('rust_sha256') == consumer['rust_sha256'],
            'built static library and matching checked Rust source/artifact identities required')
    constructors = bridge.get('constructor_checks', [])
    require(len(constructors) == len(expected_symbols) and {c.get('symbol') for c in constructors} == expected_symbols
            and all(c.get('exact_constructor_parameter_signature_proved') is False and c.get('borrow_retention_proved') is False
                    and c.get('construction_check') == 'native_constructibility_with_declared_argument_categories'
                    and c.get('wrapper_allocation_exception_boundary') == 'catch_status' for c in constructors),
            'every typed constructor must retain its checked scope and external obligations')
    costs = [c for c in bridge.get('cost_accounting', []) if c.get('route') == 'handle_create']
    require(len(costs) == len(expected_symbols) and {c.get('symbol') for c in costs} == expected_symbols
            and all(c.get('output_write') == 'only_after_successful_registry_insertion' and c.get('exception_boundary') == 'catch_status'
                    and c.get('borrow_retention_proved') is False for c in costs), 'constructor costs/output protocol missing')
    execution = report.get('execution', {})
    required_true = ('bidirectional_native', 'boost_nondefault_constructible', 'vector_length_rejected',
                     'pod_span_constructor', 'span_copy_observed', 'noexcept_wrapper_allocation_failure', 'output_preserved_on_failure')
    require(all(execution.get(k) is True for k in required_true)
            and execution.get('boost_success_cases') == 5 and execution.get('boost_domain_failure_cases') == 3
            and execution.get('vector_constructor_cases') == 8 and execution.get('pointer_negative_controls') == 5,
            'real library, constructor overload, POD/span, and failure-case denominator incomplete')
    failures = execution.get('allocation_failure_sites')
    require(type(failures) is int and failures >= 4 and execution.get('allocation_recovery_calls') == failures
            and execution.get('warm_registry_live_allocation_delta') == 0 and execution.get('live_fixture_objects') == 0,
            'each observed construction allocation site must refuse, release, and recover')
    boost = report.get('boost', {})
    require(type(boost.get('version')) is int and boost['version'] > 0
            and execution.get('boost_version') == boost['version'] and execution.get('boost_lib_version') == boost.get('library_version')
            and boost.get('students_t_headers') and boost.get('version_headers'), 'installed Boost identities disagree or are missing')
    headers = report.get('headers', {})
    before = headers.get('before', {})
    require(before and headers.get('unchanged') is True and headers.get('after') == before
            and all(sha(value) for value in before.values())
            and headers.get('snapshot_sha256') == hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            and all(before.get(p) == value for p, value in {**boost['students_t_headers'], **boost['version_headers']}.items()),
            'actual transitive header content snapshot incomplete or changed')
    inputs = {str(p.relative_to(ROOT)): _digest(p) for p in sorted(EXAMPLE.iterdir()) if p.is_file()}
    require(report.get('inputs_unchanged') is True and report.get('inputs') == inputs, 'qualified example source changed')
    if require_controls:
        controls = report.get('negative_controls', [])
        require([c.get('id') for c in controls] == list(NEGATIVE_CONTROLS)
                and all(c.get('rejected') is True and c.get('output_directory_created') is False
                        and [d.get('code') for d in c.get('diagnostics', [])] == [c.get('expected_code')]
                        and c.get('expected_code') == ('E_CPP_NATIVE' if c['id'] in NEGATIVE_CONTROLS[-3:] else 'E_CPP_CONTRACT')
                        for c in controls), 'all native/schema constructor rejection controls must run and refuse publication')
    if require_benchmark:
        performance = report.get('performance', {})
        rows = performance.get('measurements', [])
        names = {name for pair in PAIRS for name in pair}
        require(performance.get('status') == 'measured' and performance.get('scope') == 'lifecycle_pairs_and_separate_steady_state_methods'
                and len(rows) == len(names) and {r.get('case') for r in rows} == names, 'all lifecycle and separate method timing rows required')
        by_name = {r['case']: r for r in rows}
        for row in rows:
            samples, iterations = row.get('samples_ns'), row.get('iterations')
            require(type(iterations) is int and 0 < iterations <= 1000000 and isinstance(samples, list) and len(samples) == 7
                    and all(type(v) is int and v > 0 for v in samples)
                    and type(row.get('checksum')) is int and row['checksum'] >= 0
                    and row.get('median_ns_per_operation') == statistics.median(samples) / iterations,
                    'timing sample or derived median is incomplete or inconsistent')
        require(len({r['iterations'] for r in rows}) == 1, 'timing routes used different iteration counts')
        expected = []
        for base, route in PAIRS:
            require(by_name[base]['checksum'] == by_name[route]['checksum'], 'timing routes produced different observations')
            ratio = by_name[route]['median_ns_per_operation'] / by_name[base]['median_ns_per_operation']
            require(math.isfinite(ratio) and ratio > 0, 'invalid timing ratio')
            expected.append({'baseline': base, 'route': route, 'observed_median_ratio': ratio})
        require(performance.get('comparison') == expected, 'derived timing ratios differ from raw samples')
    return True


def validate_constructor_qualification(report, *, require_benchmark=True, require_controls=True):
    try:
        return _validate_constructor_qualification(report, require_benchmark=require_benchmark, require_controls=require_controls)
    except (AttributeError, KeyError, TypeError, IndexError, ArithmeticError) as exc:
        raise ValueError('E_CPP_CONSTRUCTOR_EVIDENCE: malformed nested qualification record') from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--rustc')
    parser.add_argument('--iterations', type=int, default=100000)
    parser.add_argument('--no-benchmark', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite an earlier qualification')
    with tempfile.TemporaryDirectory(prefix='hepta-cpp-constructors-') as temp:
        try:
            result = qualify_cpp_constructors(temp, cxx=args.cxx, rustc=args.rustc,
                                               benchmark=not args.no_benchmark, iterations=args.iterations)
            if result['ok']:
                validate_constructor_qualification(result, require_benchmark=not args.no_benchmark)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            result = {'schema': 'hepta.cpp-constructor-qualification.v1', 'ok': False, 'error': str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'ok': result['ok'], 'output': str(args.output)}))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
