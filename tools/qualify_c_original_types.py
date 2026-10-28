#!/usr/bin/env python3
"""Replay source-bound original C types and finite array migration at O0/O2.

The same captured Clang/libclang pipeline admits ordinary, fixed and incomplete
array forms and refuses entry-effect/physical-binding counterexamples. This
retains automatic tool cost and native values, without inferring pointer
contracts, total migration cost, source equivalence or whole-language safety.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_contracts import contract_identity
from hepta.c_migrate import migrate_c_project
from hepta.c_parameter_types import original_type_reader_identity
from tools.qualify_hia_integrated import _source_state

VALUES = [1, 3, 7, 12]
RECORD = 'struct State { unsigned char *data; unsigned int count; };\n'


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cases():
    result = []
    for name, parameter, prefix in (
        ('pointer', 'const unsigned int *data', ''),
        ('fixed_array', 'const unsigned int data[8]', ''),
        ('incomplete_array', 'const unsigned int data[]', ''),
        ('macro_fixed_array', 'const unsigned int data[EXTENT]', '#define EXTENT 8\n'),
    ):
        result.append({'name': name, 'record': False, 'admitted': True, 'effect': 0,
            'source': prefix + 'unsigned int probe(unsigned int n, ' + parameter + ') { return n + data[0]; }\n',
            'headers': {}, 'reason': None})
    for name, parameter in (('record_fixed_array', 'const struct State ctx[1]'),
                            ('record_incomplete_array', 'const struct State ctx[]')):
        result.append({'name': name, 'record': True, 'admitted': True, 'effect': 0,
            'source': RECORD + 'unsigned int probe(unsigned int n, ' + parameter + ') { return n + ctx->count; }\n',
            'headers': {}, 'reason': None})
    result.append({'name': 'header_fixed_prototype', 'record': False, 'admitted': True, 'effect': 0,
        'source': '#include "api.h"\nunsigned int probe(unsigned int n, const unsigned int *data) { return n + data[0]; }\n',
        'headers': {'api.h': 'unsigned int probe(unsigned int n, const unsigned int data[8]);\n'}, 'reason': None})
    for name, parameter, prefix, is_record, reason in (
        ('vla_entry', 'const unsigned int data[++n]', '', False, 'E_C_VLA_PARAMETER'),
        ('macro_vla_entry', 'const unsigned int data[EXTENT]', '#define EXTENT (++n)\n', False, 'E_C_VLA_PARAMETER'),
        ('typeof_entry', 'const __typeof__(unsigned int[++n]) data', '', False, 'E_C_PARAMETER_DECLARATOR'),
        ('record_vla_entry', 'const struct State ctx[++n]', RECORD, True, 'E_C_VLA_PARAMETER'),
    ):
        body = 'n + ctx->count' if is_record else 'n + data[0]'
        result.append({'name': name, 'record': is_record, 'admitted': False, 'effect': 1,
            'source': prefix + 'unsigned int probe(unsigned int n, ' + parameter + ') { return ' + body + '; }\n',
            'headers': {}, 'reason': reason})
    for name, directive in (('header_offset_decoy', ''), ('presumed_file_decoy', '#line 500 "input.c"\n')):
        header = directive + ' ' * 32 + 'const __typeof__(unsigned int[++n]) data\n'
        start, stop = header.index('const'), header.index('data')
        plain = 'const unsigned int *'
        text = ('/*' + ' ' * (start - 2) + plain + ' ' * (stop - start - len(plain)) + 'data */\n'
                'unsigned int probe(unsigned int n,\n#include "parameter.h"\n) { return n + data[0]; }\n')
        result.append({'name': name, 'record': False, 'admitted': False, 'effect': 1,
                       'source': text, 'headers': {'parameter.h': header}, 'reason': 'E_C_PARAMETER_DECLARATOR'})
    return result


def contracts(record):
    if record:
        return {'schema': 'hepta.c-record-views.v1',
            'records': {'State': {'buffers': {'data': {'length_field': 'count', 'add': 0}}}},
            'functions': {'probe': {'slices': {}, 'records': {'ctx': {'access': 'read'}}}}}
    return {'schema': 'hepta.c-contracts.v1',
            'functions': {'probe': {'slices': {'data': {'length': 'n', 'access': 'read'}}}}}


def observe(path, record):
    class State(ctypes.Structure):
        _fields_ = [('data', ctypes.POINTER(ctypes.c_ubyte)), ('count', ctypes.c_uint)]
    library = ctypes.CDLL(str(path))
    function = library.probe
    if record:
        backing = (ctypes.c_ubyte * 32)(*range(32))
        # VLA controls evaluate ++n at entry; all 32 State objects and backing
        # allocations remain live, and every input uses n+1 <= 13.
        storage = (State * 32)(*[State(backing, 17) for _ in range(32)])
        function.argtypes = [ctypes.c_uint, ctypes.POINTER(State)]
    else:
        storage = (ctypes.c_uint * 32)(*[11 + index for index in range(32)])
        function.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_uint
    return [int(function(value, storage)) for value in VALUES]


def qualify(options):
    output = options.output_directory.resolve()
    require(not output.is_relative_to(ROOT), 'retain evidence outside frozen source')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'hepta.c-original-type-qualification.v2', 'ok': False, 'status': 'running',
        'started_utc': datetime.now(timezone.utc).isoformat(), 'rows': [], 'inputs': VALUES,
        'runner_sha256': digest(__file__),
        'claims': {'actual_original_type_and_physical_source_binding_executed': False,
                   'fixed_and_incomplete_array_native_controls_executed': False,
                   'source_equivalence_proved': False, 'whole_language_soundness_proved': False,
                   'general_C_or_CPP_migration_qualified': False, 'foreign_pointer_validity_proved': False,
                   'performance_advantage_established': False, 'total_migration_cost_measured': False,
                   'full_P4_closed': False, 'observations_added_to_test_denominator': False}}
    started = time.perf_counter()
    try:
        before = _source_state()
        report['source_before'] = before
        require(before['head'] == options.expected_head and not before['status'], 'exact clean expected HEAD required')
        identity = original_type_reader_identity(options.clang)
        rustc = Path(shutil.which(options.rustc) or options.rustc).resolve(strict=True)
        report['tools'] = {'original_type_reader': identity, 'rustc': {'path': str(rustc), 'sha256': digest(rustc)}}
        write(output / 'qualification.json', report)
        for case in cases():
            for optimization in ('-O0', '-O2'):
                directory = output / (case['name'] + '-' + optimization[1:])
                directory.mkdir()
                source = directory / 'input.c'
                source.write_text(case['source'])
                for name, content in case['headers'].items():
                    (directory / name).write_text(content)
                flags = ['-std=c11', optimization, '-fPIC']
                compile_argv = [options.clang, *flags, '-c', 'input.c', '-o', 'input.o']
                database = directory / 'compile_commands.json'
                write(database, [{'directory': str(directory), 'file': 'input.c', 'arguments': compile_argv}])
                specification = contracts(case['record'])
                write(directory / 'contracts.json', specification)
                tick = time.perf_counter()
                migration = migrate_c_project(database, directory / 'translated', contracts=specification,
                                               clang=options.clang, rustc=str(rustc), verify_native=True)
                migration_seconds = time.perf_counter() - tick
                write(directory / 'migration.json', migration)
                row = {'case': case['name'], 'optimization': optimization, 'record_view': case['record'],
                    'expected_admission': case['admitted'], 'expected_refusal': case['reason'],
                    'input_source_sha256': digest(source), 'contract_identity': contract_identity(specification),
                    'migration_path': str(directory / 'migration.json'), 'migration_seconds': migration_seconds,
                    'observed': {}, 'input_values': VALUES, 'complete': False}
                report['rows'].append(row)
                write(output / 'qualification.json', report)
                require(migration['ok'] is case['admitted'], case['name'] + ': unexpected migration admission')
                require(migration['declaration_inventory_complete'] is True, 'incomplete declaration inventory')
                if not case['admitted']:
                    require(not (directory / 'translated').exists(), 'refusal published a translated bundle')
                    require(any(item['code'] == case['reason'] for item in migration['diagnostics']), 'wrong refusal code')
                    require(any(item['status'] == 'rejected' and item['reason'] == case['reason']
                                for item in migration['declarations']), 'refusal not attached to a declaration')
                receipts = migration['source_type_admission']
                for receipt in receipts:
                    require(receipt['schema'] == 'hepta.c-original-parameter-types.v2', 'wrong original-type schema')
                    require(receipt['capture_sha256'] == migration['build']['sha256'], 'type/capture identity mismatch')
                    require(receipt['reader'] == identity['reader'] and receipt['worker'] == identity['worker']
                            and receipt['python'] == identity['python'] and receipt['compiler'] == identity['compiler'],
                            'type tool identity changed')
                if case['admitted']:
                    require(bool(receipts), 'admission lacks original-type evidence')
                    expected_functions = sum(item['kind'] == 'FunctionDecl' and
                        item['status'] != 'system_or_compiler_declaration' for item in migration['declarations'])
                    require(sum(len(receipt['functions']) for receipt in receipts) == expected_functions,
                            'original result/parameter coverage incomplete')
                    require(all(info['state'] == 'fixed' for receipt in receipts for fn in receipt['functions']
                                for info in [fn['result'], *fn['parameters']]), 'admitted variable/unmodeled original type')
                elif case['reason'] == 'E_C_VLA_PARAMETER':
                    require(any(parameter['state'] == 'variable' for receipt in receipts
                                for fn in receipt['functions'] for parameter in fn['parameters']), 'VLA refusal lacks original-type observation')
                original = directory / 'original.so'
                argv = [options.clang, *flags, '-shared', 'input.c', '-o', str(original)]
                tick = time.perf_counter()
                row['original_build'] = {'argv': argv, 'cwd': str(directory), 'returncode': None,
                                         'status': 'attempted', 'timeout_seconds': 60}
                write(output / 'qualification.json', report)
                failure = None
                try:
                    process = subprocess.run(argv, cwd=directory, capture_output=True, timeout=60, check=False)
                    streams = {'stdout': process.stdout, 'stderr': process.stderr}
                    row['original_build'].update(returncode=process.returncode, status='completed')
                except subprocess.TimeoutExpired as error:
                    streams = {'stdout': error.stdout or b'', 'stderr': error.stderr or b''}
                    row['original_build']['status'] = 'timeout'
                    failure = error
                except OSError as error:
                    streams = {'stdout': b'', 'stderr': str(error).encode('utf-8', errors='replace')}
                    row['original_build']['status'] = 'spawn_failed'
                    failure = error
                row['original_build']['elapsed_seconds'] = time.perf_counter() - tick
                for stream in ('stdout', 'stderr'):
                    path = directory / ('original-build.' + stream)
                    path.write_bytes(streams[stream])
                    row['original_build'][stream + '_path'] = str(path)
                    row['original_build'][stream + '_sha256'] = digest(path)
                write(output / 'qualification.json', report)
                if failure is not None:
                    raise failure
                require(row['original_build']['returncode'] == 0, 'original native compilation failed')
                expected = [value + case['effect'] + (17 if case['record'] else 11) for value in VALUES]
                row['expected_values'] = expected
                row['observed']['original_C'] = observe(original, case['record'])
                if case['admitted']:
                    row['observed']['migrated_Hepta'] = observe(directory / 'translated/libtranslated.so', case['record'])
                require(all(values == expected for values in row['observed'].values()), 'native value mismatch')
                row['whole_bundle_rejected_without_publication'] = not case['admitted']
                row['complete'] = True
                row['artifacts'] = {path.relative_to(directory).as_posix(): digest(path)
                                    for path in sorted(directory.rglob('*')) if path.is_file()}
                write(directory / 'observation.json', row)
                write(output / 'qualification.json', report)
        report['source_after'] = _source_state()
        report['source_unchanged'] = report['source_before'] == report['source_after']
        require(report['source_unchanged'], 'source changed during qualification')
        report['tools_after'] = original_type_reader_identity(options.clang)
        require(report['tools_after'] == identity and digest(rustc) == report['tools']['rustc']['sha256'], 'tool identity changed')
        report['counts'] = {
            'source_cases': len(cases()), 'configurations': len(report['rows']),
            'admitted_configurations': sum(row['expected_admission'] for row in report['rows']),
            'rejected_configurations': sum(not row['expected_admission'] for row in report['rows']),
            'original_native_values': sum(len(row['observed']['original_C']) for row in report['rows']),
            'migrated_native_values': sum(len(row['observed'].get('migrated_Hepta', [])) for row in report['rows']),
        }
        report['claims']['actual_original_type_and_physical_source_binding_executed'] = True
        report['claims']['fixed_and_incomplete_array_native_controls_executed'] = True
        report.update(ok=True, status='finite_original_type_array_controls_passed')
    except Exception as error:
        report.update(ok=False, status='failed', error={'type': type(error).__name__, 'message': str(error),
                                                     'traceback': traceback.format_exc()})
        try:
            report['source_after'] = _source_state()
            report['source_unchanged'] = report.get('source_before') == report['source_after']
        except Exception as inventory_error:
            report['source_inventory_error'] = str(inventory_error)
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    report['cost'] = {'automatic_migration_seconds': sum(row['migration_seconds'] for row in report['rows']),
                      'elapsed_seconds': time.perf_counter() - started, 'manual_review_hours': None,
                      'model_tokens': None, 'scope': 'actual_automatic_tool_cost_not_total_migration_cost'}
    write(output / 'qualification.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--rustc', required=True)
    options = parser.parse_args()
    report = qualify(options)
    print(json.dumps({key: report.get(key) for key in ('ok', 'status', 'counts', 'cost', 'error')}, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
