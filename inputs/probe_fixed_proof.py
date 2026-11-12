"""Observe the frozen proof mechanical ports; never run proof policy or HIA."""
import argparse
import ast
import builtins
from contextlib import contextmanager
import dis
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback
from types import FunctionType

EXPECTED = 'e07eac32ef9915346ad132c3c753ba56cc730d6a5ce073a4e063a5d42b6665a7'
NAMES = ('call0', 'call1', 'call2', 'call3', 'call4', 'call-held',
         'import-all', 'import-assumptions', 'import-importlib',
         'update-mapping', 'update-duplicates', 'update-nonmapping',
         'format-plain', 'format-02d', 'build-string-no-second-format',
         'wrong-update-operand-refused', 'wrong-string-count-refused')

def error(value):
    return {'type': type(value).__module__ + '.' + type(value).__qualname__,
            'message': str(value), 'traceback': ''.join(traceback.format_exception(value))}

def snapshot_functions(namespace):
    result = {}
    for name, value in namespace.items():
        if isinstance(value, FunctionType) and (name.endswith('_template') or name.startswith('call_')):
            code = value.__code__
            result[name] = {'co_consts_repr': repr(code.co_consts), 'co_consts_types': [type(x).__name__ for x in code.co_consts],
                'co_code_hex': code.co_code.hex(), 'co_exceptiontable_hex': code.co_exceptiontable.hex(),
                'instructions': [{'offset': x.offset, 'opname': x.opname, 'arg': x.arg,
                    'argval_repr': repr(x.argval), 'raw_argument_byte': code.co_code[x.offset + 1]}
                    for x in dis.get_instructions(code, show_caches=True, adaptive=False)]}
    return result

def definition_profile(raw, filename):
    # Separate diagnostic compilation of original fixed function definitions.
    # Excludes top-level port construction and every runtime policy function;
    # its functions are inspected only, never a replacement admitted module.
    tree = ast.parse(raw, filename)
    nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
    namespace = {'__name__': 'diagnostic_proof_definitions', '__package__': 'hepta'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), filename, 'exec'), namespace)
    return snapshot_functions(namespace)

class Frame:
    def __init__(self, values):
        self.values = dict(enumerate(values)); self.events = []
    def _move(self, slot):
        self.events.append(['move', slot]); return self.values.pop(slot)
    def _get(self, slot):
        self.events.append(['get', slot]); return self.values[slot]

def outcome(call):
    try:
        return {'value': call(), 'error': None}
    except BaseException as value:
        return {'value': None, 'error': {'type': type(value).__name__, 'message': str(value)}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-version', required=True)
    args = parser.parse_args()
    raw = args.candidate.read_bytes()
    assert len(raw) == 7532 and sha256(raw).hexdigest() == EXPECTED
    assert '.'.join(map(str, sys.version_info[:3])) == args.expected_version
    root = args.source.resolve(strict=True); sys.path.insert(0, str(root))
    out = args.output.absolute(); out.mkdir(mode=0o700, exist_ok=False)
    report = {'schema': 'hia.proof-contract.fixed-mechanical-observations.v1',
              'python': sys.version, 'candidate_bytes': len(raw), 'candidate_sha256': EXPECTED,
              'planned_names': NAMES, 'observations': [], 'native_entries': 0,
              'proof_policy_calls': 0, 'current_cold': False, 'whole_native': False,
              'scope': 'ACTUAL_FIXED_CPYTHON_MECHANISMS_ONLY', 'status': 'STARTED'}
    started = time.perf_counter_ns()
    try:
        report['definition_only_diagnostic_profiles'] = definition_profile(raw, str(args.candidate))
        spec = importlib.util.spec_from_file_location('hepta._proof_foreign_observed', args.candidate)
        foreign = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(foreign)
        except BaseException as exc:
            report['actual_import_error'] = error(exc)
            report['actual_partially_imported_profiles'] = snapshot_functions(vars(foreign))
            report['status'] = 'IMPORT_REFUSAL_BEFORE_MECHANISM_CONTROLS'
            return 1
        report['actual_import_error'] = None
        report['actual_imported_profiles'] = snapshot_functions(vars(foreign))
        def observe(name, call):
            row = {'name': name}
            try:
                row['detail'] = call(); row['status'] = 'PASS'
            except BaseException as exc:
                row.update(status='FAIL', error=error(exc))
            report['observations'].append(row)
        def call_control(count):
            calls = []
            def provider(*values):
                calls.append(list(values)); return ['called', list(values)]
            values = list(range(11, 11 + count))
            expected = provider(*values); calls.clear()
            frame = Frame([provider, *values])
            result = foreign.CALLS[(count, ())](frame, tuple(range(count + 1)))
            assert result == expected and calls == [values]
            assert frame.values == {} and frame.events == [['move', i] for i in range(count + 1)]
            return {'value': result, 'events': frame.events, 'provider_calls': len(calls)}
        for count in range(5):
            observe('call' + str(count), lambda count=count: call_control(count))
        def held():
            value = object(); calls = []
            def provider(*, held_owners):
                calls.append(held_owners); return held_owners
            frame = Frame([provider, value]); actual = foreign.call_held(frame, (0, 1))
            assert actual is value and calls == [value] and frame.values == {}
            assert frame.events == [['move', 0], ['move', 1]]
            return {'same_identity': True, 'events': frame.events, 'provider_calls': 1}
        observe('call-held', held)
        namespace = {'__name__': 'hepta.hia_proof_contract', '__package__': 'hepta'}
        groups, plain, fields = foreign.import_ports(namespace)
        from hepta import hia_safe_core
        def import_control(index):
            imported = groups[index]()
            names = foreign.IMPORT_NAMES if index == 0 else ('ASSUMPTIONS',)
            assert imported is hia_safe_core
            for name in names:
                assert fields[name](imported) is getattr(hia_safe_core, name)
            return {'same_module': True, 'same_field_identities': list(names)}
        observe('import-all', lambda: import_control(0))
        observe('import-assumptions', lambda: import_control(1))
        def plain_import():
            import importlib
            assert plain() is importlib
            return {'same_importlib_identity': True}
        observe('import-importlib', plain_import)
        class Mapping:
            def __init__(self, values, events): self.values, self.events = values, events
            def keys(self): self.events.append(['keys']); return list(self.values)
            def __getitem__(self, key): self.events.append(['get', key]); return self.values[key]
        def update(values):
            expected_events, actual_events = [], []
            expected = {**{'a': 1, 'same': 2}, **Mapping(values, expected_events)}
            target = {'a': 1, 'same': 2}; frame = Frame([target, Mapping(values, actual_events)])
            actual = foreign.update_dict(frame, 0, 1)
            assert actual is target and actual == expected and list(actual) == list(expected)
            assert actual_events == expected_events and frame.events == [['get', 0], ['get', 1]]
            return {'value': actual, 'keys': list(actual), 'mapping_events': actual_events, 'same_target': True}
        observe('update-mapping', lambda: update({'other': 3}))
        observe('update-duplicates', lambda: update({'same': 4, 'other': 5}))
        def invalid_update():
            def original(): return {**{}, **17}
            expected = outcome(original); frame = Frame([{}, 17])
            actual = outcome(lambda: foreign.update_dict(frame, 0, 1))
            assert actual == expected and actual['error'] is not None
            return actual
        observe('update-nonmapping', invalid_update)
        def formatted(specification):
            events = []
            class Value:
                def __format__(self, spec): events.append(spec); return 'formatted:' + spec
            original_value = Value()
            expected = f'{original_value:02d}' if specification else f'{original_value}'
            expected_events = events[:]; events.clear(); frame = Frame([Value()])
            actual = (foreign.format_02d if specification else foreign.format_plain)(frame, 0)
            assert actual == expected and events == expected_events == [specification]
            assert frame.values == {} and frame.events == [['move', 0]]
            return {'value': actual, 'formats': events}
        observe('format-plain', lambda: formatted(''))
        observe('format-02d', lambda: formatted('02d'))
        def build_string():
            class AlreadyFormatted(str):
                def __format__(self, spec): raise AssertionError('already formatted fragment formatted again')
            frame = Frame([AlreadyFormatted(x) for x in ('ab', '', 'é', 'Z')])
            value = foreign.build_string(frame, (0, 1, 2, 3))
            assert value == 'abéZ' and frame.values == {}
            assert frame.events == [['move', i] for i in range(4)]
            return {'value': value, 'events': frame.events, 'additional_format_calls': 0}
        observe('build-string-no-second-format', build_string)
        def invalid_template(name, opname, expected_message):
            original = getattr(foreign, name); code = original.__code__; rawcode = bytearray(code.co_code)
            item = next(x for x in dis.get_instructions(original) if x.opname == opname)
            rawcode[item.offset + 1] = 0
            mutant = FunctionType(code.replace(co_code=bytes(rawcode)), original.__globals__)
            setattr(foreign, name, mutant)
            try:
                result = outcome(foreign._update_port if name == '_update_template' else foreign._string_port)
            finally:
                setattr(foreign, name, original)
            assert result['error'] and result['error']['type'] == 'RuntimeError' and expected_message in result['error']['message']
            return {'error': result['error'], 'malformed_code_executed': False}
        observe('wrong-update-operand-refused', lambda: invalid_template('_update_template', 'DICT_UPDATE', 'DICT_UPDATE opcode'))
        observe('wrong-string-count-refused', lambda: invalid_template('_string_template', 'BUILD_STRING', 'BUILD_STRING opcode'))
        assert tuple(row['name'] for row in report['observations']) == NAMES
        report['status'] = 'PASS' if all(row['status'] == 'PASS' for row in report['observations']) else 'FAIL'
        return 0 if report['status'] == 'PASS' else 1
    except BaseException as exc:
        report.update(status='HARNESS_ERROR', error=error(exc))
        return 1
    finally:
        report['input_unchanged'] = args.candidate.read_bytes() == raw
        report['elapsed_ns'] = time.perf_counter_ns() - started
        (out / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'observed': len(report['observations']),
                          'passed': sum(row['status'] == 'PASS' for row in report['observations']),
                          'input_unchanged': report['input_unchanged']}))

if __name__ == '__main__':
    raise SystemExit(main())
