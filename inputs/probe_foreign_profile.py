"""Actual fixed CPython representation ports; no business owner or HIA entry.

Retain the old import refusal, full physical instructions, and invalid real
bytecode-operand negative controls. Never execute a malformed template.
"""
from __future__ import annotations
import argparse
import dis
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback
from types import FunctionType
from unittest.mock import patch

OLD_SHA = '47394ead9d7e024f69a44b130a63d0a617c8fdc80f67d5916473b6416629878d'


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def exception(error):
    return {'type': type(error).__module__ + '.' + type(error).__qualname__, 'message': str(error)}


def load(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    try:
        specification.loader.exec_module(module)
        return module, None
    except BaseException as error:
        return module, exception(error)


def outcome(function):
    try:
        return {'value': function(), 'error': None}
    except BaseException as error:
        return {'value': None, 'error': exception(error)}


def instructions(function):
    return {'code_hex': function.__code__.co_code.hex(),
            'constants': function.__code__.co_consts, 'stack_size': function.__code__.co_stacksize,
            'exception_table_hex': function.__code__.co_exceptiontable.hex(),
            'instructions': [{'offset': item.offset, 'opcode': item.opcode, 'opname': item.opname,
                              'arg': item.arg, 'argrepr': item.argrepr,
                              'raw_argument_byte': function.__code__.co_code[item.offset + 1]}
                             for item in dis.get_instructions(function, show_caches=True, adaptive=False)]}


class Frame:
    def __init__(self, values):
        self.values = values

    def _get(self, slot):
        return self.values[slot]

    def _move(self, slot):
        return self.values.pop(slot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.absolute(); out.mkdir(mode=0o700)
    before = {str(path.resolve()): digest(path) for path in (args.original, args.candidate)}
    report = {'schema': 'hia.verification.fixed-foreign-profile.observations.r5',
              'scope': 'ACTUAL_CPYTHON_FIXED_PRIMITIVES_ONLY_NO_NATIVE_POLICY_ENTRY',
              'python': sys.version, 'implementation': sys.implementation.name,
              'inputs_before': before, 'observations': [], 'status': 'STARTED',
              'native_entries': 0, 'current_source_cold': False, 'whole_stack_native': False}
    started = time.monotonic_ns()

    def record(name, function):
        try:
            detail = function()
            report['observations'].append({'name': name, 'status': 'PASS', 'detail': detail})
        except BaseException:
            report['observations'].append({'name': name, 'status': 'FAIL', 'traceback': traceback.format_exc()})

    try:
        assert sys.implementation.name == 'cpython' and sys.version_info[:2] in ((3, 12), (3, 13), (3, 14))
        assert digest(args.original) == OLD_SHA
        assert digest(args.candidate) == args.candidate_sha
        old, old_error = load(args.original, 'frozen_verification_foreign_r3')
        new, new_error = load(args.candidate, 'candidate_verification_foreign_r5')
        report['original_import'] = old_error
        report['candidate_import'] = new_error
        report['original_templates'] = {name: instructions(getattr(old, name)) for name in
            ('_merge_empty_template', '_merge_kind_template', '_update_template')}
        if new_error is not None:
            raise RuntimeError('candidate fixed primitive import refused: ' + repr(new_error))
        report['candidate_templates'] = {name: instructions(getattr(new, name)) for name in
            ('_merge_empty_template', '_merge_kind_template', '_update_template')}

        def admission():
            if sys.version_info[:2] == (3, 14):
                assert old_error == {'type': 'builtins.RuntimeError', 'message': 'verification DICT_MERGE opcode template differs'}
            else:
                assert old_error is None
            for name in report['original_templates']:
                assert report['candidate_templates'][name] == report['original_templates'][name]
            pairs = []
            for name in ('_merge_empty_template', '_merge_kind_template'):
                items = report['candidate_templates'][name]['instructions']
                call, = [item for item in items if item['opname'] == 'CALL_FUNCTION_EX']
                assert (call['arg'], call['raw_argument_byte']) == ((None, 0) if sys.version_info[:2] == (3, 14) else (1, 1))
                pairs.append({'template': name, 'arg': call['arg'], 'raw_argument_byte': call['raw_argument_byte']})
            return pairs
        record('actual_original_refusal_and_unchanged_instruction_templates', admission)

        def merge(kind):
            called = []
            def provider(*positional, **keywords):
                called.append([list(positional), keywords])
                return [list(positional), keywords]
            if kind:
                frame = Frame({0: provider, 1: (7, 9), 2: 'artifact', 3: {'x': 11}})
                prepared = new.merge_kind(frame, 0, 1, 2, 3)
                expected = {'kind': 'artifact', 'x': 11}
            else:
                frame = Frame({0: provider, 1: (7, 9), 2: {'x': 11}})
                prepared = new.merge_empty(frame, 0, 1, 2)
                expected = {'x': 11}
            assert type(prepared) is dict and prepared == expected and called == []
            frame.values[9] = prepared
            result = new.mapping_call(frame, 0, 1, 9)
            assert result == [[7, 9], expected] and called == [result]
            assert not {0, 1, 9} & frame.values.keys()
            return {'prepared': prepared, 'physical_call_count': len(called), 'result': result}
        record('empty_keyword_merge_prepares_without_call_then_exact_call', lambda: merge(False))
        record('explicit_kind_merge_prepares_without_call_then_exact_call', lambda: merge(True))

        def invalid_mapping(value, kind):
            called = []
            def provider(*args, **kwargs):
                called.append(True)
            if kind:
                a = Frame({0: provider, 1: (), 2: 'artifact', 3: value})
                b = Frame(dict(a.values))
                reference = outcome(lambda: old._merge_kind_template(a, 0, 1, 2, 3))
                def invoke():
                    b.values[9] = new.merge_kind(b, 0, 1, 2, 3)
                    return new.mapping_call(b, 0, 1, 9)
            else:
                a = Frame({0: provider, 1: (), 2: value}); b = Frame(dict(a.values))
                reference = outcome(lambda: old._merge_empty_template(a, 0, 1, 2))
                def invoke():
                    b.values[9] = new.merge_empty(b, 0, 1, 2)
                    return new.mapping_call(b, 0, 1, 9)
            actual = outcome(invoke)
            assert reference == actual and actual['error'] is not None and called == []
            return actual
        record('original_duplicate_keyword_error_before_provider', lambda: invalid_mapping({'kind': 7}, True))
        record('original_nonmapping_error_before_provider', lambda: invalid_mapping(7, False))
        record('original_nonstring_keyword_error_before_provider', lambda: invalid_mapping({1: 7}, False))

        def update():
            original = {'same': 1, 'before': 2}
            frame = Frame({0: original, 1: {'same': 3, 'after': 4}})
            result = new.update_dict(frame, 0, 1)
            assert result is original and result == {'same': 3, 'before': 2, 'after': 4}
            return {'same_destination': True, 'keys': list(result), 'value': result}
        record('dict_update_replaces_duplicates_in_actual_destination', update)

        def bad_operand(opname):
            template = new._merge_empty_template
            instruction, = [item for item in dis.get_instructions(template, show_caches=True, adaptive=False)
                            if item.opname == opname]
            raw = bytearray(template.__code__.co_code)
            raw[instruction.offset + 1] = 2
            altered = FunctionType(template.__code__.replace(co_code=bytes(raw)), vars(new))
            result = outcome(lambda: new._merge_port(altered, (None,)))
            assert result['error'] == {'type': 'builtins.RuntimeError', 'message': 'verification DICT_MERGE opcode template differs'}
            return {'mutant_opcode': opname, 'mutant_operand': 2, 'malformed_code_executed': False, 'outcome': result}
        record('actual_wrong_merge_operand_refused_before_execution', lambda: bad_operand('DICT_MERGE'))
        record('actual_wrong_call_operand_refused_before_execution', lambda: bad_operand('CALL_FUNCTION_EX'))

        def unsupported():
            with patch.object(new.sys, 'version_info', (3, 15, 0)):
                result = outcome(lambda: new._merge_port(new._merge_empty_template, (None,)))
            assert result['error'] == {'type': 'builtins.RuntimeError', 'message': 'verification mapping ports require a reviewed CPython ABI'}
            return result
        record('unreviewed_interpreter_profile_refused', unsupported)
        def explicit_null_and_literal_indexes():
            rows = []
            for original, prepared in ((new._merge_empty_template, new.merge_empty),
                                       (new._merge_kind_template, new.merge_kind)):
                original_instructions = tuple(dis.get_instructions(original, show_caches=True, adaptive=False))
                prepared_instructions = {item.offset: item for item in dis.get_instructions(prepared, show_caches=True, adaptive=False)}
                null, = [item for item in original_instructions if item.opname == 'PUSH_NULL']
                replacement = prepared_instructions[null.offset]
                assert replacement.opname == 'LOAD_CONST' and replacement.argval is None
                assert prepared.__code__.co_consts[:len(original.__code__.co_consts)] == original.__code__.co_consts
                for item in original_instructions:
                    if item.opname == 'LOAD_CONST':
                        actual = prepared_instructions[item.offset]
                        assert actual.opname == item.opname and actual.arg == item.arg and actual.argval == item.argval
                rows.append({'template': original.__name__, 'original_constants': list(original.__code__.co_consts),
                             'prepared_constants': list(prepared.__code__.co_consts), 'null_offset': null.offset,
                             'none_index': replacement.arg, 'original_literal_indexes_preserved': True})
            return rows
        record('explicit_none_placeholder_preserves_original_literal_indexes', explicit_null_and_literal_indexes)

        def incorrect_kind_constant_refused():
            template = new._merge_kind_template
            constants = template.__code__.co_consts
            assert constants.count('kind') == 1
            changed = tuple('altered-key' if value == 'kind' else value for value in constants)
            altered = FunctionType(template.__code__.replace(co_consts=changed), vars(new))
            result = outcome(lambda: new._merge_port(altered, constants))
            assert result['error'] == {'type': 'builtins.RuntimeError', 'message': 'verification DICT_MERGE opcode template differs'}
            return {'original_constants': list(constants), 'mutant_constants': list(changed),
                    'malformed_code_executed': False, 'outcome': result}
        record('incorrect_original_kind_literal_refused_before_execution', incorrect_kind_constant_refused)
        report['status'] = 'PASS' if len(report['observations']) == 12 and all(row['status'] == 'PASS' for row in report['observations']) else 'FAIL'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        after = {str(path.resolve()): digest(path) for path in (args.original, args.candidate)}
        report['inputs_after'] = after
        report['inputs_unchanged'] = after == before
        if after != before:
            report['status'] = 'FAIL'
        report['elapsed_ns'] = time.monotonic_ns() - started
        (out / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'observations': len(report['observations']),
                          'inputs_unchanged': report['inputs_unchanged'], 'native_entries': 0}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
