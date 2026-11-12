"""Render fixed call/DICT_MERGE/DICT_UPDATE mechanism templates.

Only call ABI shapes are read from the exact retained policy. No body or
branch is copied to this bridge; no business source is compiled at runtime.
The runtime bytecode suffix adjustment exposes single existing CPython
representation primitives, with explicit opcode and interpreter admission.
"""
from __future__ import annotations
import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEGACY_IMPORT_FROM = '''def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('native-build imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,),
        co_stacksize=2, co_name='_native_build_import_from', co_qualname='_native_build_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('native-build IMPORT_FROM primitive differs')
    return function
'''

MOVED_IMPORT_FROM = '''def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('native-build imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    # Move the argument onto the interpreter stack before the import. A held
    # ImportError must not retain an extra module parameter in this port's
    # traceback after the HIA controller has retired its module temporary.
    constants = _from_template.__code__.co_consts
    if None not in constants:
        constants += (None,)
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['LOAD_CONST'], constants.index(None), dis.opmap['STORE_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,), co_consts=constants,
        co_stacksize=2, co_name='_native_build_import_from', co_qualname='_native_build_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',
            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('native-build IMPORT_FROM primitive differs')
    return function
'''


def reviewed_import_support(text):
    """Normalize only the two reviewed complete IMPORT_FROM definitions."""
    definitions = [node for node in ast.parse(text).body
                   if isinstance(node, ast.FunctionDef) and node.name == '_import_from_port']
    if len(definitions) != 1:
        raise ValueError('artifacts import support lacks one reviewed port')
    node = definitions[0]
    lines = text.splitlines(keepends=True)
    actual = ''.join(lines[node.lineno - 1:node.end_lineno])
    if actual not in (LEGACY_IMPORT_FROM, MOVED_IMPORT_FROM):
        raise ValueError('artifacts import support definition is unreviewed')
    return ''.join(lines[:node.lineno - 1]) + MOVED_IMPORT_FROM + ''.join(lines[node.end_lineno:])

PREFIX = '''"""Fixed CPython call/mapping primitives for HIA-issued artifacts ports.

This module performs no proof or service branch. HIA alone chooses each port,
its operands and one-use lifetime permission. The mapping templates expose
actual DICT_MERGE (duplicate refusal) and DICT_UPDATE (duplicate replacement)
separately; they do not execute a retained policy function.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType


def _merge_empty_template(frame, callee_slot, positional_slot, mapping_slot):
    return frame._get(callee_slot)(*frame._get(positional_slot), **frame._get(mapping_slot))


def _merge_kind_template(frame, callee_slot, positional_slot, kind_slot, mapping_slot):
    return frame._get(callee_slot)(*frame._get(positional_slot), kind=frame._get(kind_slot), **frame._get(mapping_slot))


def _update_template(frame, destination_slot, mapping_slot):
    return {**frame._get(destination_slot), **frame._get(mapping_slot)}


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('artifacts mapping ports require a reviewed CPython ABI')


def _merge_port(template, constants):
    _profile()
    code = template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
    merges = tuple(i for i in meaningful if i.opname == 'DICT_MERGE')
    calls = tuple(i for i in meaningful if i.opname == 'CALL_FUNCTION_EX')
    nulls = tuple(i for i in meaningful if i.opname == 'PUSH_NULL')
    allowed = {'RESUME', 'PUSH_NULL', 'LOAD_FAST', 'LOAD_FAST_BORROW',
               'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_ATTR', 'LOAD_CONST',
               'CALL', 'BUILD_MAP', 'DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE'}
    # CPython 3.14 removed this instruction's flags operand. Keep the
    # reviewed raw no-argument encoding separate from 3.12/3.13 flag 1.
    call_argument = None if sys.version_info[:2] == (3, 14) else 1
    call_raw_argument = 0 if sys.version_info[:2] == (3, 14) else 1
    if (code.co_exceptiontable or code.co_consts != constants
            or len(merges) != 1 or len(calls) != 1 or len(nulls) != 1
            or merges[0].arg != 1 or calls[0].arg != call_argument
            or code.co_code[calls[0].offset + 1] != call_raw_argument
            or tuple(i.opname for i in meaningful[-3:]) != ('DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('artifacts DICT_MERGE opcode template differs')
    # 3.14 can omit the unused implicit None from the original constants.
    # Preserve all original literal indexes; append a real None only for
    # the fixed, safely poppable replacement of the interpreter NULL.
    port_constants = constants if None in constants else constants + (None,)
    none_index = port_constants.index(None)
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], none_index))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_consts=port_constants, co_name='_artifacts_dict_merge',
                          co_qualname='_artifacts_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('artifacts mapping preparation still calls a provider')
    return result


def _update_port():
    _profile()
    code = _update_template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
    maps = tuple(i for i in meaningful if i.opname == 'BUILD_MAP')
    updates = tuple(i for i in meaningful if i.opname == 'DICT_UPDATE')
    allowed = {'RESUME', 'LOAD_FAST', 'LOAD_FAST_BORROW',
               'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_ATTR', 'LOAD_CONST',
               'CALL', 'BUILD_MAP', 'DICT_UPDATE', 'RETURN_VALUE'}
    if (code.co_exceptiontable or code.co_consts != (None,)
            or len(maps) != 1 or maps[0].arg != 0 or len(updates) != 2
            or any(i.arg != 1 for i in updates)
            or tuple(i.opname for i in meaningful[-2:]) != ('DICT_UPDATE', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('artifacts DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_artifacts_dict_update',
                        co_qualname='_artifacts_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
merge_kind = _merge_port(_merge_kind_template,
                         ('kind',) if sys.version_info[:2] == (3, 14) else (None, 'kind'))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('artifacts mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))

'''


def source():
    from tools.generate_hia_native_build_foreign import IMPORT_SUPPORT
    from tools.hia_service_artifacts_control import compile_policy
    text = (ROOT / 'tools/hia_service_artifacts_policy.py').read_text()
    policy = ast.parse(text)
    compiled = compile_policy(text)
    from hashlib import sha256
    from tools.generate_hia_service_artifacts import table
    table_sha256 = sha256(table(compiled)).hexdigest()
    shapes = sorted({(len(node.args), tuple(keyword.arg for keyword in node.keywords))
                     for node in ast.walk(policy) if isinstance(node, ast.Call)
                     and not any(keyword.arg is None for keyword in node.keywords)})
    groups = sorted({(node.module, tuple(alias.name for alias in node.names))
                     for node in ast.walk(policy) if isinstance(node, ast.ImportFrom)})
    names = tuple(sorted({name for module, fields in groups for name in fields}))
    imports = reviewed_import_support(IMPORT_SUPPORT).replace('native-build', 'service-artifacts').replace(
        '_native_build', '_service_artifacts')
    layout = tuple((fn.mode, fn.kind, fn.next_slot, len(fn.parameters), len(fn.captures))
                   for fn in compiled.functions)
    lines = [PREFIX, '\nTABLE_SHA256 = ' + repr(table_sha256) + '\n',
             '\nFUNCTION_LAYOUT = ' + repr(layout) + '\n',
             'IMPORT_NAMES = ' + repr(names) + '\n', imports]
    for index, (module, fields) in enumerate(groups):
        lines.append('def _import_template_' + str(index) + '():\n    from .' +
                     module + ' import ' + ', '.join(fields) + '\n\n')
    lines.append('def import_ports(namespace):\n    return ({\n')
    for index, (module, fields) in enumerate(groups):
        lines.append('        ' + repr((module, fields)) + ': _import_name_port(_import_template_' +
                     str(index) + ', namespace, ' + repr(module) + ', ' + repr(fields) + ', 1),\n')
    lines.append('    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})\n\n')
    inventory = []
    for index, (positional, keywords) in enumerate(shapes):
        if positional > 14 or len(keywords) > 8:
            raise ValueError('artifacts fixed call shape is outside the reviewed source profile')
        operands = ['frame._move(slots[' + str(i + 1) + '])' for i in range(positional)]
        operands.extend(key + '=frame._move(slots[' + str(positional + i + 1) + '])'
                        for i, key in enumerate(keywords))
        name = '_call_' + str(index)
        lines.append('def ' + name + '(frame, slots):\n    return frame._move(slots[0])(' +
                     ', '.join(operands) + ')\n\n')
        inventory.append('    ' + repr((positional, keywords)) + ': ' + name + ',\n')
    lines.append('CALLS = {\n' + ''.join(inventory) + '}\n')
    return ''.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT/'hepta/hia_service_artifacts_foreign.py'
    raw = source().encode()
    if args.check:
        if path.read_bytes() != raw:
            raise AssertionError('fixed artifacts call templates differ')
    else:
        path.write_bytes(raw)
    print(path)


if __name__ == '__main__':
    main()
