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

PREFIX = '''"""Fixed CPython call/mapping primitives for HIA-issued native-build ports.

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


def _update_template(frame, destination_slot, mapping_slot):
    return {**frame._get(destination_slot), **frame._get(mapping_slot)}


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('native-build mapping ports require a reviewed CPython ABI')


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
    if (code.co_exceptiontable or code.co_consts != constants
            or len(merges) != 1 or len(calls) != 1 or len(nulls) != 1
            or merges[0].arg != 1
            or (calls[0].arg is not None or code.co_code[calls[0].offset+1] != 0
                if sys.version_info[:2] == (3, 14)
                else calls[0].arg != 1 or code.co_code[calls[0].offset+1] != 1)
            or tuple(i.opname for i in meaningful[-3:]) != ('DICT_MERGE', 'CALL_FUNCTION_EX', 'RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)):
        raise RuntimeError('native-build DICT_MERGE opcode template differs')
    raw = bytearray(code.co_code[:calls[0].offset])
    raw[nulls[0].offset:nulls[0].offset+2] = bytes((dis.opmap['LOAD_CONST'], 0))
    raw.extend(bytes((dis.opmap['SWAP'], 2, dis.opmap['POP_TOP'], 0)) * 3)
    raw.extend(bytes((dis.opmap['RETURN_VALUE'], 0)))
    result = FunctionType(code.replace(co_code=bytes(raw), co_name='_native_build_dict_merge',
                          co_qualname='_native_build_dict_merge'), globals())
    if any(i.opname == 'CALL_FUNCTION_EX' for i in dis.get_instructions(result)):
        raise RuntimeError('native-build mapping preparation still calls a provider')
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
        raise RuntimeError('native-build DICT_UPDATE opcode template differs')
    raw = bytearray(code.co_code)
    # Omit the unused new dict and the copy of the actual destination. The
    # remaining fixed DICT_UPDATE mutates that exact HIA-owned dict, so an
    # overwritten foreign value is not kept alive by a shadow dictionary.
    for item in (maps[0], updates[0]):
        raw[item.offset:item.offset+2] = bytes((dis.opmap['NOP'], 0))
    return FunctionType(code.replace(co_code=bytes(raw), co_name='_native_build_dict_update',
                        co_qualname='_native_build_dict_update'), globals())


merge_empty = _merge_port(_merge_empty_template, (None,))
update_dict = _update_port()


def mapping_call(frame, callee_slot, positional_slot, keywords_slot):
    if type(frame._get(positional_slot)) is not tuple or type(frame._get(keywords_slot)) is not dict:
        raise RuntimeError('native-build mapping call lacks exact prepared containers')
    return frame._move(callee_slot)(*frame._move(positional_slot), **frame._move(keywords_slot))

'''


IMPORT_SUPPORT = "def _import_name_port(template, namespace, module, fromlist, level):\n    _profile()\n    code = template.__code__\n    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)\n                       if i.opname != 'CACHE')\n    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')\n    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:\n        raise RuntimeError('native-build IMPORT_NAME template differs')\n    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)\n    if (tuple(i.opname for i in prefix) not in (\n            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),\n            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))\n            or prefix[1].argval != level or prefix[2].argval != fromlist):\n        raise RuntimeError('native-build original import operands differ')\n    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))\n    return FunctionType(code.replace(co_code=raw, co_name='_native_build_import_name',\n                                    co_qualname='_native_build_import_name'), namespace)\n\ndef _from_template(module):\n    return module.ARTIFACT_PROFILE\n\ndef _import_from_port(name, namespace):\n    _profile()\n    if name not in IMPORT_NAMES:\n        raise RuntimeError('native-build imported name is outside the fixed inventory')\n    # Actual IMPORT_FROM includes CPython's original circular-import fallback\n    # and error formatting. A generic getattr would not implement that port.\n    # Move the argument onto the interpreter stack before the import. A held\n    # ImportError must not retain an extra module parameter in this port's\n    # traceback after the HIA controller has retired its module temporary.\n    constants = _from_template.__code__.co_consts\n    if None not in constants:\n        constants += (None,)\n    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,\n                 dis.opmap['LOAD_CONST'], constants.index(None), dis.opmap['STORE_FAST'], 0,\n                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,\n                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))\n    code = _from_template.__code__.replace(co_code=raw, co_names=(name,), co_consts=constants,\n        co_stacksize=2, co_name='_native_build_import_from', co_qualname='_native_build_import_from')\n    function = FunctionType(code, namespace)\n    if tuple(i.opname for i in dis.get_instructions(function)) != (\n            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',\n            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):\n        raise RuntimeError('native-build IMPORT_FROM primitive differs')\n    return function\n\n\ndef _unbound_template():\n    value: object\n    return value\n\n\ndef _empty_free_template():\n    if False:\n        value = None\n    return lambda: value\n\n\n_EMPTY_FREE = _empty_free_template()\n_UNBOUND_PORTS = {}\n\n\ndef unbound(name, free):\n    _profile()\n    if type(name) is not str or type(free) is not int or free not in (0, 1):\n        raise RuntimeError('native-build unbound-name representation differs')\n    key = (name, free)\n    if key not in _UNBOUND_PORTS:\n        if free:\n            code = _EMPTY_FREE.__code__.replace(co_freevars=(name,))\n            function = FunctionType(code, globals(), closure=_EMPTY_FREE.__closure__)\n            expected = 'LOAD_DEREF'\n        else:\n            code = _unbound_template.__code__.replace(co_varnames=(name,))\n            function = FunctionType(code, globals())\n            expected = 'LOAD_FAST_CHECK'\n        instructions = tuple(dis.get_instructions(function, adaptive=False))\n        if not any(item.opname == expected and item.argval == name for item in instructions):\n            raise RuntimeError('native-build unbound interpreter opcode differs')\n        _UNBOUND_PORTS[key] = function\n    return _UNBOUND_PORTS[key]()\n"

def source():
    policy = ast.parse((ROOT/'tools/hia_native_build_policy.py').read_bytes())
    shapes = sorted({(len(n.args), tuple(k.arg for k in n.keywords))
                     for n in ast.walk(policy) if isinstance(n, ast.Call)
                     and not any(k.arg is None for k in n.keywords)})
    groups = sorted({(n.module, tuple(a.name for a in n.names))
                     for n in ast.walk(policy) if isinstance(n, ast.ImportFrom)},
                    key=lambda group: (group[0] or '', group[1]))
    names = tuple(sorted({name for module, fields in groups for name in fields}))
    lines = [PREFIX, '\nIMPORT_NAMES = '+repr(names)+'\n', IMPORT_SUPPORT]
    for index, (module, fields) in enumerate(groups):
        lines.append('def _import_template_'+str(index)+'():\n    from .'+(module or '')+' import '+', '.join(fields)+'\n\n')
    lines.append('def import_ports(namespace):\n    return ({\n')
    for index, (module, fields) in enumerate(groups):
        lines.append('        '+repr((module, fields))+': _import_name_port(_import_template_'+str(index)+', namespace, '+repr(module or '')+', '+repr(fields)+', 1),\n')
    lines.append('    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})\n\n')
    inventory = []
    for index, (positional, keywords) in enumerate(shapes):
        if positional > 14 or len(keywords) > 8:
            raise ValueError('unreviewed fixed native-build call shape')
        operands = ['frame._move(slots['+str(i+1)+'])' for i in range(positional)]
        operands.extend(key+'=frame._move(slots['+str(positional+i+1)+'])'
                        for i,key in enumerate(keywords))
        name = '_call_' + str(index)
        lines.append('def '+name+'(frame, slots):\n    return frame._move(slots[0])('+', '.join(operands)+')\n\n')
        inventory.append('    '+repr((positional,keywords))+': '+name+',\n')
    lines.append('CALLS = {\n'+''.join(inventory)+'}\n')
    return ''.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT/'hepta/hia_native_build_foreign.py'
    raw = source().encode()
    if args.check:
        if path.read_bytes() != raw:
            raise AssertionError('fixed native-build call templates differ')
    else:
        path.write_bytes(raw)
    print(path)


if __name__ == '__main__':
    main()
