"""Generate the complete public assembly/routing HIA and fixed primitive inventory.

The generated ports contain only fixed CALL/FORMAT/BUILD_STRING/import
mechanisms and immutable table identity. They never contain an original policy
body. No runtime eval, exec, AST interpretation or source compiler is used.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_machine_plan_control import (
    BODY as CONTROL_BODY, helpers, table, MAGIC, EMIT_MAGIC, ABI, OUTPUT)
from tools.hia_exception_delivery import BODY as EXCEPTION_BODY
from tools.hia_front_control import OPS
from tools.hia_core_lowering_table import BODY as EXPAND_BODY, compress_table, reference_expand


class _FrontBuilder(Builder):
    """Preserve the original front images' scalar SSA allocation order.

    The shared Builder keeps its block-local scalar CSE for other owners.
    These two frozen front inputs use the original Builder.op emission rule
    from a733926a (generate_hia_selfhost.py blob e0d1b9c7).
    """

    def op(self, op, args, t=None, **attrs):
        out = [] if t is None else [self.value(t)]
        self.block['ops'].append({
            'op': op, 'args': [a[0] for a in args],
            'out': [self.param(x) for x in out], 'attrs': attrs,
        })
        return out[0] if out else None


def emission(data, packed):
    padded = packed + bytes((-len(packed)) % 112)
    words = struct.unpack('<' + 'Q' * (len(padded) // 8), padded)
    groups = [words[i:i+224] for i in range(0, len(words), 224)]
    result = ['def emit_policy(o:mutbuf,w:mutbuf) -> u32:\n'
        '    if length(o) < ' + str(len(data)+len(padded)) + ' or length(w) < 96:\n'
        '        return ABI\n    put(w,88,' + str(len(data)) + ')\n' +
        '\n'.join('    emit_part_' + str(i) + '(o,w)' for i in range(len(groups))) +
        '\n    return expand_policy(o)']
    for i, group in enumerate(groups):
        result.append('def emit_part_' + str(i) + '(o:mutbuf,w:mutbuf) -> u64:\n' +
            '\n'.join('    words14(o,w,' + ','.join(map(str, group[j:j+14])) + ')'
                      for j in range(0, len(group), 14)) + '\n    return 0')
    return '\n\n'.join(result)


def transport_helpers():
    nodes = [n for n in ast.parse(helpers()).body if n.name != 'words']
    fixed = ast.unparse(ast.Module(body=nodes, type_ignores=[]))
    writer = ('def words14(o:mutbuf,w:mutbuf,' +
              ','.join('v' + str(i) + ':u64' for i in range(14)) + ') -> u64:\n' +
              '\n'.join('    put(o,get(w,88)+' + str(i*8) + ',v' + str(i) + ')' for i in range(14)) +
              '\n    put(w,88,get(w,88)+112)\n    return 0')
    return fixed + '\n\n' + writer


def document(policy, module_name):
    data = table(policy)
    packed = compress_table(data)
    if reference_expand(packed) != data:
        raise AssertionError('public-front table encoding is not lossless')
    constants = {'MAGIC': MAGIC, 'EMIT_MAGIC': EMIT_MAGIC, 'ABI': ABI,
                 'OUTPUT_BYTES': OUTPUT, 'TABLE_BYTES': len(data), 'PACKED_BYTES': len(packed),
                 'WORKSPACE_BYTES': 1024+8*max(f.next_slot for f in policy.functions), **OPS}
    parsed = ast.parse(CONTROL_BODY + '\n' + transport_helpers() + '\n' +
                       emission(data, packed) + '\n' + EXPAND_BODY + '\n' + EXCEPTION_BODY)
    class Names(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    nodes = ast.fix_missing_locations(Names().visit(parsed)).body
    names = {n.name: 'f'+str(i) for i,n in enumerate(nodes)}
    signatures = {n.name: ([p.annotation.id for p in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = _FrontBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns], 'effects':['read','write','trap'],
            'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8',
                                  'module':module_name,'functions':functions})


PORT_HELPERS = r'''
def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3,12),(3,13),(3,14)):
        raise RuntimeError('public-front ports require a reviewed CPython ABI')

def format_value(frame, slot):
    return f'{frame._move(slot)}'

def _build_string_port(template, count):
    _profile()
    code = template.__code__
    instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
    meaningful = tuple(i for i in instructions if i.opname != 'CACHE')
    format_name = 'FORMAT_SIMPLE' if sys.version_info[:2] == (3,14) else 'FORMAT_VALUE'
    formats = tuple(i for i in meaningful if i.opname == format_name)
    builds = tuple(i for i in meaningful if i.opname == 'BUILD_STRING')
    allowed = {'RESUME','LOAD_FAST','LOAD_FAST_BORROW','LOAD_FAST_BORROW_LOAD_FAST_BORROW',
               'LOAD_ATTR','LOAD_METHOD','LOAD_CONST','LOAD_SMALL_INT','BINARY_SUBSCR',
               'CALL','FORMAT_VALUE','FORMAT_SIMPLE','BUILD_STRING','RETURN_VALUE','PUSH_NULL','BINARY_OP'}
    if (code.co_exceptiontable or len(formats) != count or len(builds) != 1
            or builds[0].arg != count or tuple(i.opname for i in meaningful[-2:]) != ('BUILD_STRING','RETURN_VALUE')
            or any(i.opname not in allowed for i in meaningful)
            or any(i.opname == 'BINARY_OP' and i.argrepr != '[]' for i in meaningful)
            or any(i.opname == 'CACHE' and any(f.offset+2 == i.offset for f in formats) for i in instructions)
            or any(code.co_code[i.offset+1] != 0 for i in formats)
            or any(v is not None and (type(v) is not int or not 0 <= v < count) for v in code.co_consts)):
        raise RuntimeError('public-front BUILD_STRING fixed template differs')
    raw = bytearray(code.co_code)
    for instruction in formats:
        raw[instruction.offset:instruction.offset+2] = bytes((dis.opmap['NOP'],0))
    function = FunctionType(code.replace(co_code=bytes(raw),co_name='_public_front_build_string',
        co_qualname='_public_front_build_string'),globals())
    if any(i.opname in ('FORMAT_SIMPLE','FORMAT_VALUE') for i in dis.get_instructions(function)):
        raise RuntimeError('public-front BUILD_STRING still formats its completed operands')
    return function

def _import_name_port(template, namespace, module, names):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code,show_caches=True,adaptive=False) if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('public-front IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME','LOAD_CONST','LOAD_CONST','IMPORT_NAME'),
            ('RESUME','LOAD_SMALL_INT','LOAD_CONST','IMPORT_NAME'))
            or prefix[1].argval != 1 or prefix[2].argval != names):
        raise RuntimeError('public-front import operands differ')
    raw = code.co_code[:imports[0].offset+2]+bytes((dis.opmap['RETURN_VALUE'],0))
    return FunctionType(code.replace(co_code=raw,co_name='_public_front_import_name',
                        co_qualname='_public_front_import_name'),namespace)

def _from_template(module):
    return module.elaborate_program

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('public-front import field differs')
    raw = bytes((dis.opmap['RESUME'],0,dis.opmap['LOAD_FAST'],0,dis.opmap['IMPORT_FROM'],0,
                 dis.opmap['SWAP'],2,dis.opmap['POP_TOP'],0,dis.opmap['RETURN_VALUE'],0))
    function = FunctionType(_from_template.__code__.replace(co_code=raw,co_names=(name,),
        co_stacksize=2,co_name='_public_front_import_from',co_qualname='_public_front_import_from'),namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME','LOAD_FAST','IMPORT_FROM','SWAP','POP_TOP','RETURN_VALUE'):
        raise RuntimeError('public-front IMPORT_FROM primitive differs')
    return function

def _unbound_template():
    value: object
    return value

def _empty_free_template():
    if False:
        value = None
    return lambda: value

_EMPTY_FREE = _empty_free_template()
_UNBOUND_PORTS = {}
def unbound(name, free):
    _profile()
    if type(name) is not str or type(free) is not int or free not in (0,1):
        raise RuntimeError('public-front unbound-name representation differs')
    key = (name,free)
    if key not in _UNBOUND_PORTS:
        if free:
            function = FunctionType(_EMPTY_FREE.__code__.replace(co_freevars=(name,)),
                                    globals(),closure=_EMPTY_FREE.__closure__)
            expected = 'LOAD_DEREF'
        else:
            function = FunctionType(_unbound_template.__code__.replace(co_varnames=(name,)),globals())
            expected = 'LOAD_FAST_CHECK'
        if not any(i.opname == expected and i.argval == name for i in dis.get_instructions(function,adaptive=False)):
            raise RuntimeError('public-front unbound opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()
'''


def ports_source(policy, data, entries, imports):
    output = ['"""Generated fixed CPython operands for public-front HIA-issued effects.\n\nNo business-policy body, runtime AST, exec, or dynamic source compiler.\n"""',
              'from __future__ import annotations', 'import dis', 'import sys',
              'from types import FunctionType', '',
              'TABLE_SHA256 = '+repr(sha256(data).hexdigest()),
              'ROOT_NAMES = '+repr(tuple(entries)),
              'FUNCTION_COUNT = '+repr(len(policy.functions)),
              'IMPORT_NAMES = '+repr(tuple(sorted({n for names in imports.values() for n in names}))),
              PORT_HELPERS]
    calls = []
    for number, (positional, names) in enumerate(sorted(policy.call_shapes)):
        if any(not name.isidentifier() for name in names):
            raise ValueError('public-front keyword cannot be a fixed Python identifier')
        operands = ['frame._move(slots['+str(i)+'])' for i in range(1,positional+1)]
        operands += [name+'=frame._move(slots['+str(positional+i+1)+'])' for i,name in enumerate(names)]
        symbol = '_call_'+str(number)
        output += ['def '+symbol+'(frame, slots):',
                   '    return frame._move(slots[0])('+', '.join(operands)+')','']
        calls.append((positional,names,symbol))
    output += ['CALLS = {']+['    '+repr((p,k))+': '+s+',' for p,k,s in calls]+['}','']
    strings = []
    for count in sorted(policy.string_shapes):
        symbol = '_string_'+str(count)
        form = ''.join('{frame._move(slots['+str(i)+'])}' for i in range(count))
        output += ['def '+symbol+'(frame, slots):', '    return f'+repr(form),'']
        strings.append((count,symbol))
    output += ['BUILD_STRINGS = {']+[
        '    '+str(n)+': _build_string_port('+s+','+str(n)+'),' for n,s in strings]+['}','']
    groups = sorted(imports.items())
    for number,(module,names) in enumerate(groups):
        output += ['def _import_template_'+str(number)+'():',
                   '    from .'+module+' import '+', '.join(names),'']
    output += ['def import_ports(namespace):','    return ({']+[
        '        '+repr((module,tuple(names)))+': _import_name_port(_import_template_'+str(i)+
        ', namespace, '+repr(module)+', '+repr(tuple(names))+'),' for i,(module,names) in enumerate(groups)]+[
        '    }, {name: _import_from_port(name,namespace) for name in IMPORT_NAMES})','']
    return '\n'.join(output).rstrip()+'\n'
