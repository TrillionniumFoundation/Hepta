#!/usr/bin/env python3
"""Independent, fail-closed HIA scalar and resource *research probe*.

NOT a replacement for hepta.hia_program.verify_program and NOT release authority.
The strict subset is deliberately small enough to admit independent native checks.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import subprocess
import tempfile
from pathlib import Path

SCHEMA = 'hepta.audit.scalar-u32.v1'
UINT32 = 2**32 - 1
OPERATORS = {'+': 'int.add.wrap', '-': 'int.sub.wrap', '*': 'int.mul.wrap',
             '^': 'bit.xor', '&': 'bit.and', '|': 'bit.or'}
C_OPS = {v: k for k, v in OPERATORS.items()}
CHECKED_OPS = frozenset({'int.add.checked','int.sub.checked','int.mul.checked',
                         'int.div.checked','int.rem.checked','int.shl.checked','int.shr.checked'})
BINARY_OPS = frozenset(C_OPS)|CHECKED_OPS
MAX_SOURCE = 65_536
MAX_PROGRAM = 256*1024
MAX_AST = 2 * 1024 * 1024
MAX_NODES = 4096
MAX_DEPTH = 128
MAX_INSTRUCTIONS = 256
IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')

class ProgramTrap(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__('program trap: '+code)

class Rejected(ValueError):
    def __init__(self, code: str, reason: str):
        self.code = code
        super().__init__(f'{code}: {reason}')

def reject(code: str, reason: str) -> None:
    raise Rejected(code, reason)

def canonical_bytes(value: object) -> bytes:
    # Bound canonicalization while walking the object rather than after dumping it.
    encoder=json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                             allow_nan=False, check_circular=True)
    chunks=[];length=0
    try:
        for part in encoder.iterencode(value):
            data=part.encode('ascii')
            length+=len(data)
            if length>MAX_PROGRAM:
                reject('E_JSON_BUDGET','canonical input exceeds bounded profile')
            chunks.append(data)
    except (RecursionError, UnicodeError):
        reject('E_JSON','invalid or overly nested JSON input')
    return b''.join(chunks)

def identity(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def _keys(obj: object, expected: set[str], code: str) -> None:
    if type(obj) is not dict or set(obj) != expected:
        reject(code, f'expected exact fields {sorted(expected)}')

def _ident(v: object, code: str) -> str:
    if type(v) is not str or IDENT.fullmatch(v) is None:
        reject(code, 'not a bounded identifier')
    return v

def verify_scalar(program: object) -> dict:
    """Check exact, bounded, one-block, u32 SSA; return a detached copy."""
    try:
        p = json.loads(canonical_bytes(program), parse_constant=lambda _: reject('E_JSON', 'nonfinite'))
    except (TypeError, ValueError, OverflowError) as e:
        if isinstance(e, Rejected):
            raise
        reject('E_JSON', str(e))
    _keys(p, {'schema', 'name', 'params', 'ops', 'result'}, 'E_SCHEMA')
    if p['schema'] != SCHEMA:
        reject('E_VERSION', 'explicit schema required')
    _ident(p['name'], 'E_NAME')
    if type(p['params']) is not list or len(p['params']) > 16:
        reject('E_PARAMS', 'invalid parameters')
    if type(p['ops']) is not list or len(p['ops']) > MAX_INSTRUCTIONS:
        reject('E_OP_BUDGET', 'instruction limit')
    names = set()
    for param in p['params']:
        _keys(param, {'name', 'type'}, 'E_PARAM')
        name = _ident(param['name'], 'E_PARAM')
        if name in names or param['type'] != 'u32':
            reject('E_PARAM', 'non-unique parameter or unsupported type')
        names.add(name)
    for op in p['ops']:
        if type(op) is not dict or 'opcode' not in op:
            reject('E_OPCODE', 'operation record required')
        op_name = op['opcode']
        required = {'id', 'opcode', 'value'} if op_name == 'const' else {'id', 'opcode', 'args'}
        _keys(op, required, 'E_OPCODE')
        new_id = _ident(op['id'], 'E_SSA')
        if new_id in names:
            reject('E_SSA', 'SSA reassignment')
        if op_name == 'const':
            if type(op['value']) is not int or not 0 <= op['value'] <= UINT32:
                reject('E_CONST', 'constant must be exact unsigned 32-bit integer')
        elif op_name in BINARY_OPS:
            if type(op['args']) is not list or len(op['args']) != 2:
                reject('E_ARGS', 'binary instruction requires two operands')
            for arg in op['args']:
                if type(arg) is not str or arg not in names:
                    reject('E_SSA', 'use before definition')
        else:
            reject('E_OPCODE', f'unsupported opcode {op_name}')
        names.add(new_id)
    if type(p['result']) is not str or p['result'] not in names:
        reject('E_RETURN', 'undefined result')
    return p

def interpret_scalar(program: object, args: object) -> int:
    p = verify_scalar(program)
    if type(args) not in (tuple, list) or len(args) != len(p['params']):
        reject('E_INVOKE', 'argument count mismatch')
    vals: dict[str,int] = {}
    for param, arg in zip(p['params'], args):
        if type(arg) is not int or not 0 <= arg <= UINT32:
            reject('E_INVOKE', 'argument out of u32 domain')
        vals[param['name']] = arg
    for op in p['ops']:
        name = op['opcode']
        if name == 'const':
            result = op['value']
        else:
            a, b = (vals[x] for x in op['args'])
            if name in CHECKED_OPS:
                operation=name.split('.')[1]
                if operation=='add':
                    result=a+b
                elif operation=='sub':
                    result=a-b
                elif operation=='mul':
                    result=a*b
                elif operation=='div':
                    if b==0:raise ProgramTrap('division_by_zero')
                    result=a//b
                elif operation=='rem':
                    if b==0:raise ProgramTrap('division_by_zero')
                    result=a%b
                elif operation=='shl':
                    if b>=32:raise ProgramTrap('shift_count')
                    result=(a<<b)&UINT32  # count checked, value wraps per HIA finite profile
                else:
                    if b>=32:raise ProgramTrap('shift_count')
                    result=a>>b
                if not 0<=result<=UINT32:
                    raise ProgramTrap('overflow')
            else:
                result = {'int.add.wrap': lambda: a+b,
                          'int.sub.wrap': lambda: a-b,
                          'int.mul.wrap': lambda: a*b,
                          'bit.and': lambda: a&b,
                          'bit.or': lambda: a|b,
                          'bit.xor': lambda: a^b}[name]() & UINT32
        vals[op['id']] = result
    return vals[p['result']]

def emit_native_c(program: object, func: str = 'hia_entry') -> str:
    p = verify_scalar(program)
    _ident(func, 'E_NATIVE_NAME')
    if any(op['opcode'] in CHECKED_OPS for op in p['ops']):
        reject('E_ABI_TRAP', 'trapping opcode requires explicit status-return ABI')
    sig = ', '.join('uint32_t '+a['name'] for a in p['params']) or 'void'
    src = ['#include <stdint.h>', '#include <limits.h>',
           '_Static_assert(sizeof(unsigned int)*CHAR_BIT == 32, "u32 requires 32-bit unsigned int");',
           f'uint32_t {func}({sig}) {{']
    for op in p['ops']:
        if op['opcode'] == 'const':
            expr = f'UINT32_C({op["value"]})'
        else:
            a, b = op['args']
            expr = f'(({a}) {C_OPS[op["opcode"]]} ({b}))'
        src.append(f'    uint32_t {op["id"]} = {expr};')
    src.append(f'    return {p["result"]};')
    src.append('}')
    return '\n'.join(src)+'\n'

def emit_checked_native_c(program: object, func: str = 'hia_checked') -> str:
    """Explicitly report traps as status, never silently alter return semantics.

    Status: 0=OK, 1=overflow, 2=division by zero, 3=invalid shift count,
    4=invalid output pointer (ABI contract). Only for this finite unsigned profile.
    """
    p=verify_scalar(program)
    _ident(func,'E_NATIVE_NAME')
    sig=', '.join('uint32_t '+a['name'] for a in p['params'])
    sig=(sig+', ' if sig else '')+'uint32_t *out'
    src=['#include <stdint.h>','#include <limits.h>',
         '_Static_assert(sizeof(unsigned int)*CHAR_BIT == 32, "u32 requires 32-bit unsigned int");',
         f'int {func}({sig}) {{','    if (out == 0) return 4;']
    for op in p['ops']:
        name=op['opcode'];new=op['id']
        if name=='const':
            src.append(f'    uint32_t {new} = UINT32_C({op["value"]});')
            continue
        a,b=op['args']
        if name in C_OPS:
            expr=f'(({a}) {C_OPS[name]} ({b}))'
        else:
            action=name.split('.')[1]
            if action=='add':
                src.append(f'    if ((uint64_t){a} + (uint64_t){b} > UINT32_MAX) return 1;')
                expr=f'({a} + {b})'
            elif action=='sub':
                src.append(f'    if ({a} < {b}) return 1;')
                expr=f'({a} - {b})'
            elif action=='mul':
                src.append(f'    if ((uint64_t){a} * (uint64_t){b} > UINT32_MAX) return 1;')
                expr=f'({a} * {b})'
            elif action in ('div','rem'):
                src.append(f'    if ({b} == 0) return 2;')
                expr=f'({a} {"/" if action=="div" else "%"} {b})'
            elif action in ('shl','shr'):
                src.append(f'    if ({b} >= 32) return 3;')
                expr=f'({a} {"<<" if action=="shl" else ">>"} {b})'
            else:
                reject('E_NATIVE','unexpected operation')
        src.append(f'    uint32_t {new} = {expr};')
    src.append(f'    *out = {p["result"]};')
    src.append('    return 0;')
    src.append('}')
    return '\n'.join(src)+'\n'

def _clang_rlimits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (8, 9))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_AST, MAX_AST))
    resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024, 1024*1024*1024))

def _validate_ast_tree(obj: object) -> None:
    todo = [(obj, 1)]
    seen = 0
    while todo:
        n, depth = todo.pop()
        if depth > MAX_DEPTH:
            reject('E_AST_DEPTH', 'Clang AST depth budget exceeded')
        if type(n) is not dict:
            reject('E_AST', 'non-dictionary AST node')
        seen += 1
        if seen > MAX_NODES:
            reject('E_AST_BUDGET', 'Clang AST node budget exceeded')
        children = n.get('inner', [])
        if type(children) is not list:
            reject('E_AST', 'malformed child list')
        todo.extend((child, depth+1) for child in children)

def translate_clang_scalar(source: str, function_name: str, clang: str = 'clang') -> dict:
    """Wholly reject unsupported C; no macros, global state, calls, pointers or signed math."""
    if type(source) is not str:
        reject('E_SOURCE', 'source must be unicode text')
    try:
        data = source.encode('utf-8')
    except UnicodeError:
        reject('E_SOURCE', 'invalid unicode encoding')
    if not data or len(data) > MAX_SOURCE or b'\x00' in data or '#' in source:
        reject('E_SOURCE', 'invalid/oversized or preprocessed source')
    _ident(function_name, 'E_FUNCTION')
    with tempfile.TemporaryDirectory(prefix='hia-clang-') as folder:
        src_path = Path(folder) / 'source.c'
        ast_path = Path(folder) / 'ast.json'
        src_path.write_bytes(data)
        error_path=Path(folder)/'clang.stderr'
        with ast_path.open('wb') as stdout, error_path.open('wb') as stderr:
            try:
                p = subprocess.run([clang, '-Xclang', '-ast-dump=json', '-fsyntax-only',
                                    '-std=c11', '-fno-color-diagnostics', '-Werror', str(src_path)],
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   timeout=15, preexec_fn=_clang_rlimits(), check=False)
            except (subprocess.TimeoutExpired, OSError) as e:
                reject('E_CLANG', str(e))
        if p.returncode or ast_path.stat().st_size > MAX_AST:
            with error_path.open('rb') as errors:
                error_summary=errors.read(256).decode('utf-8','replace')
            reject('E_CLANG', 'AST generation failed, was truncated or exceeded budget: '+error_summary)
        try:
            root = json.loads(ast_path.read_bytes())
        except (ValueError, OSError, RecursionError):
            reject('E_AST', 'not valid bounded JSON')
    if type(root) is not dict or type(root.get('inner')) is not list:
        reject('E_AST', 'invalid translation unit')
    # The Clang builtins (no source position) are not user program declarations.
    user_decls = [d for d in root['inner']
                  if type(d) is dict and isinstance(d.get('loc'), dict)
                  and type(d['loc'].get('offset')) is int]
    if len(user_decls) != 1:
        reject('E_WHOLE_UNIT', 'requires exactly one user-defined function and no globals')
    fn = user_decls[0]
    _validate_ast_tree(fn)
    if fn.get('kind') != 'FunctionDecl' or fn.get('name') != function_name:
        reject('E_FUNCTION', 'single function does not match requested name')
    if fn.get('type', {}).get('qualType') not in ('unsigned int (unsigned int)',
            'unsigned int (unsigned int, unsigned int)', 'unsigned int (void)',
            'unsigned int (unsigned int, unsigned int, unsigned int)'):
        reject('E_TYPE', 'strict unsigned-int signature only')
    children = fn.get('inner', [])
    params = [x for x in children if x.get('kind') == 'ParmVarDecl']
    bodies = [x for x in children if x.get('kind') == 'CompoundStmt']
    if len(bodies) != 1 or len(params) + 1 != len(children):
        reject('E_BODY', 'one body and only parameters required')
    names=[]
    for par in params:
        if par.get('type', {}).get('desugaredQualType', par.get('type', {}).get('qualType')) != 'unsigned int':
            reject('E_TYPE', 'all parameters must be exactly unsigned int')
        names.append(_ident(par.get('name'), 'E_PARAM'))
    if len(set(names)) != len(names):
        reject('E_PARAM', 'duplicate parameter')
    body = bodies[0]
    stmts = body.get('inner', [])
    if len(stmts) != 1 or stmts[0].get('kind') != 'ReturnStmt' or len(stmts[0].get('inner', [])) != 1:
        reject('E_BODY', 'single return expression required')
    ops: list[dict] = []
    def lower(node: object) -> str:
        if type(node) is not dict:
            reject('E_EXPR', 'invalid expression node')
        kind = node.get('kind')
        if kind in ('ImplicitCastExpr', 'ParenExpr'):
            if kind == 'ImplicitCastExpr' and node.get('castKind') != 'LValueToRValue':
                reject('E_CAST', 'implicit conversion outside safe scalar subset')
            inside=node.get('inner', [])
            if len(inside)!=1:
                reject('E_CAST', 'one operand required')
            return lower(inside[0])
        if kind == 'DeclRefExpr':
            name=node.get('referencedDecl', {}).get('name')
            if name not in names:
                reject('E_REF', 'not a function parameter')
            return name
        if kind == 'IntegerLiteral':
            try:
                value=int(node.get('value'))
            except (ValueError, TypeError):
                reject('E_LITERAL','invalid literal')
            if not 0<=value<=UINT32:
                reject('E_LITERAL','out of u32 range')
            ident='v'+str(len(ops))
            ops.append({'id':ident,'opcode':'const','value':value})
            return ident
        if kind == 'BinaryOperator':
            opcode=node.get('opcode')
            if opcode not in OPERATORS or node.get('type',{}).get('desugaredQualType',node.get('type',{}).get('qualType')) != 'unsigned int':
                reject('E_EXPR','unsupported operator or type')
            operands=node.get('inner', [])
            if len(operands)!=2:
                reject('E_EXPR','binary node must have two operands')
            left=lower(operands[0]); right=lower(operands[1])
            ident='v'+str(len(ops))
            ops.append({'id':ident,'opcode':OPERATORS[opcode],'args':[left,right]})
            return ident
        reject('E_EXPR', 'unsupported '+str(kind))
    result=lower(stmts[0]['inner'][0])
    program={'schema':SCHEMA,'name':function_name,
             'params':[{'name':x,'type':'u32'} for x in names],
             'ops':ops, 'result':result}
    return verify_scalar(program)

def verify_linear_resource(operations: object, max_live_bytes: int = 1_048_576) -> dict:
    """Finite straight-line owner/loan validator, NOT Rust lifetime soundness."""
    if type(operations) is not list or len(operations)>256 or type(max_live_bytes) is not int or max_live_bytes<0:
        reject('E_RESOURCE_BUDGET','bad resource program/budget')
    owners:dict[str,int]={}
    loans:dict[str,tuple[str,str]]={}
    all_ids:set[str]=set()
    peak=0
    for idx,op in enumerate(operations):
        if type(op) is not dict or 'op' not in op:
            reject('E_RESOURCE',f'bad record at {idx}')
        kind=op['op']
        allowed={'owner.new':{'op','id','bytes'}, 'owner.move':{'op','from','to'},
                 'borrow.read':{'op','owner','id'},'borrow.mut':{'op','owner','id'},
                 'loan.end':{'op','id'},'owner.drop':{'op','id'}}
        if kind not in allowed or set(op)!=allowed[kind]:
            reject('E_RESOURCE','unsupported or extra resource attributes')
        if kind=='owner.new':
            new=_ident(op['id'],'E_RESOURCE')
            size=op['bytes']
            if new in all_ids or type(size) is not int or size<0 or size>max_live_bytes:
                reject('E_RESOURCE','duplicate owner or invalid extent')
            all_ids.add(new)
            owners[new]=size
        elif kind=='owner.move':
            old=_ident(op['from'],'E_RESOURCE'); new=_ident(op['to'],'E_RESOURCE')
            if old not in owners or new in all_ids or any(v[0]==old for v in loans.values()):
                reject('E_RESOURCE','move invalid or has active loans')
            all_ids.add(new)
            owners[new]=owners.pop(old)
        elif kind in ('borrow.read','borrow.mut'):
            root=_ident(op['owner'],'E_RESOURCE'); name=_ident(op['id'],'E_RESOURCE')
            if root not in owners or name in all_ids:
                reject('E_RESOURCE','invalid borrow')
            if kind=='borrow.mut' and any(v[0]==root for v in loans.values()):
                reject('E_ALIAS','mutable borrow requires exclusivity')
            if kind=='borrow.read' and any(v==(root,'mut') for v in loans.values()):
                reject('E_ALIAS','read blocked by mutable loan')
            all_ids.add(name)
            loans[name]=(root,'mut' if kind=='borrow.mut' else 'read')
        elif kind=='loan.end':
            if op['id'] not in loans:
                reject('E_LOAN','loan missing or already ended')
            del loans[op['id']]
        else:
            owner=_ident(op['id'],'E_RESOURCE')
            if owner not in owners or any(v[0]==owner for v in loans.values()):
                reject('E_RESOURCE','invalid drop or live loans')
            del owners[owner]
        live=sum(owners.values())
        peak=max(peak,live)
        if live>max_live_bytes:
            reject('E_RESOURCE_BUDGET','live heap budget exceeded')
    if owners or loans:
        reject('E_LEAK','unclosed owners/loans')
    return {'profile':'straight_line_owned_bytes.v1', 'peak_payload_bytes':peak,
            'source_digest':identity(operations),'authority':'DENY_ALL',
            'excluded':['allocator_metadata','rss','host_crash','ffi','async_cancel','threads']}
