"""HIA owner of CPython 3.12.14 CALL adaptive and instrumented dispatch.

New, unexecuted rebuild source. The actual opcode/counter, function version
and primitive facts are observed from the original instruction and stack.
HIA chooses every specialization, cache write and re-dispatch; the raw port
does not call _Py_Specialize_Call. A successful dispatch ticket is neither
a Python result nor permission to return from an active evaluator frame.

The complete Py_STATS profile, fast-call bodies and retaining driver are
separate admission obligations. The original 17/46 population is unchanged.
"""
from __future__ import annotations
import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLICD01', 'little'),
    'PACKET_MAGIC': int.from_bytes(b'HCLIBC31', 'little'), 'ABI': 4294967293,
    'PHASE': 8, 'SEQ': 16, 'PENDING': 24, 'ACKSEQ': 32, 'ACKOP': 40,
    'RAISED': 48, 'OP': 64, 'FINAL': 112,
    'MODE': 120, 'COUNTER': 128, 'NARGS': 136, 'KW': 144, 'OPARG': 152,
    'KIND': 160, 'NEXTMODE': 168, 'NEXTCOUNTER': 176, 'ARGCOUNT': 184,
    'BOUND': 192, 'FORCE_CALL': 200, 'INSTRUMENTED': 208,
    'VERSION': 216, 'PYARGS': 224, 'ANSWER': 256,
    'GEN': 384, 'CODE': 392, 'PC': 400,
    'CALL': 171, 'INSTRUMENTED_CALL': 241,
    'PY_EXACT': 23, 'PY_DEFAULTS': 24, 'BOUND_EXACT': 28,
    'BUILTIN_CLASS': 29, 'BUILTIN_FAST_KW': 34, 'DESCR_FAST_KW': 38,
    'BUILTIN_FAST': 39, 'BUILTIN_O': 40, 'ISINSTANCE': 41, 'LEN': 42,
    'LIST_APPEND': 43, 'DESCR_FAST': 44, 'DESCR_NOARGS': 45, 'DESCR_O': 46,
    'STR_ONE': 47, 'TUPLE_ONE': 48, 'TYPE_ONE': 56,
}

SOURCE = r'''
def cli_json_py312_call_dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 512 or get(w,0) != MAGIC or get(w,FINAL) != 0:
        return ABI
    if length(s) < 64 or read(s,0) != PACKET_MAGIC or read(s,8) != 31214:
        return ABI
    units = read(s,16)
    pc = get(w,PC)
    if units == 0 or units > 288230376151711742 or length(s) != 64 + units * 64 or pc >= units:
        return ABI
    at = 64 + pc * 64
    if get(w,GEN) == 0 or get(w,CODE) == 0 or read(s,at) != CALL or read(s,at+56) != 1:
        return ABI
    if get(w,PENDING) != 0:
        if get(w,ACKSEQ) != get(w,SEQ) or get(w,ACKOP) != get(w,OP):
            return ABI
        put(w,PENDING,0)
    elif get(w,PHASE) != 0:
        return ABI
    if get(w,PHASE) == 0:
        if get(w,SEQ) != 0 or get(w,RAISED) != 0 or get(w,FORCE_CALL) > 1:
            return ABI
        return request(w,1,0,1)
    while True:
        phase = get(w,PHASE)
        if phase == 1 or phase == 10:
            status = observed(w,phase)
        elif phase == 2 or phase == 11:
            status = monitored(w,phase)
        elif phase == 3:
            status = specialize(w)
        elif phase == 4 or phase == 5:
            status = versioned(w,phase)
        elif phase == 6:
            status = request(w,7,get(w,NEXTCOUNTER),7)
        elif phase == 7:
            put(w,FORCE_CALL,0)
            put(w,INSTRUMENTED,0)
            status = request(w,1,0,1)
        elif phase == 8:
            put(w,FINAL,1)
            return 0
        else:
            return ABI
        if status != 4:
            return status
    return ABI

def observed(w:mutbuf, phase:u64) -> u64:
    if get(w,RAISED) != 0 or answer(w,0) > 255 or answer(w,1) > 65535 or answer(w,2) > 2147483647 or answer(w,3) > 1 or answer(w,4) > 255:
        return ABI
    put(w,MODE,answer(w,0))
    put(w,COUNTER,answer(w,1))
    put(w,NARGS,answer(w,2))
    put(w,KW,answer(w,3))
    put(w,OPARG,answer(w,4))
    if phase == 10:
        # INCREMENT_ADAPTIVE_COUNTER operates on the cache AFTER the
        # monitor callback, including its original uint16 wrap.
        return request(w,7,(get(w,COUNTER)+16)&65535,11)
    mode = get(w,MODE)
    if get(w,FORCE_CALL) != 0:
        mode = CALL
    elif mode == INSTRUMENTED_CALL:
        return request(w,2,0,2)
    if mode != CALL:
        if fast_opcode(mode) == 0:
            return ABI
        put(w,FINAL,3)
        return 3
    if (get(w,COUNTER)>>4) != 0:
        return request(w,7,get(w,COUNTER)-16,8)
    return request(w,3,0,3)

def monitored(w:mutbuf, phase:u64) -> u64:
    if phase == 2:
        if get(w,RAISED) != 0:
            if answer(w,0) == 0:
                return ABI
            put(w,FINAL,2)
            return 1
        if answer(w,0) != 0:
            return ABI
        put(w,INSTRUMENTED,1)
        return request(w,1,0,10)
    if get(w,RAISED) != 0:
        return ABI
    put(w,FORCE_CALL,1)
    return request(w,1,0,1)

def specialize(w:mutbuf) -> u64:
    if get(w,RAISED) != 0:
        return ABI
    kind = answer(w,0)
    put(w,KIND,kind)
    if kind == 1:
        return c_function(w)
    if kind == 2:
        return py_function(w)
    if kind == 3:
        return class_call(w)
    if kind == 4:
        return descriptor(w)
    if kind != 0:
        return ABI
    return failed(w)

def c_function(w:mutbuf) -> u64:
    if answer(w,1) > 1 or answer(w,3) > 1 or answer(w,4) > 1:
        return ABI
    if answer(w,1) == 0:
        return failed(w)
    flags = answer(w,2)
    if flags == 8:
        if get(w,KW) != 0 or get(w,NARGS) != 1:
            return failed(w)
        if answer(w,3) != 0:
            return selected(w,LEN)
        return selected(w,BUILTIN_O)
    if flags == 128:
        if get(w,KW) != 0:
            return failed(w)
        if get(w,NARGS) == 2 and answer(w,4) != 0:
            return selected(w,ISINSTANCE)
        return selected(w,BUILTIN_FAST)
    if flags == 130:
        return selected(w,BUILTIN_FAST_KW)
    return failed(w)

def py_function(w:mutbuf) -> u64:
    flags = answer(w,1)
    argcount = answer(w,3)
    defcount = answer(w,4)
    bound = answer(w,6)
    nargs = answer(w,7)
    if answer(w,5) > 1 or bound > 1 or argcount > 2147483647 or defcount > 2147483647 or nargs > 2147483647:
        return ABI
    # function_kind does NOT reject CO_GENERATOR. Only complex parameters
    # and a non-optimized frame make the original function non-simple.
    if answer(w,5) == 0 or get(w,KW) != 0 or (flags&12) != 0 or answer(w,2) != 0 or (flags&1) == 0:
        return failed(w)
    if defcount > argcount or nargs > argcount or nargs < argcount-defcount:
        return failed(w)
    put(w,ARGCOUNT,argcount)
    put(w,PYARGS,nargs)
    put(w,BOUND,bound)
    return request(w,4,0,4)

def versioned(w:mutbuf, phase:u64) -> u64:
    if get(w,RAISED) != 0:
        return ABI
    if phase == 4:
        version = answer(w,0)
        if version > 4294967295:
            return ABI
        if version == 0:
            return failed(w)
        put(w,VERSION,version)
        # The original writes func_version BEFORE discovering that a
        # bound-method call would need defaults. Preserve that failed write.
        return request(w,5,version,5)
    if get(w,ARGCOUNT) == get(w,PYARGS):
        if get(w,BOUND) != 0:
            return selected(w,BOUND_EXACT)
        return selected(w,PY_EXACT)
    if get(w,BOUND) != 0:
        return failed(w)
    return selected(w,PY_DEFAULTS)

def class_call(w:mutbuf) -> u64:
    if answer(w,1) > 1 or answer(w,2) > 1 or answer(w,3) > 3 or answer(w,4) > 1:
        return ABI
    if answer(w,1) != 0 or answer(w,2) == 0:
        return failed(w)
    if get(w,NARGS) == 1 and get(w,KW) == 0 and get(w,OPARG) == 1:
        identity = answer(w,3)
        if identity == 1:
            return selected(w,STR_ONE)
        if identity == 2:
            return selected(w,TYPE_ONE)
        if identity == 3:
            return selected(w,TUPLE_ONE)
    if answer(w,4) != 0:
        return selected(w,BUILTIN_CLASS)
    return failed(w)

def descriptor(w:mutbuf) -> u64:
    if get(w,KW) != 0:
        return failed(w)
    flags = answer(w,1)
    if flags == 4:
        if get(w,NARGS) != 1:
            return failed(w)
        return selected(w,DESCR_NOARGS)
    if flags == 8:
        if get(w,NARGS) != 2:
            return failed(w)
        if answer(w,2) > 1 or answer(w,3) > 1:
            return ABI
        if answer(w,2) != 0 and get(w,OPARG) == 1 and answer(w,3) != 0:
            return selected(w,LIST_APPEND)
        return selected(w,DESCR_O)
    if flags == 128:
        return selected(w,DESCR_FAST)
    if flags == 130:
        return selected(w,DESCR_FAST_KW)
    return failed(w)

def failed(w:mutbuf) -> u64:
    backoff = (get(w,COUNTER)&15)+1
    if backoff > 12:
        backoff = 12
    put(w,NEXTMODE,CALL)
    put(w,NEXTCOUNTER,(((1<<backoff)-1)<<4)|backoff)
    return request(w,6,CALL,6)

def selected(w:mutbuf, mode:u64) -> u64:
    if fast_opcode(mode) == 0:
        return ABI
    put(w,NEXTMODE,mode)
    put(w,NEXTCOUNTER,832)
    return request(w,6,mode,6)

def fast_opcode(mode:u64) -> u64:
    if mode == PY_EXACT or mode == PY_DEFAULTS or mode == BOUND_EXACT or mode == BUILTIN_CLASS or mode == BUILTIN_FAST_KW or mode == DESCR_FAST_KW:
        return 1
    if mode >= BUILTIN_FAST and mode <= TUPLE_ONE:
        return 1
    if mode == TYPE_ONE:
        return 1
    return 0

def answer(w:mutbuf, index:u64) -> u64:
    return get(w,ANSWER+index*8)

def request(w:mutbuf, op:u64, arg:u64, phase:u64) -> u64:
    seq = get(w,SEQ)
    if seq == 18446744073709551615:
        return ABI
    put(w,SEQ,seq+1)
    put(w,PENDING,1)
    put(w,OP,op)
    put(w,72,arg)
    put(w,80,0)
    put(w,88,0)
    put(w,96,0)
    put(w,104,0)
    put(w,PHASE,phase)
    return 2

WORD_HELPERS
'''

def source_program():
    helpers = []
    for name, kind in (('read', 'readbuf'), ('get', 'mutbuf')):
        helpers += [f'def {name}(s:{kind}, at:u64) -> u64:', '    value = 0']
        for i in range(8):
            helpers.append(f'    value = value | (byte(s, at + {i}) << {i*8})')
        helpers.append('    return value')
    helpers.append('def put(w:mutbuf, at:u64, value:u64) -> u64:')
    for i in range(8):
        helpers.append(f'    store(w, at + {i}, value >> {i*8})')
    helpers.append('    return 0')
    source = SOURCE.replace('WORD_HELPERS', '\n'.join(helpers))
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]), node)
            return node
    return ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(source))))+'\n'

def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source_program()).body
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures = {node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns], 'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8',
                                  'module':'cli_json_py312_call_dispatch','functions':functions})

if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
