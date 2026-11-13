"""HIA plans for the original CPython 3.12.14 specialized CALL families.

Unexecuted isolated source. Each family retains its own guards, reference
release order, early-error stack and eval-breaker choice. A failed guard
requests the original CALL continuation without changing the actual opcode.
Python child frames still require the same-C-entry owner; no EvalFrame
fallback or additional protective object reference is introduced.
"""
from __future__ import annotations
import ast
from pathlib import Path

SYMBOLS = {
    'MAGIC':int.from_bytes(b'HCLICL01','little'), 'FAST_MAGIC':int.from_bytes(b'HCLICF01','little'),
    'PACKET_MAGIC':int.from_bytes(b'HCLIBC31','little'), 'ABI':4294967293,
    'PHASE':8,'SEQ':16,'PENDING':24,'ACKSEQ':32,'ACKOP':40,'RAISED':48,'RESULT':56,
    'OP':64,'FINAL':112,'GEN':120,'CODE':128,'PC':136,'OPARG':144,'KWNAMES':152,
    'TOP':160,'BASE':168,'CALLABLE':176,'ARGBASE':184,'TOTAL':192,'KWCOUNT':200,
    'IS_METHOD':208,'ROUTE':216,'INDEX':224,'CHILD':232,'INSTRUMENTED':240,'MODE':248,
    'ANSWER':256,'EXT_MAGIC':512,'ARGCOUNT':520,'DEFCOUNT':528,'MINARGS':536,
    'DROP_ORDER':544,'BREAK':552,'SCALAR':560,'C_RECURSIVE':568,'NEXT':576,
    'PY_EXACT':23,'PY_DEFAULTS':24,'BOUND_EXACT':28,'BUILTIN_CLASS':29,
    'BUILTIN_FAST_KW':34,'DESCR_FAST_KW':38,'BUILTIN_FAST':39,'BUILTIN_O':40,
    'ISINSTANCE':41,'LEN':42,'LIST_APPEND':43,'DESCR_FAST':44,'DESCR_NOARGS':45,
    'DESCR_O':46,'STR_ONE':47,'TUPLE_ONE':48,'TYPE_ONE':56,
}

SOURCE=r'''
def cli_json_py312_call_fast(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 1024 or get(w,0) != MAGIC or get(w,EXT_MAGIC) != FAST_MAGIC or get(w,FINAL) != 0:
        return ABI
    if length(s) < 64 or read(s,0) != PACKET_MAGIC or read(s,8) != 31214:
        return ABI
    units = read(s,16)
    pc = get(w,PC)
    if units == 0 or units > 288230376151711742 or length(s) != 64 + units*64 or pc >= units:
        return ABI
    at = 64 + pc*64
    if read(s,at) != 171 or read(s,at+8) != get(w,OPARG) or read(s,at+56) != 1 or get(w,GEN) == 0 or get(w,CODE) == 0:
        return ABI
    if get(w,PENDING) != 0:
        if get(w,ACKSEQ) != get(w,SEQ) or get(w,ACKOP) != get(w,OP):
            return ABI
        put(w,PENDING,0)
    elif get(w,PHASE) != 0:
        return ABI
    if get(w,PHASE) == 0:
        if get(w,SEQ) != 0 or get(w,RAISED) != 0 or get(w,RESULT) != 0 or get(w,INSTRUMENTED) != 0:
            return ABI
        return request(w,100,0,0,100)
    while True:
        phase = get(w,PHASE)
        if phase == 6:
            return child_done(w)
        if phase < 110:
            status = guards(w,phase)
        elif phase < 130:
            status = python_frame(w,phase)
        elif phase < 150:
            status = primitive(w,phase)
        else:
            status = cleanup(w,phase)
        if status != 4 or get(w,FINAL) != 0:
            return status
    return ABI

def guards(w:mutbuf, phase:u64) -> u64:
    if get(w,RAISED) != 0 or get(w,RESULT) != 0:
        return ABI
    if phase == 100:
        top = answer(w,0)
        base = answer(w,1)
        total = answer(w,4)
        if top > 2147483647 or base > top or top-base != get(w,OPARG)+2 or answer(w,3) > top or top-answer(w,3) != total or answer(w,5) > total or answer(w,6) > 1:
            return ABI
        put(w,TOP,top)
        put(w,BASE,base)
        put(w,CALLABLE,answer(w,2))
        put(w,ARGBASE,answer(w,3))
        put(w,TOTAL,total)
        put(w,KWCOUNT,answer(w,5))
        put(w,IS_METHOD,answer(w,6))
        return request(w,101,0,0,101)
    if phase == 101:
        mode = get(w,MODE)
        if mode == BOUND_EXACT:
            if answer(w,0) != 0 or answer(w,1) != 1:
                return request(w,112,0,0,109)
            return request(w,102,0,0,102)
        if mode == PY_EXACT or mode == PY_DEFAULTS:
            return py_guard(w,mode)
        return foreign_guard(w,mode)
    if phase == 102:
        if answer(w,6) != 1 or answer(w,4) != get(w,TOTAL)+1 or answer(w,0) != get(w,TOP):
            return ABI
        put(w,CALLABLE,answer(w,2))
        put(w,ARGBASE,answer(w,3))
        put(w,TOTAL,answer(w,4))
        put(w,IS_METHOD,1)
        put(w,MODE,PY_EXACT)
        return request(w,101,0,0,101)
    if phase == 109:
        if answer(w,0) != get(w,TOP):
            return ABI
        put(w,FINAL,3)
        return 3
    return ABI

def py_guard(w:mutbuf, mode:u64) -> u64:
    if get(w,KWNAMES) != 0:
        return ABI
    # Fields are guarded raw facts; no borrowed PyFunction is dereferenced
    # by HIA. The original guard order stops before frame allocation.
    if answer(w,0) != 1 or answer(w,1) != 1 or answer(w,2) != answer(w,3):
        return request(w,112,0,0,109)
    argcount = answer(w,4)
    total = get(w,TOTAL)
    defaults = answer(w,7)
    if argcount > 2147483647 or defaults > argcount or answer(w,5) != total:
        return ABI
    if mode == PY_EXACT:
        if argcount != total:
            return request(w,112,0,0,109)
    elif total > argcount or total < argcount-defaults:
        return request(w,112,0,0,109)
    if answer(w,6) != 1:
        return request(w,112,0,0,109)
    put(w,ARGCOUNT,argcount)
    put(w,DEFCOUNT,defaults)
    put(w,MINARGS,argcount-defaults)
    put(w,ROUTE,1)
    return request(w,103,argcount,0,110)

def python_frame(w:mutbuf, phase:u64) -> u64:
    if get(w,ROUTE) != 1 or get(w,RAISED) != 0 or get(w,RESULT) != 0:
        return ABI
    if phase == 110:
        if answer(w,0) == 0 or answer(w,1) != get(w,ARGCOUNT):
            return ABI
        put(w,CHILD,answer(w,0))
        put(w,INDEX,0)
        put(w,PHASE,111)
        return 4
    if phase == 111:
        index = get(w,INDEX)
        if index < get(w,TOTAL):
            return request(w,104,index,0,112)
        if index < get(w,ARGCOUNT):
            return request(w,105,index,index-get(w,MINARGS),113)
        if index != get(w,ARGCOUNT):
            return ABI
        return request(w,106,get(w,BASE),0,114)
    if phase == 112 or phase == 113:
        index = get(w,INDEX)+1
        if answer(w,0) != index:
            return ABI
        put(w,INDEX,index)
        put(w,PHASE,111)
        return 4
    if phase == 114:
        if answer(w,0) != get(w,BASE):
            return ABI
        # Same actual-child permission as the generic binder route.
        return request(w,9,get(w,CHILD),0,6)
    return ABI

def foreign_guard(w:mutbuf, mode:u64) -> u64:
    if answer(w,0) > 1 or answer(w,2) > 1 or answer(w,4) > 1 or answer(w,6) > 1:
        return ABI
    if answer(w,3) != get(w,TOTAL) or answer(w,4) != get(w,IS_METHOD):
        return ABI
    valid = answer(w,0) == 1
    if mode == TYPE_ONE or mode == STR_ONE or mode == TUPLE_ONE:
        if get(w,KWNAMES) != 0 or get(w,OPARG) != 1:
            return ABI
        valid = valid and get(w,IS_METHOD) == 0
    elif mode == BUILTIN_CLASS:
        valid = valid and answer(w,6) == 1
    elif mode == BUILTIN_O:
        if get(w,KWNAMES) != 0:
            return ABI
        valid = valid and get(w,TOTAL) == 1 and answer(w,1) == 8
    elif mode == BUILTIN_FAST or mode == BUILTIN_FAST_KW:
        if mode == BUILTIN_FAST and get(w,KWNAMES) != 0:
            return ABI
        flags = 128
        if mode == BUILTIN_FAST_KW:
            flags = 130
        valid = valid and answer(w,1) == flags
    elif mode == LEN or mode == ISINSTANCE:
        if get(w,KWNAMES) != 0:
            return ABI
        count = 1
        if mode == ISINSTANCE:
            count = 2
        valid = valid and get(w,TOTAL) == count
    elif mode == LIST_APPEND:
        if get(w,KWNAMES) != 0 or get(w,OPARG) != 1:
            return ABI
        valid = valid and answer(w,2) == 1
    elif mode == DESCR_O or mode == DESCR_NOARGS or mode == DESCR_FAST or mode == DESCR_FAST_KW:
        if mode != DESCR_FAST_KW and get(w,KWNAMES) != 0:
            return ABI
        flags = 128
        if mode == DESCR_O:
            flags = 8
            valid = valid and get(w,TOTAL) == 2
        elif mode == DESCR_NOARGS:
            flags = 4
            valid = valid and get(w,TOTAL) == 1
        elif mode == DESCR_FAST_KW:
            flags = 130
        valid = valid and answer(w,1) == flags and answer(w,2) == 1
    else:
        return ABI
    if valid == False:
        return request(w,112,0,0,109)
    put(w,ROUTE,2)
    put(w,DROP_ORDER,1)
    put(w,BREAK,1)
    put(w,C_RECURSIVE,0)
    if mode == TYPE_ONE or mode == LEN or mode == ISINSTANCE or mode == LIST_APPEND:
        put(w,BREAK,0)
    if mode == LEN:
        put(w,DROP_ORDER,0)
    if mode == BUILTIN_O or mode == DESCR_O or mode == DESCR_NOARGS:
        return request(w,108,0,0,130)
    return request(w,107,mode,0,131)

def primitive(w:mutbuf, phase:u64) -> u64:
    if get(w,ROUTE) != 2:
        return ABI
    if phase == 130:
        if answer(w,0) != 0:
            if get(w,RAISED) == 0 or get(w,RESULT) != 0:
                return ABI
            return request(w,114,get(w,TOP),0,148)
        if get(w,RAISED) != 0 or get(w,RESULT) != 0:
            return ABI
        put(w,C_RECURSIVE,1)
        return request(w,107,get(w,MODE),0,131)
    if phase == 131:
        mode = get(w,MODE)
        if get(w,C_RECURSIVE) != 0:
            return request(w,109,0,0,132)
        if mode == LEN or mode == ISINSTANCE:
            if (answer(w,0)>>63) != 0:
                if get(w,RAISED) == 0 or get(w,RESULT) != 0:
                    return ABI
                return request(w,114,get(w,TOP),0,148)
            if get(w,RAISED) != 0 or get(w,RESULT) != 0:
                return ABI
            put(w,SCALAR,answer(w,0))
            if mode == LEN:
                return request(w,116,get(w,SCALAR),0,132)
            return request(w,117,get(w,SCALAR),0,132)
        if mode == LIST_APPEND:
            if answer(w,0) != 0:
                if get(w,RAISED) == 0 or get(w,RESULT) != 0:
                    return ABI
                return request(w,114,get(w,TOP)-1,0,148)
            if get(w,RAISED) != 0 or get(w,RESULT) != 0:
                return ABI
            # AppendTakeRef already consumed args[1]. Release self, then
            # method, and skip the original following POP_TOP entirely.
            return request(w,110,0,0,145)
        return begin_cleanup(w)
    if phase == 132:
        put(w,C_RECURSIVE,0)
        return begin_cleanup(w)
    if phase == 145:
        return request(w,111,0,0,146)
    if phase == 146:
        return request(w,106,get(w,BASE),0,147)
    if phase == 147:
        if get(w,RAISED) != 0 or get(w,RESULT) != 0 or answer(w,0) != get(w,BASE):
            return ABI
        put(w,NEXT,get(w,PC)+5)
        put(w,FINAL,4)
        return 4
    if phase == 148:
        if get(w,RAISED) == 0 or get(w,RESULT) != 0:
            return ABI
        put(w,FINAL,2)
        return 1
    return ABI

def begin_cleanup(w:mutbuf) -> u64:
    if (get(w,RESULT) == 0) == (get(w,RAISED) == 0):
        return ABI
    put(w,INDEX,0)
    if get(w,DROP_ORDER) == 0:
        return request(w,111,0,0,150)
    put(w,PHASE,151)
    return 4

def cleanup(w:mutbuf, phase:u64) -> u64:
    if phase == 150:
        put(w,PHASE,151)
        return 4
    if phase == 151:
        index = get(w,INDEX)
        if index < get(w,TOTAL):
            return request(w,110,index,0,152)
        if index != get(w,TOTAL):
            return ABI
        if get(w,DROP_ORDER) != 0:
            return request(w,111,0,0,153)
        return request(w,106,get(w,BASE),0,154)
    if phase == 152:
        put(w,INDEX,get(w,INDEX)+1)
        put(w,PHASE,151)
        return 4
    if phase == 153:
        return request(w,106,get(w,BASE),0,154)
    if phase == 154:
        if answer(w,0) != get(w,BASE):
            return ABI
        return request(w,113,0,0,155)
    if phase == 155:
        if get(w,RESULT) == 0:
            if get(w,RAISED) == 0:
                return ABI
            put(w,FINAL,2)
            return 1
        if get(w,RAISED) != 0:
            return ABI
        put(w,FINAL,1)
        return 0
    return ABI

def child_done(w:mutbuf) -> u64:
    if get(w,ROUTE) != 1:
        return ABI
    if answer(w,0) == 1:
        if get(w,RAISED) == 0 or get(w,RESULT) != 0 or answer(w,3) != 1:
            return ABI
        put(w,FINAL,2)
        return 1
    if answer(w,0) != 0 or get(w,RAISED) != 0 or get(w,RESULT) == 0 or answer(w,3) != 0:
        return ABI
    put(w,FINAL,1)
    return 0

def answer(w:mutbuf, index:u64) -> u64:
    return get(w,ANSWER+index*8)

def request(w:mutbuf, op:u64, a:u64, b:u64, phase:u64) -> u64:
    seq = get(w,SEQ)
    if seq == 18446744073709551615:
        return ABI
    put(w,SEQ,seq+1)
    put(w,PENDING,1)
    put(w,OP,op)
    put(w,72,a)
    put(w,80,b)
    put(w,88,0)
    put(w,96,0)
    put(w,104,0)
    put(w,PHASE,phase)
    return 2

WORD_HELPERS
'''

def source_program():
    helpers=[]
    for name,kind in (('read','readbuf'),('get','mutbuf')):
        helpers += [f'def {name}(s:{kind}, at:u64) -> u64:','    value = 0']
        for i in range(8):
            helpers.append(f'    value = value | (byte(s, at + {i}) << {i*8})')
        helpers.append('    return value')
    helpers.append('def put(w:mutbuf, at:u64, value:u64) -> u64:')
    for i in range(8):
        helpers.append(f'    store(w, at + {i}, value >> {i*8})')
    helpers.append('    return 0')
    source=SOURCE.replace('WORD_HELPERS','\n'.join(helpers))
    class Constants(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in SYMBOLS:
                return ast.copy_location(ast.Constant(SYMBOLS[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Constants().visit(ast.parse(source))))+'\n'

def document():
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'cli_json_py312_call_fast','functions':functions})

if __name__=='__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
