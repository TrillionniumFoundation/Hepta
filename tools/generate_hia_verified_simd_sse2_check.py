"""Author the independent closed SSE2 final-text checker.

Input is the HIA ELF binder's receipt for the actual object, shared image and
export. Register operands, packed operations, all memory offsets and every
branch destination are recovered from its linked text. The accepted grammar
is the forward-byte induction with four-vector, one-vector, and one-byte steps.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_shared_linker import document
from tools.generate_hia_elf_linker import SOURCE as ELF

MODULE = 'verified_simd_sse2_check'
OPS = ('mark','imm','mov','cmp','test','add','or','pxor','por','sad','paddq','load128',
       'store128','sete','shiftbytes','extract','load8','store8','ret','cmpi','addi','subi',
       'branch','jump','call','ud2')
NAMES = {name:i+1 for i,name in enumerate(OPS)}
LABELS = {name:i for i,name in enumerate(('admitted','bulk','postbulk','vector','horizontal','tail','return','abort'))}

def schedule(kind):
    """Rows express the live registers and memory accesses required at each induction step."""
    rows = []
    def inst(op, *args):
        rows.append((NAMES[op], *args, *([0]*(3-len(args)))))
    def mark(label):
        inst('mark',LABELS[label])
    def branch(cond,label):
        inst('branch',cond,LABELS[label])
    def jump(label):
        inst('jump',LABELS[label])
    copy = kind == 3
    if copy:
        inst('mov',0,8)
        for extent in (6,1):
            inst('cmp',8,extent)
            branch(7,'abort')
        inst('test',8,8)
        branch(4,'return')
        for ptr,end in ((7,9),(2,10)):
            inst('test',ptr,ptr)
            branch(4,'abort')
            inst('mov',end,ptr)
            inst('add',end,8)
            branch(2,'abort')
        inst('cmp',9,2)
        branch(6,'admitted')
        inst('cmp',10,7)
        branch(7,'abort')
        mark('admitted')
        inst('mov',10,8)
    else:
        inst('imm',0,0)
        inst('cmp',2,6)
        branch(7,'abort')
        inst('test',2,2)
        branch(4,'return')
        inst('test',7,7)
        branch(4,'abort')
        inst('mov',9,7)
        inst('add',9,2)
        branch(2,'abort')
        inst('mov',10,2)
        for r in ((0,2,3,4,5) if kind==2 else (0,2)):
            inst('pxor',r,r)
    def advance(n):
        inst('addi',7,n)
        if copy:
            inst('addi',2,n)
        inst('subi',10,n)
    for label,chunk,nxt in (('bulk',64,'postbulk'),('vector',16,'horizontal')):
        mark(label)
        inst('cmpi',10,chunk)
        branch(2,nxt)
        for offset in range(0,chunk,16):
            inst('load128',1,2 if copy else 7,offset)
            if copy:
                inst('store128',1,7,offset)
            elif kind==1:
                inst('sad',1,2)
                inst('paddq',0,1)
            else:
                inst('por',(0,3,4,5)[offset//16],1)
        advance(chunk)
        jump(label)
        if label=='bulk':
            mark('postbulk')
            if kind==2:
                for r in (3,4,5):
                    inst('por',0,r)
    mark('horizontal')
    combine='add' if kind==1 else 'or'
    if not copy:
        inst('extract',0,0)
        inst('shiftbytes',0,8)
        inst('extract',9,0)
        inst(combine,0,9)
    mark('tail')
    inst('test',10,10)
    branch(4,'return')
    inst('load8',9,2 if copy else 7,0)
    if copy:
        inst('store8',9,7,0)
    else:
        inst(combine,0,9)
    advance(1)
    jump('tail')
    mark('return')
    if kind==2:
        inst('test',0,0)
        inst('imm',0,0)
        inst('sete',0)
    inst('ret')
    mark('abort')
    inst('subi',4,8)
    inst('call')
    inst('ud2')
    return rows

POLICY = '''
def validate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 168 or length(o) < 32 or length(w) < 2048:
        return 0
    shape = uint(s, 0, 8)
    if shape < 1 or shape > 3 or uint(s, 8, 8) != BIND_REPLY:
        return 0
    span = uint(s, 32, 8)
    if span == 0 or span > 2048 or length(s) != 88 + span + 56:
        return 0
    if uint(s, 40, 8) != 0 or uint(s, 48, 8) != 0 or uint(s, 64, 8) != 1 or uint(s, 72, 8) != 56 or uint(s, 80, 8) != 0:
        return 0
    record = 88 + span
    if uint(s, record, 8) != 0 or uint(s, record + 8, 8) != 1 or uint(s, record + 16, 8) != 0:
        return 0
    if uint(s, record + 32, 8) != 1 or uint(s, record + 40, 8) != uint(s, 56, 8):
        return 0
    put(w, 0, 88)
    put(w, 8, record)
    put(w, 16, 0)
    rows = specification(w, shape)
    i = 0
    while i < rows:
        row = get(w, 1024 + i * 4) & 4294967295
        op = row & 255
        a = (row >> 8) & 255
        b = (row >> 16) & 255
        pos = get(w, 0)
        if op == OP_MARK:
            put(w, 64 + a * 8, pos)
        else:
            actual = decode(s, w)
            if actual == 0:
                return 0
            if op == OP_BRANCH or op == OP_JUMP:
                required = choose(op == OP_BRANCH, token(op, a, 0, 0), op)
                if actual != required:
                    return 0
                n = get(w, 16)
                put(w, 192 + n * 16, get(w, 24))
                put(w, 200 + n * 16, choose(op == OP_BRANCH, b, a))
                put(w, 16, n + 1)
            else:
                if actual != row:
                    return 0
                if op == OP_CALL:
                    if uint(s, record + 24, 8) != pos - 88 + 1:
                        return 0
                    disp = get(w, 32)
                    if uint(s, record + 48, 8) != disp:
                        return 0
                    if uint(s, 24, 8) + pos - 88 + 5 + disp != uint(s, 56, 8):
                        return 0
        i = i + 1
    if get(w, 0) != record:
        return 0
    i = 0
    while i < get(w, 16):
        if get(w, 192 + i * 16) != get(w, 64 + get(w, 200 + i * 16) * 8):
            return 0
        i = i + 1
    put(o, 0, SUCCESS)
    put(o, 8, shape)
    put(o, 16, 1)
    put(o, 24, span)
    return 32

def decode(s:readbuf, w:mutbuf) -> u64:
    p = get(w, 0)
    end = get(w, 8)
    if p >= end:
        return 0
    first = byte(s, p)
    if first == 195:
        put(w, 0, p + 1)
        return OP_RET
    if first == 184:
        if end - p < 5 or uint(s, p + 1, 4) != 0:
            return 0
        put(w, 0, p + 5)
        return OP_IMM
    if first == 232 or first == 233:
        if end - p < 5:
            return 0
        relative(s, w, p + 1)
        return choose(first == 232, OP_CALL, OP_JUMP)
    if end - p < 2:
        return 0
    second = byte(s, p + 1)
    if first == 15:
        if second == 11:
            put(w, 0, p + 2)
            return OP_UD2
        if second < 128 or second > 143 or end - p < 6:
            return 0
        relative(s, w, p + 2)
        return token(OP_BRANCH, second - 128, 0, 0)
    if first == 102 or first == 243:
        return packed_op(s, w, p, end)
    if first < 64 or first > 79 or (first & 2) != 0 or end - p < 3:
        return 0
    off = 2
    if second == 15:
        if end - p < 4:
            return 0
        off = 3
    modrm = byte(s, p + off)
    mod = modrm >> 6
    src = ((modrm >> 3) & 7) + ((first & 4) << 1)
    dst = (modrm & 7) + ((first & 1) << 3)
    put(w, 0, p + off + 1)
    if second == 136 or second == 15:
        if second == 15 and byte(s, p + 2) == 148:
            if first == 64 and mod == 3 and src == 0:
                return token(OP_SETE, dst, 0, 0)
            return 0
        if mod != 2 or (dst & 7) == 4 or end - p < off + 5:
            return 0
        disp = uint(s, p + off + 1, 4)
        if disp != 0:
            return 0
        put(w, 0, p + off + 5)
        if second == 136 and (first & 8) == 0:
            return token(OP_STORE8, src, dst, 0)
        if second == 15 and (first & 8) != 0 and byte(s, p + 2) == 182:
            return token(OP_LOAD8, src, dst, 0)
        return 0
    if mod != 3 or (first & 8) == 0:
        return 0
    if second == 131:
        if end - p < 4 or (first & 4) != 0:
            return 0
        imm = byte(s, p + 3)
        if imm >= 128:
            return 0
        put(w, 0, p + 4)
        op = choose(src == 0, OP_ADDI, choose(src == 5, OP_SUBI, choose(src == 7, OP_CMPI, 0)))
    else:
        op = choose(second == 137, OP_MOV, choose(second == 57, OP_CMP, choose(second == 133, OP_TEST, choose(second == 1, OP_ADD, choose(second == 9, OP_OR, 0)))))
        imm = src
    if op == 0:
        return 0
    return token(op, dst, imm, 0)

def packed_op(s:readbuf, w:mutbuf, p:u64, end:u64) -> u64:
    if end - p < 4:
        return 0
    first = byte(s, p)
    rex = 0
    start = p + 1
    if byte(s, start) == 72 or byte(s, start) == 73:
        rex = byte(s, start)
        start = start + 1
    if end - start < 3 or byte(s, start) != 15:
        return 0
    op = byte(s, start + 1)
    rm = byte(s, start + 2)
    mod = rm >> 6
    reg = (rm >> 3) & 7
    base = rm & 7
    next = start + 3
    put(w, 0, next)
    if first == 243:
        if rex != 0 or (op != 111 and op != 127) or mod > 1 or (base != 7 and base != 2):
            return 0
        disp = 0
        if mod == 1:
            if next == end or byte(s, next) >= 128:
                return 0
            disp = byte(s, next)
            put(w, 0, next + 1)
        return token(choose(op == 111, OP_LOAD128, OP_STORE128), reg, base, disp)
    if mod != 3:
        return 0
    if op == 126 and rex != 0:
        return token(OP_EXTRACT, base + ((rex & 1) << 3), reg, 0)
    if rex != 0:
        return 0
    if op == 115 and reg == 3:
        if next == end:
            return 0
        put(w, 0, next + 1)
        return token(OP_SHIFTBYTES, base, byte(s, next), 0)
    decoded = choose(op == 239, OP_PXOR, choose(op == 235, OP_POR, choose(op == 246, OP_SAD, choose(op == 212, OP_PADDQ, 0))))
    if decoded == 0:
        return 0
    return token(decoded, reg, base, 0)

def relative(s:readbuf, w:mutbuf, at:u64) -> u64:
    disp = uint(s, at, 4)
    if disp >= 2147483648:
        disp = disp | 18446744069414584320
    put(w, 32, disp)
    put(w, 24, at + 4 + disp)
    return put(w, 0, at + 4)

def token(op:u64, a:u64, b:u64, c:u64) -> u64:
    return op | (a << 8) | (b << 16) | (c << 24)
'''


def source_program():
    import re
    enums = {**{'OP_' + name.upper():op for name,op in NAMES.items()},
             'BIND_REPLY':int.from_bytes(b'HIAEBNR1','little'), 'SUCCESS':int.from_bytes(b'HIASIMV1','little')}
    source = re.sub(r'\b[A-Z][A-Z0-9_]+\b', lambda m: str(enums[m[0]]), POLICY)
    source += '\ndef specification(w:mutbuf, shape:u64) -> u64:\n'
    for shape in (1,2):
        source += f'    if shape == {shape}:\n        return grammar{shape}(w)\n'
    source += '    return grammar3(w)\n'
    for shape in (1,2,3):
        rows = schedule(shape)
        wire = bytes(v for row in rows for v in row)
        source += f'\ndef grammar{shape}(w:mutbuf) -> u64:\n'
        for i in range(0,len(wire),8):
            word = int.from_bytes(wire[i:i+8],'little')
            source += f'    put(w, {1024+i}, {word})\n'
        source += f'    return {len(rows)}\n'
    return source



def embedded_source(binding, scratch, result):
    """Read the already bound text in the supplied verifier's private arena."""
    import ast
    nodes = ast.parse(source_program()).body
    names = {n.name for n in nodes}
    def ref(name):
        return ast.Name(id=name, ctx=ast.Load())
    def number(n):
        return ast.Constant(n)
    def add(n, expr):
        return ast.BinOp(number(n), ast.Add(), expr)
    def call(name, *args):
        return ast.Call(ref(name), list(args), [])
    class Arena(ast.NodeTransformer):
        def visit_Call(self, node):
            name = node.func.id
            if name == 'length':
                return {'s': add(8, call('get',ref('w'),number(192))), 'o':number(32), 'w':number(2048)}[node.args[0].id]
            args = [self.visit(arg) for arg in node.args]
            if name in names:
                args = [arg for arg in args if not (isinstance(arg,ast.Name) and arg.id in {'s','o'})]
                return call('simd_' + name, *args)
            if name in ('uint','byte') and isinstance(args[0],ast.Name) and args[0].id == 's':
                return call('simd_read' if name=='uint' else 'byte',ref('w'),add(binding-8,args[1]),*args[2:])
            if name in ('get','put'):
                base = result if args[0].id == 'o' else scratch
                return call(name,ref('w'),add(base,args[1]),*args[2:])
            return call(name,*args)
        def visit_FunctionDef(self, node):
            if node.name == 'validate':
                node.returns.id = 'u64'
            node.name = 'simd_' + node.name
            node.args.args = [arg for arg in node.args.args if arg.arg not in {'s','o'}]
            return self.generic_visit(node)
    transformed=ast.fix_missing_locations(Arena().visit(ast.Module(nodes,[])))
    return ast.unparse(transformed) + '''
def simd_read(w:mutbuf, at:u64, n:u64) -> u64:
    result = 0
    i = 0
    while i < n:
        result = result | (byte(w, at + i) << (8 * i))
        i = i + 1
    return result
'''


if __name__ == '__main__':
    helpers = ELF[ELF.index('def uint('):ELF.index('def copy_bytes(')]
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MODULE + '.hepta')
    target.write_text(render_assembly(document(source_program() + helpers, MODULE)))
