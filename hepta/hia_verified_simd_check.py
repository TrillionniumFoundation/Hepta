"""Independent final-byte checker for closed SSE2 forward byte recurrences.

This consumer imports neither a machine encoder nor the SIMD producer.  It
decodes every text byte, binds the complete linked ELF with the existing strict
loader checker, recognizes a closed control-flow/ABI shape, and asks the pinned
solver about initiation, vector/scalar transitions, bounds and termination.
The induction over successive 64-byte, 16-byte and one-byte chunks is part of
this explicit trusted Python model; this is not a general x86 or arbitrary-loop
verifier. The original single-vector loop remains an admitted separate shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
from pathlib import Path
import struct
import time

from .hia_program import verify_program
from .hia_safe_core import _solver_identity
from .hia_safe_core_elf import bind_final_artifact


class VerifiedSIMDRejected(ValueError):
    def __init__(self, message, *, counterexample=None, validation=None):
        super().__init__("E_HIA_VERIFIED_SIMD: " + message)
        self.counterexample, self.validation = counterexample, validation


def require(condition, message):
    if not condition:
        raise VerifiedSIMDRejected(message)


PROFILE = "hia.closed-forward-byte-loops.sse2.direct-borrowed-u64.v1"
UNROLLED_PROFILE = "hia.closed-forward-byte-loops.sse2.direct-borrowed-u64.v2"
PARALLEL_ZERO_PROFILE = "hia.closed-forward-byte-loops.sse2.direct-borrowed-u64.v3"
SOURCE_FILES = ("hia_verified_simd_check.py", "hia_safe_core.py", "hia_safe_core_elf.py",
                "elf_shared_abi.py", "hia_program.py", "hia_opcodes.py", "hia_schema.py",
                "hia_capability_flow.py", "hia_json_preflight.py")


def _identity():
    return {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def _signature(operation):
    return (operation["op"], tuple(operation["args"]),
            tuple((v["name"], v["type"]) for v in operation["out"]), operation["attrs"])


def recognize_simd_core(document):
    """Admit only the complete specified recurrence, including preflight effects.

    Version 1 intentionally fixes local SSA/block spellings; module and export
    names remain arbitrary. Other Core shapes retain their existing lowering.
    """
    checked = verify_program(document)
    d = checked.as_dict()
    require(checked.structured_bytes is None and d["schema"] == "hepta.hia.program.v8" and
            len(d["functions"]) == 1, "one primitive v8 Core function required")
    f = d["functions"][0]
    require(set(f) == {"name", "params", "returns", "effects", "entry", "blocks"},
            "unreviewed Core function metadata")
    types = [p["type"] for p in f["params"]]
    copy = types == ["mutbuf", "readbuf", "usize"]
    require(copy or types == ["readbuf", "usize"], "unrecognized borrowed loop parameters")
    params = ([('destination', 'mutbuf')] if copy else []) + [('source', 'readbuf'), ('count', 'usize')]
    pairs = lambda seq: [(p["name"], p["type"]) for p in seq]
    require(pairs(f["params"]) == params and f["returns"] == ["u64"] and f["entry"] == "entry" and
            f["effects"] == (["read", "trap", "write"] if copy else ["read", "trap"]),
            "Core ABI/effects differ from closed recurrence")
    require([b["id"] for b in f["blocks"]] == ["entry", "loop", "body", "done", "invalid"],
            "complete closed five-block Core required")
    blocks = {b["id"]: b for b in f["blocks"]}
    ops = {k: [_signature(x) for x in b["ops"]] for k, b in blocks.items()}
    s = lambda op, args=(), out=(), **attrs: (op, tuple(args), tuple(out), attrs)
    entry = [s("buffer.len", ['source'], [('source_extent', 'usize')]),
             s("compare.le", ['count', 'source_extent'], [('source_fits', 'bool')])]
    if copy:
        entry += [s("buffer.len", ['destination'], [('destination_extent', 'usize')]),
                  s("compare.le", ['count', 'destination_extent'], [('destination_fits', 'bool')]),
                  s("bool.and", ['source_fits', 'destination_fits'], [('fits', 'bool')])]
    entry += [s("const", out=[('zero', 'usize')], value=0)]
    if not copy:
        entry += [s("const", out=[('initial', 'u64')], value=0)]
    require(ops['entry'] == entry and pairs(blocks['entry']['params']) == params,
            "Core must validate the complete range before any byte effect")
    state = params + [('index', 'usize')] + ([] if copy else [('total', 'u64')])
    for block, prefix in [('loop', 'l_'), ('body', 'b_'), ('done', 'd_')]:
        require(pairs(blocks[block]['params']) == [(prefix+n, t) for n,t in state],
                "Core loop-carried state differs")
    require(ops['loop'] == [s('compare.lt', ['l_index','l_count'], [('more','bool')])],
            "Core loop condition differs")
    body = [s('buffer.load', ['b_source','b_index'], [('byte','u8')])]
    if copy:
        kind = 'copy_u8'
        body += [s('buffer.store', ['b_destination','b_index','byte'])]
    else:
        require(len(ops['body']) == 5 and ops['body'][2][0] in ('int.add.wrap','bit.or'),
                "Core reduction recurrence differs")
        kind = 'sum_u8' if ops['body'][2][0] == 'int.add.wrap' else 'all_zero_u8'
        body += [s('int.cast', ['byte'], [('wide','u64')], mode='wrap'),
                 s(ops['body'][2][0], ['b_total','wide'], [('next_total','u64')])]
    body += [s('const', out=[('one','usize')], value=1),
             s('int.add.wrap', ['b_index','one'], [('next_index','usize')])]
    require(ops['body'] == body, "Core byte effect/stride differs")
    done, answer = [], 'd_total'
    if copy:
        done, answer = [s('int.cast', ['d_count'], [('answer','u64')], mode='wrap')], 'answer'
    elif kind == 'all_zero_u8':
        done, answer = [s('const', out=[('done_zero','u64')], value=0),
                        s('const', out=[('done_one','u64')], value=1),
                        s('compare.eq', ['d_total','done_zero'], [('all_zero','bool')]),
                        s('select', ['all_zero','done_one','done_zero'], [('answer','u64')])], 'answer'
    require(ops['done'] == done and blocks['done']['term'] == {'op':'ret','values':[answer]} and
            not ops['invalid'] and not blocks['invalid']['params'] and
            blocks['invalid']['term'] == {'op':'trap','code':'bounds'}, "Core exit differs")
    incoming = [n for n,t in params] + ['zero'] + ([] if copy else ['initial'])
    branch = lambda cond, left, la, right, ra: {'op':'branch','cond':cond,
        'then':{'target':left,'args':la}, 'else':{'target':right,'args':ra}}
    carried = ['l_'+n for n,t in state]
    back = ['b_'+n for n,t in params] + ['next_index'] + ([] if copy else ['next_total'])
    require(blocks['entry']['term'] == branch('fits' if copy else 'source_fits','loop',incoming,'invalid',[]) and
            blocks['loop']['term'] == branch('more','body',carried,'done',carried) and
            blocks['body']['term'] == {'op':'jump','target':'loop','args':back},
            "Core edge/state transport differs")
    return kind, f['name']


@dataclass(frozen=True)
class Instruction:
    pc: int
    op: str
    args: tuple
    size: int


def decode_simd(data):
    """Closed independent decoder; every byte, including abort suffix, is read."""
    require(type(data) is bytes and 0 < len(data) <= 2048, "bounded immutable SIMD text required")
    rows, p = [], 0
    while p < len(data):
        begin = p
        def take(n):
            nonlocal p
            require(p+n <= len(data), 'truncated instruction')
            b = data[p:p+n]; p += n
            return b
        first = take(1)[0]
        if first in (0x66, 0xf3):
            rex = 0
            second = take(1)[0]
            if second in (0x48, 0x49):
                rex, second = second, take(1)[0]
            require(second == 0x0f, 'unsupported SIMD prefix')
            opcode, modrm = take(1)[0], take(1)[0]
            mod, reg, rm = modrm >> 6, (modrm >> 3)&7, modrm&7
            if first == 0xf3:
                require(not rex and opcode in (0x6f,0x7f) and mod in (0,1,2) and rm in (2,7),
                        'unreviewed SIMD memory addressing')
                displacement = (0 if mod == 0 else
                                int.from_bytes(take(1 if mod == 1 else 4),'little',signed=True))
                op, args = (('load128',(reg,rm,displacement)) if opcode == 0x6f else
                            ('store128',(rm,displacement,reg)))
            elif opcode == 0x7e:
                require(rex in (0x48,0x49) and mod == 3, 'unreviewed MOVQ form')
                op, args = 'xmm_to_gpr', (rm + (8 if rex&1 else 0),reg)
            elif opcode == 0x73:
                require(not rex and mod == 3 and reg == 3, 'unreviewed packed shift')
                op, args = 'psrldq', (rm,take(1)[0])
            else:
                require(not rex and mod == 3 and opcode in (0xef,0xeb,0xdb,0xf6,0xd4,0xfb),
                        'unsupported packed arithmetic')
                op, args = {0xef:'pxor',0xeb:'por',0xdb:'pand',0xf6:'psadbw',0xd4:'paddq',0xfb:'psubq'}[opcode], (reg,rm)
        else:
            rex = first if 0x40 <= first <= 0x4f else 0
            opcode = take(1)[0] if rex else first
            high_r, high_b = (8 if rex&4 else 0), (8 if rex&1 else 0)
            require(not rex&2, 'indexed addressing is outside SIMD profile')
            def mr():
                v = take(1)[0]
                return v>>6, ((v>>3)&7)+high_r, (v&7)+high_b, (v>>3)&7
            if 0xb8 <= opcode <= 0xbf:
                require(rex in (0,0x41,0x48,0x49), 'invalid immediate prefix')
                op,args = 'imm',(opcode-0xb8+high_b,int.from_bytes(take(8 if rex&8 else 4),'little'))
            elif opcode in (0xc3,):
                require(not rex, 'prefixed return')
                op,args = 'ret',()
            elif opcode in (0xe8,0xe9):
                require(not rex, 'prefixed control transfer')
                d = struct.unpack('<i',take(4))[0]
                op,args = ('call' if opcode == 0xe8 else 'jmp'),(p+d,)
            elif opcode == 0x0f:
                ext = take(1)[0]
                if 0x80 <= ext <= 0x8f:
                    require(not rex and ext&15 in (2,4,6,7), 'unsupported condition')
                    d = struct.unpack('<i',take(4))[0]
                    op,args = 'jcc',(ext&15,p+d)
                elif ext == 0xb6:
                    mod,reg,rm,group = mr()
                    require(rex&8 and mod == 2 and rm&7 != 4, 'unsupported byte load')
                    op,args = 'load8',(reg,rm,struct.unpack('<i',take(4))[0])
                elif ext == 0x94:
                    mod,reg,rm,group = mr()
                    require(rex == 0x40 and mod == 3 and reg == 0, 'unsupported SETE')
                    op,args = 'sete',(rm,)
                elif ext == 0x0b:
                    require(not rex, 'prefixed UD2')
                    op,args = 'ud2',()
                else:
                    raise VerifiedSIMDRejected('unreviewed 0F opcode')
            elif opcode in (0x89,0x01,0x29,0x09,0x21,0x31,0x39,0x85):
                mod,reg,rm,group = mr()
                require(rex&8 and mod == 3, 'unsupported integer arithmetic form')
                op,args = {0x89:'mov',0x01:'add',0x29:'sub',0x09:'or',0x21:'and',0x31:'xor',0x39:'cmp',0x85:'test'}[opcode],(rm,reg)
            elif opcode in (0x81,0x83):
                mod,reg,rm,group = mr()
                require(rex&8 and not high_r and mod == 3 and group in (0,5,7), 'unsupported immediate arithmetic')
                op,args = 'alu_imm',({0:'add',5:'sub',7:'cmp'}[group],rm,int.from_bytes(take(4 if opcode==0x81 else 1),'little',signed=True))
            elif opcode == 0x88:
                mod,reg,rm,group = mr()
                require(rex and not rex&8 and mod == 2 and rm&7 != 4, 'unsupported byte store')
                op,args = 'store8',(rm,struct.unpack('<i',take(4))[0],reg)
            else:
                raise VerifiedSIMDRejected('unsupported opcode at byte '+str(begin))
        rows.append(Instruction(begin,op,args,p-begin))
    boundaries = {r.pc for r in rows}
    for r in rows:
        if r.op in ('jmp','jcc'):
            require(r.args[-1] in boundaries, 'branch is not an instruction boundary')
    return rows


def _structure(rows, kind, binding):
    """Close CFG and its frame condition while leaving data operators to SMT."""
    pos, labels, edges, parts = 0, {}, [], {}
    def take(op, *args):
        nonlocal pos
        require(pos < len(rows), 'missing control-flow instruction')
        r=rows[pos]; pos+=1
        require(r.op == op and r.args == args, 'closed control-flow/ABI shape differs at '+str(r.pc))
        return r
    def label(name): labels[name]=rows[pos].pc
    def branch(cond,name):
        nonlocal pos
        r=rows[pos]; pos+=1
        require(r.op == 'jcc' and r.args[0] == cond, 'closed branch condition differs')
        edges.append((r.args[1],name))
    def jump(name):
        nonlocal pos
        r=rows[pos]; pos+=1
        require(r.op=='jmp', 'missing loop backedge'); edges.append((r.args[0],name))
    def capture(name,n):
        nonlocal pos
        require(pos+n <= len(rows),'missing semantic block')
        parts[name]=rows[pos:pos+n]; pos+=n
    copy = kind=='copy_u8'
    parallel_zero = False
    if copy:
        take('mov',0,8)
        for extent in (6,1): take('cmp',8,extent); branch(7,'abort')
        take('test',8,8); branch(4,'done')
        for ptr,end in ((7,9),(2,10)):
            take('test',ptr,ptr); branch(4,'abort'); take('mov',end,ptr); take('add',end,8); branch(2,'abort')
        take('cmp',9,2); branch(6,'admitted'); take('cmp',10,7); branch(7,'abort')
        label('admitted'); take('mov',10,8)
    else:
        take('imm',0,0); take('cmp',2,6); branch(7,'abort'); take('test',2,2); branch(4,'done')
        take('test',7,7); branch(4,'abort'); take('mov',9,7); take('add',9,2); branch(2,'abort')
        take('mov',10,2); take('pxor',0,0); take('pxor',2,2)
        if kind=='all_zero_u8' and pos<len(rows) and rows[pos].op=='pxor':
            for register in (3,4,5): take('pxor',register,register)
            parallel_zero = True
            require(pos<len(rows) and rows[pos].op=='alu_imm' and rows[pos].args==('cmp',10,64),
                    'parallel zero accumulators require the complete guarded bulk loop')
    chunk_instructions = 2 if copy or kind=='all_zero_u8' else 3
    # A 64-byte guard dominates all four explicitly displaced 16-byte
    # accesses. No pointer/count updates occur between those chunks.
    if pos < len(rows) and rows[pos].op == 'alu_imm' and rows[pos].args == ('cmp',10,64):
        label('bulk'); take('alu_imm','cmp',10,64); branch(2,'bulk_merge' if parallel_zero else 'vector')
        capture('bulk',4*chunk_instructions)
        take('alu_imm','add',7,64)
        if copy: take('alu_imm','add',2,64)
        take('alu_imm','sub',10,64); jump('bulk')
        if parallel_zero:
            label('bulk_merge'); capture('bulk_merge',3)
    label('vector'); take('alu_imm','cmp',10,16); branch(2,'tail' if copy else 'horizontal')
    capture('vector',chunk_instructions)
    take('alu_imm','add',7,16)
    if copy: take('alu_imm','add',2,16)
    take('alu_imm','sub',10,16); jump('vector')
    if not copy:
        label('horizontal'); capture('horizontal',4)
    label('tail'); take('test',10,10); branch(4,'done'); capture('scalar',2)
    take('alu_imm','add',7,1)
    if copy: take('alu_imm','add',2,1)
    take('alu_imm','sub',10,1); jump('tail')
    label('done')
    if kind=='all_zero_u8': take('test',0,0); take('imm',0,0); take('sete',0)
    take('ret')
    label('abort'); take('alu_imm','sub',4,8)
    r=rows[pos]; pos+=1
    require(r.op=='call' and binding['calls']=={r.pc:'abort'}, 'abort relocation differs')
    take('ud2'); require(pos==len(rows),'unreviewed trailing instructions')
    require(all(target==labels[name] for target,name in edges),'branch target changes closed flow')
    # Semantic parts have no branches, stack effects or hidden register writes.
    for name,offsets in (('vector',(0,)),('bulk',(0,16,32,48))):
        if name not in parts:
            continue
        for chunk,offset in enumerate(offsets):
            instructions=parts[name][chunk*chunk_instructions:(chunk+1)*chunk_instructions]
            for r in instructions:
                require(r.op in ('load128','store128','psadbw','paddq','psubq','pxor','por','pand'),
                        'unreviewed vector semantic instruction')
            require(instructions[0].op=='load128' and
                    instructions[0].args==(1,2 if copy else 7,offset),
                    'vector load must use the exact guarded source offset')
            if copy:
                require(instructions[1].op=='store128' and instructions[1].args[:2]==(7,offset),
                        'vector store must use the exact guarded destination offset')
            else:
                require(sum(r.op=='load128' for r in instructions)==1 and
                        all(r.op!='store128' for r in instructions),
                        'reduction chunk must have its single guarded vector read and no store')
                if parallel_zero and name=='bulk':
                    require(instructions[1].args==((0,3,4,5)[chunk],1),
                            'parallel zero chunk must update its exact independent accumulator')
    if parallel_zero:
        require(all(r.op in ('por','pxor','pand') and r.args[0]==0 and r.args[1] in (0,3,4,5)
                    for r in parts['bulk_merge']),
                'parallel zero merge must preserve every register except its result')
    if not copy:
        require(all(r.op in ('xmm_to_gpr','psrldq','add','sub','or','and','xor') for r in parts['horizontal']),
                'unreviewed horizontal semantic instruction')
    require(parts['scalar'][0].op=='load8' and parts['scalar'][0].args==(9,2 if copy else 7,0),
            'tail must read exactly one guarded byte')
    if copy:
        require(parts['scalar'][1].op=='store8' and parts['scalar'][1].args[:2]==(7,0),
                'tail must store exactly one guarded byte')
    else:
        require(parts['scalar'][1].op in ('add','sub','or','and','xor') and parts['scalar'][1].args==(0,9),
                'tail accumulator must preserve the frame')
    for r in parts.get('horizontal',[]):
        if r.op=='xmm_to_gpr': require(r.args[0] in (0,9),'horizontal writes nonvolatile state')
        elif r.op in ('add','sub','or','and','xor'): require(r.args[0] in (0,9),'horizontal writes nonvolatile state')
    return labels,parts


def _prefix(z, ctx, rows, labels):
    bv=lambda n:z.BitVecVal(n%(1<<64),64,ctx=ctx)
    initial={i:z.BitVec('abi_r'+str(i),64,ctx=ctx) for i in range(16)}
    positions={r.pc:i for i,r in enumerate(rows)}
    pending=[(0,initial,z.BoolVal(True,ctx=ctx),None,None)]
    outcomes=[]
    stops={labels.get('bulk',labels['vector']):'vector',labels['done']:'done',labels['abort']:'abort'}
    while pending:
        pc,regs,path,cf,zf=pending.pop()
        if pc in stops:
            outcomes.append((stops[pc],path,regs)); continue
        r=rows[positions[pc]]; regs=dict(regs); nextpc=pc+r.size
        op,a=r.op,r.args
        if op=='imm': regs[a[0]]=bv(a[1])
        elif op=='mov': regs[a[0]]=regs[a[1]]
        elif op in ('cmp','add'):
            x,y=regs[a[0]],regs[a[1]]
            if op=='cmp': cf,zf=z.ULT(x,y),x==y
            else:
                regs[a[0]]=x+y; cf,zf=z.ULT(x+y,x),x+y==0
        elif op=='test': cf,zf=z.BoolVal(False,ctx=ctx),(regs[a[0]]&regs[a[1]])==0
        elif op=='pxor': pass
        elif op=='jcc':
            cond={2:cf,4:zf,6:z.Or(cf,zf),7:z.And(z.Not(cf),z.Not(zf))}[a[0]]
            pending.append((a[1],dict(regs),z.And(path,cond),cf,zf))
            path=z.And(path,z.Not(cond))
        else: raise VerifiedSIMDRejected('unsupported guard instruction')
        pending.append((nextpc,regs,path,cf,zf))
        require(len(pending)+len(outcomes)<32,'guard path budget exceeded')
    return initial,outcomes


def _alu(op,a,b):
    if op=='add': return a+b
    if op=='sub': return a-b
    if op=='or': return a|b
    if op=='and': return a&b
    if op=='xor': return a^b
    raise VerifiedSIMDRejected('missing integer semantics')


def _packed(z,ctx,op,a,b):
    if op=='pxor': return a^b
    if op=='por': return a|b
    if op=='pand': return a&b
    if op in ('paddq','psubq'):
        lanes=[_alu('add' if op=='paddq' else 'sub',z.Extract(k+63,k,a),z.Extract(k+63,k,b)) for k in (0,64)]
        return z.Concat(lanes[1],lanes[0])
    if op=='psadbw':
        lanes=[]
        for start in (0,8):
            values=[]
            for j in range(start,start+8):
                x,y=z.ZeroExt(56,z.Extract(j*8+7,j*8,a)),z.ZeroExt(56,z.Extract(j*8+7,j*8,b))
                values.append(z.If(z.UGE(x,y),x-y,y-x))
            lanes.append(sum(values,z.BitVecVal(0,64,ctx=ctx)))
        return z.Concat(lanes[1],lanes[0])
    raise VerifiedSIMDRejected('missing packed semantics')


def _vector_transition(z,ctx,instructions,blocks,acc,prefix,*,copy,partial_accumulators=None):
    """Interpret one complete decoded vector block in the induction state.

    The structure check has already fixed every read/write displacement. Keep
    the actual decoded displacement in this memory projection too, so four
    successive chunks cannot silently reuse the first symbolic source block.
    Only reduction entry states promise a zero register; copy's XMM inputs are
    all arbitrary SysV caller state.
    """
    xmm={i:z.BitVec(prefix+'_initial_xmm'+str(i),128,ctx=ctx) for i in range(8)}
    if not copy:
        xmm[0],xmm[2]=acc,z.BitVecVal(0,128,ctx=ctx)
        if partial_accumulators is not None:
            xmm.update(partial_accumulators)
    stored=[]
    for r in instructions:
        if r.op=='load128':
            offset=r.args[2]
            require(offset%16==0 and 0<=offset//16<len(blocks),'unreviewed symbolic read displacement')
            xmm[r.args[0]]=blocks[offset//16]
        elif r.op=='store128':
            stored.append((r.args[1],xmm[r.args[2]]))
        else:
            xmm[r.args[0]]=_packed(z,ctx,r.op,xmm[r.args[0]],xmm[r.args[1]])
    return xmm,stored


def validate_verified_simd_artifact(document, object_bytes, final_bytes, *, timeout_ms=15000, query_directory=None):
    require(type(object_bytes) is bytes and type(final_bytes) is bytes,'immutable ELF bytes required')
    require(type(timeout_ms) is int and 100 <= timeout_ms <= 60000,'timeout must be 100..60000 milliseconds')
    started=time.monotonic(); deadline=started+timeout_ms/1000
    checked=verify_program(document); kind,export=recognize_simd_core(checked)
    identity=_identity(); binding=bind_final_artifact(object_bytes,final_bytes,export)
    require(binding['entry']==0 and binding['binding'].get('function_shape')=='direct_entry',
            'SIMD requires one directly exported function')
    rows=decode_simd(binding['text']); labels,parts=_structure(rows,kind,binding)
    unrolled='bulk' in parts
    parallel_zero='bulk_merge' in parts
    try: z=importlib.import_module('z3')
    except ImportError as exc: raise VerifiedSIMDRejected('pinned solver unavailable') from exc
    ctx=z.Context()
    solver_identity=_solver_identity(z)
    output=None
    if query_directory is not None:
        output=Path(query_directory).absolute(); output.mkdir(parents=False,exist_ok=False)
    reports=[]
    def check(name, violation, assumptions=(), expected='unsat'):
        remaining=int((deadline-time.monotonic())*1000)
        require(remaining>0,'total SIMD validation deadline exhausted')
        solver=z.Solver(ctx=ctx); solver.set(timeout=remaining); solver.add(*assumptions,violation)
        query=solver.to_smt2(); result=solver.check(); row={'name':name,'result':str(result),'expected':expected,
            'query_sha256':sha256(query.encode()).hexdigest()}; reports.append(row)
        if output is not None: (output/(str(len(reports)).zfill(2)+'-'+name+'.smt2')).write_text(query)
        if str(result)!=expected:
            witness={'obligation':name,'model':str(solver.model())} if result==z.sat else None
            raise VerifiedSIMDRejected('failed obligation '+name, counterexample=witness,
                                       validation={'ok':False,'complete':False,'obligations':reports})
    bv=lambda n:z.BitVecVal(n,64,ctx=ctx)
    initial,outcomes=_prefix(z,ctx,rows,labels)
    copy=kind=='copy_u8'; n=initial[8 if copy else 2]
    ptrs=[initial[7],initial[2]] if copy else [initial[7]]
    extents=[initial[6],initial[1]] if copy else [initial[6]]
    valid=z.And(*[z.ULE(n,e) for e in extents],z.Or(n==0,z.And(*[
        z.And(p!=0,z.UGE(p+n,p)) for p in ptrs],
        z.Or(z.ULE(ptrs[0]+n,ptrs[1]),z.ULE(ptrs[1]+n,ptrs[0])) if copy else z.BoolVal(True,ctx=ctx))))
    check('caller_contract_nonvacuous',valid,expected='sat')
    path=lambda name:z.Or(*[p for s,p,r in outcomes if s==name])
    check('decoded_entry_guards',z.Or(path('abort')!=z.Not(valid),path('done')!=(valid&(n==0)),
                                     path('vector')!=(valid&(n!=0))))
    bad=[]
    for stage,p,regs in outcomes:
        if stage=='vector':
            bad.append(z.And(p,z.Or(regs[10]!=n,regs[7]!=initial[7],
                                   regs[2]!=initial[2],regs[0]!=(n if copy else bv(0)))))
    check('loop_initiation',z.Or(*bad))
    # Natural-number invariant i + remaining = n, current pointers = base+i.
    # Each decoded backedge is exactly the +w/-w transition checked below.
    ni,ii,pi,ei=z.Ints('count index base extent',ctx=ctx)
    invariant=[0<=ii,ii<=ni,ni<=ei,ei<(1<<64),pi>0,pi+ni<(1<<64)]
    for width in ((64,16,1) if unrolled else (16,1)):
        guard=ni-ii>=width
        accesses=(0,16,32,48) if width==64 else (0,)
        access_width=16 if width>=16 else 1
        violation=z.Or(ii+width>ni,pi+ii<pi,pi+ii+width>pi+ni,
                       ii+width>=(1<<64),ni-(ii+width)<0,ni-(ii+width)>=ni-ii,
                       *[z.Or(pi+ii+offset<pi,pi+ii+offset+access_width>pi+ni)
                         for offset in accesses])
        check('range_and_decreasing_variant_'+str(width),violation,invariant+[guard])
    check('loop_exit_covers_exact_count',ii!=ni,invariant+[ni-ii==0])
    # Prefix guards and the fixed CFG never write saved registers or data.
    # The vector/tail instruction frame is closed by _structure. The sole
    # call is abort: sub rsp,8 aligns entry rsp == 8 (mod 16), and CALL
    # writes its eight-byte return slot at entry_rsp-16. RET reads the
    # caller's entry return slot at [entry_rsp, entry_rsp+8).
    rsp=z.BitVec('entry_rsp',64,ctx=ctx)
    stack_contract=[(rsp&bv(15))==8,z.UGE(rsp,bv(16)),z.ULE(rsp,bv((1<<64)-9))]
    check('abort_call_stack_alignment_and_bounds',z.Or(((rsp-bv(8))&bv(15))!=0,
          z.UGT(rsp-bv(16),rsp),z.UGT((rsp-bv(16))+bv(8),rsp),z.ULT(rsp+bv(8),rsp)),stack_contract)
    for name,chunks in ((('bulk',4),('vector',1)) if unrolled else (('vector',1),)):
        blocks=[z.BitVec(name+'_source_bytes_'+str(j),128,ctx=ctx) for j in range(chunks)]
        acc=z.BitVec(name+'_prior_accumulator',128,ctx=ctx)
        partials=({j:z.BitVec(name+'_prior_accumulator_'+str(j),128,ctx=ctx) for j in (3,4,5)}
                  if parallel_zero and name=='bulk' else {})
        xmm,stored=_vector_transition(z,ctx,parts[name],blocks,acc,name,copy=copy,
                                      partial_accumulators=partials)
        if copy:
            require([offset for offset,value in stored]==[16*j for j in range(chunks)],
                    'decoded stores do not cover the complete vector block')
            check(name+'_copy_byte_semantics',z.Or(*[value!=blocks[offset//16] for offset,value in stored]))
        elif kind=='sum_u8':
            lane_sum=lambda x:z.Extract(63,0,x)+z.Extract(127,64,x)
            reference=sum([z.ZeroExt(56,z.Extract(j*8+7,j*8,block))
                           for block in blocks for j in range(16)],bv(0))
            check(name+'_sum_induction',z.Or(lane_sum(xmm[0])!=lane_sum(acc)+reference,xmm[2]!=0))
        else:
            prior_zero=z.And(acc==0,*[value==0 for value in partials.values()])
            next_zero=z.And(xmm[0]==0,*[xmm[register]==0 for register in partials])
            check(name+'_zero_scan_induction',z.Or(next_zero!=z.And(prior_zero,*[block==0 for block in blocks]),xmm[2]!=0))
    if parallel_zero:
        # The bulk invariant retains all four independent accumulators. Its
        # false guard must pass through this decoded merge, even when count
        # was initially below 64. The existing 16-byte loop then receives
        # exactly its scalar zero-predicate state and persistent zero vector.
        initial_xmm={i:z.BitVec('merge_initial_xmm'+str(i),128,ctx=ctx) for i in range(8)}
        initial_xmm[2]=z.BitVecVal(0,128,ctx=ctx)
        merged=dict(initial_xmm)
        for instruction in parts['bulk_merge']:
            dst,src=instruction.args
            merged[dst]=_packed(z,ctx,instruction.op,merged[dst],merged[src])
        check('parallel_zero_merge_and_frame',z.Or(
            (merged[0]==0)!=z.And(*[initial_xmm[i]==0 for i in (0,3,4,5)]),
            merged[2]!=0,*[merged[i]!=initial_xmm[i] for i in range(1,8)]))
    if copy:
        # Under the full-range disjointness guard, writing each next prefix
        # cannot alter any byte of the complete source range, including bytes
        # that a later iteration has not loaded yet.
        dp,sp,nn,j,k=z.Ints('dst_base src_base copy_count source_offset store_offset',ctx=ctx)
        disjoint=[dp>0,sp>0,nn>0,dp+nn<(1<<64),sp+nn<(1<<64),
                  z.Or(dp+nn<=sp,sp+nn<=dp),0<=j,j<nn,0<=k,k<nn]
        check('copy_source_preserved_between_iterations',dp+k==sp+j,disjoint)
    if not copy:
        x={i:z.BitVec('horizontal_initial_xmm'+str(i),128,ctx=ctx) for i in range(8)}; x[0]=acc
        g={i:z.BitVec('horizontal_initial_r'+str(i),64,ctx=ctx) for i in range(16)}
        for r in parts['horizontal']:
            if r.op=='xmm_to_gpr': g[r.args[0]]=z.Extract(63,0,x[r.args[1]])
            elif r.op=='psrldq': x[r.args[0]]=z.LShR(x[r.args[0]],min(r.args[1],16)*8)
            else: g[r.args[0]]=_alu(r.op,g[r.args[0]],g[r.args[1]])
        mismatch=(g[0]!=(z.Extract(63,0,acc)+z.Extract(127,64,acc)) if kind=='sum_u8'
                  else (g[0]==0)!=(acc==0))
        check('horizontal_reduction',mismatch)
    old=z.BitVec('prior_scalar_accumulator',64,ctx=ctx); byte=z.BitVec('tail_byte',8,ctx=ctx)
    g={i:z.BitVec('tail_initial_r'+str(i),64,ctx=ctx) for i in range(16)}; g[0]=old; g[9]=z.ZeroExt(56,byte)
    tail=parts['scalar'][1]
    if copy:
        check('scalar_copy_byte_semantics',z.Extract(7,0,g[tail.args[2]])!=byte)
    else:
        value=_alu(tail.op,g[tail.args[0]],g[tail.args[1]])
        mismatch=(value!=old+z.ZeroExt(56,byte) if kind=='sum_u8'
                  else (value==0)!=z.And(old==0,byte==0))
        check('scalar_tail_induction',mismatch)
    require(time.monotonic()<deadline and identity==_identity(),'checker changed or final deadline exhausted')
    require(solver_identity==_solver_identity(z) and time.monotonic()<deadline,'solver changed or final deadline exhausted')
    report={
        'schema':'hepta.hia.verified-simd-machine-validation.v1',
        'profile':PARALLEL_ZERO_PROFILE if parallel_zero else UNROLLED_PROFILE if unrolled else PROFILE,
        'ok':True,'complete':True,'status':'smt_validated','kind':kind,
        'validation_mode':'independent_supplied_bytes_closed_loop_induction',
        'subject':{'core_sha256':checked.sha256,'input_sha256':checked.input_sha256,
                   'object_sha256':sha256(object_bytes).hexdigest(),'final_image_sha256':sha256(final_bytes).hexdigest(),
                   'entry_symbol':export},
        'checker':{'name':'hepta.hia_verified_simd_check.validate_verified_simd_artifact',
                   'source_identity':identity,'solver':solver_identity,'producer_reemission_used':False},
        'image_binding':binding['binding'],'obligations':reports,
        'property':'all-count closed-loop Core refinement, caller byte bounds, complete copy effects and SysV preservation in the declared model',
        'abi':{'arguments':['destination','destination_extent','source','source_extent','count'] if copy else ['source','source_extent','count'],
               'return':'u64','invalid_range':'nonreturning libc abort before data effects','empty_null_allowed':True,
               'copy_overlap':'rejected before effects' if copy else 'not applicable','count_domain':'all u64 counts'},
        'claims':{'all_input_refinement_in_independent_model':True,'inductive_loop_model_checked':True,
                  'final_elf_bytes_bound':True,'vector_and_tail_memory_bounds_checked':True,
                  'copy_source_preserved':copy,'whole_language_soundness_proved':False,
                  'machine_checked_isa_refinement_proved':False,'foreign_pointer_liveness_proved':False,
                  'timing_or_side_channels_proved':False,'serialized_receipt_authorizes_execution':False},
        'assumptions':[
            'SysV AMD64 x86-64 with SSE2; entry RSP is 8 modulo 16, at least 16, and at most 2^64-9; [RSP-16,RSP+8) is live stack with the caller return address in its final eight bytes.',
            'For each admitted nonempty range, the caller supplies a live initialized allocation covering its declared extent, disjoint from the active stack; destination is exclusive.',
            'Source/destination overlap is an invalid direct-copy ABI input; it is rejected before writes. Empty ranges permit null.',
            'The existing ELF/loader model, these independent instruction/Core/loop semantics and pinned Z3 are trusted Python components, not a hardware ISA theorem.',
            'The loader maps inspected immutable bytes and immediately resolves libc abort as nonreturning; concurrency, signals, faults and side channels are outside this model.'],
        'model_counts':{'decoded_instructions':len(rows),'vector_width':16,'scalar_tail_width':1,
                        'vector_unroll':4 if unrolled else 1,'superblock_width':64 if unrolled else 16,
                        'reduction_accumulators':4 if parallel_zero else 0 if copy else 1,
                        'range_admission_sites':1,'guard_paths':len(outcomes),'loop_backedges':3 if unrolled else 2},
        'elapsed_seconds':time.monotonic()-started}
    if output is not None: (output/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
