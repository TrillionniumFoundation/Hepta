"""Independent final-byte checker for closed x86 SIMD byte recurrences.

This consumer imports neither a machine encoder nor the SIMD producer.  It
decodes every text byte, binds the complete linked ELF with the existing strict
loader checker, recognizes a closed control-flow/ABI shape, and asks the pinned
solver about initiation, vector/scalar transitions, bounds and termination.
The induction over successive four-vector, single-vector and one-byte chunks
is part of this explicit trusted Python model; this is not a general x86 or
arbitrary-loop verifier. SSE2, AVX2 and AVX-512 have separate closed profiles.
Decoded wide instructions declare exact CPU/OS-state requirements; proving
semantics here does not authorize execution on an unprobed host.
"""
from __future__ import annotations

from .hia_loaded_source import loaded_source_identity

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
from .hia_verified_simd_wide_x64 import decode_wide_instruction, decode_copy_tail_memory, WideMachineRejected


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
WIDE_PROFILES = {256: "hia.closed-forward-byte-loops.avx2.direct-borrowed-u64.v1",
                 512: "hia.closed-forward-byte-loops.avx512.direct-borrowed-u64.v1"}
COPY_ENDPOINT_PROFILES = {bits:profile[:-1]+'2.copy-endpoints' for bits,profile in WIDE_PROFILES.items()}
COPY_FAST_ENDPOINT_PROFILES = {bits:profile[:-1]+'3.copy-endpoints-fast' for bits,profile in WIDE_PROFILES.items()}
BOUNDED_REDUCTION_PROFILES = {bits:profile[:-1]+'2.reduce-bounded' for bits,profile in WIDE_PROFILES.items()}
BOUNDED_ONE_REDUCTION_PROFILES = {bits:profile[:-1]+'3.reduce-bounded-one' for bits,profile in WIDE_PROFILES.items()}
CORE_RECOGNITION_PROFILE = "hia.closed-forward-byte-recurrence.alpha.v1"
SOURCE_FILES = ("hia_verified_simd_check.py", "hia_safe_core.py", "hia_safe_core_elf.py",
                "hia_verified_simd_wide_x64.py",
                "elf_shared_abi.py", "hia_program.py", "hia_opcodes.py", "hia_schema.py",
                "hia_capability_flow.py", "hia_json_preflight.py", "hia_solver_identity.py")


def _identity():
    return loaded_source_identity(__name__, SOURCE_FILES)


def _signature(operation):
    return (operation["op"], tuple(operation["args"]),
            tuple((v["name"], v["type"]) for v in operation["out"]), operation["attrs"])


def _alpha_rewrite(document, values, blocks, block_order):
    """Rename only identifier fields, simultaneously and without capture.

    This helper does not synthesize instructions or change operand order,
    types, attributes, effects, trap codes, module names or external symbols.
    It is also used with inverse maps to check the complete input round trip.
    """
    def name(mapping, original):
        require(original in mapping, 'alpha-renaming has an unmapped identifier')
        return mapping[original]

    def declaration(item):
        return {**item, 'name':name(values,item['name'])}

    def edge(item):
        return {**item, 'target':name(blocks,item['target']),
                'args':[name(values,arg) for arg in item['args']]}

    function=document['functions'][0]
    renamed={}
    for block in function['blocks']:
        term=block['term']
        if term['op']=='branch':
            term={**term, 'cond':name(values,term['cond']),
                  'then':edge(term['then']), 'else':edge(term['else'])}
        elif term['op']=='jump':
            term=edge(term)
        elif term['op']=='ret':
            term={**term, 'values':[name(values,arg) for arg in term['values']]}
        else:
            require(term['op']=='trap','unreviewed alpha-renaming terminator')
            term=dict(term)
        ident=name(blocks,block['id'])
        require(ident not in renamed,'alpha-renaming merged two blocks')
        renamed[ident]={**block, 'id':ident,
            'params':[declaration(item) for item in block['params']],
            'ops':[{**op, 'args':[name(values,arg) for arg in op['args']],
                    'out':[declaration(item) for item in op['out']]} for op in block['ops']],
            'term':term}
    require(len(block_order)==len(renamed) and set(block_order)==set(renamed),
            'alpha-renaming lost or duplicated a block declaration')
    return {**document, 'functions':[{**function,
        'params':[declaration(item) for item in function['params']],
        'entry':name(blocks,function['entry']),
        'blocks':[renamed[ident] for ident in block_order]}]}


def _alpha_normal_form(checked):
    """Make a reversible identifier-only view of one already verified Core.

    Block roles come only from the two required branch edges. Definition
    positions choose names, never instructions or values. The original strict
    recurrence recognizer still checks every resulting operation and edge.
    """
    d = checked.as_dict()
    require(checked.structured_bytes is None and d["schema"] == "hepta.hia.program.v8" and
            len(d["functions"]) == 1, "one primitive v8 Core function required")
    f = d["functions"][0]
    require(set(f) == {"name", "params", "returns", "effects", "entry", "blocks"},
            "unreviewed Core function metadata")
    types=[p['type'] for p in f['params']]
    copy=types==['mutbuf','readbuf','usize']
    require(copy or types==['readbuf','usize'],'unrecognized borrowed loop parameters')
    require(len(f['blocks'])==5,'complete closed five-block Core required')
    by_id={block['id']:block for block in f['blocks']}
    entry=by_id[f['entry']]
    require(entry['term']['op']=='branch','closed recurrence requires an entry branch')
    loop=by_id[entry['term']['then']['target']]
    require(loop['term']['op']=='branch','closed recurrence requires a loop branch')
    roles={'entry':f['entry'], 'loop':loop['id'],
           'body':loop['term']['then']['target'], 'done':loop['term']['else']['target'],
           'invalid':entry['term']['else']['target']}
    require(len(set(roles.values()))==5 and set(roles.values())==set(by_id),
            'closed recurrence roles must name five distinct complete blocks')
    block_map={actual:role for role,actual in roles.items()}
    body=by_id[roles['body']]
    if copy:
        kind='copy_u8'
    else:
        require(len(body['ops'])==5 and body['ops'][2]['op'] in ('int.add.wrap','bit.or'),
                'Core reduction recurrence differs')
        kind='sum_u8' if body['ops'][2]['op']=='int.add.wrap' else 'all_zero_u8'

    params=(['destination'] if copy else [])+['source','count']
    state=params+['index']+([] if copy else ['total'])
    parameter_names={'entry':params, 'invalid':[],
        **{role:[prefix+name for name in state] for role,prefix in
           (('loop','l_'),('body','b_'),('done','d_'))}}
    entry_outputs=['source_extent','source_fits']
    if copy: entry_outputs+=['destination_extent','destination_fits','fits']
    entry_outputs+=['zero']+([] if copy else ['initial'])
    body_outputs=[['byte'],[],['one'],['next_index']] if copy else [
        ['byte'],['wide'],['next_total'],['one'],['next_index']]
    done_outputs=([['answer']] if copy else
                  [[name] for name in ('done_zero','done_one','all_zero','answer')]
                  if kind=='all_zero_u8' else [])
    output_names={'entry':[[name] for name in entry_outputs], 'loop':[['more']],
                  'body':body_outputs, 'done':done_outputs, 'invalid':[]}
    value_map={}; inverse_values={}

    def bind(actual, canonical):
        require(actual not in value_map and canonical not in inverse_values,
                'SSA alpha-renaming is not a bijection')
        value_map[actual]=canonical; inverse_values[canonical]=actual

    for role,ident in roles.items():
        block=by_id[ident]
        require(len(block['params'])==len(parameter_names[role]) and
                len(block['ops'])==len(output_names[role]),
                'closed recurrence declaration/operation inventory differs')
        for parameter,canonical in zip(block['params'],parameter_names[role]):
            bind(parameter['name'],canonical)
        for op,expected in zip(block['ops'],output_names[role]):
            require(len(op['out'])==len(expected),'closed recurrence output inventory differs')
            for output,canonical in zip(op['out'],expected):
                bind(output['name'],canonical)

    order=list(roles)
    original_order=[block['id'] for block in f['blocks']]
    normalized=_alpha_rewrite(d,value_map,block_map,order)
    # Recheck the transformed typed Core as well as the exact inverse. Neither
    # an old report nor an emitter-provided map can authorize this operation.
    normal_checked=verify_program(normalized)
    normal=normal_checked.as_dict()
    restored=_alpha_rewrite(normal,inverse_values,{role:actual for role,actual in roles.items()},
                            original_order)
    require(restored==d,'Core alpha-renaming inverse round trip differs from the original')
    mapping={'ssa':dict(sorted(value_map.items())), 'blocks':dict(sorted(block_map.items())),
             'original_block_order':original_order}
    evidence={'profile':CORE_RECOGNITION_PROFILE, 'original_core_sha256':checked.sha256,
        'normal_form_core_sha256':normal_checked.sha256,
        'renaming_sha256':sha256(json.dumps(mapping,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'renaming':mapping, 'bijections_checked':True, 'inverse_roundtrip_checked':True,
        'renamed_ssa_definitions':sum(actual!=canonical for actual,canonical in value_map.items()),
        'renamed_blocks':sum(actual!=canonical for actual,canonical in block_map.items()),
        'block_declaration_order_changed':[block_map[ident] for ident in original_order]!=order}
    return normal,evidence


def _recognize_simd_core(document):
    checked=verify_program(document)
    d,evidence=_alpha_normal_form(checked)
    f=d['functions'][0]
    copy=[p['type'] for p in f['params']]==['mutbuf','readbuf','usize']
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
    return kind, f['name'], evidence


def recognize_simd_core(document):
    """Admit the complete recurrence modulo a checked identifier bijection.

    Local SSA and block spellings and block declaration order may differ.
    Operations, types, ordered operands, effects and complete edge transport
    retain the original strict shape; module and export names are preserved.
    """
    kind,export,_=_recognize_simd_core(document)
    return kind,export


@dataclass(frozen=True)
class Instruction:
    pc: int
    op: str
    args: tuple
    size: int
    cpu_features: tuple = ()


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
        try:
            tail_memory=decode_copy_tail_memory(data,begin)
        except WideMachineRejected as exc:
            raise VerifiedSIMDRejected(str(exc)) from exc
        if tail_memory is not None:
            op,args,size=tail_memory
            p=begin+size; rows.append(Instruction(begin,op,args,size)); continue
        if first in (0xc4, 0xc5, 0x62):
            try:
                op,args,size,features = decode_wide_instruction(data,begin)
            except WideMachineRejected as exc:
                raise VerifiedSIMDRejected(str(exc)) from exc
            p = begin + size
            rows.append(Instruction(begin,op,args,size,features))
            continue
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
                    if mod == 0:
                        # The short reduction entry uses one plain [RDI]
                        # byte load into a low 64-bit GPR. No SIB, RIP-relative
                        # address, register extension or implicit displacement.
                        require(rex==0x48 and rm==7, 'unsupported direct byte load')
                        displacement=0
                    else:
                        require(rex&8 and mod == 2 and rm&7 != 4, 'unsupported byte load')
                        displacement=struct.unpack('<i',take(4))[0]
                    op,args = 'load8',(reg,rm,displacement)
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
    if any(r.cpu_features for r in rows):
        return _structure_wide(rows,kind,binding)
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


def _structure_wide(rows, kind, binding):
    """Close the independent AVX2/AVX-512 four-chunk machine profile."""
    memory_rows=[r for r in rows if r.op in ('vload','vstore') or r.op.endswith('_mem')]
    widths={r.args[0] for r in memory_rows}
    require(widths and max(widths) in (256,512),'one complete wide memory width is required')
    bits=max(widths); width=bits//8
    pos,labels,edges,parts=0,{},[],{}
    copy=kind=='copy_u8'
    endpoint=copy and any(r.op in ('copy_load','copy_store') for r in rows)
    bounded=not copy and any(r.op=='copy_load' for r in rows)
    endpoint_fast=False
    bounded_one=False
    require(widths<={128,256,512} if endpoint else widths=={128,bits} if bounded else widths=={bits},
            'unreviewed mixed vector memory width')

    def next_row():
        nonlocal pos
        require(pos<len(rows),'missing wide control-flow instruction')
        row=rows[pos]; pos+=1
        return row

    def take(op,*args):
        row=next_row()
        require(row.op==op and row.args==args,
                'closed wide control-flow/ABI shape differs at '+str(row.pc))
        return row

    def label(name):
        require(pos<len(rows),'missing wide label')
        labels[name]=rows[pos].pc

    def branch(condition,name):
        row=next_row()
        require(row.op=='jcc' and row.args[0]==condition,'closed wide branch condition differs')
        edges.append((row.args[1],name))

    def jump(name):
        row=next_row(); require(row.op=='jmp','missing wide backedge')
        edges.append((row.args[0],name))

    def capture(name,count):
        nonlocal pos
        require(pos+count<=len(rows),'missing wide semantic block')
        parts[name]=rows[pos:pos+count]; pos+=count

    if copy:
        take('mov',0,8)
        for extent in (6,1):
            take('cmp',8,extent); branch(7,'abort')
        take('test',8,8); branch(4,'done')
        for pointer,end in ((7,9),(2,10)):
            take('test',pointer,pointer); branch(4,'abort')
            take('mov',end,pointer); take('add',end,8); branch(2,'abort')
        take('cmp',9,2); branch(6,'admitted'); take('cmp',10,7); branch(7,'abort')
        label('admitted'); take('mov',10,8)
    else:
        take('imm',0,0); take('cmp',2,6); branch(7,'abort')
        take('test',2,2); branch(4,'done')
        take('test',7,7); branch(4,'abort')
        take('mov',9,7); take('add',9,2); branch(2,'abort')
        take('mov',10,2)
        if bounded:
            if pos<len(rows) and rows[pos].op=='alu_imm' and rows[pos].args==('cmp',10,1):
                bounded_one=True
                take('alu_imm','cmp',10,1); branch(4,'single_byte')
            take('alu_imm','cmp',10,width); branch(2,'short_initialize')
        parts['initialize']=[]
        for register in (0,2,3,4,5):
            parts['initialize'].append(take('vpxor',bits,register,register,register))

    chunk_instructions=2 if copy or kind=='sum_u8' else 1
    label('bulk'); take('alu_imm','cmp',10,width*4)
    branch(2,'vector' if copy else 'bulk_merge')
    capture('bulk',chunk_instructions*4)
    take('alu_imm','add',7,width*4)
    if copy: take('alu_imm','add',2,width*4)
    take('alu_imm','sub',10,width*4); jump('bulk')
    if not copy:
        label('bulk_merge'); capture('bulk_merge',3)
    label('vector'); take('alu_imm','cmp',10,width)
    branch(2,'tail_dispatch' if endpoint else 'wide_cleanup' if copy else 'horizontal')
    capture('vector',chunk_instructions)
    take('alu_imm','add',7,width)
    if copy: take('alu_imm','add',2,width)
    take('alu_imm','sub',10,width); jump('vector')
    if not copy:
        label('horizontal')
        if bounded:
            capture('wide_fold',4 if bits==512 else 2); jump('narrow_vector')
            label('short_initialize'); parts['short_initialize']=[]
            for register in (0,2):
                parts['short_initialize'].append(take('vpxor',128,register,register,register))
            label('narrow_vector'); take('alu_imm','cmp',10,16); branch(2,'narrow_horizontal')
            capture('narrow_vector',chunk_instructions)
            take('alu_imm','add',7,16); take('alu_imm','sub',10,16); jump('narrow_vector')
            label('narrow_horizontal'); capture('narrow_horizontal',4)
        else:
            capture('horizontal',8 if bits==512 else 6)
    if endpoint:
        label('tail_dispatch'); take('test',10,10); branch(4,'wide_cleanup')
        if pos<len(rows) and rows[pos].op=='alu_imm' and rows[pos].args==('cmp',10,1):
            endpoint_fast=True
            take('alu_imm','cmp',10,1); branch(4,'endpoint_1')
        levels=[]; level=width//2
        while level>=2:
            levels.append(level); label('endpoint_'+str(level))
            take('alu_imm','cmp',10,level); branch(2,'endpoint_'+str(level//2))
            capture('endpoint_'+str(level),7); jump('wide_cleanup')
            level//=2
        levels.append(1); label('endpoint_1'); capture('endpoint_1',2)
        parts['_endpoint_levels']=levels
        label('wide_cleanup'); take('vzeroupper')
    elif bounded:
        for level in (8,4,2):
            label('word_'+str(level)); take('alu_imm','cmp',10,level); branch(2,'word_'+str(level//2))
            capture('word_'+str(level),5 if kind=='sum_u8' else 2)
            take('alu_imm','add',7,level); take('alu_imm','sub',10,level)
        label('word_1'); take('test',10,10); branch(4,'wide_cleanup'); capture('word_1',2)
        label('wide_cleanup'); take('vzeroupper')
    else:
        label('wide_cleanup'); take('vzeroupper')
        label('tail'); take('test',10,10); branch(4,'done'); capture('scalar',2)
        take('alu_imm','add',7,1)
        if copy: take('alu_imm','add',2,1)
        take('alu_imm','sub',10,1); jump('tail')
    label('done')
    if kind=='all_zero_u8':
        take('test',0,0); take('imm',0,0); take('sete',0)
    take('ret')
    if bounded_one:
        label('single_byte'); capture('single_byte',1); jump('done')
        require(parts['single_byte'][0].op=='load8' and parts['single_byte'][0].args[1:]==(7,0),
                'single-byte reduction must read exactly the admitted source byte')
    label('abort'); take('alu_imm','sub',4,8)
    call=next_row()
    require(call.op=='call' and binding['calls']=={call.pc:'abort'},'wide abort relocation differs')
    take('ud2'); require(pos==len(rows),'unreviewed trailing wide instructions')
    require(all(target==labels[name] for target,name in edges),'wide branch target changes closed flow')

    packed={'vpxor','vpor','vpand','vpsadbw','vpaddq','vpsubq'}
    for name,chunks in (('bulk',4),('vector',1)):
        for chunk in range(chunks):
            offset=chunk*width
            group=parts[name][chunk*chunk_instructions:(chunk+1)*chunk_instructions]
            accumulator=(0,3,4,5)[chunk] if name=='bulk' else 0
            if copy:
                read,write=(parts[name][chunk],parts[name][4+chunk]) if endpoint and name=='bulk' else group
                register=chunk+1 if endpoint and name=='bulk' else 1
                require(read.op=='vload' and read.args==(bits,register,2,offset) and
                        write.op=='vstore' and write.args[:3]==(bits,7,offset),
                        'wide copy must read/write its exact guarded chunk')
            else:
                first=group[0]
                require(first.op.endswith('_mem') and first.op[:-4] in packed and
                        first.args==(bits,1 if kind=='sum_u8' else accumulator,
                                    2 if kind=='sum_u8' else accumulator,7,offset),
                        'folded reduction must read its exact guarded chunk')
                if kind=='sum_u8':
                    require(group[1].op in packed and group[1].args==(bits,accumulator,accumulator,1),
                            'wide sum chunk must preserve the accumulator frame')
    if not copy:
        require(all(r.op in packed-{'vpsadbw'} and r.args[0]==bits and r.args[1]==0 and
                    r.args[2] in (0,3,4,5) and r.args[3] in (0,3,4,5)
                    for r in parts['bulk_merge']), 'wide merge has unreviewed register effects')
        for row in parts.get('horizontal',parts.get('narrow_horizontal',[])):
            require(row.op in packed | {'vextract','vmovq','vpsrldq','add','sub','or','and','xor'},
                    'unreviewed wide horizontal instruction')
            if row.op=='vmovq':
                require(row.args[0] in (0,9),'wide horizontal writes nonvolatile GPR state')
            elif row.op in ('add','sub','or','and','xor'):
                require(row.args[0] in (0,9),'wide horizontal writes nonvolatile GPR state')
    if bounded:
        require(all(r.op in packed|{'vextract'} for r in parts['wide_fold']),
                'wide-to-narrow fold has unreviewed effects')
        first=parts['narrow_vector'][0]
        require(first.op.endswith('_mem') and first.op[:-4] in packed and
                first.args==(128,1 if kind=='sum_u8' else 0,2 if kind=='sum_u8' else 0,7,0),
                'narrow cleanup must read exactly sixteen guarded bytes')
        if kind=='sum_u8':
            require(parts['narrow_vector'][1].op in packed and
                    parts['narrow_vector'][1].args==(128,0,0,1),
                    'narrow cleanup sum must preserve the accumulator frame')
        for level in (8,4,2,1):
            block=parts['word_'+str(level)]
            require(block[0].op=='copy_load' and block[0].args==(level*8,9,7,0),
                    'bounded reduction must read its exact guarded word')
            require(block[-1].op in ('add','sub','or','and','xor') and block[-1].args==(0,9),
                    'bounded reduction accumulator frame differs')
            if kind=='sum_u8' and level!=1:
                require(block[1].op=='vgpr_to_xmm' and block[2].op in packed and
                        block[2].args[0]==128 and block[3].op=='vmovq',
                        'bounded sum has unreviewed word-reduction effects')
    if endpoint:
        for level in parts['_endpoint_levels']:
            block=parts['endpoint_'+str(level)]
            readop,writeop=('vload','vstore') if level>=16 else ('copy_load','copy_store')
            first,last=(1,2) if level>=16 else (9,11)
            require(block[0].op==readop and block[0].args==(level*8,first,2,0),
                    'endpoint first load width/base/register differs')
            if level==1:
                stores=[block[1]]
            else:
                require([(r.op,r.args) for r in (block[1],block[2],block[5])]==[
                        ('alu_imm',('sub',10,level)),('add',(2,10)),('add',(7,10))] and
                        block[3].op==readop and block[3].args==(level*8,last,2,0),
                        'endpoint delta or final source address differs')
                stores=[block[4],block[6]]
            require(all(r.op==writeop and r.args[:3]==(level*8,7,0) and
                        (level>=16 or r.args[3] in (9,11)) for r in stores),
                    'endpoint stores have unreviewed width/base/register effects')
    elif not bounded:
        require(parts['scalar'][0].op=='load8' and parts['scalar'][0].args==(9,2 if copy else 7,0),
                'wide tail must read its exact guarded byte')
    if copy and not endpoint:
        require(parts['scalar'][1].op=='store8' and parts['scalar'][1].args[:2]==(7,0),
                'wide tail must store its exact guarded byte')
    elif not copy and not bounded:
        require(parts['scalar'][1].op in ('add','sub','or','and','xor') and
                parts['scalar'][1].args==(0,9),'wide tail accumulator frame differs')
    parts['_wide']={'bits':bits,'width':width,'target_isa':'avx512' if bits==512 else 'avx2',
                    'copy_tail':'endpoints-fast' if endpoint_fast else 'endpoints' if endpoint else 'byte' if copy else None,
                    'reduce_tail':'bounded-one' if bounded_one else 'bounded' if bounded else 'byte' if not copy else None}
    return labels,parts


def _prefix(z, ctx, rows, labels):
    bv=lambda n:z.BitVecVal(n%(1<<64),64,ctx=ctx)
    initial={i:z.BitVec('abi_r'+str(i),64,ctx=ctx) for i in range(16)}
    positions={r.pc:i for i,r in enumerate(rows)}
    pending=[(0,initial,z.BoolVal(True,ctx=ctx),None,None)]
    outcomes=[]
    stops={labels.get('bulk',labels['vector']):'vector',labels['done']:'done',labels['abort']:'abort'}
    if 'short_initialize' in labels:
        stops[labels['narrow_vector']]='narrow'
    if 'single_byte' in labels:
        stops[labels['single_byte']]='single'
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
        elif op=='alu_imm':
            require(a[0]=='cmp','unreviewed guard immediate effect')
            cf,zf=z.ULT(regs[a[1]],bv(a[2])),regs[a[1]]==bv(a[2])
        elif op in ('pxor','vpxor'): pass
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


def _wide_packed(z,ctx,operation,left,right):
    """Bit-accurate packed semantics at the actual decoded vector width."""
    bits=left.size()
    require(bits in (128,256,512) and right.size()==bits,'wide operand width mismatch')
    if operation=='vpxor': return left^right
    if operation=='vpor': return left|right
    if operation=='vpand': return left&right
    if operation in ('vpaddq','vpsubq'):
        lanes=[_alu('add' if operation=='vpaddq' else 'sub',
                    z.Extract(k+63,k,left),z.Extract(k+63,k,right)) for k in range(0,bits,64)]
        return z.Concat(*reversed(lanes))
    if operation=='vpsadbw':
        left_s,right_s=z.simplify(left),z.simplify(right)
        left_zero=z.is_bv_value(left_s) and left_s.as_long()==0
        right_zero=z.is_bv_value(right_s) and right_s.as_long()==0
        lanes=[]
        for start in range(0,bits//8,8):
            values=[]
            for j in range(start,start+8):
                a=z.ZeroExt(56,z.Extract(j*8+7,j*8,left))
                b=z.ZeroExt(56,z.Extract(j*8+7,j*8,right))
                # The unsigned |0-byte| identity is exact. Folding an actual
                # constant zero keeps the 256-byte obligation compact without
                # assuming that a decoded instruction preserved its source.
                values.append(b if left_zero else a if right_zero else z.If(z.UGE(a,b),a-b,b-a))
            lanes.append(sum(values,z.BitVecVal(0,64,ctx=ctx)))
        return z.Concat(*reversed(lanes))
    raise VerifiedSIMDRejected('missing wide packed semantics')


def _wide_execute(z,ctx,instructions,vector_bits,vectors,registers,blocks=(),*,memory_bits=None):
    """Interpret VEX/EVEX operands, including zeroed upper destination bits."""
    x,g=dict(vectors),dict(registers)
    stored=[]

    def low(value,bits):
        require(0<bits<=vector_bits,'wide instruction exceeds the modeled register width')
        return value if bits==vector_bits else z.Extract(bits-1,0,value)

    def write(register,value):
        require(value.size()<=vector_bits,'wide destination exceeds its register')
        x[register]=value if value.size()==vector_bits else z.ZeroExt(vector_bits-value.size(),value)

    def memory(bits,offset):
        width=bits//8
        require(bits==(vector_bits if memory_bits is None else memory_bits) and
                offset>=0 and offset%width==0 and offset//width<len(blocks),
                'unreviewed wide symbolic memory projection')
        return blocks[offset//width]

    for row in instructions:
        op,a=row.op,row.args
        if op=='vload':
            bits,destination,base,offset=a
            write(destination,memory(bits,offset))
        elif op=='vstore':
            bits,base,offset,source=a
            stored.append((offset,low(x[source],bits)))
        elif op.endswith('_mem'):
            bits,destination,source,base,offset=a
            write(destination,_wide_packed(z,ctx,op[:-4],low(x[source],bits),memory(bits,offset)))
        elif op in ('vpxor','vpor','vpand','vpsadbw','vpaddq','vpsubq'):
            bits,destination,source1,source2=a
            write(destination,_wide_packed(z,ctx,op,low(x[source1],bits),low(x[source2],bits)))
        elif op=='vextract':
            source_bits,destination_bits,destination,source,index=a
            value=low(x[source],source_bits)
            write(destination,z.Extract((index+1)*destination_bits-1,index*destination_bits,value))
        elif op=='vpsrldq':
            bits,destination,source,count=a
            require(bits==128,'wide shift must use one complete 128-bit lane')
            write(destination,z.LShR(low(x[source],bits),min(count,16)*8))
        elif op=='vmovq':
            destination,source=a
            g[destination]=z.Extract(63,0,x[source])
        elif op=='vgpr_to_xmm':
            destination,source=a
            write(destination,g[source])
        elif op in ('add','sub','or','and','xor'):
            g[a[0]]=_alu(op,g[a[0]],g[a[1]])
        else:
            raise VerifiedSIMDRejected('missing wide instruction semantics')
    return x,g,stored


def _prove_wide_blocks(z,ctx,parts,kind,check):
    config=parts['_wide']; bits=config['bits']; width=config['width']
    copy=kind=='copy_u8'
    zero=z.BitVecVal(0,bits,ctx=ctx)
    bv=lambda n:z.BitVecVal(n,64,ctx=ctx)
    def vector_state(prefix):
        return {i:z.BitVec(prefix+'_v'+str(i),bits,ctx=ctx) for i in range(8)}
    def gpr_state(prefix):
        return {i:z.BitVec(prefix+'_r'+str(i),64,ctx=ctx) for i in range(16)}
    def lane_sum(value):
        return sum([z.Extract(i+63,i,value) for i in range(0,bits,64)],bv(0))
    def prove(name,violation):
        # Canonicalize only the constructed ISA/Core formula. In particular,
        # no source/object byte identity or producer statement discharges an
        # arithmetic obligation. Modular additions are associative here.
        check(name,z.simplify(violation,bv_sort_ac=True))

    if not copy:
        initial=vector_state('wide_initialize'); gpr=gpr_state('wide_initialize')
        initialized,registers,stores=_wide_execute(z,ctx,parts['initialize'],bits,initial,gpr)
        prove('wide_accumulator_initiation',z.Or(*[initialized[i]!=0 for i in (0,2,3,4,5)],
              *[initialized[i]!=initial[i] for i in (1,6,7)]))

    for name,chunks in (('bulk',4),('vector',1)):
        initial=vector_state('wide_'+name); gpr=gpr_state('wide_'+name)
        if not copy: initial[2]=zero
        blocks=[z.BitVec('wide_'+name+'_source_'+str(i),bits,ctx=ctx) for i in range(chunks)]
        final,registers,stores=_wide_execute(z,ctx,parts[name],bits,initial,gpr,blocks)
        if copy:
            require([offset for offset,value in stores]==[i*width for i in range(chunks)],
                    'wide stores do not cover every requested chunk')
            prove('wide_'+name+'_copy_byte_semantics',
                  z.Or(*[value!=blocks[offset//width] for offset,value in stores]))
        else:
            accumulators=(0,3,4,5) if name=='bulk' else (0,)
            if kind=='sum_u8':
                prior=sum([lane_sum(initial[i]) for i in accumulators],bv(0))
                after=sum([lane_sum(final[i]) for i in accumulators],bv(0))
                reference=sum([z.ZeroExt(56,z.Extract(j*8+7,j*8,block))
                               for block in blocks for j in range(width)],bv(0))
                mismatch=after!=prior+reference
            else:
                before_zero=z.And(*[initial[i]==0 for i in accumulators])
                after_zero=z.And(*[final[i]==0 for i in accumulators])
                mismatch=after_zero!=z.And(before_zero,*[block==0 for block in blocks])
            prove('wide_'+name+('_sum_induction' if kind=='sum_u8' else '_zero_scan_induction'),
                  z.Or(mismatch,final[2]!=0))
    if not copy:
        initial=vector_state('wide_merge'); initial[2]=zero
        gpr=gpr_state('wide_merge')
        merged,registers,stores=_wide_execute(z,ctx,parts['bulk_merge'],bits,initial,gpr)
        mismatch=(lane_sum(merged[0])!=sum([lane_sum(initial[i]) for i in (0,3,4,5)],bv(0))
                  if kind=='sum_u8' else
                  (merged[0]==0)!=z.And(*[initial[i]==0 for i in (0,3,4,5)]))
        prove('wide_accumulator_merge_and_frame',z.Or(mismatch,merged[2]!=0,
              *[merged[i]!=initial[i] for i in range(1,8)]))

        if config.get('reduce_tail') not in ('bounded','bounded-one'):
            initial=vector_state('wide_horizontal'); gpr=gpr_state('wide_horizontal')
            final,registers,stores=_wide_execute(z,ctx,parts['horizontal'],bits,initial,gpr)
            mismatch=(registers[0]!=lane_sum(initial[0]) if kind=='sum_u8' else
                      (registers[0]==0)!=(initial[0]==0))
            prove('wide_horizontal_reduction',mismatch)


def _prove_bounded_reduction(z,ctx,parts,kind,check):
    """Compose the wide invariant with a narrow loop and disjoint word cuts.

    Every stage quantifies arbitrary prior accumulator and machine state.
    The fold and horizontal proofs include the persistent zero register and
    the frame needed by the next stage. The word partition is over arbitrary
    natural remaining counts and byte indices, not a sample of short inputs.
    """
    bits=parts['_wide']['bits']
    zero=z.BitVecVal(0,bits,ctx=ctx)
    bv=lambda n:z.BitVecVal(n,64,ctx=ctx)
    def state(prefix):
        x={i:z.BitVec(prefix+'_v'+str(i),bits,ctx=ctx) for i in range(8)}
        g={i:z.BitVec(prefix+'_r'+str(i),64,ctx=ctx) for i in range(16)}
        return x,g
    def lane_sum(value):
        return sum([z.Extract(i+63,i,value) for i in range(0,value.size(),64)],bv(0))
    def prove(name,violation,assumptions=()):
        check(name,z.simplify(violation,bv_sort_ac=True),assumptions)
    def frame(before,after,allowed):
        return [after[i]!=before[i] for i in before if i not in allowed]

    x,g=state('short_initialize')
    final,registers,stores=_wide_execute(z,ctx,parts['short_initialize'],bits,x,g)
    prove('short_accumulator_initiation_and_frame',z.Or(final[0]!=0,final[2]!=0,
        *frame(x,final,{0,2}),*frame(g,registers,set())))

    x,g=state('wide_to_narrow'); x[2]=zero
    final,registers,stores=_wide_execute(z,ctx,parts['wide_fold'],bits,x,g)
    low=z.Extract(127,0,final[0])
    mismatch=(lane_sum(low)!=lane_sum(x[0]) if kind=='sum_u8' else
              (low==0)!=(x[0]==0))
    prove('wide_to_narrow_reduction_and_frame',z.Or(mismatch,
        z.Extract(bits-1,128,final[0])!=0,final[2]!=0,
        *frame(x,final,{0,1}),*frame(g,registers,set())))

    x,g=state('narrow_vector'); x[2]=zero
    accumulator=z.BitVec('narrow_prior_accumulator',128,ctx=ctx)
    x[0]=z.ZeroExt(bits-128,accumulator)
    block=z.BitVec('narrow_source_bytes',128,ctx=ctx)
    final,registers,stores=_wide_execute(z,ctx,parts['narrow_vector'],bits,x,g,
                                         (block,),memory_bits=128)
    reference=sum([z.ZeroExt(56,z.Extract(j*8+7,j*8,block)) for j in range(16)],bv(0))
    low=z.Extract(127,0,final[0])
    mismatch=(lane_sum(low)!=lane_sum(accumulator)+reference if kind=='sum_u8' else
              (low==0)!=z.And(accumulator==0,block==0))
    prove('narrow_vector_induction_and_frame',z.Or(mismatch,
        z.Extract(bits-1,128,final[0])!=0,final[2]!=0,
        *frame(x,final,{0,1}),*frame(g,registers,set())))

    x,g=state('narrow_horizontal'); x[2]=zero
    accumulator=z.BitVec('narrow_horizontal_accumulator',128,ctx=ctx)
    x[0]=z.ZeroExt(bits-128,accumulator)
    final,registers,stores=_wide_execute(z,ctx,parts['narrow_horizontal'],bits,x,g)
    mismatch=(registers[0]!=lane_sum(accumulator) if kind=='sum_u8' else
              (registers[0]==0)!=(accumulator==0))
    prove('narrow_horizontal_reduction_and_frame',z.Or(mismatch,final[2]!=0,
        *frame(x,final,{0,1}),*frame(g,registers,{0,9})))

    # At the 16-byte false guard, each subsequent accepted word consumes a
    # fresh prefix. Quantify an arbitrary suffix byte j to prove exact union
    # and multiplicity one, which is essential for modular byte summation.
    remaining,count,index,base,extent,j=z.Ints(
        'bounded_remaining bounded_count bounded_index bounded_base bounded_extent bounded_byte',ctx=ctx)
    assumptions=[0<=remaining,remaining<16,0<=index,index<=count,count<=extent,
                 extent<(1<<64),base>0,base+count<(1<<64),remaining==count-index]
    cursor,rest=z.IntVal(0,ctx=ctx),remaining
    hits=[]; faults=[]
    for width in (8,4,2,1):
        taken=rest>=width
        address=base+index+cursor
        faults.append(z.And(taken,z.Or(cursor<0,cursor+width>remaining,
            address<base,address+width>base+count,address+width>=(1<<64))))
        hits.append(z.And(taken,cursor<=j,j<cursor+width))
        consumed=z.If(taken,width,0)
        cursor,rest=cursor+consumed,rest-consumed
        faults.append(z.Or(rest<0,rest>=width))
    multiplicity=sum([z.If(hit,1,0) for hit in hits],z.IntVal(0,ctx=ctx))
    prove('bounded_word_partition_bounds_and_no_overlap',z.Or(*faults,rest!=0,cursor!=remaining,
        multiplicity!=z.If(z.And(0<=j,j<remaining),1,0)),assumptions)

    for width in (8,4,2,1):
        name='bounded_word_'+str(width)
        x,g=state(name); x[2]=zero
        old=g[0]
        data=z.BitVec(name+'_loaded_bytes',width*8,ctx=ctx)
        loaded=dict(g); loaded[9]=data if width==8 else z.ZeroExt(64-width*8,data)
        final,registers,stores=_wide_execute(z,ctx,parts['word_'+str(width)][1:],bits,x,loaded)
        reference=sum([z.ZeroExt(56,z.Extract(j*8+7,j*8,data)) for j in range(width)],bv(0))
        mismatch=(registers[0]!=old+reference if kind=='sum_u8' else
                  (registers[0]==0)!=z.And(old==0,data==0))
        prove(name+'_semantics_and_frame',z.Or(mismatch,final[2]!=0,
            *frame(x,final,{1}),*frame(g,registers,{0,9})))


def _prove_endpoint_tails(z,ctx,parts,check):
    """Prove exact suffix effects, including repeated writes in the overlap.

    Source reads share one byte array indexed by their actual relative offset;
    first and last blocks are not independent symbolic values. The common
    whole-range disjointness proof preserves this source across every store.
    Natural offsets are related to actual u64 addresses by the nonwrapping
    bounds obligation for each decoded tail. No tail-count samples are used.
    """
    width=parts['_wide']['width']; bits=parts['_wide']['bits']
    remaining=z.Int('endpoint_remaining',ctx=ctx)
    guards=[remaining==0]+[z.And(remaining>=w,remaining<2*w) for w in parts['_endpoint_levels']]
    check('endpoint_dispatch_partition',z.Or(z.Not(z.Or(*guards)),
        *[z.And(left,right) for i,left in enumerate(guards) for right in guards[i+1:]]),
        [remaining>=0,remaining<width])
    for w in parts['_endpoint_levels']:
        prefix='endpoint_'+str(w)
        base,n,index,j=z.Ints(prefix+'_base '+prefix+'_count '+prefix+'_index '+prefix+'_byte',ctx=ctx)
        offsets=[z.IntVal(0,ctx)] if w==1 else [z.IntVal(0,ctx),remaining-w]
        path=[remaining>=w,remaining<2*w]
        span=[base>0,n>=0,index>=0,index<=n,remaining==n-index,base+n<(1<<64)]
        coverage=z.Or(*[z.And(j>=offset,j<offset+w) for offset in offsets])
        check(prefix+'_bounds_and_exact_coverage',z.Or(
            coverage!=z.And(j>=0,j<remaining),
            *[z.Or(offset<0,offset+w>remaining,base+index+offset<base,
                   base+index+offset+w>base+n,base+index+offset>=(1<<64)) for offset in offsets]),
            path+span)
        source=z.Array(prefix+'_source',z.IntSort(ctx),z.BitVecSort(8,ctx))
        before=z.Array(prefix+'_destination',z.IntSort(ctx),z.BitVecSort(8,ctx))
        memory=before
        initial={r:z.BitVec(prefix+'_gpr'+str(r),64,ctx=ctx) for r in range(16)}
        initial.update({2:z.IntVal(0,ctx),7:z.IntVal(0,ctx),10:remaining})
        registers=dict(initial)
        vectors={r:z.BitVec(prefix+'_vector'+str(r),bits,ctx=ctx) for r in range(8)}
        vector_initial=dict(vectors)
        accesses=[]
        for row in parts[prefix]:
            op,a=row.op,row.args
            if op in ('vload','copy_load'):
                operand_bits,destination,pointer,disp=a
                offset=registers[pointer]+disp; size=operand_bits//8
                value=z.Concat(*[z.Select(source,offset+k) for k in reversed(range(size))]) if size>1 else z.Select(source,offset)
                accesses.append(('read',offset,size))
                if op=='vload':
                    vectors[destination]=z.ZeroExt(bits-operand_bits,value)
                else:
                    registers[destination]=z.ZeroExt(64-operand_bits,value)
            elif op in ('vstore','copy_store'):
                operand_bits,pointer,disp,register=a
                offset=registers[pointer]+disp; size=operand_bits//8
                value=vectors[register] if op=='vstore' else registers[register]
                accesses.append(('write',offset,size))
                for k in range(size):
                    memory=z.Store(memory,offset+k,z.Extract(k*8+7,k*8,value))
            elif op=='alu_imm':
                action,destination,amount=a
                require(action=='sub' and destination==10,'unreviewed endpoint integer effect')
                registers[destination]=registers[destination]-amount
            elif op=='add':
                registers[a[0]]=registers[a[0]]+registers[a[1]]
            else:
                raise VerifiedSIMDRejected('unreviewed endpoint data instruction')
        expected=z.If(z.And(j>=0,j<remaining),z.Select(source,j),z.Select(before,j))
        # A symbolic j proves every byte, including bytes outside the suffix.
        # In the overlap both stores select source[j], so the second is exact.
        violation=z.Or(z.Select(memory,j)!=expected,
            *[z.Or(offset<0,offset+size>remaining) for _,offset,size in accesses],
            *[registers[r]!=initial[r] for r in range(16) if r not in (2,7,9,10,11)],
            *[vectors[r]!=vector_initial[r] for r in range(8) if r not in (1,2)])
        check(prefix+'_byte_effects_and_frame',z.simplify(violation),path)


def validate_verified_simd_artifact(document, object_bytes, final_bytes, *, timeout_ms=15000, query_directory=None):
    require(type(object_bytes) is bytes and type(final_bytes) is bytes,'immutable ELF bytes required')
    require(type(timeout_ms) is int and 100 <= timeout_ms <= 60000,'timeout must be 100..60000 milliseconds')
    started=time.monotonic(); deadline=started+timeout_ms/1000
    identity=_identity()
    checked=verify_program(document); kind,export,recognition=_recognize_simd_core(checked)
    binding=bind_final_artifact(object_bytes,final_bytes,export)
    require(binding['entry']==0 and binding['binding'].get('function_shape')=='direct_entry',
            'SIMD requires one directly exported function')
    rows=decode_simd(binding['text']); labels,parts=_structure(rows,kind,binding)
    unrolled='bulk' in parts
    wide=parts.get('_wide')
    endpoint=bool(wide and wide['copy_tail'] in ('endpoints','endpoints-fast'))
    endpoint_fast=bool(wide and wide['copy_tail']=='endpoints-fast')
    bounded=bool(wide and wide.get('reduce_tail') in ('bounded','bounded-one'))
    bounded_one=bool(wide and wide.get('reduce_tail')=='bounded-one')
    parallel_zero='bulk_merge' in parts and wide is None
    vector_width=wide['width'] if wide else 16
    required_features=sorted({feature for row in rows for feature in row.cpu_features}) if wide else ['sse2']
    required_xcr0_mask=230 if 'avx512f' in required_features else 6 if 'avx' in required_features else 0
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
    admitted_path=z.Or(path('vector'),path('narrow')) if bounded else path('vector')
    if bounded_one:
        admitted_path=z.Or(admitted_path,path('single'))
    check('decoded_entry_guards',z.Or(path('abort')!=z.Not(valid),path('done')!=(valid&(n==0)),
                                     admitted_path!=(valid&(n!=0))))
    if bounded:
        ordinary=z.And(n!=0,n!=1) if bounded_one else n!=0
        check('decoded_short_entry_partition',z.Or(
            path('narrow')!=z.And(valid,ordinary,z.ULT(n,bv(vector_width))),
            path('vector')!=z.And(valid,n!=0,z.UGE(n,bv(vector_width)))))
    if bounded_one:
        check('decoded_single_byte_entry_partition',path('single')!=z.And(valid,n==1))
        check('single_byte_access_bounds',z.Or(ptrs[0]==0,z.ULT(ptrs[0]+1,ptrs[0]),
            z.UGT(ptrs[0]+1,ptrs[0]+n),z.ULT(extents[0],bv(1))),[path('single')])
        # Use the actual prefix state, every decoded destination and all
        # possible byte values. The final shared return normalizes only the
        # all-zero predicate. This path never reads or writes a vector or
        # memory location other than the one structurally admitted byte.
        byte=z.BitVec('single_source_byte',8,ctx=ctx)
        single_bad=[]
        for stage,p,regs in outcomes:
            if stage!='single': continue
            final=dict(regs)
            final[parts['single_byte'][0].args[0]]=z.ZeroExt(56,byte)
            value=z.If(final[0]==0,bv(1),bv(0)) if kind=='all_zero_u8' else final[0]
            expected=z.If(byte==0,bv(1),bv(0)) if kind=='all_zero_u8' else z.ZeroExt(56,byte)
            single_bad.append(z.And(p,z.Or(value!=expected,
                *[final[r]!=regs[r] for r in range(16) if r!=0])))
        check('single_byte_result_and_register_frame',z.Or(*single_bad))
    bad=[]
    for stage,p,regs in outcomes:
        if stage in ('vector','narrow'):
            bad.append(z.And(p,z.Or(regs[10]!=n,regs[7]!=initial[7],
                                   regs[2]!=initial[2],regs[0]!=(n if copy else bv(0)))))
    check('loop_initiation',z.Or(*bad))
    # Natural-number invariant i + remaining = n, current pointers = base+i.
    # Each decoded backedge is exactly the +w/-w transition checked below.
    ni,ii,pi,ei=z.Ints('count index base extent',ctx=ctx)
    invariant=[0<=ii,ii<=ni,ni<=ei,ei<(1<<64),pi>0,pi+ni<(1<<64)]
    steps=((4*vector_width,vector_width,16) if bounded else
           (4*vector_width,vector_width) if endpoint else
           (4*vector_width,vector_width,1) if unrolled else (vector_width,1))
    for width in steps:
        guard=ni-ii>=width
        accesses=tuple(i*vector_width for i in range(4)) if width==4*vector_width else (0,)
        access_width=vector_width if width>=vector_width else width
        violation=z.Or(ii+width>ni,pi+ii<pi,pi+ii+width>pi+ni,
                       ii+width>=(1<<64),ni-(ii+width)<0,ni-(ii+width)>=ni-ii,
                       *[z.Or(pi+ii+offset<pi,pi+ii+offset+access_width>pi+ni)
                         for offset in accesses])
        check('range_and_decreasing_variant_'+str(width),violation,invariant+[guard])
    if endpoint or bounded:
        prefix_name='copy' if endpoint else 'reduction'
        q=z.Int(prefix_name+'_prefix_suffix_byte',ctx=ctx)
        check(prefix_name+'_prefix_suffix_partition',z.And(0<=q,q<ni)!=z.Or(
            z.And(0<=q,q<ii),z.And(ii<=q,q<ii+(ni-ii))),invariant)
    else:
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
    if wide:
        _prove_wide_blocks(z,ctx,parts,kind,check)
        if bounded:
            _prove_bounded_reduction(z,ctx,parts,kind,check)
    legacy_blocks=() if wide else ((('bulk',4),('vector',1)) if unrolled else (('vector',1),))
    for name,chunks in legacy_blocks:
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
    if not copy and not wide:
        x={i:z.BitVec('horizontal_initial_xmm'+str(i),128,ctx=ctx) for i in range(8)}; x[0]=acc
        g={i:z.BitVec('horizontal_initial_r'+str(i),64,ctx=ctx) for i in range(16)}
        for r in parts['horizontal']:
            if r.op=='xmm_to_gpr': g[r.args[0]]=z.Extract(63,0,x[r.args[1]])
            elif r.op=='psrldq': x[r.args[0]]=z.LShR(x[r.args[0]],min(r.args[1],16)*8)
            else: g[r.args[0]]=_alu(r.op,g[r.args[0]],g[r.args[1]])
        mismatch=(g[0]!=(z.Extract(63,0,acc)+z.Extract(127,64,acc)) if kind=='sum_u8'
                  else (g[0]==0)!=(acc==0))
        check('horizontal_reduction',mismatch)
    if endpoint:
        _prove_endpoint_tails(z,ctx,parts,check)
    elif not bounded:
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
        'profile':COPY_FAST_ENDPOINT_PROFILES[wide['bits']] if endpoint_fast else
                  COPY_ENDPOINT_PROFILES[wide['bits']] if endpoint else
                  BOUNDED_ONE_REDUCTION_PROFILES[wide['bits']] if bounded_one else
                  BOUNDED_REDUCTION_PROFILES[wide['bits']] if bounded else
                  WIDE_PROFILES[wide['bits']] if wide else PARALLEL_ZERO_PROFILE if parallel_zero else UNROLLED_PROFILE if unrolled else PROFILE,
        'ok':True,'complete':True,'status':'smt_validated','kind':kind,
        'target_isa':wide['target_isa'] if wide else 'sse2',
        'required_cpu_features':required_features,'required_xcr0_mask':required_xcr0_mask,
        'fresh_cpu_probe_required':bool(wide),
        'validation_mode':'independent_supplied_bytes_closed_loop_induction',
        'core_recognition':recognition,
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
                  'overlapping_endpoint_copy_effects_checked':endpoint,
                  'bounded_reduction_tail_effects_checked':bounded,
                  'single_byte_entry_effects_checked':bounded_one,
                  'machine_checked_isa_refinement_proved':False,'foreign_pointer_liveness_proved':False,
                  'timing_or_side_channels_proved':False,'serialized_receipt_authorizes_execution':False},
        'assumptions':[
            'SysV AMD64 x86-64 with SSE2; entry RSP is 8 modulo 16, at least 16, and at most 2^64-9; [RSP-16,RSP+8) is live stack with the caller return address in its final eight bytes.',
            'For each admitted nonempty range, the caller supplies a live initialized allocation covering its declared extent, disjoint from the active stack; destination is exclusive.',
            'Source/destination overlap is an invalid direct-copy ABI input; it is rejected before writes. Empty ranges permit null.',
            'Before executing a wide image, the builder/loader must freshly establish every decoded required_cpu_feature and required_xcr0_mask on every allowed CPU; this semantic receipt does not attest to host CPU or OS state.',
            'The existing ELF/loader model, these independent instruction/Core/loop semantics and pinned Z3 are trusted Python components, not a hardware ISA theorem.',
            'The loader maps inspected immutable bytes and immediately resolves libc abort as nonreturning; concurrency, signals, faults and side channels are outside this model.'],
        'model_counts':{'decoded_instructions':len(rows),'vector_width':vector_width,'scalar_tail_width':8 if bounded else 1,
                        'vector_unroll':4 if unrolled else 1,'superblock_width':4*vector_width if unrolled else vector_width,
                        'reduction_accumulators':0 if copy else 4 if parallel_zero or wide else 1,
                        'range_admission_sites':1,'guard_paths':len(outcomes),'loop_backedges':2 if endpoint else 3 if unrolled else 2,
                        'copy_tail':wide['copy_tail'] if wide else 'byte' if copy else None,
                        'reduce_tail':wide.get('reduce_tail') if wide else 'byte' if not copy else None,
                        'narrow_cleanup_width':16 if bounded else None,
                        'bounded_word_widths':[8,4,2,1] if bounded else [],
                        'endpoint_widths':parts.get('_endpoint_levels',[])},
        'elapsed_seconds':time.monotonic()-started}
    if output is not None: (output/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
