"""HIA owner of the final canonicalization and complete primitive Core gate.

This component runs only after the unchanged complete lowering stream and its
late caller-owned snapshot/node/depth/byte gates. It cannot publish partial Core.
The fixed executor supplies the already sealed, private final spool verbatim.
"""
import ast
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('HIA_BASELINE_ROOT',str(ROOT.parent/'Hepta-v66-restored')))
sys.path[:0]=[str(ROOT),str(BASE)]
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.hia_composite_lowering_driver_common import COMMON,CONSTANTS as LOWER

CONSTANTS=dict(LOWER)
CONSTANTS.update({'PUBLIC_DRIVER':45,'PUBLIC_STATE':int.from_bytes(b'HIAPUB01','little'),
    'F_MAGIC':20480,'F_SLOT':20488,'F_BYTES':20496,'F_ERROR':20504,'F_FRAME':20512,
    'B_CORE_WIRE':44,'B_CANONICAL_CORE':45,'B_CANON_ARENA':46,
    'B_ADMISSION_STATE':47,'B_ADMISSION_ARENA':48,'B_SHA_INPUT':49,
    'B_SHA_OUTPUT':50,'B_SHA_WORK':51,'I_CANONICAL':26,'I_ADMISSION':27,
    'MAX_CORE':8<<20,'CANON_ARENA':64+56*262144+(8<<20),
    'ADMISSION_STATE':64<<20,'ADMISSION_ARENA':32<<20})

BODY=r'''
def publication(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 700)
    if get(w, F_MAGIC) == 0:
        if publication_begin(s, w) == 0:
            return refuse(w, 701)
    elif get(w, F_MAGIC) != PUBLIC_STATE or acknowledge(s, w, PUBLIC_DRIVER) == 0:
        return refuse(w, 702)
    while get(w, L_STATUS) == 1:
        result = publication_step(o, w)
        if result != 0:
            return result
    return refuse(w, 703)

def publication_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 128 or get(w, L_MAGIC) != LOWER_MAGIC or get(w, L_STATUS) != 2:
        return 0
    if get(w, L_DRIVER) != DRIVER_MAIN or get(w, C_PENDING) != 0:
        return 0
    if word(s, 0) != EVENT_MAGIC or word(s, 8) != 7 or word(s, 16) != get(w, C_LEASE) or word(s, 24) != get(w, C_SEQUENCE):
        return 0
    if word(s, 32) != 0 or word(s, 40) != 0 or get(w, L_FINAL_GROUP) != 0 or get(w, L_FINAL_ERROR) != 0:
        return 0
    if word(s, 48) != get(w, L_FINAL_REQUEST) or word(s, 56) != get(w, L_FN_SERIAL) or word(s, 64) != get(w, L_FN_SLOTS):
        return 0
    if word(s, 72) != get(w, L_FN_COUNT) or word(s, 80) != get(w, L_HELP_COUNT) or word(s, 88) != get(w, L_FINAL_BYTES):
        return 0
    if word(s, 96) != get(w, L_DIGEST0) or word(s, 104) != get(w, L_DIGEST1) or word(s, 112) != get(w, L_DIGEST2) or word(s, 120) != get(w, L_DIGEST3):
        return 0
    if get(w, L_STREAM_MODE) != 2 or get(w, L_STREAM_FINISHED) != 2 or word(s, 88) == 0 or word(s, 88) > MAX_CORE:
        return 0
    at = 0
    while at < 128:
        store(w, F_FRAME + at, byte(s, at))
        at = at + 1
    put(w, F_MAGIC, PUBLIC_STATE)
    put(w, F_SLOT, 4)
    put(w, F_BYTES, word(s, 88))
    put(w, F_ERROR, 0)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, PUBLIC_DRIVER)
    put(w, C_PHASE, 1)
    return 1

def publication_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        slot = get(w, F_SLOT)
        if slot == 64:
            put(w, C_PHASE, 2)
            return 0
        put(w, F_SLOT, slot + 1)
        return release(o, w, slot, 1)
    if phase == 2:
        return grow(o, w, B_CORE_WIRE, get(w, F_BYTES), 3)
    if phase == 3:
        return file_read(o, w, 1, 0, B_CORE_WIRE, 0, get(w, F_BYTES), 4)
    if phase == 4:
        return protect(o, w, B_CORE_WIRE, 1, 5)
    if phase == 5:
        # The canonicalizer borrows its output for the complete decoder's
        # preflight/key table before emitting bytes. The full existing 8 MiB
        # output allocation covers that contract, including tiny Core input.
        return grow(o, w, B_CANONICAL_CORE, MAX_CORE, 6)
    if phase == 6:
        return grow(o, w, B_CANON_ARENA, CANON_ARENA, 7)
    if phase == 7:
        wire8(w, 0, 0, 0, 0, 0, 0, 262144, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_CANON_ARENA, 0, 64, 8)
    if phase == 8:
        return invoke(o, w, I_CANONICAL, B_CORE_WIRE, 0, get(w, F_BYTES), B_CANONICAL_CORE, cap(w, B_CANONICAL_CORE), B_CANON_ARENA, CANON_ARENA, B_EMPTY, 0, 0, 9)
    if phase == 9:
        size = get(w, C_RETURN)
        if size == 0 or size > MAX_CORE or size > cap(w, B_CANONICAL_CORE):
            return refuse(w, 704)
        put(w, F_BYTES, size)
        return protect(o, w, B_CANONICAL_CORE, 1, 10)
    if phase == 10:
        return release(o, w, B_CORE_WIRE, 11)
    if phase == 11:
        return release(o, w, B_CANON_ARENA, 12)
    if phase == 12:
        return grow(o, w, B_ADMISSION_STATE, ADMISSION_STATE, 13)
    if phase == 13:
        return grow(o, w, B_ADMISSION_ARENA, ADMISSION_ARENA, 14)
    if phase == 14:
        return invoke(o, w, I_ADMISSION, B_CANONICAL_CORE, 0, get(w, F_BYTES), B_ADMISSION_STATE, ADMISSION_STATE, B_ADMISSION_ARENA, ADMISSION_ARENA, B_EMPTY, 0, 0, 15)
    if phase == 15:
        result = get(w, C_RETURN)
        if result != 0 and admission_status(result) == 0:
            return refuse(w, 705)
        put(w, F_ERROR, result)
        return release(o, w, B_ADMISSION_STATE, 16)
    if phase == 16:
        return release(o, w, B_ADMISSION_ARENA, 17)
    if phase == 17:
        if get(w, F_ERROR) != 0:
            return publication_finish(o, w)
        return grow(o, w, B_SHA_INPUT, get(w, F_BYTES) + 1, 18)
    if phase == 18:
        return grow(o, w, B_SHA_OUTPUT, 32, 19)
    if phase == 19:
        return grow(o, w, B_SHA_WORK, 1184, 20)
    if phase == 20:
        store(w, WIRE, 0)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_EMPTY, 0, 0, 21)
    if phase == 21:
        if get(w, C_RETURN) != 0:
            return refuse(w, 706)
        store(w, WIRE, 1)
        return copy(o, w, B_CONTROLLER, WIRE, B_SHA_INPUT, 0, 1, 22)
    if phase == 22:
        return copy(o, w, B_CANONICAL_CORE, 0, B_SHA_INPUT, 1, get(w, F_BYTES), 23)
    if phase == 23:
        return invoke(o, w, I_SHA_STREAM, B_SHA_INPUT, 0, get(w, F_BYTES) + 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_EMPTY, 0, 0, 24)
    if phase == 24:
        if get(w, C_RETURN) != 0:
            return refuse(w, 707)
        store(w, WIRE, 2)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_SHA_OUTPUT, 0, 32, 25)
    if phase == 25:
        if get(w, C_RETURN) != 32:
            return refuse(w, 708)
        put(w, L_DIGEST0, get(w, OBS))
        put(w, L_DIGEST1, get(w, OBS + 8))
        put(w, L_DIGEST2, get(w, OBS + 16))
        put(w, L_DIGEST3, get(w, OBS + 24))
        return release(o, w, B_SHA_INPUT, 26)
    if phase == 26:
        return release(o, w, B_SHA_OUTPUT, 27)
    if phase == 27:
        return release(o, w, B_SHA_WORK, 28)
    if phase == 28:
        return publication_finish(o, w)
    return refuse(w, 709)

def admission_status(status:u64) -> u64:
    if status >= 4294967285 and status <= 4294967295 and status != ABI:
        return 1
    if status >= 4294967280 and status <= 4294967284 and status != 4294967281:
        return 1
    if status == 4294967279 or status == 4294967278:
        return 1
    return 0

def publication_finish(o:mutbuf, w:mutbuf) -> u32:
    put(w, L_FINAL_BYTES, get(w, F_BYTES))
    error = get(w, F_ERROR)
    if error != 0:
        return finish(o, w, 8, error, get(w, L_FINAL_REQUEST))
    return finish(o, w, 0, 0, get(w, L_FINAL_REQUEST))
'''


def source_program():
    common=COMMON.replace('or image > 23:', 'or image > 27:')
    assert common!=COMMON
    tree=ast.parse(BODY+'\n'+common)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree));fns={n.name:n for n in tree.body}
    reachable={'publication'};pending=['publication']
    while pending:
        for n in ast.walk(fns[pending.pop()]):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in fns and n.func.id not in reachable:
                reachable.add(n.func.id);pending.append(n.func.id)
    tree.body=[n for n in tree.body if n.name in reachable]
    return ast.unparse(tree)+'\n'


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,sigs,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'composite_publication_driver','functions':functions})


if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/composite_publication_driver.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
