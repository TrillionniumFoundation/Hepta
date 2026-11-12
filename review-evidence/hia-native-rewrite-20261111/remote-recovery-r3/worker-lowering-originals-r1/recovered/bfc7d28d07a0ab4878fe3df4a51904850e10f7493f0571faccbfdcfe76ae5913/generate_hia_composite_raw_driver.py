"""HIA owner for raw UTF-8 JSON admission and canonical composite snapshot.

The subsequent constructor/services/stream kernels are unchanged. A private
executor retains the actual wire, actual decoder arenas and issued bitmap; no
external arena or filename can replace a lease between these native calls.
"""
from __future__ import annotations
import ast
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
BASE=Path(os.environ.get('HIA_BASELINE_ROOT',str(ROOT.parent/'Hepta-v66-restored')))
sys.path.insert(1,str(BASE))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from tools.hia_composite_lowering_driver_common import CONSTANTS as LOWER_CONSTANTS,COMMON
from tools.hia_composite_lowering_driver_services import BODY as SERVICES

CONSTANTS=dict(LOWER_CONSTANTS)
CONSTANTS.update({
    'RAW_DRIVER':44,'RAW_STATE':int.from_bytes(b'HIARND01','little'),
    'RAW_CONFIG':int.from_bytes(b'HIARNC01','little'),
    'CTOR_INIT':int.from_bytes(b'HIACDI01','little'),
    'ARENA_MAGIC':5208772604367785521,
    'JSON_PACKET_MAGIC':int.from_bytes(b'HIAJPK01','little'),
    'RAW_CONFIG_AT':12288,'RAW_FIELDS':16384,
    'B_RAW':44,'B_ARENA':45,'B_DECODE_WORK':46,'B_CODEC':47,
    'B_ISSUED_SOURCE':48,'B_CANONICAL':49,
    'I_JSON_DECODER':24,'I_JSON_PACKET':25,'I_JSON_CANONICAL':26,
    'RAW_LIMIT':8<<20,'NODES':262144,'DEPTH':64,
    'ARENA_BYTES':64+56*262144+(8<<20),
    'KEY_BYTES':8*2*262144,
    'CODEC_BYTES':64+49*262144+(8<<20)+8*2*262144,
})
CONSTANTS.update({'P_'+name:16384+8*i for i,name in enumerate((
    'RAW_BYTES','LEGACY','DIGITS','ARENA_EXTENT','NODES','CANONICAL_BYTES',
    'CURRENT_SOURCE','CURRENT_BYTES','PASS','RELEASE_SLOT','RESULT','REASON',
))})

BODY=r'''
def raw_normalize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 600)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if raw_begin(s, w) == 0:
            return refuse(w, 601)
        if length(s) > RAW_LIMIT:
            return raw_finish(o, w, 1, 0, 0)
        if complete_utf8(s) == 0:
            return raw_finish(o, w, 2, 0, 0)
    elif get(w, C_MAGIC) != RAW_STATE or get(w, C_STATUS) != 1 or acknowledge(s, w, RAW_DRIVER) == 0:
        return refuse(w, 602)
    while get(w, L_STATUS) == 1:
        if get(w, C_PHASE) >= 26000 and get(w, C_PHASE) < 27000:
            result = index_step(o, w)
        else:
            result = raw_step(o, w)
        if result != 0:
            return result
    return refuse(w, 603)

def raw_begin(s:readbuf, w:mutbuf) -> u64:
    if get(w, RAW_CONFIG_AT) != RAW_CONFIG or get(w, RAW_CONFIG_AT + 8) > 1:
        return 0
    lease = get(w, RAW_CONFIG_AT + 24)
    if lease == 0 or lease == MAX or length(s) > RAW_LIMIT + 1:
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_SOURCE) != 0 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    if cap(w, B_RAW) != length(s):
        return 0
    slot = 3
    while slot < 64:
        if slot != B_RAW and cap(w, slot) != 0:
            return 0
        slot = slot + 1
    at = 32
    while at < 64:
        if get(w, RAW_CONFIG_AT + at) != 0:
            return 0
        at = at + 8
    legacy = get(w, RAW_CONFIG_AT + 8)
    digits = get(w, RAW_CONFIG_AT + 16)
    zero(w, 0, 4096)
    zero(w, 8192, MIN_WORK - 8192)
    put(w, C_MAGIC, RAW_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, RAW_DRIVER)
    put(w, P_RAW_BYTES, length(s))
    put(w, P_LEGACY, legacy)
    put(w, P_DIGITS, digits)
    put(w, P_CURRENT_SOURCE, B_RAW)
    put(w, P_CURRENT_BYTES, length(s))
    put(w, P_PASS, 0)
    put(w, C_PHASE, 100)
    return 1

def complete_utf8(s:readbuf) -> u64:
    at = 0
    while at < length(s):
        first = byte(s, at)
        at = at + 1
        count = 0
        low = 128
        high = 191
        if first < 128:
            count = 0
        elif first >= 194 and first <= 223:
            count = 1
        elif first >= 224 and first <= 239:
            count = 2
            if first == 224:
                low = 160
            if first == 237:
                high = 159
        elif first >= 240 and first <= 244:
            count = 3
            if first == 240:
                low = 144
            if first == 244:
                high = 143
        else:
            return 0
        if count > length(s) - at:
            return 0
        i = 0
        while i < count:
            value = byte(s, at)
            if value < low or value > high:
                return 0
            at = at + 1
            i = i + 1
            low = 128
            high = 191
    return 1

def raw_decode_header(w:mutbuf) -> u64:
    result = get(w, C_RETURN)
    if result < 64 or result > ARENA_BYTES or get(w, OBS) != ARENA_MAGIC:
        return 0
    count = get(w, OBS + 8)
    if count == 0 or count > NODES or get(w, OBS + 16) != 64 + count * 56:
        return 0
    if get(w, OBS + 24) != result or get(w, OBS + 32) != result:
        return 0
    if get(w, OBS + 40) != get(w, P_CURRENT_BYTES) or get(w, OBS + 48) != 1 or get(w, OBS + 56) != 0:
        return 0
    if get(w, P_PASS) == 0:
        put(w, P_NODES, count)
    elif get(w, P_NODES) != count:
        return 0
    put(w, P_ARENA_EXTENT, result)
    return 1

def raw_packet_header(w:mutbuf) -> u64:
    result = get(w, C_RETURN)
    if result < 80 or result > CODEC_BYTES or get(w, OBS) != JSON_PACKET_MAGIC:
        return 0
    if get(w, OBS + 8) != 0 or get(w, OBS + 16) != 64 or get(w, OBS + 24) != result - 64:
        return 0
    if get(w, OBS + 32) != get(w, P_NODES) or get(w, OBS + 40) != get(w, P_CURRENT_BYTES):
        return 0
    if get(w, OBS + 48) != 0 or get(w, OBS + 56) != get(w, P_DIGITS):
        return 0
    put(w, C_PACKET_SLOT, B_CODEC)
    put(w, C_PACKET_OFFSET, 64)
    put(w, C_PACKET_BYTES, result - 64)
    return 1

def raw_finish(o:mutbuf, w:mutbuf, error:u64, stage:u64, native:u64) -> u32:
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    if error != 0:
        put(o, 32, 7)
        put(o, 40, error)
        put(o, 48, stage)
        put(o, 56, native)
    else:
        if cap(w, B_ISSUED_SOURCE) != get(w, L_INDEX_SOURCE_BYTES):
            return refuse(w, 604)
        slot = 3
        while slot < 64:
            if slot != B_ISSUED_SOURCE and cap(w, slot) != 0:
                return refuse(w, 605)
            slot = slot + 1
        put(o, 32, CTOR_INIT)
        put(o, 40, get(w, C_LEASE) + 1)
        put(o, 48, get(w, P_LEGACY))
        put(o, 56, get(w, L_INDEX_SOURCE_BYTES))
        put(o, 64, B_ISSUED_SOURCE)
        # The fixed handoff transfers this exact owned readonly mapping to
        # slot one. Its source, bytes and bitmap cannot be supplied externally.
        put(w, CAPS + B_SOURCE * 8, get(w, L_INDEX_SOURCE_BYTES))
        put(w, CAPS + B_ISSUED_SOURCE * 8, 0)
    put(w, C_MAGIC, 0)
    put(w, C_STATUS, 2)
    put(w, L_MAGIC, 0)
    put(w, L_STATUS, 0)
    return 128

def raw_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 100:
        return grow(o, w, B_ARENA, ARENA_BYTES, 101)
    if phase == 101:
        return grow(o, w, B_DECODE_WORK, KEY_BYTES, 102)
    if phase == 102:
        return grow(o, w, B_CODEC, CODEC_BYTES, 110)
    if phase == 110:
        wire8(w, 0, 0, 0, 0, 0, 0, NODES, DEPTH)
        return copy(o, w, B_CONTROLLER, WIRE, B_DECODE_WORK, 0, 64, 111)
    if phase == 111:
        return invoke(o, w, I_JSON_DECODER, get(w, P_CURRENT_SOURCE), 0, get(w, P_CURRENT_BYTES), B_ARENA, ARENA_BYTES, B_DECODE_WORK, KEY_BYTES, B_ARENA, 0, 64, 112)
    if phase == 112:
        result = get(w, C_RETURN)
        if get(w, P_PASS) == 0:
            if result == 4294967294:
                return raw_finish(o, w, 3, 1, result)
            if result == 4294967295 or result == 4294967292:
                return raw_finish(o, w, 2, 1, result)
        if raw_decode_header(w) == 0:
            return refuse(w, 606)
        return protect(o, w, B_ARENA, 1, 113)
    if phase == 113:
        wire8(w, JSON_PACKET_MAGIC, get(w, P_DIGITS), 0, 0, 0, 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_CODEC, 0, 64, 114)
    if phase == 114:
        return invoke(o, w, I_JSON_PACKET, B_ARENA, 0, get(w, P_ARENA_EXTENT), get(w, P_CURRENT_SOURCE), get(w, P_CURRENT_BYTES), B_CODEC, CODEC_BYTES, B_CODEC, 0, 64, 115)
    if phase == 115:
        if get(w, P_PASS) == 0 and get(w, C_RETURN) == 4294967280:
            return raw_finish(o, w, 4, 2, get(w, C_RETURN))
        if raw_packet_header(w) == 0:
            return refuse(w, 607)
        if get(w, P_PASS) != 0:
            put(w, L_INDEX_TARGET, B_ISSUED_SOURCE)
            put(w, L_INDEX_RETURN, 140)
            put(w, C_PHASE, 26000)
            return 0
        return protect(o, w, B_ARENA, 0, 120)
    if phase == 120:
        return grow(o, w, B_CANONICAL, RAW_LIMIT, 121)
    if phase == 121:
        wire8(w, 0, 0, 0, 0, 0, 0, NODES, DEPTH)
        return copy(o, w, B_CONTROLLER, WIRE, B_ARENA, 0, 64, 122)
    if phase == 122:
        return invoke(o, w, I_JSON_CANONICAL, B_RAW, 0, get(w, P_RAW_BYTES), B_CANONICAL, RAW_LIMIT, B_ARENA, ARENA_BYTES, B_CANONICAL, 0, 0, 123)
    if phase == 123:
        if get(w, C_RETURN) == 0 or get(w, C_RETURN) > get(w, P_RAW_BYTES):
            return refuse(w, 608)
        put(w, P_CANONICAL_BYTES, get(w, C_RETURN))
        put(w, P_CURRENT_SOURCE, B_CANONICAL)
        put(w, P_CURRENT_BYTES, get(w, C_RETURN))
        put(w, P_PASS, 1)
        return protect(o, w, B_CANONICAL, 1, 110)
    if phase == 140:
        if get(w, C_JSON_BYTES) != get(w, P_CANONICAL_BYTES):
            return refuse(w, 609)
        put(w, P_RELEASE_SLOT, 4)
        put(w, C_PHASE, 141)
        return 0
    if phase == 141:
        slot = get(w, P_RELEASE_SLOT)
        if slot == 64:
            return raw_finish(o, w, 0, 0, 0)
        put(w, P_RELEASE_SLOT, slot + 1)
        if slot == B_ISSUED_SOURCE:
            return 0
        return release(o, w, slot, 141)
    return refuse(w, 610)
'''


def source_program():
    common=COMMON.replace('or image > 23:', 'or image > 26:')
    assert common!=COMMON
    helpers=[n for n in ast.parse(SERVICES).body if isinstance(n,ast.FunctionDef) and n.name in ('json_workspace','index_step')]
    assert len(helpers)==2
    tree=ast.parse(BODY+'\n'+common+'\n'+'\n'.join(ast.unparse(n) for n in helpers))
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    fns={n.name:n for n in tree.body};assert len(fns)==len(tree.body)
    reachable={'raw_normalize'};pending=['raw_normalize']
    while pending:
        for node in ast.walk(fns[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in fns and node.func.id not in reachable:
                reachable.add(node.func.id);pending.append(node.func.id)
    tree.body=[n for n in tree.body if n.name in reachable]
    return ast.unparse(tree)+'\n'


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,sigs,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'composite_raw_driver','functions':functions})


if __name__=='__main__':
    target=ROOT/'examples/hia_bootstrap/composite_raw_driver.hiaasm'
    target.write_text(render_assembly(document()));print(target.name,target.stat().st_size)
