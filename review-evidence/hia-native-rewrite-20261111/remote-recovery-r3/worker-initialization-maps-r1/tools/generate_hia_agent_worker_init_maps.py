"""Native fixed initializer tables and immutable state-map operations.

NEW UNEXECUTED draft. This is the initializer's source-bound string-key domain,
not a general Python mapping API or a namespace capability issuer. All source
values are actual issued immutable Graph roots; cross-Graph joining remains a
separate native owner. This kernel never interprets a host dictionary plan.
"""
from __future__ import annotations
import ast,json,sys
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
def magic(value):return int.from_bytes(value.encode('ascii'),'little')
CONSTANTS={
 'IV_GRAPH':magic('HIAGRF01'),'IV_BAD':0xfffffffd,'IV_MAX':(1<<64)-1,
 'IM_COMMAND':magic('HIAWMC01'),'IM_STATE':magic('HIAWMW01'),
 'IM_EVENT':magic('HIAWME01'),'IM_MIN':4096,'IM_PAIRS':4096,
 'IM_TOOLS':magic('tools'),'IM_NAME':magic('name'),
 'V_BAD':32,'M_MAGIC':0,'M_STATUS':8,'M_SEQ':16,'M_NEED':24,
 'M_OP':40,'M_NODES':48,'M_EDGES':56,'M_POOL':64,'M_SOURCE_BYTES':72,
 'M_PAIR_CAPACITY':80,'M_PAIRS':88,'M_COUNT0':96,'M_COUNT1':104,
 'M_OUT_AT':112,'M_OUT_BYTES':120,'M_ROOT0':128,'M_ROOT1':136,
 'M_OUT_LEASE':144,'M_SOURCE_LEASE':152,'M_INV':160,'M_CALL':168,
 'M_SOURCE_DATA':176,'M_OUT_DATA':184,'M_OUT_NODES':192,'M_OUT_EDGES':200,
 'M_LIST':208,'M_SAVED_COMMAND':768,'M_SAVED_SOURCE':960,
}
HELPER=ROOT/'dependencies/generate_hia_agent_worker_init_values.py'
HELPER_SHA='9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac'
BODY=r'''
def im_kind(s:readbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > iv_word(s, 16):
        return IV_MAX
    return iv_word(s, identifier * 64)

def im_count(s:readbuf, identifier:u64) -> u64:
    return iv_word(s, identifier * 64 + 32)

def im_edge(s:readbuf, identifier:u64, index:u64) -> u64:
    first = iv_word(s, identifier * 64 + 24)
    return iv_word(s, 64 + iv_word(s, 16) * 64 + (first + index) * 8)

def im_equal(s:readbuf, left:u64, right:u64) -> u64:
    if left == right:
        return 1
    if im_kind(s, left) != 4 or im_kind(s, right) != 4:
        return 0
    size = iv_word(s, left * 64 + 16)
    if size != iv_word(s, right * 64 + 16):
        return 0
    a = iv_word(s, left * 64 + 8)
    b = iv_word(s, right * 64 + 8)
    index = 0
    while index < size:
        if byte(s, a + index) != byte(s, b + index):
            return 0
        index = index + 1
    return 1

def im_fixed(s:readbuf, identifier:u64, bytes:u64, word:u64) -> u64:
    if im_kind(s, identifier) != 4 or iv_word(s, identifier * 64 + 16) != bytes:
        return 0
    at = iv_word(s, identifier * 64 + 8)
    index = 0
    while index < bytes:
        if byte(s, at + index) != ((word >> (index * 8)) & 255):
            return 0
        index = index + 1
    return 1

def im_field_fixed(s:readbuf, mapping:u64, bytes:u64, word:u64) -> u64:
    if im_kind(s, mapping) != 6:
        return 0
    index = 0
    while index < im_count(s, mapping):
        if im_fixed(s, im_edge(s, mapping, index * 2), bytes, word) != 0:
            return im_edge(s, mapping, index * 2 + 1)
        index = index + 1
    return 0

def im_find(s:readbuf, mapping:u64, key:u64) -> u64:
    if im_kind(s, mapping) != 6:
        return IV_MAX
    index = 0
    while index < im_count(s, mapping):
        if im_equal(s, im_edge(s, mapping, index * 2), key) != 0:
            return index
        index = index + 1
    return IV_MAX

def im_map_valid(s:readbuf, w:mutbuf, mapping:u64) -> u64:
    if im_kind(s, mapping) != 6:
        return iv_bad(w, 70)
    index = 0
    while index < im_count(s, mapping):
        key = im_edge(s, mapping, index * 2)
        if im_kind(s, key) != 4:
            return iv_bad(w, 71)
        previous = 0
        while previous < index:
            if im_equal(s, im_edge(s, mapping, previous * 2), key) != 0:
                return iv_bad(w, 72)
            previous = previous + 1
        index = index + 1
    return 1

def im_initial(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 192 or length(s) < 64:
        return iv_bad(w, 40)
    index = 0
    while index < IM_MIN:
        if byte(w, index) != 0:
            return iv_bad(w, 41)
        index = index + 1
    if iv_word(r, 0) != IM_COMMAND or iv_word(r, 8) != 1:
        return iv_bad(w, 42)
    if iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 32) != 0:
        return iv_bad(w, 43)
    operation = iv_word(r, 40)
    if operation < 1 or operation > 6:
        return iv_bad(w, 44)
    if iv_word(r, 56) != length(s):
        return iv_bad(w, 45)
    if operation == 6:
        if iv_word(r, 64) != 0:
            return iv_bad(w, 46)
    elif iv_word(r, 64) == 0 or iv_word(r, 64) == iv_word(r, 48):
        return iv_bad(w, 47)
    index = 112
    while index < 192:
        if iv_word(r, index) != 0:
            return iv_bad(w, 48)
        index = index + 8
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return 0
    iv_put(w, M_MAGIC, IM_STATE)
    iv_put(w, M_STATUS, 1)
    iv_put(w, M_OP, operation)
    iv_put(w, M_NODES, iv_word(s, 16))
    iv_put(w, M_EDGES, iv_word(s, 32))
    iv_put(w, M_POOL, iv_word(s, 40))
    iv_put(w, M_SOURCE_BYTES, length(s))
    iv_put(w, M_OUT_LEASE, iv_word(r, 64))
    iv_put(w, M_SOURCE_LEASE, iv_word(r, 48))
    iv_put(w, M_INV, iv_word(r, 16))
    iv_put(w, M_CALL, iv_word(r, 24))
    iv_put(w, M_SOURCE_DATA, 64 + iv_word(s, 16) * 64 + iv_word(s, 32) * 8)
    copy_bytes(w, r, M_SAVED_COMMAND, 0, 192)
    copy_bytes(w, s, M_SAVED_SOURCE, 0, 64)
    return 1

def im_same(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 192 or length(s) != iv_get(w, M_SOURCE_BYTES):
        return iv_bad(w, 49)
    if iv_word(r, 8) != 2 or iv_word(r, 32) != iv_get(w, M_SEQ):
        return iv_bad(w, 50)
    index = 0
    while index < 192:
        if (index < 8 or index >= 16) and (index < 32 or index >= 40):
            if byte(r, index) != byte(w, M_SAVED_COMMAND + index):
                return iv_bad(w, 51)
        index = index + 1
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, M_SAVED_SOURCE + index):
            return iv_bad(w, 52)
        index = index + 1
    return 1

def im_arguments(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    operation = iv_get(w, M_OP)
    a = iv_word(r, 72)
    b = iv_word(r, 80)
    c = iv_word(r, 88)
    d = iv_word(r, 96)
    key = iv_word(r, 104)
    iv_put(w, M_PAIR_CAPACITY, 0)
    iv_put(w, M_PAIRS, 0)
    if operation == 1 or operation == 4:
        if b != 0 or c != 0 or d != 0 or key != 0:
            return iv_bad(w, 53)
        if operation == 1:
            a = im_field_fixed(s, a, 5, IM_TOOLS)
        if im_kind(s, a) != 5:
            return iv_bad(w, 54)
        iv_put(w, M_LIST, a)
        iv_put(w, M_PAIR_CAPACITY, im_count(s, a))
    elif operation == 2:
        if a != 0 or b != 0 or c != 0 or d != 0 or key != 0:
            return iv_bad(w, 55)
    else:
        if im_kind(s, key) != 4 or im_map_valid(s, w, a) == 0:
            return iv_bad(w, 56)
        if operation == 3:
            if im_map_valid(s, w, b) == 0:
                return 0
            if c == 0 or c > iv_get(w, M_NODES) or d == 0 or d > iv_get(w, M_NODES):
                return iv_bad(w, 57)
        else:
            if b != 0 or d != 0:
                return iv_bad(w, 58)
            if operation == 5:
                if c == 0 or c > iv_get(w, M_NODES):
                    return iv_bad(w, 59)
            elif c != 0:
                return iv_bad(w, 60)
    return 1

def im_pair(s:readbuf, w:mutbuf, key:u64, value:u64) -> u64:
    if im_kind(s, key) != 4 or value == 0 or value > iv_get(w, M_NODES):
        return iv_bad(w, 73)
    index = 0
    while index < iv_get(w, M_PAIRS):
        if im_equal(s, iv_get(w, IM_PAIRS + index * 16), key) != 0:
            iv_put(w, IM_PAIRS + index * 16 + 8, value)
            return 1
        index = index + 1
    iv_put(w, IM_PAIRS + index * 16, key)
    iv_put(w, IM_PAIRS + index * 16 + 8, value)
    iv_put(w, M_PAIRS, index + 1)
    return 1

def im_pairs(s:readbuf, w:mutbuf) -> u64:
    list_ = iv_get(w, M_LIST)
    index = 0
    while index < im_count(s, list_):
        item = im_edge(s, list_, index)
        key = 0
        value = 0
        if iv_get(w, M_OP) == 1:
            key = im_field_fixed(s, item, 4, IM_NAME)
            value = item
        else:
            if (im_kind(s, item) != 5 and im_kind(s, item) != 7) or im_count(s, item) != 2:
                return iv_bad(w, 74)
            key = im_edge(s, item, 0)
            value = im_edge(s, item, 1)
        if im_pair(s, w, key, value) == 0:
            return 0
        index = index + 1
    return 1

def im_counts(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    operation = iv_get(w, M_OP)
    zero = 0
    one = 0
    newnodes = 1
    if operation == 1 or operation == 4:
        zero = iv_get(w, M_PAIRS)
    elif operation == 2:
        newnodes = 2
    elif operation == 3 or operation == 5:
        a = iv_word(r, 72)
        key = iv_word(r, 104)
        zero = im_count(s, a)
        if im_find(s, a, key) == IV_MAX:
            zero = zero + 1
        if operation == 3:
            b = iv_word(r, 80)
            one = im_count(s, b)
            if im_find(s, b, key) == IV_MAX:
                one = one + 1
            newnodes = 2
    iv_put(w, M_COUNT0, zero)
    iv_put(w, M_COUNT1, one)
    nodes = iv_get(w, M_NODES)
    edges = iv_get(w, M_EDGES)
    if nodes > IV_MAX - newnodes:
        return iv_bad(w, 80)
    nodes = nodes + newnodes
    if nodes > (IV_MAX - 64) >> 6:
        return iv_bad(w, 81)
    if zero > IV_MAX - one or zero + one > (IV_MAX - edges) >> 1:
        return iv_bad(w, 82)
    edges = edges + (zero + one) * 2
    database = 64 + nodes * 64
    if edges > (IV_MAX - database) >> 3:
        return iv_bad(w, 83)
    database = database + edges * 8
    if iv_get(w, M_POOL) > IV_MAX - database:
        return iv_bad(w, 84)
    total = database + iv_get(w, M_POOL)
    if total > IV_MAX - iv_get(w, M_OUT_AT):
        return iv_bad(w, 85)
    iv_put(w, M_OUT_BYTES, total)
    iv_put(w, M_OUT_NODES, nodes)
    iv_put(w, M_OUT_EDGES, edges)
    iv_put(w, M_OUT_DATA, database)
    iv_put(w, M_NEED, iv_get(w, M_OUT_AT) + total)
    iv_put(w, M_ROOT0, iv_get(w, M_NODES) + 1)
    iv_put(w, M_ROOT1, choose(newnodes == 2, iv_get(w, M_NODES) + 2, 0))
    return 1

def im_copy(s:readbuf, w:mutbuf) -> u64:
    base = iv_get(w, M_OUT_AT)
    nodes = iv_get(w, M_NODES)
    edges = iv_get(w, M_EDGES)
    newnodes = iv_get(w, M_OUT_NODES)
    database = iv_get(w, M_OUT_DATA)
    copy_bytes(w, s, base + 64, 64, nodes * 64)
    identifier = 1
    while identifier <= nodes:
        kind = iv_word(s, identifier * 64)
        if kind == 2 or kind == 3 or kind == 4 or kind == 9:
            offset = iv_word(s, identifier * 64 + 8) - iv_get(w, M_SOURCE_DATA)
            iv_put(w, base + identifier * 64 + 8, database + offset)
        identifier = identifier + 1
    copy_bytes(w, s, base + 64 + newnodes * 64, 64 + nodes * 64, edges * 8)
    copy_bytes(w, s, base + database, iv_get(w, M_SOURCE_DATA), iv_get(w, M_POOL))
    fill_range(w, base + (nodes + 1) * 64, (newnodes - nodes) * 64, 0)
    iv_put(w, base, IV_GRAPH)
    iv_put(w, base + 8, iv_get(w, M_OUT_LEASE))
    iv_put(w, base + 16, newnodes)
    iv_put(w, base + 24, iv_get(w, M_ROOT0))
    iv_put(w, base + 32, iv_get(w, M_OUT_EDGES))
    iv_put(w, base + 40, iv_get(w, M_POOL))
    iv_put(w, base + 48, iv_get(w, M_OUT_BYTES))
    iv_put(w, base + 56, 0)
    return 1

def im_node(w:mutbuf, identifier:u64, first:u64, count:u64) -> u64:
    at = iv_get(w, M_OUT_AT) + identifier * 64
    iv_put(w, at, 6)
    iv_put(w, at + 24, first)
    iv_put(w, at + 32, count)
    iv_put(w, at + 40, identifier)
    return 0

def im_output_pair(w:mutbuf, index:u64, key:u64, value:u64) -> u64:
    at = iv_get(w, M_OUT_AT) + 64 + iv_get(w, M_OUT_NODES) * 64 + index * 8
    iv_put(w, at, key)
    iv_put(w, at + 8, value)
    return 0

def im_update(s:readbuf, w:mutbuf, mapping:u64, key:u64, value:u64, first:u64) -> u64:
    found = False
    index = 0
    while index < im_count(s, mapping):
        oldkey = im_edge(s, mapping, index * 2)
        oldvalue = im_edge(s, mapping, index * 2 + 1)
        if im_equal(s, oldkey, key) != 0:
            oldvalue = value
            found = True
        im_output_pair(w, first + index * 2, oldkey, oldvalue)
        index = index + 1
    if not found:
        im_output_pair(w, first + index * 2, key, value)
    return 0

def im_publish(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    operation = iv_get(w, M_OP)
    first = iv_get(w, M_EDGES)
    im_node(w, iv_get(w, M_ROOT0), first, iv_get(w, M_COUNT0))
    if operation == 1 or operation == 4:
        index = 0
        while index < iv_get(w, M_PAIRS):
            im_output_pair(w, first + index * 2,
                iv_get(w, IM_PAIRS + index * 16), iv_get(w, IM_PAIRS + index * 16 + 8))
            index = index + 1
    elif operation == 3 or operation == 5:
        im_update(s, w, iv_word(r, 72), iv_word(r, 104), iv_word(r, 88), first)
    if operation == 2 or operation == 3:
        first = first + iv_get(w, M_COUNT0) * 2
        im_node(w, iv_get(w, M_ROOT1), first, iv_get(w, M_COUNT1))
        if operation == 3:
            im_update(s, w, iv_word(r, 80), iv_word(r, 104), iv_word(r, 96), first)
    return 1

def im_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, M_SEQ)
    if sequence == IV_MAX:
        iv_put(w, M_STATUS, 3)
        return IV_BAD
    iv_put(w, M_SEQ, sequence + 1)
    fill_range(w, 512, 128, 0)
    iv_put(w, 512, IM_EVENT)
    iv_put(w, 520, action)
    iv_put(w, 528, iv_get(w, M_INV))
    iv_put(w, 536, iv_get(w, M_CALL))
    iv_put(w, 544, sequence + 1)
    iv_put(w, 552, iv_get(w, M_OP))
    iv_put(w, 560, iv_get(w, M_NEED))
    iv_put(w, 616, iv_get(w, V_BAD))
    iv_put(w, 624, iv_get(w, M_PAIRS))
    if action == 0:
        if iv_get(w, M_OP) == 6:
            iv_put(w, 568, 1)
            iv_put(w, 584, iv_get(w, M_SOURCE_BYTES))
            iv_put(w, 608, iv_get(w, M_SOURCE_LEASE))
        else:
            iv_put(w, 568, 2)
            iv_put(w, 576, iv_get(w, M_OUT_AT))
            iv_put(w, 584, iv_get(w, M_OUT_BYTES))
            iv_put(w, 608, iv_get(w, M_OUT_LEASE))
        iv_put(w, 592, iv_get(w, M_ROOT0))
        iv_put(w, 600, iv_get(w, M_ROOT1))
    return 640

def im_fail(w:mutbuf) -> u32:
    iv_put(w, M_STATUS, 3)
    im_event(w, 2)
    return IV_BAD

def initialization_maps(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < IM_MIN:
        return IV_BAD
    if iv_get(w, M_STATUS) >= 2:
        return IV_BAD
    if iv_get(w, M_MAGIC) == 0:
        if im_initial(s, r, w) == 0:
            return im_fail(w)
    else:
        if iv_get(w, M_MAGIC) != IM_STATE or im_same(s, r, w) == 0:
            iv_bad(w, 61)
            return im_fail(w)
    if im_arguments(s, r, w) == 0:
        return im_fail(w)
    if iv_get(w, M_OP) == 6:
        found = im_find(s, iv_word(r, 72), iv_word(r, 104))
        if found == IV_MAX:
            iv_bad(w, 62)
            return im_fail(w)
        iv_put(w, M_ROOT0, im_edge(s, iv_word(r, 72), found * 2 + 1))
        iv_put(w, M_STATUS, 2)
        return im_event(w, 0)
    capacity = iv_get(w, M_PAIR_CAPACITY)
    if capacity > (IV_MAX - IM_PAIRS) >> 4:
        iv_bad(w, 63)
        return im_fail(w)
    end = IM_PAIRS + capacity * 16
    iv_put(w, M_NEED, end)
    iv_put(w, M_OUT_AT, end)
    if end > length(w):
        return im_event(w, 1)
    if iv_get(w, M_OP) == 1 or iv_get(w, M_OP) == 4:
        if im_pairs(s, w) == 0:
            return im_fail(w)
    if im_counts(s, r, w) == 0:
        return im_fail(w)
    if iv_get(w, M_NEED) > length(w):
        return im_event(w, 1)
    im_copy(s, w)
    im_publish(s, r, w)
    iv_put(w, M_STATUS, 2)
    return im_event(w, 0)
'''
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}
def source_program():
    raw=HELPER.read_bytes();assert sha256(raw).hexdigest()==HELPER_SHA
    tree=ast.parse(raw)
    body=next(n.value.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets))
    keep={'iv_word','iv_get','iv_put','iv_bad','iv_valid_node','iv_shape'}
    shared=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef) and n.name in keep]
    assert {n.name for n in shared}==keep
    nodes=ast.parse(BODY).body+shared
    nodes.sort(key=lambda n:n.name!='initialization_maps')
    names={n.name for n in nodes};assert len(names)==len(nodes)
    for n in nodes:
        for call in ast.walk(n):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node) if node.id in CONSTANTS else node
    result=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(result))+'\n'
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(index+1) for index,node in enumerate(nodes)}
    sigs={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
                 attrs=dict(function=names['initialization_maps'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,sigs,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='worker_initialization_maps',
        functions=functions))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_worker_initialization_maps.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists()
    target.write_bytes(raw)
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        scope='INITIALIZER_NATIVE_VALUE_OPERATIONS_NEW_UNEXECUTED'),sort_keys=True),flush=True)
