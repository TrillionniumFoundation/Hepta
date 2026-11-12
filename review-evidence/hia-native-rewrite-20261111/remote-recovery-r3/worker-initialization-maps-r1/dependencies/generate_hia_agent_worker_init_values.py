"""Native complete Worker initialization value projection.

The static data file is generated from exact original expressions by
agent_worker_init_templates. Runtime identities, roots and references are
issued immutable HIAGRF01 inputs. HIA constructs every resulting value.
Matching header integers are correlation only; the fixed issuer must keep the
actual source and template mappings immutable throughout every GROW.

Source r2 splits node checking and cloning to keep live SSA parameters bounded.
No source revision has yet been generated or executed.
"""
from __future__ import annotations
import ast,json,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder

def magic(s):return int.from_bytes(s.encode('ascii'),'little')
CONSTANTS={
 'IV_CONFIG':magic('HIAWVC01'),'IV_STATE':magic('HIAWVS01'),
 'IV_EVENT':magic('HIAWVE01'),'IV_TEMPLATE':magic('HIAWVT01'),
 'IV_GRAPH':magic('HIAGRF01'),'IV_BAD':0xfffffffd,'IV_MAX':(1<<64)-1,
 'IV_MIN':4096,'IV_OUT':4096,'IV_EVENT_BASE':512,'IV_EVENT_END':640,
 'IV_TEMPLATE_LEASE':0x57565401,
 'V_MAGIC':0,'V_STATUS':8,'V_SEQ':16,'V_NEED':24,'V_BAD':32,'V_MODE':40,
 'V_SN':48,'V_SE':56,'V_SP':64,'V_TAT':72,'V_TSIZE':80,'V_TN':88,
 'V_TE':96,'V_TP':104,'V_ROOT':112,'V_OUTPUT_BYTES':120,
 'V_COUNT':320,'V_COUNT_BYTES':328,'V_DATABASE':336,'V_TOTAL_NODES':344,
 'V_TOTAL_EDGES':352,'V_TABLE':360,'V_SOURCE_BYTES':368,'V_TEMPLATE_BYTES':376,
 'V_CONFIG_COPY':768,'V_SOURCE_HEADER':960,'V_TEMPLATE_HEADER':1024,
 'V_TABLE_COPY':1088,'V_CLONE_BASE':384,'V_CLONE_NBASE':392,
 'V_CLONE_EBASE':400,'V_CLONE_PBASE':408,'V_CLONE_DATABASE':416,
}
BODY=r'''
def iv_word(s:readbuf, at:u64) -> u64:
    value = byte(s, at)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    return value | (byte(s, at + 7) << 56)

def iv_get(w:mutbuf, at:u64) -> u64:
    value = byte(w, at)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    return value | (byte(w, at + 7) << 56)

def iv_put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0

def iv_bad(w:mutbuf, reason:u64) -> u64:
    if iv_get(w, V_BAD) == 0:
        iv_put(w, V_BAD, reason)
    return 0

def iv_config(w:mutbuf, index:u64) -> u64:
    return iv_get(w, 128 + index * 8)

def iv_valid_node(s:readbuf, w:mutbuf, base:u64, size:u64, identifier:u64) -> u64:
    nodes = iv_word(s, base + 16)
    edges = iv_word(s, base + 32)
    end = 64 + nodes * 64 + edges * 8
    at = base + identifier * 64
    kind = iv_word(s, at)
    data = iv_word(s, at + 8)
    count = iv_word(s, at + 16)
    first = iv_word(s, at + 24)
    amount = iv_word(s, at + 32)
    identity = iv_word(s, at + 40)
    aux = iv_word(s, at + 48)
    if kind > 9 or iv_word(s, at + 56) != 0:
        return iv_bad(w, 17)
    if kind == 5 or kind == 6 or kind == 7:
        if data != 0 or count != 0 or identity != identifier or aux != 0:
            return iv_bad(w, 18)
        if kind == 6:
            if amount > IV_MAX >> 1:
                return iv_bad(w, 19)
            amount = amount * 2
        if first > edges or amount > edges - first:
            return iv_bad(w, 20)
    else:
        if first != 0 or amount != 0 or identity != 0:
            return iv_bad(w, 21)
        if kind == 0 or kind == 1 or kind == 8:
            if data != 0 or count != 0:
                return iv_bad(w, 22)
            if kind == 1:
                if aux > 1:
                    return iv_bad(w, 23)
            elif aux != 0:
                return iv_bad(w, 24)
        else:
            if data < end or data > size or count > size - data:
                return iv_bad(w, 25)
            if kind == 2:
                if aux > 1 or (count == 0 and aux != 0):
                    return iv_bad(w, 26)
                if count != 0:
                    if byte(s, base + data + count - 1) == 0:
                        return iv_bad(w, 27)
            elif kind == 3:
                if count != 8 or aux != 0:
                    return iv_bad(w, 28)
            elif kind == 9 and aux != 0:
                return iv_bad(w, 29)
    return 1

def iv_shape(s:readbuf, w:mutbuf, base:u64, size:u64, lease:u64) -> u64:
    if base > length(s) or size > length(s) - base or size < 64:
        return iv_bad(w, 10)
    if iv_word(s, base) != IV_GRAPH or iv_word(s, base + 8) != lease or lease == 0:
        return iv_bad(w, 11)
    if iv_word(s, base + 48) != size or iv_word(s, base + 56) != 0:
        return iv_bad(w, 12)
    nodes = iv_word(s, base + 16)
    edges = iv_word(s, base + 32)
    if nodes == 0 or nodes > (IV_MAX - 64) >> 6:
        return iv_bad(w, 13)
    end = 64 + nodes * 64
    if edges > (IV_MAX - end) >> 3:
        return iv_bad(w, 14)
    end = end + edges * 8
    if end > size or iv_word(s, base + 40) != size - end:
        return iv_bad(w, 15)
    root = iv_word(s, base + 24)
    if root == 0 or root > nodes:
        return iv_bad(w, 16)
    identifier = 1
    while identifier <= nodes:
        if iv_valid_node(s, w, base, size, identifier) == 0:
            return 0
        identifier = identifier + 1
    at = base + 64 + nodes * 64
    index = 0
    while index < edges:
        identifier = iv_word(s, at + index * 8)
        if identifier == 0 or identifier > nodes:
            return iv_bad(w, 30)
        index = index + 1
    return 1

def iv_template(t:readbuf, w:mutbuf) -> u64:
    if length(t) < 832 or iv_word(t, 0) != IV_TEMPLATE:
        return iv_bad(w, 40)
    if iv_word(t, 8) != 1 or iv_word(t, 16) != 6 or iv_word(t, 24) != length(t):
        return iv_bad(w, 41)
    if iv_word(t, 32) != 128 or iv_word(t, 40) != 64:
        return iv_bad(w, 42)
    if iv_word(t, 48) != 0 or iv_word(t, 56) != 0:
        return iv_bad(w, 43)
    index = 1
    end = 832
    while index <= 6:
        at = 64 + (index - 1) * 128
        start = iv_word(t, at + 8)
        size = iv_word(t, at + 16)
        if iv_word(t, at) != index or iv_word(t, at + 24) != IV_TEMPLATE_LEASE + index:
            return iv_bad(w, 44)
        if start < end or start > length(t) or size > length(t) - start or size < 64:
            return iv_bad(w, 45)
        if start - end > 7 or (start & 7) != 0:
            return iv_bad(w, 46)
        while end < start:
            if byte(t, end) != 0:
                return iv_bad(w, 47)
            end = end + 1
        if iv_word(t, at + 104) != 0 or iv_word(t, at + 112) != 0 or iv_word(t, at + 120) != 0:
            return iv_bad(w, 48)
        end = start + size
        index = index + 1
    if end != length(t):
        return iv_bad(w, 49)
    at = 64 + (iv_config(w, 5) - 1) * 128
    iv_put(w, V_TABLE, at)
    iv_put(w, V_TAT, iv_word(t, at + 8))
    iv_put(w, V_TSIZE, iv_word(t, at + 16))
    if iv_shape(t, w, iv_get(w, V_TAT), iv_get(w, V_TSIZE), iv_word(t, at + 24)) == 0:
        return 0
    base = iv_get(w, V_TAT)
    iv_put(w, V_TN, iv_word(t, base + 16))
    iv_put(w, V_TE, iv_word(t, base + 32))
    iv_put(w, V_TP, iv_word(t, base + 40))
    return 1

def iv_marker(t:readbuf, w:mutbuf, code:u64) -> u64:
    return iv_word(t, iv_get(w, V_TABLE) + 24 + code * 8)

def iv_kind(s:readbuf, identifier:u64) -> u64:
    return iv_word(s, identifier * 64)

def iv_digest(s:readbuf, identifier:u64) -> u64:
    at = identifier * 64
    if iv_word(s, at) != 4 or iv_word(s, at + 16) != 64 or iv_word(s, at + 48) != 64:
        return 0
    begin = iv_word(s, at + 8)
    index = 0
    while index < 64:
        ch = byte(s, begin + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        index = index + 1
    return 1

def iv_dynamic(s:readbuf, t:readbuf, w:mutbuf) -> u64:
    code = 1
    while code <= 9:
        placeholder = iv_marker(t, w, code)
        if placeholder != 0:
            if placeholder > iv_get(w, V_TN):
                return iv_bad(w, 50)
            if iv_word(t, iv_get(w, V_TAT) + placeholder * 64) != 8:
                return iv_bad(w, 51)
            previous = 1
            while previous < code:
                if iv_marker(t, w, previous) == placeholder:
                    return iv_bad(w, 52)
                previous = previous + 1
            identifier = iv_config(w, 6 + code)
            if identifier == 0 or identifier > iv_get(w, V_SN):
                return iv_bad(w, 53)
            kind = iv_kind(s, identifier)
            if code == 3:
                if kind != 5 and kind != 7:
                    return iv_bad(w, 54)
                count = iv_word(s, identifier * 64 + 32)
                iv_put(w, V_COUNT, count)
                size = 0
                while count != 0:
                    size = size + 1
                    count = count >> 8
                iv_put(w, V_COUNT_BYTES, size)
            elif code == 2 or code == 4:
                if iv_digest(s, identifier) == 0:
                    return iv_bad(w, 55)
            elif code == 9:
                if kind != 4:
                    return iv_bad(w, 56)
            elif kind != 6:
                return iv_bad(w, 57)
        code = code + 1
    identifier = 1
    while identifier <= iv_get(w, V_TN):
        if iv_word(t, iv_get(w, V_TAT) + identifier * 64) == 8:
            found = 0
            code = 1
            while code <= 9:
                if iv_marker(t, w, code) == identifier:
                    found = 1
                code = code + 1
            if found == 0:
                return iv_bad(w, 58)
        identifier = identifier + 1
    return 1

def iv_measure(t:readbuf, w:mutbuf) -> u64:
    a = iv_get(w, V_SN)
    b = iv_get(w, V_TN)
    if a > IV_MAX - b:
        return iv_bad(w, 60)
    nodes = a + b
    if nodes > (IV_MAX - 64) >> 6:
        return iv_bad(w, 61)
    a = iv_get(w, V_SE)
    b = iv_get(w, V_TE)
    if a > IV_MAX - b:
        return iv_bad(w, 62)
    edges = a + b
    database = 64 + nodes * 64
    if edges > (IV_MAX - database) >> 3:
        return iv_bad(w, 63)
    database = database + edges * 8
    total = database
    pool = iv_get(w, V_SP)
    if pool > IV_MAX - total:
        return iv_bad(w, 64)
    total = total + pool
    pool = iv_get(w, V_TP)
    if pool > IV_MAX - total:
        return iv_bad(w, 65)
    total = total + pool
    pool = iv_get(w, V_COUNT_BYTES)
    if pool > IV_MAX - total or total + pool > IV_MAX - IV_OUT:
        return iv_bad(w, 66)
    total = total + pool
    iv_put(w, V_DATABASE, database)
    iv_put(w, V_TOTAL_NODES, nodes)
    iv_put(w, V_TOTAL_EDGES, edges)
    iv_put(w, V_OUTPUT_BYTES, total)
    iv_put(w, V_NEED, IV_OUT + total)
    iv_put(w, V_ROOT, iv_get(w, V_SN) + iv_word(t, iv_get(w, V_TAT) + 24))
    return 1

def iv_map(t:readbuf, w:mutbuf, identifier:u64) -> u64:
    code = 1
    while code <= 9:
        if code != 3 and iv_marker(t, w, code) == identifier:
            return iv_config(w, 6 + code)
        code = code + 1
    return iv_get(w, V_SN) + identifier

def iv_clone_node(s:readbuf, t:readbuf, w:mutbuf, template:u64, identifier:u64) -> u64:
    at = iv_get(w, V_CLONE_BASE) + identifier * 64
    target = IV_OUT + (iv_get(w, V_CLONE_NBASE) + identifier) * 64
    copy_bytes(w, s, target, at, 64)
    kind = iv_word(s, at)
    if template != 0 and identifier == iv_marker(t, w, 3):
        iv_put(w, target, 2)
        iv_put(w, target + 8, iv_get(w, V_DATABASE) + iv_get(w, V_SP) + iv_get(w, V_TP))
        iv_put(w, target + 16, iv_get(w, V_COUNT_BYTES))
        iv_put(w, target + 48, 0)
    elif kind == 5 or kind == 6 or kind == 7:
        iv_put(w, target + 24, iv_get(w, V_CLONE_EBASE) + iv_word(s, at + 24))
        iv_put(w, target + 40, iv_get(w, V_CLONE_NBASE) + identifier)
    elif kind == 2 or kind == 3 or kind == 4 or kind == 9:
        iv_put(w, target + 8, iv_get(w, V_DATABASE) + iv_get(w, V_CLONE_PBASE) + iv_word(s, at + 8) - iv_get(w, V_CLONE_DATABASE))
    return 1

def iv_clone(s:readbuf, t:readbuf, w:mutbuf, template:u64) -> u64:
    base = 0
    nodes = iv_get(w, V_SN)
    edges = iv_get(w, V_SE)
    pool = iv_get(w, V_SP)
    iv_put(w, V_CLONE_NBASE, 0)
    iv_put(w, V_CLONE_EBASE, 0)
    iv_put(w, V_CLONE_PBASE, 0)
    if template != 0:
        base = iv_get(w, V_TAT)
        nodes = iv_get(w, V_TN)
        edges = iv_get(w, V_TE)
        pool = iv_get(w, V_TP)
        iv_put(w, V_CLONE_NBASE, iv_get(w, V_SN))
        iv_put(w, V_CLONE_EBASE, iv_get(w, V_SE))
        iv_put(w, V_CLONE_PBASE, iv_get(w, V_SP))
    database = 64 + nodes * 64 + edges * 8
    iv_put(w, V_CLONE_BASE, base)
    iv_put(w, V_CLONE_DATABASE, database)
    identifier = 1
    while identifier <= nodes:
        iv_clone_node(s, t, w, template, identifier)
        identifier = identifier + 1
    source = base + 64 + nodes * 64
    target = IV_OUT + 64 + iv_get(w, V_TOTAL_NODES) * 64 + iv_get(w, V_CLONE_EBASE) * 8
    index = 0
    while index < edges:
        value = iv_word(s, source + index * 8)
        if template != 0:
            value = iv_map(t, w, value)
        iv_put(w, target + index * 8, value)
        index = index + 1
    copy_bytes(w, s, IV_OUT + iv_get(w, V_DATABASE) + iv_get(w, V_CLONE_PBASE), base + database, pool)
    return 1

def iv_emit(s:readbuf, t:readbuf, w:mutbuf) -> u64:
    iv_clone(s, t, w, 0)
    iv_clone(t, t, w, 1)
    at = IV_OUT + iv_get(w, V_DATABASE) + iv_get(w, V_SP) + iv_get(w, V_TP)
    index = 0
    value = iv_get(w, V_COUNT)
    while index < iv_get(w, V_COUNT_BYTES):
        store(w, at + index, value & 255)
        value = value >> 8
        index = index + 1
    iv_put(w, IV_OUT, IV_GRAPH)
    iv_put(w, IV_OUT + 8, iv_config(w, 6))
    iv_put(w, IV_OUT + 16, iv_get(w, V_TOTAL_NODES))
    iv_put(w, IV_OUT + 24, iv_get(w, V_ROOT))
    iv_put(w, IV_OUT + 32, iv_get(w, V_TOTAL_EDGES))
    iv_put(w, IV_OUT + 40, iv_get(w, V_OUTPUT_BYTES) - iv_get(w, V_DATABASE))
    iv_put(w, IV_OUT + 48, iv_get(w, V_OUTPUT_BYTES))
    iv_put(w, IV_OUT + 56, 0)
    return 1

def iv_initial(s:readbuf, t:readbuf, w:mutbuf) -> u64:
    index = 0
    while index < IV_MIN:
        if index < 128 or index >= 320:
            if byte(w, index) != 0:
                return iv_bad(w, 70)
        index = index + 1
    if iv_config(w, 0) != IV_CONFIG or iv_config(w, 1) == 0 or iv_config(w, 2) == 0:
        return iv_bad(w, 71)
    if iv_config(w, 3) == 0 or iv_config(w, 4) != length(s) or iv_config(w, 6) == 0:
        return iv_bad(w, 72)
    mode = iv_config(w, 5)
    if mode == 0 or mode > 6:
        return iv_bad(w, 73)
    index = 16
    while index < 24:
        if iv_config(w, index) != 0:
            return iv_bad(w, 74)
        index = index + 1
    iv_put(w, V_MAGIC, IV_STATE)
    iv_put(w, V_STATUS, 1)
    iv_put(w, V_MODE, mode)
    if iv_shape(s, w, 0, length(s), iv_config(w, 3)) == 0:
        return 0
    iv_put(w, V_SN, iv_word(s, 16))
    iv_put(w, V_SE, iv_word(s, 32))
    iv_put(w, V_SP, iv_word(s, 40))
    iv_put(w, V_SOURCE_BYTES, length(s))
    iv_put(w, V_TEMPLATE_BYTES, length(t))
    if iv_template(t, w) == 0 or iv_dynamic(s, t, w) == 0:
        return 0
    if iv_measure(t, w) == 0:
        return 0
    index = 0
    while index < 192:
        store(w, V_CONFIG_COPY + index, byte(w, 128 + index))
        index = index + 1
    copy_bytes(w, s, V_SOURCE_HEADER, 0, 64)
    copy_bytes(w, t, V_TEMPLATE_HEADER, 0, 64)
    copy_bytes(w, t, V_TABLE_COPY, iv_get(w, V_TABLE), 128)
    return 1

def iv_same(s:readbuf, t:readbuf, w:mutbuf) -> u64:
    if length(s) != iv_get(w, V_SOURCE_BYTES) or length(t) != iv_get(w, V_TEMPLATE_BYTES):
        return iv_bad(w, 80)
    index = 0
    while index < 192:
        if byte(w, 128 + index) != byte(w, V_CONFIG_COPY + index):
            return iv_bad(w, 81)
        index = index + 1
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, V_SOURCE_HEADER + index):
            return iv_bad(w, 82)
        if byte(t, index) != byte(w, V_TEMPLATE_HEADER + index):
            return iv_bad(w, 83)
        index = index + 1
    index = 0
    while index < 128:
        if byte(t, iv_get(w, V_TABLE) + index) != byte(w, V_TABLE_COPY + index):
            return iv_bad(w, 84)
        index = index + 1
    return 1

def iv_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, V_SEQ)
    if sequence == IV_MAX:
        iv_put(w, V_STATUS, 3)
        return IV_BAD
    iv_put(w, V_SEQ, sequence + 1)
    fill_range(w, IV_EVENT_BASE, 128, 0)
    iv_put(w, IV_EVENT_BASE, IV_EVENT)
    iv_put(w, IV_EVENT_BASE + 8, action)
    iv_put(w, IV_EVENT_BASE + 16, iv_config(w, 1))
    iv_put(w, IV_EVENT_BASE + 24, iv_config(w, 2))
    iv_put(w, IV_EVENT_BASE + 32, sequence + 1)
    iv_put(w, IV_EVENT_BASE + 40, iv_get(w, V_MODE))
    iv_put(w, IV_EVENT_BASE + 48, iv_get(w, V_NEED))
    iv_put(w, IV_EVENT_BASE + 56, IV_OUT)
    iv_put(w, IV_EVENT_BASE + 64, iv_get(w, V_OUTPUT_BYTES))
    iv_put(w, IV_EVENT_BASE + 72, iv_get(w, V_ROOT))
    iv_put(w, IV_EVENT_BASE + 80, iv_config(w, 6))
    iv_put(w, IV_EVENT_BASE + 88, iv_get(w, V_SN))
    iv_put(w, IV_EVENT_BASE + 96, iv_get(w, V_TN))
    iv_put(w, IV_EVENT_BASE + 104, iv_get(w, V_BAD))
    return IV_EVENT_END

def iv_refuse(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, V_STATUS, 3)
    iv_event(w, 2)
    return IV_BAD

def init_values(s:readbuf, t:readbuf, w:mutbuf) -> u32:
    if length(w) < IV_MIN:
        return IV_BAD
    if iv_get(w, V_STATUS) == 3:
        return IV_BAD
    if iv_get(w, V_MAGIC) == 0:
        if iv_initial(s, t, w) == 0:
            return iv_refuse(w, 90)
    else:
        if iv_get(w, V_MAGIC) != IV_STATE or iv_get(w, V_STATUS) != 1:
            return iv_refuse(w, 91)
        if iv_same(s, t, w) == 0:
            return iv_refuse(w, 92)
    if iv_get(w, V_NEED) > length(w):
        return iv_event(w, 1)
    iv_emit(s, t, w)
    iv_put(w, V_STATUS, 2)
    return iv_event(w, 0)
'''
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}
def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    nodes=ast.parse(BODY).body
    assert all(isinstance(node,ast.FunctionDef) for node in nodes)
    nodes.sort(key=lambda node:node.name!='init_values')
    names={node.name for node in nodes}
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS
    tree=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(index+1) for index,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
      blocks=[dict(id='b0',params=params,ops=[
        dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
        dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
             attrs=dict(function=names['init_values'])),
        dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(value) for value in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='agent_worker_initialization_values',
        functions=functions))
    fs=value['functions']
    counts=(len(fs),sum(len(fn['blocks']) for fn in fs),
        sum(len(block['ops']) for fn in fs for block in fn['blocks']),
        max(len(fn['blocks']) for fn in fs),
        max(len(block['params']) for fn in fs for block in fn['blocks']))
    assert all(actual<=limit for actual,limit in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value)
    return value

if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    path=ROOT/'examples/hia_bootstrap/agent_worker_initialization_values.hiaasm'
    path.parent.mkdir(parents=True,exist_ok=True)
    assert not path.exists(),'preserve every generated source revision'
    path.write_bytes(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(fn['blocks']) for fn in fs),
        instructions=sum(len(block['ops']) for fn in fs for block in fn['blocks']),
        max_function_blocks=max(len(fn['blocks']) for fn in fs),
        max_block_parameters=max(len(block['params']) for fn in fs for block in fn['blocks']),
        scope='WORKER_INITIALIZATION_VALUES_SOURCE_ONLY'),sort_keys=True),flush=True)
