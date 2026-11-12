"""Complete Service initializer ordering in HIA, private service ABI draft.

NEW UNEXECUTED source r3. Path-to-string evaluation remains after all is_dir
calls, separately from publishing the resolved-Path tuple. This owns all constructor/profile/example sequencing
and exact attribute-publication points. Complete catalog, namespace, Path,
generic value and assembly peers must still be joined under a fixed issuer;
a synthetic handle or foreign test ACK is not a production service.
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
def magic(value):return int.from_bytes(value.encode('ascii'),'little')
CONSTANTS={
 'IS_CONFIG':magic('HIAWIC01'),'IS_STATE':magic('HIAWIW01'),
 'IS_REPLY':magic('HIAWIR01'),'IS_EVENT':magic('HIAWIE01'),
 'IS_SNAPSHOT':magic('HIAWIP01'),'IS_GRAPH':magic('HIAGRF01'),
 'IS_BAD':0xfffffffd,'IS_MAX':(1<<64)-1,'IS_MIN':8192,
 'IS_EVENT_AT':2048,'IS_EVENT_END':2304,'IS_SNAPSHOT_AT':4096,
 'IS_TEXT':5120,'IS_BINDINGS':6144,'IS_ROOTS':8192,
 'IS_SAVED_CONFIG':2560,'IS_SAVED_SOURCE':2816,'IS_SAVED_REPLY':2944,
 'P_CATALOG':1,'P_TOOLS':2,'P_INSTALL':3,'P_OPEN':4,'P_RESOLVE':5,
 'P_ISDIR':6,'P_ROOTS_VALUE':7,'P_DIGEST':8,'P_VALUES':9,'P_MAPS':10,
 'P_PROFILE':11,'P_STATIC':12,'P_FILE':13,'P_PUT':14,'P_JSON':15,
 'P_VERIFY':16,'P_RENDER':17,'P_ASSEMBLE':18,'P_LOOKUP':19,
}
NAMES=('MAGIC','STATUS','PHASE','SEQ','NEED','BAD_REASON','INV','CALL','DIGITS',
 'SOURCE_LEASE','SOURCE_BYTES','SOURCE_ROOT','SOURCE_NODES','SOURCE_EDGES',
 'SOURCE_EDGEBASE','STATE_ROOT','INPUT_ROOTS','ROOT_COUNT','ROOT_INDEX','DIR_INDEX',
 'PRESENCE','CATALOG','CATALOG_DIGEST','TOOLS','IDENTITIES','STORE',
 'ROOTS_TUPLE','ROOT_STRINGS','ROOT_DIGEST','BODIES','PROFILES','ARTIFACTS',
 'RESOURCES','MANIFEST','PROFILE_INDEX','RESOURCE_INDEX','VALUE','VALUE2',
 'PROGRAM','PROGRAM_CORE','PROGRAM_DIGEST','ASSEMBLY','ASSEMBLY_BYTES',
 'DIGEST0','DIGEST1','DIGEST2','DIGEST3',
 'PEER','PENDING','HAVE_REPLY','REPLY_BYTES','R_KIND','R_ONE','R_TWO','R_THREE',
 'R_AUTHORITY','R_NATIVE','OP','ARG0','ARG1','ARG2','ARG3','ARG4','ARG5',
 'VIEW_OWNER','VIEW_AT','VIEW_BYTES','LITERAL_BYTES',
 'ERROR_CLASS','ERROR_OWNER','ERROR_LEASE','ERROR_AT','ERROR_BYTES',
 'INITIAL_RESOURCE0','INITIAL_RESOURCE1','INITIAL_RESOURCE2',
 'INITIAL_RESOURCE3','INITIAL_RESOURCE4','INITIAL_RESOURCE5')
CONSTANTS.update({'I_'+name:1024+8*i for i,name in enumerate(NAMES)})
PROFILE_NAMES=('compiler','target','backend','artifact','validation','lowering','plan')
RESOURCE_NAMES=('schema_registry','workload_schema','objective_schema','cost_policy_schema',
 'plan_schema','proof_contract','assembly_grammar','core_language','machine_plan_guide',
 'proof_contract_guide','machine_validation_guide','buffer_lifecycle_guide',
 'macro_policy_guide','byte_bootstrap_guide','self_hosting_core_guide',
 'self_hosting_core_support','macro_policy','examples','diagnostics')
FILES=('docs/HIA_AGENT_ASSEMBLY.md','docs/HIA_PROGRAM.md','docs/HIA_AGENT_MACHINE_PLANS.md',
 'docs/HIA_AGENT_PROOF_RESULTS.md','docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md',
 'docs/HIA_AGENT_BUFFER_LIFECYCLE.md','docs/HIA_AGENT_MACRO_POLICY.md',
 'docs/HIA_DIRECT_BYTE_BOOTSTRAP.md','docs/HIA_SELF_HOSTING_CORE.md',
 'docs/HIA_SELFHOST_CORE_SUPPORT.json')
LITERALS={1:b'configured artifact roots must be directories',
 2:b'discovery example does not round-trip',3:b'discovery'}
LITERALS.update({100+i:name.encode() for i,name in enumerate(PROFILE_NAMES)})
LITERALS.update({200+i:('hia-'+name+'-v1').encode() for i,name in enumerate(PROFILE_NAMES)})
LITERALS.update({300+i:name.encode() for i,name in enumerate(RESOURCE_NAMES)})
LITERALS.update({400+i:name.encode() for i,name in enumerate(FILES)})
BODY=r'''
def is_word(s:readbuf, at:u64) -> u64:
    value = byte(s, at)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    return value | (byte(s, at + 7) << 56)

def is_get(w:mutbuf, at:u64) -> u64:
    value = byte(w, at)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    return value | (byte(w, at + 7) << 56)

def is_put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0

def is_bad(w:mutbuf, reason:u64) -> u64:
    if is_get(w, I_BAD_REASON) == 0:
        is_put(w, I_BAD_REASON, reason)
    is_put(w, I_STATUS, 6)
    return 0

def is_mark(w:mutbuf, bit:u64) -> u64:
    is_put(w, I_PRESENCE, is_get(w, I_PRESENCE) | (1 << bit))
    return 0

def is_node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > is_get(w, I_SOURCE_NODES):
        is_bad(w, 10)
        return 0
    return identifier * 64

def is_kind(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = is_node(s, w, identifier)
    if at == 0:
        return IS_MAX
    return is_word(s, at)

def is_item(s:readbuf, w:mutbuf, identifier:u64, index:u64) -> u64:
    at = is_node(s, w, identifier)
    if at == 0:
        return 0
    kind = is_word(s, at)
    if kind != 5 and kind != 7:
        is_bad(w, 11)
        return 0
    if index >= is_word(s, at + 32):
        is_bad(w, 12)
        return 0
    first = is_word(s, at + 24)
    if first > is_get(w, I_SOURCE_EDGES) or index >= is_get(w, I_SOURCE_EDGES) - first:
        is_bad(w, 13)
        return 0
    return is_word(s, is_get(w, I_SOURCE_EDGEBASE) + (first + index) * 8)

def is_initial(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 0 or length(s) < 64:
        return is_bad(w, 20)
    index = 0
    while index < IS_MIN:
        if index < 128 or index >= 320:
            if byte(w, index) != 0:
                return is_bad(w, 21)
        index = index + 1
    if is_get(w, 128) != IS_CONFIG or is_get(w, 136) == 0 or is_get(w, 144) == 0:
        return is_bad(w, 22)
    if is_get(w, 152) == 0 or is_get(w, 160) != length(s):
        return is_bad(w, 23)
    digits = is_get(w, 176)
    if digits != 0 and digits < 640:
        return is_bad(w, 24)
    index = 184
    while index < 320:
        if is_get(w, index) != 0:
            return is_bad(w, 25)
        index = index + 8
    if is_word(s, 0) != IS_GRAPH or is_word(s, 8) != is_get(w, 152):
        return is_bad(w, 26)
    if is_word(s, 48) != length(s) or is_word(s, 56) != 0:
        return is_bad(w, 27)
    nodes = is_word(s, 16)
    edges = is_word(s, 32)
    if nodes == 0 or nodes > (IS_MAX - 64) >> 6:
        return is_bad(w, 28)
    database = 64 + nodes * 64
    if edges > (IS_MAX - database) >> 3:
        return is_bad(w, 29)
    edgebase = database
    database = database + edges * 8
    if database > length(s) or is_word(s, 40) != length(s) - database:
        return is_bad(w, 30)
    is_put(w, I_MAGIC, IS_STATE)
    is_put(w, I_STATUS, 1)
    is_put(w, I_PHASE, 1)
    is_put(w, I_INV, is_get(w, 136))
    is_put(w, I_CALL, is_get(w, 144))
    is_put(w, I_SOURCE_LEASE, is_get(w, 152))
    is_put(w, I_SOURCE_BYTES, length(s))
    is_put(w, I_SOURCE_ROOT, is_get(w, 168))
    is_put(w, I_DIGITS, digits)
    is_put(w, I_SOURCE_NODES, nodes)
    is_put(w, I_SOURCE_EDGES, edges)
    is_put(w, I_SOURCE_EDGEBASE, edgebase)
    root = is_get(w, I_SOURCE_ROOT)
    if is_kind(s, w, root) != 5 or is_word(s, root * 64 + 32) != 2:
        return is_bad(w, 31)
    state = is_item(s, w, root, 0)
    roots = is_item(s, w, root, 1)
    if is_kind(s, w, state) != 4 or is_kind(s, w, roots) != 5:
        return is_bad(w, 32)
    is_put(w, I_STATE_ROOT, state)
    is_put(w, I_INPUT_ROOTS, roots)
    is_put(w, I_ROOT_COUNT, is_word(s, roots * 64 + 32))
    count = is_get(w, I_ROOT_COUNT)
    first = is_word(s, roots * 64 + 24)
    if first > edges or count > edges - first or count > (IS_MAX - IS_ROOTS) >> 4:
        return is_bad(w, 33)
    index = 0
    while index < count:
        if is_kind(s, w, is_item(s, w, roots, index)) != 4:
            return is_bad(w, 34)
        index = index + 1
    index = 0
    while index < 192:
        store(w, IS_SAVED_CONFIG + index, byte(w, 128 + index))
        index = index + 1
    copy_bytes(w, s, IS_SAVED_SOURCE, 0, 64)
    return 1

def is_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != is_get(w, I_SOURCE_BYTES):
        return is_bad(w, 35)
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, IS_SAVED_SOURCE + index):
            return is_bad(w, 36)
        index = index + 1
    index = 0
    while index < 192:
        if byte(w, 128 + index) != byte(w, IS_SAVED_CONFIG + index):
            return is_bad(w, 37)
        index = index + 1
    return 1

def is_request(w:mutbuf, peer:u64, phase:u64, op:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u64:
    is_put(w, I_PEER, peer)
    is_put(w, I_PHASE, phase)
    is_put(w, I_STATUS, 2)
    is_put(w, I_HAVE_REPLY, 0)
    is_put(w, I_OP, op)
    is_put(w, I_ARG0, a)
    is_put(w, I_ARG1, b)
    is_put(w, I_ARG2, c)
    is_put(w, I_ARG3, d)
    is_put(w, I_ARG4, e)
    is_put(w, I_ARG5, f)
    return 0

def is_clear_view(w:mutbuf) -> u64:
    is_put(w, I_VIEW_OWNER, 0)
    is_put(w, I_VIEW_AT, 0)
    is_put(w, I_VIEW_BYTES, 0)
    is_put(w, I_LITERAL_BYTES, 0)
    return 0

def is_call(w:mutbuf, peer:u64, phase:u64, op:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u64:
    is_clear_view(w)
    return is_request(w, peer, phase, op, a, b, c, d, e, f)

def is_named(w:mutbuf, peer:u64, phase:u64, op:u64, a:u64, b:u64, c:u64, d:u64, name:u64) -> u64:
    is_clear_view(w)
    is_put(w, I_LITERAL_BYTES, is_literal(w, name))
    return is_request(w, peer, phase, op, a, b, c, d, 0, 0)

def is_receive(r:readbuf, w:mutbuf) -> u64:
    if length(r) < 256 or is_word(r, 0) != IS_REPLY:
        return is_bad(w, 40)
    if is_word(r, 8) != is_get(w, I_INV) or is_word(r, 16) != is_get(w, I_CALL):
        return is_bad(w, 41)
    if is_word(r, 24) != is_get(w, I_PENDING) or is_word(r, 32) != is_get(w, I_PEER):
        return is_bad(w, 42)
    if is_word(r, 40) > 1 or is_word(r, 120) != length(r):
        return is_bad(w, 43)
    index = 160
    while index < 256:
        if is_word(r, index) != 0:
            return is_bad(w, 44)
        index = index + 8
    is_put(w, I_REPLY_BYTES, length(r))
    copy_bytes(w, r, IS_SAVED_REPLY, 0, 256)
    is_put(w, I_HAVE_REPLY, 1)
    is_put(w, I_STATUS, 1)
    if is_word(r, 40) != 0:
        if is_word(r, 96) == 0:
            return is_bad(w, 45)
        at = is_word(r, 104)
        size = is_word(r, 112)
        if at < 256 or at > length(r) or size > length(r) - at:
            return is_bad(w, 46)
        is_put(w, I_ERROR_CLASS, 0)
        is_put(w, I_ERROR_OWNER, 3)
        is_put(w, I_ERROR_LEASE, is_word(r, 96))
        is_put(w, I_ERROR_AT, at)
        is_put(w, I_ERROR_BYTES, size)
        is_put(w, I_STATUS, 4)
        return 1
    if length(r) != 256 or is_word(r, 96) != 0 or is_word(r, 104) != 0 or is_word(r, 112) != 0:
        return is_bad(w, 49)
    kind = is_word(r, 48)
    if kind != 7 and kind != 11:
        index = 128
        while index < 160:
            if is_word(r, index) != 0:
                return is_bad(w, 58)
            index = index + 8
    is_put(w, I_R_KIND, kind)
    is_put(w, I_R_NATIVE, is_word(r, 56))
    is_put(w, I_R_ONE, is_word(r, 64))
    is_put(w, I_R_TWO, is_word(r, 72))
    is_put(w, I_R_THREE, is_word(r, 80))
    is_put(w, I_R_AUTHORITY, is_word(r, 88))
    return 1

def is_same_reply(r:readbuf, w:mutbuf) -> u64:
    if length(r) != is_get(w, I_REPLY_BYTES):
        return is_bad(w, 47)
    index = 0
    while index < 256:
        if byte(r, index) != byte(w, IS_SAVED_REPLY + index):
            return is_bad(w, 48)
        index = index + 1
    return 1

def is_result(w:mutbuf, kind:u64, count:u64, authority:u64) -> u64:
    if is_get(w, I_HAVE_REPLY) == 0 or is_get(w, I_R_KIND) != kind:
        return is_bad(w, 50)
    if count >= 1 and is_get(w, I_R_ONE) == 0:
        return is_bad(w, 51)
    if count >= 2 and is_get(w, I_R_TWO) == 0:
        return is_bad(w, 52)
    if count >= 3 and is_get(w, I_R_THREE) == 0:
        return is_bad(w, 53)
    if authority != 0 and is_get(w, I_R_AUTHORITY) == 0:
        return is_bad(w, 54)
    if authority == 0 and is_get(w, I_R_AUTHORITY) != 0:
        return is_bad(w, 59)
    if count == 0 and kind != 5 and is_get(w, I_R_ONE) != 0:
        return is_bad(w, 64)
    if count < 2 and is_get(w, I_R_TWO) != 0:
        return is_bad(w, 65)
    if count < 3 and is_get(w, I_R_THREE) != 0:
        return is_bad(w, 66)
    return 1

def is_error(w:mutbuf, kind:u64, literal:u64) -> u64:
    is_put(w, I_ERROR_CLASS, kind)
    is_put(w, I_ERROR_OWNER, 2)
    is_put(w, I_ERROR_LEASE, is_get(w, I_INV))
    is_put(w, I_ERROR_AT, IS_TEXT)
    is_put(w, I_ERROR_BYTES, is_literal(w, literal))
    is_put(w, I_STATUS, 4)
    return 0

def is_value(w:mutbuf, mode:u64, phase:u64) -> u64:
    return is_call(w, P_VALUES, phase, mode,
        is_get(w, I_IDENTITIES), is_get(w, I_CATALOG_DIGEST),
        is_get(w, I_ROOT_STRINGS), is_get(w, I_ROOT_DIGEST),
        is_get(w, I_PROGRAM_CORE), is_get(w, I_ASSEMBLY))

def is_ctor_step(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    phase = is_get(w, I_PHASE)
    if phase == 1:
        return is_call(w, P_CATALOG, 2, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        if is_result(w, 1, 2, 0) == 0:
            return 0
        is_put(w, I_CATALOG, is_get(w, I_R_ONE))
        is_put(w, I_CATALOG_DIGEST, is_get(w, I_R_TWO))
        is_mark(w, 0)
        return is_call(w, P_TOOLS, 3, 0, is_get(w, I_CATALOG), 0, 0, 0, 0, 0)
    if phase == 3:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_TOOLS, is_get(w, I_R_ONE))
        is_mark(w, 1)
        return is_call(w, P_INSTALL, 4, 0, 0, 0, 0, 0, 0, 0)
    if phase == 4:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_IDENTITIES, is_get(w, I_R_ONE))
        is_mark(w, 2)
        is_clear_view(w)
        is_put(w, I_VIEW_OWNER, 1)
        is_put(w, I_VIEW_BYTES, length(s))
        return is_request(w, P_OPEN, 5, 0, is_get(w, I_STATE_ROOT), is_get(w, I_SOURCE_LEASE), 0, 0, 0, 0)
    if phase == 5:
        if is_result(w, 3, 0, 1) == 0:
            return 0
        is_put(w, I_STORE, is_get(w, I_R_AUTHORITY))
        is_mark(w, 3)
        is_put(w, I_PHASE, 6)
        return 0
    if phase == 6:
        need = IS_ROOTS + is_get(w, I_ROOT_COUNT) * 16
        if need > length(w):
            is_put(w, I_NEED, need)
            return 0
        is_put(w, I_PHASE, 7)
        return 0
    if phase == 7:
        index = is_get(w, I_ROOT_INDEX)
        if index == is_get(w, I_ROOT_COUNT):
            is_clear_view(w)
            is_put(w, I_VIEW_OWNER, 2)
            is_put(w, I_VIEW_AT, IS_ROOTS)
            is_put(w, I_VIEW_BYTES, index * 16)
            return is_request(w, P_ROOTS_VALUE, 10, 0, index, 0, 0, 0, 0, 0)
        value = is_item(s, w, is_get(w, I_INPUT_ROOTS), index)
        if is_get(w, I_STATUS) == 6:
            return 0
        is_clear_view(w)
        is_put(w, I_VIEW_OWNER, 1)
        is_put(w, I_VIEW_BYTES, length(s))
        return is_request(w, P_RESOLVE, 8, 0, value, is_get(w, I_SOURCE_LEASE), index, 0, 0, 0)
    if phase == 8:
        if is_result(w, 4, 1, 1) == 0:
            return 0
        index = is_get(w, I_ROOT_INDEX)
        is_put(w, IS_ROOTS + index * 16, is_get(w, I_R_AUTHORITY))
        is_put(w, IS_ROOTS + index * 16 + 8, is_get(w, I_R_ONE))
        is_put(w, I_ROOT_INDEX, index + 1)
        is_put(w, I_PHASE, 7)
        return 0
    if phase == 10:
        if is_result(w, 6, 0, 1) == 0:
            return 0
        is_put(w, I_ROOTS_TUPLE, is_get(w, I_R_AUTHORITY))
        is_mark(w, 4)
        is_put(w, I_PHASE, 11)
        return 0
    if phase == 11:
        index = is_get(w, I_DIR_INDEX)
        if index == is_get(w, I_ROOT_COUNT):
            return is_call(w, P_ROOTS_VALUE, 13, 1, is_get(w, I_ROOTS_TUPLE),
                is_get(w, I_ROOT_COUNT), 0, 0, 0, 0)
        return is_call(w, P_ISDIR, 12, 0, is_get(w, IS_ROOTS + index * 16), index, 0, 0, 0, 0)
    if phase == 12:
        if is_result(w, 5, 0, 1) == 0:
            return 0
        if is_get(w, I_R_AUTHORITY) != is_get(w, IS_ROOTS + is_get(w, I_DIR_INDEX) * 16):
            return is_bad(w, 55)
        value = is_get(w, I_R_ONE)
        if value > 1:
            return is_bad(w, 56)
        if value == 0:
            return is_error(w, 1, 1)
        is_put(w, I_DIR_INDEX, is_get(w, I_DIR_INDEX) + 1)
        is_put(w, I_PHASE, 11)
        return 0
    if phase == 13:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_ROOT_STRINGS, is_get(w, I_R_ONE))
        return is_call(w, P_DIGEST, 14, 0, is_get(w, I_ROOT_STRINGS), 0, 0, 0, 0, 0)
    if phase == 14:
        if is_result(w, 7, 1, 0) == 0:
            return 0
        is_put(w, I_ROOT_DIGEST, is_get(w, I_R_ONE))
        return is_value(w, 1, 30)
    return is_bad(w, 57)

def is_profile_step(w:mutbuf) -> u64:
    phase = is_get(w, I_PHASE)
    if phase == 30:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_BODIES, is_get(w, I_R_ONE))
        return is_call(w, P_MAPS, 31, 1, 0, 0, 0, 0, 0, 0)
    if phase == 31:
        if is_result(w, 8, 2, 0) == 0:
            return 0
        is_put(w, I_PROFILES, is_get(w, I_R_ONE))
        is_put(w, I_ARTIFACTS, is_get(w, I_R_TWO))
        is_mark(w, 5)
        is_mark(w, 6)
        is_put(w, I_PHASE, 32)
        return 0
    if phase == 32:
        index = is_get(w, I_PROFILE_INDEX)
        if index == 7:
            is_put(w, I_PHASE, 40)
            return 0
        return is_named(w, P_LOOKUP, 33, 0, is_get(w, I_BODIES), 0, 0, 0, 100 + index)
    if phase == 33:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_VALUE, is_get(w, I_R_ONE))
        return is_named(w, P_PROFILE, 34, 0, is_get(w, I_VALUE), is_get(w, I_STORE),
            0, 0, 200 + is_get(w, I_PROFILE_INDEX))
    if phase == 34:
        if is_result(w, 9, 2, 0) == 0:
            return 0
        return is_named(w, P_MAPS, 35, 2, is_get(w, I_PROFILES), is_get(w, I_ARTIFACTS),
            is_get(w, I_R_ONE), is_get(w, I_R_TWO), 100 + is_get(w, I_PROFILE_INDEX))
    if phase == 35:
        if is_result(w, 8, 2, 0) == 0:
            return 0
        is_put(w, I_PROFILES, is_get(w, I_R_ONE))
        is_put(w, I_ARTIFACTS, is_get(w, I_R_TWO))
        is_put(w, I_PROFILE_INDEX, is_get(w, I_PROFILE_INDEX) + 1)
        is_put(w, I_PHASE, 32)
        return 0
    return is_bad(w, 60)

def is_resource_bindings(w:mutbuf) -> u64:
    index = 0
    at = IS_BINDINGS + 192
    while index < 6:
        size = is_literal(w, 300 + index)
        is_put(w, IS_BINDINGS + index * 32, at - IS_BINDINGS)
        is_put(w, IS_BINDINGS + index * 32 + 8, size)
        is_put(w, IS_BINDINGS + index * 32 + 16, is_get(w, I_INITIAL_RESOURCE0 + index * 8))
        is_put(w, IS_BINDINGS + index * 32 + 24, 0)
        offset = 0
        while offset < size:
            store(w, at + offset, byte(w, IS_TEXT + offset))
            offset = offset + 1
        at = at + size
        index = index + 1
    is_clear_view(w)
    is_put(w, I_VIEW_OWNER, 2)
    is_put(w, I_VIEW_AT, IS_BINDINGS)
    is_put(w, I_VIEW_BYTES, at - IS_BINDINGS)
    return is_request(w, P_MAPS, 43, 3, 6, 0, 0, 0, 0, 0)

def is_json(w:mutbuf, value:u64, phase:u64) -> u64:
    return is_named(w, P_JSON, phase, 0, value, is_get(w, I_STORE), 0, 0, 3)

def is_resource_assign(w:mutbuf, value:u64, phase:u64) -> u64:
    return is_named(w, P_MAPS, phase, 4, is_get(w, I_RESOURCES), value, 0, 0,
        300 + is_get(w, I_RESOURCE_INDEX))

def is_resource_step(w:mutbuf) -> u64:
    phase = is_get(w, I_PHASE)
    if phase == 40:
        index = is_get(w, I_RESOURCE_INDEX)
        if index == 6:
            return is_resource_bindings(w)
        return is_call(w, P_STATIC, 41, index + 1, 0, 0, 0, 0, 0, 0)
    if phase == 41:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_json(w, is_get(w, I_R_ONE), 42)
    if phase == 42:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        index = is_get(w, I_RESOURCE_INDEX)
        is_put(w, I_INITIAL_RESOURCE0 + index * 8, is_get(w, I_R_ONE))
        is_put(w, I_RESOURCE_INDEX, index + 1)
        is_put(w, I_PHASE, 40)
        return 0
    if phase == 43:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_RESOURCES, is_get(w, I_R_ONE))
        is_mark(w, 7)
        is_put(w, I_PHASE, 44)
        return 0
    if phase == 44:
        index = is_get(w, I_RESOURCE_INDEX)
        if index == 16:
            return is_value(w, 6, 60)
        return is_named(w, P_FILE, 45, 0, 0, 0, 0, 0, 400 + index - 6)
    if phase == 45:
        if is_result(w, 10, 1, 0) == 0:
            return 0
        return is_named(w, P_PUT, 46, 0, is_get(w, I_R_ONE), is_get(w, I_STORE), 0, 0, 3)
    if phase == 46:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_resource_assign(w, is_get(w, I_R_ONE), 47)
    if phase == 47:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_RESOURCES, is_get(w, I_R_ONE))
        is_put(w, I_RESOURCE_INDEX, is_get(w, I_RESOURCE_INDEX) + 1)
        is_put(w, I_PHASE, 44)
        return 0
    return is_bad(w, 61)

def is_example_step(r:readbuf, w:mutbuf) -> u64:
    phase = is_get(w, I_PHASE)
    if phase == 60:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_json(w, is_get(w, I_R_ONE), 61)
    if phase == 61:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_resource_assign(w, is_get(w, I_R_ONE), 62)
    if phase == 62:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_RESOURCES, is_get(w, I_R_ONE))
        is_put(w, I_RESOURCE_INDEX, 17)
        return is_value(w, 4, 63)
    if phase == 63:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_call(w, P_VERIFY, 64, 0, is_get(w, I_R_ONE), 0, 0, 0, 0, 0)
    if phase == 64:
        if is_result(w, 11, 3, 0) == 0:
            return 0
        is_put(w, I_PROGRAM, is_get(w, I_R_ONE))
        is_put(w, I_PROGRAM_CORE, is_get(w, I_R_TWO))
        is_put(w, I_PROGRAM_DIGEST, is_get(w, I_R_THREE))
        is_put(w, I_DIGEST0, is_word(r, 128))
        is_put(w, I_DIGEST1, is_word(r, 136))
        is_put(w, I_DIGEST2, is_word(r, 144))
        is_put(w, I_DIGEST3, is_word(r, 152))
        return is_call(w, P_RENDER, 65, 0, is_get(w, I_PROGRAM), 0, 0, 0, 0, 0)
    if phase == 65:
        if is_result(w, 12, 2, 0) == 0:
            return 0
        is_put(w, I_ASSEMBLY, is_get(w, I_R_ONE))
        is_put(w, I_ASSEMBLY_BYTES, is_get(w, I_R_TWO))
        return is_call(w, P_ASSEMBLE, 66, 0, is_get(w, I_ASSEMBLY), 0, 0, 0, 0, 0)
    if phase == 66:
        if is_result(w, 11, 3, 0) == 0:
            return 0
        if is_word(r, 128) != is_get(w, I_DIGEST0) or is_word(r, 136) != is_get(w, I_DIGEST1):
            return is_error(w, 2, 2)
        if is_word(r, 144) != is_get(w, I_DIGEST2) or is_word(r, 152) != is_get(w, I_DIGEST3):
            return is_error(w, 2, 2)
        return is_value(w, 5, 67)
    if phase == 67:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_json(w, is_get(w, I_R_ONE), 68)
    if phase == 68:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_resource_assign(w, is_get(w, I_R_ONE), 69)
    if phase == 69:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_RESOURCES, is_get(w, I_R_ONE))
        is_put(w, I_RESOURCE_INDEX, 18)
        return is_value(w, 2, 70)
    return is_bad(w, 62)

def is_finish_step(w:mutbuf) -> u64:
    phase = is_get(w, I_PHASE)
    if phase == 70:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_json(w, is_get(w, I_R_ONE), 71)
    if phase == 71:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_resource_assign(w, is_get(w, I_R_ONE), 72)
    if phase == 72:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_RESOURCES, is_get(w, I_R_ONE))
        is_put(w, I_RESOURCE_INDEX, 19)
        is_clear_view(w)
        is_put(w, I_VIEW_OWNER, 2)
        is_put(w, I_VIEW_AT, IS_BINDINGS)
        is_put(w, I_VIEW_BYTES, 24)
        is_put(w, IS_BINDINGS, is_get(w, I_PROFILES))
        is_put(w, IS_BINDINGS + 8, is_get(w, I_ARTIFACTS))
        is_put(w, IS_BINDINGS + 16, is_get(w, I_RESOURCES))
        return is_request(w, P_VALUES, 73, 3, is_get(w, I_IDENTITIES),
            is_get(w, I_CATALOG_DIGEST), is_get(w, I_ROOT_STRINGS),
            is_get(w, I_ROOT_DIGEST), 0, 0)
    if phase == 73:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        return is_json(w, is_get(w, I_R_ONE), 74)
    if phase == 74:
        if is_result(w, 2, 1, 0) == 0:
            return 0
        is_put(w, I_MANIFEST, is_get(w, I_R_ONE))
        is_mark(w, 8)
        is_put(w, I_STATUS, 3)
        return 0
    return is_bad(w, 63)

def is_snapshot(w:mutbuf) -> u64:
    fill_range(w, IS_SNAPSHOT_AT, 512, 0)
    is_put(w, IS_SNAPSHOT_AT, IS_SNAPSHOT)
    is_put(w, IS_SNAPSHOT_AT + 8, is_get(w, I_INV))
    is_put(w, IS_SNAPSHOT_AT + 16, is_get(w, I_CALL))
    is_put(w, IS_SNAPSHOT_AT + 24, is_get(w, I_PRESENCE))
    is_put(w, IS_SNAPSHOT_AT + 32, is_get(w, I_CATALOG))
    is_put(w, IS_SNAPSHOT_AT + 40, is_get(w, I_CATALOG_DIGEST))
    is_put(w, IS_SNAPSHOT_AT + 48, is_get(w, I_TOOLS))
    is_put(w, IS_SNAPSHOT_AT + 56, is_get(w, I_IDENTITIES))
    is_put(w, IS_SNAPSHOT_AT + 64, is_get(w, I_STORE))
    is_put(w, IS_SNAPSHOT_AT + 72, is_get(w, I_ROOTS_TUPLE))
    is_put(w, IS_SNAPSHOT_AT + 80, is_get(w, I_PROFILES))
    is_put(w, IS_SNAPSHOT_AT + 88, is_get(w, I_ARTIFACTS))
    is_put(w, IS_SNAPSHOT_AT + 96, is_get(w, I_RESOURCES))
    is_put(w, IS_SNAPSHOT_AT + 104, is_get(w, I_MANIFEST))
    is_put(w, IS_SNAPSHOT_AT + 112, is_get(w, I_ROOT_COUNT))
    is_put(w, IS_SNAPSHOT_AT + 120, is_get(w, I_ROOT_INDEX))
    is_put(w, IS_SNAPSHOT_AT + 128, is_get(w, I_DIR_INDEX))
    is_put(w, IS_SNAPSHOT_AT + 136, is_get(w, I_PROFILE_INDEX))
    is_put(w, IS_SNAPSHOT_AT + 144, is_get(w, I_RESOURCE_INDEX))
    is_put(w, IS_SNAPSHOT_AT + 152, IS_ROOTS)
    is_put(w, IS_SNAPSHOT_AT + 160, is_get(w, I_ROOT_INDEX) * 16)
    is_put(w, IS_SNAPSHOT_AT + 168, is_get(w, I_ROOT_STRINGS))
    is_put(w, IS_SNAPSHOT_AT + 176, is_get(w, I_ROOT_DIGEST))
    is_put(w, IS_SNAPSHOT_AT + 184, is_get(w, I_BODIES))
    return 0

def is_event(w:mutbuf, action:u64) -> u32:
    sequence = is_get(w, I_SEQ)
    if sequence == IS_MAX:
        is_put(w, I_STATUS, 6)
        return IS_BAD
    is_put(w, I_SEQ, sequence + 1)
    if action == 2:
        is_put(w, I_PENDING, sequence + 1)
    is_snapshot(w)
    fill_range(w, IS_EVENT_AT, 256, 0)
    is_put(w, IS_EVENT_AT, IS_EVENT)
    is_put(w, IS_EVENT_AT + 8, action)
    is_put(w, IS_EVENT_AT + 16, is_get(w, I_INV))
    is_put(w, IS_EVENT_AT + 24, is_get(w, I_CALL))
    is_put(w, IS_EVENT_AT + 32, sequence + 1)
    is_put(w, IS_EVENT_AT + 40, is_get(w, I_PHASE))
    is_put(w, IS_EVENT_AT + 64, choose(action == 1, is_get(w, I_NEED), 0))
    is_put(w, IS_EVENT_AT + 72, is_get(w, I_SOURCE_LEASE))
    is_put(w, IS_EVENT_AT + 80, is_get(w, I_SOURCE_ROOT))
    is_put(w, IS_EVENT_AT + 88, is_get(w, I_DIGITS))
    is_put(w, IS_EVENT_AT + 96, is_get(w, I_STORE))
    if action == 2:
        is_put(w, IS_EVENT_AT + 48, is_get(w, I_PEER))
        is_put(w, IS_EVENT_AT + 56, sequence + 1)
        is_put(w, IS_EVENT_AT + 104, is_get(w, I_OP))
        index = 0
        while index < 6:
            is_put(w, IS_EVENT_AT + 112 + index * 8, is_get(w, I_ARG0 + index * 8))
            index = index + 1
        is_put(w, IS_EVENT_AT + 160, is_get(w, I_VIEW_OWNER))
        is_put(w, IS_EVENT_AT + 168, is_get(w, I_VIEW_AT))
        is_put(w, IS_EVENT_AT + 176, is_get(w, I_VIEW_BYTES))
        is_put(w, IS_EVENT_AT + 184, IS_TEXT)
        is_put(w, IS_EVENT_AT + 192, is_get(w, I_LITERAL_BYTES))
    is_put(w, IS_EVENT_AT + 200, IS_SNAPSHOT_AT)
    is_put(w, IS_EVENT_AT + 208, 512)
    if action == 3:
        is_put(w, IS_EVENT_AT + 216, is_get(w, I_ERROR_CLASS))
        is_put(w, IS_EVENT_AT + 224, is_get(w, I_ERROR_OWNER))
        is_put(w, IS_EVENT_AT + 232, is_get(w, I_ERROR_LEASE))
        is_put(w, IS_EVENT_AT + 240, is_get(w, I_ERROR_AT))
        is_put(w, IS_EVENT_AT + 248, is_get(w, I_ERROR_BYTES))
    return IS_EVENT_END

def init_sequence(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < IS_MIN:
        return IS_BAD
    if is_get(w, I_STATUS) >= 3:
        return IS_BAD
    if is_get(w, I_MAGIC) == 0:
        if is_initial(s, r, w) == 0:
            return IS_BAD
    else:
        if is_get(w, I_MAGIC) != IS_STATE or is_same(s, w) == 0:
            is_bad(w, 70)
            return IS_BAD
    if is_get(w, I_STATUS) == 2:
        if is_receive(r, w) == 0:
            return IS_BAD
    elif is_get(w, I_HAVE_REPLY) != 0:
        if is_same_reply(r, w) == 0:
            return IS_BAD
    while is_get(w, I_STATUS) == 1:
        is_put(w, I_NEED, 0)
        phase = is_get(w, I_PHASE)
        if phase < 30:
            is_ctor_step(s, r, w)
        elif phase < 40:
            is_profile_step(w)
        elif phase < 60:
            is_resource_step(w)
        elif phase < 70:
            is_example_step(r, w)
        else:
            is_finish_step(w)
        if is_get(w, I_NEED) > length(w):
            return is_event(w, 1)
    status = is_get(w, I_STATUS)
    if status == 2:
        return is_event(w, 2)
    if status == 3:
        return is_event(w, 0)
    if status == 4:
        return is_event(w, 3)
    return IS_BAD
'''
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}
def literal_source():
    lines=['def is_literal(w:mutbuf, code:u64) -> u64:']
    for code,raw in sorted(LITERALS.items()):
        assert len(raw)<=1024
        lines.append('    if code == '+str(code)+':')
        for at in range(0,len(raw),8):
            value=int.from_bytes(raw[at:at+8].ljust(8,b'\0'),'little')
            lines.append('        is_put(w, IS_TEXT + '+str(at)+', '+str(value)+')')
        lines.append('        return '+str(len(raw)))
    lines.extend(['    is_bad(w, 80)','    return 0'])
    return '\n'.join(lines)+'\n'
def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in CONSTANTS:return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    nodes=ast.parse(BODY+'\n'+literal_source()).body
    assert all(isinstance(node,ast.FunctionDef) for node in nodes)
    nodes.sort(key=lambda n:n.name!='init_sequence')
    names={n.name for n in nodes}
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS
    value=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(value))+'\n'
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
                 attrs=dict(function=names['init_sequence'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,sigs,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='worker_initialization_sequence',
        functions=functions))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_worker_initialization_sequence.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists()
    target.write_bytes(raw);fs=value['functions']
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        scope='INITIALIZATION_SEQUENCE_NEW_SOURCE_NOT_JOINED_NAMESPACE'),sort_keys=True),flush=True)
