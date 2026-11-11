"""Shared HIA-only private edit coordination and fixed executor protocol.

The referenced older code is immutable authoring input. This module does not
execute hosted admission, query, patch or JSON policy at runtime.
"""
import ast,importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
old=module('edit_frozen_lower_common',BASE/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py')
CONSTANTS=dict(old.CONSTANTS)
def magic(s):return int.from_bytes(s.encode(),'little')
CONSTANTS.update(dict(EDIT_STATE=magic('HIAECS01'),EDIT_INIT=magic('HIAECI01'),MAIN=56,QUERY=57,SERVICE=58,APPLY=59,
    B_PROGRAM=1,B_QUERY_GRAPH=4,B_RESPONSE_GRAPH=5,B_PROGRAM_FRAME=6,B_CORE=7,B_CORE_SOURCE=8,
    B_COMMAND=9,B_KERNEL=10,B_SELECTED_SOURCE=11,B_FACTS=12,B_SLICE=13,B_QUERY_RESULT=14,
    B_PREPARED_WIRE=15,B_UNTRUSTED_WIRE=16,B_RESPONSE_RAW=17,B_RESPONSE_VALUE=18,
    B_PENDING_GRAPH=19,B_ENVELOPE=20,B_CANDIDATE=21,B_PATCH_RECEIPT=22,B_FINAL_RECEIPT=23,
    B_DECODE_ARENA=50,B_DECODE_WORK=51,B_CODEC=52,B_PACKET_JSON=28,B_PACKET_WORK=29,
    B_SHA_INPUT=61,B_SHA_OUTPUT=62,B_SHA_WORK=63,INPUT_LIMIT=8<<20,NODES=262144,DEPTH=64,
    ARENA_MAGIC=5208772604367785521,JSON_PACKET_MAGIC=magic('HIAJPK01'),PROGRAM_RECEIPT=magic('HIAPRV01')))
MAIN_FIELDS=('MODE','DIGITS','REQUEST','CORE_BYTES','INPUT_BYTES','KIND','VERSION','CORE_VERSION',
    'CHILD_LEASE','CHILD_SEQUENCE','CHILD_TARGET','RELEASE','ARENA_BYTES','WORK_BYTES','ARENA_USED',
    'NODE_COUNT','CODEC_BYTES','PACKET_BYTES','INDEX_BYTES','QUERY_ROOT','RESPONSE_ROOT',
    'STAGE','RESULT_SLOT','RESULT_BYTES','ERROR_GROUP','ERROR_CODE','ERROR_CLASS','ERROR_BYTES')
CONSTANTS.update({'E_'+v:16384+8*i for i,v in enumerate(MAIN_FIELDS)})
CONSTANTS.update(E_INPUT_HASH=16768,E_CORE_HASH=16800,E_ACTUAL_CORE_HASH=16832,E_CHILD_EVENT=16864,
    E_QUERY_HASH=16992,E_RESPONSE_HASH=17024,E_SIMPLE_EVENT=17152)
BOUND_FIELDS=('POLICY','RAW_TARGET','GRAPH_TARGET','RETURN_DRIVER','RETURN_PHASE','REQUEST','RAW_AT','RAW_BYTES',
    'GRAPH_AT','GRAPH_BYTES','ERROR_AT','ERROR_BYTES','RELEASE_SLOT','ACTION','ERROR_CODE','CAUSE','DETAIL','DOMAIN')
CONSTANTS.update({'D_'+v:18000+8*i for i,v in enumerate(BOUND_FIELDS)})
CONSTANTS.update(BOUND_COMMAND=magic('HIAQWC01'),BOUND_EVENT=magic('HIAQWE01'),BOUND_RESULT=magic('HIAQWO01'))
SERVICE_FIELDS=('STATE','KIND','SOURCE_SLOT','SOURCE_OFFSET','SOURCE_BYTES','COMMAND_SLOT','COMMAND_OFFSET',
    'COMMAND_BYTES','INITIAL_WORK','RETURN_DRIVER','RETURN_PHASE','RESULT_SLOT','RESULT_BYTES','RESULT_CODE',
    'RESULT_EVENT_OFFSET','RESULT_EVENT_BYTES')
CONSTANTS.update({'S_'+v:28672+8*i for i,v in enumerate(SERVICE_FIELDS)})
CONSTANTS.update(S_RESULT_EVENT=28800,B_FINAL_OUTPUT=30,EDIT_RESULT=magic('HIAEDR01'))
PUBLISH_FIELDS=('FIRST','FIRST_AT','FIRST_BYTES','SECOND','SECOND_AT','SECOND_BYTES','THIRD','THIRD_AT','THIRD_BYTES',
    'TOTAL','DOMAIN','STAGE','CODE','ERROR_SOURCE','ERROR_AT','ERROR_BYTES')
CONSTANTS.update({'PUBLISH_'+v:28000+8*i for i,v in enumerate(PUBLISH_FIELDS)})
SIMPLE_FIELDS=('STATE','IMAGE','FIRST','OFFSET','SIZE','SECOND','SECOND_BYTES','WORK','INITIAL','EVENT_MAGIC',
    'EVENT_OFFSET','COMMAND','COMMAND_BYTES','RETURN','LEASE','REQUEST','SEQUENCE','ACTION','NEEDED')
CONSTANTS.update({'G_'+v:30464+8*i for i,v in enumerate(SIMPLE_FIELDS)})
HASH_FIELDS=('HASH_SLOT','HASH_BYTES','HASH_TO','HASH_RETURN','HASH_OFFSET','HASH_CHUNK','HASH_AT')
CONSTANTS.update({'M_'+v:31232+8*i for i,v in enumerate(HASH_FIELDS)})

COMMON=old.COMMON.replace('or image > 23:',
    'or image > 63 or (image >= 40 and image <= 46) or (image >= 56 and image <= 59):')
COMMON=COMMON.replace('if target < 40 or target > 42 or target == get(w, L_DRIVER):',
    'if target < 56 or target > 59 or target == get(w, L_DRIVER):')
COMMON=COMMON.replace('if pending != 1 and pending != 14 and word(s, 40) != 0:',
    'if pending != 1 and pending != 14 and pending != 15 and word(s, 40) != 0:')
assert COMMON!=old.COMMON

HELPERS=r'''
def maximum(a:u64, b:u64) -> u64:
    if a > b:
        return a
    return b

def edit_service_start(w:mutbuf, kind:u64, source:u64, offset:u64, size:u64, command:u64, command_at:u64, command_bytes:u64, initial:u64, driver:u64, phase:u64) -> u64:
    if kind < 1 or kind > 6 or initial < 128:
        return refuse(w, 1001)
    if driver != MAIN and driver != QUERY and driver != APPLY:
        return refuse(w, 1002)
    if inside(w, source, offset, size) == 0 or inside(w, command, command_at, command_bytes) == 0:
        return refuse(w, 1003)
    slot = 32
    while slot < 50:
        if cap(w, slot) != 0:
            return refuse(w, 1004)
        slot = slot + 1
    if get(w, S_STATE) == 1:
        return refuse(w, 1005)
    zero(w, S_STATE, 384)
    put(w, S_STATE, 1)
    put(w, S_KIND, kind)
    put(w, S_SOURCE_SLOT, source)
    put(w, S_SOURCE_OFFSET, offset)
    put(w, S_SOURCE_BYTES, size)
    put(w, S_COMMAND_SLOT, command)
    put(w, S_COMMAND_OFFSET, command_at)
    put(w, S_COMMAND_BYTES, command_bytes)
    put(w, S_INITIAL_WORK, initial)
    put(w, S_RETURN_DRIVER, driver)
    put(w, S_RETURN_PHASE, phase)
    return 0

def edit_simple_start(w:mutbuf, image:u64, first:u64, offset:u64, size:u64, second:u64, secondbytes:u64, work:u64, initial:u64, magic:u64, event_at:u64, command:u64, commandbytes:u64, next:u64) -> u64:
    if work < 4 or work >= 64 or cap(w, work) != 0 or initial < event_at + 128:
        return refuse(w, 1010)
    if get(w, G_STATE) == 1 or commandbytes < 64 or inside(w, command, 0, commandbytes) == 0:
        return refuse(w, 1011)
    if command != first and command != second:
        return refuse(w, 1012)
    if inside(w, first, offset, size) == 0 or inside(w, second, 0, secondbytes) == 0:
        return refuse(w, 1013)
    zero(w, G_STATE, 160)
    put(w, G_STATE, 1)
    put(w, G_IMAGE, image)
    put(w, G_FIRST, first)
    put(w, G_OFFSET, offset)
    put(w, G_SIZE, size)
    put(w, G_SECOND, second)
    put(w, G_SECOND_BYTES, secondbytes)
    put(w, G_WORK, work)
    put(w, G_INITIAL, initial)
    put(w, G_EVENT_MAGIC, magic)
    put(w, G_EVENT_OFFSET, event_at)
    put(w, G_COMMAND, command)
    put(w, G_COMMAND_BYTES, commandbytes)
    put(w, G_RETURN, next)
    put(w, C_PHASE, 40000)
    return 0

def edit_simple_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if get(w, G_STATE) != 1:
        return refuse(w, 1014)
    if phase == 40000:
        return view(o, w, get(w, G_COMMAND), 0, 64, 40001)
    if phase == 40001:
        if get(w, OBS + 8) != 1 or get(w, OBS + 16) == 0 or get(w, OBS + 24) == 0 or get(w, OBS + 32) != 0:
            return refuse(w, 1015)
        put(w, G_LEASE, get(w, OBS + 16))
        put(w, G_REQUEST, get(w, OBS + 24))
        return grow(o, w, get(w, G_WORK), get(w, G_INITIAL), 40002)
    if phase == 40002:
        return invoke(o, w, get(w, G_IMAGE), get(w, G_FIRST), get(w, G_OFFSET), get(w, G_SIZE), get(w, G_SECOND), get(w, G_SECOND_BYTES), get(w, G_WORK), cap(w, get(w, G_WORK)), get(w, G_WORK), get(w, G_EVENT_OFFSET), 128, 40003)
    if phase == 40003:
        if get(w, C_RETURN) != get(w, G_EVENT_OFFSET) + 128 or get(w, OBS) != get(w, G_EVENT_MAGIC):
            return refuse(w, 1016)
        if get(w, OBS + 16) != get(w, G_LEASE) or get(w, OBS + 24) != get(w, G_REQUEST) or get(w, G_SEQUENCE) == MAX or get(w, OBS + 32) != get(w, G_SEQUENCE) + 1:
            return refuse(w, 1017)
        put(w, G_SEQUENCE, get(w, OBS + 32))
        action = get(w, OBS + 8)
        if action == 1:
            if get(w, OBS + 40) <= cap(w, get(w, G_WORK)):
                return refuse(w, 1018)
            put(w, G_NEEDED, get(w, OBS + 40))
            return protect(o, w, get(w, G_COMMAND), 0, 40004)
        if action != 0 and action != 2:
            return refuse(w, 1019)
        copy_local(w, E_SIMPLE_EVENT, OBS, 128)
        put(w, G_STATE, 2)
        put(w, C_PHASE, get(w, G_RETURN))
        return 0
    if phase == 40004:
        put(w, WIRE, 2)
        return copy(o, w, B_CONTROLLER, WIRE, get(w, G_COMMAND), 8, 8, 40005)
    if phase == 40005:
        put(w, WIRE, get(w, G_SEQUENCE))
        return copy(o, w, B_CONTROLLER, WIRE, get(w, G_COMMAND), 32, 8, 40006)
    if phase == 40006:
        return grow(o, w, get(w, G_WORK), get(w, G_NEEDED), 40002)
    return refuse(w, 1020)

def copy_local(w:mutbuf, to:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, to + i, byte(w, at + i))
        i = i + 1
    return 0

def copy_digest(w:mutbuf, to:u64, at:u64) -> u64:
    return copy_local(w, to, at, 32)

def same_digest(w:mutbuf, a:u64, b:u64) -> u64:
    i = 0
    while i < 32:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def hash_start(w:mutbuf, slot:u64, size:u64, to:u64, next:u64) -> u64:
    return hash_view_start(w, slot, 0, size, to, next)

def hash_view_start(w:mutbuf, slot:u64, at:u64, size:u64, to:u64, next:u64) -> u64:
    if inside(w, slot, at, size) == 0 or size == MAX:
        return refuse(w, 1021)
    put(w, M_HASH_SLOT, slot)
    put(w, M_HASH_AT, at)
    put(w, M_HASH_BYTES, size)
    put(w, M_HASH_TO, to)
    put(w, M_HASH_RETURN, next)
    put(w, M_HASH_OFFSET, 0)
    put(w, C_PHASE, 300)
    return 0

def edit_result_start(w:mutbuf, first:u64, first_at:u64, first_bytes:u64, second:u64, second_at:u64, second_bytes:u64, third:u64, third_at:u64, third_bytes:u64) -> u64:
    if inside(w, first, first_at, first_bytes) == 0 or inside(w, second, second_at, second_bytes) == 0 or inside(w, third, third_at, third_bytes) == 0:
        return refuse(w, 1030)
    if first == B_FINAL_OUTPUT or second == B_FINAL_OUTPUT or third == B_FINAL_OUTPUT or cap(w, B_FINAL_OUTPUT) != 0:
        return refuse(w, 1031)
    if first_bytes > MAX - 64 or second_bytes > MAX - 64 - first_bytes or third_bytes > MAX - 64 - first_bytes - second_bytes:
        return refuse(w, 1032)
    put(w, PUBLISH_FIRST, first)
    put(w, PUBLISH_FIRST_AT, first_at)
    put(w, PUBLISH_FIRST_BYTES, first_bytes)
    put(w, PUBLISH_SECOND, second)
    put(w, PUBLISH_SECOND_AT, second_at)
    put(w, PUBLISH_SECOND_BYTES, second_bytes)
    put(w, PUBLISH_THIRD, third)
    put(w, PUBLISH_THIRD_AT, third_at)
    put(w, PUBLISH_THIRD_BYTES, third_bytes)
    put(w, PUBLISH_TOTAL, 64 + first_bytes + second_bytes + third_bytes)
    put(w, PUBLISH_DOMAIN, 0)
    put(w, PUBLISH_STAGE, 0)
    put(w, PUBLISH_CODE, 0)
    put(w, C_PHASE, 45000)
    return 0

def edit_error_start(w:mutbuf, domain:u64, stage:u64, code:u64, source:u64, offset:u64, size:u64) -> u64:
    if domain == 0 or domain > 4 or inside(w, source, offset, size) == 0 or source == B_FINAL_OUTPUT or cap(w, B_FINAL_OUTPUT) != 0:
        return refuse(w, 1033)
    put(w, PUBLISH_DOMAIN, domain)
    put(w, PUBLISH_STAGE, stage)
    put(w, PUBLISH_CODE, code)
    put(w, PUBLISH_ERROR_SOURCE, source)
    put(w, PUBLISH_ERROR_AT, offset)
    put(w, PUBLISH_ERROR_BYTES, size)
    put(w, PUBLISH_TOTAL, size)
    put(w, C_PHASE, 45010)
    return 0

def edit_publish_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 45000:
        return grow(o, w, B_FINAL_OUTPUT, get(w, PUBLISH_TOTAL), 45001)
    if phase == 45001:
        wire8(w, EDIT_RESULT, get(w, E_MODE), get(w, PUBLISH_FIRST_BYTES), get(w, PUBLISH_SECOND_BYTES), get(w, PUBLISH_THIRD_BYTES), 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_FINAL_OUTPUT, 0, 64, 45002)
    if phase == 45002:
        return copy(o, w, get(w, PUBLISH_FIRST), get(w, PUBLISH_FIRST_AT), B_FINAL_OUTPUT, 64, get(w, PUBLISH_FIRST_BYTES), 45003)
    if phase == 45003:
        return copy(o, w, get(w, PUBLISH_SECOND), get(w, PUBLISH_SECOND_AT), B_FINAL_OUTPUT, 64 + get(w, PUBLISH_FIRST_BYTES), get(w, PUBLISH_SECOND_BYTES), 45004)
    if phase == 45004:
        return copy(o, w, get(w, PUBLISH_THIRD), get(w, PUBLISH_THIRD_AT), B_FINAL_OUTPUT, 64 + get(w, PUBLISH_FIRST_BYTES) + get(w, PUBLISH_SECOND_BYTES), get(w, PUBLISH_THIRD_BYTES), 45005)
    if phase == 45005:
        return protect(o, w, B_FINAL_OUTPUT, 1, 45006)
    if phase == 45006:
        return edit_terminal(o, w)
    if phase == 45010:
        if get(w, PUBLISH_TOTAL) == 0:
            return edit_terminal(o, w)
        return grow(o, w, B_FINAL_OUTPUT, get(w, PUBLISH_TOTAL), 45011)
    if phase == 45011:
        return copy(o, w, get(w, PUBLISH_ERROR_SOURCE), get(w, PUBLISH_ERROR_AT), B_FINAL_OUTPUT, 0, get(w, PUBLISH_ERROR_BYTES), 45005)
    return refuse(w, 1034)

def edit_terminal(o:mutbuf, w:mutbuf) -> u32:
    if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0:
        return refuse(w, 1035)
    put(w, L_STATUS, 2)
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, get(w, PUBLISH_DOMAIN))
    put(o, 40, get(w, PUBLISH_CODE))
    if get(w, PUBLISH_TOTAL) != 0:
        put(o, 48, B_FINAL_OUTPUT)
        put(o, 64, get(w, PUBLISH_TOTAL))
    put(o, 72, get(w, E_MODE))
    put(o, 80, get(w, PUBLISH_STAGE))
    return 128

def edit_bound_start(w:mutbuf, source:u64, root:u64, policy:u64, raw_target:u64, graph_target:u64, driver:u64, next:u64) -> u64:
    if policy < 1 or policy > 5 or root == 0 or cap(w, source) < 128:
        return refuse(w, 1040)
    if raw_target != 0 and (raw_target < 4 or raw_target >= 64 or cap(w, raw_target) != 0):
        return refuse(w, 1041)
    if graph_target != 0 and (graph_target < 4 or graph_target >= 64 or cap(w, graph_target) != 0):
        return refuse(w, 1042)
    if raw_target != 0 and raw_target == graph_target:
        return refuse(w, 1043)
    request = advance(w, E_REQUEST)
    if request == 0:
        return ABI
    put(w, D_POLICY, policy)
    put(w, D_RAW_TARGET, raw_target)
    put(w, D_GRAPH_TARGET, graph_target)
    put(w, D_RETURN_DRIVER, driver)
    put(w, D_RETURN_PHASE, next)
    put(w, D_REQUEST, request)
    wire8(w, BOUND_COMMAND, 101, request, root, policy, get(w, E_DIGITS), 0, 0)
    return edit_service_start(w, 3, source, 0, cap(w, source), B_CONTROLLER, WIRE, 64, 1024, driver, 42000)

def edit_bound_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 42000:
        if get(w, S_STATE) != 2 or get(w, S_KIND) != 3 or get(w, S_RESULT_CODE) != 128 or get(w, S_RESULT_EVENT_BYTES) != 128:
            return refuse(w, 1044)
        if get(w, S_RESULT_EVENT) != BOUND_EVENT or get(w, S_RESULT_EVENT + 16) != 101 or get(w, S_RESULT_EVENT + 24) != get(w, D_REQUEST):
            return refuse(w, 1045)
        action = get(w, S_RESULT_EVENT + 8)
        if action != 0 and action != 3:
            return refuse(w, 1046)
        if get(w, S_RESULT_EVENT + 112) != 1024 or get(w, S_RESULT_EVENT + 120) != 96 or cap(w, get(w, S_RESULT_SLOT)) != get(w, S_RESULT_BYTES):
            return refuse(w, 1047)
        put(w, D_ACTION, action)
        return view(o, w, get(w, S_RESULT_SLOT), 1024, 96, 42001)
    if phase == 42001:
        if get(w, OBS) != BOUND_RESULT or get(w, OBS + 8) != get(w, D_POLICY):
            return refuse(w, 1048)
        put(w, D_DOMAIN, get(w, OBS + 16))
        put(w, D_ERROR_CODE, get(w, OBS + 24))
        put(w, D_CAUSE, get(w, OBS + 32))
        put(w, D_DETAIL, get(w, OBS + 88))
        put(w, D_RAW_AT, get(w, OBS + 40))
        put(w, D_RAW_BYTES, get(w, OBS + 48))
        put(w, D_GRAPH_AT, get(w, OBS + 56))
        put(w, D_GRAPH_BYTES, get(w, OBS + 64))
        put(w, D_ERROR_AT, get(w, OBS + 72))
        put(w, D_ERROR_BYTES, get(w, OBS + 80))
        if inside(w, get(w, S_RESULT_SLOT), get(w, D_RAW_AT), get(w, D_RAW_BYTES)) == 0 or inside(w, get(w, S_RESULT_SLOT), get(w, D_GRAPH_AT), get(w, D_GRAPH_BYTES)) == 0 or inside(w, get(w, S_RESULT_SLOT), get(w, D_ERROR_AT), get(w, D_ERROR_BYTES)) == 0:
            return refuse(w, 1049)
        if get(w, D_ACTION) == 3:
            if get(w, D_DOMAIN) != 1 and get(w, D_DOMAIN) != 2:
                return refuse(w, 1050)
            if get(w, D_ERROR_CODE) == 0 or get(w, D_ERROR_BYTES) == 0:
                return refuse(w, 1051)
            domain = 1
            if get(w, D_DOMAIN) == 2:
                domain = 3
            return edit_error_start(w, domain, get(w, D_POLICY), get(w, D_ERROR_CODE), get(w, S_RESULT_SLOT), get(w, D_ERROR_AT), get(w, D_ERROR_BYTES))
        if get(w, D_DOMAIN) != 0 or get(w, D_ERROR_CODE) != 0 or get(w, D_CAUSE) != 0 or get(w, D_ERROR_BYTES) != 0 or get(w, D_DETAIL) != 0:
            return refuse(w, 1052)
        if get(w, D_RAW_TARGET) != 0:
            if get(w, D_RAW_BYTES) == 0:
                return refuse(w, 1053)
            return grow(o, w, get(w, D_RAW_TARGET), get(w, D_RAW_BYTES), 42002)
        put(w, C_PHASE, 42004)
        return 0
    if phase == 42002:
        return copy(o, w, get(w, S_RESULT_SLOT), get(w, D_RAW_AT), get(w, D_RAW_TARGET), 0, get(w, D_RAW_BYTES), 42003)
    if phase == 42003:
        return protect(o, w, get(w, D_RAW_TARGET), 1, 42004)
    if phase == 42004:
        if get(w, D_GRAPH_TARGET) != 0:
            if get(w, D_GRAPH_BYTES) < 128:
                return refuse(w, 1054)
            return grow(o, w, get(w, D_GRAPH_TARGET), get(w, D_GRAPH_BYTES), 42005)
        put(w, C_PHASE, 42007)
        return 0
    if phase == 42005:
        return copy(o, w, get(w, S_RESULT_SLOT), get(w, D_GRAPH_AT), get(w, D_GRAPH_TARGET), 0, get(w, D_GRAPH_BYTES), 42006)
    if phase == 42006:
        return protect(o, w, get(w, D_GRAPH_TARGET), 1, 42007)
    if phase == 42007:
        put(w, D_RELEASE_SLOT, 32)
        put(w, C_PHASE, 42008)
        return 0
    if phase == 42008:
        slot = get(w, D_RELEASE_SLOT)
        if slot == 50:
            put(w, C_PHASE, get(w, D_RETURN_PHASE))
            return 0
        put(w, D_RELEASE_SLOT, slot + 1)
        return release(o, w, slot, 42008)
    return refuse(w, 1055)
'''

# Only immutable authoring function text is selected; no referenced Python
# policy function is executed by a generated controller.
legacy_tree=ast.parse((BASE/'native-composite-legacy-import-next/tools/generate_hia_legacy_import_driver.py').read_text())
legacy_body=next(ast.literal_eval(n.value) for n in legacy_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets))
hash_nodes={n.name:n for n in ast.parse(legacy_body).body}
HASH=ast.unparse(hash_nodes['import_hash_step']).replace(
    'get(w, M_HASH_SLOT), get(w, M_HASH_OFFSET), B_SHA_INPUT',
    'get(w, M_HASH_SLOT), get(w, M_HASH_AT) + get(w, M_HASH_OFFSET), B_SHA_INPUT')
services_tree=ast.parse((BASE/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_services.py').read_text())
services_body=next(ast.literal_eval(n.value) for n in services_tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets))
index_nodes={n.name:n for n in ast.parse(services_body).body}
INDEX='\n'.join(ast.unparse(index_nodes[n]) for n in ('json_workspace','index_step'))
ALL=HELPERS+'\n'+HASH+'\n'+INDEX+'\n'+COMMON
