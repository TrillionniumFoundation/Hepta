"""Complete historical nominal importer continuation and report owner in HIA."""
import json
from tools.legacy_authoring import source,document as build,write_document
from tools.hia_composite_lowering_driver_common import COMMON,CONSTANTS as LOWER
from tools.hia_composite_lowering_driver_services import BODY as SERVICES

CONSTANTS=dict(LOWER)
CONSTANTS.update({'IMPORT_DRIVER':46,'IMPORT_INIT':int.from_bytes(b'HIALII01','little'),
    'IMPORT_STATE':int.from_bytes(b'HIALIS01','little'),'PROJECTION':int.from_bytes(b'HIALIP01','little'),
    'COMPARISON':int.from_bytes(b'HIALCP01','little'),'INPUT_LIMIT':8<<20,
    'B_PROJECTION':4,'B_PROJECTION_WORK':5,'B_RESPONSE':45,'B_RENAMED_SOURCE':48,
    'B_SHA_INPUT':49,'B_SHA_OUTPUT':50,'B_SHA_WORK':51,
    'B_ORIGINAL_JSON':52,'B_RENAMED_JSON':53,'B_OLD_CORE':54,'B_NEW_CORE':55,'B_COMPARE':56})
FIELDS=('ORIGINAL_PACKET','RENAMED_PACKET','ORIGINAL_BYTES','RENAMED_BYTES','RENAMED_SOURCE',
        'OLD_BYTES','NEW_BYTES','RESPONSE_BYTES','RELEASE','CHILD_MODE','CHILD_TARGET','CHILD_LEASE',
        'HASH_SLOT','HASH_BYTES','HASH_TO','HASH_RETURN')
CONSTANTS.update({'M_'+name:24576+8*i for i,name in enumerate(FIELDS)})
CONSTANTS.update({'M_SOURCE_HASH':24832,'M_OLD_HASH':24864,'M_INPUT_HASH':24896,'M_TARGET_HASH':24928})

BODY=r'''
def legacy_import(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 800)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if import_begin(s, w) == 0:
            return refuse(w, 801)
    elif get(w, C_MAGIC) != IMPORT_STATE or acknowledge(s, w, IMPORT_DRIVER) == 0:
        return refuse(w, 802)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        elif phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        else:
            result = import_step(o, w)
        if result != 0:
            return result
    return refuse(w, 803)

def import_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != IMPORT_INIT:
        return 0
    lease = word(s, 8)
    extent = word(s, 24)
    if lease == 0 or lease > MAX - 4 or word(s, 16) != 0:
        return 0
    if extent < 82 or extent > SOURCE_LEASE_LIMIT or extent != cap(w, B_SOURCE):
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    at = 32
    while at < 64:
        if word(s, at) != 0:
            return 0
        at = at + 8
    slot = 3
    while slot < 64:
        if cap(w, slot) != 0:
            return 0
        slot = slot + 1
    zero(w, 0, 4096)
    zero(w, 8192, MIN_WORK - 8192)
    put(w, C_MAGIC, IMPORT_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, C_SOURCE_EXTENT, extent)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, IMPORT_DRIVER)
    put(w, C_PHASE, 1)
    return 1

def import_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        return view(o, w, B_SOURCE, 0, 64, 2)
    if phase == 2:
        packet = get(w, OBS + 8)
        if get(w, OBS) != SOURCE_MAGIC or packet < 16 or packet > PACKET_LIMIT - 2:
            return refuse(w, 804)
        if get(w, OBS + 40) != cap(w, B_SOURCE) or get(w, OBS + 24) != 64:
            return refuse(w, 805)
        put(w, M_ORIGINAL_PACKET, packet)
        return grow(o, w, B_PROJECTION, 66 + packet, 3)
    if phase == 3:
        return grow(o, w, B_PROJECTION_WORK, 64, 4)
    if phase == 4:
        return invoke(o, w, 28, B_SOURCE, 0, cap(w, B_SOURCE), B_PROJECTION, cap(w, B_PROJECTION), B_PROJECTION_WORK, 64, B_PROJECTION, 0, 64, 5)
    if phase == 5:
        if get(w, OBS) != PROJECTION or get(w, OBS + 16) != 64 or get(w, OBS + 32) != get(w, M_ORIGINAL_PACKET):
            return refuse(w, 806)
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 807)
        error = get(w, OBS + 8)
        if error != 0:
            if error > 2 or get(w, C_RETURN) != 64 or get(w, OBS + 24) != 0:
                return refuse(w, 808)
            return finish(o, w, 9, error, 0)
        size = get(w, M_ORIGINAL_PACKET) + 2
        if get(w, C_RETURN) != 64 + size or get(w, OBS + 24) != size:
            return refuse(w, 809)
        put(w, M_RENAMED_PACKET, size)
        put(w, C_PACKET_SLOT, B_SOURCE)
        put(w, C_PACKET_OFFSET, 64)
        put(w, C_PACKET_BYTES, get(w, M_ORIGINAL_PACKET))
        put(w, L_INDEX_TARGET, 0)
        put(w, L_INDEX_RETURN, 10)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 10:
        size = get(w, C_JSON_BYTES)
        if size == 0 or size > INPUT_LIMIT:
            return refuse(w, 810)
        put(w, M_ORIGINAL_BYTES, size)
        return grow(o, w, B_ORIGINAL_JSON, size, 11)
    if phase == 11:
        return copy(o, w, B_PACKET_JSON, 64, B_ORIGINAL_JSON, 0, get(w, M_ORIGINAL_BYTES), 12)
    if phase == 12:
        return protect(o, w, B_ORIGINAL_JSON, 1, 13)
    if phase == 13:
        put(w, C_PACKET_SLOT, B_PROJECTION)
        put(w, C_PACKET_OFFSET, 64)
        put(w, C_PACKET_BYTES, get(w, M_RENAMED_PACKET))
        put(w, L_INDEX_TARGET, B_RENAMED_SOURCE)
        put(w, L_INDEX_RETURN, 20)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 20:
        size = get(w, C_JSON_BYTES)
        if size != get(w, M_ORIGINAL_BYTES) + 2:
            return refuse(w, 811)
        put(w, M_RENAMED_BYTES, size)
        put(w, M_RENAMED_SOURCE, get(w, L_INDEX_SOURCE_BYTES))
        return grow(o, w, B_RENAMED_JSON, size, 21)
    if phase == 21:
        return copy(o, w, B_PACKET_JSON, 64, B_RENAMED_JSON, 0, get(w, M_RENAMED_BYTES), 22)
    if phase == 22:
        return protect(o, w, B_RENAMED_JSON, 1, 23)
    if phase == 23:
        return release(o, w, B_PROJECTION, 24)
    if phase == 24:
        return release(o, w, B_PROJECTION_WORK, 25)
    if phase == 25:
        return release(o, w, B_PACKET_JSON, 26)
    if phase == 26:
        return release(o, w, B_PACKET_WORK, 27)
    if phase == 27:
        return run_child(o, w, 1, B_RENAMED_SOURCE, get(w, M_RENAMED_SOURCE), B_OLD_CORE, get(w, C_LEASE) + 1, 28)
    if phase == 28:
        if child_result(w) == 0:
            return refuse(w, 812)
        if get(w, OBS + 32) != 0:
            return child_error(o, w)
        put(w, M_OLD_BYTES, get(w, OBS + 88))
        copy_digest(w, M_OLD_HASH, OBS + 96)
        # The rename increases the caller-owned canonical input by two bytes.
        # Its original snapshot byte error is after the complete old Core gate.
        if get(w, M_RENAMED_BYTES) > INPUT_LIMIT:
            return finish(o, w, 9, 3, 0)
        return run_child(o, w, 0, B_RENAMED_JSON, get(w, M_RENAMED_BYTES), B_NEW_CORE, get(w, C_LEASE) + 2, 29)
    if phase == 29:
        if child_result(w) == 0:
            return refuse(w, 813)
        if get(w, OBS + 32) != 0:
            return child_error(o, w)
        put(w, M_NEW_BYTES, get(w, OBS + 88))
        copy_digest(w, M_TARGET_HASH, OBS + 96)
        mirror_frame(w)
        return grow(o, w, B_COMPARE, 64, 30)
    if phase == 30:
        return invoke(o, w, 29, B_OLD_CORE, 0, get(w, M_OLD_BYTES), B_NEW_CORE, get(w, M_NEW_BYTES), B_COMPARE, 64, B_COMPARE, 0, 64, 31)
    if phase == 31:
        if get(w, C_RETURN) != 64 or get(w, OBS) != COMPARISON or get(w, OBS + 8) > 1:
            return refuse(w, 814)
        if get(w, OBS + 16) != get(w, M_OLD_BYTES) or get(w, OBS + 24) != get(w, M_NEW_BYTES):
            return refuse(w, 815)
        if get(w, OBS + 32) != 0 or get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 816)
        if get(w, OBS + 8) != 0:
            return finish(o, w, 9, 4, 0)
        return release(o, w, B_COMPARE, 32)
    if phase == 32:
        return hash_start(w, B_ORIGINAL_JSON, get(w, M_ORIGINAL_BYTES), M_SOURCE_HASH, 40)
    if phase == 40:
        return hash_start(w, B_RENAMED_JSON, get(w, M_RENAMED_BYTES), M_INPUT_HASH, 41)
    if phase == 41:
        size = 8 + get(w, M_NEW_BYTES) + 10 + REPORT_BYTES + 14 + get(w, M_RENAMED_BYTES) + 1
        put(w, M_RESPONSE_BYTES, size)
        return grow(o, w, B_RESPONSE, size, 42)
    if phase == 42:
        prefix(w)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, 0, 8, 43)
    if phase == 43:
        return copy(o, w, B_NEW_CORE, 0, B_RESPONSE, 8, get(w, M_NEW_BYTES), 44)
    if phase == 44:
        report_separator(w)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, 8 + get(w, M_NEW_BYTES), 10, 45)
    if phase == 45:
        report(w)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, 18 + get(w, M_NEW_BYTES), REPORT_BYTES, 46)
    if phase == 46:
        structured_separator(w)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, 18 + get(w, M_NEW_BYTES) + REPORT_BYTES, 14, 47)
    if phase == 47:
        return copy(o, w, B_RENAMED_JSON, 0, B_RESPONSE, 32 + get(w, M_NEW_BYTES) + REPORT_BYTES, get(w, M_RENAMED_BYTES), 48)
    if phase == 48:
        store(w, WIRE, 125)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, get(w, M_RESPONSE_BYTES) - 1, 1, 49)
    if phase == 49:
        return protect(o, w, B_RESPONSE, 1, 50)
    if phase == 50:
        return hash_start(w, B_RESPONSE, get(w, M_RESPONSE_BYTES), L_DIGEST0, 51)
    if phase == 51:
        put(w, M_RELEASE, 4)
        put(w, C_PHASE, 52)
        return 0
    if phase == 52:
        slot = get(w, M_RELEASE)
        if slot == 64:
            put(w, L_FINAL_BYTES, get(w, M_RESPONSE_BYTES))
            return finish(o, w, 0, 0, 0)
        put(w, M_RELEASE, slot + 1)
        if slot != B_RESPONSE:
            return release(o, w, slot, 52)
        return 0
    return refuse(w, 817)

def run_child(o:mutbuf, w:mutbuf, mode:u64, source:u64, extent:u64, target:u64, lease:u64, next:u64) -> u32:
    if mode > 1 or source == target or target < 4 or target >= 64 or cap(w, target) != 0:
        return refuse(w, 818)
    if extent == 0 or extent != cap(w, source) or lease == 0 or lease == MAX:
        return refuse(w, 819)
    put(w, M_CHILD_MODE, mode)
    put(w, M_CHILD_TARGET, target)
    put(w, M_CHILD_LEASE, lease)
    put(w, C_OBSERVE, 160)
    args(w, mode, source, 0, extent, target, lease, 0, 0, 0, 0, 0, 0)
    return event(o, w, 15, next)

def child_result(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 128 or get(w, OBS) != EVENT_MAGIC or get(w, OBS + 8) != 7:
        return 0
    lease = get(w, M_CHILD_LEASE)
    if get(w, M_CHILD_MODE) == 0:
        lease = lease + 1
    if get(w, OBS + 16) != lease or get(w, OBS + 24) == 0:
        return 0
    target = get(w, M_CHILD_TARGET)
    if get(w, OBS + 136) != target or get(w, OBS + 152) != 0 or cap(w, target) != 0:
        return 0
    role = get(w, OBS + 144)
    if get(w, M_CHILD_MODE) == 1:
        if role != 40 and role != 47:
            return 0
    elif role != 40 and role != 45:
        return 0
    group = get(w, OBS + 32)
    error = get(w, OBS + 40)
    if group > 8:
        return 0
    if group != 0:
        if error == 0 or get(w, OBS + 128) != 0:
            return 0
        return 1
    if error != 0 or get(w, OBS + 88) == 0 or get(w, OBS + 88) > INPUT_LIMIT:
        return 0
    if get(w, OBS + 128) < get(w, OBS + 88):
        return 0
    if get(w, M_CHILD_MODE) == 1 and role != 47:
        return 0
    if get(w, M_CHILD_MODE) == 0 and role != 45:
        return 0
    put(w, CAPS + target * 8, get(w, OBS + 128))
    return 1

def mirror_frame(w:mutbuf) -> u64:
    put(w, L_FN_SERIAL, get(w, OBS + 56))
    put(w, L_FN_SLOTS, get(w, OBS + 64))
    put(w, L_FN_COUNT, get(w, OBS + 72))
    put(w, L_HELP_COUNT, get(w, OBS + 80))
    put(w, L_FINAL_BYTES, get(w, OBS + 88))
    copy_digest(w, L_DIGEST0, OBS + 96)
    return 0

def child_error(o:mutbuf, w:mutbuf) -> u32:
    mirror_frame(w)
    return finish(o, w, get(w, OBS + 32), get(w, OBS + 40), get(w, OBS + 48))

def copy_digest(w:mutbuf, to:u64, start:u64) -> u64:
    i = 0
    while i < 4:
        put(w, to + i * 8, get(w, start + i * 8))
        i = i + 1
    return 0

def hash_start(w:mutbuf, slot:u64, size:u64, to:u64, next:u64) -> u64:
    if inside(w, slot, 0, size) == 0 or size == MAX:
        return refuse(w, 820)
    put(w, M_HASH_SLOT, slot)
    put(w, M_HASH_BYTES, size)
    put(w, M_HASH_TO, to)
    put(w, M_HASH_RETURN, next)
    put(w, C_PHASE, 300)
    return 0

def import_hash_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 300:
        return grow(o, w, B_SHA_INPUT, get(w, M_HASH_BYTES) + 1, 301)
    if phase == 301:
        return grow(o, w, B_SHA_OUTPUT, 32, 302)
    if phase == 302:
        return grow(o, w, B_SHA_WORK, 1184, 303)
    if phase == 303:
        store(w, WIRE, 0)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_EMPTY, 0, 0, 304)
    if phase == 304:
        if get(w, C_RETURN) != 0:
            return refuse(w, 821)
        store(w, WIRE, 1)
        return copy(o, w, B_CONTROLLER, WIRE, B_SHA_INPUT, 0, 1, 305)
    if phase == 305:
        return copy(o, w, get(w, M_HASH_SLOT), 0, B_SHA_INPUT, 1, get(w, M_HASH_BYTES), 306)
    if phase == 306:
        return invoke(o, w, I_SHA_STREAM, B_SHA_INPUT, 0, get(w, M_HASH_BYTES) + 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_EMPTY, 0, 0, 307)
    if phase == 307:
        if get(w, C_RETURN) != 0:
            return refuse(w, 822)
        store(w, WIRE, 2)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_SHA_OUTPUT, 32, B_SHA_WORK, 1184, B_SHA_OUTPUT, 0, 32, 308)
    if phase == 308:
        if get(w, C_RETURN) != 32:
            return refuse(w, 823)
        copy_digest(w, get(w, M_HASH_TO), OBS)
        return release(o, w, B_SHA_INPUT, 309)
    if phase == 309:
        return release(o, w, B_SHA_OUTPUT, 310)
    if phase == 310:
        return release(o, w, B_SHA_WORK, 311)
    if phase == 311:
        put(w, C_PHASE, get(w, M_HASH_RETURN))
        return 0
    return refuse(w, 824)

def hex_digest(w:mutbuf, start:u64, to:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, start + i)
        high = value >> 4
        low = value & 15
        if high < 10:
            high = high + 48
        else:
            high = high + 87
        if low < 10:
            low = low + 48
        else:
            low = low + 87
        store(w, to + i * 2, high)
        store(w, to + i * 2 + 1, low)
        i = i + 1
    return 0
'''


def report_template():
    value={'schema':'hepta.hia.legacy-composite-import.v1','ok':True,
        'source_schema':'hepta.hia.program.v2',
        'source_profile':'nominal-products-enums-cooperative-tasks-over-closed-ssa-v2',
        'source_input_sha256':'A'*64,'source_primitive_schema':'hepta.hia.program.v1',
        'source_primitive_sha256':'B'*64,'target_schema':'hepta.hia.composite.v1',
        'target_input_sha256':'C'*64,'target_core_schema':'hepta.hia.program.v6',
        'target_core_sha256':'D'*64,
        'claims':{'explicit_nominal_profile_selected':True,'legacy_v1_instruction_set_reverified':True,
            'nominal_resource_flow_reverified':True,'target_v6_core_reverified':True,
            'primitive_payload_unchanged_excluding_schema':True,'producer_source_authenticated':False,
            'whole_language_soundness_proved':False,'backend_refinement_proved':False}}
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def literal_function(name,raw):
    result=f'\ndef {name}(w:mutbuf) -> u64:\n'
    full=(len(raw)//8)*8
    for i in range(0,full,8):result+=f'    put(w, WIRE + {i}, {int.from_bytes(raw[i:i+8],"little")})\n'
    for i in range(full,len(raw)):result+=f'    store(w, WIRE + {i}, {raw[i]})\n'
    return result+'    return 0\n'


def source_program():
    raw=report_template(); constants=dict(CONSTANTS,REPORT_BYTES=len(raw))
    assert len(raw)<2048
    extras=''
    for name,value in [('prefix',b'{"core":'),('report_separator',b',"report":'),('structured_separator',b',"structured":')]:
        extras+=literal_function(name,value)
    assert len(b'{"core":')==8 and len(b',"report":')==10 and len(b',"structured":')==14
    report=literal_function('report',raw)
    injection=''
    for marker,field in [('A','M_SOURCE_HASH'),('B','M_OLD_HASH'),('C','M_INPUT_HASH'),('D','M_TARGET_HASH')]:
        offset=raw.index((marker*64).encode()); assert raw.count((marker*64).encode())==1
        injection+=f'    hex_digest(w, {field}, WIRE + {offset})\n'
    extras+=report.replace('    return 0\n',injection+'    return 0\n')
    common=COMMON.replace('or image > 23:','or image > 29:')
    common=common.replace('if pending != 1 and pending != 14 and word(s, 40) != 0:',
        'if pending != 1 and pending != 14 and pending != 15 and word(s, 40) != 0:')
    return source(BODY+extras+'\n'+SERVICES+'\n'+common,constants,'legacy_import')

def document(): return build(source_program(),'legacy_composite_import_driver')
if __name__=='__main__': write_document(document(),'legacy_composite_import_driver.hiaasm')
