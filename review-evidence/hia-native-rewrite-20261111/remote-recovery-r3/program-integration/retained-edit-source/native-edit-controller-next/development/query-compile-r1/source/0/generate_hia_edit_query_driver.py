"""HIA owner of single/batch query reconstruction, comparison and rendering.

All continuations below compile into HIA. This authoring file is not imported
by the eventual fixed native executable.
"""
from edit_authoring import source,document as build,write
from hia_edit_controller_common import CONSTANTS as BASE,ALL,magic
CONSTANTS=dict(BASE)
FIELDS=('ACTIVE_SLOT','ACTIVE_ROOT','PREFIX_MODE','COUNT','INDEX','ROOT_COUNT','ROOT_INDEX','PREFIX_ROOT_AT',
    'REQUEST','COMMAND_BYTES','FACT_BYTES','SLICE_BYTES','SLICE_WORK_BYTES','NB','NO','NV','SB','SI',
    'OP_AT','OP_BYTES','OP_WIRE_BYTES','CANON_BYTES','GRAPH_ROOT','GRAPH_BYTES','RELEASE',
    'JOIN_NODES','JOIN_ROOT','JOIN_BYTES','BATCH_FINAL','MATCH_REQUEST','RENDER_LEASE','RENDER_REQUEST')
CONSTANTS.update({'Q_'+n:20000+8*i for i,n in enumerate(FIELDS)})
CONSTANTS.update(Q_OPERATION_HASH=20480,Q_FACT_EVENT=20512,Q_SELECTORS=20736,Q_QUERY_ROOTS=21248,
    B_NORMAL_QUERY=24,B_JOINED=25,B_JOIN_TEMP=26,B_QUERY_SOURCE=31,B_CANONICAL=53,B_CANONICAL_WORK=54,B_SLICE_WORK=55,
    ARENA_BYTES=64+56*262144+(8<<20),KEY_BYTES=8*2*262144,REF=1<<63,
    GRAPH_MAGIC=magic('HIAGRF01'),PREFIX_COMMAND=magic('HIAQIC01'),PREFIX_EVENT=magic('HIAQIE01'),
    SELECT_COMMAND=magic('HIAQSC01'),SELECT_EVENT=magic('HIAQSE01'),FACT_COMMAND=magic('HIAQFC01'),FACT_EVENT=magic('HIAQFE01'),
    FACT_MAGIC=magic('HIASLC01'),SLICE_MAGIC=magic('HIASLR01'),QUERY_COMMAND=magic('HIAQQC01'),QUERY_EVENT=magic('HIAQQE01'),
    BRIDGE_COMMAND=magic('HIAPGC01'),BRIDGE_EVENT=magic('HIAPGE01'),MERGE_COMMAND=magic('HIAGMC01'),MERGE_EVENT=magic('HIAGME01'),
    BATCH_COMMAND=magic('HIAQBC01'),BATCH_EVENT=magic('HIAQBE01'),MATCH_COMMAND=magic('HIAQMC01'),MATCH_EVENT=magic('HIAQME01'),
    SINGLE_RENDER_COMMAND=magic('HIAERC01'),SINGLE_RENDER_EVENT=magic('HIAERE01'),BATCH_RENDER_COMMAND=magic('HIABRC01'),BATCH_RENDER_EVENT=magic('HIABRE01'))

BODY=r'''
def edit_query(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 1200)
    if get(w, C_MAGIC) != EDIT_STATE or acknowledge(s, w, QUERY) == 0:
        return refuse(w, 1201)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        elif phase >= 40000 and phase < 40100:
            result = edit_simple_step(o, w)
        elif phase >= 42000 and phase < 42100:
            result = edit_bound_step(o, w)
        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)
        elif phase >= 1100 and phase < 1200:
            result = single_query_step(o, w)
        elif phase >= 1400 and phase < 1600:
            result = batch_query_step(o, w)
        else:
            result = query_flow_step(o, w)
        if result != 0:
            return result
    return refuse(w, 1202)

def graph_header(w:mutbuf, slot:u64) -> u64:
    if get(w, OBS) != GRAPH_MAGIC or get(w, OBS + 8) == 0 or get(w, OBS + 16) == 0:
        return 0
    if get(w, OBS + 24) == 0 or get(w, OBS + 24) > get(w, OBS + 16) or get(w, OBS + 48) != cap(w, slot) or get(w, OBS + 56) != 0:
        return 0
    return 1

def query_flow_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    mode = get(w, E_MODE)
    if phase == 1000:
        if mode < 1 or mode > 4 or cap(w, B_CORE_SOURCE) < 82:
            return refuse(w, 1203)
        put(w, Q_ACTIVE_SLOT, B_QUERY_GRAPH)
        put(w, Q_INDEX, 0)
        return view(o, w, B_QUERY_GRAPH, 0, 64, 1001)
    if phase == 1001:
        if graph_header(w, B_QUERY_GRAPH) == 0:
            return refuse(w, 1204)
        put(w, Q_ACTIVE_ROOT, get(w, OBS + 24))
        if mode == 2:
            result = edit_bound_start(w, B_QUERY_GRAPH, get(w, Q_ACTIVE_ROOT), 2, 0, B_NORMAL_QUERY, QUERY, 1002)
            if result != 0:
                return result
            return switch(o, w, SERVICE, 50000)
        put(w, Q_PREFIX_MODE, 2)
        if mode == 1:
            put(w, Q_PREFIX_MODE, 1)
        put(w, C_PHASE, 1003)
        return 0
    if phase == 1002:
        put(w, Q_ACTIVE_SLOT, B_NORMAL_QUERY)
        put(w, Q_PREFIX_MODE, 3)
        return view(o, w, B_NORMAL_QUERY, 0, 64, 1020)
    if phase == 1020:
        if graph_header(w, B_NORMAL_QUERY) == 0:
            return refuse(w, 1205)
        put(w, Q_ACTIVE_ROOT, get(w, OBS + 24))
        put(w, C_PHASE, 1003)
        return 0
    if phase == 1003:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        put(w, Q_REQUEST, request)
        return grow(o, w, B_COMMAND, 128, 1004)
    if phase == 1004:
        zero(w, WIRE, 128)
        wire8(w, PREFIX_COMMAND, get(w, Q_PREFIX_MODE), 97, get(w, Q_REQUEST), get(w, Q_ACTIVE_ROOT), get(w, Q_INDEX), 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 128, 1005)
    if phase == 1005:
        return grow(o, w, B_KERNEL, 1024, 1006)
    if phase == 1006:
        return invoke(o, w, 35, get(w, Q_ACTIVE_SLOT), 0, cap(w, get(w, Q_ACTIVE_SLOT)), B_COMMAND, 128, B_KERNEL, 1024, B_KERNEL, 256, 128, 1007)
    if phase == 1007:
        if get(w, C_RETURN) != 384 or get(w, OBS) != PREFIX_EVENT or get(w, OBS + 16) != 97 or get(w, OBS + 24) != get(w, Q_REQUEST):
            return refuse(w, 1206)
        if get(w, OBS + 8) == 2:
            return query_error(w, 1, get(w, OBS + 72))
        if get(w, OBS + 8) != 0 or get(w, OBS + 40) == 0 or get(w, OBS + 40) > 16 or get(w, OBS + 80) == 0 or get(w, OBS + 80) > 16:
            return refuse(w, 1207)
        if get(w, OBS + 64) != get(w, OBS + 80) * 32 or inside(w, B_KERNEL, get(w, OBS + 56), get(w, OBS + 64)) == 0:
            return refuse(w, 1208)
        if mode == 3 and get(w, OBS + 40) != 1:
            return refuse(w, 1209)
        if get(w, Q_INDEX) != 0 and get(w, Q_COUNT) != get(w, OBS + 40):
            return refuse(w, 1210)
        put(w, Q_COUNT, get(w, OBS + 40))
        put(w, Q_ROOT_COUNT, get(w, OBS + 80))
        put(w, Q_ROOT_INDEX, 0)
        put(w, Q_PREFIX_ROOT_AT, get(w, OBS + 56))
        put(w, C_PHASE, 1008)
        return 0
    if phase == 1008:
        return view(o, w, B_KERNEL, get(w, Q_PREFIX_ROOT_AT) + get(w, Q_ROOT_INDEX) * 32, 32, 1009)
    if phase == 1009:
        index = get(w, Q_ROOT_INDEX)
        if get(w, Q_PREFIX_MODE) == 2:
            index = get(w, Q_INDEX)
        if index >= 16:
            return refuse(w, 1211)
        copy_local(w, Q_SELECTORS + index * 32, OBS, 32)
        put(w, Q_ROOT_INDEX, get(w, Q_ROOT_INDEX) + 1)
        if get(w, Q_ROOT_INDEX) < get(w, Q_ROOT_COUNT):
            put(w, C_PHASE, 1008)
            return 0
        return release(o, w, B_COMMAND, 1010)
    if phase == 1010:
        return release(o, w, B_KERNEL, 1100)
    if phase == 1300:
        if mode == 3:
            return edit_result_start(w, B_PREPARED_WIRE, 0, cap(w, B_PREPARED_WIRE), B_EMPTY, 0, 0, B_EMPTY, 0, 0)
        if mode == 1:
            result = edit_bound_start(w, B_QUERY_GRAPH, get(w, Q_ACTIVE_ROOT), 4, B_UNTRUSTED_WIRE, 0, QUERY, 1700)
            if result != 0:
                return result
            return switch(o, w, SERVICE, 50000)
        put(w, C_PHASE, 1400)
        return 0
    if phase == 1600:
        if mode == 4:
            return edit_result_start(w, B_PREPARED_WIRE, 0, cap(w, B_PREPARED_WIRE), B_EMPTY, 0, 0, B_EMPTY, 0, 0)
        if mode != 2:
            return refuse(w, 1212)
        result = edit_bound_start(w, B_NORMAL_QUERY, get(w, Q_ACTIVE_ROOT), 5, B_UNTRUSTED_WIRE, 0, QUERY, 1700)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    if phase == 1700:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        put(w, Q_MATCH_REQUEST, request)
        return grow(o, w, B_KERNEL, 512, 1701)
    if phase == 1701:
        wire8(w, MATCH_COMMAND, mode, 103, get(w, Q_MATCH_REQUEST), 0, 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_KERNEL, 0, 64, 1702)
    if phase == 1702:
        return invoke(o, w, 51, B_UNTRUSTED_WIRE, 0, cap(w, B_UNTRUSTED_WIRE), B_PREPARED_WIRE, cap(w, B_PREPARED_WIRE), B_KERNEL, 512, B_KERNEL, 128, 128, 1703)
    if phase == 1703:
        if get(w, C_RETURN) != 256 or get(w, OBS) != MATCH_EVENT or get(w, OBS + 16) != 103 or get(w, OBS + 24) != get(w, Q_MATCH_REQUEST):
            return refuse(w, 1213)
        if get(w, OBS + 32) != mode or get(w, OBS + 40) != cap(w, B_UNTRUSTED_WIRE) or get(w, OBS + 48) != cap(w, B_PREPARED_WIRE):
            return refuse(w, 1214)
        if get(w, OBS + 8) == 2:
            return edit_error_start(w, 1, 7, mode, B_KERNEL, get(w, OBS + 64), get(w, OBS + 72))
        if get(w, OBS + 8) != 0:
            return refuse(w, 1215)
        return release(o, w, B_KERNEL, 1704)
    if phase == 1704:
        return switch(o, w, APPLY, 60000)
    if phase == 2000:
        if mode != 5 and mode != 6:
            return refuse(w, 1216)
        return view(o, w, B_QUERY_GRAPH, 0, 64, 2001)
    if phase == 2001:
        if graph_header(w, B_QUERY_GRAPH) == 0:
            return refuse(w, 1217)
        put(w, Q_RENDER_LEASE, get(w, OBS + 8))
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        put(w, Q_RENDER_REQUEST, request)
        command = SINGLE_RENDER_COMMAND
        if mode == 6:
            command = BATCH_RENDER_COMMAND
        wire8(w, command, get(w, Q_RENDER_LEASE), request, get(w, OBS + 24), get(w, E_DIGITS), 0, 0, 0)
        result = edit_service_start(w, mode, B_QUERY_GRAPH, 0, cap(w, B_QUERY_GRAPH), B_CONTROLLER, WIRE, 64, 32768, QUERY, 2002)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    if phase == 2002:
        if get(w, S_STATE) != 2 or get(w, S_KIND) != mode or get(w, S_RESULT_EVENT + 16) != get(w, Q_RENDER_LEASE) or get(w, S_RESULT_EVENT + 24) != get(w, Q_RENDER_REQUEST):
            return refuse(w, 1218)
        at = 56
        code_at = 80
        if mode == 5:
            if get(w, S_RESULT_CODE) != 128 or get(w, S_RESULT_EVENT_BYTES) != 128 or get(w, S_RESULT_EVENT) != SINGLE_RENDER_EVENT:
                return refuse(w, 1219)
        else:
            if get(w, S_RESULT_CODE) != 256 or get(w, S_RESULT_EVENT_BYTES) != 256 or get(w, S_RESULT_EVENT) != BATCH_RENDER_EVENT:
                return refuse(w, 1220)
            at = 112
            code_at = 136
        offset = get(w, S_RESULT_EVENT + at)
        size = get(w, S_RESULT_EVENT + at + 8)
        if inside(w, get(w, S_RESULT_SLOT), offset, size) == 0:
            return refuse(w, 1221)
        if get(w, S_RESULT_EVENT + 8) == 3:
            return edit_error_start(w, 1, mode, get(w, S_RESULT_EVENT + code_at), get(w, S_RESULT_SLOT), offset, size)
        if get(w, S_RESULT_EVENT + 8) != 0:
            return refuse(w, 1222)
        return edit_result_start(w, get(w, S_RESULT_SLOT), offset, size, B_EMPTY, 0, 0, B_EMPTY, 0, 0)
    return refuse(w, 1223)

def single_query_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1100:
        size = cap(w, get(w, Q_ACTIVE_SLOT))
        if size > MAX - 128 or get(w, Q_INDEX) >= get(w, Q_COUNT):
            return refuse(w, 1230)
        put(w, Q_COMMAND_BYTES, 128 + size)
        return grow(o, w, B_COMMAND, 128 + size, 1101)
    if phase == 1101:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        zero(w, WIRE, 128)
        wire8(w, SELECT_COMMAND, 1, 89, request, 0, 0, 0, 0)
        copy_local(w, WIRE + 40, Q_SELECTORS + get(w, Q_INDEX) * 32, 32)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 128, 1102)
    if phase == 1102:
        return copy(o, w, get(w, Q_ACTIVE_SLOT), 0, B_COMMAND, 128, cap(w, get(w, Q_ACTIVE_SLOT)), 1103)
    if phase == 1103:
        return edit_simple_start(w, 36, B_CORE_SOURCE, 0, cap(w, B_CORE_SOURCE), B_COMMAND, get(w, Q_COMMAND_BYTES), B_KERNEL, 1024, SELECT_EVENT, 256, B_COMMAND, get(w, Q_COMMAND_BYTES), 1104)
    if phase == 1104:
        if get(w, E_SIMPLE_EVENT + 8) == 2:
            return query_error(w, 2, get(w, E_SIMPLE_EVENT + 64))
        put(w, C_PACKET_SLOT, B_KERNEL)
        put(w, C_PACKET_OFFSET, get(w, E_SIMPLE_EVENT + 48))
        put(w, C_PACKET_BYTES, get(w, E_SIMPLE_EVENT + 56))
        put(w, L_INDEX_TARGET, B_SELECTED_SOURCE)
        put(w, L_INDEX_RETURN, 1105)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 1105:
        return release(o, w, B_COMMAND, 1106)
    if phase == 1106:
        return release(o, w, B_KERNEL, 1107)
    if phase == 1107:
        return grow(o, w, B_COMMAND, 64, 1108)
    if phase == 1108:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        wire8(w, FACT_COMMAND, 1, 1, request, 0, 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 64, 1109)
    if phase == 1109:
        return edit_simple_start(w, 37, B_COMMAND, 0, 64, B_SELECTED_SOURCE, cap(w, B_SELECTED_SOURCE), B_KERNEL, 512, FACT_EVENT, 256, B_COMMAND, 64, 1110)
    if phase == 1110:
        if get(w, E_SIMPLE_EVENT + 8) == 2:
            return query_error(w, 2, get(w, E_SIMPLE_EVENT + 112))
        copy_local(w, Q_FACT_EVENT, E_SIMPLE_EVENT, 128)
        size = get(w, Q_FACT_EVENT + 56)
        if size < 64 or size > INPUT_LIMIT or inside(w, B_KERNEL, get(w, Q_FACT_EVENT + 48), size) == 0:
            return refuse(w, 1231)
        put(w, Q_FACT_BYTES, size)
        return grow(o, w, B_FACTS, size, 1111)
    if phase == 1111:
        return copy(o, w, B_KERNEL, get(w, Q_FACT_EVENT + 48), B_FACTS, 0, get(w, Q_FACT_BYTES), 1112)
    if phase == 1112:
        return protect(o, w, B_FACTS, 1, 1113)
    if phase == 1113:
        return view(o, w, B_FACTS, 0, 64, 1114)
    if phase == 1114:
        if get(w, OBS) != FACT_MAGIC or get(w, OBS + 8) > 131072 or get(w, OBS + 16) > 209715 or get(w, OBS + 24) > 524288:
            return refuse(w, 1232)
        put(w, Q_NB, get(w, OBS + 8))
        put(w, Q_NO, get(w, OBS + 16))
        put(w, Q_NV, get(w, OBS + 24))
        put(w, Q_SB, get(w, OBS + 48))
        put(w, Q_SI, get(w, OBS + 56))
        size = 64 + 8 * (get(w, Q_NB) + get(w, Q_NO) + get(w, Q_NV))
        put(w, Q_SLICE_BYTES, size)
        put(w, Q_SLICE_WORK_BYTES, size + 8 * get(w, Q_NB))
        return grow(o, w, B_SLICE, size, 1115)
    if phase == 1115:
        return grow(o, w, B_SLICE_WORK, get(w, Q_SLICE_WORK_BYTES), 1116)
    if phase == 1116:
        return invoke(o, w, 38, B_FACTS, 0, get(w, Q_FACT_BYTES), B_SLICE, get(w, Q_SLICE_BYTES), B_SLICE_WORK, get(w, Q_SLICE_WORK_BYTES), B_SLICE, 0, 64, 1117)
    if phase == 1117:
        result = get(w, C_RETURN)
        if result == 4294967292 or result == 4294967291 or result == 4294967290:
            return query_error(w, 3, result)
        if result != get(w, Q_SLICE_BYTES) or get(w, OBS) != SLICE_MAGIC:
            return refuse(w, 1233)
        if get(w, OBS + 8) != get(w, Q_NB) or get(w, OBS + 16) != get(w, Q_NO) or get(w, OBS + 24) != get(w, Q_NV) or get(w, OBS + 32) != get(w, Q_SB) or get(w, OBS + 40) != get(w, Q_SI):
            return refuse(w, 1234)
        return protect(o, w, B_SLICE, 1, 1118)
    if phase == 1118:
        return release(o, w, B_SLICE_WORK, 1119)
    if phase == 1119:
        reference = get(w, Q_FACT_EVENT + 80)
        if reference < REF or reference - REF > MAX - 64:
            return refuse(w, 1235)
        put(w, Q_OP_AT, 64 + reference - REF)
        return view(o, w, B_SELECTED_SOURCE, get(w, Q_OP_AT), 16, 1120)
    if phase == 1120:
        size = get(w, OBS + 8)
        if size > MAX - 16 or inside(w, B_SELECTED_SOURCE, get(w, Q_OP_AT), 16 + size) == 0:
            return refuse(w, 1236)
        put(w, Q_OP_BYTES, 16 + size)
        put(w, C_PACKET_SLOT, B_SELECTED_SOURCE)
        put(w, C_PACKET_OFFSET, get(w, Q_OP_AT))
        put(w, C_PACKET_BYTES, get(w, Q_OP_BYTES))
        put(w, L_INDEX_TARGET, 0)
        put(w, L_INDEX_RETURN, 1121)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 1121:
        if get(w, C_JSON_BYTES) == 0 or get(w, C_JSON_BYTES) > INPUT_LIMIT:
            return refuse(w, 1237)
        put(w, Q_OP_WIRE_BYTES, get(w, C_JSON_BYTES))
        return grow(o, w, B_CANONICAL, maximum(KEY_BYTES, get(w, C_JSON_BYTES)), 1122)
    if phase == 1122:
        return grow(o, w, B_CANONICAL_WORK, ARENA_BYTES, 1123)
    if phase == 1123:
        wire8(w, 0, 0, 0, 0, 0, 0, NODES, DEPTH)
        return copy(o, w, B_CONTROLLER, WIRE, B_CANONICAL_WORK, 0, 64, 1124)
    if phase == 1124:
        return invoke(o, w, 54, B_PACKET_JSON, 64, get(w, Q_OP_WIRE_BYTES), B_CANONICAL, cap(w, B_CANONICAL), B_CANONICAL_WORK, ARENA_BYTES, B_EMPTY, 0, 0, 1125)
    if phase == 1125:
        if get(w, C_RETURN) == 0 or get(w, C_RETURN) > get(w, Q_OP_WIRE_BYTES):
            return refuse(w, 1238)
        put(w, Q_CANON_BYTES, get(w, C_RETURN))
        return release(o, w, B_CANONICAL_WORK, 1126)
    if phase == 1126:
        return hash_start(w, B_CANONICAL, get(w, Q_CANON_BYTES), Q_OPERATION_HASH, 1130)
    if phase == 1130:
        size = get(w, Q_FACT_BYTES) + get(w, Q_SLICE_BYTES) + 256
        put(w, Q_COMMAND_BYTES, size)
        return grow(o, w, B_COMMAND, size, 1131)
    if phase == 1131:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        zero(w, WIRE, 256)
        wire8(w, QUERY_COMMAND, 1, 73, request, 0, get(w, Q_FACT_BYTES), get(w, Q_SLICE_BYTES), get(w, Q_FACT_EVENT + 64))
        copy_local(w, WIRE + 64, Q_FACT_EVENT + 72, 40)
        copy_digest(w, WIRE + 128, E_CORE_HASH)
        copy_digest(w, WIRE + 160, E_INPUT_HASH)
        copy_digest(w, WIRE + 192, Q_OPERATION_HASH)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 256, 1132)
    if phase == 1132:
        return copy(o, w, B_FACTS, 0, B_COMMAND, 256, get(w, Q_FACT_BYTES), 1133)
    if phase == 1133:
        return copy(o, w, B_SLICE, 0, B_COMMAND, 256 + get(w, Q_FACT_BYTES), get(w, Q_SLICE_BYTES), 1134)
    if phase == 1134:
        return release(o, w, B_KERNEL, 1135)
    if phase == 1135:
        return edit_simple_start(w, 39, B_COMMAND, 0, get(w, Q_COMMAND_BYTES), B_SELECTED_SOURCE, cap(w, B_SELECTED_SOURCE), B_KERNEL, 1024, QUERY_EVENT, 256, B_COMMAND, get(w, Q_COMMAND_BYTES), 1136)
    if phase == 1136:
        if get(w, E_SIMPLE_EVENT + 8) != 0:
            return refuse(w, 1239)
        put(w, C_PACKET_SLOT, B_KERNEL)
        put(w, C_PACKET_OFFSET, get(w, E_SIMPLE_EVENT + 48))
        put(w, C_PACKET_BYTES, get(w, E_SIMPLE_EVENT + 56))
        put(w, L_INDEX_TARGET, B_QUERY_SOURCE)
        put(w, L_INDEX_RETURN, 1137)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 1137:
        return release(o, w, B_COMMAND, 1138)
    if phase == 1138:
        return release(o, w, B_KERNEL, 1139)
    if phase == 1139:
        return grow(o, w, B_COMMAND, 64, 1140)
    if phase == 1140:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        wire8(w, BRIDGE_COMMAND, 1, 17, request, 0, 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 64, 1141)
    if phase == 1141:
        return edit_simple_start(w, 47, B_QUERY_SOURCE, 0, cap(w, B_QUERY_SOURCE), B_COMMAND, 64, B_KERNEL, 512, BRIDGE_EVENT, 256, B_COMMAND, 64, 1142)
    if phase == 1142:
        if get(w, E_SIMPLE_EVENT + 8) != 0:
            return refuse(w, 1240)
        put(w, Q_GRAPH_BYTES, get(w, E_SIMPLE_EVENT + 56))
        return grow(o, w, B_QUERY_RESULT, get(w, Q_GRAPH_BYTES), 1143)
    if phase == 1143:
        return copy(o, w, B_KERNEL, get(w, E_SIMPLE_EVENT + 48), B_QUERY_RESULT, 0, get(w, Q_GRAPH_BYTES), 1144)
    if phase == 1144:
        return protect(o, w, B_QUERY_RESULT, 1, 1145)
    if phase == 1145:
        return view(o, w, B_QUERY_RESULT, 0, 64, 1146)
    if phase == 1146:
        if graph_header(w, B_QUERY_RESULT) == 0:
            return refuse(w, 1241)
        put(w, Q_GRAPH_ROOT, get(w, OBS + 24))
        put(w, Q_RELEASE, 9)
        put(w, C_PHASE, 1190)
        return 0
    if phase == 1190:
        slot = get(w, Q_RELEASE)
        if slot == 14:
            slot = 28
        elif slot == 30:
            slot = 31
        elif slot == 32:
            slot = 53
        elif slot == 54:
            result = edit_bound_start(w, B_QUERY_RESULT, get(w, Q_GRAPH_ROOT), 5, B_PREPARED_WIRE, 0, QUERY, 1300)
            if result != 0:
                return result
            return switch(o, w, SERVICE, 50000)
        put(w, Q_RELEASE, slot + 1)
        return release(o, w, slot, 1190)
    return refuse(w, 1242)

def batch_query_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1400:
        if get(w, Q_INDEX) == 0:
            put(w, Q_QUERY_ROOTS, get(w, Q_GRAPH_ROOT))
            return grow(o, w, B_JOINED, cap(w, B_QUERY_RESULT), 1401)
        return view(o, w, B_JOINED, 0, 64, 1410)
    if phase == 1401:
        return copy(o, w, B_QUERY_RESULT, 0, B_JOINED, 0, cap(w, B_QUERY_RESULT), 1420)
    if phase == 1410:
        if graph_header(w, B_JOINED) == 0:
            return refuse(w, 1250)
        put(w, Q_JOIN_NODES, get(w, OBS + 16))
        put(w, Q_JOIN_ROOT, get(w, OBS + 24))
        if cap(w, B_JOINED) > MAX - 128:
            return refuse(w, 1251)
        put(w, Q_COMMAND_BYTES, 128 + cap(w, B_JOINED))
        return grow(o, w, B_COMMAND, get(w, Q_COMMAND_BYTES), 1411)
    if phase == 1411:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        zero(w, WIRE, 128)
        wire8(w, MERGE_COMMAND, 1, 41, request, 0, get(w, Q_JOIN_ROOT), get(w, Q_GRAPH_ROOT), 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 128, 1412)
    if phase == 1412:
        return copy(o, w, B_JOINED, 0, B_COMMAND, 128, cap(w, B_JOINED), 1413)
    if phase == 1413:
        return edit_simple_start(w, 48, B_COMMAND, 0, get(w, Q_COMMAND_BYTES), B_QUERY_RESULT, cap(w, B_QUERY_RESULT), B_KERNEL, 512, MERGE_EVENT, 256, B_COMMAND, get(w, Q_COMMAND_BYTES), 1414)
    if phase == 1414:
        if get(w, E_SIMPLE_EVENT + 8) != 0:
            return refuse(w, 1252)
        put(w, Q_JOIN_BYTES, get(w, E_SIMPLE_EVENT + 56))
        index = 0
        while index < get(w, Q_INDEX):
            if get(w, Q_QUERY_ROOTS + index * 8) == MAX:
                return refuse(w, 1253)
            put(w, Q_QUERY_ROOTS + index * 8, get(w, Q_QUERY_ROOTS + index * 8) + 1)
            index = index + 1
        if get(w, Q_GRAPH_ROOT) >= MAX - get(w, Q_JOIN_NODES):
            return refuse(w, 1254)
        put(w, Q_QUERY_ROOTS + get(w, Q_INDEX) * 8, get(w, Q_GRAPH_ROOT) + get(w, Q_JOIN_NODES) + 1)
        return grow(o, w, B_JOIN_TEMP, get(w, Q_JOIN_BYTES), 1415)
    if phase == 1415:
        return copy(o, w, B_KERNEL, get(w, E_SIMPLE_EVENT + 48), B_JOIN_TEMP, 0, get(w, Q_JOIN_BYTES), 1416)
    if phase == 1416:
        return release(o, w, B_JOINED, 1417)
    if phase == 1417:
        return grow(o, w, B_JOINED, get(w, Q_JOIN_BYTES), 1418)
    if phase == 1418:
        return copy(o, w, B_JOIN_TEMP, 0, B_JOINED, 0, get(w, Q_JOIN_BYTES), 1419)
    if phase == 1419:
        return release(o, w, B_JOIN_TEMP, 1420)
    if phase == 1420:
        return protect(o, w, B_JOINED, 1, 1421)
    if phase == 1421:
        return release(o, w, B_QUERY_RESULT, 1422)
    if phase == 1422:
        return release(o, w, B_PREPARED_WIRE, 1423)
    if phase == 1423:
        return release(o, w, B_COMMAND, 1424)
    if phase == 1424:
        return release(o, w, B_KERNEL, 1425)
    if phase == 1425:
        put(w, Q_BATCH_FINAL, 0)
        put(w, Q_COMMAND_BYTES, 128 + 8 * (get(w, Q_INDEX) + 1))
        put(w, C_PHASE, 1500)
        return 0
    if phase == 1500:
        return grow(o, w, B_COMMAND, get(w, Q_COMMAND_BYTES), 1501)
    if phase == 1501:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        zero(w, WIRE, 256)
        wire8(w, BATCH_COMMAND, 1, 71, request, 0, get(w, Q_BATCH_FINAL), get(w, Q_INDEX) + 1, 0)
        copy_local(w, WIRE + 128, Q_QUERY_ROOTS, 8 * (get(w, Q_INDEX) + 1))
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, get(w, Q_COMMAND_BYTES), 1502)
    if phase == 1502:
        return edit_simple_start(w, 49, B_JOINED, 0, cap(w, B_JOINED), B_COMMAND, get(w, Q_COMMAND_BYTES), B_KERNEL, 1024, BATCH_EVENT, 256, B_COMMAND, get(w, Q_COMMAND_BYTES), 1503)
    if phase == 1503:
        if get(w, E_SIMPLE_EVENT + 8) == 2:
            return query_error(w, 4, get(w, E_SIMPLE_EVENT + 64))
        if get(w, Q_BATCH_FINAL) == 1:
            put(w, Q_GRAPH_BYTES, get(w, E_SIMPLE_EVENT + 56))
            put(w, Q_GRAPH_ROOT, get(w, E_SIMPLE_EVENT + 72))
            return grow(o, w, B_QUERY_RESULT, get(w, Q_GRAPH_BYTES), 1520)
        return release(o, w, B_COMMAND, 1504)
    if phase == 1504:
        return release(o, w, B_KERNEL, 1505)
    if phase == 1505:
        if get(w, Q_INDEX) + 1 == get(w, Q_COUNT):
            put(w, Q_BATCH_FINAL, 1)
            put(w, C_PHASE, 1500)
            return 0
        put(w, Q_INDEX, get(w, Q_INDEX) + 1)
        if get(w, E_MODE) == 4:
            put(w, C_PHASE, 1003)
        else:
            put(w, C_PHASE, 1100)
        return 0
    if phase == 1520:
        return copy(o, w, B_KERNEL, get(w, E_SIMPLE_EVENT + 48), B_QUERY_RESULT, 0, get(w, Q_GRAPH_BYTES), 1521)
    if phase == 1521:
        return protect(o, w, B_QUERY_RESULT, 1, 1522)
    if phase == 1522:
        return release(o, w, B_COMMAND, 1523)
    if phase == 1523:
        return release(o, w, B_KERNEL, 1524)
    if phase == 1524:
        return release(o, w, B_JOINED, 1525)
    if phase == 1525:
        result = edit_bound_start(w, B_QUERY_RESULT, get(w, Q_GRAPH_ROOT), 5, B_PREPARED_WIRE, 0, QUERY, 1600)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    return refuse(w, 1255)
'''

ERRORS={
    (1,1):'E_HIA_QUERY: query must be an exact prepare_edit result',
    (1,2):'E_HIA_QUERY: invalid query selector',
    (1,10):'E_HIA_EDIT_BATCH: a batch requires 1..16 selections',
    (1,11):'E_HIA_EDIT_BATCH: a selection requires exactly function, block, output, fields',
    (1,20):'E_HIA_EDIT_BATCH: expected an exact prepared batch query',
    (1,21):'E_HIA_EDIT_BATCH: invalid query sites',
    (1,22):'E_HIA_EDIT_BATCH: query sites must retain their exact ordered identities',
    (1,23):'E_HIA_EDIT_BATCH: invalid nested selection',
    (2,1):'E_HIA_QUERY: fields must be a unique nonempty subset of op, args, attrs',
    (2,2):'E_HIA_QUERY: function, block and output identities must be strings',
    (2,3):'E_HIA_QUERY: function not found',
    (2,4):'E_HIA_QUERY: block not found',
    (2,5):'E_HIA_QUERY: SSA output does not identify one instruction',
    (3,0xfffffffc):'E_HIA_QUERY: cross-block SSA cycle reaches selected block; use full-module view',
    (3,0xfffffffb):'E_HIA_QUERY: transitive CFG view exceeds bounded block budget',
    (3,0xfffffffa):'E_HIA_QUERY: transitive SSA view exceeds bounded operation budget',
    (4,1):'E_HIA_EDIT_BATCH: selections overlap one instruction',
}
def literals():
    lines=['def query_error(w:mutbuf, stage:u64, code:u64) -> u64:']
    for (stage,code),text in ERRORS.items():
        raw=text.encode();lines.append(f'    if stage == {stage} and code == {code}:')
        end=(len(raw)//8)*8
        for at in range(0,end,8):lines.append(f'        put(w, WIRE + {at}, {int.from_bytes(raw[at:at+8],"little")})')
        for at in range(end,len(raw)):lines.append(f'        store(w, WIRE + {at}, {raw[at]})')
        lines.append(f'        return edit_error_start(w, 1, 100 + stage, code, B_CONTROLLER, WIRE, {len(raw)})')
    lines.append('    return refuse(w, 1260)')
    return '\n'.join(lines)+'\n'
def source_program():return source(BODY+'\n'+literals()+'\n'+ALL,CONSTANTS,'edit_query')
def document():return build(source_program(),'agent_edit_query_driver')
if __name__=='__main__':write(document(),'agent_edit_query_driver.hiaasm')
