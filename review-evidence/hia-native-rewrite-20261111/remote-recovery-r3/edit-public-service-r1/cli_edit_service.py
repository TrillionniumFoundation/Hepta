"""Full HIA public edit-service continuation, new unqualified development.

All runtime decisions below compile to HIA. The authoring transformation retains
the exact prior 56/57/59 semantic owners and changes only root orchestration.
Original input, compiler, native and file budgets are unchanged.
"""
import ast
from copy import deepcopy
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
CONSTANTS=dict(ES_INIT=magic("HIACBI01"),ES_REPLY=magic("HIACBR01"),
 ES_RESULT=magic("HIACBE01"),ES_PUBLICATION=magic("HIACPR01"),
 ES_STATE=magic("HIAEPS01"),ES_GRAPH=magic("HIAGRF01"),
 ES_HEAD=33792,ES_TEXT=34048,ES_EXPECT=35072,ES_HASH=35456,
 ES_ROWS=36000,ES_CHARCOUNTS=36512,ES_FIELDS=36544,ES_BUFFER=65536,
 ES_FRAME_SLOT=31,ES_PUB_SLOT=29,ES_TEMP_SLOT=27,ES_PUBLIC_SLOT=26,
 E_INPUT_STYLE=16640,J_RETURN=16648,J_REQUEST=16656,J_GRAPH_AT=16664,
 J_GRAPH_BYTES=16672,J_RELEASE=16680,J_RESPONSE_BYTES=16688)
_NAMES=("MAGIC","ACTION","PARENT_LEASE","PARENT_SEQUENCE","OUTPUT","BORROWED",
 "REQUEST","YIELD_SEQUENCE","KIND","DOMAIN","EXIT","FIELD","POLICY","TARGET",
 "SOURCE","AT","BYTES","LIFECYCLE","CONTINUE","RELEASE","RESPONSE_READY",
 "FIELD_COUNT","FIELD_BYTES","STRING_INDEX","STRING_AT","STRING_COUNT",
 "UTF_NEED","UTF_LOW","UTF_HIGH","GRAPH_BASE","GRAPH_BYTES","GRAPH_WRITE",
 "FIRST_BYTES","SECOND_BYTES","THIRD_BYTES","RECEIPT_AT","RECEIPT_PREFIX",
 "PUBLIC_BYTES","PUBLIC_PAYLOAD_BYTES","DEST_BYTES","TX_AT","TX_BYTES",
 "EXPECTED_BYTES","PRETTY_PASS","PRETTY_AT","PRETTY_OUT","PRETTY_DEPTH",
 "PRETTY_STRING","PRETTY_ESCAPE","PRETTY_OPEN","PRETTY_CHUNK","TEXT1_BYTES",
 "TEXT2_BYTES","TEXT3_BYTES","TEXT4_BYTES")
CONSTANTS.update({"ES_"+n:32000+i*8 for i,n in enumerate(_NAMES)})

BODY=r'''
def edit_service(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 2800)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if es_begin(s, w) == 0:
            return refuse(w, 2801)
    elif get(w, C_MAGIC) != EDIT_STATE or get(w, ES_MAGIC) != ES_STATE or acknowledge(s, w, MAIN) == 0:
        return refuse(w, 2802)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase == 90000:
            result = es_terminal_start(w)
        elif phase >= 70000 and phase < 71000:
            result = es_input_step(o, w)
        elif phase >= 73000 and phase < 73100:
            result = es_result_step(o, w)
        elif phase >= 74000 and phase < 75000:
            result = es_publication_step(o, w)
        elif phase >= 75000 and phase < 76000:
            result = es_output_step(o, w)
        elif phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        elif phase >= 40000 and phase < 40100:
            result = edit_simple_step(o, w)
        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)
        elif phase >= 600 and phase < 700:
            result = json_front_step(o, w)
        else:
            result = edit_main_step(o, w)
        if result != 0:
            return result
    return refuse(w, 2803)

def es_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 128 or word(s, 0) != ES_INIT or word(s, 8) != 1 or word(s, 16) != 2:
        return 0
    lease = word(s, 24)
    action = word(s, 48)
    digits = word(s, 56)
    if lease == 0 or lease > MAX - 3 or word(s, 32) == 0 or word(s, 40) == 0:
        return 0
    if action < 12 or action > 15 or digits > 4294967295 or (digits != 0 and digits < 640):
        return 0
    if word(s, 64) != cap(w, 1) or word(s, 72) != cap(w, 4) or word(s, 80) != cap(w, 5):
        return 0
    if word(s, 88) != 16 or word(s, 96) != 1024 or word(s, 104) != 32 or word(s, 112) != 0 or word(s, 120) != 0:
        return 0
    if cap(w, 0) != 1 or cap(w, 2) != MIN_WORK or cap(w, 5) < 1536:
        return 0
    slot = 3
    while slot < 64:
        if slot != 4 and slot != 5 and cap(w, slot) != 0:
            return 0
        slot = slot + 1
    at = 0
    while at < MIN_WORK:
        if at < CAPS or at >= CAPS + 512:
            if byte(w, at) != 0:
                return 0
        at = at + 1
    put(w, C_MAGIC, EDIT_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, MAIN)
    put(w, ES_MAGIC, ES_STATE)
    put(w, ES_ACTION, action)
    put(w, ES_PARENT_LEASE, word(s, 32))
    put(w, ES_PARENT_SEQUENCE, word(s, 40))
    put(w, ES_BORROWED, 48)
    mode = 3
    if action == 13:
        mode = 1
    elif action == 14:
        mode = 4
    elif action == 15:
        mode = 2
    put(w, E_MODE, mode)
    put(w, E_DIGITS, digits)
    put(w, E_REQUEST, 1)
    put(w, E_INPUT_STYLE, 1)
    put(w, J_RETURN, 1000)
    put(w, C_PHASE, 1)
    return 1

def es_drop(o:mutbuf, w:mutbuf, slot:u64, next:u64) -> u64:
    bit = 1 << slot
    mask = get(w, ES_BORROWED)
    if (mask & bit) == 0:
        return release(o, w, slot, next)
    put(w, ES_BORROWED, mask ^ bit)
    put(w, C_OBSERVE, 0)
    args(w, slot, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 5, next)

def es_row_slot(w:mutbuf, field:u64) -> u64:
    owner = get(w, ES_ROWS + field * 32 + 8)
    if owner == 1:
        return 4
    if owner == 2:
        return 5
    return 0

def es_rows_valid(w:mutbuf) -> u64:
    index = 0
    while index < 16:
        row = ES_ROWS + index * 32
        present = get(w, row)
        owner = get(w, row + 8)
        at = get(w, row + 16)
        size = get(w, row + 24)
        if present > 1 or owner > 2:
            return 0
        if owner == 0:
            if at != 0 or size != 0:
                return 0
        elif present != 1 or inside(w, 3 + owner, at, size) == 0:
            return 0
        if present == 0 and owner != 0:
            return 0
        index = index + 1
    if get(w, ES_ROWS + 64) != 1:
        return 0
    if get(w, ES_ROWS + 72) != 0 and get(w, ES_ROWS + 88) != 0:
        put(w, ES_OUTPUT, 1)
    action = get(w, ES_ACTION)
    if action == 12:
        index = 8
        while index < 12:
            if get(w, ES_ROWS + index * 32) != 1 or es_row_slot(w, index) == 0:
                return 0
            index = index + 1
    else:
        first = 13
        if action == 14:
            first = 12
        if get(w, ES_ROWS + first * 32) != 1 or es_row_slot(w, first) == 0:
            return 0
        if action != 14 and (get(w, ES_ROWS + 14 * 32) != 1 or es_row_slot(w, 14) == 0):
            return 0
    return 1

def es_fields_valid(w:mutbuf, size:u64) -> u64:
    at = 0
    start = 0
    mask = 0
    count = 0
    total = 0
    while at <= size:
        boundary = 0
        if at == size:
            boundary = 1
        elif byte(w, OBS + at) == 44:
            boundary = 1
        if boundary == 1:
            length = at - start
            value = 0
            if length == 2:
                if byte(w, OBS + start) == 111 and byte(w, OBS + start + 1) == 112:
                    value = 1
            elif length == 4:
                if get_part(w, OBS + start, 4) == 1936159329:
                    value = 2
            elif length == 5:
                if get_part(w, OBS + start, 5) == 495841080417:
                    value = 4
            if value == 0 or (mask & value) != 0 or count >= 3:
                return 0
            put(w, ES_FIELDS + count * 16, value)
            put(w, ES_FIELDS + count * 16 + 8, length)
            count = count + 1
            total = total + length
            mask = mask | value
            start = at + 1
        at = at + 1
    if count == 0:
        return 0
    put(w, ES_FIELD_COUNT, count)
    put(w, ES_FIELD_BYTES, total)
    return 1

def get_part(w:mutbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def es_input_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 70000:
        return view(o, w, 5, 1024, 256, 70001)
    if phase == 70001:
        copy_local(w, ES_ROWS, OBS, 256)
        return view(o, w, 5, 1280, 256, 70002)
    if phase == 70002:
        copy_local(w, ES_ROWS + 256, OBS, 256)
        if es_rows_valid(w) == 0:
            return refuse(w, 2810)
        if get(w, ES_ACTION) != 12:
            put(w, C_PHASE, 70400)
            return 0
        size = get(w, ES_ROWS + 11 * 32 + 24)
        if size == 0 or size > 13:
            return es_bad_fields(w)
        return view(o, w, es_row_slot(w, 11), get(w, ES_ROWS + 11 * 32 + 16), size, 70100)
    if phase == 70100:
        if es_fields_valid(w, get(w, ES_ROWS + 11 * 32 + 24)) == 0:
            return es_bad_fields(w)
        put(w, ES_STRING_INDEX, 0)
        put(w, C_PHASE, 70200)
        return 0
    if phase >= 70200 and phase < 70300:
        return es_string_step(o, w)
    if phase >= 70300 and phase < 70400:
        return es_graph_step(o, w)
    if phase == 70400:
        return es_drop(o, w, 4, 70401)
    if phase == 70401:
        return es_drop(o, w, 5, 70402)
    if phase == 70402:
        action = get(w, ES_ACTION)
        if action == 12:
            return grow(o, w, 4, get(w, ES_GRAPH_BYTES), 70403)
        field = 13
        limit = 8388608
        if action == 14:
            field = 12
        elif action == 15:
            limit = 1048576
        return es_need_file(w, field, limit, 4, 70500)
    if phase == 70403:
        return copy(o, w, ES_TEMP_SLOT, 0, 4, 0, get(w, ES_GRAPH_BYTES), 70404)
    if phase == 70404:
        return protect(o, w, 4, 1, 70405)
    if phase == 70405:
        return release(o, w, ES_TEMP_SLOT, 70406)
    if phase == 70406:
        return switch(o, w, QUERY, 1000)
    if phase == 70500:
        if get(w, ES_ACTION) == 15:
            return es_need_file(w, 14, 65536, 5, 70501)
        put(w, C_PHASE, 600)
        return 0
    if phase == 70501:
        put(w, ES_RESPONSE_READY, 1)
        put(w, C_PHASE, 600)
        return 0
    if phase == 70502:
        put(w, ES_RESPONSE_READY, 1)
        put(w, C_PHASE, 606)
        return 0
    return refuse(w, 2811)

def es_string_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    index = get(w, ES_STRING_INDEX)
    if phase == 70200:
        if index == 3:
            put(w, C_PHASE, 70300)
            return 0
        put(w, ES_STRING_AT, 0)
        put(w, ES_STRING_COUNT, 0)
        put(w, ES_UTF_NEED, 0)
        put(w, C_PHASE, 70201)
        return 0
    row = ES_ROWS + (8 + index) * 32
    size = get(w, row + 24)
    if phase == 70201:
        at = get(w, ES_STRING_AT)
        if at == size:
            if get(w, ES_UTF_NEED) != 0:
                return refuse(w, 2812)
            put(w, ES_CHARCOUNTS + index * 8, get(w, ES_STRING_COUNT))
            put(w, ES_STRING_INDEX, index + 1)
            put(w, C_PHASE, 70200)
            return 0
        return view(o, w, es_row_slot(w, 8 + index), get(w, row + 16) + at, minimum(size - at, 256), 70202)
    if phase == 70202:
        count = minimum(size - get(w, ES_STRING_AT), 256)
        if es_utf8_chunk(w, count) == 0:
            return refuse(w, 2813)
        put(w, ES_STRING_AT, get(w, ES_STRING_AT) + count)
        put(w, C_PHASE, 70201)
        return 0
    return refuse(w, 2814)

def es_utf8_chunk(w:mutbuf, size:u64) -> u64:
    index = 0
    need = get(w, ES_UTF_NEED)
    chars = get(w, ES_STRING_COUNT)
    low = get(w, ES_UTF_LOW)
    high = get(w, ES_UTF_HIGH)
    while index < size:
        value = byte(w, OBS + index)
        if need == 0:
            if value < 128:
                chars = chars + 1
            else:
                low = 128
                high = 191
                if value >= 194 and value <= 223:
                    need = 1
                elif value >= 224 and value <= 239:
                    need = 2
                    if value == 224:
                        low = 160
                elif value >= 240 and value <= 244:
                    need = 3
                    if value == 240:
                        low = 144
                    elif value == 244:
                        high = 143
                else:
                    return 0
                chars = chars + 1
        else:
            if value < low or value > high:
                return 0
            need = need - 1
            low = 128
            high = 191
        index = index + 1
    put(w, ES_UTF_NEED, need)
    put(w, ES_UTF_LOW, low)
    put(w, ES_UTF_HIGH, high)
    put(w, ES_STRING_COUNT, chars)
    return 1

def es_graph_string(w:mutbuf, node:u64, at:u64, size:u64, chars:u64) -> u64:
    base = ES_BUFFER + 64 + (node - 1) * 64
    put(w, base, 4)
    put(w, base + 8, at)
    put(w, base + 16, size)
    put(w, base + 48, chars)
    return 0

def es_graph_header(w:mutbuf) -> u64:
    fields = get(w, ES_FIELD_COUNT)
    nodes = 10 + fields
    edges = 9 + fields
    base = 64 + nodes * 64 + edges * 8
    size = 25 + get(w, ES_FIELD_BYTES)
    index = 0
    while index < 3:
        count = get(w, ES_ROWS + (8 + index) * 32 + 24)
        if count > MAX - size:
            return 0
        size = size + count
        index = index + 1
    if size > MAX - base or base + 25 > 1024:
        return 0
    put(w, ES_GRAPH_BASE, base)
    put(w, ES_GRAPH_BYTES, base + size)
    zero(w, ES_BUFFER, base + 25)
    put(w, ES_BUFFER, ES_GRAPH)
    put(w, ES_BUFFER + 8, 101)
    put(w, ES_BUFFER + 16, nodes)
    put(w, ES_BUFFER + 24, 1)
    put(w, ES_BUFFER + 32, edges)
    put(w, ES_BUFFER + 40, size)
    put(w, ES_BUFFER + 48, base + size)
    put(w, ES_BUFFER + 64, 5)
    put(w, ES_BUFFER + 64 + 32, 1)
    put(w, ES_BUFFER + 64 + 40, 1)
    put(w, ES_BUFFER + 128, 6)
    put(w, ES_BUFFER + 128 + 24, 1)
    put(w, ES_BUFFER + 128 + 32, 4)
    put(w, ES_BUFFER + 128 + 40, 2)
    put(w, ES_BUFFER + 640, 5)
    put(w, ES_BUFFER + 640 + 24, 9)
    put(w, ES_BUFFER + 640 + 32, fields)
    put(w, ES_BUFFER + 640 + 40, 10)
    es_graph_string(w, 3, base, 8, 8)
    es_graph_string(w, 5, base + 8, 5, 5)
    es_graph_string(w, 7, base + 13, 6, 6)
    es_graph_string(w, 9, base + 19, 6, 6)
    es_graph_keys(w, base)
    at = base + 25
    index = 0
    while index < 3:
        size = get(w, ES_ROWS + (8 + index) * 32 + 24)
        es_graph_string(w, 4 + index * 2, at, size, get(w, ES_CHARCOUNTS + index * 8))
        at = at + size
        index = index + 1
    index = 0
    while index < fields:
        size = get(w, ES_FIELDS + index * 16 + 8)
        es_graph_string(w, 11 + index, at, size, size)
        at = at + size
        index = index + 1
    edge = ES_BUFFER + 64 + nodes * 64
    put(w, edge, 2)
    index = 0
    while index < 8:
        put(w, edge + 8 + index * 8, 3 + index)
        index = index + 1
    index = 0
    while index < fields:
        put(w, edge + 72 + index * 8, 11 + index)
        index = index + 1
    put(w, ES_GRAPH_WRITE, base + 25)
    put(w, ES_STRING_INDEX, 0)
    return 1

def es_graph_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 70300:
        if es_graph_header(w) == 0:
            return refuse(w, 2820)
        return grow(o, w, ES_TEMP_SLOT, get(w, ES_GRAPH_BYTES), 70301)
    if phase == 70301:
        return copy(o, w, 2, ES_BUFFER, ES_TEMP_SLOT, 0, get(w, ES_GRAPH_BASE) + 25, 70302)
    if phase == 70302:
        index = get(w, ES_STRING_INDEX)
        if index == 3:
            es_field_literals(w)
            return copy(o, w, 2, ES_TEXT, ES_TEMP_SLOT, get(w, ES_GRAPH_WRITE), get(w, ES_FIELD_BYTES), 70304)
        row = ES_ROWS + (8 + index) * 32
        size = get(w, row + 24)
        put(w, ES_STRING_INDEX, index + 1)
        at = get(w, ES_GRAPH_WRITE)
        put(w, ES_GRAPH_WRITE, at + size)
        return copy(o, w, es_row_slot(w, 8 + index), get(w, row + 16), ES_TEMP_SLOT, at, size, 70302)
    if phase == 70304:
        put(w, C_PHASE, 70400)
        return 0
    return refuse(w, 2821)

def es_need_file(w:mutbuf, field:u64, limit:u64, target:u64, next:u64) -> u64:
    if cap(w, target) != 0 or (get(w, ES_BORROWED) & (1 << target)) != 0:
        return refuse(w, 2830)
    request = advance(w, ES_REQUEST)
    if request == 0:
        return ABI
    put(w, ES_CONTINUE, next)
    return es_start_result(w, 1, 0, 0, field, limit, target, 0, 0, 0)

def es_start_result(w:mutbuf, kind:u64, domain:u64, exitcode:u64, field:u64, policy:u64, target:u64, source:u64, at:u64, size:u64) -> u64:
    if kind < 1 or kind > 4 or cap(w, ES_FRAME_SLOT) != 0 or size > MAX - 128:
        return refuse(w, 2831)
    if kind == 1:
        if source != 0 or at != 0 or size != 0 or domain != 0 or exitcode != 0 or get(w, ES_REQUEST) == 0:
            return refuse(w, 2832)
        if field < 12 or field > 14 or (target != 4 and target != 5) or policy == 0:
            return refuse(w, 2833)
        put(w, ES_LIFECYCLE, 0)
    else:
        if size == 0 or inside(w, source, at, size) == 0:
            return refuse(w, 2834)
        if kind == 2:
            if field != 2 or target != ES_PUB_SLOT or (policy != 1 and policy != 2) or domain != 0 or exitcode != 0 or get(w, ES_OUTPUT) != 1 or get(w, ES_REQUEST) == 0:
                return refuse(w, 2835)
            put(w, ES_LIFECYCLE, 0)
        else:
            if field != 0 or target != 0:
                return refuse(w, 2836)
            if kind == 3:
                if domain != 0 or exitcode != 0 or policy != 1:
                    return refuse(w, 2837)
            elif domain != 1 or exitcode != 2 or policy != 0:
                return refuse(w, 2838)
            put(w, ES_LIFECYCLE, 1)
    put(w, ES_KIND, kind)
    put(w, ES_DOMAIN, domain)
    put(w, ES_EXIT, exitcode)
    put(w, ES_FIELD, field)
    put(w, ES_POLICY, policy)
    put(w, ES_TARGET, target)
    put(w, ES_SOURCE, source)
    put(w, ES_AT, at)
    put(w, ES_BYTES, size)
    put(w, C_PHASE, 73000)
    return 0

def es_result_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 73000:
        return grow(o, w, ES_FRAME_SLOT, 128 + get(w, ES_BYTES), 73001)
    if phase == 73001:
        if get(w, ES_BYTES) == 0:
            put(w, C_PHASE, 73002)
            return 0
        return copy(o, w, get(w, ES_SOURCE), get(w, ES_AT), ES_FRAME_SLOT, 128, get(w, ES_BYTES), 73002)
    if phase == 73002:
        if get(w, C_SEQUENCE) > MAX - 3:
            return refuse(w, 2840)
        sequence = get(w, C_SEQUENCE) + 3
        put(w, ES_YIELD_SEQUENCE, sequence)
        zero(w, ES_HEAD, 128)
        put(w, ES_HEAD, ES_RESULT)
        put(w, ES_HEAD + 8, 1)
        put(w, ES_HEAD + 16, 2)
        put(w, ES_HEAD + 24, get(w, C_LEASE))
        put(w, ES_HEAD + 32, sequence)
        if get(w, ES_KIND) < 3:
            put(w, ES_HEAD + 40, get(w, ES_REQUEST))
        put(w, ES_HEAD + 48, get(w, ES_KIND))
        put(w, ES_HEAD + 56, get(w, ES_DOMAIN))
        put(w, ES_HEAD + 64, get(w, ES_EXIT))
        put(w, ES_HEAD + 72, get(w, ES_FIELD))
        put(w, ES_HEAD + 80, get(w, ES_POLICY))
        put(w, ES_HEAD + 88, get(w, ES_TARGET))
        if get(w, ES_BYTES) != 0:
            put(w, ES_HEAD + 96, 128)
        put(w, ES_HEAD + 104, get(w, ES_BYTES))
        put(w, ES_HEAD + 112, 128 + get(w, ES_BYTES))
        return copy(o, w, 2, ES_HEAD, ES_FRAME_SLOT, 0, 128, 73003)
    if phase == 73003:
        return protect(o, w, ES_FRAME_SLOT, 1, 73004)
    if phase == 73004:
        if get(w, C_SEQUENCE) == MAX or get(w, C_SEQUENCE) + 1 != get(w, ES_YIELD_SEQUENCE):
            return refuse(w, 2841)
        mask = 0
        observed = 0
        if get(w, ES_LIFECYCLE) == 0:
            mask = 1 << get(w, ES_TARGET)
            observed = 128
        put(w, C_OBSERVE, observed)
        args(w, get(w, C_LEASE), get(w, ES_LIFECYCLE), ES_FRAME_SLOT, 0, 128 + get(w, ES_BYTES), mask, 0, 0, 0, 0, 0, 0)
        return event(o, w, 18, 73005)
    if phase == 73005:
        if es_adopt_reply(w) == 0:
            return refuse(w, 2842)
        return release(o, w, ES_FRAME_SLOT, get(w, ES_CONTINUE))
    return refuse(w, 2843)

def es_adopt_reply(w:mutbuf) -> u64:
    if get(w, ES_KIND) > 2 or get(w, ES_LIFECYCLE) != 0 or get(w, C_RETURN) != 0:
        return 0
    if get(w, OBS) != ES_REPLY or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 2 or get(w, OBS + 24) != get(w, C_LEASE):
        return 0
    if get(w, OBS + 32) != get(w, ES_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, ES_REQUEST) or get(w, OBS + 48) != get(w, ES_KIND):
        return 0
    if get(w, OBS + 56) <= get(w, ES_PARENT_SEQUENCE) or get(w, OBS + 64) != get(w, ES_FIELD) or get(w, OBS + 72) != get(w, ES_TARGET) or get(w, OBS + 88) != get(w, ES_POLICY):
        return 0
    target = get(w, ES_TARGET)
    size = get(w, OBS + 80)
    if cap(w, target) != 0 or (get(w, ES_BORROWED) & (1 << target)) != 0:
        return 0
    if get(w, ES_KIND) == 1:
        if size > get(w, ES_POLICY):
            return 0
    elif size < 132:
        return 0
    at = 96
    while at < 128:
        if get(w, OBS + at) != 0:
            return 0
        at = at + 8
    put(w, ES_PARENT_SEQUENCE, get(w, OBS + 56))
    put(w, CAPS + target * 8, size)
    put(w, ES_BORROWED, get(w, ES_BORROWED) | (1 << target))
    return 1
'''

CONSTANTS.update(ES_OLD_TAIL=35616,ES_NEW_TAIL=35744,ES_INSERT_KEY=35872,
 ES_MERGE_SOURCE=32448,ES_MERGE_AT=32456,ES_MERGE_BYTES=32464,
 ES_MERGE_TARGET=32472,ES_INSERT_BYTES=32480,ES_TAIL_BYTES=32488,
 ES_EMIT_BYTES=32496,ES_OLD_TAIL_BYTES=0)
BODY+=r'''
def es_terminal_start(w:mutbuf) -> u64:
    if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0 or get(w, PUBLISH_TOTAL) == 0:
        return refuse(w, 2850)
    if cap(w, B_FINAL_OUTPUT) != get(w, PUBLISH_TOTAL):
        return refuse(w, 2851)
    put(w, ES_RELEASE, 4)
    put(w, C_PHASE, 75000)
    return 0

def es_output_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 75000:
        slot = get(w, ES_RELEASE)
        if slot < 64:
            put(w, ES_RELEASE, slot + 1)
            if slot != B_FINAL_OUTPUT:
                return es_drop(o, w, slot, 75000)
            return 0
        if get(w, PUBLISH_DOMAIN) != 0:
            if get(w, PUBLISH_DOMAIN) > 4:
                return refuse(w, 2852)
            return es_start_result(w, 4, 1, 2, 0, 0, 0, B_FINAL_OUTPUT, 0, get(w, PUBLISH_TOTAL))
        return view(o, w, B_FINAL_OUTPUT, 0, 64, 75001)
    if phase == 75001:
        if get(w, OBS) != EDIT_RESULT or get(w, OBS + 8) != get(w, E_MODE):
            return refuse(w, 2853)
        first = get(w, OBS + 16)
        second = get(w, OBS + 24)
        third = get(w, OBS + 32)
        if first == 0 or get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 2854)
        total = cap(w, B_FINAL_OUTPUT)
        if total < 64 or first > total - 64 or second > total - 64 - first or third != total - 64 - first - second:
            return refuse(w, 2855)
        put(w, ES_FIRST_BYTES, first)
        put(w, ES_SECOND_BYTES, second)
        put(w, ES_THIRD_BYTES, third)
        if get(w, E_MODE) >= 3:
            if second != 0 or third != 0:
                return refuse(w, 2856)
            if get(w, ES_OUTPUT) == 0:
                return es_start_result(w, 3, 0, 0, 0, 1, 0, B_FINAL_OUTPUT, 64, first)
            put(w, C_PHASE, 75200)
            return 0
        if second <= ES_OLD_TAIL_BYTES or third == 0:
            return refuse(w, 2857)
        put(w, ES_RECEIPT_AT, 64 + first)
        put(w, ES_RECEIPT_PREFIX, second - ES_OLD_TAIL_BYTES)
        es_receipt_tails(w)
        return view(o, w, B_FINAL_OUTPUT, 64 + first + second - ES_OLD_TAIL_BYTES, ES_OLD_TAIL_BYTES, 75100)
    if phase == 75100:
        index = 0
        while index < ES_OLD_TAIL_BYTES:
            if byte(w, OBS + index) != byte(w, ES_OLD_TAIL + index):
                return refuse(w, 2858)
            index = index + 1
        if get(w, ES_OUTPUT) == 0:
            return es_merge_start(w, B_FINAL_OUTPUT, 64, get(w, ES_FIRST_BYTES), ES_PUBLIC_SLOT, 1)
        put(w, ES_PUBLIC_PAYLOAD_BYTES, get(w, ES_FIRST_BYTES))
        return hash_view_start(w, B_FINAL_OUTPUT, 64, get(w, ES_FIRST_BYTES), ES_HASH, 75110)
    if phase == 75110:
        return es_request_publication(w, 1)
    if phase >= 75120 and phase < 75200:
        return es_merge_step(o, w)
    if phase >= 75200 and phase < 75300:
        return es_pretty_step(o, w)
    return refuse(w, 2859)

def es_merge_start(w:mutbuf, source:u64, at:u64, bytes:u64, target:u64, kind:u64) -> u64:
    if inside(w, source, at, bytes) == 0 or bytes == 0 or cap(w, target) != 0:
        return refuse(w, 2860)
    prefix = get(w, ES_RECEIPT_PREFIX)
    key = es_insert_literal(w, kind)
    tail = ES_OLD_TAIL_BYTES
    if kind == 2:
        tail = ES_PUBLISHED_TAIL_BYTES
    if bytes > MAX - prefix or key > MAX - prefix - bytes or tail > MAX - prefix - bytes - key:
        return refuse(w, 2861)
    put(w, ES_MERGE_SOURCE, source)
    put(w, ES_MERGE_AT, at)
    put(w, ES_MERGE_BYTES, bytes)
    put(w, ES_MERGE_TARGET, target)
    put(w, ES_INSERT_BYTES, key)
    put(w, ES_TAIL_BYTES, tail)
    put(w, ES_PUBLIC_BYTES, prefix + key + bytes + tail)
    put(w, C_PHASE, 75120)
    return 0

def es_merge_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    target = get(w, ES_MERGE_TARGET)
    if phase == 75120:
        return grow(o, w, target, get(w, ES_PUBLIC_BYTES), 75121)
    if phase == 75121:
        return copy(o, w, B_FINAL_OUTPUT, get(w, ES_RECEIPT_AT), target, 0, get(w, ES_RECEIPT_PREFIX), 75122)
    if phase == 75122:
        return copy(o, w, 2, ES_INSERT_KEY, target, get(w, ES_RECEIPT_PREFIX), get(w, ES_INSERT_BYTES), 75123)
    if phase == 75123:
        return copy(o, w, get(w, ES_MERGE_SOURCE), get(w, ES_MERGE_AT), target, get(w, ES_RECEIPT_PREFIX) + get(w, ES_INSERT_BYTES), get(w, ES_MERGE_BYTES), 75124)
    if phase == 75124:
        source = ES_OLD_TAIL
        if get(w, ES_OUTPUT) == 1:
            source = ES_NEW_TAIL
        return copy(o, w, 2, source, target, get(w, ES_PUBLIC_BYTES) - get(w, ES_TAIL_BYTES), get(w, ES_TAIL_BYTES), 75125)
    if phase == 75125:
        return protect(o, w, target, 1, 75126)
    if phase == 75126:
        return es_start_result(w, 3, 0, 0, 0, 1, 0, target, 0, get(w, ES_PUBLIC_BYTES))
    return refuse(w, 2862)

def es_pretty_reset(w:mutbuf, pass:u64) -> u64:
    put(w, ES_PRETTY_PASS, pass)
    put(w, ES_PRETTY_AT, 0)
    put(w, ES_PRETTY_OUT, 0)
    put(w, ES_PRETTY_DEPTH, 0)
    put(w, ES_PRETTY_STRING, 0)
    put(w, ES_PRETTY_ESCAPE, 0)
    put(w, ES_PRETTY_OPEN, 0)
    put(w, C_PHASE, 75201)
    return 0

def es_emit(w:mutbuf, value:u64) -> u64:
    at = get(w, ES_EMIT_BYTES)
    if at >= MIN_WORK - ES_BUFFER:
        return 0
    if get(w, ES_PRETTY_PASS) == 1:
        store(w, ES_BUFFER + at, value)
    put(w, ES_EMIT_BYTES, at + 1)
    return 1

def es_indent(w:mutbuf, depth:u64) -> u64:
    if depth > (MIN_WORK - ES_BUFFER - 1) >> 1 or es_emit(w, 10) == 0:
        return 0
    count = depth * 2
    index = 0
    while index < count:
        if es_emit(w, 32) == 0:
            return 0
        index = index + 1
    return 1

def es_pretty_chunk(w:mutbuf, size:u64) -> u64:
    put(w, ES_EMIT_BYTES, 0)
    index = 0
    while index < size:
        value = byte(w, OBS + index)
        if get(w, ES_PRETTY_STRING) == 1:
            if es_emit(w, value) == 0:
                return 0
            if get(w, ES_PRETTY_ESCAPE) == 1:
                put(w, ES_PRETTY_ESCAPE, 0)
            elif value == 92:
                put(w, ES_PRETTY_ESCAPE, 1)
            elif value == 34:
                put(w, ES_PRETTY_STRING, 0)
        else:
            depth = get(w, ES_PRETTY_DEPTH)
            open = get(w, ES_PRETTY_OPEN)
            if value == 93 or value == 125:
                if depth == 0:
                    return 0
                depth = depth - 1
                if open == 0:
                    if es_indent(w, depth) == 0:
                        return 0
                elif (open == 91 and value != 93) or (open == 123 and value != 125):
                    return 0
                put(w, ES_PRETTY_OPEN, 0)
                put(w, ES_PRETTY_DEPTH, depth)
                if es_emit(w, value) == 0:
                    return 0
            else:
                if open != 0:
                    if es_indent(w, depth) == 0:
                        return 0
                    put(w, ES_PRETTY_OPEN, 0)
                if value == 91 or value == 123:
                    if depth == MAX:
                        return 0
                    put(w, ES_PRETTY_DEPTH, depth + 1)
                    put(w, ES_PRETTY_OPEN, value)
                    if es_emit(w, value) == 0:
                        return 0
                elif value == 44:
                    if depth == 0 or es_emit(w, 44) == 0 or es_indent(w, depth) == 0:
                        return 0
                elif value == 58:
                    if es_emit(w, 58) == 0 or es_emit(w, 32) == 0:
                        return 0
                else:
                    if value <= 32 or value >= 128 or es_emit(w, value) == 0:
                        return 0
                    if value == 34:
                        put(w, ES_PRETTY_STRING, 1)
        index = index + 1
    return 1

def es_pretty_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 75200:
        return es_pretty_reset(w, 0)
    if phase == 75201:
        at = get(w, ES_PRETTY_AT)
        if at == get(w, ES_FIRST_BYTES):
            if get(w, ES_PRETTY_DEPTH) != 0 or get(w, ES_PRETTY_STRING) != 0 or get(w, ES_PRETTY_ESCAPE) != 0 or get(w, ES_PRETTY_OPEN) != 0:
                return refuse(w, 2870)
            size = get(w, ES_PRETTY_OUT)
            if size == MAX:
                return refuse(w, 2871)
            if get(w, ES_PRETTY_PASS) == 0:
                put(w, ES_PUBLIC_PAYLOAD_BYTES, size + 1)
                return grow(o, w, ES_TEMP_SLOT, size + 1, 75203)
            if size + 1 != get(w, ES_PUBLIC_PAYLOAD_BYTES):
                return refuse(w, 2872)
            store(w, ES_BUFFER, 10)
            return copy(o, w, 2, ES_BUFFER, ES_TEMP_SLOT, size, 1, 75207)
        count = minimum(get(w, ES_FIRST_BYTES) - at, 256)
        put(w, ES_PRETTY_CHUNK, count)
        return view(o, w, B_FINAL_OUTPUT, 64 + at, count, 75202)
    if phase == 75202:
        if es_pretty_chunk(w, get(w, ES_PRETTY_CHUNK)) == 0:
            return refuse(w, 2873)
        count = get(w, ES_EMIT_BYTES)
        out = get(w, ES_PRETTY_OUT)
        if count > MAX - out:
            return refuse(w, 2874)
        put(w, ES_PRETTY_OUT, out + count)
        put(w, ES_PRETTY_AT, get(w, ES_PRETTY_AT) + get(w, ES_PRETTY_CHUNK))
        if get(w, ES_PRETTY_PASS) == 1:
            return copy(o, w, 2, ES_BUFFER, ES_TEMP_SLOT, out, count, 75201)
        put(w, C_PHASE, 75201)
        return 0
    if phase == 75203:
        return es_pretty_reset(w, 1)
    if phase == 75207:
        return protect(o, w, ES_TEMP_SLOT, 1, 75208)
    if phase == 75208:
        return hash_start(w, ES_TEMP_SLOT, get(w, ES_PUBLIC_PAYLOAD_BYTES), ES_HASH, 75209)
    if phase == 75209:
        return es_request_publication(w, 2)
    return refuse(w, 2875)

def es_request_publication(w:mutbuf, policy:u64) -> u64:
    if cap(w, ES_PUB_SLOT) != 0 or (get(w, ES_BORROWED) & (1 << ES_PUB_SLOT)) != 0:
        return refuse(w, 2880)
    request = advance(w, ES_REQUEST)
    if request == 0:
        return ABI
    put(w, ES_CONTINUE, 74000)
    return es_start_result(w, 2, 0, 0, 2, policy, ES_PUB_SLOT, B_FINAL_OUTPUT, 64, get(w, ES_FIRST_BYTES))

def es_publication_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 74000:
        return view(o, w, ES_PUB_SLOT, 0, 128, 74001)
    if phase == 74001:
        if get(w, OBS) != ES_PUBLICATION or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 2 or get(w, OBS + 24) != get(w, C_LEASE):
            return refuse(w, 2881)
        if get(w, OBS + 32) != get(w, ES_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, ES_REQUEST) or get(w, OBS + 48) != get(w, ES_PARENT_SEQUENCE) or get(w, OBS + 56) != get(w, ES_POLICY):
            return refuse(w, 2882)
        size = cap(w, ES_PUB_SLOT)
        count = get(w, OBS + 72)
        if get(w, OBS + 64) != 128 or count < 2 or count > size - 128:
            return refuse(w, 2883)
        at = 128 + count
        if get(w, OBS + 80) != at or get(w, OBS + 88) != size - at or get(w, OBS + 96) != size:
            return refuse(w, 2884)
        if get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 2885)
        put(w, ES_DEST_BYTES, count)
        put(w, ES_TX_AT, at)
        put(w, ES_TX_BYTES, size - at)
        expected = es_expected_transaction(w)
        if expected > 256 or size - at != expected:
            return refuse(w, 2886)
        put(w, ES_EXPECTED_BYTES, expected)
        return view(o, w, ES_PUB_SLOT, at, expected, 74002)
    if phase == 74002:
        at = 0
        while at < get(w, ES_EXPECTED_BYTES):
            if byte(w, OBS + at) != byte(w, ES_EXPECT + at):
                return refuse(w, 2887)
            at = at + 1
        return view(o, w, ES_PUB_SLOT, 128, 1, 74003)
    if phase == 74003:
        if byte(w, OBS) != 34:
            return refuse(w, 2888)
        return view(o, w, ES_PUB_SLOT, 127 + get(w, ES_DEST_BYTES), 1, 74004)
    if phase == 74004:
        if byte(w, OBS) != 34:
            return refuse(w, 2889)
        es_public_literals(w)
        fixed = get(w, ES_TEXT1_BYTES) + get(w, ES_TEXT2_BYTES) + get(w, ES_TEXT3_BYTES)
        if get(w, ES_DEST_BYTES) > MAX - fixed or get(w, ES_TX_BYTES) > MAX - fixed - get(w, ES_DEST_BYTES):
            return refuse(w, 2890)
        put(w, ES_PUBLIC_BYTES, fixed + get(w, ES_DEST_BYTES) + get(w, ES_TX_BYTES))
        return grow(o, w, ES_PUBLIC_SLOT, get(w, ES_PUBLIC_BYTES), 74005)
    if phase == 74005:
        return copy(o, w, 2, ES_TEXT, ES_PUBLIC_SLOT, 0, get(w, ES_TEXT1_BYTES), 74006)
    if phase == 74006:
        return copy(o, w, ES_PUB_SLOT, 128, ES_PUBLIC_SLOT, get(w, ES_TEXT1_BYTES), get(w, ES_DEST_BYTES), 74007)
    if phase == 74007:
        return copy(o, w, 2, ES_TEXT + 256, ES_PUBLIC_SLOT, get(w, ES_TEXT1_BYTES) + get(w, ES_DEST_BYTES), get(w, ES_TEXT2_BYTES), 74008)
    if phase == 74008:
        return copy(o, w, ES_PUB_SLOT, get(w, ES_TX_AT), ES_PUBLIC_SLOT, get(w, ES_TEXT1_BYTES) + get(w, ES_DEST_BYTES) + get(w, ES_TEXT2_BYTES), get(w, ES_TX_BYTES), 74009)
    if phase == 74009:
        return copy(o, w, 2, ES_TEXT + 512, ES_PUBLIC_SLOT, get(w, ES_PUBLIC_BYTES) - get(w, ES_TEXT3_BYTES), get(w, ES_TEXT3_BYTES), 74010)
    if phase == 74010:
        return protect(o, w, ES_PUBLIC_SLOT, 1, 74011)
    if phase == 74011:
        if get(w, ES_POLICY) == 2:
            return es_start_result(w, 3, 0, 0, 0, 1, 0, ES_PUBLIC_SLOT, 0, get(w, ES_PUBLIC_BYTES))
        return es_merge_start(w, ES_PUBLIC_SLOT, 0, get(w, ES_PUBLIC_BYTES), ES_TEMP_SLOT, 2)
    return refuse(w, 2891)

def es_hex(w:mutbuf, source:u64, target:u64) -> u64:
    index = 0
    while index < 32:
        value = byte(w, source + index)
        high = value >> 4
        low = value & 15
        highchar = high + 48
        lowchar = low + 48
        if high >= 10:
            highchar = high + 87
        if low >= 10:
            lowchar = low + 87
        store(w, target + index * 2, highchar)
        store(w, target + index * 2 + 1, lowchar)
        index = index + 1
    return 0

def es_quotient_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = remainder * 2 + ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def es_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    digits = 1
    remaining = value
    while remaining >= 10:
        remaining = es_quotient_ten(remaining)
        digits = digits + 1
    index = digits
    while index != 0:
        index = index - 1
        quotient = es_quotient_ten(value)
        store(w, at + index, 48 + value - quotient * 10)
        value = quotient
    return digits
'''

CONSTANTS.update(ES_POST_ACTIVE=32504,
 ES_ARGS_WORD=int.from_bytes(b"args","little"),ES_ATTRS_WORD=int.from_bytes(b"attrs","little"))
BODY=BODY.replace("== 1936159329:", "== ES_ARGS_WORD:").replace("== 495841080417:", "== ES_ATTRS_WORD:")
BODY=BODY.replace("pass:u64", "iteration:u64").replace("ES_PRETTY_PASS, pass)", "ES_PRETTY_PASS, iteration)")

def writes(raw,at,indent="    "):
    result=[]
    for offset in range(0,len(raw),8):
        part=raw[offset:offset+8]
        if len(part)==8:result.append(f"{indent}put(w, {at} + {offset}, {int.from_bytes(part,'little')})")
        else:
            result.extend(f"{indent}store(w, {at} + {offset+i}, {value})" for i,value in enumerate(part))
    return result

def literal_functions():
    old=b',"schema":"hepta.hia.patch-result.v1","status":"verified_unpublished"}'
    published=b',"schema":"hepta.hia.patch-result.v1","status":"verified_new_snapshot_published"}'
    CONSTANTS["ES_OLD_TAIL_BYTES"]=len(old)
    CONSTANTS["ES_PUBLISHED_TAIL_BYTES"]=len(published)
    lines=["def es_receipt_tails(w:mutbuf) -> u64:"]
    lines+=writes(old,"ES_OLD_TAIL")+writes(published,"ES_NEW_TAIL")+["    return 0"]
    lines+=["","def es_insert_literal(w:mutbuf, kind:u64) -> u64:"]
    for kind,text in [(1,b',"program":'),(2,b',"publication":')]:
        lines.append(f"    if kind == {kind}:")
        lines+=writes(text,"ES_INSERT_KEY","        ")+[f"        return {len(text)}"]
    lines+=["    return 0","","def es_bad_fields(w:mutbuf) -> u64:"]
    message=b"E_HIA_QUERY: fields must be a unique nonempty subset of op, args, attrs"
    lines+=writes(message,"ES_TEXT")
    lines.append(f"    return edit_error_start(w, 1, 1, 1, 2, ES_TEXT, {len(message)})")
    lines+=["","def es_graph_keys(w:mutbuf, base:u64) -> u64:"]
    lines+=writes(b"functionblockoutputfields","ES_BUFFER + base")+["    return 0"]
    lines+=["","def es_field_literals(w:mutbuf) -> u64:",
            "    index = 0","    at = 0","    while index < get(w, ES_FIELD_COUNT):",
            "        value = get(w, ES_FIELDS + index * 16)"]
    for i,(kind,text) in enumerate([(1,b"op"),(2,b"args"),(4,b"attrs")]):
        lines.append(f"        {'if' if i==0 else 'elif'} value == {kind}:")
        lines+=writes(text,"ES_TEXT + at","            ")
    lines+=["        at = at + get(w, ES_FIELDS + index * 16 + 8)",
            "        index = index + 1","    return 0",
            "","def es_expected_transaction(w:mutbuf) -> u64:"]
    lines+=writes(b'{"bytes":',"ES_EXPECT")
    lines+=['    count = 9 + es_decimal(w, ES_EXPECT + 9, get(w, ES_PUBLIC_PAYLOAD_BYTES))']
    # len(b'{"bytes":') is 9; preserve every scalar and punctuation byte.
    suffix=b',"sha256":"'
    lines+=writes(suffix,"ES_EXPECT + count")
    lines+=[f"    count = count + {len(suffix)}","    es_hex(w, ES_HASH, ES_EXPECT + count)",
            "    store(w, ES_EXPECT + count + 64, 34)",
            "    store(w, ES_EXPECT + count + 65, 125)","    return count + 66",
            "","def es_public_literals(w:mutbuf) -> u64:",
            "    if get(w, ES_POLICY) == 1:"]
    parts=[b'{"input_sha256":"'+b"A"*64+b'","ok":true,"output":',
      b',"program_sha256":"'+b"B"*64+b'","publication":',
      b',"published_representation":"independently_verified_normalized_core","schema":"hepta.hia.output.v1","status":"verified_program_published"}']
    for i,part in enumerate(parts):
        assert len(part)<256
        lines+=writes(part,f"ES_TEXT + {i*256}","        ")
        lines.append(f"        put(w, ES_TEXT{i+1}_BYTES, {len(part)})")
    lines+=["        es_hex(w, ES_HASH, ES_TEXT + "+str(parts[0].index(b"A"*64))+")",
            "        es_hex(w, ES_HASH, ES_TEXT + 256 + "+str(parts[1].index(b"B"*64))+")",
            "        return 0"]
    parts=[b'{"ok":true,"output":',b',"publication":']
    for i,part in enumerate(parts):
        lines+=writes(part,f"ES_TEXT + {i*256}")
        lines.append(f"    put(w, ES_TEXT{i+1}_BYTES, {len(part)})")
    for batch in [False,True]:
        lines.append("    "+("if" if not batch else "else")+(" get(w, ES_ACTION) == 12:" if not batch else ":"))
        for v in [2,3]:
            lines.append("        "+("if get(w, E_CORE_VERSION) != 8:" if v==2 else "else:"))
            schema=("hepta.hia.edit-batch-query.v" if batch else "hepta.hia.edit-query.v")+str(v)
            part=b',"schema":"hepta.hia.json-view-output.v1","view_schema":"'+schema.encode()+b'"}'
            lines+=writes(part,"ES_TEXT + 512","            ")
            lines.append(f"            put(w, ES_TEXT3_BYTES, {len(part)})")
    lines.append("    return 0")
    return "\n".join(lines)+"\n"

POST_ENTRY=r'''
def es_post_service(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128 or get(w, ES_MAGIC) != ES_STATE or get(w, ES_POST_ACTIVE) != 1:
        return refuse(w, 2892)
    if get(w, C_MAGIC) != EDIT_STATE or acknowledge(s, w, SERVICE) == 0:
        return refuse(w, 2893)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase == 73000:
            put(w, ES_POST_ACTIVE, 0)
            return switch(o, w, MAIN, 73000)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 74000 and phase < 75000:
            result = es_publication_step(o, w)
        elif phase >= 75000 and phase < 76000:
            result = es_output_step(o, w)
        else:
            return refuse(w, 2894)
        if result != 0:
            return result
    return refuse(w, 2895)
'''

def expanded_sources(original,base_constants):
    old_tree=ast.parse(original)
    old={f.name:f for f in old_tree.body}
    assert len(old)==len(old_tree.body)
    changed={"edit_main","edit_begin","edit_public_terminal","edit_main_step","json_front_step"}
    main=deepcopy(old["edit_main_step"])
    hits=[x for x in main.body if isinstance(x,ast.If) and ast.unparse(x.test)=="phase == 46"]
    assert len(hits)==1
    hits[0].body=ast.parse("put(w, C_PHASE, 70000)\nreturn 0").body
    front=deepcopy(old["json_front_step"])
    branches={ast.unparse(x.test):x for x in front.body if isinstance(x,ast.If)}
    branch=branches["phase == 601"]
    returns=[x for x in ast.walk(branch) if isinstance(x,ast.Return) and isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Name) and x.value.func.id=="release"]
    assert len(returns)==1
    returns[0].value=ast.parse("es_drop(o, w, 4, 602)",mode="eval").body
    prefix=ast.parse(
      "if get(w, E_MODE) >= 3:\n"
      "    return switch(o, w, QUERY, 1000)\n"
      "if get(w, ES_ACTION) == 13 and get(w, ES_RESPONSE_READY) == 0:\n"
      "    return es_need_file(w, 14, 16384, 5, 70502)\n").body
    branch=branches["phase == 606"]
    assert isinstance(branch.body[0],ast.Assign) and isinstance(branch.body[1],ast.If)
    branch.body[2:2]=prefix
    branches["phase == 609"].body=ast.parse("return es_drop(o, w, 5, 610)").body
    extra=ast.parse(BODY+"\n"+literal_functions()+"\n"+POST_ENTRY)
    new={x.name:x for x in extra.body}
    assert len(new)==len(extra.body) and not (set(new)&(set(old)-changed))
    root=new["edit_service"]
    loop=next(x for x in root.body if isinstance(x,ast.While))
    chain=loop.body[1]
    while True:
        if "phase >= 74000" in ast.unparse(chain.test):
            # Both publication and output work execute in the extended existing
            # service role. Root alone materializes and yields HIACBE frames.
            chain.test=ast.parse("phase >= 74000 and phase < 76000",mode="eval").body
            chain.body=ast.parse("put(w, ES_POST_ACTIVE, 1)\nreturn switch(o, w, SERVICE, phase)").body
            assert len(chain.orelse)==1 and isinstance(chain.orelse[0],ast.If)
            old_output=chain.orelse[0]
            assert "phase >= 75000" in ast.unparse(old_output.test)
            chain.orelse=old_output.orelse
            break
        assert len(chain.orelse)==1 and isinstance(chain.orelse[0],ast.If)
        chain=chain.orelse[0]
    functions={name:deepcopy(fn) for name,fn in old.items() if name not in changed}
    functions.update(new)
    functions["edit_main_step"]=main
    functions["json_front_step"]=front
    constants=dict(base_constants)
    constants.update(CONSTANTS)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    def reachable(entry):
        live={entry};pending=[entry]
        while pending:
            name=pending.pop()
            for x in ast.walk(functions[name]):
                if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id in functions and x.func.id not in live:
                    live.add(x.func.id);pending.append(x.func.id)
        selected=[deepcopy(functions[entry])]+[deepcopy(f) for name,f in functions.items() if name in live and name!=entry]
        tree=ast.Module(body=selected,type_ignores=[])
        tree=ast.fix_missing_locations(Expand().visit(tree))
        for fn in tree.body:
            if fn.name!=entry:
                assert fn.returns.id in ("u32","u64")
                fn.returns.id="u64"
        assert not any(isinstance(x,(ast.Break,ast.Continue,ast.Div,ast.For,ast.Try,ast.With)) for x in ast.walk(tree))
        return ast.unparse(tree)+"\n"
    return reachable("edit_service"),reachable("es_post_service"),dict(
      explicitly_changed_original_functions=sorted(changed),
      original_runtime_policy="Program admission, Core decoder/index, query and application kernels retained",
      new_root_role=56,extended_service_role=58,new_query_apply_terminal_roles=[57,59])

def merge_service_document(old_document,post_document,CopyBuilder,compact_authoring_cfg):
    original=deepcopy(old_document)
    extra=deepcopy(post_document)
    def rename(doc,prefix):
        names={f["name"]:prefix+str(i) for i,f in enumerate(doc["functions"])}
        for f in doc["functions"]:
            f["name"]=names[f["name"]]
            for b in f["blocks"]:
                for op in b["ops"]:
                    if op["op"]=="call":
                        op["attrs"]["function"]=names[op["attrs"]["function"]]
        return names
    old_names=rename(original,"o")
    post_names=rename(extra,"n")
    node=ast.parse(
      "def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n"
      "    if length(w) != 1048576:\n"
      "        return 4294967293\n"
      "    if byte(w, 32504) == 1:\n"
      "        return post(s, o, w)\n"
      "    return legacy(s, o, w)\n").body[0]
    oldentry=old_document["functions"][0]
    postentry=post_document["functions"][0]
    assert oldentry["returns"]==postentry["returns"]==["u32"]
    expected=["readbuf","mutbuf","mutbuf"]
    assert [p["type"] for p in oldentry["params"]]==expected
    assert [p["type"] for p in postentry["params"]]==expected
    names={"dispatch":"f0","post":post_names[postentry["name"]],"legacy":old_names[oldentry["name"]]}
    sigs={name:(expected,"u32") for name in names}
    builder=CopyBuilder(node,names,sigs,set());builder.statements(node.body)
    first=dict(name="f0",params=[builder.param(p) for p in builder.params],
      returns=[builder.returns],effects=["read","write","trap"],entry="b0",blocks=builder.blocks)
    result=deepcopy(original)
    result["module"]="cli_edit_service58_extended_r1"
    result["functions"]=[first]+original["functions"]+extra["functions"]
    # Compaction verifies every call against the complete function interfaces.
    # Supply the complete graph to a private copy, then select only the compact
    # wrapper. All original callee blocks remain untouched in result and are
    # independently compared through the inverse function-name bijection below.
    compact=compact_authoring_cfg(deepcopy(result))
    assert compact["functions"][0]["name"]=="f0"
    assert [f["name"] for f in compact["functions"]]==[f["name"] for f in result["functions"]]
    result["functions"][0]=compact["functions"][0]
    reverse={v:k for k,v in old_names.items()}
    restored=deepcopy(result["functions"][1:1+len(original["functions"])])
    for f in restored:
        f["name"]=reverse[f["name"]]
        for b in f["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=reverse[op["attrs"]["function"]]
    assert restored==old_document["functions"]
    return result
