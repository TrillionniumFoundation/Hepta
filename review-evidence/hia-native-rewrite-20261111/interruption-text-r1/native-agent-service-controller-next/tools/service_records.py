"""Complete service success and _error records, including deferred snapshot publication."""
CONSTANTS = dict(
    COMMAND=int.from_bytes(b'HIASRC01', 'little'), REPLY=int.from_bytes(b'HIASRR01', 'little'),
    STATE=int.from_bytes(b'HIASRW01', 'little'), EVENT=int.from_bytes(b'HIASRE01', 'little'),
    GRAPH=int.from_bytes(b'HIAGRF01', 'little'), BAD=0xfffffffd, MAX=(1 << 64) - 1,
)
LITERALS = ('contract_version', 'hepta.hia.agent-native.v1', 'request_id', 'status', 'completed',
            'result', 'rejected', 'error', 'code', 'phase', 'admission', 'message', 'retry_action',
            'correct_input', 'details_artifact', 'pending_slot_snapshot', 'type', 'E_HIA_REJECTED')
BODY = r'''
def service_record(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) == 2 or get(w, 8) == 3:
        return BAD
    if get(w, 8) == 0:
        if length(r) != 96 or word(r, 0) != COMMAND or word(r, 8) == 0 or word(r, 16) == 0 or word(r, 24) > 1:
            return refuse(w, 1)
        if graph_shape(s, 0, length(s)) == 0:
            return refuse(w, 2)
        i = 48
        while i < 96:
            if word(r, i) != 0:
                return refuse(w, 3)
            i = i + 8
        if word(r, 32) == 0 or word(r, 32) > word(s, 16) or word(r, 40) == 0 or word(r, 40) > word(s, 16):
            return refuse(w, 4)
        i = 0
        while i < 1024:
            if byte(w, i) != 0:
                return refuse(w, 5)
            i = i + 1
        put(w, 0, STATE)
        put(w, 8, 1)
        put(w, 16, word(r, 8))
        put(w, 24, word(r, 16))
        put(w, 40, length(s))
        put(w, 200, word(r, 32))
        put(w, 208, word(r, 40))
        put(w, 216, word(r, 24))
        put(w, 704, word(s, 16))
        put(w, 712, word(s, 32))
        put(w, 720, word(s, 40))
        put(w, 72, word(s, 16))
        put(w, 88, word(s, 32))
        put(w, 104, word(s, 40))
        copy_bytes(w, r, 384, 0, 96)
        copy_bytes(w, s, 512, 0, 64)
        put(w, 240, 1)
        if get(w, 216) == 1:
            error = get(w, 208)
            if gkind(s, error) != 6 or gkind(s, field(s, error, L_message)) != 4 or gkind(s, field(s, error, L_type)) != 4:
                return refuse(w, 6)
            pending = field(s, error, L_pending_slot_snapshot)
            if pending != 0 and gkind(s, pending) != 0:
                put(w, 232, pending)
                put(w, 240, 2)
                return event(w, 2)
    else:
        if get(w, 0) != STATE or get(w, 8) != 1 or length(s) != get(w, 40):
            return refuse(w, 7)
        i = 0
        while i < 64:
            if byte(s, i) != byte(w, 512 + i):
                return refuse(w, 8)
            i = i + 1
        if get(w, 240) == 1:
            if length(r) != 96:
                return refuse(w, 9)
            i = 0
            while i < 96:
                if byte(r, i) != byte(w, 384 + i):
                    return refuse(w, 10)
                i = i + 1
        elif get(w, 240) == 2:
            if length(r) < 192 or word(r, 0) != REPLY or word(r, 8) != get(w, 16) or word(r, 16) != get(w, 24):
                return refuse(w, 11)
            if word(r, 24) != get(w, 32) or word(r, 32) > 1 or word(r, 40) != length(r) - 64 or word(r, 48) != 0 or word(r, 56) != 0:
                return refuse(w, 12)
            if graph_shape(r, 64, length(r) - 64) == 0:
                return refuse(w, 13)
            copy_bytes(w, r, 576, 0, 128)
            put(w, 728, word(r, 32))
            put(w, 736, length(r))
            put(w, 248, get(w, 704) + word(r, 88))
            if word(r, 80) > MAX - get(w, 704) or word(r, 96) > MAX - get(w, 712) or word(r, 104) > MAX - get(w, 720):
                return refuse(w, 14)
            put(w, 72, get(w, 704) + word(r, 80))
            put(w, 88, get(w, 712) + word(r, 96))
            put(w, 104, get(w, 720) + word(r, 104))
            put(w, 240, 3)
        elif get(w, 240) == 3:
            if length(r) != get(w, 736):
                return refuse(w, 15)
            i = 0
            while i < 128:
                if byte(r, i) != byte(w, 576 + i):
                    return refuse(w, 16)
                i = i + 1
        else:
            return refuse(w, 17)
    put(w, 160, 0)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    project(s, w)
    if get(w, 192) != 0 or sizes(w) == 0:
        return refuse(w, 18)
    if get(w, 152) > length(w):
        return event(w, 1)
    fill_range(w, 1024, get(w, 144), 0)
    if clone_graph(s, w, 0, 0, 0, 0) == 0:
        return refuse(w, 19)
    if get(w, 240) == 3:
        if clone_graph(r, w, 64, get(w, 704), get(w, 712), get(w, 720)) == 0:
            return refuse(w, 20)
    put(w, 160, 1)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    project(s, w)
    if get(w, 192) != 0 or get(w, 168) != get(w, 56) or get(w, 176) != get(w, 64) or get(w, 184) != get(w, 80):
        return refuse(w, 21)
    put(w, 1024, GRAPH)
    put(w, 1032, get(w, 16))
    put(w, 1040, get(w, 120))
    put(w, 1048, get(w, 224))
    put(w, 1056, get(w, 128))
    put(w, 1064, get(w, 136))
    put(w, 1072, get(w, 144))
    put(w, 8, 2)
    return event(w, choose(get(w, 728) == 0, 0, 3))

def truncated(s:readbuf, w:mutbuf, source:u64, limit:u64) -> u64:
    if prefix_limit(s, w, source, limit) == 0:
        return 0
    size = get(w, 768)
    result = new_node(w, 4, 0, size, get(w, 776))
    if get(w, 160) != 0:
        copy_bytes(w, s, 1024 + get(w, 1024 + result * 64 + 8), word(s, source * 64 + 8), size)
    return result

def error_record(s:readbuf, w:mutbuf) -> u64:
    observed = get(w, 208)
    code = field(s, observed, L_code)
    if code == 0 or gkind(s, code) != 4:
        code = literal(w, L_E_HIA_REJECTED)
    else:
        code = truncated(s, w, code, 128)
    details = field(s, observed, L_details_artifact)
    if get(w, 240) == 3:
        details = get(w, 248)
    elif details == 0:
        details = new_node(w, 0, 0, 0, 0)
    phase = field(s, observed, L_phase)
    if phase == 0:
        phase = literal(w, L_admission)
    message = truncated(s, w, field(s, observed, L_message), 4096)
    if get(w, 768) == 0:
        message = field(s, observed, L_type)
    retry = field(s, observed, L_retry_action)
    if retry == 0:
        retry = literal(w, L_correct_input)
    error = new_node(w, 6, 5, 0, 0)
    pair(w, error, 0, literal(w, L_code), code)
    pair(w, error, 1, literal(w, L_phase), phase)
    pair(w, error, 2, literal(w, L_message), message)
    pair(w, error, 3, literal(w, L_retry_action), retry)
    pair(w, error, 4, literal(w, L_details_artifact), details)
    return error

def project(s:readbuf, w:mutbuf) -> u64:
    if get(w, 728) != 0:
        put(w, 224, get(w, 248))
        return 0
    result = get(w, 208)
    if get(w, 216) == 1:
        result = error_record(s, w)
    response = new_node(w, 6, 4, 0, 0)
    pair(w, response, 0, literal(w, L_contract_version), literal(w, L_hepta_hia_agent_native_v1))
    pair(w, response, 1, literal(w, L_request_id), get(w, 200))
    if get(w, 216) == 0:
        pair(w, response, 2, literal(w, L_status), literal(w, L_completed))
        pair(w, response, 3, literal(w, L_result), result)
    else:
        pair(w, response, 2, literal(w, L_status), literal(w, L_rejected))
        pair(w, response, 3, literal(w, L_error), result)
    put(w, 224, response)
    return 0

def event(w:mutbuf, action:u64) -> u32:
    if get(w, 32) == MAX:
        put(w, 8, 3)
        return BAD
    put(w, 32, get(w, 32) + 1)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 16))
    put(w, 280, get(w, 24))
    put(w, 288, get(w, 32))
    put(w, 296, choose(action == 1, get(w, 152), 0))
    put(w, 304, choose(action == 0 or action == 3, 1024, 0))
    put(w, 312, choose(action == 0 or action == 3, get(w, 144), 0))
    put(w, 320, get(w, 192))
    put(w, 328, get(w, 216))
    put(w, 336, choose(action == 0 or action == 3, get(w, 224), 0))
    put(w, 344, choose(action == 2, get(w, 232), 0))
    put(w, 352, get(w, 520))
    put(w, 360, choose(get(w, 240) == 3, get(w, 648), 0))
    put(w, 368, 0)
    put(w, 376, 0)
    return 384

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 3)
    put(w, 192, reason)
    event(w, 4)
    return BAD
'''
