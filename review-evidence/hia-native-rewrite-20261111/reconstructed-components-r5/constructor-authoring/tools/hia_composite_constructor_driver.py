"""New reconstructed complete constructor continuation controller.

This is newly authored after the environment replacement. It is not a copy of
the unavailable Stage12 constructor source or evidence. It uses the same exact
native semantic owner and preserves its partial-state metadata as sourceRef IR.
The constructor arena is released before a function arena can be acquired.
"""
from __future__ import annotations
import ast

from tools.hia_composite_lowering_driver_services import BODY as SERVICE_SOURCE

CONSTANTS = {
    'DRIVER_CTOR': 43,
    'CTOR_INIT': int.from_bytes(b'HIACDI01', 'little'),
    'CTOR_STATE': int.from_bytes(b'HIACDS01', 'little'),
    'CTOR_FRAME': int.from_bytes(b'HIACTR01', 'little'),
    'CTOR_STREAM': int.from_bytes(b'HIACTK01', 'little'),
}

BODY = r'''
def constructor_driver(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 500)
    if get(w, L_MAGIC) == 0 and get(w, C_MAGIC) == 0:
        if ctor_begin(s, w) == 0:
            return refuse(w, 501)
    elif get(w, C_MAGIC) != CTOR_STATE or get(w, C_STATUS) != 1 or acknowledge(s, w, DRIVER_CTOR) == 0:
        return refuse(w, 502)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 20000 and phase < 21000:
            result = ir_step(o, w)
        elif phase >= 22000 and phase < 23000:
            result = type_service_step(o, w)
        elif phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        else:
            result = ctor_step(o, w)
        if result != 0:
            return result
    return refuse(w, 503)

def ctor_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != CTOR_INIT or word(s, 8) == 0 or word(s, 16) > 1:
        return 0
    extent = word(s, 24)
    if extent < 82 or extent > SOURCE_LEASE_LIMIT or extent != cap(w, B_SOURCE):
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != length(w) or length(w) != MIN_WORK:
        return 0
    if word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0 or word(s, 56) != 0:
        return 0
    i = 3
    while i < 64:
        if cap(w, i) != 0:
            return 0
        i = i + 1
    zero(w, 0, 4096)
    zero(w, 8192, MIN_WORK - 8192)
    put(w, C_MAGIC, CTOR_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, word(s, 8))
    put(w, C_LEGACY, word(s, 16))
    put(w, C_SOURCE_EXTENT, extent)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, DRIVER_CTOR)
    put(w, C_PHASE, 100)
    return 1

def ctor_source_header(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 0 or get(w, OBS) != SOURCE_MAGIC:
        return 0
    size = get(w, OBS + 8)
    if size < 16 or size > PACKET_LIMIT or get(w, OBS + 24) != 64:
        return 0
    index = (64 + size + 7) & (MAX - 7)
    if get(w, OBS + 16) != (size + 7) >> 3 or get(w, OBS + 32) != index:
        return 0
    if get(w, OBS + 40) != get(w, C_SOURCE_EXTENT) or get(w, C_SOURCE_EXTENT) != index + ((size + 7) >> 3):
        return 0
    if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
        return 0
    return 1

def ctor_frame(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 64 or get(w, OBS) != CTOR_FRAME or get(w, L_CTOR_COMPLETED) != 0:
        return 0
    action = get(w, OBS + 8)
    error = get(w, OBS + 16)
    phase = get(w, OBS + 24)
    stage = get(w, OBS + 32)
    profile = get(w, OBS + 40)
    request = get(w, OBS + 48)
    pending = get(w, OBS + 56)
    if action != 0 and action != 2:
        return 0
    if error > 14 and error != 999:
        return 0
    if stage < get(w, C_CTOR_STAGE) or stage > 3 or profile > 4 or pending > 5:
        return 0
    if stage == 0 and profile != 0:
        return 0
    if stage != 0 and profile == 0:
        return 0
    if get(w, L_CTOR_PROFILE_SET) != 0 and profile != get(w, C_PROFILE):
        return 0
    if phase == 2000:
        if action != 2 or pending != 0 or request != get(w, C_CTOR_REQUEST):
            return 0
        if get(w, L_CTOR_WAITING) != 0 and error != 999:
            return 0
        if error == 999 and (get(w, L_DELEGATE_GROUP) != 2 or get(w, L_DELEGATE_ERROR) == 0 or get(w, L_DELEGATE_REQUEST) != request):
            return 0
        put(w, L_CTOR_COMPLETED, 1)
        put(w, L_CTOR_WAITING, 0)
    else:
        expected = 0
        if phase == 10:
            expected = 1
        elif phase == 30:
            expected = 2
        elif phase == 41 or phase == 81:
            expected = 3
        elif phase == 50:
            expected = 4
        elif phase == 82:
            expected = 5
        if expected == 0 or error != 0:
            return 0
        committed = 3
        if phase == 10:
            committed = choose(action == 2, 1, 2)
        if stage != committed:
            return 0
        if action == 2:
            if get(w, L_CTOR_WAITING) != 0 or pending != expected or get(w, C_CTOR_REQUEST) == MAX:
                return 0
            if request != get(w, C_CTOR_REQUEST) + 1:
                return 0
            put(w, L_CTOR_ISSUED_PHASE, phase)
            put(w, L_CTOR_WAITING, 1)
        else:
            if get(w, L_CTOR_WAITING) != 1 or pending != 0 or request != get(w, C_CTOR_REQUEST) or phase != get(w, L_CTOR_ISSUED_PHASE):
                return 0
            put(w, L_CTOR_WAITING, 0)
    put(w, C_CTOR_STAGE, stage)
    put(w, C_PROFILE, profile)
    put(w, C_CTOR_REQUEST, request)
    put(w, L_CTOR_PROFILE_SET, 1)
    put(w, L_CTOR_ACTION, action)
    put(w, L_CTOR_PHASE, phase)
    put(w, L_CTOR_PENDING, pending)
    put(w, L_CTOR_ERROR, error)
    return 1

def ctor_projection_event(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 128 or get(w, OBS) != OWNER_EVENT:
        return 0
    if get(w, OBS + 16) != get(w, L_CTOR_PROJECT_TARGET) or get(w, OBS + 24) != get(w, C_LEASE):
        return 0
    if get(w, OBS + 32) != get(w, L_CTOR_PROJECT_STREAM) or get(w, OBS + 40) != get(w, L_CTOR_PROJECT_REQUEST):
        return 0
    if get(w, OBS + 48) != get(w, C_LEGACY):
        return 0
    expected = get(w, C_PROFILE)
    if get(w, L_CTOR_PROJECT_TARGET) == 0:
        expected = 0
    if get(w, OBS + 56) != expected or get(w, OBS + 88) != 0 or get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
        return 0
    if get(w, OBS + 8) == 1:
        if get(w, OBS + 80) <= cap(w, B_PROJECTOR):
            return 0
        return 1
    if get(w, OBS + 8) != 0 or get(w, OBS + 72) < 16 or get(w, OBS + 72) > PACKET_LIMIT:
        return 0
    if get(w, OBS + 80) != get(w, OBS + 64) + get(w, OBS + 72):
        return 0
    return inside(w, B_PROJECTOR, get(w, OBS + 64), get(w, OBS + 72))

def ctor_project_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 800:
        return release(o, w, B_PROJECTOR, 801)
    if phase == 801:
        return grow(o, w, B_PROJECTOR, 512, 802)
    if phase == 802:
        target = get(w, L_CTOR_PROJECT_TARGET)
        profile = get(w, C_PROFILE)
        if target == 0:
            profile = 0
        wire8(w, OWNER_CONFIG, target, get(w, C_LEASE), get(w, L_CTOR_PROJECT_STREAM), get(w, L_CTOR_PROJECT_REQUEST), get(w, C_LEGACY), profile, 0)
        zero(w, WIRE + 64, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_PROJECTOR, 128, 128, 803)
    if phase == 803:
        if get(w, L_CTOR_PROJECT_TARGET) == 0:
            return invoke(o, w, I_OWNER_PACKET, B_EMPTY, 0, 0, B_SOURCE, get(w, C_SOURCE_EXTENT), B_PROJECTOR, cap(w, B_PROJECTOR), B_PROJECTOR, 0, 128, 804)
        return invoke(o, w, I_OWNER_PACKET, B_IR, 0, get(w, C_IR_EXTENT), B_CTOR_SOURCE, get(w, C_CTOR_SOURCE_BYTES), B_PROJECTOR, cap(w, B_PROJECTOR), B_PROJECTOR, 0, 128, 804)
    if phase == 804:
        if ctor_projection_event(w) == 0:
            return refuse(w, 504)
        if get(w, OBS + 8) == 1:
            return grow(o, w, B_PROJECTOR, get(w, OBS + 80), 803)
        put(w, C_PACKET_OFFSET, get(w, OBS + 64))
        put(w, C_PACKET_BYTES, get(w, OBS + 72))
        return grow(o, w, get(w, L_CTOR_PROJECT_DEST), get(w, C_PACKET_BYTES), 805)
    if phase == 805:
        return copy(o, w, B_PROJECTOR, get(w, C_PACKET_OFFSET), get(w, L_CTOR_PROJECT_DEST), 0, get(w, C_PACKET_BYTES), 806)
    if phase == 806:
        return protect(o, w, get(w, L_CTOR_PROJECT_DEST), 1, 807)
    if phase == 807:
        put(w, C_PACKET_SLOT, get(w, L_CTOR_PROJECT_DEST))
        put(w, C_PACKET_OFFSET, 0)
        put(w, C_PHASE, get(w, L_CTOR_PROJECT_RETURN))
        return 0
    return refuse(w, 505)

def ctor_metadata_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 690:
        return view(o, w, B_IR, get(w, C_IR_ROOT), 80, 691)
    if phase == 691:
        if get(w, OBS) != 5 or get(w, OBS + 16) != 6 or get(w, OBS + 40) != 0 or get(w, OBS + 72) != 1:
            return refuse(w, 506)
        put(w, L_CTOR_NODE, get(w, OBS + 24))
        put(w, L_CTOR_NODE_INDEX, 0)
        put(w, C_PHASE, 692)
        return 0
    if phase == 692:
        node = get(w, L_CTOR_NODE)
        if node < 131328 or (node & 7) != 0 or node > get(w, C_IR_EXTENT) - 80:
            return refuse(w, 507)
        return view(o, w, B_IR, node, 80, 693)
    if phase == 693:
        index = get(w, L_CTOR_NODE_INDEX)
        kind = get(w, OBS)
        value = get(w, OBS + 8)
        if get(w, OBS + 40) != get(w, C_IR_ROOT) or get(w, OBS + 72) != 1:
            return refuse(w, 508)
        if index == 0:
            if kind != 2 or value != get(w, C_CTOR_STAGE):
                return refuse(w, 509)
        elif index == 1:
            if kind != 2 or value != get(w, C_PROFILE):
                return refuse(w, 510)
        elif index == 2:
            if kind != 3 or value != get(w, C_LEGACY):
                return refuse(w, 511)
        elif index == 3:
            if get(w, C_CTOR_STAGE) == 0:
                if kind != 4 or value != 0:
                    return refuse(w, 512)
            elif kind != 0 or value != 24:
                return refuse(w, 513)
        else:
            if get(w, C_CTOR_STAGE) < 3:
                if kind != 4 or value != 0:
                    return refuse(w, 514)
            elif kind != 5 or get(w, OBS + 16) > 1024:
                return refuse(w, 515)
        node = get(w, OBS + 48)
        if index == 5:
            if node != 0:
                return refuse(w, 516)
            return release(o, w, B_CTOR_WORK, 699)
        put(w, L_CTOR_NODE_INDEX, index + 1)
        put(w, L_CTOR_NODE, node)
        put(w, C_PHASE, 692)
        return 0
    if phase == 699:
        if get(w, C_ERROR_GROUP) != 0:
            return ctor_handoff(o, w)
        if get(w, C_CTOR_STAGE) != 3 or get(w, C_TYPES_LIVE) != 1:
            return refuse(w, 517)
        put(w, L_CTOR_PROJECT_TARGET, 1)
        put(w, L_CTOR_PROJECT_DEST, B_FUNCTION_PACKET)
        put(w, L_CTOR_PROJECT_STREAM, get(w, C_IR_STREAM))
        put(w, L_CTOR_PROJECT_REQUEST, get(w, C_CTOR_REQUEST))
        put(w, L_CTOR_PROJECT_RETURN, 710)
        put(w, C_PHASE, 800)
        return 0
    return refuse(w, 518)

def ctor_handoff(o:mutbuf, w:mutbuf) -> u32:
    if get(w, C_PENDING) != 0 or cap(w, B_CTOR_WORK) != 0 or get(w, L_CTOR_COMPLETED) != 1:
        return refuse(w, 519)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, CTOR_HANDOFF)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, get(w, C_ERROR_GROUP))
    put(o, 40, get(w, C_FINAL_ERROR))
    put(o, 48, get(w, C_CTOR_STAGE))
    put(o, 56, get(w, C_PROFILE))
    put(o, 64, get(w, C_CTOR_REQUEST))
    put(o, 72, B_IR)
    put(o, 80, get(w, C_IR_ROOT))
    put(o, 88, get(w, C_IR_EXTENT))
    put(o, 96, get(w, C_TYPES_LIVE))
    put(o, 104, get(w, C_FN_PACKET_BYTES))
    put(o, 112, get(w, C_OUT_PACKET_BYTES))
    put(o, 120, 0)
    put(w, C_STATUS, 2)
    put(w, L_MAGIC, 0)
    put(w, L_STATUS, 0)
    return 128

def ctor_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase >= 690 and phase < 700:
        return ctor_metadata_step(o, w)
    if phase >= 800 and phase < 810:
        return ctor_project_step(o, w)
    if phase == 100:
        return view(o, w, B_SOURCE, 0, 64, 101)
    if phase == 101:
        if ctor_source_header(w) == 0:
            return refuse(w, 520)
        put(w, L_CTOR_PROJECT_TARGET, 0)
        put(w, L_CTOR_PROJECT_DEST, B_CTOR_PACKET)
        put(w, L_CTOR_PROJECT_STREAM, 0)
        put(w, L_CTOR_PROJECT_REQUEST, 0)
        put(w, L_CTOR_PROJECT_RETURN, 110)
        put(w, C_PHASE, 800)
        return 0
    if phase == 110:
        put(w, C_CTOR_PACKET_BYTES, get(w, C_PACKET_BYTES))
        put(w, L_INDEX_TARGET, B_CTOR_SOURCE)
        put(w, L_INDEX_RETURN, 111)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 111:
        put(w, C_CTOR_SOURCE_BYTES, get(w, L_INDEX_SOURCE_BYTES))
        return grow(o, w, B_CTOR_WORK, FUNCTION_BYTES, 112)
    if phase == 112:
        return grow(o, w, B_CTOR_OUTPUT, OWNER_OUTPUT_BYTES, 113)
    if phase == 113:
        return invoke(o, w, I_CTOR_OWNER, B_CTOR_PACKET, 0, get(w, C_CTOR_PACKET_BYTES), B_CTOR_OUTPUT, OWNER_OUTPUT_BYTES, B_CTOR_WORK, FUNCTION_BYTES, B_CTOR_OUTPUT, 0, 64, 201)
    if phase == 201:
        if ctor_frame(w) == 0:
            return refuse(w, 521)
        if get(w, L_CTOR_ACTION) == 0:
            if get(w, C_TYPES_LIVE) != 1:
                return refuse(w, 522)
            return invoke(o, w, I_CTOR_OWNER, B_TYPES, 0, TYPES_BYTES, B_CTOR_OUTPUT, OWNER_OUTPUT_BYTES, B_CTOR_WORK, FUNCTION_BYTES, B_CTOR_OUTPUT, 0, 64, 201)
        kind = get(w, L_CTOR_PENDING)
        put(w, L_IR_RETURN, 220)
        if get(w, L_CTOR_PHASE) == 2000:
            kind = 0
            put(w, L_IR_RETURN, 690)
            error = get(w, L_CTOR_ERROR)
            if error == 999:
                put(w, C_ERROR_GROUP, 2)
                put(w, C_FINAL_ERROR, get(w, L_DELEGATE_ERROR))
            elif error != 0:
                put(w, C_ERROR_GROUP, 1)
                put(w, C_FINAL_ERROR, error)
        producer(w, I_CTOR_RENDER, B_CTOR_WORK, B_CTOR_OUTPUT, CTOR_STREAM, kind, get(w, C_CTOR_REQUEST), 0, 0, B_CTOR_SOURCE, get(w, C_CTOR_SOURCE_BYTES))
        put(w, C_PHASE, 20000)
        return 0
    if phase == 220:
        put(w, L_SERVICE_KIND, get(w, L_CTOR_PENDING))
        put(w, L_SERVICE_RETURN, 230)
        put(w, C_PHASE, 22000)
        return 0
    if phase == 230:
        if get(w, C_TYPE_OP) == 1:
            if get(w, C_TYPE_ERROR) != 0:
                return release(o, w, B_TYPES, 231)
            put(w, C_TYPES_LIVE, 1)
        put(w, C_PHASE, 234)
        return 0
    if phase == 231:
        return release(o, w, B_TYPE_OUTPUT, 232)
    if phase == 232:
        return release(o, w, B_TRANSPORT, 233)
    if phase == 233:
        put(w, C_TYPES_LIVE, 0)
        put(w, C_PHASE, 234)
        return 0
    if phase == 234:
        return release(o, w, B_TYPE_WIRE, 235)
    if phase == 235:
        return invoke(o, w, I_CTOR_OWNER, get(w, C_PACKET_SLOT), get(w, C_PACKET_OFFSET), get(w, C_PACKET_BYTES), B_CTOR_OUTPUT, OWNER_OUTPUT_BYTES, B_CTOR_WORK, FUNCTION_BYTES, B_CTOR_OUTPUT, 0, 64, 201)
    if phase == 710:
        put(w, C_FN_PACKET_BYTES, get(w, C_PACKET_BYTES))
        put(w, L_INDEX_TARGET, B_FUNCTION_SOURCE)
        put(w, L_INDEX_RETURN, 711)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 711:
        put(w, C_FN_SOURCE_BYTES, get(w, L_INDEX_SOURCE_BYTES))
        put(w, L_CTOR_PROJECT_TARGET, 2)
        put(w, L_CTOR_PROJECT_DEST, B_OUTER_PACKET)
        put(w, L_CTOR_PROJECT_RETURN, 712)
        put(w, C_PHASE, 800)
        return 0
    if phase == 712:
        put(w, C_OUT_PACKET_BYTES, get(w, C_PACKET_BYTES))
        put(w, L_INDEX_TARGET, B_OUTER_SOURCE)
        put(w, L_INDEX_RETURN, 713)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 713:
        put(w, C_OUT_SOURCE_BYTES, get(w, L_INDEX_SOURCE_BYTES))
        return ctor_handoff(o, w)
    return refuse(w, 523)
'''


def shared_service_functions() -> str:
    """Specialize only the declared constructor service ABI, at authoring time."""
    names = {'producer_frame', 'ir_event', 'ir_step', 'json_workspace', 'index_step',
             'type_event', 'type_service_step'}
    nodes = [node for node in ast.parse(SERVICE_SOURCE).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    result = '\n\n'.join(ast.unparse(node) for node in nodes)
    result = result.replace('return switch(o, w, DRIVER_MAIN, get(w, L_IR_RETURN))',
                            'put(w, C_PHASE, get(w, L_IR_RETURN))\n        return 0')
    result = result.replace('return switch(o, w, DRIVER_MAIN, get(w, L_SERVICE_RETURN))',
                            'put(w, C_PHASE, get(w, L_SERVICE_RETURN))\n        return 0')
    result = result.replace('L_FN_REQUEST', 'C_CTOR_REQUEST')
    result = result.replace('B_FUNCTION_SOURCE', 'B_CTOR_SOURCE')
    result = result.replace('C_FN_SOURCE_BYTES', 'C_CTOR_SOURCE_BYTES')
    old = '''        if get(w, C_TYPES_LIVE) != 1 or get(w, L_SERVICE_KIND) < 2 or get(w, L_SERVICE_KIND) > 5:
            return refuse(w, 223)'''
    new = '''        if get(w, L_SERVICE_KIND) < 1 or get(w, L_SERVICE_KIND) > 5:
            return refuse(w, 223)
        if get(w, L_SERVICE_KIND) == 1:
            if get(w, C_TYPES_LIVE) != 0:
                return refuse(w, 524)
        elif get(w, C_TYPES_LIVE) != 1:
            return refuse(w, 525)'''
    assert old in result
    result = result.replace(old, new)
    result = result.replace('get(w, L_PRODUCER_MAGIC) != FN_STREAM', 'get(w, L_PRODUCER_MAGIC) != CTOR_STREAM')
    old = '''        put(w, L_SERVICE_TARGET, 3)
        if get(w, L_FN_KERNEL) == I_FUNCTION_ADMIT:
            if get(w, L_SERVICE_KIND) != 2:
                return refuse(w, 225)
            put(w, L_SERVICE_TARGET, 2)
        return release(o, w, B_REQUEST, 22001)'''
    new = '''        put(w, L_SERVICE_TARGET, 1)
        if get(w, L_SERVICE_KIND) == 1:
            return grow(o, w, B_TRANSPORT, 4096, 22050)
        return release(o, w, B_REQUEST, 22001)
    if phase == 22050:
        return grow(o, w, B_TYPE_EVENT, 128, 22051)
    if phase == 22051:
        return grow(o, w, B_TYPES, TYPES_BYTES, 22052)
    if phase == 22052:
        return grow(o, w, B_TYPE_OUTPUT, TYPE_OUTPUT_BYTES, 22053)
    if phase == 22053:
        return release(o, w, B_REQUEST, 22001)'''
    assert old in result
    result = result.replace(old, new)
    result = result.replace('wire8(w, TYPE_REQUEST_CONFIG, 2,', 'wire8(w, TYPE_REQUEST_CONFIG, 1,')
    old = '''        if operation == 5:
            operation = 6'''
    new = '''        if operation == 4:
            operation = 5
        elif operation == 5:
            operation = 6'''
    assert old in result
    result = result.replace(old, new)
    ast.parse(result)
    return result


BODY += '\n' + shared_service_functions()
