"""HIA raw JSON input admission before the existing complete native edit chain.

The fixed executor carries three immutable byte views. This HIA controller
decodes the query after program admission and wraps response bytes without
decoding them; the actual application owner retains response error ordering.
"""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(ROOT/'tools'),str(BASE/'native-edit-controller-next/tools'),str(BASE/'Hepta-agent-edit-native')]
import main_r4
from edit_authoring import source,document as build
from hia_edit_controller_common import ALL
from hepta.hia_agent_assembly import render_assembly

CONSTANTS=dict(main_r4.CONSTANTS)
CONSTANTS.update(EDIT_JSON_INIT=int.from_bytes(b'HIAEJI01','little'),E_INPUT_STYLE=16640,
    J_RETURN=16648,J_REQUEST=16656,J_GRAPH_AT=16664,J_GRAPH_BYTES=16672,J_RELEASE=16680,
    J_RESPONSE_BYTES=16688,J_GRAPH_LEASE=16696,
    DECODE_COMMAND=int.from_bytes(b'HIADJC01','little'),DECODE_EVENT=int.from_bytes(b'HIAJDE01','little'),
    GRAPH_MAGIC=int.from_bytes(b'HIAGRF01','little'),PREFIX_TEXT=17344)

BODY=main_r4.BODY
assert BODY.count('def edit_child_refusal(')==1
BODY=BODY.replace('def edit_child_refusal(','def previous_child_refusal(')
old='''        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)'''
assert BODY.count(old)==1
BODY=BODY.replace(old,old+'''
        elif phase >= 600 and phase < 700:
            result = json_front_step(o, w)''')
old='if length(s) != 64 or word(s, 0) != EDIT_INIT or word(s, 56) != 0:'
assert BODY.count(old)==1
BODY=BODY.replace(old,'if length(s) != 64 or (word(s, 0) != EDIT_INIT and word(s, 0) != EDIT_JSON_INIT) or word(s, 56) != 0:')
old='    put(w, E_MODE, mode)'
assert BODY.count(old)==1
BODY=BODY.replace(old,'''    if word(s, 0) == EDIT_JSON_INIT:
        put(w, E_INPUT_STYLE, 1)
'''+old)
for phase,target in ((46,1000),(200,2000)):
    old=f'''    if phase == {phase}:
        return switch(o, w, QUERY, {target})'''
    assert BODY.count(old)==1
    BODY=BODY.replace(old,f'''    if phase == {phase}:
        if get(w, E_INPUT_STYLE) == 1:
            put(w, J_RETURN, {target})
            put(w, C_PHASE, 600)
            return 0
        return switch(o, w, QUERY, {target})''')

FRONT=r'''
def edit_child_refusal(o:mutbuf, w:mutbuf) -> u32:
    group = get(w, E_ERROR_GROUP)
    error = get(w, E_ERROR_CODE)
    if group != 7 and group != 10:
        return previous_child_refusal(o, w)
    stage = get(w, E_CHILD_EVENT + 48)
    status = get(w, E_CHILD_EVENT + 56)
    message = 0
    if group == 7:
        if error == 1:
            if stage != 0 or status != 0:
                return refuse(w, 1810)
            message = 1
        elif error == 2:
            if stage == 0:
                if status != 0:
                    return refuse(w, 1811)
            elif stage != 1 or (status != 4294967295 and status != 4294967292):
                return refuse(w, 1812)
            message = 2
        elif error == 3:
            if stage != 1 or status != 4294967294:
                return refuse(w, 1813)
            message = 3
        elif error == 4:
            if stage != 2 or status != 4294967280:
                return refuse(w, 1814)
            message = 2
        else:
            return refuse(w, 1815)
    else:
        if error != 1 or stage != 0 or status != 0:
            return refuse(w, 1816)
        message = 4
    size = prefix_message(w, message)
    if size == 0:
        return refuse(w, 1817)
    return edit_error_start(w, 2, group, error, B_CONTROLLER, PREFIX_TEXT, size)

def json_front_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if get(w, E_INPUT_STYLE) != 1:
        return refuse(w, 1800)
    if phase == 600:
        request = advance(w, E_REQUEST)
        if request == 0:
            return ABI
        put(w, J_REQUEST, request)
        wire8(w, DECODE_COMMAND, 41, request, 9, get(w, E_DIGITS), 0, 0, 0)
        result = edit_service_start(w, 2, B_QUERY_GRAPH, 0, cap(w, B_QUERY_GRAPH), B_CONTROLLER, WIRE, 64, 512, MAIN, 601)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    if phase == 601:
        if get(w, S_STATE) != 2 or get(w, S_KIND) != 2 or get(w, S_RESULT_CODE) != 128 or get(w, S_RESULT_EVENT_BYTES) != 128:
            return refuse(w, 1801)
        if get(w, S_RESULT_EVENT) != DECODE_EVENT or get(w, S_RESULT_EVENT + 16) != 41 or get(w, S_RESULT_EVENT + 24) != get(w, J_REQUEST):
            return refuse(w, 1802)
        if cap(w, get(w, S_RESULT_SLOT)) != get(w, S_RESULT_BYTES):
            return refuse(w, 1803)
        offset = get(w, S_RESULT_EVENT + 112)
        size = get(w, S_RESULT_EVENT + 120)
        error = get(w, S_RESULT_EVENT + 104)
        if inside(w, get(w, S_RESULT_SLOT), offset, size) == 0:
            return refuse(w, 1804)
        action = get(w, S_RESULT_EVENT + 8)
        if action == 3:
            if error == 0 or error == ABI or size == 0:
                return refuse(w, 1805)
            return edit_error_start(w, 1, 31, error, get(w, S_RESULT_SLOT), offset, size)
        if action != 0 or error != 0 or size < 128:
            return refuse(w, 1806)
        put(w, J_GRAPH_AT, offset)
        put(w, J_GRAPH_BYTES, size)
        return release(o, w, B_QUERY_GRAPH, 602)
    if phase == 602:
        return grow(o, w, B_QUERY_GRAPH, get(w, J_GRAPH_BYTES), 603)
    if phase == 603:
        return copy(o, w, get(w, S_RESULT_SLOT), get(w, J_GRAPH_AT), B_QUERY_GRAPH, 0, get(w, J_GRAPH_BYTES), 604)
    if phase == 604:
        return protect(o, w, B_QUERY_GRAPH, 1, 605)
    if phase == 605:
        put(w, J_RELEASE, 32)
        put(w, C_PHASE, 606)
        return 0
    if phase == 606:
        slot = get(w, J_RELEASE)
        if slot < 50:
            put(w, J_RELEASE, slot + 1)
            return release(o, w, slot, 606)
        # Response bytes remain uninterpreted through query checking. The
        # existing bounded response owner decodes them only after a match.
        size = cap(w, B_RESPONSE_GRAPH)
        if size > MAX - 128 or cap(w, B_COMMAND) != 0:
            return refuse(w, 1807)
        put(w, J_RESPONSE_BYTES, size)
        return grow(o, w, B_COMMAND, 128 + size, 607)
    if phase == 607:
        zero(w, WIRE, 128)
        put(w, WIRE, GRAPH_MAGIC)
        put(w, WIRE + 8, 101)
        put(w, WIRE + 16, 1)
        put(w, WIRE + 24, 1)
        put(w, WIRE + 40, get(w, J_RESPONSE_BYTES))
        put(w, WIRE + 48, 128 + get(w, J_RESPONSE_BYTES))
        put(w, WIRE + 64, 9)
        put(w, WIRE + 72, 128)
        put(w, WIRE + 80, get(w, J_RESPONSE_BYTES))
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 128, 608)
    if phase == 608:
        return copy(o, w, B_RESPONSE_GRAPH, 0, B_COMMAND, 128, get(w, J_RESPONSE_BYTES), 609)
    if phase == 609:
        # Every input view has an owned mapping, including a zero-byte view.
        # The generic release helper elides zero-capacity slots, so consume
        # this known live input mapping with an explicit release event.
        put(w, C_OBSERVE, 0)
        args(w, B_RESPONSE_GRAPH, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return event(o, w, 5, 610)
    if phase == 610:
        return grow(o, w, B_RESPONSE_GRAPH, 128 + get(w, J_RESPONSE_BYTES), 611)
    if phase == 611:
        return copy(o, w, B_COMMAND, 0, B_RESPONSE_GRAPH, 0, cap(w, B_RESPONSE_GRAPH), 612)
    if phase == 612:
        return protect(o, w, B_RESPONSE_GRAPH, 1, 613)
    if phase == 613:
        return release(o, w, B_COMMAND, 614)
    if phase == 614:
        return switch(o, w, QUERY, get(w, J_RETURN))
    return refuse(w, 1808)
'''

PREFIX_MESSAGES={
    1:b'E_HIA_LIMIT: program exceeds byte budget',
    2:b'E_HIA_FORMAT: invalid/deep UTF-8 JSON',
    3:b'E_HIA_LIMIT: program exceeds structural budget before JSON allocation',
    4:b'E_HIA_VERSION_COLLISION: historical nominal v2 requires import_legacy_composite_v2; the primitive v2 namespace cannot infer a producer profile',
}
def prefix_source():
    text='\ndef prefix_message(w:mutbuf, message:u64) -> u64:\n'
    for ident,payload in PREFIX_MESSAGES.items():
        text+=f'    if message == {ident}:\n'
        for offset in range(0,len(payload),8):
            block=payload[offset:offset+8]
            if len(block)==8:text+=f'        put(w, PREFIX_TEXT + {offset}, {int.from_bytes(block,"little")})\n'
            else:
                for i,value in enumerate(block):text+=f'        store(w, PREFIX_TEXT + {offset+i}, {value})\n'
        text+=f'        return {len(payload)}\n'
    return text+'    return 0\n'

def source_program():return source(BODY+'\n'+FRONT+'\n'+prefix_source()+'\n'+ALL,CONSTANTS,'edit_main')
def document():return build(source_program(),'agent_edit_json_main')
if __name__=='__main__':
    doc=document();out=ROOT/'examples/hia_bootstrap/agent_edit_json_main.hiaasm'
    out.write_text(render_assembly(doc))
    print(out.name,out.stat().st_size,len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']))
