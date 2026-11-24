"""HIA durability barriers for the original controller audit events."""
from tools.generate_hia_mcp_job_bridge_common import authored
TEXT=dict(audit='audit',events='events.jsonl',open='{"action":',
          start_intent='"process_start_intent"',start='"process_start"',reuse='"process_start_reused"',
          read='"process_read"',status='"process_status"',time=',"at_unix_ms":',host=',"host":',
          intent=',"outcome":{"phase":"intent","remote_operation_submitted":false}',
          launch=',"outcome":{"launch_state":',launch_end=',"phase":"result"}',
          reused=',"outcome":{"phase":"result","retried_launch":false,"reused":true}',
          observation=',"outcome":{"ok":true,"phase":"observation"}',subject=',"subject":',end='}\n')
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        at = text_audit(w, 16384)
        store(w, at, 0)
        return call(o, w, 1, 257, get(w, 1200), 16384, 589824, 0, 0, 0, 12)
    if phase == 1:
        if result == NEG2:
            return call(o, w, 2, 258, get(w, 1200), 16384, 448, 0, 0, 0, 12)
        if failed(result) or result < 3:
            return audit_error(w)
        put(w, 1624, result)
        at = text_events(w, 16448)
        store(w, at, 0)
        return call(o, w, 4, 257, result, 16448, 658497, 384, 0, 0, 12)
    if phase == 2:
        if failed(result) and result != NEG17:
            return audit_error(w)
        return call(o, w, 3, 74, get(w, 1200), 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if failed(result):
            return audit_error(w)
        return call(o, w, 1, 257, get(w, 1200), 16384, 589824, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or result < 3:
            return audit_error(w)
        put(w, 1632, result)
        return call(o, w, 5, 5, result, 9216, 0, 0, 0, 0, 12)
    if phase == 5:
        if failed(result) or safe_regular(w, 9216, 0) == False:
            return audit_error(w)
        copy_state(w, 9216, 18000, 144)
        if getn(w, 9240, 4) & 63 != 0:
            return call(o, w, 6, 91, get(w, 1632), 384, 0, 0, 0, 0, 0)
        return call(o, w, 7, 5, get(w, 1624), 18144, 0, 0, 0, 0, 12)
    if phase == 6:
        if failed(result):
            return audit_error(w)
        return call(o, w, 5, 5, get(w, 1632), 9216, 0, 0, 0, 0, 12)
    if phase == 7:
        if failed(result) or getn(w, 18168, 4) & 61440 != 16384:
            return audit_error(w)
        return call(o, w, 8, 5, get(w, 1200), 18288, 0, 0, 0, 0, 12)
    if phase == 8:
        if failed(result):
            return audit_error(w)
        return call(o, w, 9, 228, 0, 9216, 0, 0, 0, 0, 12)
    if phase == 9:
        if failed(result):
            return audit_error(w)
        put(w, 1648, line(w))
        put(w, 1640, 0)
        return audit_write(o, w)
    if phase == 10:
        if result == NEG4:
            return audit_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1648) - get(w, 1640):
            return audit_error(w)
        put(w, 1640, get(w, 1640) + result)
        if get(w, 1640) < get(w, 1648):
            return audit_write(o, w)
        return call(o, w, 11, 75, get(w, 1632), 0, 0, 0, 0, 0, 0)
    if phase == 11:
        if failed(result):
            return audit_error(w)
        return call(o, w, 12, 74, get(w, 1624), 0, 0, 0, 0, 0, 0)
    if phase == 12:
        if failed(result):
            return audit_error(w)
        return call(o, w, 13, 74, get(w, 1200), 0, 0, 0, 0, 0, 0)
    if phase == 13:
        if failed(result):
            return audit_error(w)
        return call(o, w, 14, 262, get(w, 1624), 16448, 9216, 256, 0, 0, 60)
    if phase == 14:
        if failed(result) or safe_regular(w, 9216, 1) == False or get(w, 9216) != get(w, 18000) or get(w, 9224) != get(w, 18008):
            return audit_error(w)
        return call(o, w, 15, 5, get(w, 1624), 9216, 0, 0, 0, 0, 12)
    if phase == 15:
        if failed(result) or same_stamp(w, 9216, 18144) == False:
            return audit_error(w)
        return call(o, w, 16, 262, get(w, 1200), 16384, 9216, 0, 0, 0, 60)
    if phase == 16:
        if failed(result) or get(w, 9216) != get(w, 18144) or get(w, 9224) != get(w, 18152):
            return audit_error(w)
        return call(o, w, 17, 5, get(w, 1200), 9216, 0, 0, 0, 0, 12)
    if phase == 17:
        if failed(result) or same_stamp(w, 9216, 18288) == False:
            return audit_error(w)
        return call(o, w, 18, 3, get(w, 1632), 0, 0, 0, 0, 0, 0)
    if phase == 18:
        if failed(result):
            return audit_error(w)
        return call(o, w, 19, 3, get(w, 1624), 0, 0, 0, 0, 0, 0)
    if phase == 19:
        if failed(result):
            return audit_error(w)
        return enter(w, get(w, 1600), get(w, 1608))
    return audit_error(w)

def audit_error(w:mutbuf) -> u32:
    if get(w, 1616) == 0:
        return 0
    put(w, 1688, 1)
    return enter(w, get(w, 1600), get(w, 1608))

def audit_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 10, 1, get(w, 1632), JSON + get(w, 1640), get(w, 1648) - get(w, 1640), 0, 0, 0, 12)

def line(w:mutbuf) -> u64:
    kind = get(w, 1616)
    at = text_open(w, JSON)
    if kind == 0:
        at = text_start_intent(w, at)
    elif kind == 1:
        at = text_start(w, at)
    elif kind == 2:
        at = text_reuse(w, at)
    elif kind == 3:
        at = text_read(w, at)
    else:
        at = text_status(w, at)
    at = text_time(w, at)
    at = decimal(w, at, get(w, 9216) * 1000 + get(w, 9224) // 1000000)
    at = text_host(w, at)
    at = qslot(w, at, S_HOST)
    if kind == 0:
        at = text_intent(w, at)
    elif kind == 1:
        at = text_launch(w, at)
        at = qslot(w, at, S_LAUNCH_STATE)
        at = text_launch_end(w, at)
    elif kind == 2:
        at = text_reused(w, at)
    else:
        at = text_observation(w, at)
    at = text_subject(w, at)
    at = qslot(w, at, S_JOB_ID)
    at = text_end(w, at)
    return at - JSON
'''

def source():
    return authored(SOURCE,text=TEXT)
