"""HIA fixed response framing and release of the original transaction lease."""
from tools.generate_hia_mcp_request_audit_common import authored, ERRORS
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 0:
        if get(w,HOT_OWNED) != 0:
            put(w,HOT_OWNED,0)
            return call(o,w,1,3,get(w,HOTFD),0,0,0,0,0,0)
        return step(w,2)
    if phase == 1:
        put(w,HOTFD,NONE)
        return step(w,2)
    if phase == 2:
        build_response(w)
        if get(w,LOCKED) != 0:
            flock_bytes(w,271600,2,0)
            return call(o,w,3,72,get(w,DAEMON_AUDITFD),6,271600,0,0,0,48)
        return step(w,4)
    if phase == 3:
        put(w,LOCKED,0)
        if failed(result):
            put(w,96,31)
            put(w,104,result)
            build_response(w)
        return step(w,4)
    if phase == 4:
        if get(w,CURRENT_PHASE) >= 3:
            return call(o,w,5,1,1,QUERY_OUTPUT,get(w,QUERY_BYTES),0,0,0,12)
        return call(o,w,5,1,1,RESPONSE,512,0,0,0,12)
    if phase == 5:
        if result == NEG4:
            return step(w,4)
        if result != choose(get(w,CURRENT_PHASE) >= 3,get(w,QUERY_BYTES),512):
            return call(o,w,99,60,74,0,0,0,0,0,0)
        if get(w,CURRENT_PHASE) == 0 and get(w,96) != 0:
            return call(o,w,99,60,choose(get(w,104) == 0,65,74),0,0,0,0,0,0)
        put(w,32,0)
        return enter(w,M_SESSION,10)
    return call(o,w,99,60,74,0,0,0,0,0,0)

def build_response(w:mutbuf) -> u64:
    if get(w,CURRENT_PHASE) >= 3:
        return history_response(w)
    fill_range(w,RESPONSE,512,0)
    put(w,RESPONSE,OUT_MAGIC)
    put(w,RESPONSE+8,1)
    put(w,RESPONSE+16,get(w,CURRENT_PHASE))
    if get(w,96) != 0:
        put(w,RESPONSE+24,choose(get(w,104) == 0,1,2))
        put(w,RESPONSE+32,get(w,96))
        end = error_text(w,get(w,96),RESPONSE+192)
        put(w,RESPONSE+104,end-(RESPONSE+192))
    put(w,RESPONSE+88,get(w,CURRENT_SLOT))
    put(w,RESPONSE+96,get(w,CURRENT_GEN))
    if get(w,ID_PRESENT) != 0:
        put(w,RESPONSE+40,64)
        put(w,RESPONSE+48,get(w,TICKET_HOT))
        put(w,RESPONSE+56,get(w,RECORD+208))
        put(w,RESPONSE+64,get(w,RECORD+216))
        put(w,RESPONSE+72,get(w,RECORD+224))
        put(w,RESPONSE+80,get(w,RECORD+232))
        copy_state(w,RECORD,RESPONSE+128,64)
    return 0

def history_response(w:mutbuf) -> u64:
    fill_range(w,QUERY_OUTPUT,64,0)
    put(w,QUERY_OUTPUT,choose(get(w,CURRENT_PHASE) == 4,ARCHIVE_OUT_MAGIC,HISTORY_OUT_MAGIC))
    put(w,QUERY_OUTPUT+8,1)
    if get(w,96) != 0:
        put(w,QUERY_OUTPUT+24,1)
        put(w,QUERY_OUTPUT+32,get(w,96))
        end = QUERY_OUTPUT+64
        if get(w,CURRENT_PHASE) == 4:
            if get(w,96) == 37:
                end = text_audit_error_37(w,end)
            else:
                end = text_audit_error_38(w,end)
        elif get(w,96) == 33:
            end = text_audit_error_33(w,end)
        elif get(w,96) == 35:
            end = text_audit_error_35(w,end)
        else:
            end = text_history_unavailable(w,end)
        put(w,QUERY_BYTES,end-QUERY_OUTPUT)
    put(w,QUERY_OUTPUT+16,get(w,QUERY_BYTES))
    put(w,QUERY_OUTPUT+40,get(w,CURRENT_SLOT))
    put(w,QUERY_OUTPUT+48,get(w,CURRENT_GEN))
    return 0
'''
SOURCE+='\ndef error_text(w:mutbuf,reason:u64,at:u64) -> u64:\n'
for k in ERRORS:SOURCE+=f'    if reason == {k}:\n        return text_audit_error_{k}(w,at)\n'
SOURCE+='    return text_audit_error_1(w,at)\n'
def source():return authored(SOURCE,extra={
    'OUT_MAGIC':int.from_bytes(b'HIAAUO01','little'),
    'HISTORY_OUT_MAGIC':int.from_bytes(b'HIAAHO01','little'),
    'ARCHIVE_OUT_MAGIC':int.from_bytes(b'HIARQO01','little')})
