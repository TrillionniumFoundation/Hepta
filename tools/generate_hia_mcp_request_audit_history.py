"""Native owner-scoped hot history; no admission ticket or archive seeding.

The public semantics follow request_audit.rs::history_at. The enclosing daemon
has already checked the caller's kernel worker lease and holds the store lock.
"""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_codec import SOURCE as CODEC, TEXT as CODEC_TEXT

TEXT = {
    **CODEC_TEXT,
    'history_prefix': '{"automatic_operation_retry":false,"cross_session_resume":false,"history_is_live":true,"next_after_id":',
    'history_requests': ',"requests":[',
    'history_suffix': '],"retention":{"global":512,"per_session":128},"session_scope":"native_mcp_session_only","status_semantics":"native_request_dispatch_observation_not_side_effect_delivery_or_business_success"}',
    'history_time': '{"accepted_unix_ms":',
    'history_elapsed': ',"elapsed_ms":',
    'history_id': ',"request_id":',
    'history_state': ',"state":',
    'history_tool': ',"tool_name":',
    'accepted': '"accepted"',
}
SOURCE = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase == 0:
        return procedure(w,M_OPEN,1,1,0,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) != NONE:
            reason = history(w)
            if reason != 0:
                put(w,96,reason)
        return enter(w,M_RESPONSE,0)
    put(w,96,1)
    return enter(w,M_RESPONSE,0)

def dispatch_active(w:mutbuf,id:u64) -> bool:
    index = 0
    while index < 32:
        ticket = TICKETS+index*512
        if get(w,ticket) == 1 and equal(w,id,ticket+64,64):
            return True
        index = index+1
    return False

def history(w:mutbuf) -> u64:
    start = 0
    if get(w,INPUT+96) == 64:
        found = False
        index = 0
        while index < get(w,HOTCOUNT):
            record = HOT_RECORDS+index*256
            if equal(w,record+64,INPUT+128,64) and equal(w,record,INPUT+192,64):
                start = index+1
                found = True
            index = index+1
        if found == False:
            return 33
    count = 0
    more = False
    index = start
    while index < get(w,HOTCOUNT):
        record = HOT_RECORDS+index*256
        if equal(w,record+64,INPUT+128,64):
            if count < get(w,INPUT+88):
                put(w,QUERY_ROWS+count*8,record)
                count = count+1
            else:
                more = True
        index = index+1
    # Exact original serde_json::json! cannot represent a u128 above u64.
    # That public call fails and leaves the original process store lock poisoned.
    # Preserve both outcomes explicitly without crashing the native owner.
    index = 0
    while index < count:
        if get(w,get(w,QUERY_ROWS+index*8)+216) != 0:
            put(w,STORE_POISONED,1)
            return 35
        index = index+1
    at = text_history_prefix(w,QUERY_OUTPUT+64)
    if more:
        at = quoted(w,at,get(w,QUERY_ROWS+(count-1)*8),64)
    else:
        at = text_null(w,at)
    at = text_history_requests(w,at)
    index = 0
    while index < count:
        if index != 0:
            store(w,at,44)
            at = at+1
        at = history_row(w,at,get(w,QUERY_ROWS+index*8))
        index = index+1
    at = text_history_suffix(w,at)
    size = at-(QUERY_OUTPUT+64)
    if size > 65536:
        return 34
    wire = size+WIRE_OVERHEAD
    index = 0
    while index < size:
        ch = byte(w,QUERY_OUTPUT+64+index)
        if ch == 34 or ch == 92:
            wire = wire+1
        index = index+1
    if wire > 65536:
        return 34
    put(w,QUERY_BYTES,64+size)
    return 0

def history_row(w:mutbuf,at:u64,record:u64) -> u64:
    at = text_history_time(w,at)
    at = decimal128(w,at,get(w,record+208),get(w,record+216))
    at = text_history_elapsed(w,at)
    if get(w,record+224) == 0:
        at = text_null(w,at)
    else:
        at = decimal(w,at,get(w,record+232))
    at = text_history_id(w,at)
    at = quoted(w,at,record,64)
    at = text_history_state(w,at)
    if get(w,record+200) == 0:
        if dispatch_active(w,record):
            at = text_accepted(w,at)
        else:
            at = text_unknown(w,at)
    elif get(w,record+200) == 1:
        at = text_completed(w,at)
    else:
        at = text_failed_state(w,at)
    at = text_history_tool(w,at)
    at = quoted(w,at,record+128,get(w,record+192))
    return text_close(w,at)
'''

def source():
    return authored(SOURCE+'\n'+CODEC, text=TEXT, extra={
        'WIRE_OVERHEAD': len(b'{"content":[{"type":"text","text":""}],"isError":false,"resultType":"complete"}')})
