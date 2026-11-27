"""Owner-scoped usage projection over the held complete archive query.

The enclosing archive owner validates every original and all final fences.
Only this projection state is new; admission, locking and deadlines are shared.
"""

TEXT = {
    'usage_active': '{"active":',
    'usage_completed': ',"completed":',
    'usage_failed': ',"contains_parameters_or_output":false,"coverage":"metadata_retained_at_archive_introduction_and_subsequent_admitted_requests","failed":',
    'usage_first': ',"first_accepted_unix_ms":',
    'usage_last': ',"last_accepted_unix_ms":',
    'usage_tools': ',"retention":"archive_metadata_not_evicted_with_hot_cache","schema":"hepta-private-usage-v1","scope":"same_verified_credential_or_native_session","semantics":"dispatch_observation_not_transport_delivery_or_business_success","tool_counts":{',
    'usage_total': '},"total_requests":',
    'usage_unknown': ',"unknown":',
}

# 2,048 open-addressed entries each hold a length, count and 64-byte name.
# The original 65+name-length per-distinct-tool budget admits fewer than 1,024
# names. A refused projection still scans and fences all remaining originals.
C = {'U_TABLE': 20 << 20, 'U_SORT': (20 << 20)+262144,
     'U_STATE': (20 << 20)+300000, 'U_FIRST': (20 << 20)+300256,
     'U_LAST': (20 << 20)+300512}

SOURCE = r'''
def usage_prepare(w:mutbuf) -> u64:
    fill_range(w,U_TABLE,2048*80,0)
    fill_range(w,U_STATE,256,0)
    return 0

def usage_record(w:mutbuf) -> bool:
    if equal(w,Q_RECORD+64,INPUT+128,64) == False:
        return True
    total = get(w,U_STATE)
    state = get(w,Q_RECORD+200)
    if total == NONE or state > 2:
        return False
    put(w,U_STATE,total+1)
    put(w,U_STATE+8+state*8,get(w,U_STATE+8+state*8)+1)
    if state == 0 and dispatch_active(w,Q_RECORD):
        put(w,U_STATE+32,get(w,U_STATE+32)+1)
    if total == 0 or record_order(w,Q_RECORD,U_FIRST):
        copy_state(w,Q_RECORD,U_FIRST,256)
    if total == 0 or record_order(w,U_LAST,Q_RECORD):
        copy_state(w,Q_RECORD,U_LAST,256)
    if get(w,U_STATE+56) != 0:
        return True
    size = get(w,Q_RECORD+192)
    hash = 14695981039346656037
    index = 0
    while index < size:
        hash = (hash ^ byte(w,Q_RECORD+128+index))*1099511628211
        index = index+1
    slot = hash & 2047
    visited = 0
    while visited < 2048:
        row = U_TABLE+slot*80
        length = get(w,row)
        if length == 0:
            budget = get(w,U_STATE+40)+65+size
            if budget > 65536:
                put(w,U_STATE+56,1)
                return True
            put(w,U_STATE+40,budget)
            put(w,U_STATE+48,get(w,U_STATE+48)+1)
            put(w,row,size)
            put(w,row+8,1)
            copy_state(w,Q_RECORD+128,row+16,size)
            return True
        if length == size and equal(w,row+16,Q_RECORD+128,size):
            if get(w,row+8) == NONE:
                return False
            put(w,row+8,get(w,row+8)+1)
            return True
        slot = (slot+1) & 2047
        visited = visited+1
    return False

def usage_tool_before(w:mutbuf,left:u64,right:u64) -> bool:
    size = get(w,left)
    other = get(w,right)
    index = 0
    while index < size and index < other:
        a = byte(w,left+16+index)
        b = byte(w,right+16+index)
        if a != b:
            return a < b
        index = index+1
    return size < other

def usage_render(w:mutbuf) -> bool:
    if get(w,U_STATE+56) != 0:
        return False
    total = get(w,U_STATE)
    if total != 0 and (get(w,U_FIRST+216) != 0 or get(w,U_LAST+216) != 0):
        put(w,STORE_POISONED,1)
        return False
    active = get(w,U_STATE+32)
    if active > get(w,U_STATE+8):
        return False
    count = 0
    slot = 0
    while slot < 2048:
        row = U_TABLE+slot*80
        if get(w,row) != 0:
            pos = count
            while pos > 0 and usage_tool_before(w,row,get(w,U_SORT+(pos-1)*8)):
                put(w,U_SORT+pos*8,get(w,U_SORT+(pos-1)*8))
                pos = pos-1
            put(w,U_SORT+pos*8,row)
            count = count+1
        slot = slot+1
    if count != get(w,U_STATE+48) or count > 1024:
        return False
    at = text_usage_active(w,QUERY_OUTPUT+64)
    at = decimal(w,at,active)
    at = text_usage_completed(w,at)
    at = decimal(w,at,get(w,U_STATE+16))
    at = text_usage_failed(w,at)
    at = decimal(w,at,get(w,U_STATE+24))
    at = text_usage_first(w,at)
    if total == 0:
        at = text_null(w,at)
    else:
        at = decimal(w,at,get(w,U_FIRST+208))
    at = text_usage_last(w,at)
    if total == 0:
        at = text_null(w,at)
    else:
        at = decimal(w,at,get(w,U_LAST+208))
    at = text_usage_tools(w,at)
    index = 0
    while index < count:
        row = get(w,U_SORT+index*8)
        if index != 0:
            store(w,at,44)
            at = at+1
        at = quoted(w,at,row+16,get(w,row))
        store(w,at,58)
        at = decimal(w,at+1,get(w,row+8))
        index = index+1
    at = text_usage_total(w,at)
    at = decimal(w,at,total)
    at = text_usage_unknown(w,at)
    at = decimal(w,at,get(w,U_STATE+8)-active)
    at = text_close(w,at)
    size = at-QUERY_OUTPUT-64
    if size > 65536:
        return False
    wire = size+WIRE_OVERHEAD
    index = 0
    while index < size:
        ch = byte(w,QUERY_OUTPUT+64+index)
        if ch == 34 or ch == 92:
            wire = wire+1
        index = index+1
    if wire > 65536:
        return False
    put(w,QUERY_BYTES,64+size)
    return True
'''
