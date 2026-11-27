"""Native archive paging over complete held original namespaces.

The query has one absolute three-second deadline supplied by the trusted
controller. It keeps only limit+1 rows, reads all retained originals, and
retains directory watches until the final content and namespace fence.
"""
import re
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_codec import SOURCE as CODEC, TEXT as CODEC_TEXT
from tools.generate_hia_mcp_request_audit_history import SOURCE as HISTORY, TEXT as HISTORY_TEXT
from tools.generate_hia_mcp_request_audit_usage import SOURCE as USAGE, TEXT as USAGE_TEXT, C as USAGE_C
from tools.generate_hia_mcp_request_audit_observation import SOURCE as OBSERVATION
from tools.generate_hia_mcp_request_audit_index import C as INDEX_C

TEXT = {
    **CODEC_TEXT, **HISTORY_TEXT, **USAGE_TEXT,
    'archive_prefix': '{"archive_retention":"no_automatic_metadata_eviction","automatic_operation_retry":false,"contains_parameters_or_output":false,"coverage":"metadata_retained_at_archive_introduction_and_subsequent_admitted_requests","history_is_live":true,"next_after_id":',
    'archive_total': '],"total":',
    'proc_fd': '/proc/self/fd/',
}

SOURCE = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    at = frame(w)
    if phase == 44 and get(w,48) != NONE:
        # The index now owns this exact watch even if the final deadline check
        # refuses the response after publication.
        save(w,0,NONE)
    if phase >= 980:
        return cleanup(o,w)
    if phase == 900:
        if failed(get(w,8)):
            return query_error(o,w,38)
        seconds = get(w,at+2048)
        nanos = get(w,at+2056)
        deadline = get(w,INPUT+256)
        fraction = get(w,INPUT+264)
        if seconds > deadline or (seconds == deadline and nanos >= fraction):
            return query_error(o,w,37)
        put(w,0,get(w,at+392))
        put(w,8,get(w,at+384))
        return checked(o,w)
    if phase == 0:
        save(w,0,NONE)
        save(w,1,NONE)
        save(w,2,0)
        put(w,B_ORIGINALS,0)
        index = 0
        while index < group_count(w):
            select_member(w,index)
            fill_range(w,query_base(w),B_PROJECT_BYTES,0)
            if get(w,CURRENT_PHASE) == 5:
                usage_prepare(w)
            index = index+1
        select_member(w,0)
    put(w,at+392,phase)
    put(w,at+384,get(w,8))
    return call(o,w,900,228,1,at+2048,0,0,0,0,12)

def checked(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        # Do not grant a malformed internal frame a new or extended budget.
        seconds = get(w,at+2048)
        nanos = get(w,at+2056)
        if get(w,INPUT+256) > seconds+3 or (get(w,INPUT+256) == seconds+3 and get(w,INPUT+264) > nanos):
            return query_error(o,w,38)
        return procedure(w,M_OPEN,0,1,0,0,0,0,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        return procedure(w,M_INDEX,0,29,0,0,0,0,0,0,0,0)
    if phase == 29:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        select_member(w,0)
        return step(w,30)
    if phase == 30:
        if get(w,INPUT+96) == 64:
            return procedure(w,M_ARCHIVE,ARCHIVE_READ,2,INPUT+192,Q_CURSOR,0,0,0,0,0,0)
        return step(w,31)
    if phase == 2:
        if get(w,48) == NONE or get(w,48) == NEG2 or equal(w,Q_CURSOR+64,INPUT+128,64) == False:
            if get(w,B_ACTIVE) == 0:
                return query_error(o,w,38)
            put(w,B_ERRORS+get(w,B_MEMBER)*8,38)
            put(w,96,0)
            put(w,104,0)
        return step(w,31)
    if phase == 31:
        index = get(w,B_MEMBER)+1
        if index < group_count(w):
            select_member(w,index)
            return step(w,30)
        select_member(w,0)
        return step(w,3)
    if phase == 3:
        return call(o,w,4,294,O_NONBLOCK+O_CLOEXEC,0,0,0,0,0,0)
    if phase == 4:
        if failed(result):
            return query_error(o,w,38)
        save(w,0,result)
        save(w,2,0)
        return step(w,5)
    if phase == 5:
        index = local(w,2)
        if index == watch_count(w):
            save(w,2,0)
            return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,7,0,0,0,0,0,0,0,0)
        end = text_proc_fd(w,at+3072)
        end = decimal(w,end,watch_fd(w,index))
        store(w,end,0)
        return call(o,w,6,254,local(w,0),at+3072,16781262,0,0,0,12)
    if phase == 6:
        if failed(result):
            return query_error(o,w,38)
        index = 0
        while index < local(w,2):
            if get(w,Q_WATCHES+index*8) == result:
                return query_error(o,w,38)
            index = index+1
        put(w,Q_WATCHES+local(w,2)*8,result)
        save(w,2,local(w,2)+1)
        return step(w,5)
    if phase == 7:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        return step(w,8)
    if phase == 8:
        if local(w,2) == choose(get(w,LAYOUT) == 0,1,257):
            return step(w,40)
        text_dot(w,at+1024)
        return call(o,w,9,257,original_directory(w),at+1024,O_DIRECTORY+O_CLOEXEC+O_NOFOLLOW,0,0,0,12)
    if phase == 9:
        if failed(result):
            return query_error(o,w,38)
        save(w,1,result)
        return step(w,10)
    if phase == 10:
        return call(o,w,11,217,local(w,1),Q_SCAN,65536,0,0,0,12)
    if phase == 11:
        if result == NEG4:
            return step(w,10)
        if failed(result) or result > 65536:
            return query_error(o,w,38)
        if result == 0:
            descriptor = local(w,1)
            save(w,1,NONE)
            return call(o,w,20,3,descriptor,0,0,0,0,0,0)
        save(w,3,result)
        save(w,4,0)
        return step(w,12)
    if phase == 12:
        pos = local(w,4)
        size = local(w,3)
        if pos == size:
            return step(w,10)
        if pos > size or size-pos < 20:
            return query_error(o,w,38)
        span = getn(w,Q_SCAN+pos+16,2)
        if span < 20 or span > size-pos:
            return query_error(o,w,38)
        name = Q_SCAN+pos+19
        count = 0
        while count < span-19 and byte(w,name+count) != 0:
            count = count+1
        if count == span-19:
            return query_error(o,w,38)
        save(w,4,pos+span)
        if (count == 1 and byte(w,name) == 46) or (count == 2 and getn(w,name,2) == 11822):
            return step(w,12)
        id = name
        staged = False
        if count == 134 and byte(w,name) == 46 and byte(w,name+65) == 45 and getn(w,name+130,4) == 1886221358 and lowerhex(w,name+66,64):
            id = name+1
            staged = True
        elif count != 69 or getn(w,name+64,4) != 1869834798 or byte(w,name+68) != 110:
            return query_error(o,w,38)
        if lowerhex(w,id,64) == False:
            return query_error(o,w,38)
        shard = hex_digit_value(byte(w,id))*16+hex_digit_value(byte(w,id+1))
        if local(w,2) != 0 and shard != local(w,2)-1:
            return query_error(o,w,38)
        if staged:
            return step(w,12)
        copy_state(w,id,Q_ID,64)
        filename(w,Q_ID,at+1024)
        return procedure(w,M_ARCHIVE,ARCHIVE_FIND,13,Q_ID,0,0,0,0,0,0,0)
    if phase == 13:
        if get(w,48) != original_directory(w):
            return query_error(o,w,38)
        return procedure(w,M_FILES,READ_FILE,14,original_directory(w),at+1024,READ_DATA,2048,0,Q_STAMP,0,1)
    if phase == 14:
        if get(w,48) == NONE or get(w,48) > 2048:
            return query_error(o,w,38)
        if observation_record(w,READ_DATA,get(w,48),Q_RECORD,Q_ID):
            return step(w,16)
        return json_decode(o,w,15,READ_DATA,get(w,48))
    if phase == 15:
        if json_ok(w,result) == False or parse_record(w,Q_RECORD,Q_ID) == False:
            return query_error(o,w,38)
        return step(w,16)
    if phase == 16:
        return procedure(w,M_INDEX,1,17,Q_RECORD,Q_STAMP,0,0,0,0,0,0)
    if phase == 17:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        if get(w,B_ORIGINALS) == NONE:
            return query_error(o,w,38)
        put(w,B_ORIGINALS,get(w,B_ORIGINALS)+1)
        index = 0
        while index < group_count(w):
            select_member(w,index)
            if get(w,B_ACTIVE) == 0 or get(w,B_ERRORS+index*8) == 0:
                if select_record(w) == False:
                    return query_error(o,w,38)
            index = index+1
        select_member(w,0)
        return step(w,12)
    if phase == 20:
        if failed(result):
            return query_error(o,w,38)
        save(w,2,local(w,2)+1)
        return step(w,8)
    if phase == 40:
        index = 0
        while index < group_count(w):
            select_member(w,index)
            if get(w,B_ACTIVE) == 0 or get(w,B_ERRORS+index*8) == 0:
                if render_page(w) == False:
                    if get(w,B_ACTIVE) == 0 or get(w,STORE_POISONED) != 0:
                        return query_error(o,w,38)
                    put(w,B_ERRORS+index*8,38)
                elif get(w,B_ACTIVE) != 0:
                    size = get(w,QUERY_BYTES)
                    copy_state(w,QUERY_OUTPUT,B_OUTPUTS+index*B_OUTPUT_BYTES,size)
                    put(w,B_SIZES+index*8,size)
            index = index+1
        select_member(w,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_FENCE,43,0,0,0,0,0,0,0,0)
    if phase == 43:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        return step(w,41)
    if phase == 41:
        return call(o,w,42,0,local(w,0),Q_EVENTS,65536,0,0,0,12)
    if phase == 42:
        if result == NEG4:
            return step(w,41)
        if result == Q_AGAIN:
            return procedure(w,M_INDEX,2,44,local(w,0),0,0,0,0,0,0,0)
        if failed(result) or result == 0 or result > 65536 or unrelated_events(w,result) == False:
            return query_error(o,w,38)
        return step(w,41)
    if phase == 44:
        if get(w,48) == NONE:
            return query_error(o,w,38)
        return step(w,980)
    return query_error(o,w,38)

def watch_count(w:mutbuf) -> u64:
    return choose(get(w,LAYOUT) == 0,2,259)

def watch_fd(w:mutbuf,index:u64) -> u64:
    if index == 0:
        return get(w,ROOTFD)
    if index == 1:
        return get(w,LEGACYFD)
    if index == 2:
        return get(w,SHARDROOTFD)
    return get(w,SHARD_FDS+(index-3)*8)

def original_directory(w:mutbuf) -> u64:
    if local(w,2) == 0:
        return get(w,LEGACYFD)
    return get(w,SHARD_FDS+(local(w,2)-1)*8)

def unrelated_events(w:mutbuf,size:u64) -> bool:
    at = 0
    while at < size:
        if size-at < 16:
            return False
        row = Q_EVENTS+at
        span = getn(w,row+12,4)
        mask = getn(w,row+4,4)
        if span > size-at-16 or getn(w,row,4) != get(w,Q_WATCHES) or mask & 61440 != 0:
            return False
        count = 0
        while count < span and byte(w,row+16+count) != 0:
            count = count+1
        if count == 0 or count == span:
            return False
        # Only unrelated children of the held state root may be ignored.
        end = text_legacy(w,Q_NAME)
        if count == end-Q_NAME-1 and equal(w,row+16,Q_NAME,count):
            return False
        end = text_shards(w,Q_NAME)
        if count == end-Q_NAME-1 and equal(w,row+16,Q_NAME,count):
            return False
        end = text_anchor11(w,Q_NAME)
        if count == end-Q_NAME-1 and equal(w,row+16,Q_NAME,count):
            return False
        end = text_anchor12(w,Q_NAME)
        if count == end-Q_NAME-1 and equal(w,row+16,Q_NAME,count):
            return False
        end = text_intent(w,Q_NAME)
        if count == end-Q_NAME-1 and equal(w,row+16,Q_NAME,count):
            return False
        at = at+16+span
    return at == size

def select_record(w:mutbuf) -> bool:
    if get(w,CURRENT_PHASE) == 5:
        return usage_record(w)
    if equal(w,Q_RECORD+64,INPUT+128,64) == False:
        return True
    if get(w,query_base(w)+240008) == NONE:
        return False
    put(w,query_base(w)+240008,get(w,query_base(w)+240008)+1)
    if get(w,INPUT+96) == 64 and record_order(w,Q_CURSOR,Q_RECORD) == False:
        return True
    count = get(w,query_base(w)+240000)
    limit = get(w,INPUT+88)+1
    at = 0
    while at < count and record_order(w,Q_RECORD,Q_PAGE+at*256) == False:
        at = at+1
    if at == limit:
        return True
    if count < limit:
        put(w,query_base(w)+240000,count+1)
    else:
        count = count-1
    while count > at:
        copy_state(w,Q_PAGE+(count-1)*256,Q_PAGE+count*256,256)
        count = count-1
    copy_state(w,Q_RECORD,Q_PAGE+at*256,256)
    return True

def render_page(w:mutbuf) -> bool:
    if get(w,CURRENT_PHASE) == 5:
        return usage_render(w)
    count = get(w,query_base(w)+240000)
    more = count > get(w,INPUT+88)
    if more:
        count = get(w,INPUT+88)
    index = 0
    while index < count:
        if get(w,Q_PAGE+index*256+216) != 0:
            # The original serde_json u128 projection panics while holding the
            # global audit store guard. Preserve that store-wide poison.
            put(w,STORE_POISONED,1)
            return False
        index = index+1
    at = text_archive_prefix(w,QUERY_OUTPUT+64)
    if more:
        at = quoted(w,at,Q_PAGE+(count-1)*256,64)
    else:
        at = text_null(w,at)
    at = text_history_requests(w,at)
    index = 0
    while index < count:
        if index != 0:
            store(w,at,44)
            at = at+1
        at = history_row(w,at,Q_PAGE+index*256)
        index = index+1
    at = text_archive_total(w,at)
    at = decimal(w,at,get(w,query_base(w)+240008))
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

def query_error(o:mutbuf,w:mutbuf,reason:u64) -> u32:
    put(w,96,reason)
    put(w,104,0)
    return step(w,980)

def cleanup(o:mutbuf,w:mutbuf) -> u32:
    if local(w,1) != NONE:
        descriptor = local(w,1)
        save(w,1,NONE)
        return call(o,w,980,3,descriptor,0,0,0,0,0,0)
    if local(w,0) != NONE:
        descriptor = local(w,0)
        save(w,0,NONE)
        return call(o,w,981,3,descriptor,0,0,0,0,0,0)
    if get(w,0) != 982 and get(w,I_NEW_READY) != 0:
        return procedure(w,M_INDEX,3,982,0,0,0,0,0,0,0,0)
    return enter(w,M_RESPONSE,0)
'''

def source():
    active = HISTORY[HISTORY.index('\ndef dispatch_active('):HISTORY.index('\ndef history(')]
    row = HISTORY[HISTORY.index('\ndef history_row('):]
    offsets = {'Q_PAGE':0, 'Q_CURSOR':16384, 'U_TABLE':0, 'U_SORT':163840,
               'U_STATE':184320, 'U_FIRST':184576, 'U_LAST':184832}
    body = SOURCE+active+row+'\n'+USAGE+'\n'+CODEC+'\n'+OBSERVATION
    body = re.sub(r'\b('+'|'.join(offsets)+r')\b',
                  lambda match: '(query_base(w)+'+str(offsets[match[0]])+')', body)
    return authored(body, text=TEXT, extra={
        **USAGE_C,
        **INDEX_C,
        'Q_PAGE': 17 << 20, 'Q_CURSOR': (17 << 20)+16384,
        'Q_RECORD': (17 << 20)+16640, 'Q_ID': (17 << 20)+17152,
        'Q_STAMP': (17 << 20)+17216,
        'Q_WATCHES': (17 << 20)+32768, 'Q_NAME': (17 << 20)+65536,
        'Q_SCAN': 18 << 20, 'Q_EVENTS': 19 << 20,
        'Q_AGAIN': (1 << 64)-11,
        'WIRE_OVERHEAD': len(b'{"content":[{"type":"text","text":""}],"isError":false,"resultType":"complete"}')})

