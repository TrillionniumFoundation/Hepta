"""One private reply capability per native archive/usage request.

The existing audit socket carries an atomic v2 frame and one SCM_RIGHTS
descriptor. It never carries that query's response, so metadata observation
does not hold the legacy complete-exchange mutex.
"""

C = {
    'MQ_SOCKET':2240, 'MQ_PEER':2248, 'MQ_ACTIVE':2256,
    'MQ_NEXT':2264, 'MQ_RESULT':2272,
    'MQ_MSG':57000, 'MQ_IOV':57064, 'MQ_CONTROL':57120,
    'MQ_PAIR':57152, 'MQ_PTR':57168, 'MQ_POLL':57184,
    'MQ_ARCHIVE_IN':int.from_bytes(b'HIARQY02','little'),
    'MQ_USAGE_IN':int.from_bytes(b'HIAUSQ02','little'),
    'MQ_ARCHIVE_OUT':int.from_bytes(b'HIARQO02','little'),
    'MQ_USAGE_OUT':int.from_bytes(b'HIAUSO02','little'),
}

SOURCE = r'''
def metadata_start(o:mutbuf,w:mutbuf) -> u32:
    put(w,MQ_SOCKET,NONE)
    put(w,MQ_PEER,NONE)
    put(w,MQ_ACTIVE,1)
    return call(o,w,200,53,1,526341,0,MQ_PAIR,0,0,192)

def metadata_advance(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 200:
        if failed(result):
            return metadata_fail(o,w)
        put(w,MQ_SOCKET,getn(w,MQ_PAIR,4))
        put(w,MQ_PEER,getn(w,MQ_PAIR+4,4))
        if get(w,MQ_SOCKET) < 3 or get(w,MQ_PEER) < 3 or get(w,MQ_SOCKET) == get(w,MQ_PEER):
            return metadata_fail(o,w)
        zero_frame(w,MQ_MSG,56)
        zero_frame(w,MQ_CONTROL,24)
        put(w,MQ_PTR,AUDIT_WIRE)
        return relocate(o,w,201,MQ_PTR,1,MQ_IOV)
    if phase == 201:
        put(w,MQ_IOV+8,get(w,1936))
        put(w,MQ_PTR,MQ_IOV)
        return relocate(o,w,202,MQ_PTR,1,MQ_MSG+16)
    if phase == 202:
        put(w,MQ_MSG+24,1)
        put(w,MQ_PTR,MQ_CONTROL)
        return relocate(o,w,203,MQ_PTR,1,MQ_MSG+32)
    if phase == 203:
        put(w,MQ_MSG+40,24)
        put(w,MQ_CONTROL,20)
        put(w,MQ_CONTROL+8,4294967297)
        put(w,MQ_CONTROL+16,get(w,MQ_PEER))
        return metadata_clock(o,w,1)
    if phase == 204:
        if result == NEG4:
            return metadata_clock(o,w,1)
        if result == NEG11:
            return metadata_clock(o,w,3)
        if result != get(w,1936):
            return metadata_fail(o,w)
        descriptor = get(w,MQ_PEER)
        put(w,MQ_PEER,NONE)
        return call(o,w,205,3,descriptor,0,0,0,0,0,0)
    if phase == 205:
        if failed(result):
            return metadata_fail(o,w)
        return metadata_clock(o,w,2)
    if phase == 206:
        put(w,MQ_RESULT,result)
        return metadata_clock(o,w,5)
    if phase == 207:
        if failed(result) and result != NEG4:
            return metadata_fail(o,w)
        return metadata_clock(o,w,1)
    if phase == 208:
        if failed(result) and result != NEG4:
            return metadata_fail(o,w)
        return metadata_clock(o,w,2)
    if phase == 210:
        if failed(result):
            return metadata_fail(o,w)
        seconds = get(w,ARCHIVE_CLOCK)
        nanos = get(w,ARCHIVE_CLOCK+8)
        if seconds > get(w,ARCHIVE_DEADLINE_SEC) or (seconds == get(w,ARCHIVE_DEADLINE_SEC) and nanos >= get(w,ARCHIVE_DEADLINE_NSEC)):
            return archive_timeout(o,w)
        next = get(w,MQ_NEXT)
        if next == 1:
            return call(o,w,204,46,get(w,1864),MQ_MSG,16448,0,0,0,12)
        if next == 2:
            return call(o,w,206,45,get(w,MQ_SOCKET),HISTORY_REPLY,65601,64,0,0,12)
        if next == 3:
            put(w,MQ_POLL,get(w,1864)+17179869184)
            return call(o,w,207,7,MQ_POLL,1,1,0,0,0,3)
        if next == 4:
            put(w,MQ_POLL,get(w,MQ_SOCKET)+4294967296)
            return call(o,w,208,7,MQ_POLL,1,10,0,0,0,3)
        if next == 5:
            return metadata_received(o,w,get(w,MQ_RESULT))
        return metadata_fail(o,w)
    if phase == 220:
        return metadata_close(o,w)
    return metadata_fail(o,w)

def metadata_clock(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,MQ_NEXT,next)
    return call(o,w,210,228,1,ARCHIVE_CLOCK,0,0,0,0,12)

def metadata_received(o:mutbuf,w:mutbuf,size:u64) -> u32:
    if size == NEG4:
        return metadata_clock(o,w,2)
    if size == NEG11:
        return metadata_clock(o,w,4)
    if size <= 64 or size > 65600:
        return metadata_fail(o,w)
    if get(w,HISTORY_REPLY) != choose(get(w,1920) == 5,MQ_USAGE_OUT,MQ_ARCHIVE_OUT) or get(w,HISTORY_REPLY+8) != 2 or get(w,HISTORY_REPLY+16) != size or get(w,HISTORY_REPLY+56) != 0:
        return metadata_fail(o,w)
    status = get(w,HISTORY_REPLY+24)
    reason = get(w,HISTORY_REPLY+32)
    if status > 1 or (status == 0 and reason != 0) or (status == 1 and (reason == 0 or reason > 38)):
        return metadata_fail(o,w)
    if get(w,HISTORY_REPLY+40) != get(w,432) or get(w,HISTORY_REPLY+48) != get(w,448):
        return metadata_fail(o,w)
    put(w,HISTORY_REPLY_BYTES,size)
    put(w,HISTORY_STATUS,status)
    put(w,HISTORY_REASON,reason)
    put(w,2016,0)
    return metadata_close(o,w)

def metadata_fail(o:mutbuf,w:mutbuf) -> u32:
    put(w,2016,1)
    put(w,456,0)
    return metadata_close(o,w)

def metadata_close(o:mutbuf,w:mutbuf) -> u32:
    if get(w,MQ_PEER) != NONE:
        descriptor = get(w,MQ_PEER)
        put(w,MQ_PEER,NONE)
        return call(o,w,220,3,descriptor,0,0,0,0,0,0)
    if get(w,MQ_SOCKET) != NONE:
        descriptor = get(w,MQ_SOCKET)
        put(w,MQ_SOCKET,NONE)
        return call(o,w,220,3,descriptor,0,0,0,0,0,0)
    put(w,MQ_ACTIVE,0)
    return audit_return(w)
'''
