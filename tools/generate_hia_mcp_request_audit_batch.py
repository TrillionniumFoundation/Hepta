"""Native private reply capabilities and fixed metadata observation groups.

SCM_RIGHTS transports one private socket per v2 query. The daemon owns it until
the complete observation has ended, even when the original caller disappears.
Only already received, validated, same-kind requests can enter a frozen group.
"""
from tools.generate_hia_mcp_request_audit_common import authored

SOURCE = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase < 100:
        return receive_message(o,w)
    if phase < 200:
        return collect(o,w)
    return publish(o,w)

def receive_message(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 0:
        put(w,B_PEER,NONE)
        put(w,B_RIGHT_COUNT,0)
        put(w,B_RIGHT_INDEX,0)
        put(w,B_MESSAGE_OK,0)
        fill_range(w,B_MSG,56,0)
        fill_range(w,B_CONTROL,256,0)
        put(w,B_PTR,INPUT)
        return relocate(o,w,1,B_PTR,1,B_IOV)
    if phase == 1:
        put(w,B_IOV+8,4609)
        put(w,B_PTR,B_IOV)
        return relocate(o,w,2,B_PTR,1,B_MSG+16)
    if phase == 2:
        put(w,B_MSG+24,1)
        put(w,B_PTR,B_CONTROL)
        return relocate(o,w,3,B_PTR,1,B_MSG+32)
    if phase == 3:
        put(w,B_MSG+40,256)
        return call(o,w,4,47,0,B_MSG,1073741824+get(w,B_RECEIVE_FLAGS),0,0,0,12)
    if phase == 4:
        if result == NEG4:
            return step(w,0)
        put(w,B_RECEIVE_SIZE,result)
        if failed(result):
            put(w,B_MESSAGE_OK,1)
            return resume_receive(w)
        # Every installed descriptor is found before any refusal. Linux closes
        # truncated excess rights; all complete rights returned here are ours.
        ancillary_ok = ancillary(w)
        flags = getn(w,B_MSG+48,4)
        valid = ancillary_ok and flags & 40 == 0 and result > 0 and result <= 4608
        rights = get(w,B_RIGHT_COUNT)
        if ancillary_ok and rights == 0 and get(w,B_MSG+40) == 0 and flags & 8 == 0:
            if result == 0:
                put(w,B_POLL,35184372088832)
                return call(o,w,10,7,B_POLL,1,0,0,0,0,3)
            put(w,B_MESSAGE_OK,1)
            return resume_receive(w)
        if valid and rights == 1:
            put(w,B_PEER,get(w,B_RIGHTS))
            put(w,B_RIGHT_COUNT,0)
            if get(w,B_PEER) < 3:
                return close_received(o,w,0)
            put(w,B_SOCKET_OPTION+8,4)
            return call(o,w,5,55,get(w,B_PEER),1,3,B_SOCKET_OPTION,B_SOCKET_OPTION+8,0,960)
        return close_received(o,w,0)
    if phase == 5:
        if failed(result) or getn(w,B_SOCKET_OPTION,4) != 5 or getn(w,B_SOCKET_OPTION+8,4) != 4:
            return close_received(o,w,0)
        put(w,B_SOCKET_OPTION+8,4)
        return call(o,w,6,55,get(w,B_PEER),1,39,B_SOCKET_OPTION,B_SOCKET_OPTION+8,0,960)
    if phase == 6:
        if failed(result) or getn(w,B_SOCKET_OPTION,4) != 1 or getn(w,B_SOCKET_OPTION+8,4) != 4:
            return close_received(o,w,0)
        put(w,B_SOCKET_OPTION+16,12)
        return call(o,w,7,55,get(w,B_PEER),1,17,B_SOCKET_OPTION,B_SOCKET_OPTION+16,0,960)
    if phase == 7:
        if failed(result) or getn(w,B_SOCKET_OPTION+16,4) != 12 or getn(w,B_SOCKET_OPTION+4,4) != get(w,24) or getn(w,B_SOCKET_OPTION,4) != get(w,INPUT+56):
            return close_received(o,w,0)
        if get(w,INPUT+48) >= 32 or get(w,INPUT+56) <= 1:
            return close_received(o,w,0)
        flock_bytes(w,B_SOCKET_OPTION+64,1,64+get(w,INPUT+48))
        return call(o,w,8,72,get(w,DAEMON_AUDITFD),5,B_SOCKET_OPTION+64,0,0,0,48)
    if phase == 8:
        if failed(result) or getn(w,B_SOCKET_OPTION+64,2) != 1 or getn(w,B_SOCKET_OPTION+88,4) != get(w,INPUT+56):
            return close_received(o,w,0)
        put(w,B_MESSAGE_OK,1)
        return resume_receive(w)
    if phase == 10:
        if result == NEG4:
            put(w,B_POLL,35184372088832)
            return call(o,w,10,7,B_POLL,1,0,0,0,0,3)
        if failed(result):
            put(w,B_MESSAGE_OK,1)
            put(w,B_RECEIVE_SIZE,result)
        elif result > 0 and getn(w,B_POLL+6,2) & 8208 != 0:
            put(w,B_MESSAGE_OK,1)
        # A zero-byte packet from a still-open peer is malformed data, not EOF.
        return resume_receive(w)
    if phase == 80:
        return close_received(o,w,get(w,B_AFTER_CLOSE))
    return close_received(o,w,0)

def ancillary(w:mutbuf) -> bool:
    size = get(w,B_MSG+40)
    if size > 256:
        return False
    at = 0
    messages = 0
    valid = True
    while at < size:
        if size-at < 16:
            return False
        span = get(w,B_CONTROL+at)
        if span < 16 or span > size-at:
            return False
        level = getn(w,B_CONTROL+at+8,4)
        kind = getn(w,B_CONTROL+at+12,4)
        if level == 1 and kind == 1:
            pos = 16
            while pos+4 <= span:
                count = get(w,B_RIGHT_COUNT)
                if count >= 60:
                    return False
                put(w,B_RIGHTS+count*8,getn(w,B_CONTROL+at+pos,4))
                put(w,B_RIGHT_COUNT,count+1)
                pos = pos+4
            if pos != span:
                valid = False
        else:
            valid = False
        messages = messages+1
        at = at+((span+7) & 18446744073709551608)
    if size == 0:
        return valid and get(w,B_RIGHT_COUNT) == 0
    return valid and size == 24 and messages == 1 and get(w,B_CONTROL) == 20 and get(w,B_RIGHT_COUNT) == 1

def close_received(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,B_AFTER_CLOSE,next)
    if get(w,B_PEER) != NONE:
        descriptor = get(w,B_PEER)
        put(w,B_PEER,NONE)
        return call(o,w,80,3,descriptor,0,0,0,0,0,0)
    index = get(w,B_RIGHT_INDEX)
    if index < get(w,B_RIGHT_COUNT):
        put(w,B_RIGHT_INDEX,index+1)
        return call(o,w,80,3,get(w,B_RIGHTS+index*8),0,0,0,0,0,0)
    put(w,B_RIGHT_COUNT,0)
    put(w,B_MESSAGE_OK,0)
    return resume_receive(w)

def collect(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 100:
        put(w,B_ACTIVE,1)
        put(w,B_COUNT,0)
        put(w,B_FROZEN,0)
        put(w,B_SEALED,0)
        put(w,B_ORIGINALS,0)
        put(w,B_KIND,get(w,CURRENT_PHASE))
        put(w,B_MIN_SEC,get(w,INPUT+256))
        put(w,B_MIN_NS,get(w,INPUT+264))
        fill_range(w,B_FDS,64,255)
        fill_range(w,B_SIZES,64,0)
        fill_range(w,B_ERRORS,64,0)
        append_member(w)
        return call(o,w,101,228,1,B_CLOCK,0,0,0,0,12)
    if phase == 101:
        if failed(result):
            return group_error(w,38)
        seconds = get(w,B_CLOCK)
        nanos = get(w,B_CLOCK+8)
        if time_before(seconds,nanos,get(w,B_MIN_SEC),get(w,B_MIN_NS)) == False:
            return group_error(w,37)
        entered = get(w,B_MEMBERS+272)
        fraction = get(w,B_MEMBERS+280)
        if time_before(seconds,nanos,entered,fraction) or time_before(entered+3,fraction,get(w,B_MIN_SEC),get(w,B_MIN_NS)):
            return group_error(w,38)
        seconds = entered
        nanos = fraction+choose(get(w,B_KIND) == 5,1000000,2000000)
        if nanos >= 1000000000:
            seconds = seconds+1
            nanos = nanos-1000000000
        put(w,B_CUT_SEC,seconds)
        put(w,B_CUT_NS,nanos)
        hint = choose(get(w,B_KIND) == 5,get(w,B_USAGE_LARGE),get(w,B_ARCHIVE_LARGE))
        if hint != 1:
            return freeze(o,w)
        return step(w,110)
    if phase == 110:
        return call(o,w,111,228,1,B_CLOCK,0,0,0,0,12)
    if phase == 111:
        if failed(result):
            return group_error(w,38)
        seconds = get(w,B_CLOCK)
        nanos = get(w,B_CLOCK+8)
        if get(w,B_COUNT) == METADATA_BATCH_SIZE or time_before(seconds,nanos,get(w,B_CUT_SEC),get(w,B_CUT_NS)) == False or time_before(seconds,nanos,get(w,B_MIN_SEC),get(w,B_MIN_NS)) == False:
            return freeze(o,w)
        put(w,B_RECEIVE_NEXT,17)
        put(w,B_RECEIVE_FLAGS,64)
        return step(w,0)
    if phase == 112:
        return call(o,w,116,228,1,B_CLOCK,0,0,0,0,12)
    if phase == 116:
        if failed(result):
            return step(w,115)
        seconds = get(w,B_CLOCK)
        nanos = get(w,B_CLOCK+8)
        if get(w,B_FROZEN) != 0 or get(w,B_COUNT) >= METADATA_BATCH_SIZE:
            return step(w,115)
        if time_before(seconds,nanos,get(w,B_CUT_SEC),get(w,B_CUT_NS)) == False or time_before(seconds,nanos,get(w,B_MIN_SEC),get(w,B_MIN_NS)) == False:
            return step(w,115)
        entered = get(w,INPUT+272)
        fraction = get(w,INPUT+280)
        if time_before(seconds,nanos,get(w,INPUT+256),get(w,INPUT+264)) == False or time_before(seconds,nanos,entered,fraction) or time_before(entered+3,fraction,get(w,INPUT+256),get(w,INPUT+264)):
            return step(w,115)
        append_member(w)
        return step(w,110)
    if phase == 113:
        if failed(result) and result != NEG4:
            return group_error(w,38)
        return step(w,110)
    if phase == 114:
        # EAGAIN: wait only to the earliest fixed cutoff or member deadline.
        seconds = get(w,B_CUT_SEC)
        nanos = get(w,B_CUT_NS)
        if time_before(get(w,B_MIN_SEC),get(w,B_MIN_NS),seconds,nanos):
            seconds = get(w,B_MIN_SEC)
            nanos = get(w,B_MIN_NS)
        now = get(w,B_CLOCK)
        fraction = get(w,B_CLOCK+8)
        if time_before(now,fraction,seconds,nanos) == False:
            return freeze(o,w)
        seconds = seconds-now
        if nanos < fraction:
            seconds = seconds-1
            nanos = nanos+1000000000
        put(w,B_SLEEP,seconds)
        put(w,B_SLEEP+8,nanos-fraction)
        put(w,B_POLL,4294967296)
        return call(o,w,113,271,B_POLL,1,B_SLEEP,0,8,0,51)
    if phase == 115:
        # A different packet is kept exactly once for the next group/exchange.
        put(w,B_DEFERRED_SIZE,get(w,PACKET_SIZE))
        put(w,B_DEFERRED_PEER,get(w,B_PEER))
        put(w,B_PEER,NONE)
        copy_state(w,INPUT,B_DEFERRED,get(w,PACKET_SIZE))
        return freeze(o,w)
    return group_error(w,38)

def append_member(w:mutbuf) -> u64:
    index = get(w,B_COUNT)
    copy_state(w,INPUT,B_MEMBERS+index*512,512)
    put(w,B_FDS+index*8,get(w,B_PEER))
    put(w,B_PEER,NONE)
    put(w,B_COUNT,index+1)
    seconds = get(w,INPUT+256)
    nanos = get(w,INPUT+264)
    if time_before(seconds,nanos,get(w,B_MIN_SEC),get(w,B_MIN_NS)):
        put(w,B_MIN_SEC,seconds)
        put(w,B_MIN_NS,nanos)
    return 0

def freeze(o:mutbuf,w:mutbuf) -> u32:
    put(w,B_FROZEN,1)
    select_member(w,0)
    enter(w,M_SESSION,14)
    return call(o,w,14,228,1,frame(w)+2048,0,0,0,0,12)

def group_error(w:mutbuf,reason:u64) -> u32:
    put(w,B_FROZEN,1)
    select_member(w,0)
    put(w,96,reason)
    put(w,104,0)
    return enter(w,M_RESPONSE,0)

def publish(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    if phase == 1000:
        if get(w,B_ACTIVE) != 1 or get(w,B_FROZEN) != 1 or get(w,B_COUNT) == 0 or get(w,B_COUNT) > METADATA_BATCH_SIZE:
            return call(o,w,1999,60,65,0,0,0,0,0,0)
        if get(w,LOCKED) != 0:
            flock_bytes(w,271600,2,0)
            return call(o,w,1001,72,get(w,DAEMON_AUDITFD),6,271600,0,0,0,48)
        return step(w,1002)
    if phase == 1001:
        put(w,LOCKED,0)
        if failed(result):
            put(w,96,38)
        return step(w,1002)
    if phase == 1002:
        return call(o,w,1003,228,1,B_CLOCK,0,0,0,0,12)
    if phase == 1003:
        if failed(result):
            put(w,96,38)
        elif time_before(get(w,B_CLOCK),get(w,B_CLOCK+8),get(w,B_MIN_SEC),get(w,B_MIN_NS)) == False:
            put(w,96,37)
        build_responses(w)
        put(w,B_SEALED,1)
        put(w,B_SEND_INDEX,0)
        return step(w,1010)
    if phase == 1010:
        index = get(w,B_SEND_INDEX)
        if index == get(w,B_COUNT):
            put(w,B_ACTIVE,0)
            put(w,B_COUNT,0)
            put(w,32,0)
            return enter(w,M_SESSION,10)
        return call(o,w,1011,44,get(w,B_FDS+index*8),B_OUTPUTS+index*B_OUTPUT_BYTES,get(w,B_SIZES+index*8),16448,0,0,12)
    if phase == 1011:
        if result == NEG4:
            return step(w,1010)
        if result == 18446744073709551605:
            return call(o,w,1013,228,1,B_CLOCK,0,0,0,0,12)
        # Each reply is atomic. A closed cancelled peer cannot prevent another
        # member's publication or release the daemon's observation custody.
        index = get(w,B_SEND_INDEX)
        descriptor = get(w,B_FDS+index*8)
        put(w,B_FDS+index*8,NONE)
        return call(o,w,1012,3,descriptor,0,0,0,0,0,0)
    if phase == 1012:
        put(w,B_SEND_INDEX,get(w,B_SEND_INDEX)+1)
        return step(w,1010)
    if phase == 1013:
        index = get(w,B_SEND_INDEX)
        member = B_MEMBERS+index*512
        if failed(result) or time_before(get(w,B_CLOCK),get(w,B_CLOCK+8),get(w,member+256),get(w,member+264)) == False:
            descriptor = get(w,B_FDS+index*8)
            put(w,B_FDS+index*8,NONE)
            return call(o,w,1012,3,descriptor,0,0,0,0,0,0)
        put(w,B_POLL,get(w,B_FDS+index*8)+17179869184)
        put(w,B_SLEEP,0)
        put(w,B_SLEEP+8,1000000)
        return call(o,w,1014,271,B_POLL,1,B_SLEEP,0,8,0,51)
    if phase == 1014:
        return step(w,1010)
    return call(o,w,1999,60,65,0,0,0,0,0,0)

def build_responses(w:mutbuf) -> u64:
    index = 0
    success = False
    while index < get(w,B_COUNT):
        at = B_OUTPUTS+index*B_OUTPUT_BYTES
        member = B_MEMBERS+index*512
        reason = get(w,96)
        if reason == 0:
            reason = get(w,B_ERRORS+index*8)
        fill_range(w,at,64,0)
        put(w,at,choose(get(w,B_KIND) == 5,B_USAGE_OUT,B_ARCHIVE_OUT))
        put(w,at+8,2)
        if reason != 0:
            put(w,at+24,1)
            put(w,at+32,reason)
            end = at+64
            if reason == 37:
                end = text_audit_error_37(w,end)
            else:
                end = text_audit_error_38(w,end)
            put(w,B_SIZES+index*8,end-at)
        else:
            success = True
        put(w,at+16,get(w,B_SIZES+index*8))
        put(w,at+40,get(w,member+48))
        put(w,at+48,get(w,member+64))
        index = index+1
    if success:
        large = choose(get(w,B_ORIGINALS) > METADATA_LARGE_ROWS,1,0)
        if get(w,B_KIND) == 5:
            put(w,B_USAGE_LARGE,large)
        else:
            put(w,B_ARCHIVE_LARGE,large)
    return 0
'''


def source():
    return authored(SOURCE)
