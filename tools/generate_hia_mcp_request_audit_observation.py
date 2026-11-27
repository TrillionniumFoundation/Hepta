"""Direct decoding of this observation's ordinary ASCII receipt JSON.

This is a conservative fast path, not a content cache. Every admitted value is
decoded from the complete freshly read original, with the same six-field schema,
identity, state, tool and integer domains. Escapes, sequences and every shape not
proved here return to the existing full JSON decoder and record validation.
"""

SOURCE = r'''
def observation_space(w:mutbuf,pos:u64,end:u64) -> u64:
    while pos < end:
        ch = byte(w,pos)
        if ch != 32 and ch != 9 and ch != 10 and ch != 13:
            return pos
        pos = pos+1
    return pos

def observation_integer(w:mutbuf,pos:u64,end:u64,target:u64) -> u64:
    begin = pos
    lo = 0
    hi = 0
    while pos < end:
        ch = byte(w,pos)
        if ch < 48 or ch > 57:
            if pos == begin:
                return NONE
            put(w,target,lo)
            put(w,target+8,hi)
            return pos
        if pos != begin and byte(w,begin) == 48:
            return NONE
        if pos-begin == 39:
            return NONE
        digit = ch-48
        if hi > 1844674407370955161 or (hi == 1844674407370955161 and lo > 11068046444225730969):
            return NONE
        if hi == 1844674407370955161 and lo == 11068046444225730969 and digit > 5:
            return NONE
        lower = (lo & 4294967295)*10+digit
        upper = (lo >> 32)*10+(lower >> 32)
        lo = (upper << 32) | (lower & 4294967295)
        hi = hi*10+(upper >> 32)
        pos = pos+1
    return NONE

def observation_string_end(w:mutbuf,pos:u64,end:u64) -> u64:
    begin = pos
    while pos < end:
        ch = byte(w,pos)
        if ch == 34:
            return pos
        if ch < 32 or ch > 126 or ch == 92 or pos-begin == 64:
            return NONE
        pos = pos+1
    return NONE

def observation_record(w:mutbuf,start:u64,size:u64,target:u64,id:u64) -> bool:
    if size == 0 or size > 2048:
        return False
    end = start+size
    pos = observation_space(w,start,end)
    if pos == end or byte(w,pos) != 123:
        return False
    pos = observation_space(w,pos+1,end)
    fill_range(w,target,256,0)
    seen = 0
    while pos < end:
        if byte(w,pos) != 34:
            return False
        begin = pos+1
        finish = observation_string_end(w,begin,end)
        if finish == NONE:
            return False
        key = audit_key(w,begin,finish-begin)
        if key == 0 or key > 6:
            return False
        bit = 1 << (key-1)
        if seen & bit != 0:
            return False
        seen = seen | bit
        pos = observation_space(w,finish+1,end)
        if pos == end or byte(w,pos) != 58:
            return False
        pos = observation_space(w,pos+1,end)
        if pos == end:
            return False
        if key <= 4:
            if byte(w,pos) != 34:
                return False
            begin = pos+1
            finish = observation_string_end(w,begin,end)
            if finish == NONE:
                return False
            count = finish-begin
            if key <= 2:
                if count != 64 or lowerhex(w,begin,64) == False:
                    return False
                if key == 1 and equal(w,begin,id,64) == False:
                    return False
                copy_state(w,begin,target+(key-1)*64,64)
            elif key == 3:
                if valid_tool(w,begin,count) == False:
                    return False
                copy_state(w,begin,target+128,count)
                put(w,target+192,count)
            else:
                if count == 7 and getn(w,begin,7) == 31084746196774517:
                    put(w,target+200,0)
                elif count == 9 and get(w,begin) == 7311705475154997091 and byte(w,begin+8) == 100:
                    put(w,target+200,1)
                elif count == 6 and getn(w,begin,6) == 110386477359462:
                    put(w,target+200,2)
                else:
                    return False
            pos = finish+1
        elif key == 5:
            pos = observation_integer(w,pos,end,target+208)
            if pos == NONE:
                return False
        else:
            if end-pos >= 4 and getn(w,pos,4) == 1819047278:
                pos = pos+4
            else:
                pos = observation_integer(w,pos,end,target+232)
                if pos == NONE or get(w,target+240) != 0:
                    return False
                put(w,target+224,1)
        pos = observation_space(w,pos,end)
        if pos == end:
            return False
        ch = byte(w,pos)
        if ch == 125:
            return seen & 31 == 31 and observation_space(w,pos+1,end) == end
        if ch != 44:
            return False
        pos = observation_space(w,pos+1,end)
    return False
'''

SOURCE = SOURCE.replace('31084746196774517', str(int.from_bytes(b'unknown', 'little')))
SOURCE = SOURCE.replace('7311705475154997091', str(int.from_bytes(b'complete', 'little')))
SOURCE = SOURCE.replace('110386477359462', str(int.from_bytes(b'failed', 'little')))
SOURCE = SOURCE.replace('1819047278', str(int.from_bytes(b'null', 'little')))
