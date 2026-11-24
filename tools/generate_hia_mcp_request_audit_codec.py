"""Exact durable audit record codec, including the original u128 timestamp."""
KEYS=('request_id','owner','tool_name','state','accepted_unix_ms','elapsed_ms',
      'root_device','root_inode','archive_device','archive_inode',
      'format','root','legacy','archive','shards','device','inode')
F={name:i+1 for i,name in enumerate(KEYS)}
TEXT=dict(record_id='{"request_id":',record_owner=',"owner":',
          record_tool=',"tool_name":',record_state=',"state":',
          record_time=',"accepted_unix_ms":',record_elapsed=',"elapsed_ms":',
          unknown='"unknown"',completed='"completed"',failed_state='"failed"')
SOURCE=r'''
def audit_field(w:mutbuf,parent:u64,key:u64) -> u64:
    if get(w,parent) != 6:
        return NONE
    child = get(w,parent+24)
    found = NONE
    while child != NONE:
        row = ARENA+64+child*72
        if audit_key(w,ARENA+get(w,row+40),get(w,row+48)) == key:
            if found != NONE:
                return NONE
            found = row
        child = get(w,row+16)
    return found

def fields_exact(w:mutbuf,parent:u64,required:u64,allowed:u64) -> bool:
    if get(w,parent) != 6:
        return False
    seen = 0
    child = get(w,parent+24)
    while child != NONE:
        row = ARENA+64+child*72
        key = audit_key(w,ARENA+get(w,row+40),get(w,row+48))
        if key == 0:
            return False
        bit = 1 << (key-1)
        if bit & allowed == 0 or bit & seen != 0:
            return False
        seen = seen | bit
        child = get(w,row+16)
    return seen & required == required

def parse_u128(w:mutbuf,row:u64,target:u64) -> bool:
    if row == NONE or get(w,row) != 3:
        return False
    at = get(w,72)+get(w,row+24)
    size = get(w,row+32)
    if size == 0 or size > 39:
        return False
    lo = 0
    hi = 0
    index = 0
    while index < size:
        ch = byte(w,at+index)
        if ch < 48 or ch > 57:
            return False
        digit = ch-48
        if hi > 1844674407370955161 or (hi == 1844674407370955161 and lo > 11068046444225730969):
            return False
        if hi == 1844674407370955161 and lo == 11068046444225730969 and digit > 5:
            return False
        lower = (lo & 4294967295)*10+digit
        upper = (lo >> 32)*10+(lower >> 32)
        lo = (upper << 32) | (lower & 4294967295)
        hi = hi*10+(upper >> 32)
        index = index+1
    put(w,target,lo)
    put(w,target+8,hi)
    return True

def scalar_number(w:mutbuf,row:u64,target:u64) -> bool:
    if parse_u128(w,row,target) == False:
        return False
    return get(w,target+8) == 0

def parse_string(w:mutbuf,row:u64,target:u64,size:u64) -> bool:
    if row == NONE or get(w,row) != 4 or get(w,row+32) != size:
        return False
    copy_state(w,ARENA+get(w,row+24),target,size)
    return True

def parse_record(w:mutbuf,target:u64,id:u64) -> bool:
    root = ARENA+64
    if fields_exact(w,root,31,63) == False:
        return False
    fill_range(w,target,256,0)
    if parse_string(w,audit_field(w,root,1),target,64) == False or lowerhex(w,target,64) == False:
        return False
    if equal(w,target,id,64) == False:
        return False
    if parse_string(w,audit_field(w,root,2),target+64,64) == False or lowerhex(w,target+64,64) == False:
        return False
    tool = audit_field(w,root,3)
    if tool == NONE or get(w,tool) != 4:
        return False
    size = get(w,tool+32)
    if valid_tool(w,ARENA+get(w,tool+24),size) == False:
        return False
    copy_state(w,ARENA+get(w,tool+24),target+128,size)
    put(w,target+192,size)
    state = audit_field(w,root,4)
    if state == NONE or get(w,state) != 4:
        return False
    start = ARENA+get(w,state+24)
    size = get(w,state+32)
    if size == 7 and getn(w,start,7) == 31084746196774517:
        put(w,target+200,0)
    elif size == 9 and get(w,start) == 7311705475154997091 and byte(w,start+8) == 100:
        put(w,target+200,1)
    elif size == 6 and getn(w,start,6) == 110386477359462:
        put(w,target+200,2)
    else:
        return False
    if parse_u128(w,audit_field(w,root,5),target+208) == False:
        return False
    elapsed = audit_field(w,root,6)
    if elapsed != NONE and get(w,elapsed) != 0:
        if scalar_number(w,elapsed,target+232) == False:
            return False
        put(w,target+224,1)
    return True

def decimal128(w:mutbuf,at:u64,lo:u64,hi:u64) -> u64:
    if lo == 0 and hi == 0:
        store(w,at,48)
        return at+1
    count = 0
    while lo != 0 or hi != 0:
        part = hi >> 32
        a = part // 10
        rem = part % 10
        part = (rem << 32)+(hi & 4294967295)
        b = part // 10
        rem = part % 10
        part = (rem << 32)+(lo >> 32)
        c = part // 10
        rem = part % 10
        part = (rem << 32)+(lo & 4294967295)
        d = part // 10
        rem = part % 10
        hi = (a << 32)|b
        lo = (c << 32)|d
        store(w,24576+count,48+rem)
        count = count+1
    while count != 0:
        count = count-1
        store(w,at,byte(w,24576+count))
        at = at+1
    return at

def render_record(w:mutbuf,record:u64,target:u64) -> u64:
    at = text_record_id(w,target)
    at = quoted(w,at,record,64)
    at = text_record_owner(w,at)
    at = quoted(w,at,record+64,64)
    at = text_record_tool(w,at)
    at = quoted(w,at,record+128,get(w,record+192))
    at = text_record_state(w,at)
    if get(w,record+200) == 0:
        at = text_unknown(w,at)
    elif get(w,record+200) == 1:
        at = text_completed(w,at)
    else:
        at = text_failed_state(w,at)
    at = text_record_time(w,at)
    at = decimal128(w,at,get(w,record+208),get(w,record+216))
    at = text_record_elapsed(w,at)
    if get(w,record+224) == 0:
        at = text_null(w,at)
    else:
        at = decimal(w,at,get(w,record+232))
    at = text_close(w,at)
    return at-target
'''
# Author constants from the exact ASCII spellings, never hand-maintained numbers.
SOURCE=SOURCE.replace('31084746196774517',str(int.from_bytes(b'unknown','little')))
SOURCE=SOURCE.replace('7311705475154997091',str(int.from_bytes(b'complete','little')))
SOURCE=SOURCE.replace('110386477359462',str(int.from_bytes(b'failed','little')))
SOURCE+='\ndef audit_key(w:mutbuf,at:u64,size:u64) -> u64:\n'
for name,index in F.items():
    raw=name.encode();checks=[]
    for off in range(0,len(raw),8):
        part=raw[off:off+8];checks.append(f'(getn(w,at+{off},{len(part)}) ^ {int.from_bytes(part,"little")})')
    SOURCE+=f'    if size == {len(raw)} and ('+' | '.join(checks)+f') == 0:\n        return {index}\n'
SOURCE+='    return 0\n'
