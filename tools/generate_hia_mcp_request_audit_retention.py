"""HIA hot-cache validation and original 512-global/128-owner retention."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op = get(w,frame(w)+16)
    if op == RETENTION_SNAPSHOT:
        return snapshot(o,w)
    if op == RETENTION_TARGET:
        return target_pin(o,w)
    if op == RETENTION_ADMIT:
        return retain(o,w)
    return bad(w,1)

def snapshot(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        save(w,0,0)
        return call(o,w,1,5,get(w,HOTFD),at+512,0,0,0,0,12)
    if phase == 1:
        if failed(result):
            return io_bad(w,result)
        if directory_ok(w,at+512) == False:
            return bad(w,3)
        return procedure(w,M_SCAN,0,2,get(w,HOTFD),HOT_NAMES,544,0,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,1,get(w,48))
        save(w,2,0)
        return step(w,3)
    if phase == 3:
        index = local(w,2)
        if index == local(w,1):
            save(w,2,0)
            put(w,HOTCOUNT,0)
            return step(w,5)
        name = HOT_NAMES+index*144
        save(w,2,index+1)
        if byte(w,name) == 46:
            return procedure(w,M_RECORDS,RECORD_CLEAN,4,get(w,HOTFD),name,get(w,name+136),0,0,0,0,0)
        return step(w,3)
    if phase == 4:
        if get(w,48) == NONE:
            return done(w,NONE)
        return step(w,3)
    if phase == 5:
        index = local(w,2)
        if index == local(w,1):
            return call(o,w,7,5,get(w,HOTFD),at+656,0,0,0,0,12)
        name = HOT_NAMES+index*144
        save(w,2,index+1)
        if byte(w,name) == 46:
            return step(w,5)
        if get(w,HOTCOUNT) >= 512 or get(w,name+136) != 69 or getn(w,name+64,5) != 474317450798 or lowerhex(w,name,64) == False:
            return bad(w,14)
        return procedure(w,M_RECORDS,RECORD_READ,6,get(w,HOTFD),name,HOT_RECORDS+get(w,HOTCOUNT)*256,0,0,0,0,0)
    if phase == 6:
        if get(w,48) == NONE:
            return done(w,NONE)
        put(w,HOTCOUNT,get(w,HOTCOUNT)+1)
        return step(w,5)
    if phase == 7:
        if failed(result):
            return io_bad(w,result)
        if stamp_equal(w,at+512,at+656) == False:
            if local(w,0) >= 2:
                return bad(w,22)
            save(w,0,local(w,0)+1)
            copy_state(w,at+656,at+512,144)
            return procedure(w,M_SCAN,0,2,get(w,HOTFD),HOT_NAMES,544,0,0,0,0,0)
        sort_hot(w)
        save(w,2,0)
        return step(w,8)
    if phase == 8:
        index = local(w,2)
        if index == get(w,HOTCOUNT):
            return done(w,0)
        return procedure(w,M_ARCHIVE,ARCHIVE_SEED,9,HOT_RECORDS+index*256,0,0,0,0,0,0,0)
    if phase == 9:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,2,local(w,2)+1)
        return step(w,8)
    return bad(w,1)

def sort_hot(w:mutbuf) -> u64:
    index = 1
    while index < get(w,HOTCOUNT):
        position = index
        while position > 0 and record_order(w,HOT_RECORDS+position*256,HOT_RECORDS+(position-1)*256):
            copy_state(w,HOT_RECORDS+position*256,COMPARE_RECORD,256)
            copy_state(w,HOT_RECORDS+(position-1)*256,HOT_RECORDS+position*256,256)
            copy_state(w,COMPARE_RECORD,HOT_RECORDS+(position-1)*256,256)
            position = position-1
        index = index+1
    return 0

def target_pin(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    if phase == 0:
        if get(w,INPUT+96) == 0:
            return done(w,0)
        tool = INPUT+192
        size = get(w,INPUT+88)
        status = size == 14 and get(w,tool) == 6877960222911325554 and getn(w,tool+8,6) == 126944209466741
        result = size == 14 and get(w,tool) == 6877960222911325554 and getn(w,tool+8,6) == 127979094992242
        if get(w,INPUT+96) != 64 or lowerhex(w,INPUT+256,64) == False or (status == False and result == False):
            return bad(w,23)
        return procedure(w,M_RECORDS,RECORD_READ,1,get(w,HOTFD),INPUT+256,COMPARE_RECORD,1,0,0,0,0)
    if phase == 1:
        if get(w,48) == NONE:
            return done(w,NONE)
        save(w,0,choose(get(w,48) == NEG2,0,1))
        return procedure(w,M_ARCHIVE,ARCHIVE_READ,2,INPUT+256,TEMP_RECORD,0,0,0,0,0,0)
    if phase == 2:
        if get(w,48) == NONE:
            return done(w,NONE)
        archived = get(w,48) != NEG2
        if local(w,0) == 0 and archived == False:
            return bad(w,23)
        if local(w,0) != 0 and archived:
            if record_identity(w,COMPARE_RECORD,TEMP_RECORD) == False or (get(w,COMPARE_RECORD+200) != 0 and get(w,COMPARE_RECORD+200) != get(w,TEMP_RECORD+200)) or (get(w,COMPARE_RECORD+224) != 0 and equal(w,COMPARE_RECORD+224,TEMP_RECORD+224,16) == False):
                return bad(w,20)
        selected = choose(archived,TEMP_RECORD,COMPARE_RECORD)
        if equal(w,selected+64,INPUT+128,64) == False:
            return bad(w,23)
        return done(w,0)
    return bad(w,1)

def active(w:mutbuf,id:u64) -> bool:
    if get(w,INPUT+96) == 64 and equal(w,id,INPUT+256,64):
        return True
    index = 0
    while index < 32:
        at = TICKETS+index*512
        if get(w,at) == 1:
            if equal(w,id,at+64,64):
                return True
            if get(w,at+384) != 0 and equal(w,id,at+320,64):
                return True
        index = index+1
    return False

def retain(o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        total = get(w,HOTCOUNT)
        count = 0
        index = 0
        while index < total:
            record = HOT_RECORDS+index*256
            put(w,record+248,0)
            if equal(w,record+64,INPUT+128,64):
                count = count+1
            index = index+1
        save(w,0,total)
        save(w,1,count)
        return step(w,1)
    if phase == 1:
        if local(w,1) < 128 and local(w,0) < 512:
            return done(w,1)
        save(w,2,0)
        save(w,3,choose(local(w,1) >= 128,1,0))
        return step(w,2)
    if phase == 2:
        index = local(w,2)
        if index == get(w,HOTCOUNT):
            return done(w,0)
        record = HOT_RECORDS+index*256
        save(w,2,index+1)
        if get(w,record+248) != 0 or (local(w,3) != 0 and equal(w,record+64,INPUT+128,64) == False) or active(w,record):
            return step(w,2)
        save(w,4,record)
        return procedure(w,M_ARCHIVE,ARCHIVE_READ,3,record,TEMP_RECORD,0,0,0,0,0,0)
    if phase == 3:
        record = local(w,4)
        if get(w,48) == NONE or get(w,48) == NEG2 or record_identity(w,record,TEMP_RECORD) == False or (get(w,record+200) != 0 and get(w,record+200) != get(w,TEMP_RECORD+200)) or (get(w,record+224) != 0 and equal(w,record+224,TEMP_RECORD+224,16) == False):
            put(w,96,0)
            put(w,104,0)
            return step(w,2)
        return procedure(w,M_RECORDS,RECORD_READ,4,get(w,HOTFD),record,COMPARE_RECORD,0,0,0,0,0)
    if phase == 4:
        if get(w,48) == NONE:
            return done(w,NONE)
        if record_equal(w,local(w,4),COMPARE_RECORD) == False:
            return bad(w,18)
        filename(w,local(w,4),at+1024)
        return call(o,w,5,263,get(w,HOTFD),at+1024,0,0,0,0,12)
    if phase == 5:
        if failed(result):
            return io_bad(w,result)
        return call(o,w,6,74,get(w,HOTFD),0,0,0,0,0,0)
    if phase == 6:
        if failed(result):
            return io_bad(w,result)
        record = local(w,4)
        put(w,record+248,1)
        save(w,0,local(w,0)-1)
        if equal(w,record+64,INPUT+128,64):
            save(w,1,local(w,1)-1)
        return step(w,1)
    return bad(w,1)
'''
SOURCE=SOURCE.replace('474317450798',str(int.from_bytes(b'.json','little')))
SOURCE=SOURCE.replace('6877960222911325554',str(int.from_bytes(b'request_','little')))
SOURCE=SOURCE.replace('126944209466741',str(int.from_bytes(b'status','little')))
SOURCE=SOURCE.replace('127979094992242',str(int.from_bytes(b'result','little')))
def source():return authored(SOURCE,extra={'TICKETS':7<<20})
