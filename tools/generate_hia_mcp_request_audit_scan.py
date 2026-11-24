"""HIA bounded hot snapshots and streaming exceptional staging cleanup."""
from tools.generate_hia_mcp_request_audit_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase = get(w,0)
    result = get(w,8)
    at = frame(w)
    if phase == 0:
        text_dot(w,at+512)
        save(w,0,NONE)
        save(w,3,0)
        if arg(w,3) == 3:
            end = text_init_prefix(w,at+1600)
            if arg(w,5) != 0:
                end = text_shard_prefix(w,at+1600)
            save(w,4,end-at-1600)
        return call(o,w,1,257,arg(w,0),at+512,O_DIRECTORY+O_CLOEXEC+O_NOFOLLOW,0,0,0,12)
    if phase == 1:
        if failed(result):
            return scan_error(o,w,31,result)
        save(w,0,result)
        return step(w,2)
    if phase == 2:
        return call(o,w,3,217,local(w,0),SCAN_DATA,65536,0,0,0,12)
    if phase == 3:
        if result == NEG4:
            return step(w,2)
        if failed(result):
            return scan_error(o,w,31,result)
        if result == 0:
            return call(o,w,8,3,local(w,0),0,0,0,0,0,0)
        if result > 65536:
            return scan_error(o,w,14,0)
        save(w,1,result)
        save(w,2,0)
        return step(w,4)
    if phase == 4:
        pos = local(w,2)
        size = local(w,1)
        if pos == size:
            return step(w,2)
        if size-pos < 20:
            return scan_error(o,w,14,0)
        span = getn(w,SCAN_DATA+pos+16,2)
        if span < 20 or span > size-pos:
            return scan_error(o,w,14,0)
        name = SCAN_DATA+pos+19
        count = 0
        while count < span-19 and byte(w,name+count) != 0:
            count = count+1
        if count == span-19 or utf8(w,name,count) == False:
            return scan_error(o,w,14,0)
        save(w,2,pos+span)
        if (count == 1 and byte(w,name) == 46) or (count == 2 and getn(w,name,2) == 11822):
            return step(w,4)
        if arg(w,3) == 4:
            save(w,3,1)
            return call(o,w,8,3,local(w,0),0,0,0,0,0,0)
        if arg(w,3) == 2:
            if count >= 70 and byte(w,name) == 46 and equal(w,name+1,arg(w,4),64) and byte(w,name+65) == 45 and getn(w,name+count-4,4) == 1886221358:
                if count > 143:
                    return scan_error(o,w,15,0)
                copy_state(w,name,at+1024,count)
                store(w,at+1024+count,0)
                return procedure(w,M_RECORDS,RECORD_CLEAN,5,arg(w,0),at+1024,count,0,0,0,0,0)
            return step(w,4)
        if arg(w,3) == 3:
            prefix = local(w,4)
            if count == prefix+68 and equal(w,name,at+1600,prefix) and lowerhex(w,name+prefix,64) and getn(w,name+count-4,4) == 1886221358:
                copy_state(w,name,at+1024,count)
                store(w,at+1024+count,0)
                return procedure(w,M_METADATA,1,6,arg(w,0),at+1024,arg(w,4),0,0,0,0,0)
            return step(w,4)
        if local(w,3) >= arg(w,2) or count > 143:
            return scan_error(o,w,13,0)
        target = arg(w,1)+local(w,3)*144
        fill_range(w,target,144,0)
        copy_state(w,name,target,count)
        put(w,target+136,count)
        save(w,3,local(w,3)+1)
        return step(w,4)
    if phase == 5:
        if get(w,48) == NONE:
            return scan_error(o,w,get(w,96),get(w,104))
        return step(w,4)
    if phase == 6:
        if get(w,48) == NONE:
            return scan_error(o,w,get(w,96),get(w,104))
        save(w,3,local(w,3)+get(w,48))
        if local(w,3) > 1:
            return scan_error(o,w,32,0)
        return step(w,4)
    if phase == 99:
        return done(w,NONE)
    if phase == 8:
        return done(w,local(w,3))
    return scan_error(o,w,1,0)

def scan_error(o:mutbuf,w:mutbuf,reason:u64,error:u64) -> u32:
    put(w,96,reason)
    put(w,104,error)
    if local(w,0) != NONE:
        return call(o,w,99,3,local(w,0),0,0,0,0,0,0)
    return done(w,NONE)
'''
def source():return authored(SOURCE)
