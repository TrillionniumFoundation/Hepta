"""Native actual exception diagnostic path and guard custody."""
C={'MAGIC7': 3976762378627926344, 'VREQUEST2': 3616479931699120456, 'VREQUEST3': 3688537525737048392, 'N_TUPLE_QUERY': 3760595119774976328, 'N_GMAGIC': 3616464469816854856, 'N_GOBJECT': 3626597568978438472, 'N_NAME': 512, 'N_ARGS': 536, 'N_SPACE': 560, 'N_TYPE': 584, 'N_KEY': 608, 'N_ATTR': 632, 'N_LIST': 656, 'N_TUP': 680, 'N_RET': 704, 'N_MSG': 728, 'N_GCAP': 752, 'N_PTR': 776, 'N_RESUME': 784, 'N_DROP': 792, 'N_INDEX': 800, 'N_PID': 808, 'N_GLOBAL': 816, 'N_OP': 824, 'N_RESULT_NEXT': 832, 'N_FORMAT': 840, 'N_GERR': 848, 'N_UNKNOWN': 856, 'N_SCAN': 864, 'N_GPHASE': 872, 'N_SEND': 880, 'N_CHAR': 888, 'N_HEAD': 1024, 'N_SHADOW': 14848, 'N_GREQ': 15360, 'N_GOUT': 15552, 'N_GREPLY': 3626034619025017160, 'N_RENDER': 896}
SOURCE=r'''
def native_log(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==0:
        return native_begin(s,o,w)
    if phase==10 or phase==11:
        return native_write(o,w,phase)
    if phase>=2000 and phase<2020:
        return native_guard_begin(o,w,phase)
    if phase>=2020 and phase<2100:
        return native_protocol(o,w,phase)
    if phase>=2100 and phase<2200:
        return native_default(o,w,phase)
    if phase>=2200 and phase<2300:
        return native_string(o,w,phase)
    if phase>=2300 and phase<2400:
        return native_render(o,w,phase)
    return native_cleanup(o,w,phase)

def native_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT:
        return 4294967293
    at=8
    while at<192:
        if (at<24 or at>40) and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if readword(s,24)==0:
        return 4294967293
    zero(o,128,OUT-128)
    put(o,M_DEFER,1)
    copy_input(s,24,o,CAP,24)
    return system(o,2000,39,0,0,0,0,0,0,0)

def native_guard_begin(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2000:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0 or get(w,216)==0:
            return finish(o,107)
        put(o,N_PID,pid)
        put(o,PHASE,2001)
        put(o,0,0)
        return 5
    if phase==2001:
        if get(o,FEEDBACK)!=get(w,208) or get(w,208)==0:
            return finish(o,107)
        native_guard_packet(o,0)
        put(o,N_GREQ+96,16)
        return native_guard_call(o,w,2002)
    if phase==2002:
        if native_guard_record(o,0)==False:
            return finish(o,107)
        if get(o,N_GOUT+8)!=0:
            return finish(o,choose(get(o,N_GOUT+8)==4,103,107))
        within(o,N_GCAP,N_GOUT+16,24)
        return native_global_atom(o,2,2003,0,1)
    if phase==2003:
        if get(o,FEEDBACK)!=0:
            return system(o,2004,202,1,32,128,1,0,0,0)
        put(o,N_GLOBAL,1)
        put(o,N_SCAN,get(w,224))
        return again(o,2005)
    if phase==2004:
        return native_global_atom(o,2,2003,0,1)
    if phase==2005:
        if get(o,N_SCAN)==0:
            put(o,ERROR,107)
            return native_global_atom(o,3,2008,0,0)
        return native_memory(o,2006,0,get(o,N_SCAN),3,N_HEAD,128)
    if phase==2006:
        if get(o,N_HEAD)!=N_GOBJECT or get(o,N_HEAD+8)!=get(o,N_PID) or get(o,N_HEAD+16)!=0:
            put(o,ERROR,107)
            return native_global_atom(o,3,2008,0,0)
        if get(o,N_SCAN)!=get(o,N_GCAP):
            put(o,N_SCAN,get(o,N_HEAD+48))
            return again(o,2005)
        if get(o,N_HEAD+24)!=0 or get(o,N_HEAD+32)!=0 or get(o,N_HEAD+56)!=get(o,N_GCAP+8) or get(o,N_HEAD+64)!=get(o,N_GCAP+16):
            put(o,ERROR,107)
        elif get(o,N_HEAD+72)!=0 or get(o,N_HEAD+80)!=0 or get(o,N_HEAD+88)!=16 or get(o,N_HEAD+96)!=1664 or get(o,N_HEAD+112)!=0:
            put(o,ERROR,107)
        else:
            put(o,N_PTR,get(o,N_SCAN))
        return native_global_atom(o,3,2008,0,0)
    if phase==2008:
        put(o,N_GLOBAL,0)
        return system(o,2009,202,1,32,129,2147483647,0,0,0)
    if phase==2009:
        if get(o,ERROR)!=0:
            return finish(o,get(o,ERROR))
        native_packet(o,VREQUEST2,26)
        within(o,RQ+24,CAP,24)
        return value(o,w,2020)
    return native_fail(o,107)

def native_protocol(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2020:
        if native_ok(o)==False:
            return native_value_failed(o)
        if get(o,VP+8200)!=0:
            return native_fail(o,107)
        within(o,N_SPACE,VP+8224,24)
        within(o,N_ARGS,VP+8248,24)
        within(o,N_NAME,VP+8272,24)
        if get(o,N_SPACE)==0 or get(o,N_ARGS)==0 or get(o,N_NAME)==0:
            return native_unknown(o)
        return native_snapshot(o,2021)
    if phase==2021:
        return native_drop(o,w,N_SPACE,2022)
    if phase==2022:
        native_packet(o,VREQUEST3,36)
        within(o,RQ+24,CAP,24)
        return value(o,w,2023)
    if phase==2023:
        return native_take(o,N_TYPE,2024)
    if phase==2024:
        native_packet(o,VREQUEST,2)
        put(o,RQ+104,4)
        put(o,RQ+96,native_literal(o,RQ+128,0))
        put(o,VIN,135)
        return value(o,w,2025)
    if phase==2025:
        return native_take(o,N_KEY,2026)
    if phase==2026:
        native_packet(o,VREQUEST3,39)
        within(o,RQ+24,N_TYPE,24)
        within(o,RQ+48,N_KEY,24)
        return value(o,w,2027)
    if phase==2027:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return native_unknown(o)
        if get(o,VP+8)==3:
            put(o,N_FORMAT,0)
            return again(o,2028)
        put(o,N_FORMAT,1)
        return native_take(o,N_ATTR,2028)
    if phase==2028:
        return native_drop(o,w,N_KEY,2029)
    if phase==2029:
        return native_drop(o,w,N_TYPE,2030)
    if phase==2030:
        if get(o,N_FORMAT)==0:
            return again(o,2100)
        native_packet(o,VREQUEST5,49)
        within(o,RQ+24,N_ATTR,24)
        return value(o,w,2031)
    if phase==2031:
        if native_ok(o)==False:
            return native_text(o,w,1,2200)
        kind=get(o,VP+16)
        if kind!=3 and kind!=4 and kind!=5:
            return native_text(o,w,1,2200)
        put(o,N_FORMAT,kind)
        native_packet(o,VREQUEST,3)
        return value(o,w,2032)
    if phase==2032:
        return native_take(o,N_LIST,2033)
    if phase==2033:
        if get(o,N_FORMAT)!=3:
            return again(o,2035)
        native_packet(o,VREQUEST,16)
        within(o,RQ+24,N_LIST,24)
        within(o,RQ+48,CAP,24)
        return value(o,w,2034)
    if phase==2034:
        if native_ok(o)==False:
            return native_value_failed(o)
        return again(o,2035)
    if phase==2035:
        native_packet(o,N_TUPLE_QUERY,40)
        within(o,RQ+24,N_LIST,24)
        return value(o,w,2036)
    if phase==2036:
        return native_take(o,N_TUP,2037)
    if phase==2037:
        return native_drop(o,w,N_LIST,2038)
    if phase==2038:
        native_packet(o,VREQUEST5,70)
        within(o,RQ+24,N_ATTR,24)
        within(o,RQ+48,N_TUP,24)
        return value(o,w,2039)
    if phase==2039:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY or get(o,VP+88)!=1 or get(o,VP+96)!=1 or get(o,VP+24)==0:
            return native_unknown(o)
        disposition=get(o,VP+64)
        if disposition!=1 and disposition!=2:
            return native_unknown(o)
        within(o,N_RET,VP+24,24)
        put(o,N_FORMAT,disposition)
        if get(o,VP+104)!=0:
            put(o,ERROR,107)
        return native_snapshot(o,2040)
    if phase==2040:
        return native_drop(o,w,N_ATTR,2041)
    if phase==2041:
        return native_drop(o,w,N_TUP,2042)
    if phase==2042:
        if get(o,ERROR)!=0:
            return again(o,2400)
        if get(o,N_FORMAT)==2:
            return native_text(o,w,1,2200)
        put(o,N_FORMAT,10)
        native_packet(o,VREQUEST,7)
        within(o,RQ+24,N_RET,24)
        return value(o,w,2140)
    return native_fail(o,107)

def native_default(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2100:
        native_packet(o,VREQUEST,7)
        within(o,RQ+24,N_ARGS,24)
        return value(o,w,2101)
    if phase==2101:
        if native_ok(o)==False or get(o,VP+16)!=11:
            return native_value_failed(o)
        n=get(o,VP+48)
        if n==0:
            return native_text(o,w,5,2200)
        if n!=1:
            # A general repr traversal is a separate remaining formatter path.
            return native_fail(o,107)
        native_packet(o,VREQUEST,2)
        put(o,RQ+104,2)
        put(o,RQ+96,1)
        store(o,RQ+128,48)
        put(o,VIN,129)
        return value(o,w,2102)
    if phase==2102:
        return native_take(o,N_KEY,2103)
    if phase==2103:
        native_packet(o,VREQUEST,12)
        within(o,RQ+24,N_ARGS,24)
        within(o,RQ+48,N_KEY,24)
        return value(o,w,2104)
    if phase==2104:
        return native_take(o,N_RET,2105)
    if phase==2105:
        return native_drop(o,w,N_KEY,2106)
    if phase==2106:
        put(o,N_FORMAT,0)
        native_packet(o,VREQUEST,7)
        within(o,RQ+24,N_RET,24)
        return value(o,w,2140)
    if phase==2140:
        if native_ok(o)==False:
            return native_value_failed(o)
        kind=get(o,VP+16)
        if kind==4:
            within(o,N_MSG,N_RET,24)
            zero(o,N_RET,24)
            return native_snapshot(o,2201)
        if kind==2 and get(o,N_FORMAT)!=10:
            within(o,N_MSG,N_RET,24)
            zero(o,N_RET,24)
            put(o,N_RENDER,2)
            return native_snapshot(o,2201)
        if kind==3 and get(o,N_FORMAT)!=10:
            native_packet(o,VREQUEST,19)
            within(o,RQ+24,N_RET,24)
            put(o,RQ+112,8)
            return value(o,w,2150)
        if kind==8:
            native_packet(o,VREQUEST2,26)
            within(o,RQ+24,N_RET,24)
            return value(o,w,2141)
        if get(o,N_FORMAT)==10:
            return native_text(o,w,1,2200)
        if kind==0:
            return native_text(o,w,2,2200)
        if kind==1:
            native_packet(o,VREQUEST,19)
            within(o,RQ+24,N_RET,24)
            put(o,RQ+112,1)
            return value(o,w,2148)
        return native_fail(o,107)
    if phase==2141:
        if native_ok(o)==False:
            return native_value_failed(o)
        within(o,N_SPACE,VP+8224,24)
        within(o,N_LIST,VP+8248,24)
        within(o,N_TYPE,VP+8272,24)
        put(o,N_RESULT_NEXT,choose(get(o,VP+8200)==4,1,0))
        return native_snapshot(o,2142)
    if phase==2142:
        return native_drop(o,w,N_SPACE,2143)
    if phase==2143:
        return native_drop(o,w,N_TYPE,2144)
    if phase==2144:
        if get(o,N_RESULT_NEXT)==0:
            if get(o,N_FORMAT)==10:
                return native_text(o,w,1,2200)
            return native_fail(o,107)
        return native_drop(o,w,N_RET,2145)
    if phase==2145:
        within(o,N_MSG,N_LIST,24)
        zero(o,N_LIST,24)
        return native_snapshot(o,2201)
    if phase==2148:
        if native_ok(o)==False or byte(o,VP+8192)>1:
            return native_value_failed(o)
        return native_text(o,w,choose(byte(o,VP+8192)!=0,3,4),2200)
    if phase==2150:
        if native_ok(o)==False or get(o,VP+64)!=8:
            return native_value_failed(o)
        bits=get(o,VP+8192)
        if ((bits>>52)&2047)==2047:
            literal=6
            if (bits&4503599627370495)==0:
                literal=choose((bits>>63)!=0,8,7)
            return native_text(o,w,literal,2200)
        # The unique Value's native shortest-roundtrip numeric formatter
        # produces the finite token. Container JSON is never used as repr.
        native_packet(o,VREQUEST,18)
        within(o,RQ+24,N_RET,24)
        return value(o,w,2151)
    if phase==2151:
        put(o,N_RENDER,7)
        return native_take(o,N_MSG,2201)
    return native_fail(o,107)

def native_string(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2200:
        return native_take(o,N_MSG,2201)
    if phase==2201:
        put(o,N_INDEX,0)
        return again(o,2202)
    if phase==2202:
        index=get(o,N_INDEX)
        if index==10:
            return atom(o,2,2300,0,1)
        at=N_NAME+index*24
        put(o,N_INDEX,index+1)
        if at==N_NAME or at==N_MSG or get(o,at)==0:
            return again(o,2202)
        return native_drop(o,w,at,2202)
    return native_fail(o,107)

def native_render(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2300:
        if get(o,FEEDBACK)!=0:
            return system(o,2301,202,1,44,128,1,0,0,0)
        put(o,HELD,1)
        prefix(o)
        return write(o,2310,27)
    if phase==2301:
        return atom(o,2,2300,0,1)
    if phase==2310 or phase==2320:
        put(o,FIELD,choose(phase==2310,0,1))
        within(o,STR,choose(phase==2310,N_NAME,N_MSG),24)
        value_packet(o,7)
        within(o,RQ+24,STR,24)
        return value(o,w,2311)
    if phase==2311:
        expected=choose(get(o,N_RENDER)==0,4,get(o,N_RENDER))
        if get(o,FIELD)==0:
            expected=4
        if ok(o)==False or get(o,VP+16)!=expected:
            return native_fail(o,107)
        put(o,NBYTES,get(o,VP+72))
        put(o,OFFSET,0)
        return again(o,2312)
    if phase==2312:
        if get(o,OFFSET)==get(o,NBYTES):
            if get(o,FIELD)==0:
                value_packet(o,7)
                within(o,RQ+24,N_MSG,24)
                return value(o,w,2314)
            store(o,BUF,10)
            return write(o,2400,1)
        n=get(o,NBYTES)-get(o,OFFSET)
        if n>512:
            n=512
        value_packet(o,19)
        within(o,RQ+24,STR,24)
        put(o,RQ+104,get(o,OFFSET))
        put(o,RQ+112,n)
        return value(o,w,2313)
    if phase==2313:
        if ok(o)==False:
            return native_fail(o,107)
        render_chunk(o)
        if get(o,USED)==0:
            return native_fail(o,107)
        return write(o,2312,get(o,USED))
    if phase==2314:
        if ok(o)==False or get(o,VP+16)!=choose(get(o,N_RENDER)==0,4,get(o,N_RENDER)):
            return native_fail(o,107)
        if get(o,VP+72)==0:
            store(o,BUF,10)
            return write(o,2400,1)
        store(o,BUF,58)
        store(o,BUF+1,32)
        return write(o,2320,2)
    return native_fail(o,107)

def native_write(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        return system(o,11,1,12,2,BUF+get(o,WRITTEN),get(o,USED)-get(o,WRITTEN),0,0,0)
    n=get(o,FEEDBACK)
    if n==MAX-3:
        return again(o,10)
    if n==0 or n>=NEGATIVE or n>get(o,USED)-get(o,WRITTEN):
        return native_fail(o,107)
    put(o,WRITTEN,get(o,WRITTEN)+n)
    if get(o,WRITTEN)<get(o,USED):
        return again(o,10)
    return again(o,get(o,NEXT))

def native_cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2400:
        zero(o,STR,24)
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,2401,0,0)
        put(o,N_INDEX,0)
        return again(o,2410)
    if phase==2401:
        return system(o,2402,202,1,44,129,2147483647,0,0,0)
    if phase==2402:
        put(o,N_INDEX,0)
        return again(o,2410)
    if phase==2410:
        if get(o,M_UNKNOWN)!=0:
            return again(o,2980)
        index=get(o,N_INDEX)
        if index==10:
            return native_snapshot(o,2420)
        put(o,N_INDEX,index+1)
        at=N_NAME+index*24
        if get(o,at)==0:
            return again(o,2410)
        return native_drop(o,w,at,2410)
    if phase==2420:
        native_guard_packet(o,2)
        return native_guard_call(o,w,2421)
    if phase==2421:
        if native_guard_record(o,2)==False or get(o,N_GOUT+56)!=1:
            put(o,M_UNKNOWN,1)
            return finish(o,107)
        zero(o,N_GCAP,24)
        put(o,N_PTR,0)
        if get(o,N_GOUT+8)!=0:
            put(o,ERROR,107)
        return finish(o,get(o,ERROR))
    if phase==2900:
        if native_guard_record(o,1)==False or get(o,N_GOUT+56)!=1:
            return native_unknown(o)
        zero(o,get(o,N_DROP),24)
        if get(o,N_GOUT+8)!=0:
            put(o,ERROR,107)
        return native_snapshot(o,get(o,N_RESUME))
    if phase==2980:
        zero(o,STR,24)
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,2981,0,0)
        return again(o,2982)
    if phase==2981:
        return system(o,2982,202,1,44,129,2147483647,0,0,0)
    if phase==2982:
        if get(o,N_PTR)==0:
            return finish(o,107)
        put(o,N_CHAR,1)
        return native_memory(o,2983,3,N_CHAR,0,get(o,N_PTR)+112,8)
    if phase==2983:
        return native_memory(o,2984,3,N_CHAR,0,get(o,N_PTR)+72,8)
    if phase==2984:
        return finish(o,107)
    return finish(o,107)

def native_take(o:mutbuf,at:u64,next:u64) -> u32:
    if native_ok(o)==False:
        return native_value_failed(o)
    if get(o,VP+24)==0 or get(o,at)!=0:
        return native_unknown(o)
    within(o,at,VP+24,24)
    return native_snapshot(o,next)

def native_snapshot(o:mutbuf,next:u64) -> u32:
    zero(o,N_SHADOW,512)
    i=0
    count=0
    while i<10:
        at=N_NAME+i*24
        if get(o,at)!=0:
            if count>=8:
                return native_unknown(o)
            put(o,N_SHADOW+count*32,2)
            within(o,N_SHADOW+count*32+8,at,24)
            count=count+1
        i=i+1
    return native_memory(o,next,3,N_SHADOW,0,get(o,N_PTR)+1152,512)

def native_drop(o:mutbuf,w:mutbuf,at:u64,next:u64) -> u32:
    if get(o,at)==0:
        return again(o,next)
    put(o,N_DROP,at)
    put(o,N_RESUME,next)
    native_guard_packet(o,1)
    put(o,N_GREQ+64,2)
    within(o,N_GREQ+72,at,24)
    return native_guard_call(o,w,2900)

def native_guard_packet(o:mutbuf,op:u64) -> u64:
    zero(o,N_GREQ,192)
    put(o,N_GREQ,N_GMAGIC)
    put(o,N_GREQ+8,op)
    if op!=0:
        within(o,N_GREQ+40,N_GCAP,24)
    return 0

def native_guard_call(o:mutbuf,w:mutbuf,next:u64) -> u32:
    zero(o,N_GOUT,128)
    return invoke(o,next,get(w,216),N_GREQ,192,N_GOUT,128,get(w,208),256)

def native_packet(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,256)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    put(o,VIN,128)
    return 0

def native_text(o:mutbuf,w:mutbuf,index:u64,next:u64) -> u32:
    native_packet(o,VREQUEST,2)
    put(o,RQ+104,4)
    n=native_literal(o,RQ+128,index)
    put(o,RQ+96,n)
    put(o,VIN,128+n)
    return value(o,w,next)

def native_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0

def native_value_failed(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY or get(o,VP+8)==11:
        return native_unknown(o)
    return native_fail(o,choose(get(o,VP+8)==5,103,107))

def native_unknown(o:mutbuf) -> u32:
    put(o,M_UNKNOWN,1)
    put(o,ERROR,107)
    return again(o,2400)

def native_fail(o:mutbuf,kind:u64) -> u32:
    put(o,ERROR,kind)
    return again(o,2400)

def native_memory(o:mutbuf,next:u64,source:u64,source_at:u64,target:u64,target_at:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,source)
    put(o,8,source_at)
    put(o,16,target)
    put(o,24,target_at)
    put(o,32,n)
    return 8

def native_global_atom(o:mutbuf,action:u64,next:u64,expected:u64,value:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,expected)
    put(o,16,value)
    return action

def native_guard_record(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,N_GOUT)!=choose(get(o,M_DEFER)!=0,N_GREPLY,N_GREPLY):
        return False
    status=get(o,N_GOUT+8)
    pending=get(o,N_GOUT+40)
    known=get(o,N_GOUT+48)
    taken=get(o,N_GOUT+56)
    raw=get(o,N_GOUT+64)
    if status!=0 and status!=1 and status!=4 and status!=5 and status!=9:
        return False
    if pending>1 or known>1 or taken>1:
        return False
    if known==0 and status!=9:
        return False
    if raw!=0 and raw!=1 and raw!=5 and raw!=6 and raw!=9 and raw!=11:
        return False
    if taken==1 and status!=0 and status!=9:
        return False
    at=88
    if get(o,M_DEFER)!=0:
        if get(o,N_GOUT+88)>1 or get(o,N_GOUT+96)>1:
            put(o,M_UNKNOWN,1)
            return False
        if get(o,N_GOUT+88)!=0:
            put(o,M_QUEUE,1)
        if get(o,N_GOUT+96)!=0:
            put(o,M_UNMAP,1)
        at=104
    while at<128:
        if get(o,N_GOUT+at)!=0:
            return False
        at=at+8
    if op==0:
        if known!=1 or taken!=0 or raw!=0:
            return False
        if status==0:
            ptr=get(o,N_GOUT+16)
            return ptr!=0 and ptr<=MAX-(128+96*16) and pending==1 and get(o,N_GOUT+72)==128+96*16 and get(o,N_GOUT+80)==16
    else:
        if get(o,N_GOUT+72)!=0 or get(o,N_GOUT+80)!=0:
            return False
        if status==0 and (known!=1 or raw!=0):
            return False
        if op==3 and taken!=0:
            return False
        if (op==1 or op==2) and status==0 and taken!=1:
            return False
        if op==1 and status==0 and pending!=1:
            return False
    return get(o,N_GOUT+16)==0 and get(o,N_GOUT+24)==0 and get(o,N_GOUT+32)==0 and get(o,N_GOUT+72)==0 and get(o,N_GOUT+80)==0

def native_literal(o:mutbuf,at:u64,index:u64) -> u64:
    if index==0:
        store(o,at+0,95)
        store(o,at+1,95)
        store(o,at+2,115)
        store(o,at+3,116)
        store(o,at+4,114)
        store(o,at+5,95)
        store(o,at+6,95)
        return 7
    if index==1:
        store(o,at+0,60)
        store(o,at+1,101)
        store(o,at+2,120)
        store(o,at+3,99)
        store(o,at+4,101)
        store(o,at+5,112)
        store(o,at+6,116)
        store(o,at+7,105)
        store(o,at+8,111)
        store(o,at+9,110)
        store(o,at+10,32)
        store(o,at+11,115)
        store(o,at+12,116)
        store(o,at+13,114)
        store(o,at+14,40)
        store(o,at+15,41)
        store(o,at+16,32)
        store(o,at+17,102)
        store(o,at+18,97)
        store(o,at+19,105)
        store(o,at+20,108)
        store(o,at+21,101)
        store(o,at+22,100)
        store(o,at+23,62)
        return 24
    if index==2:
        store(o,at+0,78)
        store(o,at+1,111)
        store(o,at+2,110)
        store(o,at+3,101)
        return 4
    if index==3:
        store(o,at+0,84)
        store(o,at+1,114)
        store(o,at+2,117)
        store(o,at+3,101)
        return 4
    if index==4:
        store(o,at+0,70)
        store(o,at+1,97)
        store(o,at+2,108)
        store(o,at+3,115)
        store(o,at+4,101)
        return 5
    if index==5:
        return 0
    if index==6:
        store(o,at+0,110)
        store(o,at+1,97)
        store(o,at+2,110)
        return 3
    if index==7:
        store(o,at+0,105)
        store(o,at+1,110)
        store(o,at+2,102)
        return 3
    if index==8:
        store(o,at+0,45)
        store(o,at+1,105)
        store(o,at+2,110)
        store(o,at+3,102)
        return 4
    return 0
'''
