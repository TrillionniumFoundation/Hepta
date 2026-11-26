"""Actual native log data transport, dynamic codec buffers and real row updates."""
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase>=2300:
        return log_transport(o,w,phase)
    if phase==2000:
        if get(w,L_MODE)==1:
            at=P_CAPTURE_OUT+get(w,P_CAP_INDEX)*256
            l_field(w,2,0,get(w,at+72),get(w,at+80))
            l_field(w,3,0,get(w,at+88),get(w,at+96))
            put(w,L_HEADER+48,get(w,at+56))
            put(w,L_HEADER+56,get(w,at+64))
            put(w,L_HEADER+64,get(w,at+24))
            put(w,L_HEADER+72,get(w,at+32))
            put(w,L_HEADER+112,6)
            return jump(w,2300)
        if get(w,L_MODE)!=0:
            return l_unknown(w,2000)
        clear(w,L_CWD_WORK,200704)
        clear(w,L_RQ,32)
        clear(w,L_VR,128)
        put(w,L_RQ,L_CWD_REQUEST)
        put(w,L_CWD_ACTIVE,1)
        return p_invoke(w,2001,R_LOG_CWD,p_at(w,L_RQ),32,p_at(w,L_VR),128,p_at(w,L_CWD_WORK),200704)
    if phase==2001:
        if r!=0 or get(w,L_VR)!=L_CWD_REPLY:
            return l_unknown(w,2001)
        if get(w,L_VR+72)!=0:
            return l_unknown(w,2002)
        if get(w,L_VR+56)==0:
            put(w,L_CWD_ACTIVE,0)
        if get(w,L_VR+32)!=NONE:
            put(w,L_FD,get(w,L_VR+32))
            put(w,L_FD_HELD,1)
            put(w,L_CWD_N,get(w,L_VR+40))
        if get(w,L_VR+8)!=0:
            return l_fail(w,E_OS,errno(get(w,L_VR+16)))
        if get(w,L_CWD_ACTIVE)!=0 or get(w,L_FD_HELD)!=1 or get(w,L_VR+48)!=15 or get(w,L_CWD_N)==0:
            return l_unknown(w,2003)
        l_field(w,0,0,get(w,P_FRAME),get(w,L_FRAME_N))
        l_field(w,1,2,get(w,L_FD),get(w,L_CWD_N))
        return jump(w,2300)
    return 4294967293

def log_transport(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(w,RESULT)
    if phase==2300:
        total=128
        i=0
        while i<8:
            n=get(w,L_FIELDS+i*32+8)
            if n>9223372036854771584-total:
                return l_fail(w,E_MEMORY,12)
            total=total+n
            i=i+1
        put(w,L_INPUT_N,total)
        return l_newmap(o,w,2301,total)
    if phase==2301:
        if l_keepmap(w,L_IN)==False:
            return l_fail(w,E_MEMORY,errno(r))
        return p_copy(w,2302,p_at(w,L_HEADER),get(w,L_IN),128)
    if phase==2302:
        if r!=0:
            return l_unknown(w,2302)
        put(w,L_INDEX,0)
        put(w,L_OFFSET,128)
        return jump(w,2310)
    if phase==2310:
        index=get(w,L_INDEX)
        if index==8:
            clear(w,L_CODEC_WORK,128)
            return p_invoke(w,2330,R_LOG_CODEC,get(w,L_IN),get(w,L_INPUT_N),p_at(w,L_VR),0,p_at(w,L_CODEC_WORK),128)
        field=L_FIELDS+index*32
        n=get(w,field+8)
        if n==0:
            put(w,L_INDEX,index+1)
            return jump(w,2310)
        kind=get(w,field+16)
        to=get(w,L_IN)+get(w,L_OFFSET)
        if kind==1:
            return l_read(w,get(w,field),n,to,2324)
        if kind==2:
            put(w,L_READ_N,n)
            put(w,L_READ_TO,to)
            put(w,L_READ_OFFSET,0)
            return jump(w,2320)
        if kind!=0 or get(w,field)==0:
            return l_unknown(w,2310)
        return p_copy(w,2324,get(w,field),to,n)
    if phase==2320:
        remaining=get(w,L_READ_N)-get(w,L_READ_OFFSET)
        if remaining==0:
            put(w,RESULT,0)
            return jump(w,2324)
        amount=choose(remaining>65536,65536,remaining)
        put(w,L_AMOUNT,amount)
        return call(o,w,2321,17,get(w,L_FD),get(w,L_READ_TO)+get(w,L_READ_OFFSET),amount,get(w,L_READ_OFFSET),0,0,0)
    if phase==2321:
        if r==NONE-3:
            return jump(w,2320)
        if failed(r):
            return l_fail(w,E_OS,errno(r))
        if r==0 or r>get(w,L_AMOUNT):
            return l_fail(w,E_OS,5)
        put(w,L_READ_OFFSET,get(w,L_READ_OFFSET)+r)
        return jump(w,2320)
    if phase==2324:
        if r!=0:
            return l_unknown(w,2324)
        index=get(w,L_INDEX)
        put(w,L_OFFSET,get(w,L_OFFSET)+get(w,L_FIELDS+index*32+8))
        put(w,L_INDEX,index+1)
        return jump(w,2310)
    if phase==2330:
        if r!=4294967294 or get(w,L_CODEC_WORK)==0 or get(w,L_CODEC_WORK)>=4294967292:
            return l_unknown(w,2330)
        put(w,L_JSON_N,get(w,L_CODEC_WORK))
        return l_newmap(o,w,2331,get(w,L_JSON_N)+128)
    if phase==2331:
        if l_keepmap(w,L_JSON)==False:
            return l_fail(w,E_MEMORY,errno(r))
        return p_invoke(w,2332,R_LOG_CODEC,get(w,L_IN),get(w,L_INPUT_N),get(w,L_JSON)+128,get(w,L_JSON+8)-128,p_at(w,L_CODEC_WORK),128)
    if phase==2332:
        if r!=get(w,L_JSON_N):
            return l_unknown(w,2332)
        clear(w,L_RQ,128)
        put(w,L_RQ,L_LOG_REQUEST)
        put(w,L_RQ+8,choose(get(w,L_MODE)==0,0,1))
        put(w,L_RQ+96,get(w,L_JSON_N))
        return p_copy(w,2333,p_at(w,L_RQ),get(w,L_JSON),128)
    if phase==2333:
        if r!=0:
            return l_unknown(w,2333)
        clear(w,L_VR,128)
        return p_invoke(w,2334,R_LOG_OWNER,get(w,L_JSON),get(w,L_JSON_N)+128,p_at(w,L_VR),128,p_at(w,L_LOG_WORK),65536)
    if phase==2334:
        if r!=0 or get(w,L_VR)!=L_LOG_REPLY or get(w,L_VR+88)!=1 or get(w,L_VR+72)!=0:
            return l_unknown(w,2334)
        put(w,L_LOG_STATUS,get(w,L_VR+8))
        put(w,L_LOG_DETAIL,get(w,L_VR+16))
        put(w,L_LOG_PRIMARY,get(w,L_VR+40))
        put(w,L_QUEUE,get(w,L_QUEUE)|get(w,L_VR+112))
        if get(w,L_VR+8)!=0:
            if get(w,L_VR+8)==5 and (get(w,L_VR+16)==5 or get(w,L_VR+16)==12):
                return l_fail(w,E_MEMORY,12)
            return l_fail(w,E_CONTEXT,2334)
        if get(w,L_VR+40)!=1 or get(w,L_VR+48)!=1 or get(w,L_VR+56)!=choose(get(w,L_MODE)==0,1,0) or get(w,L_VR+64)!=0 or get(w,L_VR+104)!=0:
            return l_fail(w,E_CLEANUP,2334)
        put(w,L_CLEAN_INDEX,32)
        return jump(w,2500)
    if phase==2400:
        offset=get(w,L_READ_OFFSET)
        if offset==get(w,L_READ_N):
            put(w,RESULT,0)
            return jump(w,get(w,L_READ_NEXT))
        amount=get(w,L_READ_N)-offset
        if amount>8192:
            amount=8192
        put(w,L_AMOUNT,amount)
        l_request(w,L_Q6,19)
        l_arg(w,24,get(w,L_READ_SLOT))
        put(w,L_RQ+104,offset)
        put(w,L_RQ+112,amount)
        return l_value(w,2401,128)
    if phase==2401:
        if l_ordinary(w)==False or get(w,L_VR+64)!=get(w,L_AMOUNT):
            return l_value_failed(w,2401)
        return p_copy(w,2402,p_at(w,L_VR+8192),get(w,L_READ_TO)+get(w,L_READ_OFFSET),get(w,L_AMOUNT))
    if phase==2402:
        if r!=0:
            return l_unknown(w,2402)
        put(w,L_READ_OFFSET,get(w,L_READ_OFFSET)+get(w,L_AMOUNT))
        return jump(w,2400)
    return 4294967293
'''
if __name__=='__main__':write_module('clang_origin_log_hooks',SOURCE)
