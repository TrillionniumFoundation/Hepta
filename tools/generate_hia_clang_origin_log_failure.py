"""Actual exception fields and native MemoryError replacement before Clang cleanup."""
from tools.generate_hia_clang_origin_log_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase>=2700:
        return memory_error(o,w,phase)
    if phase>=2600:
        return os_format(o,w,phase)
    if phase>=2250:
        return field_sizes(w,phase)
    if phase>=2200:
        return integer_field(w,phase)
    if phase>=2130:
        return capture_fields(w,phase)
    return exception_fields(w,phase)

def exception_fields(w:mutbuf,phase:u64) -> u32:
    if phase==2100:
        clear(w,L_RQ,64)
        clear(w,L_VR,128)
        put(w,L_RQ,L_EARLY_REQUEST)
        return p_invoke(w,2101,R_LOG_EARLY,p_at(w,L_RQ),64,p_at(w,L_VR),128,0,0)
    if phase==2101:
        if get(w,RESULT)!=0 or get(w,L_VR)!=L_EARLY_REPLY or get(w,L_VR+88)!=1 or get(w,L_VR+24)==0 or get(w,L_VR+32)==0 or get(w,L_VR+40)==0:
            return l_unknown(w,2101)
        put(w,L_OS_FIELDS,get(w,L_VR+24))
        put(w,L_OS_FIELDS+8,get(w,L_VR+32))
        put(w,L_OS_FIELDS+16,get(w,L_VR+40))
        l_request(w,L_Q5,91)
        p_saved_copy(w,L_OS_FIELDS,L_RQ+24,24)
        return l_value(w,2102,128)
    if phase==2102:
        if l_hold(w,0)==False:
            return l_value_failed(w,2102)
        return l_query(w,2103,L_Q6,26,0)
    if phase==2103:
        if l_valid(w,L_V1)==False:
            return l_unknown(w,2103)
        i=0
        while i<3:
            at=L_VR+8224+i*24
            if get(w,at)!=0:
                if l_hold_at(w,3+i,at)==False:
                    return l_unknown(w,2103)
            i=i+1
        if get(w,L_VR+8)!=0 or get(w,L_REFS+3*32+24)!=1 or get(w,L_REFS+4*32+24)!=1 or get(w,L_REFS+5*32+24)!=1:
            return l_value_failed(w,2103)
        return l_query(w,2104,L_Q6,36,0)
    if phase==2104:
        if l_hold(w,1)==False:
            return l_value_failed(w,2104)
        return l_query(w,2105,L_Q6,38,1)
    if phase==2105:
        if l_hold(w,2)==False:
            return l_value_failed(w,2105)
        l_field(w,4,1,2,0)
        l_request(w,L_Q11,105)
        l_arg(w,24,0)
        return l_value(w,2106,128)
    if phase==2106:
        if l_valid(w,L_V1) and get(w,L_VR+8)==2 and get(w,L_VR+24)==0:
            return jump(w,2120)
        if l_hold(w,6)==False:
            return l_value_failed(w,2106)
        return l_query(w,2107,L_Q6,7,6)
    if phase==2107:
        if l_ordinary(w)==False:
            return l_value_failed(w,2107)
        kind=get(w,L_VR+16)
        if kind==0:
            return jump(w,2120)
        if kind!=2:
            return l_unknown(w,2107)
        put(w,L_OS_INDEX,1)
        return jump(w,2108)
    if phase==2108:
        index=get(w,L_OS_INDEX)
        if index==4:
            put(w,L_OS_INDEX,0)
            clear(w,L_OS_HEADER,64)
            clear(w,L_OS_FIELDS,128)
            put(w,L_OS_HEADER,L_OS_REQUEST)
            return jump(w,2600)
        l_request(w,L_Q11,105)
        l_arg(w,24,0)
        put(w,L_RQ+104,index)
        return l_value(w,2109,128)
    if phase==2109:
        index=get(w,L_OS_INDEX)
        if l_hold(w,6+index)==False:
            return l_value_failed(w,2109)
        put(w,L_OS_INDEX,index+1)
        return jump(w,2108)
    if phase==2120:
        return l_query(w,2121,L_Q6,7,4)
    if phase==2121:
        if l_ordinary(w)==False or get(w,L_VR+16)!=11:
            return l_value_failed(w,2121)
        n=get(w,L_VR+48)
        if n==0:
            l_field(w,5,0,0,0)
            put(w,L_INDEX,0)
            return jump(w,2130)
        if n!=1:
            return l_fail(w,E_CONTEXT,2121)
        l_request(w,L_Q6,2)
        put(w,L_RQ+96,1)
        put(w,L_RQ+104,2)
        store(w,L_RQ+128,48)
        return l_value(w,2122,129)
    if phase==2122:
        if l_hold(w,27)==False:
            return l_value_failed(w,2122)
        l_request(w,L_Q7,12)
        l_arg(w,24,4)
        l_arg(w,48,27)
        return l_value(w,2123,128)
    if phase==2123:
        if l_hold(w,20)==False:
            return l_value_failed(w,2123)
        l_field(w,5,1,20,0)
        put(w,L_INDEX,0)
        return jump(w,2130)
    return 4294967293

def capture_key(w:mutbuf,index:u64) -> u64:
    if index==0:
        put(w,L_RQ+128,1701080931)
        return 4
    if index==1:
        put(w,L_RQ+128,28554821438038371)
        return 7
    put(w,L_RQ+128,6874026255041192291)
    put(w,L_RQ+136,491496043109)
    return 13

def capture_fields(w:mutbuf,phase:u64) -> u32:
    if phase==2130:
        index=get(w,L_INDEX)
        if index==3:
            put(w,L_INDEX,0)
            return jump(w,2250)
        l_request(w,L_Q6,2)
        n=capture_key(w,index)
        put(w,L_RQ+96,n)
        put(w,L_RQ+104,4)
        return l_value(w,2131,128+n)
    if phase==2131:
        index=get(w,L_INDEX)
        if l_hold(w,24+index)==False:
            return l_value_failed(w,2131)
        l_request(w,L_Q6,9)
        l_arg(w,24,3)
        l_arg(w,48,24+index)
        return l_value(w,2132,128)
    if phase==2132:
        index=get(w,L_INDEX)
        if l_valid(w,L_V1) and get(w,L_VR+8)==3 and get(w,L_VR+24)==0:
            put(w,L_INDEX,index+1)
            return jump(w,2130)
        if l_hold(w,10+index)==False:
            return l_value_failed(w,2132)
        return l_query(w,2133,L_Q6,7,10+index)
    if phase==2133:
        if l_ordinary(w)==False:
            return l_value_failed(w,2133)
        index=get(w,L_INDEX)
        kind=get(w,L_VR+16)
        if kind==0:
            put(w,L_INDEX,index+1)
            return jump(w,2130)
        if index!=1:
            if kind!=4:
                return l_fail(w,E_CONTEXT,2133)
            l_field(w,choose(index==0,6,7),1,10+index,get(w,L_VR+72))
            put(w,L_HEADER+112,get(w,L_HEADER+112)|choose(index==0,8,16))
            put(w,L_INDEX,index+1)
            return jump(w,2130)
        if kind!=12:
            return l_fail(w,E_CONTEXT,2134)
        l_request(w,L_Q11,101)
        put(w,L_RQ+104,53)
        return l_value(w,2140,128)
    if phase==2140:
        if l_hold(w,21)==False:
            return l_value_failed(w,2140)
        l_request(w,L_Q6,37)
        l_arg(w,24,11)
        l_arg(w,48,21)
        return l_value(w,2141,128)
    if phase==2141:
        if l_ordinary(w)==False or get(w,L_VR+48)!=1:
            return l_value_failed(w,2141)
        put(w,L_OS_INDEX,1)
        return jump(w,2142)
    if phase==2142:
        index=get(w,L_OS_INDEX)
        if index==6:
            put(w,L_HEADER+112,get(w,L_HEADER+112)|1)
            l_field(w,2,1,14,0)
            l_field(w,3,1,15,0)
            return l_integer(w,13,L_HEADER+72,2150,1)
        l_request(w,L_Q11,43)
        l_arg(w,24,11)
        put(w,L_RQ+104,index)
        return l_value(w,2143,128)
    if phase==2143:
        index=get(w,L_OS_INDEX)
        if l_hold(w,12+index)==False:
            return l_value_failed(w,2143)
        put(w,L_OS_INDEX,index+1)
        return jump(w,2142)
    if phase==2150:
        return l_integer(w,16,L_HEADER+48,2151,0)
    if phase==2151:
        return l_integer(w,17,L_HEADER+56,2152,0)
    if phase==2152:
        put(w,L_INDEX,2)
        return jump(w,2130)
    return 4294967293

def integer_field(w:mutbuf,phase:u64) -> u32:
    if phase==2200:
        if l_ordinary(w)==False:
            return l_value_failed(w,2200)
        if get(w,L_VR+16)==0 and get(w,L_INT_SIGN)==1:
            put(w,get(w,L_INT_TO),0)
            put(w,L_HEADER+64,0)
            return jump(w,get(w,L_INT_NEXT))
        if get(w,L_VR+16)!=2 or get(w,L_VR+72)==0 or get(w,L_VR+72)>20:
            return l_fail(w,E_CONTEXT,2200)
        put(w,L_AMOUNT,get(w,L_VR+72))
        l_request(w,L_Q6,19)
        l_arg(w,24,get(w,L_INT_SLOT))
        put(w,L_RQ+112,get(w,L_AMOUNT))
        return l_value(w,2201,128)
    if phase==2201:
        if l_ordinary(w)==False or get(w,L_VR+64)!=get(w,L_AMOUNT):
            return l_value_failed(w,2201)
        n=get(w,L_AMOUNT)
        negative=byte(w,L_VR+8192)==45
        at=0
        if negative:
            if get(w,L_INT_SIGN)==0:
                return l_fail(w,E_CONTEXT,2201)
            at=1
        if at==n:
            return l_unknown(w,2201)
        value=0
        while at<n:
            ch=byte(w,L_VR+8192+at)
            if ch<48 or ch>57 or value>(NONE-(ch-48))//10:
                return l_fail(w,E_CONTEXT,2201)
            value=value*10+ch-48
            at=at+1
        if get(w,L_INT_SIGN)==1:
            if value>choose(negative,9223372036854775808,9223372036854775807):
                return l_fail(w,E_CONTEXT,2201)
            put(w,L_HEADER+64,1)
        if negative:
            value=0-value
        put(w,get(w,L_INT_TO),value)
        return jump(w,get(w,L_INT_NEXT))
    return 4294967293

def field_sizes(w:mutbuf,phase:u64) -> u32:
    if phase==2250:
        index=get(w,L_INDEX)
        while index<8:
            if get(w,L_FIELDS+index*32+16)==1:
                put(w,L_INDEX,index)
                return l_query(w,2251,L_Q6,7,get(w,L_FIELDS+index*32))
            index=index+1
        return jump(w,2300)
    if phase==2251:
        index=get(w,L_INDEX)
        if l_ordinary(w)==False:
            return l_value_failed(w,2251)
        expected=choose(index==2 or index==3,7,4)
        if get(w,L_VR+16)!=expected:
            return l_fail(w,E_CONTEXT,2251)
        l_field(w,index,1,get(w,L_FIELDS+index*32),get(w,L_VR+72))
        put(w,L_INDEX,index+1)
        return jump(w,2250)
    return 4294967293

def os_format(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(w,RESULT)
    if phase==2600:
        index=get(w,L_OS_INDEX)
        if index==4:
            total=64+get(w,L_OS_FIELDS+8)+get(w,L_OS_FIELDS+40)
            i=2
            while i<4:
                n=get(w,L_OS_FIELDS+i*32+8)
                if n>922337203685477000 or total>9223372036854771584-10*n-32:
                    return l_fail(w,E_MEMORY,12)
                total=total+10*n+32
                i=i+1
            return l_newmap(o,w,2602,total)
        return l_query(w,2601,L_Q6,7,6+index)
    if phase==2601:
        if l_ordinary(w)==False:
            return l_value_failed(w,2601)
        index=get(w,L_OS_INDEX)
        kind=get(w,L_VR+16)
        n=get(w,L_VR+72)
        if index==0 and kind!=2:
            return l_fail(w,E_CONTEXT,2601)
        if index==1 and kind==0:
            return jump(w,2120)
        if index==1 and kind!=4:
            return l_fail(w,E_CONTEXT,2601)
        if index>=2 and kind!=0 and kind!=4 and kind!=7:
            return l_fail(w,E_CONTEXT,2601)
        put(w,L_OS_FIELDS+index*32,kind)
        put(w,L_OS_FIELDS+index*32+8,choose(kind==0,0,n))
        put(w,L_OS_INDEX,index+1)
        return jump(w,2600)
    if phase==2602:
        if l_keepmap(w,L_TEXT)==False:
            return l_fail(w,E_MEMORY,errno(r))
        put(w,L_OS_INDEX,0)
        put(w,L_OS_OFFSET,64)
        return jump(w,2603)
    if phase==2603:
        index=get(w,L_OS_INDEX)
        if index==2:
            put(w,L_OS_FLAGS,0)
            return jump(w,2610)
        n=get(w,L_OS_FIELDS+index*32+8)
        return l_read(w,6+index,n,get(w,L_TEXT)+get(w,L_OS_OFFSET),2604)
    if phase==2604:
        index=get(w,L_OS_INDEX)
        n=get(w,L_OS_FIELDS+index*32+8)
        put(w,L_OS_HEADER+16+index*8,n)
        put(w,L_OS_OFFSET,get(w,L_OS_OFFSET)+n)
        put(w,L_OS_INDEX,index+1)
        return jump(w,2603)
    if phase==2610:
        index=get(w,L_OS_INDEX)
        if index==4:
            put(w,L_OS_HEADER+8,get(w,L_OS_FLAGS))
            return p_copy(w,2630,p_at(w,L_OS_HEADER),get(w,L_TEXT),64)
        kind=get(w,L_OS_FIELDS+index*32)
        if kind==0 or index==3 and (get(w,L_OS_FLAGS)&1)==0:
            put(w,L_OS_HEADER+16+index*8,0)
            put(w,L_OS_INDEX,index+1)
            return jump(w,2610)
        put(w,L_OS_FLAGS,get(w,L_OS_FLAGS)|(1<<(index-2)))
        n=get(w,L_OS_FIELDS+index*32+8)
        return l_newmap(o,w,2611,16+n)
    if phase==2611:
        if l_keepmap(w,L_REPR)==False:
            return l_fail(w,E_MEMORY,errno(r))
        index=get(w,L_OS_INDEX)
        clear(w,L_RQ,16)
        put(w,L_RQ,L_REPR_REQUEST)
        put(w,L_RQ+8,choose(get(w,L_OS_FIELDS+index*32)==7,1,0))
        return p_copy(w,2612,p_at(w,L_RQ),get(w,L_REPR),16)
    if phase==2612:
        if r!=0:
            return l_unknown(w,2612)
        index=get(w,L_OS_INDEX)
        return l_read(w,6+index,get(w,L_OS_FIELDS+index*32+8),get(w,L_REPR)+16,2613)
    if phase==2613:
        n=get(w,L_OS_FIELDS+get(w,L_OS_INDEX)*32+8)
        return p_invoke(w,2614,R_LOG_REPR,get(w,L_REPR),16+n,get(w,L_TEXT)+get(w,L_OS_OFFSET),get(w,L_TEXT+8)-get(w,L_OS_OFFSET),p_at(w,L_REPR_WORK),8192)
    if phase==2614:
        if r>=4294967292 or r>get(w,L_TEXT+8)-get(w,L_OS_OFFSET):
            return l_unknown(w,2614)
        index=get(w,L_OS_INDEX)
        put(w,L_OS_HEADER+16+index*8,r)
        put(w,L_OS_OFFSET,get(w,L_OS_OFFSET)+r)
        return call(o,w,2615,11,get(w,L_REPR),get(w,L_REPR+8),0,0,0,0,0)
    if phase==2615:
        if r!=0:
            return l_fail(w,E_CLEANUP,errno(r))
        put(w,L_REPR,0)
        put(w,L_REPR+8,0)
        put(w,L_OS_INDEX,get(w,L_OS_INDEX)+1)
        return jump(w,2610)
    if phase==2630:
        if r!=0:
            return l_unknown(w,2630)
        clear(w,L_CODEC_WORK,128)
        return p_invoke(w,2631,R_LOG_CODEC,get(w,L_TEXT),get(w,L_OS_OFFSET),p_at(w,L_VR),0,p_at(w,L_CODEC_WORK),128)
    if phase==2631:
        if r!=4294967294 or get(w,L_CODEC_WORK)==0 or get(w,L_CODEC_WORK)>=4294967292:
            return l_unknown(w,2631)
        put(w,L_FAILURE_CONTEXT,get(w,L_CODEC_WORK))
        return l_newmap(o,w,2632,get(w,L_FAILURE_CONTEXT))
    if phase==2632:
        if l_keepmap(w,L_TEXT_OUT)==False:
            return l_fail(w,E_MEMORY,errno(r))
        return p_invoke(w,2633,R_LOG_CODEC,get(w,L_TEXT),get(w,L_OS_OFFSET),get(w,L_TEXT_OUT),get(w,L_TEXT_OUT+8),p_at(w,L_CODEC_WORK),128)
    if phase==2633:
        if r!=get(w,L_FAILURE_CONTEXT):
            return l_unknown(w,2633)
        l_field(w,5,0,get(w,L_TEXT_OUT),r)
        put(w,L_INDEX,0)
        return jump(w,2130)
    return 4294967293

def memory_error(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2700:
        l_request(w,L_Q11,32)
        put(w,L_RQ+104,27)
        return l_value(w,2701,128)
    if phase==2701:
        if l_hold(w,28)==False:
            return l_value_failed(w,2701)
        l_request(w,L_Q7,3)
        return l_value(w,2702,128)
    if phase==2702:
        if l_hold(w,29)==False:
            return l_value_failed(w,2702)
        return l_query(w,2703,L_Q11,40,29)
    if phase==2703:
        if l_hold(w,30)==False:
            return l_value_failed(w,2703)
        l_request(w,L_Q11,75)
        l_arg(w,24,28)
        l_arg(w,48,30)
        return l_value(w,2704,128)
    if phase==2704:
        if l_hold(w,31)==False:
            return l_value_failed(w,2704)
        clear(w,L_RQ,64)
        clear(w,L_VR,128)
        put(w,L_RQ,L_EXCEPTION_REQUEST)
        l_arg(w,24,31)
        return p_invoke(w,2705,R_LOG_EXCEPTION,p_at(w,L_RQ),64,p_at(w,L_VR),128,0,0)
    if phase==2705:
        if get(w,RESULT)!=0 or get(w,L_VR)!=L_EXCEPTION_REPLY or get(w,L_VR+88)>1 or get(w,L_VR+96)>1:
            return l_unknown(w,2705)
        put(w,L_REPLACED,get(w,L_VR+96))
        put(w,L_REPLACEMENT_PENDING,get(w,L_VR+80))
        put(w,L_REPLACEMENT_CLEAN,get(w,L_VR+104))
        put(w,L_REPLACEMENT_ERRNO,get(w,L_VR+112))
        if get(w,L_VR+88)!=1:
            return l_unknown(w,2705)
        if get(w,L_VR+96)!=1 or get(w,L_VR+24)==0 or get(w,L_VR+32)==0 or get(w,L_VR+40)==0:
            return l_fail(w,E_CONTEXT,2705)
        if get(w,L_VR+104)!=0:
            put(w,P_CLEAN_ERROR,E_CLEANUP)
            put(w,P_CLEAN_ERRNO,get(w,L_VR+112))
        put(w,L_CLEAN_INDEX,32)
        return jump(w,2500)
    return 4294967293
'''
if __name__=='__main__':write_module('clang_origin_log_failure',SOURCE)
