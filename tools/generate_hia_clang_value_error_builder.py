"""Build real Value graphs from a private HIA-generated exception recipe."""
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==1600:
        return row(o,w)
    if phase==1601:
        return value_done(w)
    if phase==1602 or phase==1603:
        return dropped(w,phase)
    if phase>=1610 and phase<=1643:
        return scalar(o,w,phase)
    if phase==1660:
        return inspected(w)
    return 4294967293

def row(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,E_PLAN_INDEX)
    if get(w,E_BAD)!=0 or get(w,E_PLAN_COUNT)>E_PLAN_CAP or at>get(w,E_PLAN_COUNT):
        return a_unknown(w,1600)
    if at==get(w,E_PLAN_COUNT):
        return jump(w,700)
    r=E_PLAN+at*64
    op=get(w,r)
    dst=get(w,r+8)
    if dst!=NONE and (dst>=63 or get(w,A_REFS+dst*32+24)!=0):
        return a_unknown(w,1600)
    put(w,E_ROW,r)
    put(w,E_OP,op)
    put(w,E_DST,dst)
    if op==20:
        n=get(w,r+16)
        if get(w,A_XMAP)==0 or get(w,A_XCAP)<128 or n>get(w,A_XCAP)-128:
            return a_unknown(w,1600)
        put(w,E_OUT_BASE,get(w,A_XMAP))
        put(w,E_OUT_N,n)
        return string_header(w)
    if op==1 or op==14 or op==15 or op==16 or op==18:
        n=get(w,r+32)
        if op==14:
            n=get(w,r+24)
        if op==15:
            n=4096
        if n>2305843009213690000:
            return a_unknown(w,1610)
        need=256+4*n
        if op==16:
            fn=get(w,r+48)
            prefix=get(w,r+32)
            if fn>576460752303000000 or prefix>9223372036854700000-16*fn:
                return a_unknown(w,1610)
            need=16384+prefix+16*fn
        if op==18:
            count=get(w,r+24)
            at=get(w,r+16)
            if count==0 or count>8 or at<E_TEXT or at>E_TEXT+get(w,E_TEXT_N) or count*32>E_TEXT+get(w,E_TEXT_N)-at:
                return a_unknown(w,1640)
            put(w,E_SEG_AT,at)
            put(w,E_SEG_COUNT,count)
            put(w,E_SEG_INDEX,0)
            need=8192
            i=0
            while i<count:
                kind=get(w,at+i*32)
                if kind>1:
                    return a_unknown(w,1640)
                n=get(w,at+i*32+16)
                if kind==1:
                    n=4128
                if n>9223372036854700000-need:
                    return a_unknown(w,1640)
                need=need+n
                i=i+1
        if need<8192:
            need=8192
        need=(need+4095)&18446744073709547520
        put(w,E_AMOUNT,need)
        if get(w,A_XCAP)>=need and get(w,A_XMAP)!=0:
            return jump(w,1612)
        if get(w,A_XMAP)==0:
            return a_newmap(o,w,1611,need)
        return call(o,w,1611,25,get(w,A_XMAP),get(w,A_XCAP),need,1,0,0,0)
    a_request(w,A_V6,0)
    if op==2:
        put(w,A_RQ,A_V7)
        put(w,A_RQ+8,3)
    elif op==3:
        put(w,A_RQ,A_V7)
        put(w,A_RQ+8,16)
        if e_arg(w,get(w,r+16),24)==False or e_arg(w,get(w,r+24),48)==False:
            return a_unknown(w,1600)
    elif op==4:
        put(w,A_RQ,A_V4)
        put(w,A_RQ+8,40)
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1600)
    elif op==5:
        put(w,A_RQ+8,4)
    elif op==6:
        put(w,A_RQ+8,10)
        if e_arg(w,get(w,r+16),24)==False or e_arg(w,get(w,r+24),48)==False or e_arg(w,get(w,r+32),72)==False:
            return a_unknown(w,1600)
    elif op==7:
        id=get(w,r+16)
        code=32
        if id>30:
            put(w,A_RQ,A_V5)
            code=57
        if id>=38:
            code=87
        if id>=43:
            code=98
        if id>=46:
            code=99
        if id>=48:
            code=101
        if id==71 or id==72:
            code=110
        elif id==73:
            code=112
        if id==0 or id>73:
            return a_unknown(w,1600)
        put(w,A_RQ+8,code)
        put(w,A_RQ+104,id)
    elif op==8 or op==9:
        put(w,A_RQ,A_V5)
        put(w,A_RQ+8,choose(op==8,75,104))
        if e_arg(w,get(w,r+16),24)==False or e_arg(w,get(w,r+24),48)==False:
            return a_unknown(w,1600)
        if op==8 and get(w,r+32)!=NONE:
            if e_arg(w,get(w,r+32),72)==False:
                return a_unknown(w,1600)
    elif op==10:
        put(w,A_RQ,A_V5)
        cls=get(w,r+24)
        if cls!=53 and cls!=54:
            return a_unknown(w,1600)
        put(w,A_RQ+8,choose(cls==53,102,103))
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1600)
    elif op==19:
        if dst>60 or get(w,A_REFS+(dst+1)*32+24)!=0 or get(w,A_REFS+(dst+2)*32+24)!=0:
            return a_unknown(w,1660)
        put(w,A_RQ+8,26)
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1660)
        return a_value(w,1660,128)
    elif op==17:
        put(w,A_RQ,A_V5)
        put(w,A_RQ+8,108)
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1600)
        if get(w,r+24)!=NONE:
            if e_arg(w,get(w,r+24),48)==False:
                return a_unknown(w,1600)
    elif op==11:
        put(w,A_RQ,A_V5)
        put(w,A_RQ+8,106)
        put(w,A_RQ+104,get(w,r+32))
        if e_arg(w,get(w,r+16),24)==False or e_arg(w,get(w,r+24),48)==False:
            return a_unknown(w,1600)
    elif op==12:
        put(w,A_RQ,A_V5)
        put(w,A_RQ+8,78)
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1600)
        return a_value(w,1603,128)
    elif op==13:
        put(w,A_RQ,A_V5)
        put(w,A_RQ+8,91)
        if e_arg(w,get(w,r+16),24)==False:
            return a_unknown(w,1600)
    else:
        return a_unknown(w,1600)
    return a_value(w,1601,128)

def value_done(w:mutbuf) -> u32:
    if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1:
        return a_unknown(w,1601)
    op=get(w,E_OP)
    extended=op==9 or op==10 or op==11 or op==17 or op==7 and get(w,get(w,E_ROW)+16)>=48
    delivered=get(w,A_VR+24)!=0
    if extended:
        if get(w,A_VR+88)!=1 or get(w,A_VR+96)>1:
            return a_unknown(w,1601)
        delivered=get(w,A_VR+96)==1
        if delivered==False and get(w,A_VR+24)!=0:
            return a_unknown(w,1601)
    dst=get(w,E_DST)
    held=False
    if delivered:
        if dst==NONE:
            dst=63
        if a_capture(w,dst,A_VR+24)==False:
            return a_unknown(w,1601)
        held=True
    if get(w,A_VR+8)!=0 or get(w,E_DST)!=NONE and held==False:
        return a_value_failed(w,1601)
    if op==9 or op==10 or op==11 or op==17:
        if get(w,A_VR+64)!=1:
            return a_unknown(w,1601)
    if held and dst==63:
        return a_simple(w,1602,A_V5,78,63)
    return next_row(w)

def dropped(w:mutbuf,phase:u64) -> u32:
    if a_cap_drop_valid(w)==False:
        return a_unknown(w,phase)
    slot=63
    if phase==1603:
        slot=get(w,get(w,E_ROW)+16)
    if get(w,A_VR+96)==1:
        clear(w,A_REFS+slot*32,32)
    if get(w,A_VR+8)!=0 or get(w,A_VR+80)!=0 or get(w,A_VR+104)!=0 or get(w,A_VR+112)!=0:
        a_clean_error(w,16,get(w,A_VR+8))
    if get(w,A_VR+96)!=1:
        return jump(w,700)
    return next_row(w)

def next_row(w:mutbuf) -> u32:
    put(w,E_PLAN_INDEX,get(w,E_PLAN_INDEX)+1)
    return jump(w,1600)

def scalar(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase>=1621 and phase<=1630:
        return os_text(w,phase)
    if phase>=1640 and phase<=1643:
        return segments(w,phase)
    r=get(w,RESULT)
    row=get(w,E_ROW)
    op=get(w,E_OP)
    if phase==1611:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_XMAP,r)
        put(w,A_XCAP,get(w,E_AMOUNT))
        return jump(w,1612)
    if phase==1612:
        put(w,E_OUT_BASE,get(w,A_XMAP))
        if op==18:
            put(w,E_OUT_N,0)
            return jump(w,1640)
        if op==16:
            put(w,E_OUT_N,get(w,row+32))
            put(w,E_TEMP,(get(w,row+32)+8192+6*get(w,row+48)+15)&18446744073709551600)
            return a_copy(w,1621,get(w,row+24),get(w,A_XMAP)+128,get(w,row+32))
        if op==15:
            clear(w,A_RQ,128)
            put(w,A_RQ,get(w,row+16))
            return a_invoke(w,1620,8,a_at(w,A_RQ),8,get(w,A_XMAP)+128,4096,0,0)
        clear(w,A_RQ,128)
        if op==14:
            n=get(w,row+24)
            ptr=get(w,row+16)
            put(w,A_RQ,A_CODEC_REQUEST)
            put(w,A_RQ+16,n)
        else:
            n=get(w,row+32)
            ptr=get(w,row+24)
            put(w,A_RQ,A_V6)
            put(w,A_RQ+8,2)
            put(w,A_RQ+96,n)
            put(w,A_RQ+104,get(w,row+16))
            put(w,A_RQ+112,get(w,row+40))
        put(w,E_INPUT_PTR,ptr)
        put(w,E_INPUT_N,n)
        return a_copy(w,1613,a_at(w,A_RQ),get(w,A_XMAP),128)
    if phase==1613:
        if r!=0:
            return a_unknown(w,phase)
        return a_copy(w,1614,get(w,E_INPUT_PTR),get(w,A_XMAP)+128,get(w,E_INPUT_N))
    if phase==1614:
        if r!=0:
            return a_unknown(w,phase)
        n=get(w,E_INPUT_N)
        if op==14:
            put(w,E_OUT_BASE,get(w,A_XMAP)+128+n)
            clear(w,A_CODEC_WORK,32)
            return a_invoke(w,1615,3,get(w,A_XMAP),128+n,get(w,E_OUT_BASE),128+3*n,a_at(w,A_CODEC_WORK),32)
        put(w,E_OUT_N,n)
        return scalar_value(w)
    if phase==1615:
        if r!=0:
            return a_unknown(w,phase)
        return a_copy(w,1616,get(w,E_OUT_BASE),a_at(w,A_RQ),128)
    if phase==1616:
        if r!=0 or get(w,A_RQ)!=A_CODEC_REPLY or get(w,A_RQ+8)!=0 or get(w,A_RQ+16)>3*get(w,E_INPUT_N):
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,A_RQ+16))
        return string_header(w)
    if phase==1617:
        if r!=0:
            return a_unknown(w,phase)
        return scalar_value(w)
    if phase==1620:
        if r>=4096:
            return a_unknown(w,phase)
        put(w,E_OUT_N,r)
        return string_header(w)
    return 4294967293


def os_text(w:mutbuf,phase:u64) -> u32:
    result=get(w,RESULT)
    row=get(w,E_ROW)
    if phase==1621:
        if result!=0:
            return a_unknown(w,phase)
        clear(w,A_RQ,128)
        put(w,A_RQ,0x206f6e7272455b)
        at=7
        number=get(w,row+16)
        more=True
        while more:
            store(w,A_RQ+at,48+number%10)
            at=at+1
            number=number//10
            if number==0:
                more=False
        i=7
        j=at-1
        while i<j:
            v=byte(w,A_RQ+i)
            store(w,A_RQ+i,byte(w,A_RQ+j))
            store(w,A_RQ+j,v)
            i=i+1
            j=j-1
        store(w,A_RQ+at,93)
        store(w,A_RQ+at+1,32)
        n=at+2
        pos=get(w,E_OUT_N)
        put(w,E_OUT_N,pos+n)
        return a_copy(w,1622,a_at(w,A_RQ),get(w,A_XMAP)+128+pos,n)
    if phase==1622:
        if result!=0:
            return a_unknown(w,phase)
        clear(w,A_RQ,128)
        put(w,A_RQ,get(w,row+16))
        return a_invoke(w,1623,8,a_at(w,A_RQ),8,get(w,A_XMAP)+128+get(w,E_OUT_N),4096,0,0)
    if phase==1623:
        if result>=4096:
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,E_OUT_N)+result)
        if get(w,row+56)==0:
            return string_header(w)
        clear(w,A_RQ,128)
        store(w,A_RQ,58)
        store(w,A_RQ+1,32)
        return a_copy(w,1624,a_at(w,A_RQ),get(w,A_XMAP)+128+get(w,E_OUT_N),2)
    if phase==1624:
        if result!=0:
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,E_OUT_N)+2)
        clear(w,A_RQ,128)
        put(w,A_RQ,A_CODEC_REQUEST)
        put(w,A_RQ+16,get(w,row+48))
        return a_copy(w,1625,a_at(w,A_RQ),get(w,A_XMAP)+get(w,E_TEMP),128)
    if phase==1625:
        if result!=0:
            return a_unknown(w,phase)
        return a_copy(w,1626,get(w,row+40),get(w,A_XMAP)+get(w,E_TEMP)+128,get(w,row+48))
    if phase==1626:
        if result!=0:
            return a_unknown(w,phase)
        n=get(w,row+48)
        put(w,E_STAGE,get(w,A_XMAP)+get(w,E_TEMP)+128+n)
        clear(w,A_CODEC_WORK,32)
        return a_invoke(w,1627,3,get(w,A_XMAP)+get(w,E_TEMP),128+n,get(w,E_STAGE),128+3*n,a_at(w,A_CODEC_WORK),32)
    if phase==1627:
        if result!=0:
            return a_unknown(w,phase)
        return a_copy(w,1628,get(w,E_STAGE),a_at(w,A_RQ),128)
    if phase==1628:
        if result!=0 or get(w,A_RQ)!=A_CODEC_REPLY or get(w,A_RQ+8)!=0 or get(w,A_RQ+16)>3*get(w,row+48):
            return a_unknown(w,phase)
        put(w,E_INPUT_N,get(w,A_RQ+16))
        clear(w,A_RQ,128)
        put(w,A_RQ,0x3152504552414948)
        return a_copy(w,1629,a_at(w,A_RQ),get(w,E_STAGE)+112,16)
    if phase==1629:
        if result!=0:
            return a_unknown(w,phase)
        return a_invoke(w,1630,9,get(w,E_STAGE)+112,16+get(w,E_INPUT_N),get(w,A_XMAP)+128+get(w,E_OUT_N),get(w,E_TEMP)-128-get(w,E_OUT_N),a_at(w,A_CODEC_WORK),8192)
    if phase==1630:
        if result>get(w,E_TEMP)-128-get(w,E_OUT_N):
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,E_OUT_N)+result)
        return string_header(w)
    return 4294967293

def inspected(w:mutbuf) -> u32:
    if a_ordinary(w)==False or get(w,A_VR+8192)!=A_NATIVE or get(w,A_VR+8200)!=0:
        return a_unknown(w,1660)
    i=0
    while i<3:
        if get(w,A_VR+8224+i*24)==0:
            return a_unknown(w,1660)
        i=i+1
    i=0
    while i<3:
        if a_capture(w,get(w,E_DST)+i,A_VR+8224+i*24)==False:
            return a_unknown(w,1660)
        i=i+1
    return next_row(w)

def errno_prefix(w:mutbuf,number:u64) -> u64:
    clear(w,A_RQ,128)
    put(w,A_RQ,0x206f6e7272455b)
    at=7
    more=True
    while more:
        store(w,A_RQ+at,48+number%10)
        at=at+1
        number=number//10
        if number==0:
            more=False
    i=7
    j=at-1
    while i<j:
        v=byte(w,A_RQ+i)
        store(w,A_RQ+i,byte(w,A_RQ+j))
        store(w,A_RQ+j,v)
        i=i+1
        j=j-1
    store(w,A_RQ+at,93)
    store(w,A_RQ+at+1,32)
    return at+2

def segments(w:mutbuf,phase:u64) -> u32:
    index=get(w,E_SEG_INDEX)
    at=get(w,E_SEG_AT)+index*32
    if phase==1640:
        if index==get(w,E_SEG_COUNT):
            return string_header(w)
        if index>get(w,E_SEG_COUNT):
            return a_unknown(w,1640)
        if get(w,at)==0:
            n=get(w,at+16)
            put(w,E_SEG_N,n)
            return a_copy(w,1641,get(w,at+8),get(w,A_XMAP)+128+get(w,E_OUT_N),n)
        n=errno_prefix(w,get(w,at+24))
        put(w,E_SEG_N,n)
        return a_copy(w,1642,a_at(w,A_RQ),get(w,A_XMAP)+128+get(w,E_OUT_N),n)
    if phase==1641 or phase==1642:
        if get(w,RESULT)!=0:
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,E_OUT_N)+get(w,E_SEG_N))
        if phase==1642:
            clear(w,A_RQ,128)
            put(w,A_RQ,get(w,at+24))
            return a_invoke(w,1643,8,a_at(w,A_RQ),8,get(w,A_XMAP)+128+get(w,E_OUT_N),4096,0,0)
    else:
        if get(w,RESULT)>=4096:
            return a_unknown(w,phase)
        put(w,E_OUT_N,get(w,E_OUT_N)+get(w,RESULT))
    put(w,E_SEG_INDEX,index+1)
    return jump(w,1640)

def string_header(w:mutbuf) -> u32:
    a_request(w,A_V6,2)
    put(w,A_RQ+96,get(w,E_OUT_N))
    put(w,A_RQ+104,4)
    return a_copy(w,1617,a_at(w,A_RQ),get(w,E_OUT_BASE),128)

def scalar_value(w:mutbuf) -> u32:
    clear(w,A_VR,A_VR_N)
    return a_invoke(w,1601,1,get(w,E_OUT_BASE),128+get(w,E_OUT_N),a_at(w,A_VR),A_VR_N,get(w,A_VALUE_WORK),get(w,A_VALUE_WORK_N))
'''
if __name__=='__main__':write_module('clang_value_error_builder',SOURCE)
