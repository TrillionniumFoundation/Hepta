"""Fixed native Value invocation driver; executes after the Value mutex is released."""
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve

SOURCE=r'''
def result_value_invocations(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<65536:
        return 4294967293
    if get(w,0)==0:
        return invoke_init(s,o,w)
    if get(w,0)!=3544406888999373128 or get(w,24)!=length(w):
        return 4294967293
    phase=get(w,8)
    if phase==21:
        return invoke_request_scan(s,w)
    if phase==41:
        return invoke_response_scan(s,w)
    if phase==45:
        return invoke_drop_reply(s,o,w)
    if phase==47:
        return invoke_next_cap(s,w)
    if phase>=600:
        return invoke_cleanup(o,w)
    if get(o,7496)!=0:
        put(w,248,1)
        if phase==10 or phase==11 or phase==20 or phase==22:
            return invoke_fail(o,w,11)
    if phase==10:
        return invoke_construct_reply(o,w)
    if phase==11:
        return invoke_capture_reply(o,w)
    if phase==20:
        return invoke_body_reply(o,w)
    if phase==22:
        if get(o,P_FEEDBACK)!=0 or get(w,360)!=0:
            return invoke_fail(o,w,11)
        if get(w,352)!=0:
            invoke_value_frame(w,90)
            copy(w,2072,192,24)
            copy(w,2096,3696,24)
            put(w,8,44)
            return invoke_value(o,w,2048,128,16384,8192)
        put(w,8,40)
        role(o,0,0,get(w,272),get(w,280),0,get(w,288),get(w,296),0,0,0)
        return 9
    if phase==40:
        put(w,304,get(o,P_FEEDBACK))
        if get(w,304)!=0:
            return invoke_resume(o,w)
        put(w,8,41)
        return invoke_helper(o,w,get(w,288),get(w,296),3,0,length(o))
    if phase==42:
        if get(o,P_FEEDBACK)!=0 or get(w,360)!=0:
            return invoke_fail(o,w,11)
        put(w,328,0)
        return invoke_scan_continue(o,w)
    if phase==43:
        if invoke_value_valid(o,w,16384,DROP_REPLY)==False:
            return invoke_pending(o,w,640)
        if get(w,16384+88)!=1 or get(w,16384+96)!=1:
            return invoke_pending(o,w,640)
        put(w,328,get(w,328)+1)
        return invoke_scan_continue(o,w)
    if phase==44:
        put(w,304,get(o,P_FEEDBACK))
        if get(w,304)!=0:
            return invoke_fail(o,w,11)
        put(w,8,45)
        return invoke_helper(o,w,get(w,32)+16384,8192,0,get(w,288),get(w,296))
    if phase==46:
        if get(o,P_FEEDBACK)!=0:
            return invoke_fail(o,w,11)
        return invoke_resume(o,w)
    if phase==48:
        if get(o,P_FEEDBACK)!=0:
            return invoke_fail(o,w,11)
        if get(w,3696)==0:
            put(w,328,get(w,328)+1)
            return invoke_scan_continue(o,w)
        invoke_value_frame(w,89)
        copy(w,2072,192,24)
        copy(w,2096,3696,24)
        put(w,8,43)
        return invoke_value(o,w,2048,128,16384,8192)
    if phase==50:
        if invoke_value_valid(o,w,16384,REPLY)==False:
            return invoke_fail(o,w,11)
        if get(w,16384+8)!=0:
            return invoke_fail(o,w,get(w,16384+8))
        if get(w,16384+24)==0:
            return invoke_fail(o,w,11)
        invoke_primary(w,16384,get(w,64))
        put(w,504,get(w,16384+56))
        if (get(w,64)==1 and get(w,504)!=0) or (get(w,64)==2 and get(w,504)!=1 and get(w,504)!=2):
            put(w,56,11)
        put(w,8,600)
        return 10
    return invoke_fail(o,w,11)

def invoke_init(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    put(w,0,3544406888999373128)
    put(w,16,choose(readword(s,8)==97,70,readword(s,8)))
    put(w,496,choose(readword(s,8)==97,1,0))
    put(w,504,0)
    put(w,24,length(w))
    put(w,32,get(o,7040))
    put(w,72,0)
    copy_output_to_work(o,w,192,7080,24)
    copy_output_to_work(o,w,216,7056,24)
    copy_output_to_work(o,w,384,7176,24)
    copy_output_to_work(o,w,416,7104,24)
    copy_output_to_work(o,w,440,7128,24)
    copy_output_to_work(o,w,464,7152,24)
    op=get(w,16)
    if op==68:
        zero(w,32768,128)
        put(w,32768,3553696688193489224)
        put(w,32776,1)
        put(w,32864,length(s)-128)
        from_input(s,w,32896,128,length(s)-128)
        put(w,8,10)
        return invoke_code_at(o,w,32768,length(s))
    if op==69 or op==115:
        invoke_code_frame(w,2,384)
        put(w,8,10)
        return invoke_code_at(o,w,512,128)
    invoke_code_frame(w,4,384)
    put(w,608,128)
    zero(w,640,128)
    put(w,640,3544418983308511560)
    put(w,648,1)
    copy(w,664,192,24)
    put(w,8,20)
    return invoke_code_at(o,w,512,256)

def copy_output_to_work(o:mutbuf,w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(o,at+i))
        i=i+1
    return 0

def invoke_code_frame(w:mutbuf,op:u64,cap:u64) -> u64:
    zero(w,512,128)
    put(w,512,3553696688193489224)
    put(w,520,op)
    if cap!=0:
        copy(w,536,cap,24)
    return 0

def invoke_value_frame(w:mutbuf,op:u64) -> u64:
    zero(w,2048,128)
    put(w,2048,MAGIC5)
    put(w,2056,op)
    return 0

def invoke_code_at(o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    role(o,0,0,get(w,32)+at,n,0,get(w,32)+8192,8192,0,0,0)
    return 8

def invoke_value(o:mutbuf,w:mutbuf,at:u64,n:u64,out:u64,on:u64) -> u64:
    role(o,0,0,get(w,32)+at,n,0,get(w,32)+out,on,0,0,0)
    return 9

def invoke_helper(o:mutbuf,w:mutbuf,source:u64,n:u64,selector:u64,out:u64,on:u64) -> u64:
    return role(o,15,0,source,n,selector,out,on,0,get(w,32),get(w,24))

def invoke_code_valid(o:mutbuf,w:mutbuf) -> bool:
    return get(o,P_FEEDBACK)==0 and get(w,8192)==3553978163170199880 and get(w,8280)==1 and get(w,8272)<=1 and get(w,8288)<=1

def invoke_value_valid(o:mutbuf,w:mutbuf,at:u64,magic:u64) -> bool:
    return get(o,P_FEEDBACK)==0 and get(w,at)==magic

def invoke_primary(w:mutbuf,at:u64,disposition:u64) -> u64:
    copy(w,80,at+24,24)
    put(w,104,1)
    put(w,64,disposition)
    put(w,256,get(w,at+16))
    put(w,264,get(w,at+48))
    return 0

def invoke_construct_reply(o:mutbuf,w:mutbuf) -> u64:
    if invoke_code_valid(o,w)==False:
        put(w,488,1)
        return invoke_pending(o,w,600)
    if get(w,8288)==1 and get(w,8216)!=0:
        copy(w,128,8216,24)
        put(w,112,1)
    if get(w,8272)!=0:
        put(w,120,1)
    if get(w,8200)!=0:
        return invoke_fail(o,w,get(w,8200))
    if get(w,112)!=1 or get(w,8208)!=1:
        return invoke_fail(o,w,11)
    invoke_value_frame(w,48)
    if get(w,16)==115:
        put(w,2048,MAGIC8)
    copy(w,2072,416,24)
    if get(w,16)==69 or get(w,16)==115:
        copy(w,2096,440,24)
    copy(w,2120,464,24)
    put(w,2144,24)
    put(w,2152,choose(get(w,16)==68,3,4))
    copy(w,2176,128,24)
    put(w,8,11)
    return invoke_value(o,w,2048,152,16384,8192)

def invoke_capture_reply(o:mutbuf,w:mutbuf) -> u64:
    if invoke_value_valid(o,w,16384,REPLY)==False or get(w,16472)!=1:
        put(w,488,1)
        return invoke_pending(o,w,600)
    if get(w,16)==115 and (get(w,16488)>1 or get(w,16496)>1 or get(w,16504)!=1 or get(w,16464)!=(get(w,16488)|get(w,16496))):
        put(w,488,1)
        return invoke_pending(o,w,600)
    if get(w,16480)==1:
        if get(w,16408)==0:
            put(w,488,1)
            return invoke_pending(o,w,600)
        put(w,112,0)
        invoke_primary(w,16384,1)
        if get(w,16392)!=0 or (get(w,16)==115 and get(w,16488)!=0) or (get(w,16)!=115 and get(w,16464)!=0):
            put(w,56,11)
    elif get(w,16480)==0:
        put(w,72,choose(get(w,16392)==0,11,get(w,16392)))
    else:
        put(w,488,1)
        return invoke_pending(o,w,600)
    put(w,8,600)
    return 10

def invoke_body_reply(o:mutbuf,w:mutbuf) -> u64:
    if invoke_code_valid(o,w)==False:
        put(w,488,1)
        return invoke_pending(o,w,600)
    if get(w,152)==0 and get(w,8288)==1 and get(w,8216)!=0:
        if get(w,8208)!=2:
            put(w,488,1)
            return invoke_pending(o,w,600)
        put(w,152,1)
        copy(w,160,8216,24)
    if get(w,8272)!=0:
        put(w,184,1)
    if get(w,8200)!=0 or get(w,152)==0:
        return invoke_fail(o,w,choose(get(w,8200)==0,11,get(w,8200)))
    action=get(w,8240)
    if action==0:
        at=12288
        if get(w,at)!=3544423351290251592 or (get(w,at+8)!=1 and get(w,at+8)!=2) or get(w,at+16)!=0 or get(w,at+24)==0:
            return invoke_fail(o,w,11)
        i=48
        while i<128:
            if get(w,at+i)!=0:
                return invoke_fail(o,w,11)
            i=i+8
        put(w,64,get(w,at+8))
        invoke_value_frame(w,85)
        copy(w,2072,at+24,24)
        copy(w,2096,192,24)
        put(w,2152,get(w,64))
        put(w,8,50)
        return invoke_value(o,w,2048,128,16384,8192)
    if action!=1:
        return invoke_fail(o,w,11)
    put(w,272,get(w,8248))
    put(w,280,get(w,8256))
    put(w,288,get(w,8264))
    put(w,296,get(w,8296))
    if get(w,272)==0 or get(w,280)<128 or get(w,280)>524160 or get(w,288)==0 or get(w,296)!=524288:
        return invoke_fail(o,w,11)
    put(w,8,21)
    return invoke_helper(o,w,get(w,272),get(w,280),3,0,length(o))

def invoke_allowed(op:u64) -> bool:
    return (op>=1 and op<=19) or (op>=23 and op<=29) or (op>=32 and op<=44) or op==46 or op==50 or op==57 or op==62 or op==63 or (op>=67 and op<=70) or op==75 or op==87 or op==98

def invoke_request_scan(s:readbuf,w:mutbuf) -> u64:
    put(w,360,0)
    put(w,352,0)
    if length(s)<128 or readword(s,0)==MAGIC6 or readword(s,0)==MAGIC7 or readword(s,0)==MAGIC8 or readword(s,0)==MAGIC9 or readword(s,0)==MAGIC10 or readword(s,0)==MAGIC11 or invoke_allowed(readword(s,8))==False:
        put(w,360,1)
        put(w,8,22)
        return 0
    op=readword(s,8)
    put(w,344,op)
    if op==6 or op==29:
        put(w,352,1)
        from_input(s,w,3696,24,24)
    put(w,8,22)
    return 0

def invoke_resume(o:mutbuf,w:mutbuf) -> u64:
    invoke_code_frame(w,9,160)
    put(w,616,get(w,304))
    put(w,8,20)
    return invoke_code_at(o,w,512,128)

def invoke_response_scan(s:readbuf,w:mutbuf) -> u64:
    put(w,360,0)
    put(w,312,0)
    put(w,320,0)
    if length(s)<8192 or readword(s,0)!=REPLY:
        put(w,360,1)
        put(w,8,42)
        return 0
    op=get(w,344)
    status=readword(s,8)
    if status!=0 and ((op<68 or op>70) or readword(s,96)!=1):
        put(w,8,42)
        return 0
    if op==23:
        put(w,312,1)
        put(w,320,readword(s,64)*choose(readword(s,16)==6,2,1))
        put(w,336,choose(readword(s,16)==6,2,1))
    elif op==26:
        put(w,312,2)
        put(w,320,3)
    elif op==28:
        put(w,312,3)
        put(w,320,2)
    elif op==7 or op==8 or op==10 or op==11 or op==13 or op==14 or op==15 or op==16 or op==17 or op==19 or op==34 or op==37 or op==62 or op==63:
        put(w,320,0)
    else:
        put(w,320,1)
    put(w,8,42)
    return 0

def invoke_scan_continue(o:mutbuf,w:mutbuf) -> u64:
    if get(w,328)>=get(w,320):
        put(w,360,0)
        if get(w,248)!=0:
            put(w,8,600)
            return 10
        return invoke_resume(o,w)
    put(w,8,47)
    return invoke_helper(o,w,get(w,288),get(w,296),3,0,length(o))

def invoke_next_cap(s:readbuf,w:mutbuf) -> u64:
    index=get(w,328)
    mode=get(w,312)
    at=24
    if mode==1:
        stride=get(w,336)
        iskey=stride==2 and index%2==0
        at=8192+(index//stride)*64+choose(iskey,16,40)
    elif mode==2:
        at=8224+index*24
    elif mode==3:
        at=8208+index*24
    if at>length(s) or length(s)-at<24:
        put(w,8,48)
        return 11
    from_input(s,w,3696,at,24)
    put(w,8,48)
    return 0

def invoke_drop_reply(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s)<128 or length(o)<8192 or readword(s,0)!=DROP_REPLY:
        put(w,8,46)
        return 11
    from_input(s,o,0,0,128)
    if get(w,344)==6:
        zero(o,0,128)
        put(o,0,REPLY)
        put(o,8,readword(s,8))
    put(w,8,46)
    return 0

def invoke_fail(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(w,104)==0 and get(w,72)==0:
        put(w,72,status)
    put(w,8,600)
    return 10

def invoke_pending(o:mutbuf,w:mutbuf,next:u64) -> u64:
    if get(w,104)==0 and get(w,72)==0:
        put(w,72,11)
    put(w,56,11)
    put(w,8,next)
    invoke_result(o,w,1)
    return 0

def invoke_result(o:mutbuf,w:mutbuf,pending:u64) -> u64:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(w,72))
    if get(w,104)!=0:
        put(o,16,get(w,256))
        copy_output(w,o,24,80,24)
        put(o,48,get(w,264))
        put(o,64,get(w,64))
        if get(w,496)!=0:
            put(o,56,get(w,504))
        put(o,96,1)
    put(o,80,pending)
    put(o,88,1)
    put(o,104,get(w,56))
    put(o,120,pending)
    return 0

def copy_output(w:mutbuf,o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(w,at+i))
        i=i+1
    return 0

def invoke_cleanup(o:mutbuf,w:mutbuf) -> u64:
    phase=get(w,8)
    if get(w,488)!=0:
        return invoke_pending(o,w,600)
    if phase==600:
        if get(w,16)==70:
            invoke_value_frame(w,90)
            copy(w,2072,192,24)
            put(w,8,601)
            return invoke_value(o,w,2048,128,16384,8192)
        put(w,8,610)
        return 10
    if phase==601:
        if invoke_value_valid(o,w,16384,DROP_REPLY)==False or get(w,16472)!=1 or get(w,16480)!=1:
            return invoke_pending(o,w,600)
        put(w,8,610)
        return 10
    if phase==610:
        if get(w,152)!=0:
            invoke_code_frame(w,3,160)
            put(w,8,611)
            return invoke_code_at(o,w,512,128)
        if get(w,184)!=0:
            invoke_code_frame(w,5,0)
            put(w,8,612)
            return invoke_code_at(o,w,512,128)
        put(w,8,620)
        return 10
    if phase==611:
        if invoke_code_valid(o,w)==False:
            return invoke_pending(o,w,610)
        if get(w,8288)==1:
            put(w,152,0)
            zero(w,160,24)
            put(w,184,get(w,8272))
        if get(w,152)!=0 or get(w,184)!=0:
            return invoke_pending(o,w,610)
        put(w,8,620)
        return 10
    if phase==612:
        if invoke_code_valid(o,w)==False or get(w,8272)!=0:
            return invoke_pending(o,w,610)
        put(w,184,0)
        put(w,8,620)
        return 10
    if phase==620:
        if get(w,112)!=0:
            invoke_code_frame(w,3,128)
            put(w,8,621)
            return invoke_code_at(o,w,512,128)
        if get(w,120)!=0:
            invoke_code_frame(w,5,0)
            put(w,8,622)
            return invoke_code_at(o,w,512,128)
        put(w,368,0)
        put(w,8,630)
        return 10
    if phase==621:
        if invoke_code_valid(o,w)==False:
            return invoke_pending(o,w,620)
        if get(w,8288)==1:
            put(w,112,0)
            zero(w,128,24)
            put(w,120,get(w,8272))
        if get(w,112)!=0 or get(w,120)!=0:
            return invoke_pending(o,w,620)
        put(w,368,0)
        put(w,8,630)
        return 10
    if phase==622:
        if invoke_code_valid(o,w)==False or get(w,8272)!=0:
            return invoke_pending(o,w,620)
        put(w,120,0)
        put(w,368,0)
        put(w,8,630)
        return 10
    if phase==630:
        index=get(w,368)
        if index>=3:
            put(w,8,900)
            invoke_result(o,w,0)
            return 0
        at=416+index*24
        if get(w,at)==0:
            put(w,368,index+1)
            return 10
        invoke_value_frame(w,78)
        copy(w,2072,at,24)
        put(w,8,631)
        return invoke_value(o,w,2048,128,16384,8192)
    if phase==631:
        if invoke_value_valid(o,w,16384,DROP_REPLY)==False or get(w,16472)!=1:
            return invoke_pending(o,w,630)
        if get(w,16480)==1:
            zero(w,416+get(w,368)*24,24)
            put(w,368,get(w,368)+1)
        else:
            return invoke_pending(o,w,630)
        put(w,8,630)
        return 10
    if phase==640:
        put(w,248,1)
        invoke_value_frame(w,89)
        copy(w,2072,192,24)
        copy(w,2096,3696,24)
        put(w,8,43)
        return invoke_value(o,w,2048,128,16384,8192)
    if phase==900:
        invoke_result(o,w,0)
        return 0
    return invoke_pending(o,w,600)
'''

def source_program():
    return resolve('result_value_invocations',SOURCE)
def program():
    return document(source_program(),'result_value_invocations')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/result_value_invocations.hepta'
    path.write_text(render_assembly(program()))
    print(path.name,path.stat().st_size,flush=True)
