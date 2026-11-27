"""CaptureRejected graphs from actual native process and stream evidence."""
from tools.generate_hia_clang_value_error_plan_common import C,write_module
from tools import generate_hia_clang_value_error_surface as file_surface
C.update(E_CAP_FRAME=3320,E_CAP_FRAME_N=3328,E_ARGC=3336,E_ARGI=3344,E_ARG_AT=3352,
 E_RECORD=3360,E_UTF8_PTR=3368,E_UTF8_N=3376,E_PREFIX_N=3384,E_UTF8=3440,E_PRIVATE=3520)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==1400:
        return begin(w)
    if phase>=1420 and phase<=1422:
        return reap_text(o,w,phase)
    if phase==1402:
        if get(w,RESULT)!=0 or get(w,E_PRIVATE+104)!=0x3130584643414948:
            return a_unknown(w,1402)
        return decide(w)
    if phase==1401:
        if get(w,RESULT)!=0 or get(w,E_UTF8)!=0x3152453855414948 or get(w,E_UTF8+8)!=1:
            return a_unknown(w,1401)
        if get(w,E_UTF8+16)>=get(w,E_UTF8+24) or get(w,E_UTF8+24)>get(w,E_UTF8_N) or get(w,E_UTF8+32)<1 or get(w,E_UTF8+32)>3:
            return a_unknown(w,1401)
        return frame(w)
    if phase==1410:
        if get(w,RESULT)!=0 or get(w,A_RQ)!=0x3130504143414948 or get(w,A_RQ+8)!=0:
            return a_unknown(w,1410)
        count=get(w,A_RQ+16)
        if count==0 or count>(get(w,E_CAP_FRAME_N)-128)//10:
            return a_unknown(w,1410)
        put(w,E_ARGC,count)
        put(w,E_ARGI,0)
        put(w,E_ARG_AT,128)
        if get(w,E_RECORD)!=0 or (get(w,E_REAP_KIND)&1)!=0:
            e_list(w,50)
        return next_argument(w)
    if phase==1411:
        if get(w,RESULT)!=0:
            return a_unknown(w,1411)
        n=get(w,A_RQ)
        at=get(w,E_ARG_AT)+8
        if n==0 or at>=get(w,E_CAP_FRAME_N) or n>=get(w,E_CAP_FRAME_N)-at:
            return a_unknown(w,1411)
        if get(w,E_ARGI)==0 and get(w,E_FILENAME)!=0:
            put(w,E_FN_PTR,get(w,E_CAP_FRAME)+at)
            put(w,E_FN_N,n)
        if get(w,E_RECORD)!=0 or (get(w,E_REAP_KIND)&1)!=0:
            e_fs(w,51,get(w,E_CAP_FRAME)+at,n)
            e_append(w,50,51)
            e_drop(w,51)
        put(w,E_ARGI,get(w,E_ARGI)+1)
        put(w,E_ARG_AT,at+n+1)
        return next_argument(w)
    return 4294967293

def begin(w:mutbuf) -> u32:
    index=get(w,A_INNER_WORK+840)
    if index>2:
        return a_unknown(w,1400)
    at=A_INNER_WORK+2300000+index*256
    if get(w,at)!=0x3130524143414948:
        return a_unknown(w,1400)
    put(w,E_CAPTURE,at)
    arena=get(w,A_INNER_WORK+1912)
    if arena==0:
        return a_unknown(w,1400)
    return a_copy(w,1402,arena+index*131072+1880,a_at(w,E_PRIVATE),120)

def decide(w:mutbuf) -> u32:
    at=get(w,E_CAPTURE)
    kind=0
    if get(w,E_PRIVATE+112)!=0:
        if get(w,at+8)==11 and (get(w,at+248)&4294967295)==207:
            kind=1
        if get(w,E_PRIVATE+80)!=0 and get(w,at+40)==11 and (get(w,at+248)>>32)==207:
            kind=kind|2
    put(w,E_REAP_KIND,kind)
    if kind!=0:
        put(w,E_CAP_FRAME,get(w,A_INNER_WORK+600))
        put(w,E_CAP_FRAME_N,get(w,A_INNER_WORK+608))
        if get(w,E_CAP_FRAME)==0 or get(w,E_CAP_FRAME_N)<128:
            return a_unknown(w,1420)
        return jump(w,1420)
    return decide_after(w)

def decide_after(w:mutbuf) -> u32:
    at=get(w,E_CAPTURE)
    code=get(w,at+8)
    if code==0 or code>13:
        return jump(w,1000)
    put(w,E_CAPTURE,at)
    put(w,E_CODE,code)
    put(w,E_PHASE,get(w,at+248)&4294967295)
    put(w,E_ERRNO,get(w,at+16))
    put(w,E_FILENAME,0)
    put(w,E_RECORD,0)
    put(w,E_CAUSE,0)
    put(w,E_CLOSE_NEXT,0)
    if code==12 and (get(w,E_PHASE)==62 or get(w,E_PHASE)==66 or get(w,E_PHASE)==69):
        code=7
        put(w,E_CODE,code)
    if code==11 and get(w,E_PHASE)==501:
        i=0
        found=False
        while i<3 and found==False:
            if get(w,E_PRIVATE+40+i*8)!=0:
                put(w,E_ERRNO,get(w,E_PRIVATE+40+i*8))
                put(w,E_CLOSE_NEXT,i+1)
                found=True
            i=i+1
        if found==False:
            return a_unknown(w,1400)
        os_exception(w,15)
        return jump(w,1700)
    if code==12 or code==6 and get(w,E_PHASE)==21 and get(w,E_ERRNO)!=0:
        os_exception(w,15)
        return jump(w,1700)
    if code==13:
        e_class(w,32,27)
        e_list(w,34)
        e_tuple(w,35,34)
        e_exception(w,15,32,35,NONE)
        return jump(w,1700)
    if code==11 and (get(w,E_PHASE)<200 or get(w,E_PHASE)>208):
        return jump(w,1000)
    if code==7:
        put(w,E_CAUSE,1)
        if get(w,E_PHASE)==67 and get(w,at+192)==0:
            put(w,E_FILENAME,1)
    elif (code==6 and get(w,E_PHASE)!=21 or code==11) and get(w,E_ERRNO)!=0:
        put(w,E_CAUSE,1)
    if (code==8 or code==9 or code==10 or code==11 or code==6 and get(w,E_PHASE)>=100) and get(w,at+200)==0 and get(w,E_PRIVATE+72)==1:
        put(w,E_RECORD,1)
    if (get(w,E_REAP_KIND)&1)!=0:
        put(w,E_CAUSE,3)
    if code==10:
        stream=get(w,at+232)
        if stream>1:
            return a_unknown(w,1400)
        put(w,E_UTF8_PTR,get(w,E_PRIVATE))
        put(w,E_UTF8_N,get(w,E_PRIVATE+8))
        if get(w,E_UTF8_PTR)==0 or get(w,E_UTF8_N)==0:
            return a_unknown(w,1400)
        put(w,E_CAUSE,2)
        return a_invoke(w,1401,10,get(w,E_UTF8_PTR),get(w,E_UTF8_N),a_at(w,E_UTF8),64,0,0)
    return frame(w)

def frame(w:mutbuf) -> u32:
    if get(w,E_RECORD)==0 and get(w,E_FILENAME)==0 and (get(w,E_REAP_KIND)&1)==0:
        return construct(w)
    put(w,E_CAP_FRAME,get(w,A_INNER_WORK+600))
    put(w,E_CAP_FRAME_N,get(w,A_INNER_WORK+608))
    if get(w,E_CAP_FRAME)==0 or get(w,E_CAP_FRAME_N)<128:
        return a_unknown(w,1410)
    return a_copy(w,1410,get(w,E_CAP_FRAME),a_at(w,A_RQ),128)

def next_argument(w:mutbuf) -> u32:
    if get(w,E_ARGI)==get(w,E_ARGC) or (get(w,E_RECORD)==0 and (get(w,E_REAP_KIND)&1)==0 and get(w,E_ARGI)!=0):
        if get(w,E_RECORD)!=0:
            record(w)
        return construct(w)
    at=get(w,E_ARG_AT)
    if at>get(w,E_CAP_FRAME_N) or get(w,E_CAP_FRAME_N)-at<8:
        return a_unknown(w,1411)
    return a_copy(w,1411,get(w,E_CAP_FRAME)+at,a_at(w,A_RQ),8)

def record(w:mutbuf) -> u64:
    at=get(w,E_CAPTURE)
    e_tuple(w,52,50)
    e_list(w,53)
    e_append(w,53,52)
    if get(w,at+24)==1:
        e_number(w,55,get(w,at+32),1)
    else:
        e_none(w,55)
    e_append(w,53,55)
    e_scalar(w,56,7,get(w,at+72),get(w,at+80),0)
    e_append(w,53,56)
    e_scalar(w,57,7,get(w,at+88),get(w,at+96),0)
    e_append(w,53,57)
    e_number(w,58,get(w,at+56),0)
    e_append(w,53,58)
    e_number(w,59,get(w,at+64),0)
    e_append(w,53,59)
    e_tuple(w,54,53)
    e_row(w,10,61,54,53,0,0,0,0)
    if (get(w,E_REAP_KIND)&1)==0:
        e_drop(w,50)
    e_drop(w,52)
    e_drop(w,53)
    e_drop(w,54)
    e_drop(w,55)
    e_drop(w,56)
    e_drop(w,57)
    e_drop(w,58)
    e_drop(w,59)
    return 0

def construct(w:mutbuf) -> u32:
    code=get(w,E_CODE)
    phase=get(w,E_PHASE)
    e_class(w,32,48)
    e_dict(w,43)
    e_none(w,44)
    text_value(w,45,1)
    code_value(w,46)
    e_item(w,43,45,46)
    text_value(w,47,2)
    e_item(w,43,47,choose(get(w,E_RECORD)!=0,61,44))
    text_value(w,48,3)
    e_item(w,43,48,44)
    if code==7 or code==11:
        start=get(w,E_TEXT_N)
        if code==7:
            text_exec(w)
        else:
            if (phase==203 or phase==206) and get(w,get(w,E_CAPTURE)+24)==1:
                text_cleanup_group(w)
                e_digits(w,get(w,E_ERRNO))
                text_semicolon(w)
            else:
                text_cleanup_reap(w)
        prefix_n=get(w,E_TEXT_N)-start
        if (get(w,E_REAP_KIND)&1)!=0:
            segments=E_TEXT+get(w,E_TEXT_N)
            e_segment(w,0,a_at(w,E_TEXT+start),prefix_n,0)
            e_segment(w,0,get(w,E_REAP_MAP),get(w,E_REAP_N),0)
            e_segments(w,33,segments,2)
        else:
            e_row(w,16,33,get(w,E_ERRNO),a_at(w,E_TEXT+start),prefix_n,get(w,E_FN_PTR),get(w,E_FN_N),get(w,E_FILENAME))
    else:
        start=get(w,E_TEXT_N)
        message(w)
        e_scalar(w,33,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
    e_list(w,34)
    e_append(w,34,33)
    e_tuple(w,35,34)
    e_exception(w,15,32,35,43)
    if get(w,E_CAUSE)==1:
        os_exception(w,42)
    elif get(w,E_CAUSE)==2:
        unicode_cause(w)
    elif get(w,E_CAUSE)==3:
        reap_cause(w)
    if get(w,E_CAUSE)!=0:
        e_chain(w,15,42,1)
        e_chain(w,15,42,0)
    return jump(w,1700)

def reap_text(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1420:
        n=get(w,E_CAP_FRAME_N)
        if n>1537228672809127936:
            return a_fail(w,18,12)
        need=(8192+6*n+4095)&18446744073709547520
        put(w,E_AMOUNT,need)
        if get(w,E_REAP_MAP)!=0:
            if get(w,E_REAP_CAP)>=need:
                return reap_invoke(w)
            return call(o,w,1421,25,get(w,E_REAP_MAP),get(w,E_REAP_CAP),need,1,0,0,0)
        return a_newmap(o,w,1421,need)
    if phase==1421:
        if failed(get(w,RESULT)):
            return a_fail(w,18,errno(get(w,RESULT)))
        put(w,E_REAP_MAP,get(w,RESULT))
        put(w,E_REAP_CAP,get(w,E_AMOUNT))
        return reap_invoke(w)
    n=get(w,RESULT)
    if n<38 or n>=4294967292 or n>get(w,E_REAP_CAP):
        return a_unknown(w,1422)
    put(w,E_REAP_N,n)
    return decide_after(w)

def reap_invoke(w:mutbuf) -> u32:
    return a_invoke(w,1422,25,get(w,E_CAP_FRAME),get(w,E_CAP_FRAME_N),get(w,E_REAP_MAP),get(w,E_REAP_CAP),a_at(w,A_CODEC_WORK),8192)

def reap_cause(w:mutbuf) -> u64:
    e_class(w,36,72)
    e_dict(w,37)
    e_number(w,38,3,0)
    reap_field(w,0,50)
    reap_field(w,1,38)
    reap_field(w,2,44)
    reap_field(w,3,44)
    e_list(w,39)
    e_append(w,39,50)
    e_append(w,39,38)
    e_tuple(w,40,39)
    e_exception(w,42,36,40,37)
    e_drop(w,36)
    e_drop(w,37)
    e_drop(w,38)
    e_drop(w,39)
    e_drop(w,40)
    e_drop(w,50)
    return 0

def reap_field(w:mutbuf,which:u64,value:u64) -> u64:
    start=get(w,E_TEXT_N)
    if which==0:
        text_reap_cmd(w)
    elif which==1:
        text_reap_timeout(w)
    elif which==2:
        text_reap_output(w)
    else:
        text_reap_stderr(w)
    e_scalar(w,49,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
    e_item(w,37,49,value)
    e_drop(w,49)
    return 0

def unicode_cause(w:mutbuf) -> u64:
    text_value(w,36,4)
    e_scalar(w,37,7,get(w,E_UTF8_PTR),get(w,E_UTF8_N),0)
    e_number(w,38,get(w,E_UTF8+16),0)
    e_number(w,39,get(w,E_UTF8+24),0)
    text_value(w,40,4+get(w,E_UTF8+32))
    e_list(w,53)
    e_append(w,53,36)
    e_append(w,53,37)
    e_append(w,53,38)
    e_append(w,53,39)
    e_append(w,53,40)
    e_tuple(w,54,53)
    e_row(w,17,42,54,NONE,0,0,0,0)
    return 0

def text_value(w:mutbuf,slot:u64,which:u64) -> u64:
    start=get(w,E_TEXT_N)
    if which==1:
        text_key_code(w)
    elif which==2:
        text_key_capture(w)
    elif which==3:
        text_key_capture_error(w)
    elif which==4:
        text_utf8(w)
    elif which==5:
        text_invalid_start(w)
    elif which==6:
        text_invalid_continuation(w)
    else:
        text_unexpected_end(w)
    return e_scalar(w,slot,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)

def code_value(w:mutbuf,slot:u64) -> u64:
    start=get(w,E_TEXT_N)
    code=get(w,E_CODE)
    if code==1:
        text_code_argv(w)
    elif code==2:
        text_code_budget(w)
    elif code==3:
        text_code_env(w)
    elif code==4:
        text_code_input(w)
    elif code==5:
        text_code_input_size(w)
    elif code==6:
        text_code_ownership(w)
    elif code==7:
        text_code_exec(w)
    elif code==8:
        text_code_output_size(w)
    elif code==9:
        text_code_timeout(w)
    elif code==11:
        text_code_cleanup(w)
    else:
        text_code_encoding(w)
    return e_scalar(w,slot,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)

def message(w:mutbuf) -> u64:
    code=get(w,E_CODE)
    phase=get(w,E_PHASE)
    if code==1:
        return text_argv(w)
    if code==2:
        return text_budget(w)
    if code==3:
        return text_env(w)
    if code==4:
        return text_input(w)
    if code==5:
        return text_input_size(w)
    if code==6:
        if phase==21:
            return text_sigchld(w)
        if phase==22:
            if get(w,E_ERRNO)!=0:
                return text_nonreap_unavailable(w)
            return text_nonreap_unconfirmed(w)
        if get(w,E_ERRNO)!=0:
            return text_leader_unknown(w)
        return text_wrong_child(w)
    if code==8:
        if phase==102 or phase==103:
            return text_output_poll(w)
        if phase==301 or phase==302:
            return text_output_final(w)
        return text_output_grew(w)
    if code==9:
        return text_timeout(w)
    if get(w,get(w,E_CAPTURE)+232)==0:
        return text_encoding_stdout(w)
    return text_encoding_stderr(w)
'''
SOURCE+=file_surface.SOURCE[file_surface.SOURCE.index('\ndef os_exception('):file_surface.SOURCE.index('\ndef message(')]
TEXTS={
'reap_cmd':'cmd','reap_timeout':'timeout','reap_output':'output','reap_stderr':'stderr',
'key_code':'code','key_capture':'capture','key_capture_error':'capture_error',
'utf8':'utf-8','invalid_start':'invalid start byte','invalid_continuation':'invalid continuation byte','unexpected_end':'unexpected end of data',
'cleanup_group':'Compiler process-group termination failed: errno=', 'cleanup_reap':'Compiler leader reap was not confirmed: ', 'semicolon':'; ',
'exec':'Compiler launch failed: ','argv':'Expected a nonempty executable argv',
'budget':'Capture limits must be nonnegative integer bytes and finite time in (0,3600]s',
'env':'Invalid or oversized child environment entry','input':'Compiler stdin must be UTF-8 text','input_size':'Compiler stdin exceeds byte budget',
'sigchld':'Default SIGCHLD disposition is required','nonreap_unavailable':'Non-reaping child observation unavailable',
'nonreap_unconfirmed':'Could not confirm non-reaping child observation','leader_unknown':'Compiler leader ownership is no longer confirmed',
'wrong_child':'Child observation names another process','output_poll':'Compiler exceeded stdout/stderr byte budget',
'output_final':'Compiler output exceeded byte budget','output_grew':'Compiler output grew beyond byte budget','timeout':'Compiler exceeded wall-time budget',
'encoding_stdout':'Compiler stdout was not UTF-8','encoding_stderr':'Compiler stderr was not UTF-8',
}
for name in ['argv','budget','env','input','input_size','ownership','exec','output_size','timeout','encoding','cleanup']:TEXTS['code_'+name]='E_CAPTURE_'+name.upper()
def source():
 text=SOURCE
 for name,value in TEXTS.items():
  raw=value.encode();text+='\ndef text_'+name+'(w:mutbuf) -> u64:\n    at=E_TEXT+get(w,E_TEXT_N)\n'
  at=0
  while len(raw)-at>=8:
   text+='    put(w,at+'+str(at)+','+str(int.from_bytes(raw[at:at+8],'little'))+')\n';at+=8
  for i in range(at,len(raw)):text+='    store(w,at+'+str(i)+','+str(raw[i])+')\n'
  text+='    put(w,E_TEXT_N,get(w,E_TEXT_N)+'+str(len(raw))+')\n    return 0\n'
 return text
if __name__=='__main__':write_module('clang_value_error_capture',source())
