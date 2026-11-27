"""Native exception ordering for cleanup, evidence and final descriptor failures."""
from tools.generate_hia_clang_value_error_plan_common import C,write_module
C.update(E_PRIVATE=3520)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PHASE)!=1700:
        return 4294967293
    at=get(w,E_CAPTURE)
    code=get(w,E_CODE)
    phase=get(w,E_PHASE)
    raw=code==12 or code==13 or code==6 and phase==21 and get(w,E_ERRNO)!=0 or code==11 and phase==501
    cleanphase=get(w,at+248)>>32
    secondary=get(w,E_PRIVATE+80)!=0 and cleanphase<500
    evidence=get(w,at+200)
    if raw:
        if secondary:
            segments=error_segments(w,True,False)
            e_parts(w,51,15)
            text_scalar(w,54,1)
            e_list(w,55)
            e_segments(w,56,segments,get(w,E_NEXT))
            e_append(w,55,56)
            e_item(w,51,54,55)
            i=51
            while i<=56:
                e_drop(w,i)
                i=i+1
    else:
        if secondary or evidence==12:
            segments=error_segments(w,False,evidence==12)
            e_segments(w,62,segments,get(w,E_NEXT))
            e_item(w,43,48,62)
            e_drop(w,62)
        if evidence==13:
            memory_override(w)
        elif evidence!=0 and evidence!=12:
            return jump(w,1000)
    i=get(w,E_CLOSE_NEXT)
    while i<3:
        number=get(w,E_PRIVATE+40+i*8)
        if number!=0:
            os_override(w,number)
        i=i+1
    return jump(w,1600)

def error_segments(w:mutbuf,notes:bool,evidence:bool) -> u64:
    at=get(w,E_CAPTURE)
    phase=get(w,at+248)>>32
    secondary=get(w,E_PRIVATE+80)!=0 and phase<500
    prefix=get(w,E_TEXT_N)
    with_os=False
    with_reap=False
    if notes:
        text_notes_prefix(w)
    if secondary:
        if get(w,at+40)==6:
            text_ownership_prefix(w)
            if get(w,at+48)!=0:
                text_leader_unknown(w)
            else:
                text_wrong_child(w)
        else:
            text_cleanup_prefix(w)
            if (phase==203 or phase==206) and get(w,at+24)==1:
                text_cleanup_group(w)
                e_digits(w,get(w,at+48))
                text_semicolon(w)
            else:
                text_cleanup_reap(w)
            if (get(w,E_REAP_KIND)&2)!=0:
                with_reap=True
            else:
                with_os=True
    prefix_n=get(w,E_TEXT_N)-prefix
    middle=get(w,E_TEXT_N)
    if secondary and evidence:
        text_evidence(w)
    middle_n=get(w,E_TEXT_N)-middle
    start=E_TEXT+get(w,E_TEXT_N)
    count=0
    if prefix_n!=0:
        e_segment(w,0,a_at(w,E_TEXT+prefix),prefix_n,0)
        count=count+1
    if with_os:
        e_segment(w,1,0,0,get(w,at+48))
        count=count+1
    if with_reap:
        e_segment(w,0,get(w,E_REAP_MAP),get(w,E_REAP_N),0)
        count=count+1
    if middle_n!=0:
        e_segment(w,0,a_at(w,E_TEXT+middle),middle_n,0)
        count=count+1
    if evidence:
        e_segment(w,1,0,0,get(w,at+208))
        count=count+1
    put(w,E_NEXT,count)
    return start

def memory_override(w:mutbuf) -> u64:
    e_row(w,13,62,15,0,0,0,0,0)
    e_drop(w,15)
    e_class(w,55,27)
    e_list(w,56)
    e_tuple(w,57,56)
    e_exception(w,15,55,57,NONE)
    e_chain(w,15,62,1)
    e_drop(w,55)
    e_drop(w,56)
    e_drop(w,57)
    e_drop(w,62)
    return 0

def os_override(w:mutbuf,number:u64) -> u64:
    e_row(w,13,62,15,0,0,0,0,0)
    e_drop(w,15)
    e_class(w,55,25)
    e_number(w,56,number,0)
    e_strerror(w,57,number)
    e_list(w,58)
    e_append(w,58,56)
    e_append(w,58,57)
    e_tuple(w,59,58)
    e_os(w,15,55,59)
    e_chain(w,15,62,1)
    i=55
    while i<=59:
        e_drop(w,i)
        i=i+1
    e_drop(w,62)
    return 0

def text_scalar(w:mutbuf,slot:u64,which:u64) -> u64:
    start=get(w,E_TEXT_N)
    text_notes(w)
    return e_scalar(w,slot,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
'''
TEXTS={'notes':'__notes__','notes_prefix':'Cleanup refused: ','ownership_prefix':'E_CAPTURE_OWNERSHIP: ',
'leader_unknown':'Compiler leader ownership is no longer confirmed','wrong_child':'Child observation names another process',
'cleanup_prefix':'E_CAPTURE_CLEANUP: ','cleanup_group':'Compiler process-group termination failed: errno=',
'cleanup_reap':'Compiler leader reap was not confirmed: ','semicolon':'; ','evidence':'; capture evidence: '}
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
if __name__=='__main__':write_module('clang_value_error_secondary',source())
