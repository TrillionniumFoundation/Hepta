"""Native public filesystem and publication exception graphs."""
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PHASE)!=2000:
        return 4294967293
    error=get(w,ERROR)
    phase=get(w,A_INNER_WORK+696)
    number=get(w,A_INNER_WORK+24)
    if error==10:
        e_class(w,32,45)
        start=get(w,E_TEXT_N)
        if phase==518 or phase==60 and get(w,A_INNER_WORK+704)==520:
            text_stale_publication(w)
        else:
            text_stale_compilation(w)
        wrapper(w,start)
        return jump(w,1600)
    if error==11:
        e_class(w,32,50)
        start=get(w,E_TEXT_N)
        if phase==515:
            text_link(w)
        elif phase==516:
            text_staged_race(w)
        else:
            text_exists(w)
        wrapper(w,start)
        if phase==515:
            os_error(w,44,number,2,False)
            e_chain(w,15,44,1)
            e_chain(w,15,44,0)
        return jump(w,1600)
    if error==6 or error==12:
        filenames=0
        exhausted=False
        if phase==304:
            filenames=1
            exhausted=number==17 and get(w,A_INNER_WORK+1144)==20
        elif phase==307:
            filenames=3
        os_error(w,15,number,filenames,exhausted)
        return jump(w,1600)
    return a_unknown(w,2000)

def wrapper(w:mutbuf,start:u64) -> u64:
    e_scalar(w,33,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
    e_list(w,34)
    e_append(w,34,33)
    e_tuple(w,35,34)
    e_exception(w,15,32,35,NONE)
    return 0

def os_error(w:mutbuf,dst:u64,number:u64,filenames:u64,exhausted:bool) -> u64:
    e_class(w,36,25)
    e_number(w,37,number,0)
    if exhausted:
        start=get(w,E_TEXT_N)
        text_exhausted(w)
        e_scalar(w,38,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
    else:
        e_strerror(w,38,number)
    e_list(w,39)
    e_append(w,39,37)
    e_append(w,39,38)
    if exhausted==False and filenames!=0:
        off=912
        size=904
        if filenames==2:
            off=944
            size=936
        elif filenames==3:
            off=928
            size=920
        ptr=get(w,A_INNER_WORK+616)+get(w,A_INNER_WORK+off)
        n=get(w,A_INNER_WORK+size)
        if ptr==0 or n==0:
            put(w,E_BAD,1)
            return 0
        e_fs(w,40,ptr,n)
        e_append(w,39,40)
        if filenames==2:
            e_none(w,41)
            e_append(w,39,41)
            e_fs(w,42,get(w,A_INNER_WORK+616)+get(w,A_INNER_WORK+880),get(w,A_INNER_WORK+872))
            e_append(w,39,42)
    e_tuple(w,43,39)
    e_os(w,dst,36,43)
    return 0
'''
TEXTS={
 'stale_compilation':'E_HIA_PROGRAM_STALE: native compiler or HIA implementation changed during compilation',
 'stale_publication':'E_HIA_PROGRAM_STALE: native compiler or HIA implementation changed during publication',
 'exists':'E_PUBLISH_EXISTS: output must be a new file',
 'link':'E_PUBLISH_LINK: no-replace link failed',
 'staged_race':'E_PUBLISH_RACE: staged identity or payload changed',
 'exhausted':'No usable temporary directory name found'}
def source():
 text=SOURCE
 for name,value in TEXTS.items():
  raw=value.encode('ascii');text+='\ndef text_'+name+'(w:mutbuf) -> u64:\n    at=E_TEXT+get(w,E_TEXT_N)\n'
  i=0
  while len(raw)-i>=8:
   text+='    put(w,at+'+str(i)+','+str(int.from_bytes(raw[i:i+8],'little'))+')\n';i+=8
  for j in range(i,len(raw)):text+='    store(w,at+'+str(j)+','+str(raw[j])+')\n'
  text+='    put(w,E_TEXT_N,get(w,E_TEXT_N)+'+str(len(raw))+')\n    return 0\n'
 return text
if __name__=='__main__':write_module('clang_value_error_fileflow',source())
