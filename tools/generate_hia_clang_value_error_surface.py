"""Native stable-file and source-identity exception types and cause graphs."""
from tools.generate_hia_clang_value_error_plan_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PHASE)!=1200:
        return 4294967293
    put(w,E_PLAN_COUNT,0)
    put(w,E_PLAN_INDEX,0)
    put(w,E_TEXT_N,0)
    put(w,E_BAD,0)
    put(w,E_FN_PTR,0)
    put(w,E_FN_N,0)
    put(w,E_FILENAME,0)
    put(w,E_CAUSE,0)
    if get(w,A_INNER_WORK+2544)==0x3146434543414948 and get(w,E_CLEAN_STAGE)==0 and get(w,E_EARLY)==0:
        put(w,E_CLEAN_STAGE,1)
        put(w,E_TOP_ERROR,get(w,ERROR))
        put(w,E_TOP_ERRNO,get(w,ERROR_NO))
        put(w,ERROR,get(w,A_INNER_WORK+16))
        put(w,ERROR_NO,10000+get(w,A_INNER_WORK+24))
        phase=get(w,A_INNER_WORK+696)
        if get(w,ERROR)==0 or (get(w,A_INNER_WORK+2552)==2 and (phase==870 or phase==871)):
            return jump(w,2100)
    error=get(w,ERROR)
    phase=get(w,A_INNER_WORK+696)
    if error==11 and phase>=512 and phase<=516:
        return jump(w,2000)
    if error==10:
        if phase==501 or phase==518 or phase==60 and get(w,A_INNER_WORK+24)==61:
            return jump(w,2000)
    if error==6 and (phase==301 or phase==304 or phase==307) or error==12 and phase==308:
        return jump(w,2000)
    if get(w,ERROR)==9:
        return jump(w,1900)
    at=A_INNER_WORK+2112
    if get(w,A_INNER_WORK+2368)!=0x3146455643414948:
        if get(w,A_INNER_WORK+696)==843:
            return jump(w,1400)
        return jump(w,1000)
    kind=get(w,A_INNER_WORK+2376)
    if kind!=1 and kind!=2:
        return jump(w,1000)
    code=get(w,at+8)
    phase=get(w,at+24)
    number=get(w,at+16)
    cls=49
    index=get(w,A_INNER_WORK+2392)
    if kind==2:
        if get(w,at+120)!=0x3130464549414948:
            return jump(w,1000)
        code=get(w,at+88)
        phase=get(w,at+96)
        file=A_INNER_WORK+293601280
        ptr=get(w,file+72)+get(w,file+88)+192
        n=get(w,file+96)
        if n<193:
            return a_unknown(w,1200)
        put(w,E_FN_PTR,ptr)
        put(w,E_FN_N,n-193)
    else:
        if index>2:
            return a_unknown(w,1200)
        if index==1:
            cls=45
        elif index==2:
            cls=50
        put(w,E_FN_PTR,get(w,A_INNER_WORK+616)+get(w,A_INNER_WORK+1600))
        put(w,E_FN_N,get(w,A_INNER_WORK+1608))
    if code==0:
        return jump(w,1000)
    put(w,E_CODE,code)
    put(w,E_PHASE,phase)
    put(w,E_ERRNO,number)
    put(w,E_CLASS,cls)
    if code==2:
        if phase==20 or phase==22 or phase==43:
            put(w,E_FILENAME,1)
        if cls==45:
            os_exception(w,15)
            return jump(w,1600)
        put(w,E_CAUSE,1)
    elif code!=3 and code!=4:
        return jump(w,1000)
    e_class(w,32,cls)
    start=get(w,E_TEXT_N)
    message(w)
    e_scalar(w,33,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
    e_list(w,34)
    e_append(w,34,33)
    e_tuple(w,35,34)
    e_exception(w,15,32,35,NONE)
    if get(w,E_CAUSE)!=0:
        os_exception(w,42)
        e_chain(w,15,42,1)
        e_chain(w,15,42,0)
    return jump(w,1600)

def os_exception(w:mutbuf,dst:u64) -> u64:
    e_class(w,36,25)
    e_number(w,37,get(w,E_ERRNO),0)
    e_strerror(w,38,get(w,E_ERRNO))
    e_list(w,39)
    e_append(w,39,37)
    e_append(w,39,38)
    if get(w,E_FILENAME)!=0:
        e_fs(w,40,get(w,E_FN_PTR),get(w,E_FN_N))
        e_append(w,39,40)
    e_tuple(w,41,39)
    e_os(w,dst,36,41)
    return 0

def message(w:mutbuf) -> u64:
    cls=get(w,E_CLASS)
    code=get(w,E_CODE)
    phase=get(w,E_PHASE)
    if cls==49:
        if code==2:
            return text_tool_io(w)
        if code==3:
            return text_tool_shape(w)
        if phase==23:
            return text_tool_before(w)
        if phase==43:
            return text_tool_path(w)
        return text_tool_during(w)
    if cls==50:
        if code==2:
            return text_pub_io(w)
        if code==3:
            return text_pub_identity(w)
        if phase==20:
            if get(w,A_INNER_WORK+1512)==0:
                return text_pub_bytes(w)
            return text_pub_identity(w)
        if phase==23:
            return text_pub_before(w)
        if phase==43:
            return text_pub_path(w)
        return text_pub_bytes(w)
    if code==3:
        return text_art_shape(w)
    if phase==23:
        return text_art_before(w)
    if phase==43:
        return text_art_path(w)
    return text_art_during(w)
'''
TEXTS={
'tool_io':'E_TOOL_IDENTITY: unable to hash stable ordinary file',
'tool_shape':'E_TOOL_IDENTITY: expected bounded ordinary file',
'tool_before':'E_TOOL_IDENTITY: file replaced before read',
'tool_during':'E_TOOL_IDENTITY: file mutated during read',
'tool_path':'E_TOOL_IDENTITY: file path replaced',
'pub_io':'E_PUBLISH_IO: file not available for exact read',
'pub_identity':'E_PUBLISH_IDENTITY: ordinary file identity mismatch',
'pub_before':'E_PUBLISH_RACE: file changed before read',
'pub_path':'E_PUBLISH_RACE: pathname changed during verification',
'pub_bytes':'E_PUBLISH_BYTES: staged/published content changed',
'art_shape':'E_HIA_PROGRAM_LLVM: native artifact must be a bounded ordinary nonempty file',
'art_before':'E_HIA_PROGRAM_LLVM: artifact changed before reading',
'art_path':'E_HIA_PROGRAM_LLVM: artifact pathname changed during reading',
'art_during':'E_HIA_PROGRAM_LLVM: artifact changed during reading',
}
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
if __name__=='__main__':write_module('clang_value_error_surface',source())
