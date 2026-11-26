"""Actual canonical exception objects and exact protocol TypeError messages."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    if phase==1000:
        error=get(w,ERROR)
        put(w,A_ERROR_CLASS,45)
        if error==16:
            put(w,A_ERROR_CLASS,23)
            put(w,A_NAME_INDEX,0)
            slot=0
            if get(w,A_ERROR_SELECTOR)==125:
                slot=6
            return a_simple(w,1001,A_V6,36,slot)
        if error==18 or error==13:
            put(w,A_ERROR_CLASS,27)
        return jump(w,1008)
    if phase==1001 or phase==1005:
        slot=20
        if phase==1005:
            slot=22
        if a_ordinary(w)==False or a_capture(w,slot,A_VR+24)==False:
            return a_value_failed(w,phase)
        a_request(w,A_V6,38)
        a_arg(w,slot,24)
        return a_value(w,phase+1,128)
    if phase==1002 or phase==1006:
        slot=21
        if phase==1006:
            slot=23
        if a_ordinary(w)==False or a_capture(w,slot,A_VR+24)==False:
            return a_value_failed(w,phase)
        return a_simple(w,phase+1,A_V6,7,slot)
    if phase==1003 or phase==1007:
        if a_ordinary(w)==False or get(w,A_VR+16)!=4:
            return a_unknown(w,phase)
        put(w,A_NAME_LENGTH,get(w,A_VR+72))
        put(w,A_NAME_OFFSET,0)
        put(w,A_NAME_N,0)
        return name_read(w)
    if phase==1004:
        if a_ordinary(w)==False or get(w,A_VR+64)!=get(w,A_AMOUNT):
            return a_unknown(w,1004)
        at=choose(get(w,A_NAME_INDEX)==0,A_NAME1,A_NAME2)
        i=0
        count=get(w,A_NAME_N)
        while i<get(w,A_AMOUNT):
            b=byte(w,A_VR+8192+i)
            if b==46:
                count=0
            elif count<200:
                store(w,at+count,b)
                count=count+1
            i=i+1
        put(w,A_NAME_N,count)
        put(w,A_NAME_OFFSET,get(w,A_NAME_OFFSET)+get(w,A_AMOUNT))
        return name_read(w)
    if phase==1008:
        put(w,A_ERROR_N,0)
        message(w)
        if get(w,A_ERROR_CLASS)==27:
            return request_class(w)
        if get(w,ERROR)==7 and get(w,A_INNER_ACTIVE)==1:
            at=A_INNER_WORK+2300000+512
            ptr=get(w,at+120)
            n=get(w,at+128)
            if n>3145728 or (n!=0 and ptr==0):
                return a_unknown(w,1020)
            put(w,A_BUFFER_OP,4)
            return a_invoke(w,1020,4,ptr,n,a_at(w,A_ERROR_FRAME+128+get(w,A_ERROR_N)),65536-128-get(w,A_ERROR_N),a_at(w,0),A_WORK)
        return message_value(w)
    if phase==1020:
        n=get(w,RESULT)
        if n>12000:
            return a_unknown(w,1020)
        put(w,A_ERROR_N,get(w,A_ERROR_N)+n)
        return message_value(w)
    if phase==1010:
        if a_ordinary(w)==False or a_capture(w,17,A_VR+24)==False:
            return a_value_failed(w,1010)
        return request_class(w)
    if phase==1011:
        if a_ordinary(w)==False or a_capture(w,16,A_VR+24)==False:
            return a_value_failed(w,1011)
        return a_simple(w,1012,A_V1,3,NONE)
    if phase==1012:
        if a_ordinary(w)==False or a_capture(w,18,A_VR+24)==False:
            return a_value_failed(w,1012)
        if get(w,A_ERROR_CLASS)==27:
            return a_simple(w,1014,A_V4,40,18)
        a_request(w,A_V1,16)
        a_arg(w,18,24)
        a_arg(w,17,48)
        return a_value(w,1013,128)
    if phase==1013:
        if a_ordinary(w)==False:
            return a_value_failed(w,1013)
        return a_simple(w,1014,A_V4,40,18)
    if phase==1014:
        if a_ordinary(w)==False or a_capture(w,19,A_VR+24)==False:
            return a_value_failed(w,1014)
        a_request(w,A_V5,75)
        a_arg(w,16,24)
        a_arg(w,19,48)
        return a_value(w,1015,128)
    if phase==1015:
        if a_ordinary(w)==False or a_capture(w,15,A_VR+24)==False:
            return a_value_failed(w,1015)
        return jump(w,700)
    return 4294967293

def message_value(w:mutbuf) -> u32:
    clear(w,A_ERROR_FRAME,128)
    put(w,A_ERROR_FRAME,A_V1)
    put(w,A_ERROR_FRAME+8,2)
    put(w,A_ERROR_FRAME+96,get(w,A_ERROR_N))
    put(w,A_ERROR_FRAME+104,4)
    return a_invoke(w,1010,1,a_at(w,A_ERROR_FRAME),128+get(w,A_ERROR_N),a_at(w,A_VR),A_VR_N,get(w,A_VALUE_WORK),get(w,A_VALUE_WORK_N))

def request_class(w:mutbuf) -> u32:
    kind=get(w,A_ERROR_CLASS)
    a_request(w,choose(kind>=43,A_V5,A_V6),choose(kind>=43,98,32))
    put(w,A_RQ+104,kind)
    return a_value(w,1011,128)

def name_read(w:mutbuf) -> u32:
    at=get(w,A_NAME_OFFSET)
    n=get(w,A_NAME_LENGTH)
    if at==n:
        which=get(w,A_NAME_INDEX)
        base=choose(which==0,A_NAME1,A_NAME2)
        count=truncate_name(w,base,get(w,A_NAME_N))
        put(w,choose(which==0,A_NAME1_N,A_NAME2_N),count)
        if which==0 and get(w,A_ERROR_SELECTOR)==123:
            put(w,A_NAME_INDEX,1)
            return a_simple(w,1005,A_V6,36,11)
        return jump(w,1008)
    amount=n-at
    if amount>8192:
        amount=8192
    put(w,A_AMOUNT,amount)
    a_request(w,A_V6,19)
    a_arg(w,choose(get(w,A_NAME_INDEX)==0,21,23),24)
    put(w,A_RQ+104,at)
    put(w,A_RQ+112,amount)
    return a_value(w,1004,128)

def truncate_name(w:mutbuf,at:u64,n:u64) -> u64:
    if n==0:
        return 0
    p=n-1
    while p!=0 and byte(w,at+p)>=128 and byte(w,at+p)<192:
        p=p-1
    b=byte(w,at+p)
    size=1
    if b>=194 and b<=223:
        size=2
    elif b>=224 and b<=239:
        size=3
    elif b>=240:
        size=4
    if p+size<=n:
        return n
    return p

def append_name(w:mutbuf,which:u64) -> u64:
    at=choose(which==0,A_NAME1,A_NAME2)
    n=get(w,choose(which==0,A_NAME1_N,A_NAME2_N))
    pos=get(w,A_ERROR_N)
    a_within(w,A_ERROR_FRAME+128+pos,at,n)
    put(w,A_ERROR_N,pos+n)
    return 0

def message(w:mutbuf) -> u64:
    error=get(w,ERROR)
    detail=get(w,A_ERROR_SELECTOR)
    if error==16:
        if detail==123:
            text_expected(w)
            append_name(w,0)
            text_result(w)
            append_name(w,1)
        elif detail==125:
            text_quote(w)
            append_name(w,0)
            text_not_callable(w)
        elif detail==601:
            text_path_bytes(w)
        elif detail==602:
            text_mix(w)
        else:
            text_missing(w)
            append_name(w,0)
    elif error==4 and detail==10241:
        text_profile(w)
    elif error==17 or error==4:
        text_no_clang(w)
    elif error==5:
        text_destination(w)
    elif error==10:
        text_stale(w)
    elif error==3:
        text_profile(w)
    elif error==7:
        text_compile(w)
    elif error==1:
        text_verify(w)
    elif error==2:
        text_ir(w)
    elif error==9:
        text_inventory(w)
    elif error!=18 and error!=13:
        text_native_failure(w)
    return 0
'''
TEXTS={
'missing':'expected str, bytes or os.PathLike object, not ',
'expected':'expected ',
'result':'.__fspath__() to return str or bytes, not ',
'quote':"'",
'not_callable':"' object is not callable",
'path_bytes':"argument should be a str or an os.PathLike object where __fspath__ returns a str, not 'bytes'",
'mix':"Can't mix strings and bytes in path components",
'no_clang':'E_HIA_PROGRAM_LLVM: actual Clang 20+ is required',
'destination':'E_HIA_PROGRAM_LLVM: a new output path in an existing directory is required',
'stale':'E_HIA_PROGRAM_STALE: native compiler or HIA implementation changed during compilation',
'profile':'E_HIA_PROGRAM_LLVM: expected an actual Clang 20+ GNU/Linux driver matching the measured native host',
'compile':'E_HIA_PROGRAM_NATIVE: Clang rejected independently verified HIA LLVM: ',
'verify':'E_HIA_PROGRAM_ORIGIN: LLVM differs from independently reverified standalone program',
'ir':'E_HIA_PROGRAM_LLVM: generated LLVM exceeds the closed textual profile',
'inventory':'E_HIA_PROGRAM_LLVM: object import/export inventory differs from the closed core ABI',
'native_failure':'E_HIA_PROGRAM_LLVM: native build failed'}
def source():
 text=SOURCE
 for name,value in TEXTS.items():
  raw=value.encode();text+='\ndef text_'+name+'(w:mutbuf) -> u64:\n    at=A_ERROR_FRAME+128+get(w,A_ERROR_N)\n'
  at=0
  while len(raw)-at>=8:
   text+='    put(w,at+'+str(at)+','+str(int.from_bytes(raw[at:at+8],'little'))+')\n';at+=8
  for i in range(at,len(raw)):text+='    store(w,at+'+str(i)+','+str(raw[i])+')\n'
  text+='    put(w,A_ERROR_N,get(w,A_ERROR_N)+'+str(len(raw))+')\n    return 0\n'
 return text
if __name__=='__main__':write_module('clang_value_exceptions',source())
