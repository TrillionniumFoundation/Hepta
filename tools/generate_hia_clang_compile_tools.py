"""Measured native host and real Clang discovery/version admission."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==200:
        clear(w,P_UNAME,390)
        return call(o,w,201,63,P_UNAME,0,0,0,0,0,3)
    if phase==201:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        if linux(w,P_UNAME)==False or x86(w,P_UNAME+260)==False:
            return p_fail(w,E_PROFILE,2)
        put(w,P_HOST,0)
        return p_frame(o,w,32+get(w,P_TOOL_N),203)
    if phase==203:
        return p_buffer(w,204,0,get(w,P_SOURCE)+get(w,P_TOOL_AT),get(w,P_TOOL_N),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==204:
        if r!=32+get(w,P_TOOL_N):
            return p_fail(w,E_CONTEXT,204)
        put(w,P_WHICH_ACTIVE,1)
        return p_invoke(w,205,R_WHICH,get(w,P_FRAME),r,p_at(w,P_SUBOUT),128,p_at(w,P_WHICH_WORK),4096)
    if phase==205:
        if r!=0 or get(w,P_SUBOUT)!=WHICH_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,205)
        if get(w,P_SUBOUT+8)!=0:
            return p_fail(w,E_TOOL,get(w,P_SUBOUT+16))
        put(w,P_FOUND_N,get(w,P_SUBOUT+24))
        put(w,P_FOUND_PTR,get(w,P_SUBOUT+32))
        return p_frame(o,w,32+get(w,P_FOUND_N),207)
    if phase==207:
        return p_buffer(w,208,1,get(w,P_FOUND_PTR),get(w,P_FOUND_N),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==208:
        if r!=32+get(w,P_FOUND_N):
            return p_fail(w,E_CONTEXT,208)
        put(w,P_PATH_ACTIVE,1)
        return p_invoke(w,209,R_PATH,get(w,P_FRAME),r,p_at(w,P_SUBOUT),128,p_at(w,P_PATH_WORK),200704)
    if phase==209:
        if r!=0 or get(w,P_SUBOUT)!=PATH_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,209)
        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+88)!=1 or get(w,P_SUBOUT+96)!=1 or get(w,P_SUBOUT+104)!=0 or get(w,P_SUBOUT+112)!=1 or get(w,P_SUBOUT+120)!=0:
            return p_fail(w,E_TOOL,get(w,P_SUBOUT+16))
        if get(w,P_SUBOUT+32)==NONE or get(w,P_SUBOUT+48)!=15:
            return p_fail(w,E_CONTEXT,210)
        put(w,P_PATH_FD,get(w,P_SUBOUT+32))
        n=get(w,P_SUBOUT+40)
        put(w,P_COMPILER_N,n)
        pn=get(w,P_PATH_N)
        if pn>(9223372036854771712-65792)//5 or n>9223372036854771712-65792-5*pn:
            return p_fail(w,E_MEMORY,12)
        off=5*(pn+8)+96
        put(w,P_COMPILER_OFF,off)
        inv=(off+n+8)&18446744073709551608
        put(w,P_INV_OFF,inv)
        need=(inv+65536+4095)&18446744073709547520
        put(w,P_STR_NEED,need)
        return call(o,w,211,9,0,need,3,34,NONE,0,0)
    if phase==211:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_STRINGS,r)
        put(w,P_STRINGS_CAP,get(w,P_STR_NEED))
        put(w,P_IO_AT,0)
        return read_compiler(o,w)
    if phase==212:
        if failed(r):
            if errno(r)==4:
                return read_compiler(o,w)
            return p_fail(w,E_TOOL,errno(r))
        if r==0 or r>get(w,P_COMPILER_N)-get(w,P_IO_AT):
            return p_fail(w,E_TOOL,5)
        put(w,P_IO_AT,get(w,P_IO_AT)+r)
        return read_compiler(o,w)
    if phase==214:
        if r!=0:
            return p_fail(w,E_CONTEXT,214)
        return p_file(o,w,220,0,0,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N),1073741824,0,0,0,0)
    if phase==220:
        p_saved_copy(w,P_FILE_RESULT+128,P_TOOL_SHA,32)
        return p_capture(o,w,230,0)
    if phase==230:
        at=P_CAPTURE_OUT
        put(w,P_VERSION_CODE,get(w,at+32))
        n=get(w,at+112)
        if n>196608:
            return p_fail(w,E_CONTEXT,230)
        put(w,P_VERSION_FULL_N,n)
        return p_copy(w,231,get(w,at+104),p_at(w,P_VERSION),n)
    if phase==231:
        if r!=0:
            return p_fail(w,E_CONTEXT,231)
        return p_capture(o,w,240,1)
    if phase==240:
        at=P_CAPTURE_OUT+256
        put(w,P_DRIVER_CODE,get(w,at+32))
        n=get(w,at+112)
        if n>196608:
            return p_fail(w,E_CONTEXT,240)
        put(w,P_DRIVER_FULL_N,n)
        return p_copy(w,241,get(w,at+104),p_at(w,P_DRIVER),n)
    if phase==241:
        if r!=0:
            return p_fail(w,E_CONTEXT,241)
        if get(w,P_VERSION_CODE)!=0 or get(w,P_DRIVER_CODE)!=0 or version(w)==False or driver(w)==False:
            return p_fail(w,E_TOOL,241)
        return p_buffer(w,249,3,get(w,P_SOURCE)+get(w,P_PATH_AT),get(w,P_PATH_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    if phase==249:
        if r!=0:
            return p_fail(w,E_DESTINATION,22)
        return call(o,w,250,4,get(w,P_STRINGS)+get(w,P_DEST_OFF),P_STAT,0,0,0,0,12)
    if phase==250:
        if failed(r)==False:
            return p_fail(w,E_DESTINATION,17)
        return call(o,w,251,6,get(w,P_STRINGS)+get(w,P_DEST_OFF),P_STAT,0,0,0,0,12)
    if phase==251:
        if failed(r)==False and get(w,P_STAT+24)&61440==40960:
            return p_fail(w,E_DESTINATION,17)
        return call(o,w,252,4,get(w,P_STRINGS)+get(w,P_PARENT_OFF),P_STAT,0,0,0,0,12)
    if phase==252:
        if failed(r) or get(w,P_STAT+24)&61440!=16384:
            return p_fail(w,E_DESTINATION,20)
        return call(o,w,253,2,get(w,P_STRINGS)+get(w,P_PARENT_OFF),589824,0,0,0,0,0)
    if phase==253:
        if failed(r):
            return p_fail(w,E_TEMP,errno(r))
        put(w,P_PARENT_FD,r)
        return jump(w,300)
    return 4294967293

def read_compiler(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,P_IO_AT)
    n=get(w,P_COMPILER_N)
    if at==n:
        return p_buffer(w,214,2,get(w,P_SOURCE),get(w,P_SOURCE_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    return call(o,w,212,17,get(w,P_PATH_FD),get(w,P_STRINGS)+get(w,P_COMPILER_OFF)+at,n-at,at,0,0,0)

def version(w:mutbuf) -> bool:
    n=get(w,P_VERSION_FULL_N)
    at=0
    found=False
    while at+17<=n:
        if clang_version(w,P_VERSION+at):
            a=byte(w,P_VERSION+at+14)
            b=byte(w,P_VERSION+at+15)
            if a>=50 and a<=57 and b>=48 and b<=57 and byte(w,P_VERSION+at+16)==46:
                found=True
        at=at+1
    line=0
    scanning=True
    while line<n and scanning:
        a=byte(w,P_VERSION+line)
        if a==10 or a==13 or a==11 or a==12 or a==28 or a==29 or a==30:
            scanning=False
        elif a==194 and line+1<n and byte(w,P_VERSION+line+1)==133:
            scanning=False
        elif a==226 and line+2<n and byte(w,P_VERSION+line+1)==128 and (byte(w,P_VERSION+line+2)==168 or byte(w,P_VERSION+line+2)==169):
            scanning=False
        else:
            line=line+1
    put(w,P_VERSION_N,line)
    return found

def white(w:mutbuf,at:u64,n:u64) -> u64:
    if n==0:
        return 0
    a=byte(w,at)
    if a>=9 and a<=13 or a>=28 and a<=32:
        return 1
    if n>=2 and a==194:
        b=byte(w,at+1)
        if b==133 or b==160:
            return 2
    if n>=3:
        b=byte(w,at+1)
        c=byte(w,at+2)
        if a==225 and b==154 and c==128:
            return 3
        if a==226 and b==128 and (c>=128 and c<=138 or c==168 or c==169 or c==175):
            return 3
        if a==226 and b==129 and c==159:
            return 3
        if a==227 and b==128 and c==128:
            return 3
    return 0

def driver(w:mutbuf) -> bool:
    n=get(w,P_DRIVER_FULL_N)
    first=0
    scan=True
    while first<n and scan:
        step=white(w,P_DRIVER+first,n-first)
        if step==0:
            scan=False
        else:
            first=first+step
    at=first
    last=first
    while at<n:
        step=white(w,P_DRIVER+at,n-at)
        if step==0:
            at=at+1
            last=at
        else:
            at=at+step
    size=last-first
    good=False
    if size==24:
        good=driver_unknown(w,P_DRIVER+first)
    elif size==19:
        good=driver_pc(w,P_DRIVER+first)
    elif size==16:
        good=driver_short(w,P_DRIVER+first)
    if good:
        i=0
        while i<size:
            store(w,P_DRIVER+i,byte(w,P_DRIVER+first+i))
            i=i+1
        put(w,P_DRIVER_N,size)
    return good
'''
def match(name,text,nul=False):
 raw=text.encode();lines=[f'def {name}(w:mutbuf,at:u64) -> bool:']
 for i,b in enumerate(raw+ (b'\0'if nul else b'')):
  lines += [f'    if byte(w,at+{i})!={b}:','        return False']
 lines += ['    return True'];return '\n'.join(lines)
for name,text,nul in [('linux','Linux',True),('x86','x86_64',True),('clang_version','clang version ',False),('driver_unknown','x86_64-unknown-linux-gnu',False),('driver_pc','x86_64-pc-linux-gnu',False),('driver_short','x86_64-linux-gnu',False)]:
 SOURCE+='\n'+match(name,text,nul)
if __name__=='__main__':write_module('clang_compile_tools',SOURCE)
