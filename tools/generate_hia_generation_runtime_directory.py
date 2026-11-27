"""Native ordered Path(directory).absolute() consumer for Runtime construction.

This private component is called only after the actual coordinator has finished
admission and the optional totality proof. Inputs contain actual Value caps.
All dependencies are fixed native links to the one Value arena and the existing
absolute/gettempdir components; no request supplies an entry or context.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_clang_capture_common as base
from tools import generate_hia_clang_value_common as old
from tools import generate_hia_clang_value_coercion as coercion
from tools import generate_hia_clang_value_path as path
from tools import generate_hia_clang_value_buffers as buffers
ROOT=Path(__file__).resolve().parents[1]
C=dict(old.C)
C.update(A_WORK=524288,A_VR_N=32768,A_REPLY_N=32768,
 DQ=int.from_bytes(b'HIARTDQ1','little'),DR=int.from_bytes(b'HIARTDR1','little'),
 DX=int.from_bytes(b'HIARTDW1','little'),
 ABSQ=int.from_bytes(b'HIAGPAQ1','little'),ABSR=int.from_bytes(b'HIAGPAR1','little'),
 TEMPQ=int.from_bytes(b'HIAGTDQ1','little'),TEMPR=int.from_bytes(b'HIAGTDR1','little'),
 A_V7=int.from_bytes(b'HIABVQ07','little'),A_V9=int.from_bytes(b'HIABVQ09','little'),
 A_V11=int.from_bytes(b'HIABVQ11','little'),
 D_FILE=896,D_FILE_N=904,D_ABS_ACTIVE=912,D_OP=920,D_RETURNED=928,
 D_READY=936,D_READ_SOURCE=944,D_TEMP_CONTEXT=952,D_AFTER_CLEAN=960,
 D_ABS_WORK=98304,D_PURE_WORK=65536,D_TYPE_QUERY=968,D_PATHBUF=327680,A_WINDOWS=976,
 R_CONTEXT=int.from_bytes(b'HIARTCW1','little'),R_ERROR=int.from_bytes(b'HIARTDE1','little'),
 R_PTR=512,R_EXTENT=520,R_READY=528,R_META=560,R_REQUEST=31457280,R_OUTPUT=31465472)
SOURCE=r'''
def directory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)==131072:
        return runtime_controller(s,o,w)
    if length(w)==32:
        return pure(s,o,w)
    if length(s)!=128 or length(o)<32768 or length(w)!=A_WORK:
        return 4294967293
    phase=get(w,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1 or phase==2:
        return binding(s,o,w,phase)
    if phase>=100 and phase<200:
        return coercing(s,o,w)
    if phase>=200 and phase<300:
        return parts(s,o,w)
    if phase>=500 and phase<600:
        return absolute_path(o,w,phase)
    if phase>=600 and phase<700:
        return bytes_result(o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word(s,0)!=DQ or word(s,8)>1:
        return 4294967293
    op=word(s,8)
    if op==0 and word(s,24)==0:
        return 4294967293
    i=16
    while i<128:
        if op!=0 or i<24 or i>40:
            if word(s,i)!=0:
                return 4294967293
        i=i+8
    put(w,PHASE,1)
    return 4

def binding(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if get(w,0)!=0:
            if get(w,0)!=DX or get(w,A_BASE)!=get(o,128):
                return 4294967293
            if get(w,A_VALUE_ENTRY)!=get(o,136) or get(w,A_VALUE_WORK)!=get(o,144):
                return 4294967293
        put(w,D_OP,word(s,8))
        return call(o,w,2,39,0,0,0,0,0,0,0)
    if get(w,RESULT)<2 or get(w,RESULT)>2147483647:
        return 4294967293
    if get(w,0)!=0 and get(w,8)!=get(w,RESULT):
        return 4294967293
    if get(w,0)==0:
        if word(s,8)!=0:
            clear(o,0,128)
            put(o,0,DR)
            put(o,88,1)
            put(o,104,1)
            return 0
        pid=get(w,RESULT)
        clear(w,0,4096)
        put(w,0,DX)
        put(w,8,pid)
        put(w,A_BASE,get(o,128))
        put(w,A_VALUE_ENTRY,get(o,136))
        put(w,A_VALUE_WORK,get(o,144))
        put(w,A_VALUE_WORK_N,256)
        put(w,D_TEMP_CONTEXT,get(o,152))
        put(w,A_STATE,1)
        put(w,D_FILE,NONE)
        a_request(w,A_V5,91)
        copied(s,w,24,A_RQ+24,24)
        return a_value(w,100,128)
    if word(s,8)==0:
        return 4294967293
    if get(w,A_UNKNOWN)!=0:
        return finish(o,w)
    put(w,A_CLEAN_ERROR,0)
    put(w,A_CLEAN_ERRNO,0)
    return jump(w,700)

def absolute_path(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(w,RESULT)
    if phase==500:
        return a_newmap(o,w,501,128+get(w,A_RAW_N))
    if phase==501:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_RAW_MAP,r)
        put(w,A_RAW_CAP,(get(w,A_RAW_N)+4223)&18446744073709547520)
        put(w,A_OFFSET,0)
        return read_value(w)
    if phase==502:
        if a_ordinary(w)==False or get(w,A_VR+64)!=get(w,A_AMOUNT):
            return a_value_failed(w,502)
        return a_copy(w,503,a_at(w,A_VR+8192),get(w,A_RAW_MAP)+128+get(w,A_OFFSET),get(w,A_AMOUNT))
    if phase==503:
        if r!=0:
            return a_unknown(w,503)
        put(w,A_OFFSET,get(w,A_OFFSET)+get(w,A_AMOUNT))
        return read_value(w)
    if phase==510:
        return a_newmap(o,w,511,get(w,A_RAW_CAP))
    if phase==511:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_PATH_MAP,r)
        put(w,A_PATH_CAP,get(w,A_RAW_CAP))
        put(w,D_PURE_WORK,1)
        return a_invoke(w,512,4,get(w,A_RAW_MAP)+128,get(w,A_RAW_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,D_PURE_WORK),32)
    if phase==512:
        if r==0 or r>get(w,A_PATH_CAP)-128:
            return a_unknown(w,512)
        put(w,A_RAW_N,r)
        put(w,D_PURE_WORK,0)
        put(w,D_PURE_WORK+8,r)
        return a_invoke(w,513,4,0,0,get(w,A_PATH_MAP)+96,32,a_at(w,D_PURE_WORK),32)
    if phase==513:
        if r!=0:
            return a_unknown(w,513)
        clear(w,D_ABS_WORK,200704)
        put(w,D_ABS_ACTIVE,1)
        return a_invoke(w,514,2,get(w,A_PATH_MAP)+96,32+get(w,A_RAW_N),a_at(w,A_VR),128,a_at(w,D_ABS_WORK),200704)
    if phase==514:
        if r!=0 or get(w,A_VR)!=ABSR or get(w,A_VR+56)>1 or get(w,A_VR+72)>1:
            return a_unknown(w,514)
        if get(w,A_VR+72)!=0:
            return a_unknown(w,515)
        if get(w,A_VR+56)==0:
            put(w,D_ABS_ACTIVE,0)
        if get(w,A_VR+8)!=0 or get(w,A_VR+56)!=0:
            return a_fail(w,20,get(w,A_VR+16))
        if get(w,A_VR+32)<3 or get(w,A_VR+32)>2147483647 or get(w,A_VR+48)!=15:
            return a_unknown(w,516)
        put(w,D_FILE,get(w,A_VR+32))
        put(w,D_FILE_N,get(w,A_VR+40))
        return jump(w,600)
    if phase==550:
        a_request(w,TEMPQ,0)
        return a_invoke(w,551,3,a_at(w,A_RQ),32,a_at(w,A_VR),4096,get(w,D_TEMP_CONTEXT),204800)
    if phase==551:
        if r!=0 or get(w,A_VR)!=TEMPR or get(w,A_VR+80)!=1 or get(w,A_VR+56)>1:
            return a_unknown(w,551)
        if get(w,A_VR+8)!=0 or get(w,A_VR+56)!=0:
            return a_fail(w,20,get(w,A_VR+16))
        if get(w,A_VR+32)<3 or get(w,A_VR+32)>2147483647 or get(w,A_VR+48)!=15:
            return a_unknown(w,552)
        put(w,D_FILE,get(w,A_VR+32))
        put(w,D_FILE_N,get(w,A_VR+40))
        return jump(w,600)
    return 4294967293

def read_value(w:mutbuf) -> u32:
    at=get(w,A_OFFSET)
    n=get(w,A_RAW_N)
    if at==n:
        return jump(w,510)
    amount=n-at
    if amount>8192:
        amount=8192
    put(w,A_AMOUNT,amount)
    a_request(w,A_V6,19)
    a_arg(w,get(w,A_SELECTED),24)
    put(w,A_RQ+104,at)
    put(w,A_RQ+112,amount)
    return a_value(w,502,128)

def bytes_result(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(w,RESULT)
    if phase==600:
        return a_newmap(o,w,601,get(w,D_FILE_N)+4224)
    if phase==601:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_FS_MAP,r)
        put(w,A_FS_CAP,(get(w,D_FILE_N)+8319)&18446744073709547520)
        put(w,A_OFFSET,0)
        return read_file(o,w)
    if phase==602:
        if r==18446744073709551612:
            return read_file(o,w)
        if r==0 or failed(r) or r>get(w,D_FILE_N)-get(w,A_OFFSET):
            return a_fail(w,20,choose(failed(r),errno(r),5))
        put(w,A_OFFSET,get(w,A_OFFSET)+r)
        return read_file(o,w)
    if phase==603:
        if r!=0:
            return a_unknown(w,603)
        return a_copy(w,607,get(w,A_FS_MAP),a_at(w,A_VR),128)
    if phase==607:
        if r!=0:
            return a_unknown(w,607)
        if get(w,A_VR)!=0x3130434454524149:
            return a_unknown(w,604)
        if get(w,A_VR+8)!=0:
            put(w,A_RAW_VALUE_ERROR,get(w,A_VR+8))
            return a_fail(w,21,get(w,A_VR+16))
        put(w,A_FS_N,get(w,A_VR+16))
        if get(w,A_FS_N)>4045:
            return a_fail(w,22,36)
        return a_copy(w,604,get(w,A_FS_MAP)+128,a_at(w,D_PATHBUF),get(w,A_FS_N))
    if phase==604:
        if r!=0:
            return a_unknown(w,605)
        put(w,D_READY,1)
        return jump(w,700)
    return 4294967293

def read_file(o:mutbuf,w:mutbuf) -> u32:
    if get(w,A_OFFSET)==get(w,D_FILE_N):
        put(w,D_PURE_WORK,2)
        return a_invoke(w,603,4,get(w,A_FS_MAP)+128,get(w,D_FILE_N),get(w,A_FS_MAP),get(w,A_FS_CAP),a_at(w,D_PURE_WORK),32)
    amount=get(w,D_FILE_N)-get(w,A_OFFSET)
    return call(o,w,602,17,get(w,D_FILE),get(w,A_FS_MAP)+128+get(w,A_OFFSET),amount,get(w,A_OFFSET),0,0,0)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(w,RESULT)
    if phase==799:
        return finish(o,w)
    if phase==700:
        put(w,A_CLEAN_INDEX,0)
        return clean_cap(w)
    if phase==701:
        if a_cap_drop_valid(w)==False:
            return a_unknown_finish(o,w,701)
        if get(w,A_VR+104)!=0:
            put(w,A_TOKEN_PENDING,1)
        if get(w,A_VR+96)==1:
            clear(w,A_REFS+get(w,A_CLEAN_INDEX)*32,32)
            put(w,A_CLEAN_INDEX,get(w,A_CLEAN_INDEX)+1)
            return clean_cap(w)
        a_clean_error(w,11,get(w,A_VR+8))
        return finish(o,w)
    if phase==702:
        if r!=0 or get(w,A_VR)!=A_R2 or get(w,A_VR+88)!=1 or get(w,A_VR+120)!=1:
            return a_unknown_finish(o,w,702)
        if get(w,A_VR+104)!=0:
            a_clean_error(w,11,get(w,A_VR+8))
            return finish(o,w)
        put(w,A_TOKEN_PENDING,0)
        return jump(w,710)
    if phase==710:
        if get(w,D_ABS_ACTIVE)!=0:
            clear(w,A_RQ,32)
            put(w,A_RQ,ABSQ)
            put(w,A_RQ+8,1)
            return a_invoke(w,711,2,a_at(w,A_RQ),32,a_at(w,A_VR),128,a_at(w,D_ABS_WORK),200704)
        return jump(w,720)
    if phase==711:
        if r!=0 or get(w,A_VR)!=ABSR or get(w,A_VR+56)>1 or get(w,A_VR+72)>1:
            return a_unknown_finish(o,w,711)
        if get(w,A_VR+72)!=0:
            return a_unknown_finish(o,w,712)
        if get(w,A_VR+56)!=0:
            a_clean_error(w,11,get(w,A_VR+16))
            return finish(o,w)
        put(w,D_ABS_ACTIVE,0)
        return jump(w,720)
    if phase==720:
        if get(w,D_FILE)!=NONE:
            if get(w,A_CLOSE_METHOD)==0:
                return call(o,w,721,436,get(w,D_FILE),get(w,D_FILE),0,0,0,0,0)
            return call(o,w,722,3,get(w,D_FILE),0,0,0,0,0,0)
        put(w,A_MAP_INDEX,0)
        return clean_map(o,w)
    if phase==721:
        if r==18446744073709551612:
            return jump(w,720)
        if r==18446744073709551578:
            put(w,A_CLOSE_METHOD,1)
            return jump(w,720)
        if r!=0:
            a_clean_error(w,11,errno(r))
            return finish(o,w)
        put(w,D_FILE,NONE)
        return jump(w,720)
    if phase==722:
        if r!=0:
            return a_unknown_finish(o,w,722)
        put(w,D_FILE,NONE)
        return jump(w,720)
    if phase==730:
        if r!=0:
            a_clean_error(w,11,errno(r))
            return finish(o,w)
        slot=map_slot(get(w,A_MAP_INDEX))
        put(w,slot,0)
        put(w,slot+8,0)
        put(w,A_MAP_INDEX,get(w,A_MAP_INDEX)+1)
        return clean_map(o,w)
    return 4294967293

def clean_cap(w:mutbuf) -> u32:
    i=get(w,A_CLEAN_INDEX)
    while i<33:
        keep=i==15
        if i==11 and get(w,ERROR)!=0 and get(w,A_CALL_DISPOSITION)==1:
            keep=True
        if keep==False and get(w,A_REFS+i*32+24)!=0:
            put(w,A_CLEAN_INDEX,i)
            return a_simple(w,701,A_V5,78,i)
        i=i+1
    if get(w,A_TOKEN_PENDING)!=0:
        return a_simple(w,702,A_V5,93,NONE)
    return jump(w,710)

def map_slot(index:u64) -> u64:
    if index==0:
        return A_RAW_MAP
    if index==1:
        return A_PATH_MAP
    return A_FS_MAP

def clean_map(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,A_MAP_INDEX)
    while i<3:
        slot=map_slot(i)
        if get(w,slot)!=0:
            put(w,A_MAP_INDEX,i)
            return call(o,w,730,11,get(w,slot),get(w,slot+8),0,0,0,0,0)
        i=i+1
    put(w,A_STATE,2)
    return finish(o,w)

def finish(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,DR)
    put(o,8,choose(get(w,ERROR)!=0,get(w,ERROR),get(w,A_CLEAN_ERROR)))
    put(o,16,get(w,ERROR_NO))
    if get(w,A_REFS+15*32+24)!=0:
        copied_work(w,o,A_REFS+15*32,24,24)
        clear(w,A_REFS+15*32,32)
        put(o,96,1)
    if get(w,ERROR)!=0 and get(w,A_CALL_DISPOSITION)==1 and get(w,A_REFS+11*32+24)!=0:
        copied_work(w,o,A_REFS+11*32,56,24)
        clear(w,A_REFS+11*32,32)
        put(o,120,1)
    put(o,80,choose(get(w,A_STATE)!=2,1,0))
    put(o,88,choose(get(w,A_UNKNOWN)==0,1,0))
    put(o,104,choose(get(w,A_STATE)==2,1,0))
    put(o,112,get(w,A_CLEAN_ERRNO))
    if get(w,D_READY)!=0 and get(w,ERROR)==0:
        n=get(w,A_FS_N)
        copied_work(w,o,D_PATHBUF,128,n)
        put(o,48,n)
    return 0

def a_unknown_finish(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,A_UNKNOWN,1)
    put(w,A_STATE,4)
    put(w,ERROR_NO,detail)
    if get(w,ERROR)==0:
        put(w,ERROR,19)
    return finish(o,w)

def a_fail(w:mutbuf,error:u64,detail:u64) -> u32:
    if get(w,ERROR)==0:
        put(w,ERROR,error)
        put(w,ERROR_NO,detail)
    put(w,A_STATE,3)
    return jump(w,700)

def a_unknown(w:mutbuf,detail:u64) -> u32:
    put(w,A_UNKNOWN,1)
    put(w,A_STATE,4)
    if get(w,ERROR)==0:
        put(w,ERROR,19)
        put(w,ERROR_NO,detail)
    return jump(w,799)

def pure(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    mode=get(w,0)
    if mode==0:
        if length(o)!=32:
            return 4294967293
        clear(o,0,32)
        put(o,0,ABSQ)
        put(o,16,get(w,8))
        return 0
    if mode==1:
        return normalize_posix(s,o)
    if mode==3:
        if length(o)<length(s):
            return 4294967294
        i=0
        while i<length(s):
            b=byte(s,i)
            store(o,i,choose(b==92,47,b))
            i=i+1
        return length(s)
    if mode!=2 or length(o)<128+length(s):
        return 4294967293
    clear(o,0,128)
    put(o,0,0x3130434454524149)
    i=0
    pos=0
    chars=0
    while i<length(s):
        b=byte(s,i)
        if b==0:
            put(o,8,3)
            put(o,16,chars)
            return 0
        n=1
        if b>=194 and b<=223:
            n=2
        elif b>=224 and b<=239:
            n=3
        elif b>=240 and b<=244:
            n=4
        elif b>=128:
            put(o,8,2)
            put(o,16,chars)
            return 0
        if n>length(s)-i:
            put(o,8,2)
            put(o,16,chars)
            return 0
        if b==237 and n==3 and byte(s,i+1)>=160:
            c=byte(s,i+1)
            d=byte(s,i+2)
            if c==178 or c==179:
                # U+DC80..DCFF: the exact filesystem surrogateescape domain.
                out=((c&15)<<6)|(d&63)
                if out>=128 and out<=255:
                    store(o,128+pos,out)
                    pos=pos+1
                else:
                    put(o,8,1)
                    put(o,16,chars)
                    return 0
            else:
                put(o,8,1)
                put(o,16,chars)
                return 0
        else:
            j=0
            while j<n:
                store(o,128+pos+j,byte(s,i+j))
                j=j+1
            pos=pos+n
        i=i+n
        chars=chars+1
    put(o,16,pos)
    return 0
def runtime_controller(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<41943040 or get(w,424)!=R_CONTEXT:
        return 4294967293
    phase=get(o,128)
    r=get(o,136)
    if phase==700:
        if get(w,R_PTR)!=0:
            return r_again(o,2009)
        return r_system(o,2000,9,0,0,524288,3,34,NONE,0)
    if phase==2000:
        if r==0 or failed(r):
            clear(w,R_META,136)
            put(w,R_META,R_ERROR)
            put(w,R_META+8,DR)
            put(w,R_META+16,18)
            put(w,R_META+24,errno(r))
            put(w,R_META+96,1)
            put(w,R_META+112,1)
            put(w,R_READY,2)
            return r_again(o,2009)
        put(w,R_PTR,r)
        put(w,R_EXTENT,524288)
        return r_directory(o,w,2001,0)
    if phase==2001:
        valid=r==0 and get(o,R_OUTPUT)==DR
        if valid:
            valid=get(o,R_OUTPUT+80)<=1 and get(o,R_OUTPUT+88)<=1
        if valid:
            valid=get(o,R_OUTPUT+96)<=1 and get(o,R_OUTPUT+104)<=1 and get(o,R_OUTPUT+120)<=1
        if valid==False:
            clear(w,R_META,136)
            put(w,R_META,R_ERROR)
            put(w,R_META+8,DR)
            put(w,R_META+16,19)
            put(w,R_META+24,2001)
            put(w,R_META+88,1)
            put(w,R_READY,2)
            return r_again(o,2009)
        put(w,R_META,R_ERROR)
        copied_work(o,w,R_OUTPUT,R_META+8,128)
        if get(o,R_OUTPUT+8)==0 and get(o,R_OUTPUT+88)==1 and get(o,R_OUTPUT+80)==0 and get(o,R_OUTPUT+104)==1:
            n=get(o,R_OUTPUT+48)
            if n==0 or n>4045:
                put(w,R_META+16,19)
                put(w,R_META+24,2002)
                put(w,R_READY,2)
            else:
                copied_work(o,w,R_OUTPUT+128,73728,n)
                store(w,73728+n,0)
                put(w,216,n)
                put(w,R_READY,1)
        else:
            put(w,R_READY,2)
        if get(o,R_OUTPUT+88)==1 and get(o,R_OUTPUT+80)==0 and get(o,R_OUTPUT+104)==1:
            return r_system(o,2002,11,0,get(w,R_PTR),get(w,R_EXTENT),0,0,0,0)
        return r_again(o,2009)
    if phase==2002:
        if r!=0:
            put(w,R_READY,2)
            put(w,R_META+16,choose(get(w,R_META+16)!=0,get(w,R_META+16),11))
            put(w,R_META+88,1)
            put(w,R_META+112,0)
            put(w,R_META+120,errno(r))
            return r_again(o,2009)
        put(w,R_PTR,0)
        put(w,R_EXTENT,0)
        if get(w,R_READY)==1:
            clear(w,R_META,136)
            return r_again(o,700)
        return r_again(o,2009)
    if phase==2010:
        if get(w,R_PTR)==0:
            return r_again(o,2019)
        return r_directory(o,w,2011,1)
    if phase==2011:
        if r!=0 or get(o,R_OUTPUT)!=DR or get(o,R_OUTPUT+88)!=1 or get(o,R_OUTPUT+80)!=0 or get(o,R_OUTPUT+104)!=1:
            return r_again(o,2029)
        if get(o,R_OUTPUT+96)!=0 or get(o,R_OUTPUT+120)!=0:
            if get(w,R_META)!=0:
                return r_again(o,2029)
            put(w,R_META,R_ERROR)
            copied_work(o,w,R_OUTPUT,R_META+8,128)
        return r_system(o,2012,11,0,get(w,R_PTR),get(w,R_EXTENT),0,0,0,0)
    if phase==2012:
        if r!=0:
            return r_again(o,2029)
        put(w,R_PTR,0)
        put(w,R_EXTENT,0)
        return r_again(o,2019)
    return 4294967293

def r_directory(o:mutbuf,w:mutbuf,next:u64,op:u64) -> u32:
    clear(o,R_REQUEST,128)
    clear(o,R_OUTPUT,32768)
    put(o,R_REQUEST,DQ)
    put(o,R_REQUEST+8,op)
    if op==0:
        copied_work(w,o,432,R_REQUEST+24,24)
    put(o,128,next)
    put(o,0,3)
    put(o,8,R_REQUEST)
    put(o,16,128)
    put(o,24,3)
    put(o,32,R_OUTPUT)
    put(o,40,32768)
    put(o,48,0)
    put(o,56,get(w,R_PTR))
    put(o,64,524288)
    return 36

def r_system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,128,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def r_again(o:mutbuf,next:u64) -> u32:
    put(o,128,next)
    return 10

'''
def fn(source,name):
    return re.search(r'def '+name+r'\(.*?(?=\ndef |\Z)',source,re.S).group(0)
def windows_parts(pa):
    old="    if phase==200:\n        return a_simple(w,201,A_V6,7,2)"
    new="""    if phase==250:
        a_request(w,A_V6,32)
        put(w,A_RQ+104,16)
        return a_value(w,251,128)
    if phase==251:
        if a_ordinary(w)==False or a_capture(w,32,A_VR+24)==False:
            return a_value_failed(w,251)
        a_request(w,A_V6,37)
        a_arg(w,0,24)
        a_arg(w,32,48)
        return a_value(w,252,128)
    if phase==252:
        if a_ordinary(w)==False or get(w,A_VR+48)>1:
            return a_value_failed(w,252)
        put(w,A_WINDOWS,get(w,A_VR+48))
        return jump(w,200)
    if phase==200:
        return a_simple(w,201,A_V6,7,2)"""
    assert pa.count(old)==1;pa=pa.replace(old,new)
    old="""            if byte(w,A_VR+8192)==47:
                put(w,A_JOIN_N,0)
            elif get(w,A_JOIN_N)!=0:
                put(w,840,1)"""
    new="""            if get(w,A_WINDOWS)==1:
                put(w,840,8)
            elif byte(w,A_VR+8192)==47:
                put(w,A_JOIN_N,0)
            elif get(w,A_JOIN_N)!=0:
                put(w,840,1)"""
    assert pa.count(old)==1;pa=pa.replace(old,new)
    old="        put(w,A_JOIN_N,get(w,A_JOIN_N)+1)\n        put(w,840,0)"
    new="        put(w,A_JOIN_N,get(w,A_JOIN_N)+get(w,840))\n        put(w,840,0)"
    assert pa.count(old)==1;pa=pa.replace(old,new)
    old="def append_item(w:mutbuf) -> u32:\n    if get(w,840)==1:"
    new="""def append_item(w:mutbuf) -> u32:
    if get(w,840)==8:
        put(w,A_RQ+2048,get(w,A_ITEM_N))
        return a_copy(w,207,a_at(w,A_RQ+2048),get(w,A_RAW_MAP)+128+get(w,A_JOIN_N),8)
    if get(w,840)==1:"""
    assert pa.count(old)==1;pa=pa.replace(old,new)
    old="""        put(w,D_PURE_WORK,1)
        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,D_PURE_WORK),32)"""
    new="""        if get(w,A_WINDOWS)==1:
            clear(w,D_ABS_WORK,327680)
            return a_invoke(w,234,5,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,D_ABS_WORK),327680)
        put(w,D_PURE_WORK,1)
        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,D_PURE_WORK),32)"""
    assert pa.count(old)==1;pa=pa.replace(old,new)
    old="    if phase==231:"
    new="""    if phase==234:
        if r==0 or r>get(w,A_PATH_CAP)-128:
            return a_unknown(w,234)
        put(w,D_PURE_WORK,3)
        return a_invoke(w,235,4,get(w,A_PATH_MAP)+128,r,get(w,A_RAW_MAP)+128,get(w,A_RAW_CAP)-128,a_at(w,D_PURE_WORK),32)
    if phase==235:
        if r==0 or r>get(w,A_RAW_CAP)-128:
            return a_unknown(w,235)
        put(w,D_PURE_WORK,1)
        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,r,get(w,A_PATH_MAP)+128,get(w,A_PATH_CAP)-128,a_at(w,D_PURE_WORK),32)
    if phase==231:"""
    assert pa.count(old)==1;return pa.replace(old,new)

def source_program():
    co=coercion.SOURCE.replace('def advance(', 'def coercing(').replace('return lookup(', 'return directory_lookup(').replace('def lookup(', 'def directory_lookup(').replace('return invoke(', 'return directory_invoke(').replace('def invoke(', 'def directory_invoke(')
    co=co.replace('        if kind==4 or kind==7:\n','        if kind==0:\n            return jump(w,550)\n        if kind==4:\n',1)
    co=co.replace('        if base==4 or base==7:\n','        if base==14:\n            a_request(w,A_V11,32)\n            put(w,A_RQ+104,14)\n            return a_value(w,130,128)\n        if base==4:\n',1)
    co=co.replace('    if phase>=110 and phase<=119:\n','''    if phase==130:
        if a_ordinary(w)==False or a_capture(w,31,A_VR+24)==False:
            return a_value_failed(w,130)
        a_request(w,A_V6,37)
        a_arg(w,0,24)
        a_arg(w,31,48)
        return a_value(w,131,128)
    if phase==131:
        if a_ordinary(w)==False or get(w,A_VR+48)!=1:
            return a_unknown(w,131)
        return jump(w,250)
    if phase>=110 and phase<=119:
''',1)
    co=co.replace('a_request(w,A_V5,69)','a_request(w,A_V5,115)')
    co=co.replace('a_simple(w,120,A_V1,3,NONE)','a_simple(w,120,A_V7,3,NONE)')
    co=co.replace('a_simple(w,121,A_V4,40,9)','a_simple(w,121,A_V11,40,9)')
    co=co.replace('if kind!=4 and kind!=7:', 'if kind!=4:')
    pa=path.SOURCE.replace('def advance(','def parts(').replace('a_request(w,A_V1,23)','a_request(w,A_V9,23)')
    pa=pa.replace('return jump(w,508)','return jump(w,513)')
    pa=pa.replace('        put(w,A_BUFFER_OP,2)\n        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,0),A_WORK)',
      '        put(w,D_PURE_WORK,1)\n        return a_invoke(w,232,4,get(w,A_RAW_MAP)+128,get(w,A_JOIN_N),r+128,get(w,A_PATH_CAP)-128,a_at(w,D_PURE_WORK),32)')
    pa=pa.replace('        put(w,A_BUFFER_OP,0)\n        return a_invoke(w,233,4,0,0,get(w,A_RAW_MAP),get(w,A_RAW_CAP),a_at(w,0),A_WORK)',
      '        put(w,D_PURE_WORK,0)\n        put(w,D_PURE_WORK+8,r)\n        return a_invoke(w,233,4,0,0,get(w,A_RAW_MAP)+96,32,a_at(w,D_PURE_WORK),32)')
    pa=pa.replace('        return jump(w,513)','        raw=get(w,A_RAW_MAP)\n        cap=get(w,A_RAW_CAP)\n        put(w,A_RAW_MAP,get(w,A_PATH_MAP))\n        put(w,A_RAW_CAP,get(w,A_PATH_CAP))\n        put(w,A_PATH_MAP,raw)\n        put(w,A_PATH_CAP,cap)\n        return jump(w,513)')
    pa=windows_parts(pa)
    common='\n'.join(fn(old.COMMON,n)for n in ['a_at','a_invoke','a_copy','a_within','a_request','a_arg','a_value','a_simple','a_ordinary','a_capture','a_value_failed','a_newmap','a_cap_drop_valid','a_clean_error'])
    return SOURCE+'\n'+co+'\n'+pa+'\n'+common+'\n'+fn(buffers.SOURCE,'normalize_posix')+'\n'+fn(buffers.SOURCE,'copied')+'\n'+fn(buffers.SOURCE,'copied').replace('def copied(', 'def copied_work(').replace('s:readbuf','s:mutbuf')
def main():
    base.C.update(C)
    tree=base.document(source_program(),'generation_runtime_directory','directory')
    target=ROOT/'examples/hia_bootstrap/generation_runtime_directory.hepta'
    target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
