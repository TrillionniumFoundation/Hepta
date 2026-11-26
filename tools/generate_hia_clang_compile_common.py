"""Shared state and fixed-role transport for the native Clang producer.

This file is an author. The generated HIA policies own every decision and no
Python file is a production input. The fixed bridge binds role and catalog
addresses; requests carry no native callbacks or implementation identity flags.
"""
from tools import generate_hia_clang_capture_common as capture
C=dict(
 P_REQUEST=int.from_bytes(b'HIACLB01','little'),P_REPLY=int.from_bytes(b'HIACLR01','little'),
 P_CONTEXT=int.from_bytes(b'HIACLW01','little'),P_WORK=512<<20,
 P_SELF=32,P_PID=40,P_TAG=48,P_EXTENT=56,P_BASE=64,P_SOURCE=72,P_SOURCE_N=80,P_OUTPUT=88,P_OUTPUT_N=96,
 P_ROLE=128,P_SI=136,P_SN=144,P_OI=152,P_ON=160,P_WI=168,P_WN=176,
 P_CATALOG=192,P_CATALOG_N=200,
 P_CORE_N=256,P_TOOL_N=264,P_PATH_N=272,P_ABI_N=280,P_TARGET=288,P_KIND=296,P_LAYOUT=304,
 P_CANON_N=320,P_IR_N=328,P_META_N=336,P_SCHEMA=344,
 P_IMPL_SHA=368,P_CORE_SHA=400,P_IR_SHA=432,P_TOOL_SHA=464,P_ART_SHA=496,P_ABI_SHA=528,
 P_TOOL_AT=560,P_PATH_AT=568,P_ABI_AT=576,
 P_FRAME=600,P_FRAME_CAP=608,P_STRINGS=616,P_STRINGS_CAP=624,
 P_PATH_ACTIVE=640,P_WHICH_ACTIVE=648,P_FILE_ACTIVE=656,P_CAPTURE_ACTIVE=664,
 P_ID_ACTIVE=672,P_RETIRING=680,P_UNKNOWN=688,P_ERROR_PHASE=696,P_ID_NEXT=704,P_ID_COMPARE=712,
 P_ENSURE_NEED=720,P_ENSURE_NEXT=728,P_CLOSE_METHOD=736,P_CLOSE_UNKNOWN=744,
 P_STDOUT=752,P_STDERR=760,P_PARENT_FD=768,P_DIRECTORY_FD=776,P_SOURCE_FD=784,P_MISC_FD=792,
 P_ROOT_REMOVED=800,P_CLEAN_NEXT=808,P_CLEAN_INDEX=816,P_CLEAN_ERROR=824,P_CLEAN_ERRNO=832,
 P_CAP_INDEX=840,P_FOUND_N=848,P_COMPILER_N=856,P_COMPILER_OFF=864,
 P_DEST_N=872,P_DEST_OFF=880,P_PARENT_N=888,P_PARENT_OFF=896,
 P_DIR_N=904,P_DIR_OFF=912,P_SOURCE_PATH_N=920,P_SOURCE_OFF=928,P_ART_PATH_N=936,P_ART_OFF=944,
 P_VERSION_N=952,P_DRIVER_N=960,P_MULTICALL=968,P_HOST=976,P_ART_N=984,P_ART_PTR=992,
 P_SHARED=1000,P_INV_N=1008,P_RECEIPT_N=1016,P_ACTUAL_EXIT=1024,P_EXIT_KNOWN=1032,
 P_BUF_OP=1040,P_IO_AT=1048,P_IO_N=1056,P_IO_NEXT=1064,P_FILE_NEXT=1072,P_FILE_INDEX=1080,
 P_CAPTURE_NEXT=1088,P_VERSION_CODE=1096,P_DRIVER_CODE=1104,P_FOUND_CLANG=1112,P_COMPILER_LLVM=1120,
 P_PATH_FD=1128,P_STR_NEED=1136,P_TEMP_ATTEMPTS=1144,P_RANDOM_AT=1152,P_RANDOM_N=1160,
 P_ART_ID=1176,P_PUB_ID=1240,P_PUBLISHED=1304,P_WITHDRAWN=1312,P_RMT_ACTIVE=1320,
 P_DRAIN_NEXT=1328,P_FD_SLOT=1336,P_CAPTURE_PHASE=1344,P_TMP_N=1352,P_SOURCE_ID=1360,P_STAGE_ID=1424,
 P_FILE_MODE=1488,P_FILE_MAX=1496,P_FILE_ALLOW=1504,P_FILE_COMPARE=1512,P_EXPECT_PTR=1520,P_EXPECT_N=1528,
 P_EXPECT_ID=1536,P_FILE_PATH_OFF=1600,P_FILE_PATH_N=1608,P_LAST_FRAME_N=1616,
 P_VERSION_FULL_N=1624,P_DRIVER_FULL_N=1632,P_ART_ROOT_REMOVED=1640,
 P_INPUT_SHA=1664,P_INPUT_HASH_PRESENT=1696,P_INV_OFF=1704,P_FOUND_PTR=1712,P_FILE_FINISH=1720,
 P_PUB_COMPLETE=1728,P_STDOUT_N=1736,P_STDERR_N=1744,P_DIAG_ATTEMPTED=1752,P_DIAG_INDEX=1760,
 P_DIR_CREATED=1768,P_DRAINING=1776,P_IO_PTR=1784,P_IO_TOTAL=1792,P_IO_FD=1800,P_DIAG_NEXT=1808,
 P_OBJ_WORK=1824,P_OBJ_WORK_CAP=1832,P_OBJ_OUT=1840,P_OBJ_OUT_CAP=1848,P_OBJ_NEEDED=1856,P_OBJ_NEXT=1864,P_OBJ_RESULT=1872,P_OBJ_OUT_NEED=1880,P_OBJ_WORK_NEED=1888,P_DIAG_READY=1896,P_RMT_ABORT=1904,P_CAPTURE_ARENA=1912,P_CAPTURE_ARENA_CAP=1920,
 P_ORIGIN_PTR=1928,P_ORIGIN_N=1936,P_ORIGIN_MAP=1944,P_ORIGIN_CAP=1952,P_ORIGIN_DIR_N=1960,
 P_CATALOG_MAP=1968,P_CATALOG_CAP=1976,P_CATALOG_TEMPLATE=1984,P_CATALOG_TEMPLATE_N=1992,
 P_CATALOG_DATA_OFF=2000,P_CATALOG_NEED=2008,P_CATALOG_READY=2016,P_ORIGIN_INFO=2048,P_PEEK_PTR=2080,
 P_CATALOG_MAGIC=int.from_bytes(b'HIACLST1','little'),
 P_TEMP_NAME=13312,P_RANDOM=13440,P_FILE_RESULT=14336,
 P_SMALL=4096,P_SUBOUT=8192,P_STAT=12288,P_UNAME=12544,
 P_WHICH_WORK=16384,P_PATH_WORK=24576,P_FILE_WORK=262144,
 P_CAPTURE_WORK=2<<20,P_CAPTURE_STRIDE=65536,
 P_HASH_WORK=3<<20,P_RAW=4<<20,P_CANON=12<<20,P_IR_REQUEST=20<<20,P_IR=29<<20,
 P_EMIT_WORK=48<<20,P_ADMIT_OUT=176<<20,P_ADMIT_WORK=240<<20,
 P_INV_OUT=272<<20,P_INV_WORK=274<<20,P_META=278<<20,
 P_VERSION=(278<<20)+65536,P_DRIVER=(278<<20)+262144,
 P_ID_WORK=280<<20,P_RMT_WORK=282<<20,P_RECEIPT_WORK=283<<20,P_ART_FILE_WORK=286<<20,P_VERIFY_FILE_WORK=288<<20,P_CAPTURE_OUT=2300000,
 R_COPY=0,R_HASH=1,R_ADMISSION=2,R_CANONICAL=3,R_LLVM=4,R_LLVM_META=5,
 R_WHICH=6,R_PATH=7,R_FILE=8,R_CAPTURE=9,R_OBJECT=10,R_SHARED=11,R_IDENTITY=12,R_RMTREE=13,R_RECEIPT=14,R_BUFFERS=15,
 ID_REQUEST=int.from_bytes(b'HIAIDQ01','little'),ID_REPLY=int.from_bytes(b'HIAIDR01','little'),
 LLVM_REQUEST=int.from_bytes(b'HIALLV01','little'),META_REQUEST=int.from_bytes(b'HIALLM01','little'),
 META_REPLY=int.from_bytes(b'HIALLR01','little'),
 WHICH_REQUEST=int.from_bytes(b'HIACWH01','little'),WHICH_REPLY=int.from_bytes(b'HIACWR01','little'),
 PATH_REQUEST=int.from_bytes(b'HIAPTO01','little'),PATH_REPLY=int.from_bytes(b'HIAPOR01','little'),
 FILE_REQUEST=int.from_bytes(b'HIASFL01','little'),FILE_REPLY=int.from_bytes(b'HIASFR01','little'),
 CAPTURE_REQUEST=int.from_bytes(b'HIACAP01','little'),CAPTURE_REPLY=int.from_bytes(b'HIACAR01','little'),
 OBJECT_REQUEST=int.from_bytes(b'HIAOEL01','little'),OBJECT_REPLY=int.from_bytes(b'HIAOER01','little'),
 RMT_REQUEST=int.from_bytes(b'HIARMTQ1','little'),RMT_REPLY=int.from_bytes(b'HIARMTR1','little'),
 E_VERIFY=1,E_IR=2,E_PROFILE=3,E_TOOL=4,E_DESTINATION=5,E_TEMP=6,E_COMPILE=7,E_ARTIFACT=8,
 E_INVENTORY=9,E_STALE=10,E_PUBLICATION=11,E_OS=12,E_MEMORY=13,E_CLEANUP=14,E_CONTEXT=15,
)
COMMON=r'''
def p_at(w:mutbuf,offset:u64) -> u64:
    return get(w,P_BASE)+offset

def p_invoke(w:mutbuf,next:u64,role:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,PHASE,next)
    put(w,P_ROLE,role)
    put(w,P_SI,si)
    put(w,P_SN,sn)
    put(w,P_OI,oi)
    put(w,P_ON,on)
    put(w,P_WI,wi)
    put(w,P_WN,wn)
    return 2

def p_copy(w:mutbuf,next:u64,si:u64,oi:u64,n:u64) -> u32:
    return p_invoke(w,next,R_COPY,si,n,oi,n,p_at(w,P_SMALL),0)

def p_hash(w:mutbuf,next:u64,si:u64,n:u64,where:u64) -> u32:
    clear(w,P_HASH_WORK,1184)
    return p_invoke(w,next,R_HASH,si,n,p_at(w,where),32,p_at(w,P_HASH_WORK),1184)

def p_equal(w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return False
        i=i+1
    return True

def p_fail(w:mutbuf,error:u64,detail:u64) -> u32:
    if get(w,ERROR)==0:
        put(w,ERROR,error)
        put(w,ERROR_NO,detail)
        put(w,P_ERROR_PHASE,get(w,PHASE))
    return jump(w,900)

def p_frame(o:mutbuf,w:mutbuf,n:u64,next:u64) -> u32:
    if n==0 or n>9223372036854771712:
        return p_fail(w,E_MEMORY,12)
    if n<=get(w,P_FRAME_CAP):
        return jump(w,next)
    need=(n+4095)&18446744073709547520
    put(w,P_ENSURE_NEED,need)
    put(w,P_ENSURE_NEXT,next)
    if get(w,P_FRAME)==0:
        return call(o,w,810,9,0,need,3,34,NONE,0,0)
    return call(o,w,811,25,get(w,P_FRAME),get(w,P_FRAME_CAP),need,1,0,0,0)

def p_allocation(w:mutbuf) -> u32:
    r=get(w,RESULT)
    if failed(r):
        return p_fail(w,E_MEMORY,errno(r))
    put(w,P_FRAME,r)
    put(w,P_FRAME_CAP,get(w,P_ENSURE_NEED))
    return jump(w,get(w,P_ENSURE_NEXT))

def p_small_copy(w:mutbuf,next:u64,si:u64,oi:u64,n:u64) -> u32:
    return p_copy(w,next,p_at(w,si),p_at(w,oi),n)

def p_identity(w:mutbuf,next:u64,compare:u64) -> u32:
    put(w,P_ID_NEXT,next)
    put(w,P_ID_COMPARE,compare)
    put(w,P_ID_ACTIVE,1)
    return p_invoke(w,60,R_IDENTITY,get(w,P_CATALOG),get(w,P_CATALOG_N),p_at(w,P_SUBOUT),128,p_at(w,P_ID_WORK),2097152)

def p_identity_result(w:mutbuf) -> u32:
    if get(w,RESULT)!=0 or get(w,P_SUBOUT)!=ID_REPLY:
        put(w,P_UNKNOWN,1)
        return p_fail(w,E_CONTEXT,60)
    if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+64)!=0 or get(w,P_SUBOUT+72)!=1:
        return p_fail(w,E_STALE,get(w,P_SUBOUT+8))
    if get(w,P_ID_COMPARE)==0:
        i=0
        while i<32:
            store(w,P_IMPL_SHA+i,byte(w,P_SUBOUT+32+i))
            i=i+1
    elif p_equal(w,P_IMPL_SHA,P_SUBOUT+32,32)==False:
        return p_fail(w,E_STALE,61)
    clear(w,P_SMALL,32)
    put(w,P_SMALL,ID_REQUEST)
    put(w,P_SMALL+8,1)
    return p_invoke(w,61,R_IDENTITY,p_at(w,P_SMALL),32,p_at(w,P_SUBOUT),128,p_at(w,P_ID_WORK),2097152)

def p_identity_retired(w:mutbuf) -> u32:
    if get(w,RESULT)!=0 or get(w,P_SUBOUT)!=ID_REPLY:
        put(w,P_UNKNOWN,1)
        return p_fail(w,E_CONTEXT,61)
    if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+64)!=0 or get(w,P_SUBOUT+72)!=1 or get(w,P_SUBOUT+80)!=1:
        return p_fail(w,E_CLEANUP,get(w,P_SUBOUT+16))
    put(w,P_ID_ACTIVE,0)
    return jump(w,get(w,P_ID_NEXT))
def p_buffer(w:mutbuf,next:u64,op:u64,si:u64,sn:u64,oi:u64,on:u64) -> u32:
    put(w,P_BUF_OP,op)
    return p_invoke(w,next,R_BUFFERS,si,sn,oi,on,p_at(w,0),P_WORK)

def p_file_work(w:mutbuf) -> u64:
    index=get(w,P_FILE_INDEX)
    if index==0:
        return P_FILE_WORK
    if index==1:
        return P_ART_FILE_WORK
    return P_VERIFY_FILE_WORK

def p_file(o:mutbuf,w:mutbuf,next:u64,index:u64,mode:u64,path:u64,n:u64,maximum:u64,expected:u64,en:u64,compare:u64,identity:u64) -> u32:
    if n>9223372036854775614 or en>9223372036854775614-n:
        return p_fail(w,E_MEMORY,12)
    put(w,P_FILE_NEXT,next)
    put(w,P_FILE_INDEX,index)
    put(w,P_FILE_MODE,mode)
    put(w,P_FILE_PATH_OFF,path)
    put(w,P_FILE_PATH_N,n)
    put(w,P_FILE_MAX,maximum)
    put(w,P_EXPECT_PTR,expected)
    put(w,P_EXPECT_N,en)
    put(w,P_FILE_COMPARE,compare)
    clear(w,P_EXPECT_ID,64)
    if compare!=0:
        i=0
        while i<64:
            store(w,P_EXPECT_ID+i,byte(w,identity+i))
            i=i+1
    return p_frame(o,w,193+n+en,820)

def p_capture(o:mutbuf,w:mutbuf,next:u64,index:u64) -> u32:
    put(w,P_CAPTURE_NEXT,next)
    put(w,P_CAP_INDEX,index)
    n=1024+get(w,P_COMPILER_N)
    if index==2:
        n=n+get(w,P_SOURCE_PATH_N)+get(w,P_ART_PATH_N)
    return p_frame(o,w,n,840)

def p_saved_copy(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,b+i,byte(w,a+i))
        i=i+1
    return 0

def p_close(o:mutbuf,w:mutbuf,slot:u64,next:u64) -> u32:
    fd=get(w,slot)
    if fd==NONE:
        return jump(w,next)
    if get(w,P_CLOSE_UNKNOWN)!=0:
        put(w,P_UNKNOWN,1)
        return jump(w,999)
    put(w,P_FD_SLOT,slot)
    put(w,P_IO_NEXT,next)
    if get(w,P_CLOSE_METHOD)==1:
        return call(o,w,871,3,fd,0,0,0,0,0,0)
    return call(o,w,870,436,fd,fd,0,0,0,0,0)
'''
def write_module(name,source,entry='advance'):
 capture.C.update(C)
 return capture.write_module(name,source+'\n'+COMMON,entry)
