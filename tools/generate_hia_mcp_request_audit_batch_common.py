"""Fixed layout of private metadata request groups in the audit process.

This layout is process-local. It never changes the existing shared writer
memfd, ticket lease, durable record, or root capability representation.
"""

BASE = 22 << 20
C = {
    'M_BATCH': 17,
    'B_ACTIVE': BASE, 'B_COUNT': BASE+8, 'B_MEMBER': BASE+16,
    'B_KIND': BASE+24, 'B_MIN_SEC': BASE+32, 'B_MIN_NS': BASE+40,
    'B_CUT_SEC': BASE+48, 'B_CUT_NS': BASE+56,
    'B_ARCHIVE_LARGE': BASE+64, 'B_USAGE_LARGE': BASE+72,
    'B_ORIGINALS': BASE+80, 'B_FROZEN': BASE+88,
    'B_PEER': BASE+96, 'B_RECEIVE_NEXT': BASE+104,
    'B_RECEIVE_FLAGS': BASE+112, 'B_RECEIVE_SIZE': BASE+120,
    'B_RIGHT_COUNT': BASE+128, 'B_RIGHT_INDEX': BASE+136,
    'B_MESSAGE_OK': BASE+144, 'B_AFTER_CLOSE': BASE+152,
    'B_DEFERRED_SIZE': BASE+160, 'B_DEFERRED_PEER': BASE+168,
    'B_SEND_INDEX': BASE+176, 'B_SEALED': BASE+184,
    'B_MEMBERS': BASE+4096, 'B_FDS': BASE+8192,
    'B_SIZES': BASE+8256, 'B_ERRORS': BASE+8320,
    'B_MSG': BASE+8448, 'B_IOV': BASE+8512,
    'B_CONTROL': BASE+8576, 'B_PTR': BASE+8832,
    'B_CLOCK': BASE+8896, 'B_SLEEP': BASE+8912, 'B_POLL': BASE+8928,
    'B_RIGHTS': BASE+8960, 'B_SOCKET_OPTION': BASE+9472,
    'B_DEFERRED': BASE+16384,
    'B_PROJECTIONS': 23 << 20, 'B_PROJECT_BYTES': 262144,
    'B_OUTPUTS': 25 << 20, 'B_OUTPUT_BYTES': 65664,
    'METADATA_BATCH_SIZE': 8,
    'METADATA_LARGE_ROWS': 16384,
    'B_ARCHIVE_MAGIC': int.from_bytes(b'HIARQY02', 'little'),
    'B_USAGE_MAGIC': int.from_bytes(b'HIAUSQ02', 'little'),
    'B_ARCHIVE_OUT': int.from_bytes(b'HIARQO02', 'little'),
    'B_USAGE_OUT': int.from_bytes(b'HIAUSO02', 'little'),
}

COMMON = r'''
def resume_receive(w:mutbuf) -> u32:
    result = get(w,B_RECEIVE_SIZE)
    enter(w,M_SESSION,get(w,B_RECEIVE_NEXT))
    put(w,8,result)
    return 6

def group_member(w:mutbuf,index:u64) -> u64:
    if get(w,B_ACTIVE) == 0:
        return 0
    return index

def query_base(w:mutbuf) -> u64:
    return B_PROJECTIONS+get(w,B_MEMBER)*B_PROJECT_BYTES

def group_count(w:mutbuf) -> u64:
    return choose(get(w,B_ACTIVE) == 0,1,get(w,B_COUNT))

def select_member(w:mutbuf,index:u64) -> u64:
    put(w,B_MEMBER,index)
    if get(w,B_ACTIVE) != 0:
        copy_state(w,B_MEMBERS+index*512,INPUT,512)
        put(w,CURRENT_SLOT,get(w,INPUT+48))
        put(w,CURRENT_WORKER,get(w,INPUT+56))
        put(w,CURRENT_GEN,get(w,INPUT+64))
        put(w,CURRENT_PHASE,get(w,B_KIND))
        put(w,INPUT+256,get(w,B_MIN_SEC))
        put(w,INPUT+264,get(w,B_MIN_NS))
    return 0

def time_before(a:u64,b:u64,c:u64,d:u64) -> bool:
    return a < c or (a == c and b < d)
'''
