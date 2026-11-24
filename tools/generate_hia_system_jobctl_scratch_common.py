"""Shared authoring for original engine scratch custody, not a host policy shim."""
from __future__ import annotations
import ast,os,re
from tools import generate_hia_system_jobctl_control as control
from tools import generate_hia_system_jobctl_record as record
from tools.generate_hia_system_jobctl_request import POLICY as REQUEST_POLICY

C=dict(STATE_BYTES=128<<20,NONE=(1<<64)-1,NEG100=(1<<64)-100,NEG4=(1<<64)-4,NEG2=(1<<64)-2,NEG3=(1<<64)-3,
 SC_OP=62000,SC_NEXT=62008,SC_INTERACTIVE=62024,SC_ARGC=62032,SC_ARG=62040,SC_ARG_SIZE=62048,
 SC_STDIN_PRESENT=62056,SC_STDIN=62064,SC_STDIN_SIZE=62072,SC_STATE_ARG=62080,SC_STATE_SIZE=62088,
 SC_ID=62096,SC_ID_SIZE=62104,SC_NONCE=62112,SC_NONCE_SIZE=62120,SC_PID=62128,SC_STOPPED=62136,
 SC_FAILED=62144,SC_EXITED=62152,SC_JSON=62160,SC_JSON_SIZE=62168,SC_ERROR=62176,SC_ERROR_SIZE=62184,SC_SELECTED=62192,
 SC_OWN_FD=62200,SC_PARENT_FD=62208,SC_UID=62216,SC_BINDING_SIZE=62224,SC_PATH_SIZE=62232,
 SC_STATE_CANON_SIZE=62240,SC_FD=62248,SC_USED=62256,SC_TEMP_NEXT=62264,SC_PHASE=62272,
 SC_ERROR_CODE=62280,SC_ERRNO=62288,SC_RENDER_STATE=62296,SC_ADOPTED=62304,SC_DEV=62312,SC_INO=62320,
 SC_ATOMIC_NEXT=62328,SC_ATOMIC_SOURCE=62336,SC_ATOMIC_SIZE=62344,SC_ATOMIC_USED=62352,
 SC_ATOMIC_FD=62360,SC_ATOMIC_PARENT=62368,SC_PROCESS_ID=62376,
 SC_DIR_OP=62400,SC_DIR_NEXT=62408,SC_DIR_ERROR=62416,SC_WALK_FD=62424,SC_WALK_AT=62432,
 SC_WALK_SIZE=62440,SC_WALK_USED=62448,SC_WALK_NEXT=62456,SC_DIR_FD=62464,SC_DIR_PARENT=62472,
 SC_TEMP_FD=62480,SC_VERIFY_NEXT=62488,SC_WALK_RESULT=62496,SC_DIR_COUNT=62504,SC_DIR_DEPTH=62512,
 SC_DIR_DEADLINE=62520,SC_DIR_LEAF_SIZE=62528,SC_MOUNT_NEXT=62536,SC_MOUNT_FD=62544,
 SC_MOUNT_RESULT=62552,SC_MOUNT_FIRST=62560,SC_CLOSE_NEXT=62568,SC_CLEAN_INDEX=62576,
 G_NEXT=62600,G_OP=62608,G_FD=62616,G_DIR_FD=62624,G_USED=62632,G_COUNT=62640,G_DIR_USED=62648,
 G_DIR_SIZE=62656,G_MEMBERS=62664,G_DEADLINE=62672,G_PID=62680,G_IO_KIND=62688,G_ENTRY_SIZE=62696,
 G_ERROR_CONTEXT=62704,G_EXIT_NEXT=62712,G_UTF_INDEX=62720,G_UTF_LEN=62728,G_INT_ERROR=62736,
 G_FIELD_AT=62744,G_FIELD_SIZE=62752,G_FIRST_AT=62760,G_FIRST_SIZE=62768,G_SCAN_AT=62776,
 SC_DIR_BEFORE=62384,SC_WALK_OLD=62392,SC_MOUNT_TARGET=62584,SC_CLEAR_ACTIVE=62592,SC_BEFORE=62800,SC_BEFORE_NEW=62944,
 SC_DIR_ENTRY_ERROR=62784,SC_VALUE_SOURCE=63700,SC_VALUE_SIZE=63708,SC_FINISH_NEXT=63716,SC_CLOSE_INDEX=63724,SC_ATOMIC_KIND=63732,SC_ATOMIC_OWNED=63740,SC_ORIGINAL_ERROR_SIZE=63748,
 SC_VALUE_WORK=4<<20,SC_VALUE_BYTES=64+524289*56+(8<<20)+16384,SC_VALUE_OUTPUT=48<<20,
 SC_WORK=68<<20,SC_IO=70<<20,SC_IO_CAP=2<<20,SC_DENTS=72<<20,SC_STAT=73<<20,
 SC_PATH_TEMP=74<<20,SC_NAME=75<<20,SC_CLAIM=76<<20,SC_STACK=78<<20,
 SC_OUT=80<<20,SC_OUT_END=88<<20,SC_STATE=114<<20,SC_PATH=115<<20,SC_BINDING=116<<20,
 SC_ERROR_TEXT=88<<20,SC_ERROR_END=90<<20,
 DIR_FLAGS=65536+131072+524288)
TEXT={
 'empty':'','colon':': ','os_error':' (os error ','close':')','unknown_error':'Unknown error ',
 'group_custody':'original engine child custody lost','group_exit':'original engine child exit is unconfirmed',
 'group_budget':'engine group observation budget exceeded','group_visibility':'engine group visibility unconfirmed',
 'stat_bound':'engine process identity exceeds its bound','stat_bad':'engine process identity malformed',
 'stat_absent':'engine process group absent','restricted':'engine original-group visibility is restricted',
 'no_proc':'engine original-group proc mount is unconfirmed','mount_bound':'engine mount observation exceeds its bound',
 'pid_range':'engine process group exceeds PID range: out of range integral type conversion attempted',
 'group_stop':'engine group stop unconfirmed','group_timeout':'original engine group did not stop',
 'invalid_digit':'invalid digit found in string','int_overflow':'number too large to fit in target type',
 'int_underflow':'number too small to fit in target type','int_empty':'cannot parse integer from empty string',
 'utf_invalid':'invalid utf-8 sequence of ','utf_bytes':' bytes from index ','utf_incomplete':'incomplete utf-8 byte sequence from index ',
 'proc':'/proc','mountinfo':'/proc/self/mountinfo','slash_stat':'/stat','fdinfo':'/proc/self/fdinfo/','procfd':'/proc/self/fd/',
 'root':'/','scratch':'engine-scratch','slash_scratch':'/engine-scratch','claim':'claim.json',
 'directory_unavailable':'engine directory unavailable','directory_absolute':'engine directory must be absolute',
 'directory_normalized':'engine directory path is not normalized','directory_create':'cannot exclusively create private engine directory',
 'directory_identity':'private engine directory identity or permissions changed; retained',
 'directory_original':'engine directory differs from its original owner inode',
 'directory_depth':'engine cleanup directory depth exceeded; retained','directory_budget':'engine cleanup budget exceeded; retained',
 'directory_mount':'engine cleanup refuses a mounted descendant; retained','directory_descendant':'engine cleanup descendant identity changed; retained',
 'directory_incomplete':'engine cleanup incomplete','directory_remove':'engine directory removal unconfirmed',
 'directory_durable':'engine directory removal durability unconfirmed','mount_id_bound':'engine mount identity exceeds its bound',
 'mount_id_absent':'engine mount identity unavailable','mount_id_invalid':'invalid engine mount identity',
 'write_zero':'failed to write whole buffer',
 'unconfirmed':'original process group unconfirmed; no cleanup submitted',
 'retained_prefix':'retain scratch after original supervision error: ',
 'scratch_file':'/engine-scratch.json','retained_file':'/engine-scratch.retained.json',
 'scratch_tmp':'/engine-scratch.tmp-','retained_tmp':'/engine-scratch.retained.tmp-',
}
IDS={name:i for i,name in enumerate(TEXT)}
C.update({'E_'+n.upper():i for n,i in IDS.items()})

COMMON=r'''
def sc_finish(w:mutbuf) -> u32:
    put(w, 0, get(w, SC_NEXT))
    return 8

def sc_go(w:mutbuf, next:u64) -> u32:
    put(w, 0, next)
    return 8

def sc_error(w:mutbuf, context:u64, errno:u64) -> u64:
    at = sc_text(w, SC_ERROR_TEXT, context)
    if errno != 0:
        if at != SC_ERROR_TEXT:
            at = sc_text(w, at, E_COLON)
        at = sc_errno(w, at, errno)
        at = sc_text(w, at, E_OS_ERROR)
        at = decimal(w, at, errno)
        at = sc_text(w, at, E_CLOSE)
    put(w, SC_ERROR, SC_ERROR_TEXT)
    put(w, SC_ERROR_SIZE, at - SC_ERROR_TEXT)
    put(w, SC_FAILED, 1)
    return 0

def sc_result_error(w:mutbuf, context:u64, result:u64) -> u64:
    return sc_error(w, context, choose(failed(result), 0 - result, 5))

def sc_utf_error(w:mutbuf) -> u64:
    at = SC_ERROR_TEXT
    if get(w, G_UTF_LEN) == 0:
        at = sc_text(w, at, E_UTF_INCOMPLETE)
    else:
        at = sc_text(w, at, E_UTF_INVALID)
        at = decimal(w, at, get(w, G_UTF_LEN))
        at = sc_text(w, at, E_UTF_BYTES)
    at = decimal(w, at, get(w, G_UTF_INDEX))
    put(w, SC_ERROR, SC_ERROR_TEXT)
    put(w, SC_ERROR_SIZE, at - SC_ERROR_TEXT)
    put(w, SC_FAILED, 1)
    return 0

def sc_equal(w:mutbuf, a:u64, b:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, a + index) != byte(w, b + index):
            return 0
        index = index + 1
    return 1

def sc_point(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0:
        put(w, G_UTF_LEN, 0)
        return 0
    point = byte(w, at)
    width = 1
    if point < 128:
        return 4294967296 | point
    if point >= 194 and point <= 223:
        width = 2
        point = point & 31
    elif point >= 224 and point <= 239:
        width = 3
        point = point & 15
    elif point >= 240 and point <= 244:
        width = 4
        point = point & 7
    else:
        put(w, G_UTF_LEN, 1)
        return 0
    index = 1
    first = byte(w, at)
    while index < width:
        if index >= size:
            put(w, G_UTF_LEN, 0)
            return 0
        next = byte(w, at + index)
        if next < 128 or next > 191 or (index == 1 and ((first == 224 and next < 160) or (first == 237 and next > 159) or (first == 240 and next < 144) or (first == 244 and next > 143))):
            put(w, G_UTF_LEN, index)
            return 0
        point = (point << 6) | (next & 63)
        index = index + 1
    return (width << 32) | point

def sc_utf8(w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        value = sc_point(w, at + index, size - index)
        if value == 0:
            put(w, G_UTF_INDEX, index)
            return 0
        index = index + (value >> 32)
    return 1

def sc_space(point:u64) -> u64:
    return choose((point >= 9 and point <= 13) or point == 32 or point == 133 or point == 160 or point == 5760 or (point >= 8192 and point <= 8202) or point == 8232 or point == 8233 or point == 8239 or point == 8287 or point == 12288, 1, 0)

def sc_word(w:mutbuf, at:u64, end:u64) -> u64:
    searching = 1
    while at < end and searching == 1:
        point = sc_point(w, at, end - at)
        if sc_space(point & 4294967295) == 0:
            searching = 0
        else:
            at = at + (point >> 32)
    start = at
    searching = 1
    while at < end and searching == 1:
        point = sc_point(w, at, end - at)
        if sc_space(point & 4294967295) == 1:
            searching = 0
        else:
            at = at + (point >> 32)
    put(w, G_FIELD_AT, start)
    put(w, G_FIELD_SIZE, at - start)
    return at

def sc_unsigned(w:mutbuf, at:u64, size:u64, maximum:u64) -> u64:
    put(w, G_INT_ERROR, 0)
    if size == 0:
        put(w, G_INT_ERROR, E_INT_EMPTY)
        return 0
    index = choose(byte(w, at) == 43, 1, 0)
    if index == size:
        put(w, G_INT_ERROR, E_INVALID_DIGIT)
        return 0
    value = 0
    while index < size:
        digit = byte(w, at + index) - 48
        if digit > 9:
            put(w, G_INT_ERROR, E_INVALID_DIGIT)
            return 0
        if value > maximum // 10 or (value == maximum // 10 and digit > maximum % 10):
            put(w, G_INT_ERROR, E_INT_OVERFLOW)
            return 0
        value = value * 10 + digit
        index = index + 1
    return value

def sc_i32(w:mutbuf, at:u64, size:u64) -> u64:
    negative = choose(size != 0 and byte(w, at) == 45, 1, 0)
    if negative == 1 and (size == 1 or byte(w, at + 1) == 43):
        put(w, G_INT_ERROR, E_INVALID_DIGIT)
        return 0
    value = sc_unsigned(w, at + negative, size - negative, 2147483647 + negative)
    if negative != 0:
        if get(w, G_INT_ERROR) == E_INT_OVERFLOW:
            put(w, G_INT_ERROR, E_INT_UNDERFLOW)
        value = 0 - value
    return value

def sc_now(w:mutbuf) -> u64:
    return get(w, SC_STAT) * 1000000000 + get(w, SC_STAT + 8)

def sc_nul(w:mutbuf, at:u64) -> u64:
    store(w, at, 0)
    return at
'''

def funcs(source):
    return {n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}

def text_functions(name,values):
    source=''
    for i in range(0,len(values),24):
        source+=record.texts(f'{name}_{i//24}',values[i:i+24])
    source+=f'\ndef {name}(w:mutbuf, at:u64, kind:u64) -> u64:\n'
    for i in range(0,len(values),24):
        source+=f'    if kind < {i+24}:\n        return {name}_{i//24}(w, kind - {i}, at)\n'
    return source+'    return at\n'

def compose(policy):
    helpers={**funcs(record.source_program()),**funcs(control.source_program()),**funcs(COMMON)}
    helpers['quote']=funcs(REQUEST_POLICY)['quote'].replace('REQUEST_OUT + REQUEST_CAP','SC_OUT_END')
    extra=text_functions('sc_text',list(TEXT.values()))
    errno=[os.strerror(i) for i in range(1,134)]
    extra+=text_functions('sc_errno_message',errno)
    extra+='''
def sc_errno(w:mutbuf, at:u64, value:u64) -> u64:
    if value >= 1 and value <= 133:
        return sc_errno_message(w, at, value - 1)
    return decimal(w, sc_text(w, at, E_UNKNOWN_ERROR), value)
'''
    helpers.update(funcs(extra))
    source=policy;defined=set(funcs(source))
    while True:
        needed={n.func.id for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)}-defined
        missing=sorted(needed & helpers.keys())
        if not missing:break
        for name in missing:source+='\n'+helpers[name]+'\n';defined.add(name)
    for name in sorted(C,key=len,reverse=True):source=re.sub(r'\b'+name+r'\b',str(C[name]),source)
    return source
