"""Authoring-only support for the HIA durable request audit owner.

The emitted HIA owns policy, continuation frames, exact record bytes and all
filesystem ordering. The adapter only translates the bounded Linux syscall ABI.
"""
import re
from tools.generate_hia_mcp_service_owner_common import authored as service_authored

NONE = (1 << 64) - 1
C = dict(STATE_BYTES=32 << 20, ARENA=8 << 20, ARENA_BYTES=4 << 20,
         SCRATCH=12 << 20, SCRATCH_BYTES=4 << 20, SHARED=30 << 20,
         FRAMES=65536, FRAME_BYTES=4096, INPUT=262144, RESPONSE=270336,
         RECORD=278528, TEMP_RECORD=278784, COMPARE_RECORD=279040,
         ERROR_TEXT=286720, HOT_RECORDS=1 << 20, HOT_NAMES=2 << 20,
         SCAN_DATA=3 << 20, READ_DATA=4 << 20, JSON_DATA=5 << 20,
         PIN11_DATA=6 << 20, PIN12_DATA=(6 << 20) + 4096,
         INTENT_DATA=(6 << 20) + 131072, SHARD_FDS=524288,
         SHARD_STAMPS=528384, ROOT_STAMP=600000, HOT_STAMP=600144,
         LEGACY_STAMP=600288, PIN11_STAMP=600432, PIN12_STAMP=600576,
         SHARD_ROOT_STAMP=600720,
         ROOTFD=128, HOTFD=136, LEGACYFD=144, PIN11FD=152,
         LAYOUT=160, SHARDROOTFD=168, PIN12FD=176,
         PIN11LEN=184, PIN12LEN=192, HOTCOUNT=200,
         TICKET_HOT=208, START_SEC=216, START_NSEC=224,
         RESPONSE_PHASE=232, LOCKED=240,
         M_SESSION=0, M_FILES=1, M_RECORDS=2, M_ARCHIVE=3,
         M_LAYOUT=4, M_RETENTION=5, M_ROOT=6, M_SCAN=7,
         M_WRITE=8, M_RECOVERY=9,
         OPEN_DIR=0, READ_FILE=1, FENCE_DIR=2, FENCE_PIN=3,
         RECORD_READ=0, RECORD_WRITE=1, RECORD_CLEAN=2,
         ARCHIVE_OPEN=0, ARCHIVE_FENCE=1, ARCHIVE_FIND=2,
         ARCHIVE_READ=3, ARCHIVE_SAVE=4, ARCHIVE_SEED=5,
         LAYOUT_OPEN=0, LAYOUT_FENCE=1,
         RETENTION_SNAPSHOT=0, RETENTION_ADMIT=1, RETENTION_TARGET=2,
         O_DIRECTORY=65536, O_NOFOLLOW=131072, O_CLOEXEC=524288,
         O_PATH=2097152, O_NONBLOCK=2048,
         NEG2=(1 << 64)-2, NEG4=(1 << 64)-4, NEG17=(1 << 64)-17)
C.update(M_LEASES=10, M_OPEN=11, M_RESPONSE=12, M_METADATA=13, M_INTENT=14,
         INTENT_IDS=577536, INTENT_OLD=585728,
         DAEMON_AUDITFD=256, DAEMON_CONTROLLER=264, READY=272,
         ACTIVECOUNT=280, CURRENT_SLOT=288, CURRENT_GEN=296,
         CURRENT_WORKER=304, CURRENT_PHASE=312, ROOT_PATH_LEN=320,
         STATE_FD=328, DAEMON_PID=336, PACKET_SIZE=360,
         ARCHIVE_OPENED=368, HOT_OWNED=376, ID_PRESENT=384,
         ROOT_PATH=16384, TICKETS=7 << 20, SESSION_CLOCK=271424,
         SESSION_ENTROPY=271360, LAYOUT_IDS=569344,
         LAYOUT_NAMES=(2 << 20)+131072)

ERRORS = {
    1: 'invalid request audit protocol',
    2: 'request audit session or canonical tool metadata unavailable',
    3: 'private request audit directory refused',
    4: 'private request audit inode refused',
    5: 'request audit metadata size refused',
    6: 'request audit metadata identity refused',
    7: 'request archive root binding changed',
    8: 'request archive identity changed; history never recreated automatically',
    9: 'unanchored request archive refused; history never recreated automatically',
    10: 'request audit root is not UTF-8',
    11: 'invalid request audit root',
    12: 'request audit ancestor is not searchable',
    13: 'request audit retention invariant exceeded',
    14: 'unexpected private request audit entry',
    15: 'unexpected private audit staging identity',
    16: 'audit staging inode refused',
    17: 'audit staging hard-link binding refused',
    18: 'request hot cache binding changed',
    19: 'request audit receipt binding changed',
    20: 'request archive identity changed',
    21: 'request archive terminal outcome changed',
    22: 'request hot namespace changed during validation',
    23: 'request unavailable to this scope',
    24: 'request archive anchor binding changed',
    25: 'request archive shard layout unavailable',
    26: 'duplicate request archive identity across namespaces',
    27: 'request archive record changed physical namespace',
    28: 'request archive identity is in the wrong shard',
    29: 'request audit worker lease unavailable',
    30: 'request audit shared custody changed',
    31: 'request audit I/O unavailable',
    32: 'request archive shard initialization binding changed',
}
TEXT = dict(hot='request-audit\0', legacy='request-archive-v11\0',
            anchor11='.request-archive-v11-anchor.json\0',
            shards='request-archive-v12\0', anchor12='.request-archive-v12-anchor.json\0',
            intent='.request-archive-v12-init.json\0', slash='/\0', dot='.\0',
            suffix='.json\0', tmp='.tmp\0', anchor_prefix='.archive-anchor-',
            init_prefix='.archive-v12-init-', shard_prefix='.archive-v12-anchor-')
TEXT.update({'audit_error_'+str(k): v for k,v in ERRORS.items()})

COMMON = r'''
def frame(w:mutbuf) -> u64:
    return FRAMES + get(w, 32) * FRAME_BYTES

def arg(w:mutbuf, index:u64) -> u64:
    return get(w, frame(w) + 64 + index * 8)

def local(w:mutbuf, index:u64) -> u64:
    return get(w, frame(w) + 160 + index * 8)

def save(w:mutbuf, index:u64, value:u64) -> u64:
    return put(w, frame(w) + 160 + index * 8, value)

def procedure(w:mutbuf, module:u64, operation:u64, phase:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64) -> u32:
    depth = get(w, 32)
    if depth >= 15:
        put(w, 96, 1)
        return enter(w, M_SESSION, 900)
    next = FRAMES + (depth + 1) * FRAME_BYTES
    fill_range(w, next, FRAME_BYTES, 0)
    put(w, next, get(w, 16))
    put(w, next + 8, phase)
    put(w, next + 16, operation)
    put(w, next + 64, a)
    put(w, next + 72, b)
    put(w, next + 80, c)
    put(w, next + 88, d)
    put(w, next + 96, e)
    put(w, next + 104, f)
    put(w, next + 112, g)
    put(w, next + 120, h)
    put(w, 32, depth + 1)
    return enter(w, module, 0)

def done(w:mutbuf, result:u64) -> u32:
    at = frame(w)
    module = get(w, at)
    phase = get(w, at + 8)
    put(w, 32, get(w, 32) - 1)
    put(w, 48, result)
    return enter(w, module, phase)

def step(w:mutbuf, phase:u64) -> u32:
    return enter(w, get(w, 16), phase)

def bad(w:mutbuf, reason:u64) -> u32:
    put(w, 96, reason)
    put(w, 104, 0)
    return done(w, NONE)

def io_bad(w:mutbuf, error:u64) -> u32:
    put(w, 96, 31)
    put(w, 104, error)
    return done(w, NONE)

def directory_ok(w:mutbuf, at:u64) -> bool:
    mode = getn(w, at + 24, 4)
    return mode & 61440 == 16384 and mode & 4095 == 448 and getn(w, at + 28, 4) == get(w, 24)

def regular_ok(w:mutbuf, at:u64, maximum:u64, links:u64) -> bool:
    mode = getn(w, at + 24, 4)
    return mode & 61440 == 32768 and mode & 4095 == 384 and getn(w, at + 28, 4) == get(w, 24) and get(w, at + 16) >= 1 and get(w, at + 16) <= links and get(w, at + 48) <= maximum

def stamp_equal(w:mutbuf, left:u64, right:u64) -> bool:
    return equal(w, left, right, 40) and get(w, left + 48) == get(w, right + 48) and equal(w, left + 88, right + 88, 32)

def directory_binding(w:mutbuf, left:u64, right:u64) -> bool:
    return directory_ok(w, left) and directory_ok(w, right) and equal(w, left, right, 16)

def record_identity(w:mutbuf, left:u64, right:u64) -> bool:
    return equal(w, left, right, 200) and equal(w, left + 208, right + 208, 16)

def record_equal(w:mutbuf, left:u64, right:u64) -> bool:
    return equal(w, left, right, 240)

def record_order(w:mutbuf, left:u64, right:u64) -> bool:
    if get(w, left + 216) != get(w, right + 216):
        return get(w, left + 216) < get(w, right + 216)
    if get(w, left + 208) != get(w, right + 208):
        return get(w, left + 208) < get(w, right + 208)
    index = 0
    while index < 64:
        a = byte(w, left + index)
        b = byte(w, right + index)
        if a != b:
            return a < b
        index = index + 1
    return False

def filename(w:mutbuf, id:u64, target:u64) -> u64:
    copy_state(w, id, target, 64)
    return text_suffix(w, target + 64)

def tempname(w:mutbuf, id:u64, target:u64) -> u64:
    store(w, target, 46)
    copy_state(w, id, target + 1, 64)
    store(w, target + 65, 45)
    copy_state(w, id, target + 66, 64)
    return text_tmp(w, target + 130)

def valid_tool(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 64:
        return False
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if ch != 95 and (ch < 97 or ch > 122):
            return False
        index = index + 1
    return True

def zeroes(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(w, at + index) != 0:
            return False
        index = index + 1
    return True

def utf8(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        ch = byte(w, at + index)
        count = 0
        low = 128
        high = 191
        if ch < 128:
            if ch == 0:
                return False
            count = 0
        elif ch >= 194 and ch <= 223:
            count = 1
        elif ch >= 224 and ch <= 239:
            count = 2
            if ch == 224:
                low = 160
            if ch == 237:
                high = 159
        elif ch >= 240 and ch <= 244:
            count = 3
            if ch == 240:
                low = 144
            if ch == 244:
                high = 143
        else:
            return False
        if index + count >= size:
            return False
        j = 1
        while j <= count:
            part = byte(w, at + index + j)
            if j == 1:
                if part < low or part > high:
                    return False
            elif part < 128 or part > 191:
                return False
            j = j + 1
        index = index + count + 1
    return True

def json_decode(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(w, 72, source)
    put(w, 80, size)
    put(w, SCRATCH + 48, 4096)
    put(w, SCRATCH + 56, 32)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4

def json_ok(w:mutbuf, result:u64) -> bool:
    return result >= 128 and result <= ARENA_BYTES and get(w,ARENA) == 5208772604367785521 and get(w,ARENA+32) == result

def flock_bytes(w:mutbuf, at:u64, kind:u64, start:u64) -> u64:
    fill_range(w, at, 32, 0)
    store(w, at, kind)
    put(w, at + 8, start)
    put(w, at + 16, 1)
    return at
'''

def authored(source, *, text=None, extra=None):
    values = {**C, **(extra or {})}
    combined = re.sub(r'text_(\w+)\(w,\s*', r'text_\1(w, ', source + '\n' + COMMON)
    return service_authored(combined, text={**TEXT, **(text or {})}, extra=values)
