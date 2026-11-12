"""Native CLI publication Path prefix, new unexecuted authoring revision.
Owns POSIX lexical Path.absolute join, destination exists/is_symlink,
mkdir(parents=True, exist_ok=True), and strict=False parent realpath ordering.
Private source is issued OS-argv text (UTF-8 surrogatepass, no NUL or unpaired
non-surrogateescape code points). The cwd peer must implement CPython getcwd
semantics; raw SYS_getcwd alone is not a proof for over-PATH_MAX cwd.
Staging, complete OSError/RuntimeError presentation and recursion-limit
compatibility remain explicit integration obligations.
"""
CONSTANTS={
 "BAD":0xfffffffd,"GROW":0xfffffffe,"MAX":(1<<64)-1,"BASE":4096,
 "STATE":int.from_bytes(b"HIAPPS01","little"),
 "COMMAND":int.from_bytes(b"HIAPPC01","little"),
 "EVENT":int.from_bytes(b"HIAPPE01","little"),
 "ACK":int.from_bytes(b"HIAPPA01","little"),
 "PHASE":16,"LEASE":24,"SEQ":32,"PENDING":40,"OP":48,"USED":56,
 "NEEDED":64,"LAST":72,"LAST_SIZE":80,"SOURCE_BYTES":88,
 "DEST":96,"DEST_N":104,"PARENT":112,"PARENT_N":120,
 "CURRENT":128,"CURRENT_N":136,"MK_STACK":144,"MK_PARENTS":152,
 "SAVED_ERRNO":160,"RESOLVED":168,"RESOLVED_N":176,
 "REST":184,"REST_N":192,"REST_POS":200,"RES_STACK":208,"SEEN":216,
 "CANDIDATE":224,"CANDIDATE_N":232,"CWD_CAP":240,
 "FS_PATH":768,"FS_PATH_N":776,"FS_COUNT":784,"FS_MODE":792,
 "ERROR_DOMAIN":800,"ERROR_CODE":808,"ERROR_ERRNO":816,
 "ERROR_PATH":824,"ERROR_PATH_N":832,"TEXT_AT":840,"TEXT_N":848,
 "NEXT_POINT":1000,"HEADER":1024,"LAST_HEADER":1088,
 "ROOT_PATH":4000,"RESULT_DOMAIN":856,
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_valid(s, w) == 0:
            return refused(w)
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(s, 16))
        put(w, SEQ, uint(s, 24))
        put(w, SOURCE_BYTES, length(s))
        put(w, USED, BASE)
        store(w, ROOT_PATH, 47)
        store(w, ROOT_PATH + 1, 0)
        copy_read(w, s, HEADER, 0, 64)
    elif get(w, 0) != STATE or source_same(s, w) == 0:
        return refused(w)
    if get(w, PHASE) == 99 or get(w, PHASE) == 0:
        return refused(w)
    if get(w, PENDING) != 0:
        if reply_valid(r, w) == 0:
            return refused(w)
        result = response(r, w)
        if result != 0:
            return result
    else:
        if get(w, LAST) == 0:
            if length(r) != 0:
                return refused(w)
        else:
            if length(r) != get(w, LAST_SIZE) or length(r) < 64:
                return refused(w)
            i = 0
            while i < 64:
                if byte(r, i) != byte(w, LAST_HEADER + i):
                    return refused(w)
                i = i + 1
    while get(w, PHASE) != 99:
        phase = get(w, PHASE)
        result = 0
        if phase == 1:
            result = initial(s, w)
        elif phase == 3:
            result = absolute_done(w)
        elif phase == 12:
            result = mkdir_start(w)
        elif phase == 22:
            result = mkdir_unwind(w)
        elif phase == 29:
            result = resolve_start(w)
        elif phase == 30:
            result = resolve_next(w)
        elif phase == 35:
            result = cycle_unwind(w)
        elif phase == 39:
            result = resolve_stat(w)
        elif phase == 41:
            result = complete(w)
        else:
            return refused(w)
        if result != 0:
            return result
    return refused(w)

def source_valid(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 64 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0:
        return 0
    if uint(s, 32) != length(s) - 64 or uint(s, 40) != length(s):
        return 0
    if uint(s, 48) != 0 or uint(s, 56) != 0 or length(s) > MAX - BASE - 2:
        return 0
    at = 64
    while at < length(s):
        cp = point(s, w, at, length(s), 1)
        if cp == MAX or cp == 0:
            return 0
        if cp >= 55296 and cp <= 57343 and (cp < 56448 or cp > 56575):
            return 0
        at = get(w, NEXT_POINT)
    return 1

def source_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, SOURCE_BYTES) or length(s) < 64:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, HEADER + i):
            return 0
        i = i + 1
    return 1

def need(w:mutbuf, count:u64) -> u64:
    if count > MAX - get(w, USED):
        put(w, 8, 1)
        return 0
    put(w, NEEDED, get(w, USED) + count)
    if get(w, NEEDED) > length(w):
        return 0
    return 1

def growing(w:mutbuf) -> u64:
    if get(w, 8) != 0:
        return refused(w)
    emit(w, 1)
    return GROW

def refused(w:mutbuf) -> u64:
    put(w, 8, 1)
    emit(w, 6)
    return BAD

def emit(w:mutbuf, action:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, OP))
    put(w, 296, get(w, ERROR_DOMAIN))
    put(w, 304, get(w, ERROR_CODE))
    put(w, 312, get(w, ERROR_ERRNO))
    if action == 2:
        put(w, 320, get(w, FS_PATH))
        put(w, 328, get(w, FS_PATH_N))
        put(w, 336, get(w, FS_COUNT))
        put(w, 344, get(w, FS_MODE))
    elif action == 0:
        if get(w, ERROR_DOMAIN) == 0:
            put(w, 320, get(w, DEST))
            put(w, 328, get(w, DEST_N))
            put(w, 336, get(w, PARENT))
            put(w, 344, get(w, PARENT_N))
            put(w, 352, get(w, TEXT_AT))
            put(w, 360, get(w, TEXT_N))
        else:
            put(w, 320, get(w, ERROR_PATH))
            put(w, 328, get(w, ERROR_PATH_N))
    put(w, 368, get(w, NEEDED))
    put(w, 376, get(w, PHASE))
    return 0

def done(w:mutbuf, domain:u64, code:u64, err:u64, at:u64, count:u64) -> u64:
    put(w, ERROR_DOMAIN, domain)
    put(w, ERROR_CODE, code)
    put(w, ERROR_ERRNO, err)
    put(w, ERROR_PATH, at)
    put(w, ERROR_PATH_N, count)
    put(w, PENDING, 0)
    put(w, PHASE, 99)
    emit(w, 0)
    return 128

def issue(w:mutbuf, op:u64, at:u64, count:u64, capacity:u64, mode:u64, phase:u64) -> u64:
    if get(w, SEQ) == MAX:
        return refused(w)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, OP, op)
    put(w, FS_PATH, at)
    put(w, FS_PATH_N, count)
    put(w, FS_COUNT, capacity)
    put(w, FS_MODE, mode)
    put(w, PENDING, 1)
    put(w, PHASE, phase)
    emit(w, 2)
    return 128

def reply_valid(r:readbuf, w:mutbuf) -> u64:
    if get(w, PENDING) != 1 or length(r) < 64 or uint(r, 0) != ACK:
        return 0
    if uint(r, 8) != get(w, LEASE) or uint(r, 16) != get(w, SEQ) or uint(r, 24) != get(w, OP):
        return 0
    if uint(r, 32) > 1 or uint(r, 56) != length(r) - 64:
        return 0
    op = get(w, OP)
    phase = get(w, PHASE)
    expected = 0
    if phase == 2:
        expected = 14
    elif phase == 10 or phase == 21 or phase == 40:
        expected = 7
    elif phase == 11 or phase == 31:
        expected = 8
    elif phase == 20:
        expected = 11
    elif phase == 32:
        expected = 13
    if expected == 0 or op != expected:
        return 0
    if uint(r, 32) != 0:
        if uint(r, 40) != 0 or uint(r, 48) == 0 or uint(r, 48) > 4095 or uint(r, 56) != 0:
            return 0
        return 1
    if uint(r, 48) != 0:
        return 0
    if op == 7 or op == 8:
        if uint(r, 40) != 0 or uint(r, 56) != 144:
            return 0
    elif op == 11:
        if uint(r, 40) != 0 or uint(r, 56) != 0:
            return 0
    else:
        if uint(r, 40) != uint(r, 56) or uint(r, 56) > get(w, FS_COUNT):
            return 0
        if op == 14:
            if uint(r, 56) < 2 or byte(r, length(r) - 1) != 0:
                return 0
        i = 64
        end = length(r)
        if op == 14:
            end = end - 1
        while i < end:
            if byte(r, i) == 0:
                return 0
            i = i + 1
    return 1

def consumed(r:readbuf, w:mutbuf) -> u64:
    put(w, PENDING, 0)
    put(w, LAST, 1)
    put(w, LAST_SIZE, length(r))
    copy_read(w, r, LAST_HEADER, 0, 64)
    return 0

def ignored(error:u64) -> u64:
    if error == 2 or error == 20 or error == 9 or error == 40:
        return 1
    return 0

def initial(s:readbuf, w:mutbuf) -> u64:
    count = length(s) - 64
    if need(w, count + 2) == 0:
        return growing(w)
    out = get(w, USED)
    start = out
    at = 64
    while at < length(s):
        cp = point(s, w, at, length(s), 1)
        end = get(w, NEXT_POINT)
        if cp >= 56448 and cp <= 56575:
            store(w, out, cp - 56320)
            out = out + 1
        else:
            while at < end:
                store(w, out, byte(s, at))
                out = out + 1
                at = at + 1
        at = end
    count = lexical(w, start, out - start, 0)
    store(w, start + count, 0)
    put(w, USED, start + count + 1)
    put(w, DEST, start)
    put(w, DEST_N, count)
    if byte(w, start) == 47:
        put(w, PHASE, 3)
        return 0
    put(w, CWD_CAP, 1024)
    return issue(w, 14, 0, 0, 1024, 0, 2)

def absolute_done(w:mutbuf) -> u64:
    n = parent_size(w, get(w, DEST), get(w, DEST_N))
    if need(w, n + 1) == 0:
        return growing(w)
    at = get(w, USED)
    copy_local(w, at, get(w, DEST), n)
    store(w, at + n, 0)
    put(w, USED, at + n + 1)
    put(w, PARENT, at)
    put(w, PARENT_N, n)
    return issue(w, 7, get(w, DEST), get(w, DEST_N) + 1, 144, 0, 10)

def response(r:readbuf, w:mutbuf) -> u64:
    phase = get(w, PHASE)
    if phase == 2:
        return cwd_result(r, w)
    if phase == 10 or phase == 11:
        return destination_result(r, w, phase)
    if phase == 20 or phase == 21:
        return mkdir_result(r, w, phase)
    if phase == 31 or phase == 32:
        return resolve_result(r, w, phase)
    if phase == 40:
        consumed(r, w)
        if uint(r, 32) != 0 and uint(r, 48) == 40:
            return done(w, 3, 1, 40, get(w, CANDIDATE), get(w, CANDIDATE_N))
        if same(w, get(w, RESOLVED), get(w, RESOLVED_N), get(w, PARENT), get(w, PARENT_N)) == 0:
            return done(w, 1, 2, 0, 0, 0)
        put(w, PHASE, 41)
        return 0
    return refused(w)

def cwd_result(r:readbuf, w:mutbuf) -> u64:
    if uint(r, 32) != 0:
        consumed(r, w)
        if uint(r, 48) == 34:
            if get(w, CWD_CAP) > MAX - 1024:
                return refused(w)
            put(w, CWD_CAP, get(w, CWD_CAP) + 1024)
            return issue(w, 14, 0, 0, get(w, CWD_CAP), 0, 2)
        return done(w, 2, 14, uint(r, 48), 0, 0)
    if byte(r, 64) != 47:
        consumed(r, w)
        return done(w, 2, 14, 2, 0, 0)
    cwd = uint(r, 56) - 1
    extra = get(w, DEST_N)
    if extra == 1 and byte(w, get(w, DEST)) == 46:
        extra = 0
    if cwd > MAX - 2 or extra > MAX - cwd - 2:
        return refused(w)
    if need(w, cwd + extra + 2) == 0:
        return growing(w)
    at = get(w, USED)
    copy_read(w, r, at, 64, cwd)
    out = at + cwd
    if extra != 0:
        if byte(w, out - 1) != 47:
            store(w, out, 47)
            out = out + 1
        copy_local(w, out, get(w, DEST), extra)
        out = out + extra
    store(w, out, 0)
    put(w, DEST, at)
    put(w, DEST_N, out - at)
    put(w, USED, out + 1)
    consumed(r, w)
    put(w, PHASE, 3)
    return 0

def destination_result(r:readbuf, w:mutbuf, phase:u64) -> u64:
    consumed(r, w)
    if uint(r, 32) == 0:
        if phase == 10 or (uint(r, 88) & 61440) == 40960:
            return done(w, 1, 1, 0, 0, 0)
    elif ignored(uint(r, 48)) == 0:
        return done(w, 2, get(w, OP), uint(r, 48), get(w, DEST), get(w, DEST_N))
    if phase == 10:
        return issue(w, 8, get(w, DEST), get(w, DEST_N) + 1, 144, 0, 11)
    put(w, PHASE, 12)
    return 0

def mkdir_start(w:mutbuf) -> u64:
    put(w, CURRENT, get(w, PARENT))
    put(w, CURRENT_N, get(w, PARENT_N))
    put(w, MK_STACK, 0)
    put(w, MK_PARENTS, 1)
    return issue(w, 11, get(w, CURRENT), get(w, CURRENT_N) + 1, 0, 511, 20)

def mkdir_result(r:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 21:
        consumed(r, w)
        if uint(r, 32) == 0 and (uint(r, 88) & 61440) == 16384:
            put(w, PHASE, 22)
            return 0
        err = get(w, SAVED_ERRNO)
        if uint(r, 32) != 0 and ignored(uint(r, 48)) == 0:
            err = uint(r, 48)
        return done(w, 2, 11, err, get(w, CURRENT), get(w, CURRENT_N))
    if uint(r, 32) == 0:
        consumed(r, w)
        put(w, PHASE, 22)
        return 0
    err = uint(r, 48)
    if err == 2:
        size = parent_size(w, get(w, CURRENT), get(w, CURRENT_N))
        if get(w, MK_PARENTS) == 0 or size == get(w, CURRENT_N):
            consumed(r, w)
            return done(w, 2, 11, err, get(w, CURRENT), get(w, CURRENT_N))
        if size > MAX - 25:
            return refused(w)
        if need(w, size + 25) == 0:
            return growing(w)
        at = get(w, USED)
        put(w, at, get(w, MK_STACK))
        put(w, at + 8, get(w, CURRENT))
        put(w, at + 16, get(w, CURRENT_N))
        copy_local(w, at + 24, get(w, CURRENT), size)
        store(w, at + 24 + size, 0)
        put(w, USED, at + 25 + size)
        put(w, MK_STACK, at)
        put(w, CURRENT, at + 24)
        put(w, CURRENT_N, size)
        put(w, MK_PARENTS, 1)
        consumed(r, w)
        return issue(w, 11, at + 24, size + 1, 0, 511, 20)
    consumed(r, w)
    put(w, SAVED_ERRNO, err)
    return issue(w, 7, get(w, CURRENT), get(w, CURRENT_N) + 1, 144, 0, 21)

def mkdir_unwind(w:mutbuf) -> u64:
    node = get(w, MK_STACK)
    if node == 0:
        put(w, PHASE, 29)
        return 0
    put(w, CURRENT, get(w, node + 8))
    put(w, CURRENT_N, get(w, node + 16))
    put(w, MK_STACK, get(w, node))
    put(w, MK_PARENTS, 0)
    return issue(w, 11, get(w, CURRENT), get(w, CURRENT_N) + 1, 0, 511, 20)

def resolve_start(w:mutbuf) -> u64:
    put(w, RESOLVED, ROOT_PATH)
    put(w, RESOLVED_N, 1)
    put(w, REST, get(w, PARENT))
    put(w, REST_N, get(w, PARENT_N))
    put(w, REST_POS, 0)
    put(w, RES_STACK, 0)
    put(w, SEEN, 0)
    put(w, PHASE, 30)
    return 0

def resolve_next(w:mutbuf) -> u64:
    at = get(w, REST)
    n = get(w, REST_N)
    pos = get(w, REST_POS)
    if pos >= n:
        stack = get(w, RES_STACK)
        if stack == 0:
            put(w, PHASE, 39)
            return 0
        node = get(w, stack + 32)
        put(w, node + 24, get(w, RESOLVED))
        put(w, node + 32, get(w, RESOLVED_N))
        put(w, node + 40, 1)
        put(w, REST, get(w, stack + 8))
        put(w, REST_N, get(w, stack + 16))
        put(w, REST_POS, get(w, stack + 24))
        put(w, RES_STACK, get(w, stack))
        return 0
    start = pos
    while pos < n and byte(w, at + pos) != 47:
        pos = pos + 1
    size = pos - start
    next = pos
    if pos < n:
        next = pos + 1
    if size == 0 or (size == 1 and byte(w, at + start) == 46):
        put(w, REST_POS, next)
        return 0
    if size == 2 and byte(w, at + start) == 46 and byte(w, at + start + 1) == 46:
        put(w, RESOLVED_N, parent_size(w, get(w, RESOLVED), get(w, RESOLVED_N)))
        put(w, REST_POS, next)
        return 0
    prefix = get(w, RESOLVED_N)
    if prefix > MAX - 2 or size > MAX - prefix - 2:
        return refused(w)
    if need(w, prefix + size + 2) == 0:
        return growing(w)
    out = get(w, USED)
    copy_local(w, out, get(w, RESOLVED), prefix)
    end = out + prefix
    if byte(w, end - 1) != 47:
        store(w, end, 47)
        end = end + 1
    copy_local(w, end, at + start, size)
    end = end + size
    store(w, end, 0)
    put(w, USED, end + 1)
    put(w, CANDIDATE, out)
    put(w, CANDIDATE_N, end - out)
    put(w, REST_POS, next)
    return issue(w, 8, out, end - out + 1, 144, 0, 31)

def resolve_result(r:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 32:
        return readlink_result(r, w)
    if uint(r, 32) != 0 or (uint(r, 88) & 61440) != 40960:
        consumed(r, w)
        put(w, RESOLVED, get(w, CANDIDATE))
        put(w, RESOLVED_N, get(w, CANDIDATE_N))
        put(w, PHASE, 30)
        return 0
    node = get(w, SEEN)
    while node != 0:
        if same(w, get(w, node + 8), get(w, node + 16), get(w, CANDIDATE), get(w, CANDIDATE_N)) != 0:
            consumed(r, w)
            if get(w, node + 40) != 0:
                put(w, RESOLVED, get(w, node + 24))
                put(w, RESOLVED_N, get(w, node + 32))
                put(w, PHASE, 30)
            else:
                put(w, RESOLVED, get(w, CANDIDATE))
                put(w, RESOLVED_N, get(w, CANDIDATE_N))
                put(w, PHASE, 35)
            return 0
        node = get(w, node)
    consumed(r, w)
    return issue(w, 13, get(w, CANDIDATE), get(w, CANDIDATE_N) + 1, 4096, 0, 32)

def readlink_result(r:readbuf, w:mutbuf) -> u64:
    if uint(r, 32) != 0:
        consumed(r, w)
        return done(w, 2, 13, uint(r, 48), get(w, CANDIDATE), get(w, CANDIDATE_N))
    n = uint(r, 56)
    if n > MAX - 89:
        return refused(w)
    if need(w, n + 89) == 0:
        return growing(w)
    node = get(w, USED)
    stack = node + 48
    data = stack + 40
    put(w, node, get(w, SEEN))
    put(w, node + 8, get(w, CANDIDATE))
    put(w, node + 16, get(w, CANDIDATE_N))
    put(w, node + 24, 0)
    put(w, node + 32, 0)
    put(w, node + 40, 0)
    put(w, stack, get(w, RES_STACK))
    put(w, stack + 8, get(w, REST))
    put(w, stack + 16, get(w, REST_N))
    put(w, stack + 24, get(w, REST_POS))
    put(w, stack + 32, node)
    copy_read(w, r, data, 64, n)
    store(w, data + n, 0)
    put(w, USED, data + n + 1)
    put(w, SEEN, node)
    put(w, RES_STACK, stack)
    put(w, REST, data)
    put(w, REST_N, n)
    put(w, REST_POS, 0)
    if n != 0 and byte(w, data) == 47:
        put(w, RESOLVED, ROOT_PATH)
        put(w, RESOLVED_N, 1)
    consumed(r, w)
    put(w, PHASE, 30)
    return 0

def cycle_unwind(w:mutbuf) -> u64:
    n = get(w, REST_N) - get(w, REST_POS)
    prefix = get(w, RESOLVED_N)
    if prefix > MAX - 2 or n > MAX - prefix - 2:
        return refused(w)
    if need(w, prefix + n + 2) == 0:
        return growing(w)
    at = get(w, USED)
    copy_local(w, at, get(w, RESOLVED), prefix)
    end = at + prefix
    if n != 0:
        if byte(w, end - 1) != 47:
            store(w, end, 47)
            end = end + 1
        copy_local(w, end, get(w, REST) + get(w, REST_POS), n)
        end = end + n
    store(w, end, 0)
    put(w, USED, end + 1)
    put(w, RESOLVED, at)
    put(w, RESOLVED_N, end - at)
    stack = get(w, RES_STACK)
    if stack != 0:
        put(w, REST, get(w, stack + 8))
        put(w, REST_N, get(w, stack + 16))
        put(w, REST_POS, get(w, stack + 24))
        put(w, RES_STACK, get(w, stack))
        return 0
    size = lexical(w, at, end - at, 1)
    store(w, at + size, 0)
    put(w, RESOLVED_N, size)
    put(w, PHASE, 39)
    return 0

def resolve_stat(w:mutbuf) -> u64:
    n = get(w, RESOLVED_N)
    if need(w, n + 1) == 0:
        return growing(w)
    at = get(w, USED)
    copy_local(w, at, get(w, RESOLVED), n)
    store(w, at + n, 0)
    put(w, USED, at + n + 1)
    put(w, CANDIDATE, at)
    put(w, CANDIDATE_N, n)
    return issue(w, 7, at, n + 1, 144, 0, 40)

def complete(w:mutbuf) -> u64:
    n = get(w, DEST_N)
    if n > 6148914691236517204:
        return refused(w)
    if need(w, n * 3 + 1) == 0:
        return growing(w)
    at = get(w, USED)
    end = get(w, DEST) + n
    pos = get(w, DEST)
    out = at
    while pos < end:
        cp = point_local(w, pos, end)
        next = get(w, NEXT_POINT)
        if cp == MAX or (cp >= 55296 and cp <= 57343):
            cp = 56320 + byte(w, pos)
            next = pos + 1
        out = encode(w, out, cp)
        pos = next
    put(w, TEXT_AT, at)
    put(w, TEXT_N, out - at)
    store(w, out, 0)
    put(w, USED, out + 1)
    return done(w, 0, 0, 0, 0, 0)

def parent_size(w:mutbuf, at:u64, n:u64) -> u64:
    root = 1
    if n >= 2 and byte(w, at) == 47 and byte(w, at + 1) == 47:
        root = 2
    while n > root and byte(w, at + n - 1) != 47:
        n = n - 1
    if n > root:
        n = n - 1
    return n

def lexical(w:mutbuf, at:u64, n:u64, collapse:u64) -> u64:
    leading = 0
    while leading < n and byte(w, at + leading) == 47:
        leading = leading + 1
    out = 0
    root = 0
    if leading != 0:
        store(w, at, 47)
        out = 1
        if leading == 2:
            store(w, at + 1, 47)
            out = 2
        root = out
    pos = leading
    while pos < n:
        start = pos
        while pos < n and byte(w, at + pos) != 47:
            pos = pos + 1
        size = pos - start
        if size != 0 and (size != 1 or byte(w, at + start) != 46):
            if collapse != 0 and size == 2 and byte(w, at + start) == 46 and byte(w, at + start + 1) == 46:
                if out > root:
                    out = parent_size(w, at, out)
            else:
                if out != 0 and byte(w, at + out - 1) != 47:
                    store(w, at + out, 47)
                    out = out + 1
                copy_local(w, at + out, at + start, size)
                out = out + size
        if pos < n:
            pos = pos + 1
    if out == 0:
        store(w, at, 46)
        out = 1
    return out

def same(w:mutbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    if an != bn:
        return 0
    i = 0
    while i < an:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def point(s:readbuf, w:mutbuf, at:u64, end:u64, surrogate:u64) -> u64:
    if at >= end:
        return MAX
    ch = byte(s, at)
    size = 1
    cp = ch
    if ch >= 128:
        if ch >= 194 and ch <= 223:
            size = 2
            cp = ch & 31
        elif ch >= 224 and ch <= 239:
            size = 3
            cp = ch & 15
        elif ch >= 240 and ch <= 244:
            size = 4
            cp = ch & 7
        else:
            return MAX
        if size > end - at:
            return MAX
        i = 1
        while i < size:
            ch = byte(s, at + i)
            if ch < 128 or ch > 191:
                return MAX
            cp = (cp << 6) | (ch & 63)
            i = i + 1
        if (size == 2 and cp < 128) or (size == 3 and cp < 2048) or (size == 4 and cp < 65536) or cp > 1114111:
            return MAX
        if surrogate == 0 and cp >= 55296 and cp <= 57343:
            return MAX
    put(w, NEXT_POINT, at + size)
    return cp

def point_local(w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end:
        return MAX
    ch = byte(w, at)
    size = 1
    cp = ch
    if ch >= 128:
        if ch >= 194 and ch <= 223:
            size = 2
            cp = ch & 31
        elif ch >= 224 and ch <= 239:
            size = 3
            cp = ch & 15
        elif ch >= 240 and ch <= 244:
            size = 4
            cp = ch & 7
        else:
            return MAX
        if size > end - at:
            return MAX
        i = 1
        while i < size:
            ch = byte(w, at + i)
            if ch < 128 or ch > 191:
                return MAX
            cp = (cp << 6) | (ch & 63)
            i = i + 1
        if (size == 2 and cp < 128) or (size == 3 and cp < 2048) or (size == 4 and cp < 65536) or cp > 1114111:
            return MAX
    put(w, NEXT_POINT, at + size)
    return cp

def encode(w:mutbuf, at:u64, cp:u64) -> u64:
    if cp < 128:
        store(w, at, cp)
        return at + 1
    if cp < 2048:
        store(w, at, 192 | (cp >> 6))
        store(w, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(w, at, 224 | (cp >> 12))
        store(w, at + 1, 128 | ((cp >> 6) & 63))
        store(w, at + 2, 128 | (cp & 63))
        return at + 3
    store(w, at, 240 | (cp >> 18))
    store(w, at + 1, 128 | ((cp >> 12) & 63))
    store(w, at + 2, 128 | ((cp >> 6) & 63))
    store(w, at + 3, 128 | (cp & 63))
    return at + 4

def copy_read(w:mutbuf, s:readbuf, at:u64, begin:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, byte(s, begin + i))
        i = i + 1
    return 0

def copy_local(w:mutbuf, at:u64, begin:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, byte(w, begin + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, 0)
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
