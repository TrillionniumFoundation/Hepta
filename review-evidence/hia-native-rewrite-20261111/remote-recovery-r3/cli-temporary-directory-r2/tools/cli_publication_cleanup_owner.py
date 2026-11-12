"""Native Linux CPython-3.12.14 TemporaryDirectory cleanup, new revision 1.
All traversal, fd ownership, delayed directory jobs and permission callbacks
belong to HIA. Raw filesystem receipts are private issued inputs, not authority
authenticated by these headers. A single command consumes one owned temp root.
"""
CONSTANTS={
 "BAD":0xfffffffd,"GROW":0xfffffffe,"MAX":(1<<64)-1,"BASE":4096,
 "COMMAND":int.from_bytes(b"HIATRC01","little"),"STATE":int.from_bytes(b"HIATRS01","little"),
 "EVENT":int.from_bytes(b"HIATRE01","little"),"ACK":int.from_bytes(b"HIATRA01","little"),
 "PHASE":16,"LEASE":24,"SEQ":32,"OP":40,"PENDING":48,"USED":56,"NEEDED":64,
 "SOURCE_N":72,"CONTEXT":80,"NEXT_TOKEN":88,"LIVE":96,"LAST":104,"LAST_N":112,
 "PINNED":120,"RESULT_KIND":128,"RESULT_ERRNO":136,"RESULT_OP":144,"RESULT_PATH":152,"RESULT_N":160,
 "FS_PATH":168,"FS_N":176,"FS_TOKEN":184,"FS_COUNT":192,"FS_A":200,"FS_B":208,"FS_OTHER":216,
 "HEADER":512,"LAST_HEADER":576,"PIN_HEADER":640,
 "C_PREV":0,"C_STACK":8,"C_NAME":16,"C_N":24,"C_REPEATED":32,"C_MODE":40,
 "C_RETURN":48,"C_PHASE":56,"C_JOB":64,"C_ENTRY":72,"C_HEAD":80,"C_TAIL":88,
 "C_FD":96,"C_SCAN":104,"C_DEV":112,"C_INO":120,"C_ERR_KIND":128,"C_ERRNO":136,
 "C_ERR_PATH":144,"C_ERR_N":152,"C_ERR_OP":160,
 "C_CB_PATH":168,"C_CB_N":176,"C_CB_KIND":184,"C_CB_ERRNO":192,"C_CB_OP":200,
 "C_AFTER":208,"C_WRAP":216,"C_RESET":224,"C_RESET_N":232,"C_RESET_STAGE":240,"C_SAVED":248,
 "J_NEXT":0,"J_KIND":8,"J_TOKEN":16,"J_PATH":24,"J_N":32,"J_ENTRY":40,"J_NAME":48,"J_NAME_N":56,
 "E_NEXT":0,"E_PATH":8,"E_N":16,"E_NAME":24,"E_NAME_N":32,"E_TYPE":40,"E_CACHED":48,
 "E_DEV":56,"E_INO":64,"E_MODE":72,"ENTRY_BYTES":80
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_valid(s) == 0:
            return refused(w)
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(s, 16))
        put(w, SEQ, uint(s, 24))
        put(w, SOURCE_N, length(s))
        put(w, USED, BASE)
        put(w, NEXT_TOKEN, 1)
        copy_read(w, s, HEADER, 0, 64)
    elif get(w, 0) != STATE or source_same(s, w) == 0:
        return refused(w)
    if get(w, PHASE) == 99:
        return refused(w)
    if get(w, PHASE) == 1:
        if length(r) != 0:
            return refused(w)
        v = status_wide(initial(s, w))
        if v != 0:
            return v
    elif get(w, PENDING) != 0:
        if reply_valid(r, w) == 0:
            return refused(w)
        v = status_wide(response(r, w))
        if v != 0:
            return v
    else:
        if get(w, LAST) == 0:
            if length(r) != 0:
                return refused(w)
        else:
            if length(r) != get(w, LAST_N) or length(r) < 64:
                return refused(w)
            i = 0
            while i < 64:
                if byte(r, i) != byte(w, LAST_HEADER + i):
                    return refused(w)
                i = i + 1
    while get(w, PHASE) != 99:
        c = get(w, CONTEXT)
        if c == 0:
            return refused(w)
        phase = get(w, c + C_PHASE)
        v = 0
        if phase == 1:
            v = status_wide(next_job(w))
        elif phase == 2:
            v = status_wide(begin_walk(w))
        elif phase == 20:
            v = status_wide(entry_next(w))
        elif phase == 100:
            v = status_wide(callback_begin(w))
        elif phase == 110:
            v = status_wide(reset_start(w))
        elif phase == 120:
            v = status_wide(callback_unlink(w))
        elif phase == 130:
            v = status_wide(callback_recurse(w))
        elif phase == 150:
            v = status_wide(abort_next(w))
        else:
            return refused(w)
        if v != 0:
            return v
    return refused(w)

def source_valid(s:readbuf) -> u64:
    if length(s) < 66 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0 or uint(s, 32) != length(s) - 65:
        return 0
    if uint(s, 40) != length(s) or uint(s, 48) != 0 or uint(s, 56) != 0:
        return 0
    if byte(s, 64) != 47 or byte(s, length(s) - 1) != 0 or length(s) > MAX - BASE - 321:
        return 0
    i = 64
    while i + 1 < length(s):
        if byte(s, i) == 0:
            return 0
        i = i + 1
    return 1

def source_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, SOURCE_N) or length(s) < 64:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, HEADER + i):
            return 0
        i = i + 1
    if get(w, PHASE) != 1:
        i = 64
        while i < length(s):
            if byte(s, i) != byte(w, BASE + i - 64):
                return 0
            i = i + 1
    return 1

def need(w:mutbuf, n:u64) -> u64:
    if n > MAX - get(w, USED):
        put(w, 8, 1)
        return 0
    put(w, NEEDED, get(w, USED) + n)
    if get(w, NEEDED) > length(w):
        return 0
    return 1

def growing(w:mutbuf) -> u32:
    if get(w, 8) != 0:
        return refused(w)
    emit(w, 1)
    return GROW

def initial(s:readbuf, w:mutbuf) -> u32:
    n = length(s) - 64
    if need(w, n + 320) == 0:
        return growing(w)
    copy_read(w, s, BASE, 64, n)
    c = BASE + n
    zero(w, c, 256)
    put(w, c + C_NAME, BASE)
    put(w, c + C_N, n - 1)
    put(w, c + C_PHASE, 1)
    job = c + 256
    make_job(w, job, 1, MAX, BASE, n - 1, 0)
    put(w, c + C_STACK, job)
    put(w, CONTEXT, c)
    put(w, USED, job + 64)
    put(w, PHASE, 2)
    return 0

def make_job(w:mutbuf, at:u64, kind:u64, token:u64, path:u64, n:u64, ent:u64) -> u64:
    zero(w, at, 64)
    put(w, at + J_KIND, kind)
    put(w, at + J_TOKEN, token)
    put(w, at + J_PATH, path)
    put(w, at + J_N, n)
    put(w, at + J_ENTRY, ent)
    if ent == 0:
        put(w, at + J_NAME, path)
        put(w, at + J_NAME_N, n)
    else:
        put(w, at + J_NAME, get(w, ent + E_NAME))
        put(w, at + J_NAME_N, get(w, ent + E_NAME_N))
    return 0

def push_job(w:mutbuf, at:u64) -> u64:
    c = get(w, CONTEXT)
    put(w, at + J_NEXT, get(w, c + C_STACK))
    put(w, c + C_STACK, at)
    return 0

def next_job(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    if get(w, c + C_MODE) != 0:
        put(w, c + C_PHASE, 150)
        return 0
    job = get(w, c + C_STACK)
    if job == 0:
        return context_complete(w, 0)
    put(w, c + C_STACK, get(w, job + J_NEXT))
    put(w, c + C_JOB, job)
    kind = get(w, job + J_KIND)
    if kind == 1:
        put(w, c + C_PHASE, 2)
        return 0
    if kind == 2:
        if get(w, LIVE) == 0:
            return refused(w)
        put(w, LIVE, get(w, LIVE) - 1)
        return issue(w, 2, get(w, job + J_TOKEN), 0, 0, 0, 0, 0, 0, 30)
    if kind == 3:
        if get(w, job + J_TOKEN) == MAX:
            return issue(w, 12, 0, get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 0, 0, 0, 0, 31)
        return issue(w, 21, get(w, job + J_TOKEN), get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 0, 512, 0, 0, 31)
    return refused(w)

def begin_walk(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    job = get(w, c + C_JOB)
    ent = get(w, job + J_ENTRY)
    if ent != 0 and get(w, ent + E_CACHED) != 0:
        put(w, c + C_DEV, get(w, ent + E_DEV))
        put(w, c + C_INO, get(w, ent + E_INO))
        return begin_open(w)
    if ent == 0:
        return issue(w, 8, 0, get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 144, 0, 0, 0, 3)
    return issue(w, 17, get(w, job + J_TOKEN), get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 144, 256, 0, 0, 3)

def begin_open(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    job = get(w, c + C_JOB)
    if need(w, 128) == 0:
        return growing(w)
    token = new_token(w)
    if token == 0:
        return refused(w)
    put(w, c + C_FD, token)
    if get(w, job + J_TOKEN) == MAX:
        return issue(w, 1, token, get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 0, 526336, 0, 0, 4)
    return issue(w, 16, token, get(w, job + J_NAME), get(w, job + J_NAME_N) + 1, 0, 526336, 0, get(w, job + J_TOKEN), 4)

def new_token(w:mutbuf) -> u64:
    token = get(w, NEXT_TOKEN)
    if token == 0 or token == MAX:
        return 0
    put(w, NEXT_TOKEN, token + 1)
    return token

def issue(w:mutbuf, op:u64, token:u64, path:u64, n:u64, cap:u64, a:u64, b:u64, other:u64, phase:u64) -> u32:
    if get(w, SEQ) == MAX:
        return refused(w)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, OP, op)
    put(w, FS_TOKEN, token)
    put(w, FS_PATH, path)
    put(w, FS_N, n)
    put(w, FS_COUNT, cap)
    put(w, FS_A, a)
    put(w, FS_B, b)
    put(w, FS_OTHER, other)
    put(w, PENDING, 1)
    put(w, PINNED, 0)
    put(w, get(w, CONTEXT) + C_PHASE, phase)
    emit(w, 2)
    return 256

def retry(w:mutbuf) -> u32:
    return issue(w, get(w, OP), get(w, FS_TOKEN), get(w, FS_PATH), get(w, FS_N),
                 get(w, FS_COUNT), get(w, FS_A), get(w, FS_B), get(w, FS_OTHER),
                 get(w, get(w, CONTEXT) + C_PHASE))

def consumed(r:readbuf, w:mutbuf) -> u64:
    put(w, PENDING, 0)
    put(w, PINNED, 0)
    put(w, LAST, 1)
    put(w, LAST_N, length(r))
    copy_read(w, r, LAST_HEADER, 0, 64)
    return 0

def reply_valid(r:readbuf, w:mutbuf) -> u64:
    if get(w, PENDING) != 1 or length(r) < 64 or uint(r, 0) != ACK:
        return 0
    if uint(r, 8) != get(w, LEASE) or uint(r, 16) != get(w, SEQ) or uint(r, 24) != get(w, OP):
        return 0
    if uint(r, 32) > 1 or uint(r, 56) != length(r) - 64:
        return 0
    op = get(w, OP)
    p = get(w, get(w, CONTEXT) + C_PHASE)
    good = 0
    job = get(w, get(w, CONTEXT) + C_JOB)
    if p == 3:
        if (get(w, job + J_ENTRY) == 0 and op == 8) or (get(w, job + J_ENTRY) != 0 and op == 17):
            good = 1
    elif p == 4:
        if (get(w, job + J_TOKEN) == MAX and op == 1) or (get(w, job + J_TOKEN) != MAX and op == 16):
            good = 1
    elif p == 5 and op == 3:
        good = 1
    elif p == 6 and op == 23:
        good = 1
    elif p == 7 and op == 18:
        good = 1
    elif (p == 8 or p == 30 or p == 151) and op == 2:
        good = 1
    elif p == 21 and op == 17:
        good = 1
    elif p == 22 and op == 21:
        good = 1
    elif p == 31:
        if (get(w, job + J_TOKEN) == MAX and op == 12) or (get(w, job + J_TOKEN) != MAX and op == 21):
            good = 1
    elif p == 111 and op == 8:
        good = 1
    elif p == 112 and op == 20:
        good = 1
    elif p == 121 and op == 10:
        good = 1
    elif p == 122 and op == 7:
        good = 1
    if good == 0:
        return 0
    if get(w, PINNED) != 0:
        i = 0
        while i < 64:
            if byte(r, i) != byte(w, PIN_HEADER + i):
                return 0
            i = i + 1
    if uint(r, 32) != 0:
        if uint(r, 40) != 0 or uint(r, 48) == 0 or uint(r, 48) > 4095 or uint(r, 56) != 0:
            return 0
    else:
        if uint(r, 48) != 0:
            return 0
        if op == 3 or op == 7 or op == 8 or op == 17:
            if uint(r, 40) != 0 or uint(r, 56) != 144:
                return 0
        elif op == 1 or op == 16 or op == 23:
            if uint(r, 40) != get(w, FS_TOKEN) or uint(r, 56) != 0:
                return 0
        elif op == 18:
            if uint(r, 40) != uint(r, 56) or uint(r, 56) > get(w, FS_COUNT):
                return 0
        elif uint(r, 40) != 0 or uint(r, 56) != 0:
            return 0
    copy_read(w, r, PIN_HEADER, 0, 64)
    put(w, PINNED, 1)
    return 1

def response(r:readbuf, w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    phase = get(w, c + C_PHASE)
    if phase == 3:
        if uint(r, 32) != 0:
            consumed(r, w)
            return job_error(w, 1, uint(r, 48), get(w, OP), 1)
        if need(w, 128) == 0:
            return growing(w)
        put(w, c + C_DEV, uint(r, 64))
        put(w, c + C_INO, uint(r, 72))
        ent = get(w, get(w, c + C_JOB) + J_ENTRY)
        if ent != 0:
            put(w, ent + E_CACHED, 1)
            put(w, ent + E_DEV, uint(r, 64))
            put(w, ent + E_INO, uint(r, 72))
            put(w, ent + E_MODE, uint(r, 88))
        consumed(r, w)
        return begin_open(w)
    if phase == 4:
        consumed(r, w)
        if uint(r, 32) != 0:
            if uint(r, 48) == 4:
                return retry(w)
            return job_error(w, 1, uint(r, 48), get(w, OP), 1)
        put(w, LIVE, get(w, LIVE) + 1)
        return issue(w, 3, get(w, c + C_FD), 0, 0, 144, 0, 0, 0, 5)
    if phase == 5:
        return opened_stat(r, w)
    if phase == 6:
        consumed(r, w)
        if uint(r, 32) != 0:
            if uint(r, 48) == 4:
                return retry(w)
            put(w, c + C_SCAN, 0)
            return job_error(w, 1, uint(r, 48), 18, 1)
        put(w, LIVE, get(w, LIVE) + 1)
        put(w, c + C_HEAD, 0)
        put(w, c + C_TAIL, 0)
        return issue(w, 18, get(w, c + C_SCAN), 0, 0, 32768, 0, 0, 0, 7)
    if phase == 7:
        return dents_result(r, w)
    if phase == 8:
        consumed(r, w)
        put(w, c + C_SCAN, 0)
        if get(w, c + C_SAVED) != 0:
            return job_error(w, 1, get(w, c + C_SAVED), 18, 1)
        put(w, c + C_ENTRY, get(w, c + C_HEAD))
        put(w, c + C_PHASE, 20)
        return 0
    if phase == 21:
        return entry_stat(r, w)
    if phase == 22:
        consumed(r, w)
        if uint(r, 32) != 0:
            ent = get(w, c + C_ENTRY)
            return callback(w, 1, uint(r, 48), 10, get(w, ent + E_PATH), get(w, ent + E_N), 2, 1)
        return entry_advance(w)
    if phase == 30 or phase == 31:
        consumed(r, w)
        if uint(r, 32) != 0:
            return job_error(w, 1, uint(r, 48), get(w, OP), 1)
        put(w, c + C_PHASE, 1)
        return 0
    if phase == 111 or phase == 112:
        return reset_reply(r, w, phase)
    if phase == 121 or phase == 122:
        return callback_reply(r, w, phase)
    if phase == 151:
        consumed(r, w)
        if uint(r, 32) != 0 and get(w, c + C_MODE) == 1:
            return job_error(w, 1, uint(r, 48), 2, 4)
        put(w, c + C_PHASE, 150)
        return 0
    return refused(w)

def opened_stat(r:readbuf, w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    job = get(w, c + C_JOB)
    same = 0
    if uint(r, 32) == 0:
        if uint(r, 64) == get(w, c + C_DEV) and uint(r, 72) == get(w, c + C_INO):
            same = 1
    n = 64
    if same != 0:
        n = 128
    if need(w, n) == 0:
        return growing(w)
    at = get(w, USED)
    if same != 0:
        make_job(w, at, 3, get(w, job + J_TOKEN), get(w, job + J_PATH), get(w, job + J_N), get(w, job + J_ENTRY))
        push_job(w, at)
        at = at + 64
    make_job(w, at, 2, get(w, c + C_FD), get(w, job + J_PATH), get(w, job + J_N), get(w, job + J_ENTRY))
    push_job(w, at)
    put(w, USED, at + 64)
    consumed(r, w)
    if same == 0:
        if uint(r, 32) != 0:
            return job_error(w, 1, uint(r, 48), 3, 1)
        return job_error(w, 2, 0, 3, 1)
    token = new_token(w)
    if token == 0:
        return refused(w)
    put(w, c + C_SCAN, token)
    return issue(w, 23, token, 0, 0, 0, 0, 0, get(w, c + C_FD), 6)

def dirent_size(r:readbuf, at:u64) -> u64:
    return byte(r, at + 16) | (byte(r, at + 17) << 8)

def dents_result(r:readbuf, w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    if uint(r, 32) != 0 or uint(r, 56) == 0:
        err = 0
        if uint(r, 32) != 0 and uint(r, 48) != 2:
            err = uint(r, 48)
        put(w, c + C_SAVED, err)
        consumed(r, w)
        if get(w, LIVE) == 0:
            return refused(w)
        put(w, LIVE, get(w, LIVE) - 1)
        return issue(w, 2, get(w, c + C_SCAN), 0, 0, 0, 0, 0, 0, 8)
    job = get(w, c + C_JOB)
    prefix = get(w, job + J_N)
    sep = 1
    if prefix != 0 and byte(w, get(w, job + J_PATH) + prefix - 1) == 47:
        sep = 0
    at = 64
    total = 0
    while at < length(r):
        if length(r) - at < 20:
            return refused(w)
        size = dirent_size(r, at)
        if size < 20 or size > length(r) - at or (size & 7) != 0:
            return refused(w)
        end = at + 19
        while end < at + size and byte(r, end) != 0:
            if byte(r, end) == 47:
                return refused(w)
            end = end + 1
        if end == at + size or end == at + 19:
            return refused(w)
        n = end - at - 19
        dot = 0
        if n == 1 and byte(r, at + 19) == 46:
            dot = 1
        elif n == 2 and byte(r, at + 19) == 46 and byte(r, at + 20) == 46:
            dot = 1
        if dot == 0:
            if prefix > MAX - ENTRY_BYTES - sep - 1 or n > MAX - ENTRY_BYTES - prefix - sep - 1:
                return refused(w)
            extra = ENTRY_BYTES + prefix + sep + n + 1
            if total > MAX - extra:
                return refused(w)
            total = total + extra
        at = at + size
    if need(w, total) == 0:
        return growing(w)
    at = 64
    while at < length(r):
        size = dirent_size(r, at)
        n = 0
        while byte(r, at + 19 + n) != 0:
            n = n + 1
        dot = 0
        if n == 1 and byte(r, at + 19) == 46:
            dot = 1
        elif n == 2 and byte(r, at + 19) == 46 and byte(r, at + 20) == 46:
            dot = 1
        if dot == 0:
            ent = get(w, USED)
            path = ent + ENTRY_BYTES
            name = path + prefix + sep
            zero(w, ent, ENTRY_BYTES)
            copy_local(w, path, get(w, job + J_PATH), prefix)
            if sep != 0:
                store(w, path + prefix, 47)
            copy_read(w, r, name, at + 19, n)
            store(w, name + n, 0)
            put(w, ent + E_PATH, path)
            put(w, ent + E_N, prefix + sep + n)
            put(w, ent + E_NAME, name)
            put(w, ent + E_NAME_N, n)
            put(w, ent + E_TYPE, byte(r, at + 18))
            if get(w, c + C_TAIL) == 0:
                put(w, c + C_HEAD, ent)
            else:
                put(w, get(w, c + C_TAIL) + E_NEXT, ent)
            put(w, c + C_TAIL, ent)
            put(w, USED, name + n + 1)
        at = at + size
    consumed(r, w)
    return issue(w, 18, get(w, c + C_SCAN), 0, 0, 32768, 0, 0, 0, 7)

def entry_next(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    ent = get(w, c + C_ENTRY)
    if ent == 0:
        put(w, c + C_PHASE, 1)
        return 0
    kind = get(w, ent + E_TYPE)
    if kind == 4:
        return entry_directory(w)
    if kind == 0:
        return issue(w, 17, get(w, c + C_FD), get(w, ent + E_NAME), get(w, ent + E_NAME_N) + 1, 144, 256, 0, 0, 21)
    return entry_unlink(w)

def entry_stat(r:readbuf, w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    ent = get(w, c + C_ENTRY)
    if uint(r, 32) == 0:
        put(w, ent + E_CACHED, 1)
        put(w, ent + E_DEV, uint(r, 64))
        put(w, ent + E_INO, uint(r, 72))
        put(w, ent + E_MODE, uint(r, 88))
        if (uint(r, 88) & 61440) == 16384:
            if need(w, 64) == 0:
                return growing(w)
            consumed(r, w)
            return entry_directory(w)
    consumed(r, w)
    return entry_unlink(w)

def entry_directory(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    ent = get(w, c + C_ENTRY)
    if need(w, 64) == 0:
        return growing(w)
    at = get(w, USED)
    make_job(w, at, 1, get(w, c + C_FD), get(w, ent + E_PATH), get(w, ent + E_N), ent)
    push_job(w, at)
    put(w, USED, at + 64)
    return entry_advance(w)

def entry_unlink(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    ent = get(w, c + C_ENTRY)
    return issue(w, 21, get(w, c + C_FD), get(w, ent + E_NAME), get(w, ent + E_NAME_N) + 1, 0, 0, 0, 0, 22)

def entry_advance(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    ent = get(w, c + C_ENTRY)
    put(w, c + C_ENTRY, get(w, ent + E_NEXT))
    put(w, c + C_PHASE, 20)
    return 0

def job_error(w:mutbuf, kind:u64, err:u64, op:u64, after:u64) -> u32:
    c = get(w, CONTEXT)
    job = get(w, c + C_JOB)
    return callback(w, kind, err, op, get(w, job + J_PATH), get(w, job + J_N), after, 0)

def callback(w:mutbuf, kind:u64, err:u64, op:u64, path:u64, n:u64, after:u64, wrap:u64) -> u32:
    c = get(w, CONTEXT)
    put(w, c + C_CB_KIND, kind)
    put(w, c + C_CB_ERRNO, err)
    put(w, c + C_CB_OP, op)
    put(w, c + C_CB_PATH, path)
    put(w, c + C_CB_N, n)
    put(w, c + C_AFTER, after)
    put(w, c + C_WRAP, wrap)
    put(w, c + C_PHASE, 100)
    return 0

def callback_begin(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    kind = get(w, c + C_CB_KIND)
    err = get(w, c + C_CB_ERRNO)
    path = get(w, c + C_CB_PATH)
    n = get(w, c + C_CB_N)
    if kind == 1 and err == 2:
        return callback_success(w)
    if kind != 1 or (err != 1 and err != 13):
        return callback_fail(w, kind, err, get(w, c + C_CB_OP), path, n)
    equal = same(w, path, n, get(w, c + C_NAME), get(w, c + C_N))
    if get(w, c + C_REPEATED) != 0 and equal != 0:
        return callback_fail(w, kind, err, get(w, c + C_CB_OP), path, n)
    if equal == 0:
        pn = dirname_size(w, path, n)
        if need(w, pn + 1) == 0:
            return growing(w)
        out = get(w, USED)
        copy_local(w, out, path, pn)
        store(w, out + pn, 0)
        put(w, USED, out + pn + 1)
        put(w, c + C_RESET, out)
        put(w, c + C_RESET_N, pn)
        put(w, c + C_RESET_STAGE, 0)
    else:
        put(w, c + C_RESET, path)
        put(w, c + C_RESET_N, n)
        put(w, c + C_RESET_STAGE, 1)
    put(w, c + C_PHASE, 110)
    return 0

def dirname_size(w:mutbuf, path:u64, n:u64) -> u64:
    i = n
    while i != 0 and byte(w, path + i - 1) != 47:
        i = i - 1
    all = 1
    j = 0
    while j < i:
        if byte(w, path + j) != 47:
            all = 0
        j = j + 1
    if all == 0:
        while i != 0 and byte(w, path + i - 1) == 47:
            i = i - 1
    return i

def reset_start(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    return issue(w, 8, 0, get(w, c + C_RESET), get(w, c + C_RESET_N) + 1, 144, 0, 0, 0, 111)

def reset_reply(r:readbuf, w:mutbuf, phase:u64) -> u32:
    c = get(w, CONTEXT)
    consumed(r, w)
    if phase == 111:
        if uint(r, 32) == 0 and (uint(r, 88) & 61440) == 40960:
            return reset_done(w)
        return issue(w, 20, 0, get(w, c + C_RESET), get(w, c + C_RESET_N) + 1, 0, 0, 448, 0, 112)
    if uint(r, 32) != 0:
        if uint(r, 48) == 2:
            return callback_success(w)
        return callback_fail(w, 1, uint(r, 48), 20, get(w, c + C_RESET), get(w, c + C_RESET_N))
    return reset_done(w)

def reset_done(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    if get(w, c + C_RESET_STAGE) == 0:
        put(w, c + C_RESET_STAGE, 1)
        put(w, c + C_RESET, get(w, c + C_CB_PATH))
        put(w, c + C_RESET_N, get(w, c + C_CB_N))
        put(w, c + C_PHASE, 110)
    else:
        put(w, c + C_PHASE, 120)
    return 0

def callback_unlink(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    return issue(w, 10, 0, get(w, c + C_CB_PATH), get(w, c + C_CB_N) + 1, 0, 0, 0, 0, 121)

def callback_reply(r:readbuf, w:mutbuf, phase:u64) -> u32:
    c = get(w, CONTEXT)
    consumed(r, w)
    if phase == 122:
        if uint(r, 32) == 0 and (uint(r, 88) & 61440) == 16384:
            put(w, c + C_SAVED, same(w, get(w, c + C_CB_PATH), get(w, c + C_CB_N), get(w, c + C_NAME), get(w, c + C_N)))
            put(w, c + C_PHASE, 130)
            return 0
        return callback_fail(w, 1, get(w, c + C_SAVED), 10, get(w, c + C_CB_PATH), get(w, c + C_CB_N))
    if uint(r, 32) == 0 or uint(r, 48) == 2:
        return callback_success(w)
    err = uint(r, 48)
    if err == 21:
        put(w, c + C_SAVED, 0)
        put(w, c + C_PHASE, 130)
        return 0
    if err == 1 or err == 13:
        put(w, c + C_SAVED, err)
        return issue(w, 7, 0, get(w, c + C_CB_PATH), get(w, c + C_CB_N) + 1, 144, 0, 0, 0, 122)
    return callback_fail(w, 1, err, 10, get(w, c + C_CB_PATH), get(w, c + C_CB_N))

def callback_recurse(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    if need(w, 320) == 0:
        return growing(w)
    out = get(w, USED)
    zero(w, out, 256)
    put(w, out + C_PREV, c)
    put(w, out + C_NAME, get(w, c + C_CB_PATH))
    put(w, out + C_N, get(w, c + C_CB_N))
    put(w, out + C_REPEATED, get(w, c + C_SAVED))
    put(w, out + C_PHASE, 1)
    job = out + 256
    make_job(w, job, 1, MAX, get(w, c + C_CB_PATH), get(w, c + C_CB_N), 0)
    put(w, out + C_STACK, job)
    put(w, c + C_PHASE, 131)
    put(w, USED, job + 64)
    put(w, CONTEXT, out)
    return 0

def callback_success(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    after = get(w, c + C_AFTER)
    if after == 1:
        put(w, c + C_PHASE, 1)
        return 0
    if after == 2:
        return entry_advance(w)
    if after == 4:
        put(w, c + C_PHASE, 150)
        return 0
    return refused(w)

def callback_fail(w:mutbuf, kind:u64, err:u64, op:u64, path:u64, n:u64) -> u32:
    c = get(w, CONTEXT)
    if get(w, c + C_WRAP) != 0:
        job = get(w, c + C_JOB)
        return callback(w, kind, err, 18, get(w, job + J_PATH), get(w, job + J_N), 1, 0)
    put(w, c + C_ERR_KIND, kind)
    put(w, c + C_ERRNO, err)
    put(w, c + C_ERR_OP, op)
    put(w, c + C_ERR_PATH, path)
    put(w, c + C_ERR_N, n)
    if get(w, c + C_MODE) == 0:
        put(w, c + C_MODE, 1)
    else:
        put(w, c + C_MODE, 2)
    put(w, c + C_PHASE, 150)
    return 0

def abort_next(w:mutbuf) -> u32:
    c = get(w, CONTEXT)
    job = get(w, c + C_STACK)
    while job != 0:
        put(w, c + C_STACK, get(w, job + J_NEXT))
        if get(w, job + J_KIND) == 2:
            put(w, c + C_JOB, job)
            if get(w, LIVE) == 0:
                return refused(w)
            put(w, LIVE, get(w, LIVE) - 1)
            return issue(w, 2, get(w, job + J_TOKEN), 0, 0, 0, 0, 0, 0, 151)
        job = get(w, c + C_STACK)
    return context_complete(w, 1)

def context_complete(w:mutbuf, failed:u64) -> u32:
    c = get(w, CONTEXT)
    parent = get(w, c + C_PREV)
    if parent != 0:
        put(w, CONTEXT, parent)
        if get(w, parent + C_PHASE) != 131:
            return refused(w)
        if failed != 0:
            return callback_fail(w, get(w, c + C_ERR_KIND), get(w, c + C_ERRNO), get(w, c + C_ERR_OP), get(w, c + C_ERR_PATH), get(w, c + C_ERR_N))
        return callback_success(w)
    if get(w, LIVE) != 0:
        return refused(w)
    if failed != 0:
        put(w, RESULT_KIND, get(w, c + C_ERR_KIND))
        put(w, RESULT_ERRNO, get(w, c + C_ERRNO))
        put(w, RESULT_OP, get(w, c + C_ERR_OP))
        put(w, RESULT_PATH, get(w, c + C_ERR_PATH))
        put(w, RESULT_N, get(w, c + C_ERR_N))
    put(w, PHASE, 99)
    emit(w, 0)
    return 256

def emit(w:mutbuf, action:u64) -> u64:
    zero(w, 256, 256)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, OP))
    put(w, 296, get(w, RESULT_KIND))
    put(w, 304, get(w, RESULT_ERRNO))
    put(w, 312, get(w, RESULT_OP))
    if action == 2:
        put(w, 320, get(w, FS_PATH))
        put(w, 328, get(w, FS_N))
        put(w, 336, get(w, FS_TOKEN))
        put(w, 344, get(w, FS_COUNT))
        put(w, 352, get(w, FS_A))
        put(w, 360, get(w, FS_B))
        put(w, 400, get(w, FS_OTHER))
    elif action == 0:
        put(w, 320, get(w, RESULT_PATH))
        put(w, 328, get(w, RESULT_N))
    put(w, 368, get(w, NEEDED))
    put(w, 376, get(w, PHASE))
    put(w, 384, get(w, LIVE))
    if get(w, CONTEXT) != 0:
        put(w, 392, get(w, get(w, CONTEXT) + C_PHASE))
    return 0

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 6)
    return BAD

def same(w:mutbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    if an != bn:
        return 0
    i = 0
    while i < an:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def copy_read(w:mutbuf, s:readbuf, at:u64, begin:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, byte(s, begin + i))
        i = i + 1
    return 0

def copy_local(w:mutbuf, at:u64, begin:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, byte(w, begin + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
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
def status_wide(value:u32) -> u64:
    return value

'''
