"""Static HIA lock/endmark owner source. No Python runtime Pager policy.

This is one SOURCE fragment of the independent read-owner author. The companion
common/page fragments supply fixed HIA helpers. No function in SOURCE executes
as Python. Source creation is not generation or qualification.
"""
SOURCE = r'''
def sqlite_pager_read_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(o) != 128 or length(w) != 73728:
        return ABI
    if word(s, 0) != EVENT_MAGIC or word(s, 8) != 2:
        return ABI
    if word(s, 56) > 65536 or length(s) != 128 + word(s, 56):
        return ABI
    if zero_event_tail(s) == 0:
        return ABI
    event = word(s, 24)
    if event == 1:
        return owner_begin(s, o, w)
    if get(w, 0) != STATE_MAGIC or word(s, 16) != get(w, 16):
        return ABI
    if event == 2:
        if get(w, 32) == 0 or word(s, 32) != get(w, 24) or word(s, 40) != get(w, 32):
            return ABI
        if word(s, 64) != 0 or word(s, 72) != 0 or word(s, 80) != 0 or word(s, 88) != 0:
            return ABI
        # Preserve the consumed operation for an explicit fresh-sequence EINTR retry.
        put(w, 384, get(w, 32))
        # Receipt consumption precedes every further native effect.
        put(w, 32, 0)
        return owner_return(s, o, w)
    if get(w, 32) != 0 or word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0 or word(s, 56) != 0:
        return ABI
    if word(s, 72) != 0 or word(s, 80) != 0 or word(s, 88) != 0:
        return ABI
    if event == 3 and get(w, 8) == 200:
        return page_begin(s, o, w)
    if event == 5 and get(w, 8) == 201:
        if word(s, 64) != get(w, 280):
            return ABI
        put(w, 8, 200)
        return outcome(o, w, 128)
    if event == 4 and get(w, 8) == 200 and word(s, 64) == 0:
        return cleanup(o, w)
    return ABI

def owner_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if word(s, 16) == 0 or word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0 or word(s, 56) != 0:
        return ABI
    if word(s, 64) != 34600 and word(s, 64) != 35302:
        return ABI
    if word(s, 72) != 0 or word(s, 80) != 0 or word(s, 88) != 0:
        return ABI
    index = 0
    while index < 73728:
        if byte(w, index) != 0:
            return ABI
        index = index + 1
    put(w, 0, STATE_MAGIC)
    put(w, 16, word(s, 16))
    put(w, 72, word(s, 64))
    # A state/context pair has exactly one BEGIN and no descriptor reopen.
    return issue(o, w, 1, 1, 0, 0, 0, 0)

def owner_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase >= 100 and phase < 120:
        if phase != 107 and phase != 108 and phase != 111 and word(s, 48) == EINTR:
            if word(s, 56) != 0:
                return cleanup_return(s, o, w)
            return reissue(o, w)
        return cleanup_return(s, o, w)
    # The leaf performs no hidden EINTR retry. CLOSE is handled above and
    # consumed once even on Linux EINTR. SLEEP exposes its remaining timespec.
    if word(s, 48) == EINTR:
        if phase == 38:
            return sleep_interrupted(s, o, w)
        if word(s, 56) != 0:
            return fail(o, w, 7, word(s, 48))
        return reissue(o, w)
    if phase == 60:
        return read_return(s, o, w)
    if phase >= 40 and phase <= 43:
        return index_return(s, o, w)
    if phase <= 13:
        return opening_return(s, o, w)
    if phase >= 20 and phase <= 25:
        return header_return(s, o, w)
    if phase >= 26 and phase <= 38:
        return reader_return(s, o, w)
    return fail(o, w, 7, 0)

def opening_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase == 1 or phase == 7 or phase == 9:
        if word(s, 48) > 2147483647 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        if phase == 1:
            put(w, 96, get(w, 96) | 1)
            return issue(o, w, 2, 2, 0, 0, 0, 0)
        if phase == 7:
            put(w, 96, get(w, 96) | 2)
            return issue(o, w, 8, 2, 1, 0, 0, 0)
        put(w, 96, get(w, 96) | 4)
        return issue(o, w, 10, 2, 2, 0, 0, 0)
    if phase == 2 or phase == 8 or phase == 10:
        if regular_stat(s) == 0:
            return fail(o, w, 1, word(s, 48))
        if phase == 2:
            put(w, 288, word(s, 176))
            put(w, 296, word(s, 128))
            put(w, 304, word(s, 136))
            return issue(o, w, 3, 4, 0, 0, 1073741824, 1)
        if phase == 8:
            if word(s, 128) == get(w, 296) and word(s, 136) == get(w, 304):
                return fail(o, w, 4, 0)
            put(w, 312, word(s, 128))
            put(w, 320, word(s, 136))
            return issue(o, w, 9, 1, 2, 0, 0, 0)
        if word(s, 176) < 32768:
            return fail(o, w, 4, 0)
        if word(s, 128) == get(w, 296) and word(s, 136) == get(w, 304):
            return fail(o, w, 4, 0)
        if word(s, 128) == get(w, 312) and word(s, 136) == get(w, 320):
            return fail(o, w, 4, 0)
        put(w, 328, word(s, 128))
        put(w, 336, word(s, 136))
        return dms_attempt(o, w)
    if phase == 11:
        if word(s, 48) != 0 or word(s, 56) != 32:
            return fail(o, w, 1, word(s, 48))
        # Linux LP64 struct flock: type:i16, whence:i16, pad4,
        # start:i64, len:i64, pid:i32, pad4. Keep all 32 raw bytes.
        copy_range(w, s, 704, 128, 32)
        if le(s, 128, 2) == 2:
            return fail(o, w, 4, 0)
        if le(s, 128, 2) == 1:
            return dms_attempt(o, w)
        if le(s, 128, 2) != 0:
            return fail(o, w, 7, 0)
        return issue(o, w, 12, 4, 2, 0, 128, 1)
    if phase == 13:
        # mmap returns its real address, not a normalized zero result.
        if word(s, 48) > 9223372036854775807 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 96, get(w, 96) | 8)
        return issue(o, w, 20, 6, 2, 0, 48, 0)
    if phase == 12 and is_busy(word(s, 48)) == 1 and word(s, 56) == 0:
        return dms_attempt(o, w)
    if word(s, 56) != 0:
        return fail(o, w, 7, word(s, 48))
    if word(s, 48) != 0:
        return fail(o, w, choose(is_busy(word(s, 48)) == 1, 2, 1), word(s, 48))
    if phase == 3:
        put(w, 104, get(w, 104) | 1)
        return issue(o, w, 4, 4, 0, 0, 1073741826, 510)
    if phase == 4:
        put(w, 104, get(w, 104) | 2)
        return issue(o, w, 5, 4, 0, 2, 1073741824, 1)
    if phase == 5:
        put(w, 104, get(w, 104) & 254)
        return start_read(o, w, 0, 0, 100, 1)
    if phase == 12:
        put(w, 104, get(w, 104) | 4)
        return issue(o, w, 13, 5, 2, 0, 0, 0)
    return fail(o, w, 7, 0)

def after_db_header(o:mutbuf, w:mutbuf) -> u32:
    if be_mut(w, 4096, 8) != DB_MAGIC0 or be_mut(w, 4104, 8) != DB_MAGIC1:
        return fail(o, w, 5, 0)
    size = be_mut(w, 4112, 2)
    if size == 1:
        size = 65536
    if size < 512 or size > 65536 or (size & (size - 1)) != 0:
        return fail(o, w, 5, 0)
    # This first owner supports existing WAL databases only. A rollback or
    # write-version transition is explicit UNSUPPORTED, not SQLITE_BUSY.
    if byte(w, 4114) != 2 or byte(w, 4115) != 2:
        return fail(o, w, 4, 0)
    if byte(w, 4116) > 255 or size - byte(w, 4116) < 480:
        return fail(o, w, 5, 0)
    if byte(w, 4117) != 64 or byte(w, 4118) != 32 or byte(w, 4119) != 32:
        return fail(o, w, 5, 0)
    put(w, 128, size)
    # Raw DB page 1 is a preliminary WAL-mode/geometry observation only.
    # Snapshot nPage comes from the admitted published wal-index header.
    return issue(o, w, 7, 1, 1, 0, 0, 0)

def dms_attempt(o:mutbuf, w:mutbuf) -> u32:
    put(w, 120, 11)
    return retry_schedule(o, w)

def wal_attempt(o:mutbuf, w:mutbuf) -> u32:
    put(w, 120, 20)
    return retry_schedule(o, w)

def retry_schedule(o:mutbuf, w:mutbuf) -> u32:
    put(w, 112, get(w, 112) + 1)
    if get(w, 112) > 100:
        return fail(o, w, 3, 0)
    if get(w, 112) > 5:
        delay = 1000
        if get(w, 112) >= 10:
            delay = (get(w, 112) - 9) * (get(w, 112) - 9) * 39000
        return issue(o, w, 38, 10, 0, delay, 0, 0)
    return retry_resume(o, w)

def retry_resume(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 120) == 11:
        return issue(o, w, 11, 11, 2, 0, 0, 0)
    return issue(o, w, 20, 6, 2, 0, 48, 0)

def header_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase == 22:
        if word(s, 56) != 0:
            return fail(o, w, 7, word(s, 48))
        if is_busy(word(s, 48)) == 1:
            return issue(o, w, 24, 4, 2, 0, 122, 1)
        if word(s, 48) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 104, get(w, 104) | 32)
        return issue(o, w, 20, 6, 2, 0, 48, 0)
    if phase == 24:
        if word(s, 56) != 0:
            return fail(o, w, 7, word(s, 48))
        if word(s, 48) != 0:
            # Distinguish observed recovery contention from generic retry.
            return fail(o, w, choose(is_busy(word(s, 48)) == 1, 8, 1), word(s, 48))
        put(w, 104, get(w, 104) | 64)
        return issue(o, w, 25, 4, 2, 2, 122, 1)
    if phase == 23 or phase == 25:
        if word(s, 48) != 0 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        if phase == 23:
            put(w, 104, get(w, 104) & 223)
            return issue(o, w, 26, 6, 2, 96, 4, 0)
        put(w, 104, get(w, 104) & 191)
        return wal_attempt(o, w)
    if word(s, 48) != 0 or word(s, 56) != 48:
        return fail(o, w, 1, word(s, 48))
    if phase == 20:
        copy_range(w, s, 576, 128, 48)
        # Each SHM_COPY fences before and after its aligned u32 loads.
        # The first copy therefore completes before reading header[1].
        return issue(o, w, 21, 6, 2, 48, 48, 0)
    if same(s, 128, w, 576, 48) == 0 or valid_header(w, 576) == 0:
        if (get(w, 104) & 32) != 0:
            # Original SQLite would reconstruct under WRITE. Recovery is
            # deliberately outside this read-only owner, not forged success.
            return fail(o, w, 4, 0)
        return issue(o, w, 22, 4, 2, 1, 120, 1)
    if get32(w, 576) != 3007000:
        return fail(o, w, 4, 0)
    size = get16(w, 590)
    size = (size & 65024) + ((size & 1) << 16)
    if size != get(w, 128):
        return fail(o, w, 4, 0)
    if get32(w, 596) == 0 or get32(w, 596) > 4294967294:
        return fail(o, w, 4, 0)
    copy_mut(w, 512, 576, 48)
    put(w, 144, get32(w, 592))
    put(w, 136, get32(w, 596))
    if (get(w, 104) & 32) != 0:
        return issue(o, w, 23, 4, 2, 2, 120, 1)
    return issue(o, w, 26, 6, 2, 96, 4, 0)

def valid_header(w:mutbuf, at:u64) -> u64:
    if byte(w, at + 12) == 0:
        return 0
    a = 0
    b = 0
    index = 0
    while index < 40:
        a = (a + get32(w, at + index) + b) & 4294967295
        b = (b + get32(w, at + index + 4) + a) & 4294967295
        index = index + 8
    return choose(a == get32(w, at + 40) and b == get32(w, at + 44), 1, 0)

def reader_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase == 38:
        if word(s, 48) != 0 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        return retry_resume(o, w)
    if phase == 26:
        if word(s, 48) != 0 or word(s, 56) != 4:
            return fail(o, w, 1, word(s, 48))
        if le(s, 128, 4) > get(w, 144):
            return wal_attempt(o, w)
        if le(s, 128, 4) == get(w, 144):
            return issue(o, w, 27, 4, 2, 0, 123, 1)
        return issue(o, w, 29, 6, 2, 104, 16, 0)
    if phase == 27:
        if word(s, 56) != 0:
            return fail(o, w, 7, word(s, 48))
        if is_busy(word(s, 48)) == 1:
            return issue(o, w, 29, 6, 2, 104, 16, 0)
        if word(s, 48) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 104, get(w, 104) | 8)
        put(w, 160, 0)
        return issue(o, w, 28, 6, 2, 0, 48, 0)
    if phase == 28:
        if word(s, 48) != 0 or word(s, 56) != 48:
            return fail(o, w, 1, word(s, 48))
        if same(s, 128, w, 512, 48) == 0:
            return issue(o, w, 37, 4, 2, 2, 123, 1)
        put(w, 152, get(w, 144) + 1)
        return owner_ready(o, w)
    if phase == 29:
        if word(s, 48) != 0 or word(s, 56) != 16:
            return fail(o, w, 1, word(s, 48))
        return choose_readmark(s, o, w)
    if phase >= 30 and phase <= 33:
        return readmark_lock_return(s, o, w)
    if phase == 34:
        if word(s, 48) != 0 or word(s, 56) != 4:
            return fail(o, w, 1, word(s, 48))
        put(w, 152, le(s, 128, 4) + 1)
        # SHM_COPY fenced after nBackfill, then the next request fences before
        # mark load. This order precedes the live header recheck.
        return issue(o, w, 35, 6, 2, 100 + get(w, 160) * 4, 4, 0)
    if phase == 35:
        if word(s, 48) != 0 or word(s, 56) != 4:
            return fail(o, w, 1, word(s, 48))
        if le(s, 128, 4) != get(w, 168):
            return unlock_for_retry(o, w)
        return issue(o, w, 36, 6, 2, 0, 48, 0)
    if phase == 36:
        if word(s, 48) != 0 or word(s, 56) != 48:
            return fail(o, w, 1, word(s, 48))
        if same(s, 128, w, 512, 48) == 0 or get(w, 152) > get(w, 144) + 1:
            return unlock_for_retry(o, w)
        return owner_ready(o, w)
    if phase == 37:
        if word(s, 48) != 0 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 104, get(w, 104) & 247)
        return wal_attempt(o, w)
    return fail(o, w, 7, 0)

def choose_readmark(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 160, 0)
    put(w, 168, 0)
    index = 1
    while index <= 4:
        value = le(s, 124 + index * 4, 4)
        if get(w, 168) <= value and value <= get(w, 144):
            put(w, 168, value)
            put(w, 160, index)
        index = index + 1
    if get(w, 168) < get(w, 144) or get(w, 160) == 0:
        put(w, 176, 1)
        return issue(o, w, 30, 4, 2, 1, 124, 1)
    return lock_selected(o, w)

def readmark_lock_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if word(s, 56) != 0:
        return fail(o, w, 7, word(s, 48))
    if phase == 30:
        if is_busy(word(s, 48)) == 1:
            put(w, 176, get(w, 176) + 1)
            if get(w, 176) <= 4:
                return issue(o, w, 30, 4, 2, 1, 123 + get(w, 176), 1)
            if get(w, 160) == 0:
                return wal_attempt(o, w)
            return lock_selected(o, w)
        if word(s, 48) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 104, get(w, 104) | 16)
        put(w, 160, get(w, 176))
        put(w, 168, get(w, 144))
        return issue(o, w, 31, 7, 2, get(w, 160), get(w, 144), 0)
    if phase == 33 and is_busy(word(s, 48)) == 1:
        return wal_attempt(o, w)
    if word(s, 48) != 0:
        return fail(o, w, 1, word(s, 48))
    if phase == 31:
        return issue(o, w, 32, 4, 2, 2, 123 + get(w, 160), 1)
    if phase == 32:
        put(w, 104, get(w, 104) & 239)
        return lock_selected(o, w)
    put(w, 104, get(w, 104) | 8)
    return issue(o, w, 34, 6, 2, 96, 4, 0)

def lock_selected(o:mutbuf, w:mutbuf) -> u32:
    return issue(o, w, 33, 4, 2, 0, 123 + get(w, 160), 1)

def unlock_for_retry(o:mutbuf, w:mutbuf) -> u32:
    return issue(o, w, 37, 4, 2, 2, 123 + get(w, 160), 1)

def owner_ready(o:mutbuf, w:mutbuf) -> u32:
    put(w, 8, 200)
    return outcome(o, w, 128)

def sleep_interrupted(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if word(s, 56) != 16 or word(s, 128) != 0 or word(s, 136) > get(w, 48):
        return fail(o, w, 7, word(s, 48))
    return issue(o, w, 38, 10, 0, word(s, 136), 0, 0)
'''
