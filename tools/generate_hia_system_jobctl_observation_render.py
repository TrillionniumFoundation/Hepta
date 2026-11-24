"""HIA JSON responses of original root jobctl observations."""
SOURCE=r'''
def nullable_text(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    if source == NONE:
        return lit(w, L_NULL, at)
    return quote(w, at, source, size)

def nullable_bool(w:mutbuf, at:u64, value:u64) -> u64:
    return lit(w, choose(value == NONE, L_NULL, choose(value == 0, L_FALSE, L_TRUE)), at)

def record_string(w:mutbuf, at:u64, index:u64) -> u64:
    return nullable_text(w, at, get(w, RECORD_FIELDS + index * 16), get(w, RECORD_FIELDS + index * 16 + 8))

def exit_string(w:mutbuf, at:u64, index:u64) -> u64:
    return nullable_text(w, at, get(w, EXIT_VALUES + index * 16), get(w, EXIT_VALUES + index * 16 + 8))

def stream_json(w:mutbuf, at:u64, side:u64) -> u64:
    source = STREAM_VALUES + side * 160
    at = decimal(w, lit(w, L_STREAM_OPEN, at), get(w, source))
    at = decimal(w, key(w, K_SAVED, at), get(w, source + 16))
    index = 2
    while index < 9:
        field = stream_json_key(index)
        at = key(w, field, at)
        if index >= 5 and index < 8:
            at = nullable_text(w, at, get(w, source + index * 16), get(w, source + index * 16 + 8))
        else:
            at = nullable_bool(w, at, get(w, source + index * 16))
        if at == NONE or at >= OUTPUT_END - 128:
            return NONE
        index = index + 1
    store(w, at, 125)
    return at + 1

def stream_json_key(index:u64) -> u64:
    if index == 2:
        return K_EOF
    if index == 3:
        return K_TRUNCATED
    if index == 4:
        return K_DRAIN_TIMEOUT
    if index == 5:
        return K_READ_ERROR
    if index == 6:
        return K_WRITE_ERROR
    if index == 7:
        return K_SYNC_ERROR
    return K_SYNCED

def metadata_json(w:mutbuf, at:u64, false_missing:u64) -> u64:
    kind = get(w, OBS_KIND)
    at = lit(w, L_METADATA_OPEN, at)
    if kind == 2 and get(w, T_CAPTURE) != 0:
        at = stream_json(w, lit(w, L_STDOUT_OPEN, at), 0)
        at = stream_json(w, key(w, K_STDERR, at), 1)
        if at == NONE:
            return NONE
        store(w, at, 125)
        at = at + 1
    else:
        at = lit(w, L_NULL, at)
    at = nullable_bool(w, key(w, K_OUTPUT_COMPLETE, at), choose(kind == 2, get(w, EXIT_VALUES + 112), NONE))
    at = nullable_bool(w, key(w, K_OUTPUT_DURABLE, at), choose(kind == 2, get(w, EXIT_VALUES + 128), NONE))
    at = nullable_bool(w, key(w, K_TERMINAL_RECEIPT_OBSERVED, at), choose(kind == 0, 0, 1))
    publication = L_NOT_OBSERVED
    if kind == 1:
        publication = L_PUBLICATION_PENDING
    elif kind == 2:
        publication = choose(get(w, OBS_WITNESSED) == 1, L_CONFIRMED, L_LEGACY_UNKNOWN)
    at = lit(w, publication, key(w, K_TERMINAL_PUBLICATION, at))
    confirmed = NONE
    if kind == 1 or false_missing != 0:
        confirmed = 0
    if kind == 2 and get(w, OBS_WITNESSED) == 1:
        confirmed = 1
    return nullable_bool(w, key(w, K_TERMINAL_PUBLICATION_CONFIRMED, at), confirmed)

def output_start(w:mutbuf) -> u64:
    if get(w, START_REUSED) == 1:
        return lit(w, L_REUSED, OUTPUT)
    return OUTPUT

def unknown_json(w:mutbuf, at:u64, state:u64, reason:u64) -> u64:
    at = quote(w, key(w, K_JOB_ID, at), JOB_ID, get(w, 48))
    at = lit(w, state, key(w, K_STATE, at))
    at = lit(w, reason, key(w, K_REASON, at))
    at = lit(w, L_UNKNOWN, key(w, K_OUTCOME, at))
    at = lit(w, L_FALSE, key(w, K_STATUS_AUTHORITATIVE, at))
    at = lit(w, L_FALSE, key(w, K_AUTOMATIC_RETRY, at))
    return lit(w, L_SYSTEMD, key(w, K_BACKEND, at))

def scratch_json(w:mutbuf, at:u64) -> u64:
    if get(w, SCRATCH_SIZE) != 0:
        at = key(w, K_SCRATCH_CLEANUP, at)
        if at > OUTPUT_END or get(w, SCRATCH_SIZE) > OUTPUT_END - at:
            return NONE
        copy(w, at, SCRATCH_VALUE, get(w, SCRATCH_SIZE))
        at = at + get(w, SCRATCH_SIZE)
        if get(w, RETAINED) != 0:
            at = lit(w, L_RETAINED, key(w, K_SCRATCH_CLEANUP_PUBLICATION, at))
    return at

def publication_json(w:mutbuf, at:u64) -> u64:
    reason = pending_reason(get(w, OBS_REASON))
    return unknown_json(w, at, L_FINALIZING, reason)

def pending_reason(index:u64) -> u64:
    if index == 1:
        return L_UNREADABLE
    if index == 2:
        return L_INVALID
    if index == 3:
        return L_PROTOCOL_MISMATCH
    if index == 4:
        return L_CAPTURE_INVALID
    if index == 5:
        return L_WITNESS_UNAVAILABLE
    return L_WITNESS_MISMATCH

def state_token(index:u64) -> u64:
    if index == 1:
        return L_RUNNING
    if index == 2:
        return L_FAILED
    if index == 3:
        return L_LOST
    if index == 4:
        return L_CANCELLED
    if index == 5:
        return L_TIMED_OUT
    if index == 6:
        return L_SUCCEEDED
    return L_FINALIZING

def completed_json(w:mutbuf, at:u64) -> u64:
    state = 2
    if get(w, EXIT_VALUES + 48) == 1:
        state = 5
    elif get(w, EXIT_VALUES + 64) == 1 or (get(w, T_PROTOCOL) == 0 and record_state(w) == 5):
        state = 4
    elif get(w, EXIT_VALUES + 32) == 0:
        if get(w, T_CAPTURE) == 0 or (get(w, EXIT_VALUES + 112) == 1 and get(w, EXIT_VALUES + 128) == 1):
            state = 6
    at = quote(w, key(w, K_JOB_ID, at), JOB_ID, get(w, 48))
    at = lit(w, state_token(state), key(w, K_STATE, at))
    at = signed_decimal(w, key(w, K_EXIT_CODE, at), get(w, EXIT_VALUES + 32))
    if state == 2 and get(w, EXIT_VALUES + 32) == 0:
        at = lit(w, L_CAPTURE_FAILED, key(w, K_REASON, at))
    at = nullable_bool(w, key(w, K_TIMED_OUT, at), get(w, EXIT_VALUES + 48))
    at = nullable_bool(w, key(w, K_CANCELLED, at), choose(state == 4, 1, 0))
    at = lit(w, L_FALSE, key(w, K_AUTOMATIC_RETRY, at))
    at = lit(w, L_SYSTEMD, key(w, K_BACKEND, at))
    at = scratch_json(w, at)
    if get(w, OBS_WITNESSED) == 1 and get(w, T_CAPTURE) == 1:
        at = decimal(w, key(w, K_TERMINAL_PUBLICATION_PROTOCOL, at), 1)
        at = exit_string(w, key(w, K_LAUNCH_NONCE, at), 1)
        if uint_text(w, get(w, EXIT_VALUES + 80), get(w, EXIT_VALUES + 88)) == 0:
            return NONE
        at = key(w, K_AT_UNIX_MS, at)
        copy(w, at, get(w, EXIT_VALUES + 80), get(w, EXIT_VALUES + 88))
        at = at + get(w, EXIT_VALUES + 88)
        index = 0
        while index < 4:
            at = terminal_log_json(w, at, index)
            index = index + 1
    return at

def terminal_log_json(w:mutbuf, at:u64, kind:u64) -> u64:
    field = choose(kind == 0, K_LOG_BYTES, choose(kind == 1, K_LOG_TRUNCATED, choose(kind == 2, K_LOG_SYNCED, K_LOG_ERRORS)))
    at = lit(w, L_STDOUT_OPEN, key(w, field, at))
    side = 0
    while side < 2:
        source = STREAM_VALUES + side * 160
        if side == 1:
            at = key(w, K_STDERR, at)
        if kind == 0:
            at = decimal(w, lit(w, L_SEEN_OPEN, at), get(w, source))
            at = decimal(w, key(w, K_STORED, at), get(w, source + 16))
            store(w, at, 125)
            at = at + 1
        elif kind == 1 or kind == 2:
            at = nullable_bool(w, at, get(w, source + choose(kind == 1, 48, 128)))
        else:
            value = source + 80
            if get(w, value) == NONE:
                value = source + 96
            if get(w, value) == NONE:
                value = source + 112
            at = nullable_text(w, at, get(w, value), get(w, value + 8))
        side = side + 1
    store(w, at, 125)
    return at + 1

def signed_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value >> 63 != 0:
        store(w, at, 45)
        return decimal(w, at + 1, 0 - value)
    return decimal(w, at, value)

def properties_json(w:mutbuf, at:u64) -> u64:
    store(w, at, 123)
    at = at + 1
    index = 0
    while index < get(w, PROPERTY_COUNT):
        row = PROP_TABLE + index * 32
        if index != 0:
            store(w, at, 44)
            at = at + 1
        at = quote(w, at, get(w, row), get(w, row + 8))
        if at == NONE or at >= OUTPUT_END:
            return NONE
        store(w, at, 58)
        at = quote(w, at + 1, get(w, row + 16), get(w, row + 24))
        if at == NONE:
            return NONE
        index = index + 1
    store(w, at, 125)
    return at + 1

def page_json(w:mutbuf, at:u64) -> u64:
    at = decimal(w, lit(w, L_PAGE_OPEN, at), get(w, PAGE_OFFSET))
    next = get(w, PAGE_OFFSET) + get(w, PAGE_USED)
    at = decimal(w, key(w, K_NEXT_OFFSET, at), next)
    at = decimal(w, key(w, K_SIZE, at), get(w, PAGE_SIZE))
    at = nullable_bool(w, key(w, K_EOF, at), choose(next >= get(w, PAGE_SIZE), 1, 0))
    size = lossy(w, LOG_TEXT, LOG_RAW, get(w, PAGE_USED))
    at = quote(w, key(w, K_TEXT, at), LOG_TEXT, size)
    at = key(w, K_BYTES_HEX, at)
    store(w, at, 34)
    index = 0
    at = at + 1
    while index < get(w, PAGE_USED):
        value = byte(w, LOG_RAW + index)
        store(w, at, hexadecimal(value >> 4))
        store(w, at + 1, hexadecimal(value & 15))
        at = at + 2
        index = index + 1
    store(w, at, 34)
    at = at + 1
    if get(w, PAGE_PRESENT) == 1:
        at = decimal(w, key(w, K_LOG_LIMIT_BYTES, at), 16777216)
    store(w, at, 125)
    return at + 1
'''
