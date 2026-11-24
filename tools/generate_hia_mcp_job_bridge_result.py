"""HIA authenticated terminal proof, lossless pages, report and pending owner."""
from tools.generate_hia_mcp_job_bridge_common import authored

STAGES=('admission','initial_lookup','initial_envelope','initial_binding',
        'initial_publication','output_budget','page_transport','page_decode',
        'page_binding','page_integrity','final_lookup','final_envelope',
        'final_binding','final_publication')
CAUSES=('invalid_request','unavailable','deadline','invalid_json','binding_mismatch',
        'publication_invalid','publication_changed','retention_budget','allocation','invalid_page')
TEXT=dict(expected='{"expected":',exit=',"exit_code":',report=',"report":',
          stage='stage=',cause=' cause=',elapsed=' elapsed_us=',initial=' initial_us=',
          read=' read_us=',final=' final_us=',pages=' page_reads=',validated=' validated_pages=',
          windows=' windows=',prefix_out=' prefix_stdout=',prefix_err=' prefix_stderr=',page_open=' [stage=',window=' window=',page_index=' page=',out_offset=' stdout_offset=',err_offset=' stderr_offset=',page_limit=' limit=16384',page_close=']')
for i,v in enumerate(STAGES):TEXT['stage_'+str(i)]=v
for i,v in enumerate(CAUSES):TEXT['cause_'+str(i)]=v
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, 1904) == 0:
            return enter(w, 9, 90)
        if terminal_proof(w) == False:
            return publication_error(w, 5)
        if get(w, 30024) > 524288 or get(w, 30032) > 524288 or get(w, 30024) + get(w, 30032) > 524288:
            put(w, 2200, 5)
            put(w, 2208, 7)
            return enter(w, 5, 700)
        scratch = field(w, F_SCRATCH_CLEANUP)
        if scratch == NONE or is_null(w, scratch):
            put(w, 30072, 0)
            return proof_ready(o, w, 0)
        if scratch_valid(w, scratch) == False or get(w, scratch + 64) > 1048576:
            return publication_error(w, 5)
        put(w, 30072, 1)
        end = raw(w, scratch, JSON)
        return canonical(o, w, 1, JSON, end - JSON)
    if phase == 1:
        if result > 4194304:
            return publication_error(w, 5)
        return proof_ready(o, w, result)
    if phase == 100:
        return call(o, w, 101, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 101:
        if failed(result):
            return 0
        now = get(w, 9216) * 1000000000 + get(w, 9224)
        put(w, 2008, now - get(w, 2000))
        put(w, 2016, now)
        put(w, 2048, 0)
        put(w, 2056, 0)
        put(w, 2064, 0)
        put(w, 2072, 0)
        put(w, 2080, 0)
        put(w, 2088, 0)
        count = choose(get(w, 1920) > get(w, 1928), get(w, 1920), get(w, 1928))
        count = (count + 16383) // 16384
        put(w, 2040, choose(count == 0, 1, count))
        return next_page(w)
    if phase == 400:
        return decode(o, w, 401, CHILD_OUT, get(w, 624))
    if phase == 401:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            return page_error(w, 7, 3)
        if string_eq(w, field(w, F_JOB_ID), S_JOB_ID) == False:
            return page_error(w, 8, 4)
        if page(w, field(w, F_STDOUT), get(w, 1936), get(w, 1920), STREAM) == False or page(w, field(w, F_STDERR), get(w, 1944), get(w, 1928), STREAM + get(w, 1920)) == False:
            return page_error(w, 9, 9)
        put(w, 2056, get(w, 2056) + 1)
        if get(w, 2800) == 0:
            put(w, 2072, choose(get(w, 1936) + 16384 > get(w, 1920), get(w, 1920), get(w, 1936) + 16384))
            put(w, 2080, choose(get(w, 1944) + 16384 > get(w, 1928), get(w, 1928), get(w, 1944) + 16384))
        if get(w, 2272) == 2:
            return enter(w, 10, 30)
        put(w, 2088, get(w, 2088) + 1)
        put(w, 1600, 5)
        put(w, 1608, 403)
        put(w, 1616, 3)
        return enter(w, 8, 0)
    if phase == 403:
        if get(w, 2088) < get(w, 2040):
            return next_page(w)
        return call(o, w, 402, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 402:
        if failed(result):
            return 0
        now = get(w, 9216) * 1000000000 + get(w, 9224)
        put(w, 2024, now - get(w, 2016))
        put(w, 2032, now)
        put(w, 1904, 3)
        put(w, 2272, 0)
        return enter(w, 3, 200)
    if phase == 500:
        if get(w, 1960) != 5:
            put(w, 2160, 2)
            return pending(w)
        at = text_expected(w, CHILD_IN)
        at = cp(w, S_EXPECTED, at)
        at = text_exit(w, at)
        at = signed_decimal(w, at, get(w, 1952))
        at = text_report(w, at)
        at = copy_state(w, STREAM, at, get(w, 1920))
        at = text_close(w, at)
        return child(w, 5, 501, 9, at - CHILD_IN, 524296, 0, 10000000000, NONE)
    if phase == 501:
        if child_ok(w) == False or get(w, 624) < 10 or get(w, CHILD_OUT) != get(w, 624) - 8 or get(w, 624) - 8 > 524288:
            put(w, 2160, 4)
            return pending(w)
        copy_state(w, CHILD_OUT + 8, FINISH, get(w, 624) - 8)
        bind(w, S_RESPONSE, FINISH, get(w, 624) - 8)
        put(w, 2168, 1)
        return schema(w)
    if phase == 502:
        if child_ok(w) == False or get(w, 624) != 8 or get(w, CHILD_OUT) != 0:
            if get(w, 2168) == 0:
                return 0
            put(w, 2160, 4)
            return pending(w)
        if get(w, 2168) == 0:
            return finish(o, w, get(w, S_RESPONSE), get(w, S_RESPONSE + 8))
        return decode(o, w, 503, get(w, S_RESPONSE), get(w, S_RESPONSE + 8))
    if phase == 503:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            put(w, 2160, 4)
            return pending(w)
        code = lookup(w, field(w, F_ERROR), F_CODE)
        if str_is(w, field(w, F_STATUS), 0) and (str_is(w, code, 1) or str_is(w, code, 2)):
            put(w, 2160, 3)
            return pending(w)
        return finish(o, w, get(w, S_RESPONSE), get(w, S_RESPONSE + 8))
    if phase == 600:
        put(w, 2160, 0)
        return pending(w)
    if phase == 601:
        if child_ok(w) == False or get(w, 624) < 2 or get(w, 624) > 4096:
            return 0
        copy_state(w, CHILD_OUT, FINISH, get(w, 624))
        bind(w, S_RESPONSE, FINISH, get(w, 624))
        put(w, 2168, 0)
        return schema(w)
    if phase == 700:
        return call(o, w, 701, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 701:
        if failed(result):
            return 0
        now = get(w, 9216) * 1000000000 + get(w, 9224)
        if get(w, 2016) == 0:
            put(w, 2008, now - get(w, 2000))
        elif get(w, 2032) == 0:
            put(w, 2024, now - get(w, 2016))
        put(w, 2176, now)
        diagnostic(w)
        put(w, 2160, 5)
        return pending(w)
    return 0

def publication_error(w:mutbuf, cause:u64) -> u32:
    put(w, 2200, choose(get(w, 1904) == 3, 13, 4))
    put(w, 2208, cause)
    return enter(w, 5, 700)

def terminal_proof(w:mutbuf) -> bool:
    if get(w, 2312) == 0 or number(w, field(w, F_TERMINAL_PUBLICATION_PROTOCOL)) != 1 or boolean(w, field(w, F_OUTPUT_COMPLETE), 1) == False or boolean(w, field(w, F_OUTPUT_DURABLE), 1) == False:
        return False
    nonce = field(w, F_LAUNCH_NONCE)
    if nonce == NONE or get(w, nonce) != 4 or get(w, nonce + 32) != 32:
        return False
    index = 0
    while index < 32:
        value = byte(w, ARENA + get(w, nonce + 24) + index)
        if hex_digit_value(value) == NONE:
            return False
        store(w, 30040 + index, value)
        index = index + 1
    code = int32(w, field(w, F_EXIT_CODE))
    if get(w, 2152) == 0:
        return False
    timed = field(w, F_TIMED_OUT)
    cancelled = field(w, F_CANCELLED)
    if (boolean(w, timed, 0) == False and boolean(w, timed, 1) == False) or (boolean(w, cancelled, 0) == False and boolean(w, cancelled, 1) == False):
        return False
    expected = choose(boolean(w, timed, 1), 2, choose(boolean(w, cancelled, 1), 3, choose(code == 0, 5, 4)))
    if get(w, 2304) != expected:
        return False
    stamp = field(w, F_AT_UNIX_MS)
    if valid_uint(w, stamp) == False:
        return False
    a = stream_size(w, F_STDOUT)
    b = stream_size(w, F_STDERR)
    if a == NONE or b == NONE:
        return False
    put(w, 30000, expected)
    put(w, 30008, code)
    put(w, 30016, number(w, stamp))
    put(w, 30024, a)
    put(w, 30032, b)
    return True

def stream_size(w:mutbuf, name:u64) -> u64:
    bytes = lookup(w, field(w, F_LOG_BYTES), name)
    stored = lookup(w, bytes, F_STORED)
    seen = lookup(w, bytes, F_SEEN)
    if valid_uint(w, stored) == False or valid_uint(w, seen) == False or number(w, stored) != number(w, seen):
        return NONE
    if boolean(w, lookup(w, field(w, F_LOG_TRUNCATED), name), 0) == False or is_null(w, lookup(w, field(w, F_LOG_ERRORS), name)) == False or boolean(w, lookup(w, field(w, F_LOG_SYNCED), name), 1) == False:
        return NONE
    return number(w, stored)

def int32(w:mutbuf, row:u64) -> u64:
    put(w, 2152, 0)
    if row == NONE or get(w, row) != 3:
        return 0
    source = get(w, 72) + get(w, row + 24)
    size = get(w, row + 32)
    if size == 0 or size > 11:
        return 0
    negative = byte(w, source) == 45
    index = choose(negative, 1, 0)
    if index == size:
        return 0
    value = 0
    while index < size:
        digit = byte(w, source + index)
        if digit < 48 or digit > 57:
            return 0
        value = value * 10 + digit - 48
        index = index + 1
    if value > choose(negative, 2147483648, 2147483647) or (negative and value == 0):
        return 0
    put(w, 2152, 1)
    return choose(negative, 0 - value, value)

def scratch_valid(w:mutbuf, row:u64) -> bool:
    if get(w, row) != 6 or str_is(w, lookup(w, row, F_SCHEMA), 3) == False or string_eq(w, lookup(w, row, F_JOB_ID), S_JOB_ID) == False or str_is(w, lookup(w, row, F_DIRECTORY), 4) == False:
        return False
    nonce = lookup(w, row, F_LAUNCH_NONCE)
    if nonce == NONE or get(w, nonce) != 4 or get(w, nonce + 32) != 32 or equal(w, ARENA + get(w, nonce + 24), 30040, 32) == False:
        return False
    if valid_uint(w, lookup(w, row, F_DEVICE)) == False or valid_uint(w, lookup(w, row, F_INODE)) == False or number(w, lookup(w, row, F_INODE)) == 0:
        return False
    adopted = lookup(w, row, F_WORKER_ADOPTED)
    removed = lookup(w, row, F_REMOVED)
    durable = lookup(w, row, F_DURABLE)
    stopped = lookup(w, row, F_ORIGINAL_PROCESS_GROUP_STOPPED)
    reaped = lookup(w, row, F_ORIGINAL_CHILD_REAPED)
    if bool_field(w, adopted) == False or bool_field(w, removed) == False or bool_field(w, durable) == False or bool_field(w, stopped) == False or bool_field(w, reaped) == False:
        return False
    r = boolean(w, removed, 1)
    d = boolean(w, durable, 1)
    complete = boolean(w, stopped, 1) and boolean(w, reaped, 1)
    if (r and complete == False) or (d and r == False):
        return False
    state = lookup(w, row, F_STATE)
    if str_is(w, state, 5):
        return r and d and complete
    if str_is(w, state, 6):
        return r == False and d == False
    if str_is(w, state, 7):
        return complete and d == False
    return False

def bool_field(w:mutbuf, row:u64) -> bool:
    return boolean(w, row, 0) or boolean(w, row, 1)

def proof_ready(o:mutbuf, w:mutbuf, scratch_size:u64) -> u32:
    if get(w, 1904) == 3:
        if equal(w, PROOF, 30000, 80) == False:
            return publication_error(w, 6)
        if get(w, 30072) != 0 and canonical_equal(w, SCAN_HASHES, get(w, PROOF + 80), ARENA, scratch_size) == False:
            return publication_error(w, 6)
        return enter(w, 5, 500)
    copy_state(w, 30000, PROOF, 80)
    put(w, PROOF + 80, scratch_size)
    if scratch_size != 0:
        copy_state(w, ARENA, SCAN_HASHES, scratch_size)
    put(w, 1960, get(w, 30000))
    put(w, 1952, get(w, 30008))
    put(w, 1920, get(w, 30024))
    put(w, 1928, get(w, 30032))
    return enter(w, 5, 100)

def next_page(w:mutbuf) -> u32:
    put(w, 1904, 2)
    put(w, 2272, 2)
    return enter(w, 10, 0)

def page_error(w:mutbuf, stage:u64, cause:u64) -> u32:
    put(w, 2200, stage)
    put(w, 2208, cause)
    if get(w, 2272) == 2:
        return enter(w, 10, 31)
    return enter(w, 5, 700)

def page(w:mutbuf, row:u64, offset:u64, size:u64, target:u64) -> bool:
    if row == NONE or get(w, row) != 6:
        return False
    at = lookup(w, row, F_OFFSET)
    total = lookup(w, row, F_SIZE)
    next = lookup(w, row, F_NEXT_OFFSET)
    eof = lookup(w, row, F_EOF)
    if valid_uint(w, at) == False or number(w, at) != offset or valid_uint(w, total) == False or number(w, total) != size or valid_uint(w, next) == False:
        return False
    count = choose(size - offset < 16384, size - offset, 16384)
    if number(w, next) != offset + count or boolean(w, eof, choose(offset + count == size, 1, 0)) == False:
        return False
    encoded = lookup(w, row, F_BYTES_HEX)
    if encoded == NONE or get(w, encoded) != 4 or get(w, encoded + 32) != count * 2:
        return False
    source = ARENA + get(w, encoded + 24)
    index = 0
    while index < count:
        a = hex_digit_value(byte(w, source + index * 2))
        b = hex_digit_value(byte(w, source + index * 2 + 1))
        if a == NONE or b == NONE:
            return False
        store(w, target + offset + index, (a << 4) | b)
        index = index + 1
    return True

def signed_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value >> 63 != 0:
        store(w, at, 45)
        return decimal(w, at + 1, 0 - value)
    return decimal(w, at, value)

def pending(w:mutbuf) -> u32:
    reason = get(w, 2160)
    diagnostic_size = choose(reason == 5, get(w, S_ERROR_DIAGNOSTIC + 8), 0)
    put(w, CHILD_IN, PENDING_MAGIC)
    put(w, CHILD_IN + 8, reason)
    put(w, CHILD_IN + 16, choose(reason == 0, get(w, 1912), 0))
    put(w, CHILD_IN + 24, get(w, S_JOB_ID + 8))
    put(w, CHILD_IN + 32, get(w, S_HOST + 8))
    put(w, CHILD_IN + 40, diagnostic_size)
    at = cp(w, S_REQUEST_DIGEST, CHILD_IN + 48)
    at = cp(w, S_JOB_ID, at)
    at = cp(w, S_HOST, at)
    if diagnostic_size != 0:
        at = cp(w, S_ERROR_DIAGNOSTIC, at)
    return child(w, 5, 601, 1, at - CHILD_IN, 4096, 0, 5000000000, NONE)

def schema(w:mutbuf) -> u32:
    ordinal = get(w, 888)
    put(w, CHILD_IN, choose(ordinal == 12, 3, ordinal))
    at = cp(w, S_CATALOG, CHILD_IN + 8)
    at = cp(w, S_RESPONSE, at)
    return child(w, 5, 502, choose(ordinal == 7, 12, 10), at - CHILD_IN, 8, 0, 10000000000, NONE)

def diagnostic(w:mutbuf) -> u64:
    at = text_stage(w, JSON)
    at = stage_text(w, at, get(w, 2200))
    at = text_cause(w, at)
    at = cause_text(w, at, get(w, 2208))
    at = text_elapsed(w, at)
    at = decimal(w, at, (get(w, 2176) - get(w, 2000)) // 1000)
    at = text_initial(w, at)
    at = decimal(w, at, get(w, 2008) // 1000)
    at = text_read(w, at)
    at = decimal(w, at, get(w, 2024) // 1000)
    at = text_final(w, at)
    at = decimal(w, at, choose(get(w, 2032) == 0, 0, (get(w, 2176) - get(w, 2032)) // 1000))
    at = text_pages(w, at)
    at = decimal(w, at, get(w, 2048))
    at = text_validated(w, at)
    at = decimal(w, at, get(w, 2056))
    at = text_windows(w, at)
    at = decimal(w, at, get(w, 2064))
    at = text_prefix_out(w, at)
    at = decimal(w, at, get(w, 2072))
    at = text_prefix_err(w, at)
    at = decimal(w, at, get(w, 2080))
    if get(w, 2272) == 2:
        index = 0
        while index < get(w, 2712):
            row = 36000 + index * 64
            if get(w, row + 48) != 0:
                at = text_page_open(w, at)
                at = stage_text(w, at, get(w, row + 48))
                at = text_cause(w, at)
                at = cause_text(w, at, get(w, row + 40))
                at = text_window(w, at)
                at = decimal(w, at, get(w, 2064))
                at = text_page_index(w, at)
                at = decimal(w, at, get(w, 2704) + index)
                offset = (get(w, 2704) + index) * 16384
                at = text_out_offset(w, at)
                at = decimal(w, at, choose(offset < get(w, 1920), offset, get(w, 1920)))
                at = text_err_offset(w, at)
                at = decimal(w, at, choose(offset < get(w, 1928), offset, get(w, 1928)))
                at = text_page_limit(w, at)
                at = text_elapsed(w, at)
                at = decimal(w, at, get(w, row + 56) // 1000)
                at = text_page_close(w, at)
            index = index + 1
    bind(w, S_ERROR_DIAGNOSTIC, JSON, at - JSON)
    return at - JSON
'''

def source():
    s=SOURCE
    for name,values in [('stage',STAGES),('cause',CAUSES)]:
        s+=f'\ndef {name}_text(w:mutbuf, at:u64, kind:u64) -> u64:\n'
        for i in range(len(values)):s+=f'    if kind == {i}:\n        return text_{name}_{i}(w, at)\n'
        s+='    return at\n'
    return authored(s,text=TEXT,extra={'PENDING_MAGIC':int.from_bytes(b'HIAJPN01','little'),
      '_checks':('rejected','E_HIA_REQUEST_UNKNOWN','E_HIA_TERMINATION_UNKNOWN',
                 'hepta.rea.engine-scratch-cleanup.v1','engine-scratch','removed','retained','incomplete')})
