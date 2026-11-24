"""HIA framing of existing remote owners and launch-ack publication."""
from tools.generate_hia_mcp_job_bridge_common import authored
FLAGS=(
 'hia_terminal_supervisor','hia_owner_publication','hia_workdir_authority',
 'hia_loop_authority','hia_group_authority','hia_child_publication',
 'hia_original_child_wait','hia_native_output_capture','hia_workload_spawn',
 'hia_supervisor_identity','hia_owner_lock_admission','hia_owner_record_encoding',
 'hia_owner_file_lock','hia_owner_marker_observation','hia_owner_custody','hia_native_job_owner')
TEXT=dict(
 meta_open='{"job_id":',directory=',"job_dir":',digest=',"request_digest":',unit=',"unit":',
 fingerprint=',"request_fingerprint":',execution=',"platform":"linux","execution_mode":"operator","executable":',
 args=',"args":',cwd=',"cwd":',allowed=',"allowed_cwd_prefixes":',env=',"env":',
 timeout=',"timeout_seconds":',memory=',"nice":0,"cpu_quota_percent":100,"memory_max_bytes":',
 network=',"allow_job_network":',fallback=',"allow_detached_fallback":',
 flags=''.join(',"'+f+'":true' for f in FLAGS),
 publisher=',"hia_terminal_publisher":{"encoder":',writer=',"writer":',supervisor=',"supervisor":',
 launcher='},"hia_job_launcher_sha256":',entry=',"hia_job_entry_path":',
 launched='launched',launch_failed='launch_failed',pending='pending',cancelled='cancelled',unknown='launch_unknown',
 state=',"launch_state":',error=',"launch_error":',error_unknown='"Remote launch outcome unavailable"',
 error_state='"Remote launch state unavailable"',
)
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, S_REMOTE_COMMAND + 8) == 0:
            at = shell_quote(w, get(w, 64), get(w, S_ENTRY_PATH), get(w, S_ENTRY_PATH + 8))
            bind(w, S_REMOTE_COMMAND, get(w, 64), at - get(w, 64))
            put(w, 64, at)
        put(w, CHILD_IN, OPERATION_MAGIC)
        put(w, CHILD_IN + 8, get(w, S_JOB_ID + 8))
        put(w, CHILD_IN + 16, get(w, S_HOST + 8))
        put(w, CHILD_IN + 24, get(w, S_HOST + 8))
        put(w, CHILD_IN + 32, get(w, S_JOB_KEY + 8))
        put(w, CHILD_IN + 40, get(w, S_JOB_KEY + 8))
        at = cp(w, S_JOB_DIGEST, CHILD_IN + 48)
        at = cp(w, S_JOB_DIGEST, at)
        at = cp(w, S_REQUEST_DIGEST, at)
        at = cp(w, S_JOB_ID, at)
        at = cp(w, S_HOST, at)
        at = cp(w, S_HOST, at)
        at = cp(w, S_JOB_KEY, at)
        at = cp(w, S_JOB_KEY, at)
        return child(w, 3, 1, 1, at - CHILD_IN, 512, 0, 5000000000, NONE)
    if phase == 1:
        if child_ok(w) == False or get(w, 616) != 0 or get(w, 624) < 2:
            return 0
        at = get(w, 64)
        copy_state(w, CHILD_OUT, at, get(w, 624))
        bind(w, S_OPERATION, at, get(w, 624))
        put(w, 64, at + get(w, 624))
        put(w, 1912, 0)
        if get(w, 1504) != 0:
            return submit(o, w)
        put(w, 1904, 0)
        return enter(w, 3, 200)
    if phase >= 100 and phase <= 103:
        return image(o, w, phase, result)
    if phase == 10:
        put(w, 1864, get(w, 1816))
        put(w, get(w, 1816), SUBMIT_MAGIC)
        put(w, get(w, 1816) + 8, get(w, 1872))
        put(w, get(w, 1816) + 16, get(w, S_WORKER + 8))
        put(w, get(w, 1816) + 24, get(w, 4104))
        put(w, get(w, 1816) + 32, get(w, 4168))
        put(w, get(w, 1816) + 40, get(w, 4552))
        put(w, get(w, 1816) + 48, get(w, 4488))
        put(w, get(w, 1816) + 56, 0)
        at = copy_state(w, JSON, get(w, 1816) + 64, get(w, 1872))
        put(w, 1816, at)
        put(w, 1808, 0)
        return helper_image(o, w)
    if phase == 11:
        put(w, 1808, get(w, 1808) + 1)
        if get(w, 1808) < 4:
            return helper_image(o, w)
        at = cp(w, S_WORKER, get(w, 1816))
        put(w, 1816, at)
        put(w, CHILD_IN + 24, at - get(w, 1864))
        return child(w, 3, 12, 11, at - CHILD_IN, 8388608, 8388608, 20000000000, NONE)
    if phase == 12:
        if child_ok(w) == False:
            put(w, 1888, 0)
            return launch_result(o, w)
        return decode(o, w, 13, CHILD_OUT, get(w, 624))
    if phase == 13:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            put(w, 1888, 0)
            return launch_result(o, w)
        return launch_ack(o, w)
    if phase == 14:
        decision = 0
        if child_ok(w) and get(w, 624) == 16 and get(w, CHILD_OUT) == ACK_RESULT and get(w, CHILD_OUT + 8) <= 5:
            decision = get(w, CHILD_OUT + 8)
        put(w, 1888, decision)
        return launch_result(o, w)
    if phase == 15:
        # A lost local acknowledgement may follow rename. It is never retried,
        # and the original known remote outcome still proceeds to observation.
        if child_ok(w) == False or get(w, 616) != 24 or get(w, CHILD_ERR) != RECEIPT_RESULT or get(w, CHILD_ERR + 8) != 6 or get(w, CHILD_ERR + 16) != 0:
            put(w, 1896, 1)
        put(w, 1600, 3)
        put(w, 1608, 16)
        put(w, 1616, 1)
        return enter(w, 8, 0)
    if phase == 16:
        put(w, 1904, 1)
        return enter(w, 3, 200)
    if phase == 199:
        if failed(result):
            return 0
        put(w, 2000, get(w, 9216) * 1000000000 + get(w, 9224))
        return enter(w, 3, 200)
    if phase == 200:
        if get(w, 1904) == 1 and get(w, 2000) == 0:
            return call(o, w, 199, 228, 1, 9216, 0, 0, 0, 0, 12)
        put(w, 1536, 3)
        put(w, 1544, 201)
        return enter(w, 2, 90)
    if phase == 201:
        if get(w, 1552) == 0:
            if get(w, 2272) == 1:
                put(w, 600, 65 << 8)
                put(w, 608, 3)
                put(w, 624, 0)
                return enter(w, 10, 100)
            if get(w, 1904) == 0:
                return 0
            put(w, 2200, choose(get(w, 1904) == 3, 10, choose(get(w, 1904) == 2, 6, 1)))
            put(w, 2208, 1)
            return enter(w, 5, 700)
        return outer(o, w, 5, 2, 202)
    if phase == 202:
        return observation(o, w)
    if phase == 203:
        if get(w, 2272) == 1:
            return enter(w, 10, 100)
        if child_ok(w) == False:
            if get(w, 1904) == 0:
                put(w, 1912, get(w, 1912) | 2)
                put(w, 1904, 1)
                return enter(w, 3, 200)
            if get(w, 1904) == 1:
                return enter(w, 5, 600)
            put(w, 2200, choose(get(w, 1904) == 3, 13, 6))
            put(w, 2208, choose(get(w, 1904) == 3, 6, choose(get(w, 608) == 1, 2, 1)))
            return enter(w, 5, 700)
        if get(w, 1904) == 2:
            return enter(w, 5, 400)
        return enter(w, 9, 0)
    return 0

def submit(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 4104) > 1048576 or get(w, 4168) > 1048576 or get(w, 4552) > 1048576 or get(w, 4488) > 1048576:
        return 0
    at = metadata(w)
    if at - JSON > 4194304:
        return 0
    put(w, 1872, at - JSON)
    return outer(o, w, 4, 1, 10)

def outer(o:mutbuf, w:mutbuf, role:u64, kind:u64, next_phase:u64) -> u32:
    put(w, CHILD_IN, ENTRY_MAGIC)
    put(w, CHILD_IN + 8, kind)
    put(w, CHILD_IN + 16, get(w, 4104 + (role - 1) * 64))
    put(w, CHILD_IN + 24, 0)
    pin_hex(w, CHILD_IN + 32, role)
    put(w, 1816, CHILD_IN + 96)
    put(w, 1832, role)
    put(w, 1800, next_phase)
    put(w, 1824, 0)
    return image_read(o, w)

def image(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 100:
        if result == NEG4:
            return image_read(o, w)
        remaining = get(w, 4104 + (get(w, 1832) - 1) * 64) - get(w, 1824)
        if failed(result) or result == 0 or result > remaining:
            return 0
        put(w, 1824, get(w, 1824) + result)
        if get(w, 1824) < get(w, 4104 + (get(w, 1832) - 1) * 64):
            return image_read(o, w)
        put(w, 1816, get(w, 1816) + get(w, 1824))
        return enter(w, 3, get(w, 1800))
    return 0

def image_read(o:mutbuf, w:mutbuf) -> u32:
    role = get(w, 1832)
    size = get(w, 4104 + (role - 1) * 64) - get(w, 1824)
    if get(w, 1816) + get(w, 1824) + size > CHILD_OUT:
        return 0
    return call(o, w, 100, 17, get(w, 4096 + (role - 1) * 64), get(w, 1816) + get(w, 1824), size, get(w, 1824), 0, 0, 12)

def helper_image(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 1808)
    put(w, 1832, choose(index == 0, 1, choose(index == 1, 2, choose(index == 2, 8, 7))))
    put(w, 1800, 11)
    put(w, 1824, 0)
    return image_read(o, w)

def pin_hex(w:mutbuf, target:u64, role:u64) -> u64:
    index = 0
    while index < 32:
        value = byte(w, 4112 + (role - 1) * 64 + index)
        store(w, target + index * 2, hex_digit(value >> 4))
        store(w, target + index * 2 + 1, hex_digit(value & 15))
        index = index + 1
    return target + 64

def quoted_pin(w:mutbuf, at:u64, role:u64) -> u64:
    store(w, at, 34)
    at = pin_hex(w, at + 1, role)
    store(w, at, 34)
    return at + 1

def metadata(w:mutbuf) -> u64:
    at = text_meta_open(w, JSON)
    at = qslot(w, at, S_JOB_ID)
    at = text_directory(w, at)
    at = qslot(w, at, S_JOB_DIRECTORY)
    at = text_digest(w, at)
    at = qslot(w, at, S_JOB_DIGEST)
    at = text_unit(w, at)
    at = qslot(w, at, S_UNIT)
    at = text_fingerprint(w, at)
    at = qslot(w, at, S_JOB_DIGEST)
    at = text_execution(w, at)
    at = qslot(w, at, S_EXECUTABLE)
    at = text_args(w, at)
    at = cp(w, S_ARGS, at)
    at = text_cwd(w, at)
    at = qslot(w, at, S_CWD)
    at = text_allowed(w, at)
    at = cp(w, S_ALLOWED_CWD, at)
    at = text_env(w, at)
    at = cp(w, S_ENV, at)
    at = text_timeout(w, at)
    at = cp(w, S_TIMEOUT, at)
    at = text_memory(w, at)
    at = cp(w, S_MEMORY, at)
    at = text_network(w, at)
    at = cp(w, S_ALLOW_NETWORK, at)
    at = text_fallback(w, at)
    at = cp(w, S_ALLOW_FALLBACK, at)
    at = text_flags(w, at)
    at = text_publisher(w, at)
    at = quoted_pin(w, at, 1)
    at = text_writer(w, at)
    at = quoted_pin(w, at, 2)
    at = text_supervisor(w, at)
    at = quoted_pin(w, at, 8)
    at = text_launcher(w, at)
    at = quoted_pin(w, at, 7)
    at = text_entry(w, at)
    at = qslot(w, at, S_ENTRY_PATH)
    return text_close(w, at)

def shell_quote(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    store(w, at, 39)
    at = at + 1
    index = 0
    while index < size:
        value = byte(w, source + index)
        if value == 39:
            store(w, at, 39)
            store(w, at + 1, 92)
            store(w, at + 2, 39)
            store(w, at + 3, 39)
            at = at + 4
        else:
            store(w, at, value)
            at = at + 1
        index = index + 1
    store(w, at, 39)
    return at + 1

def launch_ack(o:mutbuf, w:mutbuf) -> u32:
    put(w, CHILD_IN, ACK_MAGIC)
    status = field(w, F_STATUS)
    reported = lookup(w, status, F_JOB_ID)
    flags = choose(boolean(w, field(w, F_OK), 1), 1, 0)
    flags = flags | choose(boolean(w, field(w, F_REUSED_REMOTE), 1), 4, 0)
    flags = flags | choose(reported != NONE, 8, 0)
    put(w, CHILD_IN + 8, flags)
    pid = number(w, field(w, F_LAUNCHER_PID))
    put(w, CHILD_IN + 16, choose(pid == NONE, 0, pid))
    at = CHILD_IN + 24
    index = 0
    while index < 1584:
        store(w, at + index, 0)
        index = index + 1
    ack_field(w, at, field(w, F_BACKEND))
    ack_field(w, at + 264, reported)
    put(w, at + 528, get(w, S_JOB_ID + 8))
    cp(w, S_JOB_ID, at + 536)
    ack_field(w, at + 792, field(w, F_UNIT))
    put(w, at + 1056, get(w, S_UNIT + 8))
    cp(w, S_UNIT, at + 1064)
    ack_field(w, at + 1320, lookup(w, status, F_LAUNCH_STATE))
    return child(w, 3, 14, 1, 1608, 16, 0, 5000000000, NONE)

def ack_field(w:mutbuf, at:u64, row:u64) -> u64:
    if row != NONE and get(w, row) == 4 and get(w, row + 32) <= 256:
        put(w, at, get(w, row + 32))
        copy_state(w, ARENA + get(w, row + 24), at + 8, get(w, row + 32))
    return 0

def launch_result(o:mutbuf, w:mutbuf) -> u32:
    code = get(w, 1888)
    start = get(w, 64)
    if code == 1:
        at = text_launched(w, start)
    elif code == 2:
        at = text_launch_failed(w, start)
    elif code == 3:
        at = text_pending(w, start)
    elif code == 4:
        at = text_cancelled(w, start)
    else:
        at = text_unknown(w, start)
    bind(w, S_LAUNCH_STATE, start, at - start)
    put(w, 64, at)
    at = text_state(w, get(w, 1520))
    at = qslot(w, at, S_LAUNCH_STATE)
    at = text_error(w, at)
    if code == 0:
        at = text_error_unknown(w, at)
    elif code == 5:
        at = text_error_state(w, at)
    else:
        at = text_null(w, at)
    at = text_close(w, at)
    bind(w, S_RECORD, RECORD, at - RECORD)
    put(w, CHILD_IN, RECEIPT_MAGIC)
    put(w, CHILD_IN + 8, get(w, S_RECORD + 8))
    put(w, CHILD_IN + 16, get(w, 32))
    put(w, CHILD_IN + 24, get(w, S_JOB_ID + 8))
    at = cp(w, S_JOB_ID, CHILD_IN + 32)
    at = cp(w, S_RECORD, at)
    return child(w, 3, 15, 2, at - CHILD_IN, 0, 24, 5000000000, get(w, 1208))

def observation(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 1816)
    reading = get(w, 1904) == 2
    put(w, at, OBSERVATION_MAGIC)
    put(w, at + 8, choose(reading, 0, 1))
    put(w, at + 16, choose(reading, get(w, 1936), 0))
    put(w, at + 24, choose(reading, get(w, 1944), 0))
    put(w, at + 32, 16384)
    put(w, at + 40, get(w, S_JOB_DIRECTORY + 8))
    put(w, at + 48, get(w, S_JOB_ID + 8))
    put(w, at + 56, get(w, S_UNIT + 8))
    put(w, at + 64, 64)
    put(w, at + 72, choose(reading, 0, 63))
    end = cp(w, S_JOB_DIRECTORY, at + 80)
    end = cp(w, S_JOB_ID, end)
    end = cp(w, S_UNIT, end)
    end = cp(w, S_JOB_DIGEST, end)
    put(w, CHILD_IN + 24, end - at)
    return child(w, 3, 203, 11, end - CHILD_IN, 8388608, 8388608, choose(reading, 15000000000, 10000000000), NONE)
'''

def source():
    return authored(SOURCE,text=TEXT,extra={
      'ENTRY_MAGIC':int.from_bytes(b'HIAJEX01','little'),
      'SUBMIT_MAGIC':int.from_bytes(b'HIAJSB01','little'),
      'OPERATION_MAGIC':int.from_bytes(b'HIAJOP01','little'),
      'ACK_MAGIC':int.from_bytes(b'HIAJAK01','little'),
      'ACK_RESULT':int.from_bytes(b'HIAJAO01','little'),
      'RECEIPT_MAGIC':int.from_bytes(b'HIAJRQ01','little'),
      'RECEIPT_RESULT':int.from_bytes(b'HIAJRW01','little'),
      'OBSERVATION_MAGIC':int.from_bytes(b'HIAJOBQ1','little'),
    })
