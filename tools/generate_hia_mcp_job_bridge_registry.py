"""Original controller registry lookup and no-relaunch intent publication."""
from tools.generate_hia_mcp_job_bridge_common import authored, FIELD
from tools.generate_hia_mcp_typed_json import IGNORED_VALUE

RECORD_FIELDS=(
 'execution_mode','system_jobctl','id','host','ssh_target','unit','remote_job_dir',
 'executable','args','cwd','env_keys','created_unix_ms','idempotency_key',
 'request_fingerprint','request_digest','launch_state','launch_error')
TEXT=dict(owner_lock='controller.owner.lock',legacy_lock='controller.lock',jobs='/jobs',
          pending='pending',launched='launched',operator='"operator"',isolated='"isolated"',
          record_open='{"execution_mode":',system=',"system_jobctl":',id=',"id":',
          host=',"host":',ssh=',"ssh_target":',unit=',"unit":',remote=',"remote_job_dir":',
          executable=',"executable":',args=',"args":',cwd=',"cwd":',
          env_keys=',"env_keys":["HIA_TRANSPORT_ARGUMENTS_SHA256","LC_ALL"],"created_unix_ms":',
          job_key=',"idempotency_key":',fingerprint=',"request_fingerprint":',digest=',"request_digest":',
          record_end=',"launch_state":"pending","launch_error":null}',
          unit_prefix='hepta-runtime-job-',jobs_slash='/jobs/',array_open='[',array_close=']',
          default_launched='"launched"')
for i,name in enumerate(RECORD_FIELDS):TEXT['record_key_'+str(i)]=('{' if i==0 else ',')+'"'+name+'":'

SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 151:
        return projected_field(o, w, result)
    if phase >= 100 and phase <= 111:
        return lease_adoption(o, w, phase, result)
    if phase == 0:
        if get(w, 264) != 0:
            return walk(w, 2, 100, get(w, S_STATE_ROOT), get(w, S_STATE_ROOT + 8), 0)
        return walk(w, 2, 1, get(w, S_STATE_ROOT), get(w, S_STATE_ROOT + 8), 1)
    if phase == 1:
        put(w, 1200, get(w, 1040))
        copy_state(w, 9216, 14848, 144)
        put(w, 1216, 0)
        put(w, 1224, 0)
        put(w, 1232, 0)
        return lock_open(o, w)
    if phase == 2:
        if failed(result) or result < 3:
            return 0
        put(w, 1216 + get(w, 1232) * 8, result)
        return call(o, w, 3, 5, result, 9216, 0, 0, 0, 0, 12)
    if phase == 3:
        if failed(result) or safe_regular(w, 9216, 0) == False:
            return 0
        if getn(w, 9240, 4) & 63 != 0:
            if get(w, 1232) == 0:
                return 0
            return call(o, w, 4, 91, get(w, 1224), 384, 0, 0, 0, 0, 0)
        return lock_claim(o, w)
    if phase == 4:
        if failed(result):
            return 0
        return lock_claim(o, w)
    if phase == 5:
        if failed(result):
            return 0
        if get(w, 1232) == 0:
            put(w, 1232, 1)
            return lock_open(o, w)
        at = cp(w, S_STATE_ROOT, get(w, 64))
        at = text_jobs(w, at)
        put(w, 1440, get(w, 64))
        put(w, 1448, at - get(w, 64))
        store(w, at, 0)
        put(w, 64, at + 1)
        return walk(w, 2, 6, get(w, 1440), get(w, 1448), 1)
    if phase == 6:
        put(w, 1208, get(w, 1040))
        put(w, 1304, get(w, 1040))
        put(w, 1368, 0)
        put(w, 1408, 0)
        put(w, 1424, 0)
        return begin_scan(o, w)
    if phase == 7:
        put(w, 1304, get(w, 1208))
        put(w, 1368, 0)
        return begin_scan(o, w)
    if phase >= 19 and phase <= 39:
        return scan(s, o, w, phase, result)
    if phase == 60:
        if get(w, S_PREDECESSOR + 8) != 0:
            at = cp(w, S_PREDECESSOR, 24576)
            at = text_jobs(w, at)
            return walk(w, 2, 61, 24576, at - 24576, 0)
        put(w, 1408, 1)
        return enter(w, 2, 7)
    if phase == 61:
        put(w, 1304, get(w, 1040))
        put(w, 1368, 1)
        put(w, 1424, 0)
        return enter(w, 11, 0)
    if phase == 83:
        put(w, 1456, 0)
        put(w, 1480, 0)
        index = 0
        while index < 16384:
            store(w, 229376 + index, 0)
            index = index + 1
        return begin_scan(o, w)
    if phase == 62:
        if failed(result):
            return 0
        return enter(w, 6, 40)
    if phase >= 80 and phase <= 82:
        return predecessor_key(o, w, phase, result)
    if phase == 90:
        bind(w, 34016, get(w, S_JOB_ID), get(w, S_JOB_ID + 8))
        at = cp(w, S_JOB_ID, 16384)
        store(w, at, 46)
        store(w, at + 1, 106)
        store(w, at + 2, 115)
        store(w, at + 3, 111)
        store(w, at + 4, 110)
        store(w, at + 5, 0)
        put(w, 1552, 0)
        action = capture(w, 2, 91, get(w, 1208), 16384, 4194304, RECORD_TMP, 0, 0)
        put(w, 1136, 1)
        return action
    if phase == 91:
        if get(w, 1144) != 0 or get(w, 1120) == 0:
            return recheck_error(w)
        return project_record(o, w, 92, get(w, 1112))
    if phase == 92:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or string_eq(w, field(w, F_ID), S_JOB_ID) == False or record_valid(w) == 0:
            return recheck_error(w)
        if immutable_record(w) == 0 or string_eq(w, field(w, F_HOST), S_HOST) == False or string_eq(w, field(w, F_IDEMPOTENCY_KEY), S_JOB_KEY) == False:
            return recheck_error(w)
        if string_eq(w, field(w, F_UNIT), S_UNIT) == False or string_eq(w, field(w, F_REMOTE_JOB_DIR), S_JOB_DIRECTORY) == False:
            return recheck_error(w)
        if choose(boolean(w, field(w, F_SYSTEM_JOBCTL), 1), 1, 0) != get(w, SYSTEM_JOBCTL):
            return recheck_error(w)
        put(w, 1552, 1)
        return enter(w, get(w, 1536), get(w, 1544))
    if phase == 70:
        if failed(result):
            return 0
        put(w, 1512, get(w, 9216) * 1000 + get(w, 9224) // 1000000)
        if fresh(w) == 0:
            return 0
        put(w, 1600, 2)
        put(w, 1608, 71)
        put(w, 1616, 0)
        return enter(w, 8, 0)
    if phase == 71:
        put(w, CHILD_IN, RECEIPT_MAGIC)
        put(w, CHILD_IN + 8, get(w, S_RECORD + 8))
        put(w, CHILD_IN + 16, get(w, 32))
        put(w, CHILD_IN + 24, get(w, S_JOB_ID + 8))
        at = cp(w, S_JOB_ID, CHILD_IN + 32)
        at = cp(w, S_RECORD, at)
        return child(w, 2, 72, 2, at - CHILD_IN, 0, 24, 5000000000, get(w, 1208))
    if phase == 72:
        if child_ok(w) == False or get(w, 624) != 0 or get(w, 616) != 24 or get(w, CHILD_ERR) != RECEIPT_RESULT or get(w, CHILD_ERR + 8) != 6 or get(w, CHILD_ERR + 16) != 0:
            return 0
        put(w, 1504, 1)
        return enter(w, 3, 0)
    return 0

def lease_adoption(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 100:
        put(w, 1200, get(w, 240))
        put(w, 1216, get(w, 248))
        put(w, 1224, get(w, 256))
        copy_state(w, 9216, 14848, 144)
        return call(o, w, 101, 5, get(w, 1200), 9216, 0, 0, 0, 0, 12)
    if phase == 101:
        if failed(result) or getn(w, 9240, 4) & 65535 != 16832 or getn(w, 9244, 4) != get(w, 24) or get(w, 9216) != get(w, 14848) or get(w, 9224) != get(w, 14856):
            return 0
        return call(o, w, 102, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 102:
        if failed(result):
            return 0
        return call(o, w, 103, 72, get(w, 1200), 2, 1, 0, 0, 0, 0)
    if phase == 103:
        if failed(result):
            return 0
        put(w, 1232, 0)
        return lease_lock(o, w)
    if phase == 104:
        if failed(result) or safe_regular(w, 9216, 0) == False or getn(w, 9240, 4) & 63 != 0:
            return 0
        copy_state(w, 9216, 14992, 144)
        at = 16384
        if get(w, 1232) == 0:
            at = text_owner_lock(w, at)
        else:
            at = text_legacy_lock(w, at)
        store(w, at, 0)
        return call(o, w, 105, 262, get(w, 1200), 16384, 9216, 256, 0, 0, 60)
    if phase == 105:
        if failed(result) or same_stamp(w, 9216, 14992) == False or safe_regular(w, 9216, 0) == False:
            return 0
        return call(o, w, 106, 72, get(w, 1216 + get(w, 1232) * 8), 2, 1, 0, 0, 0, 0)
    if phase == 106:
        if failed(result):
            return 0
        return call(o, w, 107, 73, get(w, 1216 + get(w, 1232) * 8), 6, 0, 0, 0, 0, 0)
    if phase == 107:
        if failed(result):
            return 0
        if get(w, 1232) == 0:
            put(w, 1232, 1)
            return lease_lock(o, w)
        put(w, 15168, 1)
        put(w, 15176, 0)
        put(w, 15184, 0)
        put(w, 15192, 0)
        return call(o, w, 108, 72, get(w, 1216), 7, 15168, 0, 0, 0, 48)
    if phase == 108:
        if result == NEG4:
            return call(o, w, 108, 72, get(w, 1216), 7, 15168, 0, 0, 0, 48)
        if failed(result):
            return 0
        if get(w, 272) != 0:
            return call(o, w, 109, 72, get(w, 272), 1034, 0, 0, 0, 0, 0)
        return enter(w, 2, 5)
    if phase == 109:
        if result != 7:
            return 0
        return call(o, w, 110, 5, get(w, 272), 9216, 0, 0, 0, 0, 12)
    if phase == 110:
        if failed(result) or getn(w, 9240, 4) & 65535 != 33152 or getn(w, 9244, 4) != get(w, 24) or get(w, 9232) != 0 or get(w, 9264) != 8388608:
            return 0
        return call(o, w, 111, 72, get(w, 272), 2, 1, 0, 0, 0, 0)
    if phase == 111:
        if failed(result):
            return 0
        return enter(w, 2, 5)
    return 0

def lease_lock(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 104, 5, get(w, 1216 + get(w, 1232) * 8), 9216, 0, 0, 0, 0, 12)

def recheck_error(w:mutbuf) -> u32:
    put(w, 1552, 0)
    return enter(w, get(w, 1536), get(w, 1544))

def record_ready(o:mutbuf, w:mutbuf) -> u32:
    matching = string_eq(w, field(w, F_HOST), S_HOST) and string_eq(w, field(w, F_IDEMPOTENCY_KEY), S_JOB_KEY)
    if matching:
        if get(w, 1368) != 0:
            put(w, 1480, 1)
        else:
            if get(w, 1352) != 0:
                return 0
            put(w, 1352, 1)
            if select_record(w) == 0:
                return 0
    at = record_wire(w, CHILD_IN + 8)
    if matching and get(w, 1368) == 0:
        copy_state(w, CHILD_IN + 8, RECORD, at - CHILD_IN - 8)
        bind(w, S_RECORD, RECORD, at - CHILD_IN - 8)
    put(w, CHILD_IN, at - CHILD_IN - 8)
    put(w, 1432, at - CHILD_IN)
    put(w, 1416, 0)
    return hash_record(o, w)

def predecessor_key(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 80:
        if result != 0:
            return 0
        copy_state(w, 220000, SHA_INPUT + 1, get(w, 1472))
        return sha(o, w, 81, 1, get(w, 1472) + 1)
    if phase == 81:
        if result != 0:
            return 0
        return sha(o, w, 82, 2, 1)
    if result != 32 or get(w, 1456) >= 65536:
        return 0
    index = get(w, SHA_OUTPUT) & 131071
    probed = 0
    while probed < 131072:
        occupied = byte(w, 229376 + index // 8)
        mask = 1 << (index % 8)
        if occupied & mask == 0:
            store(w, 229376 + index // 8, occupied | mask)
            copy_state(w, SHA_OUTPUT, SCAN_HASHES + index * 32, 32)
            put(w, 1456, get(w, 1456) + 1)
            copy_state(w, 218000, SHA_WORK, 1184)
            return record_ready(o, w)
        if equal(w, SHA_OUTPUT, SCAN_HASHES + index * 32, 32):
            return 0
        index = (index + 1) & 131071
        probed = probed + 1
    return 0

def lock_open(o:mutbuf, w:mutbuf) -> u32:
    at = 16384
    if get(w, 1232) == 0:
        at = text_owner_lock(w, at)
    else:
        at = text_legacy_lock(w, at)
    store(w, at, 0)
    return call(o, w, 2, 257, get(w, 1200), 16384, 657474, 384, 0, 0, 12)

def lock_claim(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 5, 73, get(w, 1216 + get(w, 1232) * 8), 6, 0, 0, 0, 0, 0)

def begin_scan(o:mutbuf, w:mutbuf) -> u32:
    put(w, 1296, 0)
    put(w, 1320, 0)
    put(w, 1328, 0)
    put(w, 1336, 0)
    put(w, 1344, 0)
    put(w, 1352, 0)
    put(w, 1376, 0)
    put(w, 1392, 0)
    return call(o, w, 19, 228, 1, 9216, 0, 0, 0, 0, 12)

def scan(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 19:
        if failed(result):
            return 0
        put(w, 1384, get(w, 9216) * 1000000000 + get(w, 9224))
        return call(o, w, 20, 5, get(w, 1304), 15360, 0, 0, 0, 0, 12)
    if phase == 20:
        if failed(result) or getn(w, 15384, 4) & 61440 != 16384:
            return 0
        if get(w, 1368) != 0 and (getn(w, 15388, 4) != get(w, 24) or getn(w, 15384, 4) & 511 != 448):
            return 0
        return call(o, w, 21, 8, get(w, 1304), 0, 0, 0, 0, 0, 0)
    if phase == 21:
        if result != 0:
            return 0
        return sha(o, w, 22, 0, 1)
    if phase == 22:
        if result != 0:
            return 0
        return directory_read(o, w)
    if phase == 23:
        if result == NEG4:
            return directory_read(o, w)
        if failed(result) or result > 65536:
            return 0
        put(w, 1328, 0)
        put(w, 1336, result)
        if result == 0:
            return sha(o, w, 30, 2, 1)
        return next_entry(o, w)
    if phase == 24:
        if get(w, 1120) == 0 or get(w, 1112) == 0:
            return 0
        total = get(w, 1376) + get(w, 1112)
        if total < get(w, 1376) or (get(w, 1368) != 0 and total > 134217728):
            return 0
        put(w, 1376, total)
        return project_record(o, w, 25, get(w, 1112))
    if phase == 25:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or record_valid(w) == 0:
            return 0
        key = field(w, F_IDEMPOTENCY_KEY)
        if get(w, 1368) != 0 and get(w, 1296) == 0 and key != NONE and is_null(w, key) == False:
            host = field(w, F_HOST)
            size = get(w, host + 32)
            at = copy_state(w, ARENA + get(w, host + 24), 220000, size)
            store(w, at, 0)
            at = copy_state(w, ARENA + get(w, key + 24), at + 1, get(w, key + 32))
            put(w, 1472, at - 220000)
            copy_state(w, SHA_WORK, 218000, 1184)
            return sha(o, w, 80, 0, 1)
        return record_ready(o, w)
    if phase == 26:
        if result != 0:
            return 0
        if get(w, 1416) < get(w, 1432):
            return hash_record(o, w)
        return call(o, w, 27, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 27:
        now = get(w, 9216) * 1000000000 + get(w, 9224)
        if failed(result) or now >= get(w, 48) or (get(w, 1368) != 0 and now - get(w, 1384) > 30000000000):
            return 0
        return next_entry(o, w)
    if phase == 30:
        if result != 32:
            return 0
        if get(w, 1296) == 0:
            copy_state(w, SHA_OUTPUT, 14720, 32)
            put(w, 1296, 1)
            put(w, 1320, get(w, 1344))
            put(w, 1344, 0)
            put(w, 1352, 0)
            put(w, 1376, 0)
            return call(o, w, 21, 8, get(w, 1304), 0, 0, 0, 0, 0, 0)
        if equal(w, SHA_OUTPUT, 14720, 32) == False or get(w, 1320) != get(w, 1344):
            return scan_changed(o, w)
        return call(o, w, 31, 5, get(w, 1304), 15616, 0, 0, 0, 0, 12)
    if phase == 31:
        if failed(result):
            return 0
        if same_stamp(w, 15360, 15616) == False:
            return scan_changed(o, w)
        if get(w, 1368) != 0:
            return enter(w, 11, 100)
        if get(w, 1352) != 0:
            put(w, 1504, 0)
            return enter(w, 3, 0)
        if get(w, 1408) == 0:
            return enter(w, 6, 0)
        return call(o, w, 70, 228, 0, 9216, 0, 0, 0, 0, 12)
    return 0

def scan_changed(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1368) != 0 or get(w, 1424) >= 2:
        return 0
    put(w, 1424, get(w, 1424) + 1)
    return begin_scan(o, w)

def directory_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 23, 217, get(w, 1304), SCAN, 65536, 0, 0, 0, 12)

def next_entry(o:mutbuf, w:mutbuf) -> u32:
    while get(w, 1328) < get(w, 1336):
        at = get(w, 1328)
        if get(w, 1336) - at < 24:
            return 0
        extent = getn(w, SCAN + at + 16, 2)
        if extent < 24 or extent > get(w, 1336) - at:
            return 0
        put(w, 1328, at + extent)
        size = 0
        while size < extent - 19 and byte(w, SCAN + at + 19 + size) != 0:
            size = size + 1
        if size == extent - 19 or size > 255:
            return 0
        source = SCAN + at + 19
        skip = (size == 1 and byte(w, source) == 46) or (size == 2 and getn(w, source, 2) == 11822)
        if skip == False:
            json_name = size >= 5 and getn(w, source + size - 5, 5) == JSON_SUFFIX
            if json_name == False:
                if get(w, 1368) != 0:
                    return 0
            else:
                if get(w, 1368) != 0 and (size > 140 or get(w, 1344) >= 65536):
                    return 0
                copy_state(w, source, 16384, size)
                store(w, 16384 + size, 0)
                identity = size - 5
                if get(w, 1368) != 0:
                    while identity >= 5 and getn(w, 16384 + identity - 5, 5) == JSON_SUFFIX:
                        identity = identity - 5
                bind(w, 34016, 16384, identity)
                put(w, 1344, get(w, 1344) + 1)
                return capture(w, 2, 24, get(w, 1304), 16384, choose(get(w, 1368) == 0, 4194304, 1048576), RECORD_TMP, get(w, 1368), 0)
    return directory_read(o, w)

def hash_record(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 1432) - get(w, 1416)
    if size > 65536:
        size = 65536
    copy_state(w, CHILD_IN + get(w, 1416), SHA_INPUT + 1, size)
    put(w, 1416, get(w, 1416) + size)
    return sha(o, w, 26, 1, size + 1)

def string_field(w:mutbuf, key:u64, optional:u64) -> bool:
    row = field(w, key)
    return (optional != 0 and (row == NONE or is_null(w, row))) or (row != NONE and get(w, row) == 4)

def string_array(w:mutbuf, row:u64) -> bool:
    if row == NONE or get(w, row) != 5:
        return False
    child = get(w, row + 24)
    while child != NONE:
        record = ARENA + 64 + child * 72
        if get(w, record) != 4:
            return False
        child = get(w, record + 16)
    return True

def uint_field(w:mutbuf, row:u64, large:u64) -> bool:
    if row == NONE or get(w, row) != 3:
        return False
    size = get(w, row + 32)
    at = get(w, 72) + get(w, row + 24)
    maximum = choose(large == 0, 20, 39)
    if size == 0 or size > maximum:
        return False
    index = 0
    relation = 0
    while index < size:
        ch = byte(w, at + index)
        if ch < 48 or ch > 57:
            return False
        if size == maximum:
            reference = uint_limit(index, large)
            if relation == 0 and ch != reference:
                relation = choose(ch < reference, 1, 2)
        index = index + 1
    return relation != 2

def record_valid(w:mutbuf) -> u64:
    if string_eq(w, field(w, F_ID), 34016) == False or string_field(w, F_HOST, 0) == False:
        return 0
    seen = 0
    known = choose(get(w, 1368) != 0, LEGACY_FIELD_MASK, RECORD_FIELD_MASK)
    child = get(w, ARENA + 88)
    while child != NONE:
        row = ARENA + 64 + child * 72
        key = key_id(w, ARENA + get(w, row + 40), get(w, row + 48))
        if key < 64 and (known >> key) & 1 != 0:
            if seen & (1 << key) != 0:
                return 0
            seen = seen | (1 << key)
        child = get(w, row + 16)
    if get(w, 1368) != 0:
        host = field(w, F_HOST)
        if name_ok(w, ARENA + get(w, host + 24), get(w, host + 32)) == False:
            return 0
        if string_field(w, F_IDEMPOTENCY_KEY, 1) == False or string_field(w, F_REQUEST_DIGEST, 1) == False:
            return 0
        key = field(w, F_IDEMPOTENCY_KEY)
        if key != NONE and is_null(w, key) == False:
            if get(w, key) != 4 or get(w, key + 32) == 0 or get(w, key + 32) > 256:
                return 0
            digest = field(w, F_REQUEST_DIGEST)
            if digest == NONE or get(w, digest) != 4 or get(w, digest + 32) != 64 or lowerhex(w, ARENA + get(w, digest + 24), 64) == False:
                return 0
        return 1
    if string_field(w, F_SSH_TARGET, 0) == False or string_field(w, F_UNIT, 0) == False or string_field(w, F_REMOTE_JOB_DIR, 0) == False or string_field(w, F_EXECUTABLE, 0) == False:
        return 0
    if string_field(w, F_CWD, 1) == False or string_field(w, F_IDEMPOTENCY_KEY, 1) == False or string_field(w, F_REQUEST_DIGEST, 1) == False or string_field(w, F_LAUNCH_ERROR, 1) == False:
        return 0
    if string_array(w, field(w, F_ARGS)) == False or string_array(w, field(w, F_ENV_KEYS)) == False or uint_field(w, field(w, F_CREATED_UNIX_MS), 1) == False or uint_field(w, field(w, F_REQUEST_FINGERPRINT), 0) == False:
        return 0
    mode = field(w, F_EXECUTION_MODE)
    if mode != NONE and str_is(w, mode, 0) == False and str_is(w, mode, 1) == False:
        return 0
    system = field(w, F_SYSTEM_JOBCTL)
    if system != NONE and boolean(w, system, 0) == False and boolean(w, system, 1) == False:
        return 0
    launch = field(w, F_LAUNCH_STATE)
    if launch != NONE and get(w, launch) != 4:
        return 0
    return 1

def immutable_record(w:mutbuf) -> u64:
    if string_eq(w, field(w, F_REQUEST_DIGEST), S_JOB_DIGEST) == False or number(w, field(w, F_REQUEST_FINGERPRINT)) != get(w, 896):
        return 0
    if string_eq(w, field(w, F_SSH_TARGET), S_SSH_TARGET) == False or string_eq(w, field(w, F_EXECUTABLE), S_EXECUTABLE) == False or string_eq(w, field(w, F_CWD), S_CWD) == False:
        return 0
    mode = field(w, F_EXECUTION_MODE)
    if mode == NONE and get(w, HOST_ISOLATED) == 0:
        return 0
    if mode != NONE and str_is(w, mode, get(w, HOST_ISOLATED)) == False:
        return 0
    id = field(w, F_ID)
    if name_ok(w, ARENA + get(w, id + 24), get(w, id + 32)) == False:
        return 0
    end = typed_value(w, field(w, F_ARGS), CHILD_IN)
    if end - CHILD_IN != get(w, S_ARGS + 8) or equal(w, CHILD_IN, get(w, S_ARGS), end - CHILD_IN) == False:
        return 0
    env = field(w, F_ENV_KEYS)
    if get(w, env + 32) != 2:
        return 0
    first = ARENA + 64 + get(w, env + 24) * 72
    second = ARENA + 64 + get(w, first + 16) * 72
    if str_is(w, first, 2) == False or str_is(w, second, 3) == False:
        return 0
    return 1

def select_record(w:mutbuf) -> u64:
    if immutable_record(w) == 0:
        return 0
    put(w, SYSTEM_JOBCTL, choose(boolean(w, field(w, F_SYSTEM_JOBCTL), 1), 1, 0))
    id = field(w, F_ID)
    # Reuse fixed cache positions on every scan. A retry must not grow the
    # retained string arena merely because it revalidates the same record.
    if get(w, 1464) == 0:
        put(w, 1464, get(w, 64))
    put(w, 64, get(w, 1464))
    if freeze_string(w, id, S_JOB_ID) == False or freeze_string(w, field(w, F_UNIT), S_UNIT) == False or freeze_string(w, field(w, F_REMOTE_JOB_DIR), S_JOB_DIRECTORY) == False:
        return 0
    expected = cp(w, S_REMOTE_STATE, CHILD_IN)
    expected = text_jobs_slash(w, expected)
    expected = cp(w, S_JOB_ID, expected)
    if get(w, S_JOB_DIRECTORY + 8) != expected - CHILD_IN or equal(w, get(w, S_JOB_DIRECTORY), CHILD_IN, expected - CHILD_IN) == False:
        return 0
    launch = field(w, F_LAUNCH_STATE)
    if launch == NONE:
        at = text_launched(w, get(w, 64))
        bind(w, S_LAUNCH_STATE, get(w, 64), at - get(w, 64))
        put(w, 64, at)
    elif freeze_string(w, launch, S_LAUNCH_STATE) == False:
        return 0
    return 1

def typed_value(w:mutbuf, row:u64, at:u64) -> u64:
    if row == NONE:
        return text_null(w, at)
    kind = get(w, row)
    if kind == 4:
        return quoted(w, at, ARENA + get(w, row + 24), get(w, row + 32))
    if kind == 5:
        at = text_array_open(w, at)
        node = get(w, row + 24)
        first = 1
        while node != NONE:
            record = ARENA + 64 + node * 72
            if first == 0:
                at = text_comma(w, at)
            at = quoted(w, at, ARENA + get(w, record + 24), get(w, record + 32))
            node = get(w, record + 16)
            first = 0
        return text_array_close(w, at)
    return raw(w, row, at)

def fresh(w:mutbuf) -> u64:
    at = hex_integer(w, get(w, 64), get(w, 1512))
    store(w, at, 45)
    at = hex_integer(w, at + 1, get(w, 32))
    store(w, at, 45)
    store(w, at + 1, 49)
    bind(w, S_JOB_ID, get(w, 64), at + 2 - get(w, 64))
    put(w, 64, at + 2)
    at = text_unit_prefix(w, get(w, 64))
    at = cp(w, S_JOB_ID, at)
    bind(w, S_UNIT, get(w, 64), at - get(w, 64))
    put(w, 64, at)
    at = cp(w, S_REMOTE_STATE, get(w, 64))
    at = text_jobs_slash(w, at)
    at = cp(w, S_JOB_ID, at)
    bind(w, S_JOB_DIRECTORY, get(w, 64), at - get(w, 64))
    put(w, 64, at)
    at = text_pending(w, get(w, 64))
    bind(w, S_LAUNCH_STATE, get(w, 64), at - get(w, 64))
    put(w, 64, at)
    at = text_record_open(w, RECORD)
    at = cp(w, S_EXECUTION_MODE, at)
    at = text_system(w, at)
    if get(w, SYSTEM_JOBCTL) != 0:
        at = text_true(w, at)
    else:
        at = text_false(w, at)
    at = text_id(w, at)
    at = qslot(w, at, S_JOB_ID)
    at = text_host(w, at)
    at = qslot(w, at, S_HOST)
    at = text_ssh(w, at)
    at = qslot(w, at, S_SSH_TARGET)
    at = text_unit(w, at)
    at = qslot(w, at, S_UNIT)
    at = text_remote(w, at)
    at = qslot(w, at, S_JOB_DIRECTORY)
    at = text_executable(w, at)
    at = qslot(w, at, S_EXECUTABLE)
    at = text_args(w, at)
    at = cp(w, S_ARGS, at)
    at = text_cwd(w, at)
    at = qslot(w, at, S_CWD)
    at = text_env_keys(w, at)
    at = decimal(w, at, get(w, 1512))
    at = text_job_key(w, at)
    at = qslot(w, at, S_JOB_KEY)
    at = text_fingerprint(w, at)
    at = decimal(w, at, get(w, 896))
    at = text_digest(w, at)
    at = qslot(w, at, S_JOB_DIGEST)
    put(w, 1520, at)
    at = text_record_end(w, at)
    if at - RECORD > 4194304:
        return 0
    bind(w, S_RECORD, RECORD, at - RECORD)
    return 1

def hex_integer(w:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while value != 0 or count == 0:
        store(w, 24576 + count, hex_digit(value & 15))
        value = value >> 4
        count = count + 1
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 24576 + count))
        at = at + 1
    return at

def project_record(o:mutbuf, w:mutbuf, next_phase:u64, size:u64) -> u32:
    put(w, 2832, RECORD_TMP + size)
    put(w, 2840, next_phase)
    at = ignored_space(w, RECORD_TMP, RECORD_TMP + size)
    if at == RECORD_TMP + size or byte(w, at) != 123:
        return 0
    store(w, JSON, 123)
    put(w, 2856, JSON + 1)
    at = ignored_space(w, at + 1, RECORD_TMP + size)
    if at < RECORD_TMP + size and byte(w, at) == 125:
        return projection_done(o, w, at + 1)
    return projection_key(o, w, at)

def projection_key(o:mutbuf, w:mutbuf, at:u64) -> u32:
    end = ignored_string(w, at, get(w, 2832))
    if end == NONE:
        return 0
    put(w, 2864, at)
    put(w, 2872, end)
    return decode(o, w, 151, at, end - at)

def projected_field(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result >= 4294967292 or get(w, ARENA + 64) != 4:
        return 0
    key = key_id(w, ARENA + get(w, ARENA + 88), get(w, ARENA + 96))
    at = ignored_space(w, get(w, 2872), get(w, 2832))
    if at == get(w, 2832) or byte(w, at) != 58:
        return 0
    at = ignored_value(w, at + 1, get(w, 2832), SCRATCH, SCRATCH_BYTES)
    if at == NONE:
        return 0
    known = choose(get(w, 1368) != 0, LEGACY_FIELD_MASK, RECORD_FIELD_MASK)
    if key < 64 and (known >> key) & 1 != 0:
        out = get(w, 2856)
        if out != JSON + 1:
            store(w, out, 44)
            out = out + 1
        out = copy_state(w, get(w, 2864), out, at - get(w, 2864))
        put(w, 2856, out)
    at = ignored_space(w, at, get(w, 2832))
    if at == get(w, 2832):
        return 0
    if byte(w, at) == 125:
        return projection_done(o, w, at + 1)
    if byte(w, at) != 44:
        return 0
    return projection_key(o, w, ignored_space(w, at + 1, get(w, 2832)))

def projection_done(o:mutbuf, w:mutbuf, at:u64) -> u32:
    if ignored_space(w, at, get(w, 2832)) != get(w, 2832):
        return 0
    store(w, get(w, 2856), 125)
    return decode(o, w, get(w, 2840), JSON, get(w, 2856) + 1 - JSON)
'''

SOURCE+=IGNORED_VALUE

# Typed record fingerprinting ignores unknown JSON fields, applies the original
# serde defaults and uses canonical strings. It is independent of file ordering
# inside an object, while preserving directory enumeration order between scans.
SOURCE+='\ndef record_wire(w:mutbuf, at:u64) -> u64:\n'
for i,name in enumerate(RECORD_FIELDS):
    SOURCE+=f'    at = text_record_key_{i}(w, at)\n    row = field(w, F_{name.upper()})\n'
    default={'execution_mode':'isolated','system_jobctl':'false','launch_state':'default_launched'}.get(name)
    if default:
        SOURCE+=f'    if row == NONE:\n        at = text_{default}(w, at)\n    else:\n        at = typed_value(w, row, at)\n'
    else:SOURCE+='    at = typed_value(w, row, at)\n'
SOURCE+='    return text_close(w, at)\n'
SOURCE+='\ndef uint_limit(index:u64, large:u64) -> u64:\n'
for large,limit in enumerate(('18446744073709551615','340282366920938463463374607431768211455')):
    SOURCE+=f'    if large == {large}:\n'
    for i,ch in enumerate(limit):SOURCE+=f'        if index == {i}:\n            return {ord(ch)}\n'
SOURCE+='    return 0\n'

def source():
    return authored(SOURCE,text=TEXT,extra={
      'JSON_SUFFIX':int.from_bytes(b'.json','little'),
      'RECEIPT_MAGIC':int.from_bytes(b'HIAJRQ01','little'),
      'RECEIPT_RESULT':int.from_bytes(b'HIAJRW01','little'),
      'RECORD_FIELD_MASK':sum(1<<FIELD[n] for n in RECORD_FIELDS),
      'LEGACY_FIELD_MASK':sum(1<<FIELD[n] for n in ('id','host','idempotency_key','request_digest')),
      '_checks':('operator','isolated','HIA_TRANSPORT_ARGUMENTS_SHA256','LC_ALL')})
