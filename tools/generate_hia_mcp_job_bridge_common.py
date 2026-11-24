"""Authoring constants and shared scalar helpers for the HIA durable MCP bridge.

The checked-in .hepta sources are the executable product. This module is used
only to regenerate those sources; no host Python runs in the bridge.
"""
from __future__ import annotations
import ast
import re

STATE_BYTES = 256 << 20
INPUT_BYTES = 4 << 20
NONE = (1 << 64) - 1
# Independent, bounded custody regions. JSON node/string storage never aliases
# the original MCJB request, retained Worker stdin or frozen output proof.
C = dict(STATE_BYTES=STATE_BYTES, INPUT_BYTES=INPUT_BYTES, NONE=NONE,
         HOST_ISOLATED=816, NATIVE_JOBS_CONFIGURED=824, SYSTEM_JOBCTL=832,
         NEG100=(1<<64)-100, NEG4=(1<<64)-4, NEG11=(1<<64)-11,
         NEG2=(1<<64)-2, NEG17=(1<<64)-17,
         CACHE=262144, CACHE_END=1048576,
         INITIAL=1048576, ARGS=5242880, BINDING=6291456, WORKER=10485760,
         RECORD=11534336, RECORD_TMP=15728640, JSON=19922944,
         STREAM=24117248, PROOF=25165824, FINISH=26214400,
         SCAN=28311552, SCAN_HASHES=29360128,
         CHILD_IN=33554432, CHILD_OUT=50331648,
         CHILD_ERR=58720256, ARENA=67108864, ARENA_BYTES=167772160,
         SCRATCH=234881024, SCRATCH_BYTES=33554432,
         SHA_INPUT=131072, SHA_OUTPUT=196608, SHA_WORK=200704,
         TABLE=32768, ENV=26214400)

# Persistent slots are offsets/lengths of decoded strings or canonical JSON.
SLOTS = (
 'profile', 'host_config', 'original', 'arguments', 'tool', 'state_root',
 'catalog', 'fence_root', 'self_owner', 'host', 'executable', 'cwd',
 'worker_state', 'worker_pin', 'backend_pin', 'native_manifest', 'native_pin',
 'artifact_roots', 'timeout', 'memory', 'ssh_target', 'remote_state',
 'execution_mode', 'allowed_cwd', 'allow_network', 'allow_fallback',
 'entry_path', 'request_key', 'args', 'env', 'binding', 'worker',
 'transport_digest', 'profile_digest', 'request_digest', 'job_key',
 'job_digest', 'job_id', 'unit', 'job_directory', 'record', 'launch_state',
 'operation', 'expected', 'response', 'proof', 'predecessor',
 'nonce', 'scratch_cleanup', 'error_diagnostic', 'terminal_receipt',
 'fingerprint', 'created', 'remote_command', 'owner_path', 'stdout_bytes',
 'stderr_bytes', 'status_state', 'launch_result', 'entry_pin',
)
SLOT = {name:32768+i*16 for i,name in enumerate(SLOTS)}

FIELDS = (
 'host','python_executable','working_directory','state_root','artifact_roots',
 'worker_sha256','backend_sha256','catalog_sha256','native_helpers_manifest',
 'native_helpers_sha256','timeout_seconds','memory_max_bytes','ssh_target',
 'remote_state_dir','execution_mode','allowed_cwd_prefixes','allow_job_network',
 'allow_detached_fallback','native_jobs','entry','executable','sha256',
 'request_key','id','unit','remote_job_dir','args','cwd','env_keys',
 'created_unix_ms','idempotency_key','request_fingerprint','request_digest',
 'launch_state','launch_error','system_jobctl','schema','owner','epoch','phase',
 'predecessor_state_root','job_id','state','status_authoritative','effect_outcome',
 'outcome','terminal_publication_protocol','terminal_publication_confirmed',
 'output_complete','output_durable','launch_nonce','exit_code','timed_out',
 'cancelled','at_unix_ms','log_bytes','stdout','stderr','stored','seen',
 'log_truncated','log_errors','log_synced','scratch_cleanup','offset',
 'next_offset','size','eof','bytes_hex','status','error','code','response',
 '_hia_terminal','receipt','confirmed','witness','protocol','request_nonce',
 'job','nonce','digest','raw','facts','_hia_lifecycle','observations',
 'systemd','starter_uid','effective_uid','starter_pid','request_job',
 'starter_job','starter_nonce','expected_kind','starter_kind','starter_identity',
 'starter_invocation','request_witness','observed_uid','observed_kind',
 'observed_identity','LoadState','ActiveState','SubState','Result','ExecMainPID',
 'ExecMainCode','ExecMainStatus','InvocationID','Description','backend',
 'worker_adopted','directory','device','inode','removed','durable',
 'original_process_group_stopped','original_child_reaped','env',
 'contract_version','request_id','report_artifact','reason','supervisor_pid',
 'supervisor_uid','supervisor_identity','kind','value','invocation_id',
 'automatic_retry','_hia_status_snapshot','platform','allow_execute','allow_write',
 'ok','reused_remote','launcher_pid',
)
FIELD = {name:i+1 for i,name in enumerate(FIELDS)}

COMMON = r'''
def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0

def uint(s:readbuf, at:u64) -> u64:
    return word_load(s, at)

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def failed(value:u64) -> bool:
    return value >> 63 != 0

def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pointers:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, pointers)
    return 1

def relocate(o:mutbuf, w:mutbuf, phase:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

def decode(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(w, 72, source)
    put(w, 80, size)
    put(w, SCRATCH + 48, 1048576)
    put(w, SCRATCH + 56, 128)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, size:u64) -> u32:
    put(w, 0, phase)
    store(w, SHA_INPUT, command)
    put(o, 0, size)
    return 3

def enter(w:mutbuf, module:u64, phase:u64) -> u32:
    put(w, 16, module)
    put(w, 0, phase)
    put(w, 8, 0)
    return 6

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        put(w, target + index, uint(s, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return target + size

def copy_state(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        put(w, target + index, get(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return target + size

def equal(w:mutbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index + 8 <= size:
        if get(w, left + index) != get(w, right + index):
            return False
        index = index + 8
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return False
        index = index + 1
    return True

def bind(w:mutbuf, slot:u64, at:u64, size:u64) -> u64:
    put(w, slot, at)
    put(w, slot + 8, size)
    return 0

def cp(w:mutbuf, slot:u64, target:u64) -> u64:
    return copy_state(w, get(w, slot), target, get(w, slot + 8))

def raw(w:mutbuf, field:u64, target:u64) -> u64:
    if field == NONE:
        return text_null(w, target)
    if get(w, field) < 4:
        return copy_state(w, get(w, 72) + get(w, field + 24), target, get(w, field + 32))
    return copy_state(w, get(w, 72) + get(w, field + 56), target, get(w, field + 64))

def raw_bind(w:mutbuf, field:u64, slot:u64) -> u64:
    if field == NONE:
        return 0
    if get(w, field) < 4:
        return bind(w, slot, get(w, 72) + get(w, field + 24), get(w, field + 32))
    return bind(w, slot, get(w, 72) + get(w, field + 56), get(w, field + 64))

def freeze_raw(w:mutbuf, field:u64, slot:u64) -> bool:
    if field == NONE:
        return False
    size = choose(get(w, field) < 4, get(w, field + 32), get(w, field + 64))
    start = get(w, 64)
    if size > CACHE_END - start:
        return False
    finish = raw(w, field, start)
    put(w, 64, finish)
    bind(w, slot, start, finish - start)
    return True

def freeze_string(w:mutbuf, field:u64, slot:u64) -> bool:
    if field == NONE or get(w, field) != 4:
        return False
    size = get(w, field + 32)
    start = get(w, 64)
    if size > CACHE_END - start - 1:
        return False
    finish = copy_state(w, ARENA + get(w, field + 24), start, size)
    store(w, finish, 0)
    put(w, 64, finish + 1)
    bind(w, slot, start, size)
    return True

def lookup(w:mutbuf, parent:u64, name:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    child = get(w, parent + 24)
    found = NONE
    while child != NONE:
        row = ARENA + 64 + child * 72
        if key_id(w, ARENA + get(w, row + 40), get(w, row + 48)) == name:
            found = row
        child = get(w, row + 16)
    return found

def field(w:mutbuf, name:u64) -> u64:
    return lookup(w, ARENA + 64, name)

def string_eq(w:mutbuf, row:u64, slot:u64) -> bool:
    if row == NONE or get(w, row) != 4 or get(w, row + 32) != get(w, slot + 8):
        return False
    return equal(w, ARENA + get(w, row + 24), get(w, slot), get(w, slot + 8))

def str_is(w:mutbuf, row:u64, literal:u64) -> bool:
    if row == NONE or get(w, row) != 4:
        return False
    return text_is(w, ARENA + get(w, row + 24), get(w, row + 32), literal)

def number(w:mutbuf, row:u64) -> u64:
    if row == NONE or get(w, row) != 3:
        return NONE
    at = get(w, 72) + get(w, row + 24)
    size = get(w, row + 32)
    if size == 0 or size > 20:
        return NONE
    value = 0
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if ch < 48 or ch > 57:
            return NONE
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return NONE
        value = value * 10 + digit
        index = index + 1
    return value

def valid_uint(w:mutbuf, row:u64) -> bool:
    if row == NONE or get(w, row) != 3:
        return False
    if number(w, row) != NONE:
        return True
    at = get(w, 72) + get(w, row + 24)
    return get(w, row + 32) == 20 and get(w, at) == 3761692294704805937 and get(w, at + 8) == 3834033537023162160 and getn(w, at + 16, 4) == 892417585

def object_count(w:mutbuf, parent:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    count = 0
    child = get(w, parent + 24)
    while child != NONE:
        row = ARENA + 64 + child * 72
        later = get(w, row + 16)
        exists = False
        while later != NONE:
            next = ARENA + 64 + later * 72
            if get(w, row + 48) == get(w, next + 48) and equal(w, ARENA + get(w, row + 40), ARENA + get(w, next + 40), get(w, row + 48)):
                exists = True
            later = get(w, next + 16)
        if exists == False:
            count = count + 1
        child = get(w, row + 16)
    return count

def boolean(w:mutbuf, row:u64, expected:u64) -> bool:
    return row != NONE and get(w, row) == 1 + expected

def is_null(w:mutbuf, row:u64) -> bool:
    return row != NONE and get(w, row) == 0

def quoted(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    store(w, at, 34)
    at = at + 1
    index = 0
    while index < size:
        ch = byte(w, source + index)
        if ch == 34 or ch == 92:
            store(w, at, 92)
            store(w, at + 1, ch)
            at = at + 2
        elif ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
            escape = choose(ch == 8, 98, choose(ch == 9, 116, choose(ch == 10, 110, choose(ch == 12, 102, 114))))
            store(w, at, 92)
            store(w, at + 1, escape)
            at = at + 2
        elif ch < 32:
            store(w, at, 92)
            store(w, at + 1, 117)
            store(w, at + 2, 48)
            store(w, at + 3, 48)
            store(w, at + 4, hex_digit(ch >> 4))
            store(w, at + 5, hex_digit(ch & 15))
            at = at + 6
        else:
            store(w, at, ch)
            at = at + 1
        index = index + 1
    store(w, at, 34)
    return at + 1

def qslot(w:mutbuf, at:u64, slot:u64) -> u64:
    return quoted(w, at, get(w, slot), get(w, slot + 8))

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        store(w, at, 48)
        return at + 1
    count = 0
    while value != 0:
        store(w, 24576 + count, 48 + value % 10)
        count = count + 1
        value = value // 10
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 24576 + count))
        at = at + 1
    return at

def hex_digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)

def hex_digit_value(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    if value >= 65 and value <= 70:
        return value - 55
    return NONE

def lowerhex(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True

def name_ok(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 128:
        return False
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 45 and ch != 46 and ch != 95:
            return False
        index = index + 1
    return True

def path_ok(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 4096 or byte(w, at) != 47:
        return False
    index = 1
    start = 1
    while index <= size:
        if index == size or byte(w, at + index) == 47:
            part = index - start
            if (part == 1 and byte(w, at + start) == 46) or (part == 2 and getn(w, at + start, 2) == 11822):
                return False
            start = index + 1
        elif byte(w, at + index) == 0 or byte(w, at + index) == 10 or byte(w, at + index) == 13:
            return False
        index = index + 1
    return True

def filesystem_path_ok(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 4096 or byte(w, at) != 47:
        return False
    index = 1
    start = 1
    while index <= size:
        if index == size or byte(w, at + index) == 47:
            if index - start == 2 and getn(w, at + start, 2) == 11822:
                return False
            start = index + 1
        elif byte(w, at + index) == 0:
            return False
        index = index + 1
    return True

def path_normalize(w:mutbuf, source:u64, size:u64, target:u64) -> u64:
    if filesystem_path_ok(w, source, size) == False:
        return NONE
    store(w, target, 47)
    out = 1
    index = 1
    while index < size:
        while index < size and byte(w, source + index) == 47:
            index = index + 1
        start = index
        while index < size and byte(w, source + index) != 47:
            index = index + 1
        count = index - start
        if count != 0 and (count != 1 or byte(w, source + start) != 46):
            if out > 1:
                store(w, target + out, 47)
                out = out + 1
            copy_state(w, source + start, target + out, count)
            out = out + count
    return out

def path_equal(w:mutbuf, left:u64, ln:u64, right:u64, rn:u64) -> bool:
    a = path_normalize(w, left, ln, CHILD_IN)
    b = path_normalize(w, right, rn, CHILD_IN + 8192)
    return a != NONE and b == a and equal(w, CHILD_IN, CHILD_IN + 8192, a)

def same_stamp(w:mutbuf, left:u64, right:u64) -> bool:
    return equal(w, left, right, 72) and equal(w, left + 88, right + 88, 32)

def safe_regular(w:mutbuf, at:u64, private:u64) -> bool:
    mode = getn(w, at + 24, 4)
    return mode & 61440 == 32768 and get(w, at + 16) == 1 and getn(w, at + 28, 4) == get(w, 24) and (private == 0 or mode & 511 == 384)

def child(w:mutbuf, next_module:u64, next_phase:u64, role:u64, size:u64, out_cap:u64, err_cap:u64, timeout:u64, directory:u64) -> u32:
    put(w, 512, next_module)
    put(w, 520, next_phase)
    put(w, 528, role)
    put(w, 536, size)
    put(w, 544, out_cap)
    put(w, 552, err_cap)
    put(w, 560, timeout)
    put(w, 568, directory)
    return enter(w, 4, 0)

def child_ok(w:mutbuf) -> bool:
    return get(w, 600) == 0 and get(w, 608) == 0

def walk(w:mutbuf, module:u64, phase:u64, source:u64, size:u64, create:u64) -> u32:
    put(w, 1000, module)
    put(w, 1008, phase)
    put(w, 1016, 0)
    put(w, 1024, source)
    put(w, 1032, size)
    put(w, 1064, create)
    return enter(w, 7, 0)

def capture(w:mutbuf, module:u64, phase:u64, directory:u64, name:u64, cap:u64, target:u64, private:u64, missing:u64) -> u32:
    put(w, 1000, module)
    put(w, 1008, phase)
    put(w, 1016, 1)
    put(w, 1024, directory)
    put(w, 1032, name)
    put(w, 1080, cap)
    put(w, 1088, target)
    put(w, 1096, private)
    put(w, 1104, missing)
    put(w, 1136, 0)
    put(w, 1144, 0)
    return enter(w, 7, 0)

def finish(o:mutbuf, w:mutbuf, source:u64, size:u64) -> u32:
    put(w, 704, source)
    put(w, 712, size)
    put(w, 720, 0)
    return enter(w, 0, 900)
def canonical(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, 8388608)
    put(o, 32, ARENA + 8388608)
    put(o, 40, 64 + 262144 * 56 + 8388608 + 16384)
    return 7

def canonical_equal(w:mutbuf, left:u64, ln:u64, right:u64, rn:u64) -> bool:
    a = 0
    b = 0
    quoted = False
    escaped = False
    while a < ln and b < rn:
        x = byte(w, left + a)
        y = byte(w, right + b)
        if quoted == False:
            if x == 45 and a + 4 <= ln and getn(w, left + a, 4) == 808333357 and (a + 4 == ln or number_end(byte(w, left + a + 4))):
                a = a + 1
                x = 48
            if y == 45 and b + 4 <= rn and getn(w, right + b, 4) == 808333357 and (b + 4 == rn or number_end(byte(w, right + b + 4))):
                b = b + 1
                y = 48
        if x != y:
            return False
        if escaped:
            escaped = False
        elif quoted and x == 92:
            escaped = True
        elif x == 34:
            quoted = quoted == False
        a = a + 1
        b = b + 1
    return a == ln and b == rn

def number_end(value:u64) -> bool:
    return value == 44 or value == 93 or value == 125


'''

BASE_TEXT = dict(null='null',true='true',false='false',comma=',',close='}',colon=':',
                 quote='"',newline='\n',empty='')

def authored(source: str, *, text:dict|None=None, extra:dict|None=None) -> str:
    """Inline only reachable scalar helpers; each component keeps old budgets."""
    literals=dict(BASE_TEXT)
    literals.update(text or {})
    value=source+'\n'+COMMON
    used_names=set(re.findall(r'\bF_([A-Z0-9_]+)\b',value))
    vals=dict(C);vals.update({f'S_{k.upper()}':v for k,v in SLOT.items()})
    vals.update({f'F_{k.upper()}':v for k,v in FIELD.items()})
    vals.update(extra or {})
    for key in sorted(vals,key=len,reverse=True):
        value=re.sub(r'\b'+re.escape(key)+r'\b',str(vals[key]),value)
    for i,(name,raw) in enumerate(literals.items()):
        value=value.replace('text_'+name+'(w, ',f'text_bank_{i//16}(w, {i%16}, ')
    for first in range(0,len(literals),16):
        value+=f'\ndef text_bank_{first//16}(w:mutbuf, kind:u64, at:u64) -> u64:\n'
        for i,(_,raw) in enumerate(list(literals.items())[first:first+16]):
            raw=raw.encode()
            value+=f'    if kind == {i}:\n'
            for off in range(0,len(raw),8):
                part=raw[off:off+8]
                if len(part)==8:value+=f'        put(w, at + {off}, {int.from_bytes(part,"little")})\n'
                else:
                    for j,c in enumerate(part):value+=f'        store(w, at + {off+j}, {c})\n'
            value+=f'        return at + {len(raw)}\n'
        value+='    return at\n'
    value+='\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    used={int(n) for n in re.findall(r'(?:field\(w, |lookup\(w, [^,]+, )(\d+)\)',value)}
    # All known fields are retained: nested callers also pass field ordinals.
    groups={}
    for name,index in FIELD.items():
        if name.upper() in used_names:groups.setdefault(len(name.encode()),[]).append((name.encode(),index))
    for size,rows in groups.items():
        value+=f'    if size == {size}:\n'
        for raw,index in rows:
            clauses=[f'(getn(w, at + {off}, {len(raw[off:off+8])}) ^ {int.from_bytes(raw[off:off+8],"little")})' for off in range(0,len(raw),8)]
            value+='        if ('+' | '.join(clauses)+f') == 0:\n            return {index}\n'
    value+='    return 0\n'
    # Literal comparisons have a separate small dispatch, driven by IDs in each
    # component's own source. No caller-provided bytes become authored code.
    checks=(extra or {}).get('_checks',())
    value+='\ndef text_is(w:mutbuf, at:u64, size:u64, kind:u64) -> bool:\n'
    for i,raw in enumerate(checks):
        raw=raw.encode()
        clauses=[f'getn(w, at + {off}, {len(raw[off:off+8])}) == {int.from_bytes(raw[off:off+8],"little")}' for off in range(0,len(raw),8)]
        value+=f'    if kind == {i}:\n        return size == {len(raw)} and '+(' and '.join(clauses) or 'True')+'\n'
    value+='    return False\n'
    tree=ast.parse(value)
    nodes={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    needed={'advance'}
    todo=['advance']
    while todo:
        for n in ast.walk(nodes[todo.pop()]):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in nodes and n.func.id not in needed:
                needed.add(n.func.id);todo.append(n.func.id)
    lines=value.splitlines()
    return '\n\n'.join('\n'.join(lines[n.lineno-1:n.end_lineno]) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in needed)+'\n'
