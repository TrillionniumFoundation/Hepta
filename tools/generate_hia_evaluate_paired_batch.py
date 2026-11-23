"""Build a native paired measurement loop over admitted workload and artifact bytes.

Sealed fds 3 through 8 contain [ABI, workload], the two artifact ELFs, the
direct-call supervisor, the baseline reference batch, and the limits packet.
HIAEPL02 also requires the candidate reference batch on fd 9 and the two
canonical Core files on fds 10 and 11. HIAEPL03 requests the same checks and
a physical observation archive. HIAEPL01 accepts one agreed reference.
HIAEPL04 appends a committed active HIAEBRS1 to the limits packet and
requires a live grant and charge acknowledgement for each native arm. The
worker reads each 64-byte HIAEPGT1 event from stdout and sends an eight-byte
little-endian size and the original next HIAEBRS1 to stdin. Both identities
and the receipt sequence must match. A final archive follows the last charge.
All nine source descriptors can also be supplied as decimal argv entries.

HIAEMT01 contains four little-endian words (magic, pair length, event bytes,
event count), the ordinary HIAEPM01, then consecutive physical HIAEEV01
events. Each event has twelve words: magic, type, case, arm, monotonic time,
and seven type-specific fields. Types are begin (phase, warmups, repetitions,
loan count, scalar return ABI role), owner (reaped time, raw HIADRT01 magic, code, stopped, stdout
length, stderr length), loan (argument, loan kind, logical length), and end (case-local value or post-exit byte disagreement).
The owner is followed by its exact stdout and stderr. Each loan is followed
by the exact logical bytes in the parent-owned backing file after reaping.

The HIAEPM01 header is ten little-endian u64 words (magic, status, case count,
sample count, per-arm measured nanoseconds, per-arm measured calls, case and
arm of first mismatch or terminal). Status 0 means agreement, 1 disagreement,
2 budget exceeded, 3 runner fault, 4 invalid native report, and 5 a declared
expectation different from the baseline. Arm 2 denotes reference comparison.
The samples retain case, arm, reference status, signed exit code, raw return,
native nanoseconds, observed variation and total inspected external bytes.
"""

from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_identity_native import ABI_SCALAR_IDS
from tools.generate_hia_artifact_publication import document
from hepta.hia_schema import PRIMITIVE_PROFILES, supports_feature
from tools.generate_hia_sha256 import source_program as sha256_source
from tools.generate_hia_worker_emit_verification import key_table, literal_match
from tools.generate_hia_worker_evaluate_case import FIELDS, source_program as evaluate_case
from tools.generate_hia_worker_finite_reference import enum_reader
from tools.generate_hia_worker_request import renamed

SOURCE = Path('examples/hia_bootstrap/evaluate_paired_batch.hepta')
PACKER = SOURCE.with_name('evaluate_paired_batch_packer.hepta')
ADAPTER = 'tools/hia_evaluate_paired_batch.S'
PACK_MAGIC = int.from_bytes(b'HIAEPP01', 'little')
# The JSON decoder uses the lower 64 MiB; retained plans and observations are private.
G = 64 << 20
P = G + 4096
ROWS = G + 16384
SAMPLES = G + 131072
DIGESTS = G + 262144
LOAN = G + (1 << 20)
LIMIT = (1 << 64)-1
STATE_FIELDS = {
    'STATE': 0,
    'PARENT_PID': 8,
    'MEMORY_LIMIT': 16,
    'DEADLINE': 24,
    'ARTIFACT_BYTES': 32,
    'CANDIDATE_BYTES': 40,
    'CLOCK': 48,
    'CASE_COUNT': 56,
    'CASE_INDEX': 64,
    'ARM': 72,
    'ARGUMENT_INDEX': 88,
    'LOAN_INDEX': 96,
    'IO_FD': 104,
    'IO_BYTES': 112,
    'WARMUPS': 120,
    'REPETITIONS': 128,
    'TRAP_PHASE': 136,
    'EXPECTED_SNAPSHOT': 144,
    'SAMPLE_COUNT': 152,
    'DURATIONS': 160,
    'CANDIDATE_NS': 168,
    'MEASURED_CALLS': 176,
    'CANDIDATE_CALLS': 184,
    'MISMATCH': 192,
    'FIRST_CASE': 200,
    'FIRST_ARM': 208,
    'OWNER_MAGIC': 256,
    'OWNER_CODE': 264,
    'OWNER_STOPPED': 272,
    'STDOUT_BYTES': 280,
    'CALL_MAGIC': 288,
    'CALL_VALUE': 296,
    'CALL_NS': 304,
    'VARIATION': 312,
    'STDERR_BYTES': 320,
    'DOUBLE_REFERENCE': 328,
    'BASE_CHAINS': 336,
    'OTHER_CHAINS': 344,
    'DEFERRED_STATUS': 352,
    'RUN_STARTED': 360,
    'RUN_REAPED': 368,
    'EVENT_SIZE': 376,
    'EVENT_COUNT': 384,
    'AFTER_CASE': 392,
    'GATED': 400, 'GLOBAL_DEADLINE': 408, 'GATE_SEQUENCE': 416, 'GATE_OPEN': 424,
    'GATE_BEGAN': 432, 'GATE_ARM': 440, 'GATE_MOMENT': 448, 'GATE_CHARGED': 456,
    'GATE_FINISH': 464, 'GATE_USED': 472, 'GATE_BINDING': 11000,
    'CASE_MISMATCH': 480,
}

# File descriptors 3..8 carry [ABI, workload], baseline, candidate, native
# supervisor, agreed reference batch, and immutable memory/deadline control.
# Scratch fds 16..23 are distinct per-argument snapshot files; fd 24 receives
# the real supervisor's terminal record. All decisions return a syscall port.
POLICY = '''
def measure(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    state = get(w, STATE)
    if state == 0:
        if length(s) < 24:
            return 0
        if read_word(s,0) == GATED_CONTROL:
            if valid_gate_receipt(s,24,w,0,True) == False:
                return 0
            put(w,GATED,1)
            put(w,GLOBAL_DEADLINE,read_word(s,16))
        elif length(s) != 24 or (read_word(s,0) != CONTROL and read_word(s,0) != BOTH_CONTROL and read_word(s,0) != ARCHIVE_CONTROL):
            return 0
        m = read_word(s, 8)
        d = read_word(s, 16)
        if m < 67108864 or m > 4294967296 or d == 0:
            return 0
        if get(w,ARTIFACT_BYTES) == 0 or get(w,ARTIFACT_BYTES) > 67108864 or get(w,CANDIDATE_BYTES) == 0 or get(w,CANDIDATE_BYTES) > 67108864:
            return 0
        put(w, MEMORY_LIMIT, m)
        put(w, DEADLINE, d)
        if read_word(s,0) != CONTROL:
            mode = 1
            if read_word(s,0) == GATED_CONTROL or read_word(s,0) == ARCHIVE_CONTROL:
                mode = 2
            put(w,DOUBLE_REFERENCE,mode)
            put(w,STATE,8)
            return 8
        put(w, STATE, 1)
        return 1
    if state == 1:
        n = widen(evaluate_case(s, o, w))
        if n < 112 or n > 32816 or get(o, 0) != WORKLOAD or get(o, 8) != 0:
            return 0
        count = get(o, 16)
        if count == 0 or count > 512 or n != 48 + 64 * count:
            return 0
        put(w, CASE_COUNT, count)
        put(w, WARMUPS, get(o, 32))
        put(w, REPETITIONS, get(o, 40))
        return retain_shapes(s, o, w, count)
    if state == 2:
        return admit_reference(s, o, w)
    if state == 3:
        return measure_next(s, o, w)
    if state == 4:
        return prepare_files(s, o, w)
    if state == 5:
        if get(w,DOUBLE_REFERENCE) == 2:
            return archive_owner(o,w)
        return observe(s, o, w)
    if state == 15 or state == 16:
        return budget_returned(s,o,w,state)
    if state == 13:
        return observe(s,o,w)
    if state == 14:
        if get(w,AFTER_CASE) != 0:
            return finish(o,w,get(w,AFTER_CASE))
        put(w,CASE_INDEX,get(w,CASE_INDEX)+1)
        put(w,STATE,3)
        return measure_next(s,o,w)
    if state == 6:
        return read_files(o, w)
    if state == 7:
        return compare_file(s, o, w)
    if state == 8 or state == 9:
        return core_ledger(s, o, w, state)
    if state == 10:
        return compare_references(s, o, w)
    if state == 11:
        return finish(o,w,get(w,DEFERRED_STATUS))
    if state == 12:
        return compare_one(s,o,w)
    return 0

def valid_gate_receipt(s:readbuf, at:u64, w:mutbuf, action:u64, initial:bool) -> bool:
    if at > length(s) or length(s) - at < 228 or read_word(s,at) != BUDGET_RESULT:
        return False
    if read_word(s,at+8) != 0 or read_word(s,at+16) != action or read_word(s,at+40) != 7 or read_word(s,at+56) != 1:
        return False
    sequence = read_word(s,at+48)
    if sequence == 0 or read_word(s,at+24) != sequence or read_word(s,at+64) != 36 or read_word(s,at+80) != 64 or read_word(s,at+88) != 0:
        return False
    if read_word(s,at+104) != 1 or read_word(s,at+112) != 1 or read_word(s,at+120) != 0:
        return False
    used = read_word(s,at+72)
    charged = read_word(s,at+96)
    if used == 0 or used > 4096 or charged == 0 or charged > 20 or length(s)-at != 228 + used + charged:
        return False
    if initial == False and (sequence != get(w,GATE_SEQUENCE) + 1 or used != get(w,GATE_USED)):
        return False
    body = at+128
    i = 0
    while i < 100 + used:
        c = byte(s,body+i)
        if i < 4:
            if c != ((762868835 >> (8*i)) & 255):
                return False
        elif i < 36 or i >= 36+used:
            if (c < 48 or c > 57) and (c < 97 or c > 102):
                return False
        elif c < 48 or c > 57 or (i == 36 and used > 1 and c == 48):
            return False
        if initial:
            store(w,GATE_BINDING+i,c)
        elif byte(w,GATE_BINDING+i) != c:
            return False
        i = i+1
    value = 0
    i = 0
    while i < charged:
        c = byte(s,body+100+used+i)
        if c < 48 or c > 57 or (i == 0 and charged > 1 and c == 48) or value > 1844674407370955161 or (value == 1844674407370955161 and c > 53):
            return False
        value = 10*value+c-48
        i = i+1
    if value != get(w,GATE_CHARGED):
        return False
    if initial:
        put(w,GATE_USED,used)
    put(w,GATE_SEQUENCE,sequence)
    return True

def budget_event(o:mutbuf,w:mutbuf,operation:u64,arm:u64) -> u64:
    now = get(w,CLOCK)
    if arm > 1 or now == 0:
        return 0
    elapsed = 0
    if operation == 6:
        start = get(w,GATE_BEGAN)
        if now < start or now-start > MAX-get(w,GATE_CHARGED):
            return 0
        elapsed = now-start
        put(w,GATE_CHARGED,get(w,GATE_CHARGED)+elapsed)
    put(o,0,BUDGET_EVENT)
    put(o,8,operation)
    put(o,16,arm)
    put(o,24,get(w,GATE_SEQUENCE))
    put(o,32,now)
    put(o,40,get(w,GLOBAL_DEADLINE))
    put(o,48,elapsed)
    put(o,56,get(w,GATE_CHARGED))
    put(w,GATE_MOMENT,now)
    put(w,GATE_ARM,arm)
    put(w,STATE,choose(operation==5,15,16))
    return 14

def budget_returned(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    if valid_gate_receipt(s,0,w,choose(state==15,7,0),False) == False:
        return 0
    if state == 15:
        ms = read_word(s,32)
        start = get(w,GATE_MOMENT)
        if ms > 3600000 or start > MAX - 1000000 * ms:
            return 0
        bound = start + 1000000 * ms
        if bound > get(w,GLOBAL_DEADLINE):
            bound = get(w,GLOBAL_DEADLINE)
        put(w,GATE_BEGAN,get(w,CLOCK))
        put(w,GATE_OPEN,get(w,GATE_ARM)+1)
        if ms == 0 or get(w,CLOCK) >= bound:
            # The real session granted a token, but no child was launched.
            # Return the token with the observed zero cost before settlement.
            return finish(o,w,2)
        put(w,DEADLINE,bound)
    else:
        put(w,GATE_OPEN,0)
        put(w,DEADLINE,get(w,GLOBAL_DEADLINE))
        if get(w,GATE_FINISH) != 0:
            return finish(o,w,get(w,GATE_FINISH)-1)
    put(w,STATE,3)
    return 1

def retain_shapes(s:readbuf, o:mutbuf, w:mutbuf, count:u64) -> u64:
    signatures = first(w, 64)
    cases = lookup(w, next(w, signatures), KEY_CASES)
    case = first(w, cases)
    i = 0
    while i < count:
        size = plan_named_case(s, o, w, signatures, case)
        if size < 80 or size > 6224:
            return 0
        row = ROWS + 96*i
        put(w,row+24,case)
        put(w,row+32,choose(get(o,24) == 0,0,8))
        put(w,row+40,get(o,32))
        if get(w,DOUBLE_REFERENCE) != 0 and declared(s,o,w,row,i,case) == False:
            put(w,row+64,3)
        case = next(w, case)
        i = i + 1
    put(w,STATE,2)
    return 2

def admit_reference(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 24 or read_word(s, 0) != BATCH or read_word(s, 8) != get(w, CASE_COUNT):
        return 0
    done = read_word(s, 16)
    if done == 0 or done > get(w, CASE_COUNT):
        return 0
    at = 24
    i = 0
    budget = 0
    while i < done:
        if at > length(s) or length(s) - at < 160 or read_word(s, at) != i:
            return 0
        size = read_word(s, at+8)
        at = at + 16
        if size < 144 or size > length(s) - at or read_word(s, at) != REFERENCE:
            return 0
        status = read_word(s, at+8)
        if status > 19 or (status > 11 and status < 15):
            return 0
        if status == 5 or status == 6 or status == 16:
            if i + 1 != done:
                return 0
            budget = 1
        row = ROWS + 96*i
        if size != 144 + choose(status == 0,get(w,row+32),0) + get(w,row+40):
            return 0
        put(w, row, at)
        put(w, row+8, size)
        put(w, row+16, status)
        at = at + size
        i = i + 1
    if at != length(s) or (budget == 0 and done != get(w, CASE_COUNT)):
        return 0
    if budget != 0:
        put(w, CASE_INDEX, done - 1)
        return finish(o, w, 2)
    if get(w,DOUBLE_REFERENCE) != 0:
        put(w,STATE,10)
        return 7
    put(w, STATE, 3)
    return 1

def core_ledger(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    put(o,48,524289)
    put(o,56,128)
    if widen(decode_json(s,w,o)) >= 4294967292 or get(w,64) != 6:
        return 0
    chains = ledger_shape(w,lookup(w,64,KEY_SCHEMA))
    if chains > 1:
        return 0
    if state == 8:
        put(w,BASE_CHAINS,chains)
        put(w,STATE,9)
        return 9
    put(w,OTHER_CHAINS,chains)
    put(w,STATE,1)
    return 1

# Save the optional frozen expectation while its numeric spelling and typed
# case plan are in scope. Raw bytes of the declared SHA stay in private memory.
def declared(s:readbuf, o:mutbuf, w:mutbuf, row:u64, index:u64, case:u64) -> bool:
    expected = lookup(w,case,KEY_EXPECTED)
    if expected == MAX:
        return True
    if is_object(w,expected) == False:
        return False
    status = lookup(w,expected,KEY_STATUS)
    values = lookup(w,expected,KEY_VALUES)
    if returned_status(w,status):
        if values == MAX or get(w,values) != 5:
            return False
        role = get(o,24)
        if get(w,values+32) != choose(role==0,0,1):
            return False
        put(w,row+64,1)
        if role != 0:
            if scalar_plan(s,o,w,first(w,values),8192,choose(role==256,U32,role)) == 0:
                return False
            put(w,row+72,get(o,8200))
    elif trapped_status(w,status):
        if values != MAX:
            return False
        put(w,row+64,2)
    else:
        return False
    buffers = lookup(w,expected,KEY_BUFFERS)
    if buffers == MAX:
        return True
    if get(w,buffers) != 5 or get(o,40) == 0 or get(w,buffers+32) != get(o,40):
        return False
    put(w,row+80,get(o,40))
    node = first(w,buffers)
    arg = 0
    loan = 0
    while arg < get(o,16):
        at = 80+48*arg
        role = get(o,at)
        if role != 0:
            if node == MAX or is_object(w,node) == False:
                return False
            if uint(s,w,lookup(w,node,KEY_ARGUMENT),128) != arg:
                return False
            size = get(o,at+8)
            if uint(s,w,lookup(w,node,KEY_BYTE_LENGTH),1048576) != size:
                return False
            kind = lookup(w,node,KEY_KIND)
            if (role == 1 and readbuf_kind(w,kind) == False) or (role == 2 and mutbuf_kind(w,kind) == False):
                return False
            digest = lookup(w,node,KEY_SHA256)
            if digest == MAX or get(w,digest) != 4 or get(w,digest+32) != 64:
                return False
            dest = DIGESTS + 40*(8*index + loan)
            put(w,dest,size)
            off = get(w,digest+24)
            i = 0
            while i < 32:
                high = snapshot_nibble(byte(w,off+2*i))
                low = snapshot_nibble(byte(w,off+2*i+1))
                if high > 15 or low > 15:
                    return False
                store(w,dest+8+i,(high << 4) | low)
                i = i+1
            node = next(w,node)
            loan = loan+1
        arg = arg+1
    return node == MAX

# s and o are separate sealed read-only mappings on this port. All outputs
# and progress go into private w until the normal writable output port resumes.
def compare_references(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(o) < 24 or get(o,0) != BATCH or get(o,8) != get(w,CASE_COUNT):
        return 0
    done = get(o,16)
    if done == 0 or done > get(w,CASE_COUNT):
        return 0
    at = 24
    index = 0
    budget = 0
    while index < done:
        row = ROWS + 96*index
        if at > length(o) or length(o)-at < 160 or get(o,at) != index:
            return 0
        size = get(o,at+8)
        at = at+16
        status = get(o,at+8)
        if get(o,at) != REFERENCE or status > 19 or (status > 11 and status < 15):
            return 0
        if size != 144 + choose(status == 0,get(w,row+32),0) + get(w,row+40) or size > length(o)-at:
            return 0
        if status == 5 or status == 6 or status == 16:
            if index+1 != done:
                return 0
            budget = 1
        put(w,row+48,at)
        put(w,row+56,status)
        at = at+size
        index = index+1
    if at != length(o) or (budget == 0 and done != get(w,CASE_COUNT)):
        return 0
    if budget != 0:
        return reference_terminal(w,2,done-1)
    put(w,STATE,12)
    put(w,CASE_INDEX,0)
    return compare_one(s,o,w)

def compare_one(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = get(w,CASE_INDEX)
    if get(w,CLOCK) >= get(w,DEADLINE):
        return reference_terminal(w,2,index)
    row = ROWS + 96*index
    left = get(w,row)
    right = get(w,row+48)
    old = get(w,row+16)
    new = get(w,row+56)
    before = left+32+choose(old == 0,get(w,row+32),0)
    after = right+32+choose(new == 0,get(w,row+32),0)
    if get(w,row+64) == 3 or declared_matches(s,w,row,index,before+112) == False:
        return reference_terminal(w,5,index)
    equal = trap_class(old) == trap_class(new) and get(w,BASE_CHAINS) == get(w,OTHER_CHAINS)
    if old == 0 and new == 0 and get(w,row+32) != 0:
        equal = equal and read_word(s,left+32) == get(o,right+32)
    # 9 fixed machine counters correspond to the public base ledger.
    # Four further counters back the recursive-chain ledger when present.
    # The final retained machine diagnostic is independent of public scope.
    count = choose(get(w,BASE_CHAINS) == 0,9,13)
    i = 0
    while i < count:
        equal = equal and read_word(s,before+8*i) == get(o,after+8*i)
        i = i+1
    i = 0
    while i < get(w,row+40):
        equal = equal and byte(s,before+112+i) == byte(o,after+112+i)
        i = i+1
    if equal == False:
        put(w,CASE_INDEX,index)
        put(w,ARM,2)
        mismatch(w)
    index = index+1
    if index < get(w,CASE_COUNT):
        put(w,CASE_INDEX,index)
        return 7
    put(w,CASE_INDEX,0)
    put(w,ARM,0)
    put(w,STATE,3)
    return 1

def reference_terminal(w:mutbuf, status:u64, index:u64) -> u64:
    put(w,CASE_INDEX,index)
    put(w,ARM,2)
    put(w,DEFERRED_STATUS,status)
    put(w,STATE,11)
    return 1

def trap_class(status:u64) -> u64:
    if status == 1 or status == 3 or status == 4:
        return 8
    if status == 2:
        return 9
    if status == 15 or status == 17:
        return 11
    if status == 18 or status == 19:
        return 10
    return status

def declared_matches(s:readbuf, w:mutbuf, row:u64, index:u64, start:u64) -> bool:
    declared = get(w,row+64)
    if declared == 0:
        return True
    status = get(w,row+16)
    if (declared == 1) != (status == 0):
        return False
    if status == 0 and get(w,row+32) != 0 and get(w,row+72) != read_word(s,get(w,row)+32):
        return False
    loan = 0
    while loan < get(w,row+80):
        spec = DIGESTS + 40*(8*index+loan)
        size = get(w,spec)
        if widen(pair_hash_sha256(s,w,start,size)) != 32:
            return False
        i = 0
        while i < 32:
            if byte(w,length(w)-4096+1088+i) != byte(w,spec+8+i):
                return False
            i = i+1
        start = start+size
        loan = loan+1
    return True

def measure_next(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    n = get(w, CASE_COUNT)
    index = get(w, CASE_INDEX)
    arm = get(w, ARM)
    traps = get(w, TRAP_PHASE)
    while arm < 2:
        if index >= n:
            index = 0
            traps = traps + 1
            if traps == 2:
                traps = 0
                arm = arm + 1
        elif (get(w, ROWS+96*index+16) != 0) == (traps != 0):
            put(w, CASE_INDEX, index)
            put(w, ARM, arm)
            put(w, TRAP_PHASE, traps)
            if get(w,GATED) == 1 and get(w,GATE_OPEN) != arm + 1:
                if get(w,GATE_OPEN) != 0:
                    return budget_event(o,w,6,get(w,GATE_OPEN)-1)
                return budget_event(o,w,5,arm)
            return prepare_case(s, o, w, index)
        else:
            index = index + 1
    return finish(o, w, 0)

def prepare_case(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:
    signatures = first(w, 64)
    case = get(w,ROWS+96*index+24)
    size = plan_named_case(s, o, w, signatures, case)
    if size < 80 or size > 6224 or get(o, 0) != PLAN:
        return 0
    i = 0
    while i < size:
        put(w, P+i, get(o, i))
        i = i + 8
    row = ROWS + 96*index
    has_value = get(w, row+16) == 0 and get(o, 24) != 0
    if get(w, row+8) != 144+choose(has_value, 8, 0)+get(o, 32):
        return 0
    put(w, EXPECTED_SNAPSHOT, get(w, row)+144+choose(has_value, 8, 0))
    put(w, ARGUMENT_INDEX, 0)
    put(w, LOAN_INDEX, 0)
    put(w,CASE_MISMATCH,0)
    put(w, STATE, 4)
    if get(w,DOUBLE_REFERENCE) == 2:
        if event_header(o,w,1,get(w,CLOCK),0) == False:
            return 0
        traps = get(w,TRAP_PHASE)
        put(o,40,traps)
        put(o,48,choose(traps == 0,get(w,WARMUPS),0))
        put(o,56,choose(traps == 0,get(w,REPETITIONS),1))
        put(o,64,get(w,P+40))
        put(o,72,get(w,P+24))
        return 10
    return prepare_files(s, o, w)

def prepare_files(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    arg = get(w, ARGUMENT_INDEX)
    loan = get(w, LOAN_INDEX)
    while arg < get(w, P+16):
        row = P + 80 + 48*arg
        arg = arg + 1
        if get(w, row) != 0:
            size = get(w, row+8)
            offset = get(w, row+32)
            fill = get(w, row+24)
            mode = get(w, row+16)
            if size > 1048576 or loan >= 8:
                return 0
            if mode == 1 and (offset > length(s) or 2*size > length(s)-offset):
                return 0
            i = 0
            while i < size:
                if mode == 1:
                    high = snapshot_nibble(byte(s, offset+2*i))
                    low = snapshot_nibble(byte(s, offset+2*i+1))
                    if high > 15 or low > 15:
                        return 0
                    store(o, i, (high << 4) | low)
                else:
                    store(o, i, fill)
                i = i + 1
            if size == 0:
                store(o, 0, 0)
            put(w, ARGUMENT_INDEX, arg)
            put(w, LOAN_INDEX, loan+1)
            put(w, IO_FD, 16+loan)
            put(w, IO_BYTES, choose(size==0, 1, size))
            return 3
    return runner_packet(s, o, w)

def runner_packet(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    pid = get(w, PARENT_PID)
    deadline = get(w, DEADLINE)
    now = get(w, CLOCK)
    if now >= deadline:
        return terminal_case(o,w,2)
    remaining = deadline - now - 1
    if remaining >= 86400000000000:
        return 0
    cpu = 1
    bit = 65536
    while bit != 0:
        if remaining >= bit*1000000000:
            remaining = remaining - bit*1000000000
            cpu = cpu + bit
        bit = bit >> 1
    arm = get(w, ARM)
    count = get(w, P+16)
    loans = get(w, P+40)
    words = count + loans
    name = get(w, P+48)
    width = get(w, P+56)
    if width < 3 or width > 514 or name >= length(s) or width > length(s)-name:
        return 0
    put(o, 0, SUPERVISE)
    put(o, 8, pid)
    put(o, 16, deadline)
    put(o, 24, 24)
    put(o, 32, RUN)
    put(o, 40, pid)
    put(o, 48, get(w, MEMORY_LIMIT))
    put(o, 56, cpu)
    put(o, 64, 4+arm)
    put(o, 72, get(w, ARTIFACT_BYTES+8*arm))
    put(o, 80, words)
    put(o, 88, loans)
    put(o, 96, width-2)
    put(o, 104, choose(get(w,TRAP_PHASE)==0, get(w,WARMUPS), 0))
    put(o, 112, choose(get(w,TRAP_PHASE)==0, get(w,REPETITIONS), 1))
    put(o, 120, 1)
    put(o, 128, direct_return_mask(get(w,P+24)))
    index = 0
    word = 0
    loan = 0
    slots = 136 + 8*words
    while index < count:
        row = P+80+48*index
        role = get(w, row)
        value = get(w, row+8)
        if role == 0:
            put(o, 136+8*word, value)
            word = word + 1
        else:
            put(o, 136+8*word, 0)
            put(o, 144+8*word, value)
            put(o, slots+32*loan, word)
            put(o, slots+32*loan+8, 16+loan)
            put(o, slots+32*loan+16, value)
            put(o, slots+32*loan+24, choose(role==1, 1, 0))
            word = word + 2
            loan = loan + 1
        index = index + 1
    start = slots + 32*loans
    i = 1
    while i < width-1:
        point = byte(s, name+i)
        if point < 33 or point >= 127 or point == 92 or point == 34:
            return 0
        store(o, start+i-1, point)
        i = i + 1
    put(w, IO_BYTES, start+width-2)
    put(w, STATE, 5)
    return 4

def observe(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w,OWNER_MAGIC) != TERMINAL:
        return 0
    code = get(w,OWNER_CODE)
    stopped = get(w,OWNER_STOPPED)
    actual = get(w,STDOUT_BYTES)
    if stopped > 1 or (code > 255 and code < MAX-63 and code != MAX-255):
        return 0
    if code == MAX-255 and (stopped != 1 or actual != 0 or get(w,STDERR_BYTES) != 0):
        return 0
    if get(w,STDERR_BYTES) > 65536 or actual > 2097152:
        return terminal_case(o,w,4)
    if stopped != 0 or code == MAX-23:
        return terminal_case(o,w,2)
    arm = get(w,ARM)
    index = get(w,CASE_INDEX)
    row = ROWS + 96*index
    expected = get(w,row+16)
    sample = SAMPLES + 64*get(w,SAMPLE_COUNT)
    put(w,sample,index)
    put(w,sample+8,arm)
    put(w,sample+16,expected)
    put(w,sample+24,code)
    put(w,SAMPLE_COUNT,get(w,SAMPLE_COUNT)+1)
    if code == MAX-5:
        if actual != 0:
            return terminal_case(o,w,4)
        if expected == 0:
            return terminal_case(o,w,1)
    else:
        if code != 0:
            return terminal_case(o,w,3)
        if actual != 32 or get(w,CALL_MAGIC) != RECEIPT or get(w,VARIATION) > 1:
            return terminal_case(o,w,4)
        value = get(w,CALL_VALUE)
        duration = get(w,CALL_NS)
        put(w,sample+32,value)
        put(w,sample+40,duration)
        put(w,sample+48,get(w,VARIATION))
        if expected != 0:
            mismatch(w)
        else:
            total = get(w,DURATIONS+8*arm)
            if duration > MAX-total:
                return 0
            put(w,DURATIONS+8*arm,total+duration)
            put(w,MEASURED_CALLS+8*arm,get(w,MEASURED_CALLS+8*arm)+get(w,REPETITIONS))
            mask = direct_return_mask(get(w,P+24))
            observed = value & mask
            desired = 0
            if get(w,P+24) != 0:
                desired = read_word(s,get(w,row)+32) & mask
            if get(w,P+24) == BOOL:
                observed = choose(observed != 0, 1, 0)
            if get(w,VARIATION) != 0 or observed != desired or (get(w,P+24) == 256 and (value >> 32) != 0):
                mismatch(w)
    put(w,ARGUMENT_INDEX,0)
    put(w,LOAN_INDEX,0)
    put(w,STATE,6)
    return read_files(o,w)

def read_files(o:mutbuf, w:mutbuf) -> u64:
    arg = get(w,ARGUMENT_INDEX)
    loan = get(w,LOAN_INDEX)
    while arg < get(w,P+16):
        row = P+80+48*arg
        arg = arg + 1
        if get(w,row) != 0:
            put(w,ARGUMENT_INDEX,arg)
            put(w,LOAN_INDEX,loan+1)
            put(w,IO_FD,16+loan)
            put(w,IO_BYTES,get(w,row+8))
            put(w,STATE,7)
            return 5
    if get(w,DOUBLE_REFERENCE) == 2:
        if event_header(o,w,4,get(w,CLOCK),0) == False:
            return 0
        put(o,40,get(w,CASE_MISMATCH))
        put(w,STATE,14)
        return 10
    put(w,CASE_INDEX,get(w,CASE_INDEX)+1)
    put(w,STATE,3)
    return 1

def compare_file(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = get(w,EXPECTED_SNAPSHOT)
    size = get(w,IO_BYTES)
    if get(w,AFTER_CASE) == 0:
        if at > length(s) or size > length(s)-at:
            return 0
        i = 0
        while i < size:
            if byte(w,LOAN+i) != byte(s,at+i):
                mismatch(w)
            i = i + 1
        sample = SAMPLES + 64*(get(w,SAMPLE_COUNT)-1)
        put(w,sample+56,get(w,sample+56)+size)
        put(w,EXPECTED_SNAPSHOT,at+size)
    put(w,STATE,6)
    if get(w,DOUBLE_REFERENCE) == 2:
        if event_header(o,w,3,get(w,CLOCK),size) == False:
            return 0
        arg = get(w,ARGUMENT_INDEX)-1
        put(o,40,arg)
        put(o,48,get(w,P+80+48*arg))
        put(o,56,size)
        return 12
    return read_files(o,w)

def event_header(o:mutbuf,w:mutbuf,kind:u64,clock:u64,extra:u64) -> bool:
    size = get(w,EVENT_SIZE)+96+extra
    if size > 268435456 or clock == 0:
        return False
    put(w,EVENT_SIZE,size)
    put(w,EVENT_COUNT,get(w,EVENT_COUNT)+1)
    put(o,0,EVENT)
    put(o,8,kind)
    put(o,16,get(w,CASE_INDEX))
    put(o,24,get(w,ARM))
    put(o,32,clock)
    i = 40
    while i < 96:
        put(o,i,0)
        i = i+8
    return True

def archive_owner(o:mutbuf,w:mutbuf) -> u64:
    out_size = get(w,STDOUT_BYTES)
    err_size = get(w,STDERR_BYTES)
    if out_size > 2097152 or err_size > 65536 or get(w,RUN_REAPED) < get(w,RUN_STARTED) or get(w,OWNER_MAGIC) != TERMINAL:
        return 0
    if event_header(o,w,2,get(w,RUN_STARTED),out_size+err_size) == False:
        return 0
    put(o,40,get(w,RUN_REAPED))
    put(o,48,get(w,OWNER_MAGIC))
    put(o,56,get(w,OWNER_CODE))
    put(o,64,get(w,OWNER_STOPPED))
    put(o,72,out_size)
    put(o,80,err_size)
    put(w,STATE,13)
    return 11

def terminal_case(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(w,DOUBLE_REFERENCE) != 2:
        return finish(o,w,status)
    put(w,AFTER_CASE,status)
    if status == 1:
        put(w,CASE_MISMATCH,1)
    put(w,ARGUMENT_INDEX,0)
    put(w,LOAN_INDEX,0)
    put(w,STATE,6)
    return read_files(o,w)

def mismatch(w:mutbuf) -> u64:
    put(w,CASE_MISMATCH,1)
    if get(w,MISMATCH) == 0:
        put(w,MISMATCH,1)
        put(w,FIRST_CASE,get(w,CASE_INDEX))
        put(w,FIRST_ARM,get(w,ARM))
    return 0

def finish(o:mutbuf, w:mutbuf, status:u64) -> u64:
    if get(w,GATED) == 1 and get(w,GATE_OPEN) != 0:
        put(w,GATE_FINISH,status+1)
        return budget_event(o,w,6,get(w,GATE_OPEN)-1)
    if status == 0 and get(w,MISMATCH) != 0:
        status = 1
        put(w,CASE_INDEX,get(w,FIRST_CASE))
        put(w,ARM,get(w,FIRST_ARM))
    put(o,0,PAIR)
    put(o,8,status)
    put(o,16,get(w,CASE_COUNT))
    put(o,24,get(w,SAMPLE_COUNT))
    put(o,32,get(w,DURATIONS))
    put(o,40,get(w,CANDIDATE_NS))
    put(o,48,get(w,MEASURED_CALLS))
    put(o,56,get(w,CANDIDATE_CALLS))
    put(o,64,get(w,CASE_INDEX))
    put(o,72,get(w,ARM))
    extent = 64*get(w,SAMPLE_COUNT)
    i = 0
    while i < extent:
        put(o,80+i,get(w,SAMPLES+i))
        i = i + 8
    put(w,IO_BYTES,80+extent)
    if get(w,DOUBLE_REFERENCE) == 2:
        put(o,700000,ARCHIVE)
        put(o,700008,80+extent)
        put(o,700016,get(w,EVENT_SIZE))
        put(o,700024,get(w,EVENT_COUNT))
        return 13
    return 6
'''


def snapshot_hash():
    # Use the same HIA SHA-256 implementation as the independent digest role.
    # Relocate its small private arrays beyond the decoded JSON and case rows.
    source = sha256_source().replace('length(s)', 'n')
    source = source.replace('def sha256(s:readbuf, o:mutbuf, w:mutbuf)',
                            'def sha256(s:readbuf, w:mutbuf, base:u64, n:u64)')
    source = source.replace(' or length(o) < 32', ' or base > length(s) or n > length(s)-base')
    source = source.replace('padded_byte(s, block + i * 4 + j, padded)',
                            'padded_byte(s, block + i * 4 + j, padded, base, n)')
    source = source.replace('def padded_byte(s:readbuf, index:u64, total:u64)',
                            'def padded_byte(s:readbuf, index:u64, total:u64, base:u64, n:u64)')
    source = source.replace('byte(s, index)', 'byte(s, base + index)')
    source = source.replace('store(o, i * 4 + j,', 'store(w, 1088 + i * 4 + j,')
    return renamed(source, 'pair_hash_', scratch=4096)


def program():
    magic = dict(CONTROL=b'HIAEPL01', BOTH_CONTROL=b'HIAEPL02', ARCHIVE_CONTROL=b'HIAEPL03', GATED_CONTROL=b'HIAEPL04', BUDGET_RESULT=b'HIAEBRS1', BUDGET_EVENT=b'HIAEPGT1', ARCHIVE=b'HIAEMT01', EVENT=b'HIAEEV01', WORKLOAD=b'HIAEVW01', BATCH=b'HIAEBT01', REFERENCE=b'HIASPR01',
                 PLAN=b'HIAEVC01', SUPERVISE=b'HIADRS01', RUN=b'HIADRX02', TERMINAL=b'HIADRT01',
                 RECEIPT=b'HIADRR02', PAIR=b'HIAEPM01')
    values = {name: int.from_bytes(value, 'little') for name, value in magic.items()}
    values.update({name: G + offset for name, offset in STATE_FIELDS.items()})
    values.update(P=P, ROWS=ROWS, SAMPLES=SAMPLES, LOAN=LOAN, DIGESTS=DIGESTS, MAX=LIMIT, BOOL=ABI_SCALAR_IDS['bool'], U32=ABI_SCALAR_IDS['u32'])
    keys = (*FIELDS, 'schema', 'status', 'values', 'buffers', 'argument', 'kind', 'sha256')
    values.update({'KEY_'+name.upper(): index for index,name in enumerate(keys,1)})
    policy = re.sub(r'\b('+'|'.join(values)+r')\b', lambda m: str(values[m[0]]), POLICY)
    case = evaluate_case()
    if case.count(key_table(FIELDS)) != 1:
        raise ValueError('HIA Evaluate case key table changed')
    case = case.replace(key_table(FIELDS), key_table(keys))
    schema = enum_reader('ledger_shape', [(name,int(supports_feature(name, 'recursive_chain')))
                                         for name in PRIMITIVE_PROFILES])
    literals = [literal_match(name,text) for name,text in (('returned_status','returned'),
                ('trapped_status','trapped'), ('readbuf_kind','readbuf'), ('mutbuf_kind','mutbuf'))]
    return '\n'.join((policy,case,schema,*literals,snapshot_hash()))


def pair_document():
    """Share identical constant returns so the full checked policy fits the bootstrap CFG."""
    from hepta.hia_program import verify_program

    result = document(program(), SOURCE.stem)
    for fn in result['functions']:
        targets, duplicates = {}, {}
        for block in fn['blocks']:
            ops, term = block['ops'], block['term']
            if block['id'] == fn['entry'] or term['op'] != 'ret' or len(ops) not in (1, 2):
                continue
            first = ops[0]
            if first['op'] != 'const' or first['args'] or len(first['out']) != 1:
                continue
            value = first['out'][0]
            cast = None
            if len(ops) == 2:
                conversion = ops[1]
                if (conversion['op'] != 'int.cast' or conversion['attrs'] != {'mode': 'wrap'}
                        or conversion['args'] != [value['name']] or len(conversion['out']) != 1):
                    continue
                value = conversion['out'][0]
                cast = value['type']
            if term['values'] != [value['name']]:
                continue
            # The target has the same resource/argument types and executes
            # the same operations. Every incoming edge retains all arguments.
            key = (tuple(p['type'] for p in block['params']), first['out'][0]['type'],
                   first['attrs']['value'], cast)
            previous = targets.setdefault(key, block['id'])
            if previous != block['id']:
                duplicates[block['id']] = previous
        for block in fn['blocks']:
            term = block['term']
            edges = [term] if term['op'] == 'jump' else [term['then'], term['else']] if term['op'] == 'branch' else []
            for edge in edges:
                edge['target'] = duplicates.get(edge['target'], edge['target'])
        fn['blocks'] = [block for block in fn['blocks'] if block['id'] not in duplicates]
    verify_program(result)
    return result


def packer_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter, document as packer, elf_header
    source = Path(ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-evaluate-pair-') as directory:
        adapter, places, _ = adapter_layout(Path(directory), ADAPTER, source, {'plan': 'pair_call_hole'})
    holes = (places['plan'],)
    head = elf_header()
    result = packer(magic=PACK_MAGIC, module=PACKER.stem,
                    image_template=(head+adapter, (len(head)+holes[0],)))
    return bind_adapter(result, source, adapter, holes)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(pair_document()), encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()), encoding='utf-8')
