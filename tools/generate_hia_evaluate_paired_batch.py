"""Build the HIA native measurement loop over admitted workload and reference bytes."""

from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_identity_native import ABI_SCALAR_IDS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_evaluate_case import source_program as evaluate_case

SOURCE = Path('examples/hia_bootstrap/evaluate_paired_batch.hepta')
PACKER = SOURCE.with_name('evaluate_paired_batch_packer.hepta')
ADAPTER = 'tools/hia_evaluate_paired_batch.S'
PACK_MAGIC = int.from_bytes(b'HIAEPP01', 'little')
# The JSON decoder uses the lower 64 MiB; retained plans and observations are private.
G = 64 << 20
P = G + 4096
ROWS = G + 16384
SAMPLES = G + 49152
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
}

# File descriptors 3..8 carry [ABI, workload], baseline, candidate, native
# supervisor, agreed reference batch, and immutable memory/deadline control.
# Scratch fds 16..23 are distinct per-argument snapshot files; fd 24 receives
# the real supervisor's terminal record. All decisions return a syscall port.
POLICY = '''
def measure(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    state = get(w, STATE)
    if state == 0:
        if length(s) != 24 or read_word(s, 0) != CONTROL:
            return 0
        m = read_word(s, 8)
        d = read_word(s, 16)
        if m < 67108864 or m > 4294967296 or d == 0:
            return 0
        if get(w,ARTIFACT_BYTES) == 0 or get(w,ARTIFACT_BYTES) > 67108864 or get(w,CANDIDATE_BYTES) == 0 or get(w,CANDIDATE_BYTES) > 67108864:
            return 0
        put(w, MEMORY_LIMIT, m)
        put(w, DEADLINE, d)
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
        return observe(s, o, w)
    if state == 6:
        return read_files(o, w)
    if state == 7:
        return compare_file(s, o, w)
    return 0

def retain_shapes(s:readbuf, o:mutbuf, w:mutbuf, count:u64) -> u64:
    signatures = first(w, 64)
    cases = lookup(w, next(w, signatures), KEY_CASES)
    case = first(w, cases)
    i = 0
    while i < count:
        size = plan_named_case(s, o, w, signatures, case)
        if size < 80 or size > 6224:
            return 0
        row = ROWS + 48*i
        put(w,row+24,case)
        put(w,row+32,choose(get(o,24) == 0,0,8))
        put(w,row+40,get(o,32))
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
        row = ROWS + 48*i
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
    put(w, STATE, 3)
    return 1

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
        elif (get(w, ROWS+48*index+16) != 0) == (traps != 0):
            put(w, CASE_INDEX, index)
            put(w, ARM, arm)
            put(w, TRAP_PHASE, traps)
            return prepare_case(s, o, w, index)
        else:
            index = index + 1
    return finish(o, w, 0)

def prepare_case(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:
    signatures = first(w, 64)
    case = get(w,ROWS+48*index+24)
    size = plan_named_case(s, o, w, signatures, case)
    if size < 80 or size > 6224 or get(o, 0) != PLAN:
        return 0
    i = 0
    while i < size:
        put(w, P+i, get(o, i))
        i = i + 8
    row = ROWS + 48*index
    has_value = get(w, row+16) == 0 and get(o, 24) != 0
    if get(w, row+8) != 144+choose(has_value, 8, 0)+get(o, 32):
        return 0
    put(w, EXPECTED_SNAPSHOT, get(w, row)+144+choose(has_value, 8, 0))
    put(w, ARGUMENT_INDEX, 0)
    put(w, LOAN_INDEX, 0)
    put(w, STATE, 4)
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
        return finish(o, w, 2)
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
        return finish(o,w,4)
    if stopped != 0 or code == MAX-23:
        return finish(o,w,2)
    arm = get(w,ARM)
    index = get(w,CASE_INDEX)
    row = ROWS + 48*index
    expected = get(w,row+16)
    sample = SAMPLES + 64*get(w,SAMPLE_COUNT)
    put(w,sample,index)
    put(w,sample+8,arm)
    put(w,sample+16,expected)
    put(w,sample+24,code)
    put(w,SAMPLE_COUNT,get(w,SAMPLE_COUNT)+1)
    if code == MAX-5:
        if actual != 0:
            return finish(o,w,4)
        if expected == 0:
            return finish(o,w,1)
    else:
        if code != 0:
            return finish(o,w,3)
        if actual != 32 or get(w,CALL_MAGIC) != RECEIPT or get(w,VARIATION) > 1:
            return finish(o,w,4)
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
    put(w,CASE_INDEX,get(w,CASE_INDEX)+1)
    put(w,STATE,3)
    return 1

def compare_file(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = get(w,EXPECTED_SNAPSHOT)
    size = get(w,IO_BYTES)
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
    return read_files(o,w)

def mismatch(w:mutbuf) -> u64:
    if get(w,MISMATCH) == 0:
        put(w,MISMATCH,1)
        put(w,FIRST_CASE,get(w,CASE_INDEX))
        put(w,FIRST_ARM,get(w,ARM))
    return 0

def finish(o:mutbuf, w:mutbuf, status:u64) -> u64:
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
    return 6
'''


def program():
    magic = dict(CONTROL=b'HIAEPL01', WORKLOAD=b'HIAEVW01', BATCH=b'HIAEBT01', REFERENCE=b'HIASPR01',
                 PLAN=b'HIAEVC01', SUPERVISE=b'HIADRS01', RUN=b'HIADRX02', TERMINAL=b'HIADRT01',
                 RECEIPT=b'HIADRR02', PAIR=b'HIAEPM01')
    values = {name: int.from_bytes(value, 'little') for name, value in magic.items()}
    values.update({name: G + offset for name, offset in STATE_FIELDS.items()})
    values.update(P=P, ROWS=ROWS, SAMPLES=SAMPLES, LOAN=LOAN, MAX=LIMIT, KEY_CASES=11, BOOL=ABI_SCALAR_IDS['bool'])
    policy = re.sub(r'\b('+'|'.join(values)+r')\b', lambda m: str(values[m[0]]), POLICY)
    return policy + '\n' + evaluate_case()


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
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()), encoding='utf-8')
