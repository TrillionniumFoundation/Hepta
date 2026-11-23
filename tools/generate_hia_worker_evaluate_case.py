"""Author the Evaluate case plan from retained ABI and workload bytes."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_buffers import PROFILE
from hepta.hia_agent_identity_native import ABI_SCALAR_IDS
from tools.generate_hia_agent_identity import source_program as identity
from tools.generate_hia_agent_snapshot_json import ADAPTER as SNAPSHOT
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_artifact_authority import source_program as artifact_authority
from tools.generate_hia_worker_context_workload import POLICY as WORKLOAD
from tools.generate_hia_worker_emit_verification import POLICY as VERIFICATION, key_table
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_case.hepta')
FIELDS = ('params', 'returns', 'abi', 'max_buffer_bytes', 'function', 'arguments', 'expected',
          'bytes_hex', 'byte_length', 'fill_byte', 'cases', 'warmup_iterations', 'repetitions')
TYPES = (*ABI_SCALAR_IDS, 'readbuf', 'mutbuf')
# The admitted workload and its separately bounded ABI are carried together.
CASE_INPUT_BYTES = (16 << 20) + 3
INPUT_BYTES = (16 << 20) + 240
CASE_BYTES = 80 + 128 * 48

POLICY = r'''
# Input is [retained signatures, one admitted case]. The extent and spans below
# name data, not descriptors. Only the runner may supply distinct owned FDs.
# Refusals distinguish absent entry, argument shape/type, ABI, and snapshot
# descriptor/extent. No output marked ready is emitted on a refusal.
def evaluate_case(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_BYTES or length(o) < CASE_BYTES or length(w) < 4096:
        return INVALID
    magic = read_word(s, 0)
    if magic == AUTHORITY_REQUEST:
        return authorize_evaluation(s, o)
    if length(s) > CASE_INPUT_BYTES:
        return INVALID
    if magic == RUNNER_BINDING:
        return bind_runner(s, o)
    if magic == SNAPSHOT_BINDING:
        return materialize_snapshot(s, o)
    put(o, 48, choose(length(w) >= 25165824, 262144, 32768))
    put(o, 56, 24)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return INVALID
    signatures = first(w, 64)
    case = next(w, signatures)
    if is_object(w, signatures) == False or is_object(w, case) == False:
        return INVALID
    cases = lookup(w, case, K_cases)
    if cases != NONE:
        return plan_workload(s, o, w, signatures, case, cases)
    return plan_named_case(s, o, w, signatures, case)

# The two ABI maps are canonical bytes from admitted Store metadata. The
# presence and identity of the pinned baseline come from the retained Context.
# Preserve the original refusal precedence before reading workload or running.
def authorize_evaluation(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 120:
        return INVALID
    baseline_kind = read_word(s, 8)
    candidate_kind = read_word(s, 16)
    baseline_abi = read_word(s, 24)
    candidate_abi = read_word(s, 32)
    pinned = read_word(s, 40)
    if baseline_kind < 2 or baseline_kind > 32 or candidate_kind < 2 or candidate_kind > 32:
        return INVALID
    if baseline_abi < 2 or baseline_abi > 8388608 or candidate_abi < 2 or candidate_abi > 8388608:
        return INVALID
    if pinned != 0 and pinned != 64:
        return INVALID
    candidate_at = 48 + baseline_kind
    abi_at = candidate_at + candidate_kind
    baseline_at = abi_at + baseline_abi + candidate_abi
    if length(s) != baseline_at + pinned + 64:
        return INVALID
    if valid_hex(s, baseline_at + pinned, 64) == False:
        return INVALID
    if pinned != 0 and valid_hex(s, baseline_at, 64) == False:
        return INVALID
    if baseline_kind != 8 or read_word(s, 48) != SHARED_KIND:
        return authority_reply(o, 0)
    if candidate_kind != 8 or read_word(s, candidate_at) != SHARED_KIND:
        return authority_reply(o, 1)
    if baseline_abi != candidate_abi or equal_bytes(s, abi_at, abi_at + baseline_abi, baseline_abi) == False:
        return authority_reply(o, 3)
    if pinned == 0:
        return authority_reply(o, 7)
    if equal_bytes(s, baseline_at, baseline_at + 64, 64) == False:
        return authority_reply(o, 15)
    return authority_reply(o, 31)

def authority_reply(o:mutbuf, admitted:u64) -> u64:
    put(o, 0, AUTHORITY_RESULT)
    put(o, 8, admitted)
    return 16

def equal_bytes(s:readbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index + 8 <= size:
        if read_word(s, left + index) != read_word(s, right + index):
            return False
        index = index + 8
    while index < size:
        if byte(s, left + index) != byte(s, right + index):
            return False
        index = index + 1
    return True

def plan_named_case(s:readbuf, o:mutbuf, w:mutbuf, signatures:u64, case:u64) -> u64:
    name = lookup(w, case, K_function)
    if name == NONE or get(w, name) != 4:
        return INVALID
    signature = find_signature(w, signatures, name)
    if signature == NONE:
        return refusal(o, 1)
    return plan_case(s, o, w, signature, case, name)

# Input is [retained signatures, schema-admitted workload]. A single decode
# keeps all offsets in the admitted packet, and validates in workload order.
# The first CASE_BYTES output bytes are temporary single-case scratch. Successful
# workload rows are compacted only after all cases pass the same ABI policy.
def plan_workload(s:readbuf, o:mutbuf, w:mutbuf, signatures:u64, workload:u64, cases:u64) -> u64:
    if get(w, cases) != 5:
        return INVALID
    count = get(w, cases + 32)
    warmup = uint(s, w, lookup(w, workload, K_warmup_iterations), 100)
    repetitions = uint(s, w, lookup(w, workload, K_repetitions), 10000)
    if count < 1 or count > 512 or length(o) < CASE_BYTES + 64 * count or warmup == NONE or repetitions == NONE or repetitions == 0:
        return INVALID
    case = first(w, cases)
    index = 0
    total = 0
    while index < count:
        if is_object(w, case) == False:
            return INVALID
        result = plan_named_case(s, o, w, signatures, case)
        if result == INVALID:
            return INVALID
        if result == 16:
            reason = get(o, 8)
            return workload_rejection(o, reason, index)
        size = get(o, 32)
        total = total + size
        if total > 33554432:
            return workload_rejection(o, 9, index)
        at = CASE_BYTES + index * 64
        span(w, o, case, at)
        put(o, at + 16, get(o, 48))
        put(o, at + 24, get(o, 56))
        put(o, at + 32, get(o, 64))
        put(o, at + 40, get(o, 72))
        put(o, at + 48, size)
        put(o, at + 56, get(o, 40))
        case = next(w, case)
        index = index + 1
    if case != NONE:
        return INVALID
    row = 0
    while row < count * 64:
        put(o, 48 + row, get(o, CASE_BYTES + row))
        row = row + 8
    put(o, 0, WORKLOAD_PLAN)
    put(o, 8, 0)
    put(o, 16, count)
    put(o, 24, total)
    put(o, 32, warmup)
    put(o, 40, repetitions)
    return 48 + 64 * count

def workload_rejection(o:mutbuf, reason:u64, index:u64) -> u64:
    put(o, 0, WORKLOAD_PLAN)
    put(o, 8, reason)
    put(o, 16, index)
    return 24

def find_signature(w:mutbuf, signatures:u64, name:u64) -> u64:
    width = get(w, name + 32)
    offset = get(w, name + 24)
    row = first(w, signatures)
    while row != NONE:
        if get(w, row + 48) == width:
            key = get(w, row + 40)
            n = 0
            while n < width and byte(w, offset + n) == byte(w, key + n):
                n = n + 1
            if n == width:
                return row
        row = next(w, row)
    return NONE

def plan_case(s:readbuf, o:mutbuf, w:mutbuf, signature:u64, case:u64, name:u64) -> u64:
    if is_object(w, signature) == False:
        return INVALID
    params = lookup(w, signature, K_params)
    returns = lookup(w, signature, K_returns)
    args = lookup(w, case, K_arguments)
    if params == NONE or get(w, params) != 5 or returns == NONE or get(w, returns) != 5:
        return INVALID
    count = get(w, params + 32)
    if count > 128 or get(w, returns + 32) > 1:
        return INVALID
    if args == NONE or get(w, args) != 5 or get(w, args + 32) != count:
        return refusal(o, 10)
    abi = lookup(w, signature, K_abi)
    extent = NONE
    result = type_role(w, first(w, returns))
    if get(w, returns + 32) == 1 and (result < 1 or result > UNIT):
        return INVALID
    if abi != NONE:
        if get(w, abi) != 4 or borrowed_profile(w, get(w, abi + 24), get(w, abi + 32)) == 0:
            return refusal(o, 3)
        extent = uint(s, w, lookup(w, signature, K_max_buffer_bytes), 1048576)
        if extent == 0 or extent == NONE or result != U32:
            return INVALID
        result = 256
    expected = lookup(w, case, K_expected)
    span(w, o, name, 48)
    if expected == NONE:
        put(o, 64, 0)
        put(o, 72, 0)
    else:
        span(w, o, expected, 64)
    put(o, 16, count)
    put(o, 24, result)
    return plan_arguments(s, o, w, first(w, params), first(w, args), extent)

def plan_arguments(s:readbuf, o:mutbuf, w:mutbuf, typ:u64, value:u64, extent:u64) -> u64:
    index = 0
    total = 0
    loans = 0
    while typ != NONE:
        role = type_role(w, typ)
        at = 80 + index * 48
        if role == READBUF or role == MUTBUF:
            if extent == NONE or loans == 8:
                return refusal(o, 3)
            if is_object(w, value) == False:
                return refusal(o, 4)
            size = snapshot(s, w, value)
            if size >= NONE - 2:
                return refusal(o, 5 + NONE - size)
            if size > extent:
                return refusal(o, 8)
            if snapshot_plan(s, o, w, value, at, size, role - UNIT) == 0:
                return INVALID
            total = total + size
            loans = loans + 1
        else:
            if scalar_plan(s, o, w, value, at, role) == 0:
                return refusal(o, 2)
        typ = next(w, typ)
        value = next(w, value)
        index = index + 1
    if extent != NONE and loans == 0:
        return refusal(o, 3)
    put(o, 0, PLAN)
    put(o, 8, 0)
    put(o, 32, total)
    put(o, 40, loans)
    return 80 + 48 * index

def snapshot_plan(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, size:u64, role:u64) -> u64:
    put(o, at, role)
    put(o, at + 8, size)
    hex = lookup(w, node, K_bytes_hex)
    if hex == NONE:
        put(o, at + 16, 2)
        put(o, at + 24, uint(s, w, lookup(w, node, K_fill_byte), 255))
        put(o, at + 32, 0)
        put(o, at + 40, 0)
    else:
        if get(w, hex + 64) != size * 2 + 2:
            return 0
        put(o, at + 16, 1)
        put(o, at + 24, 0)
        put(o, at + 32, get(w, hex + 56) + 1)
        put(o, at + 40, size * 2)
    return 1

def scalar_plan(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, role:u64) -> u64:
    kind = get(w, node)
    word = 0
    if kind == 1 or kind == 2:
        word = kind - 1
        kind = 2
    elif kind == 0:
        kind = 1
    elif kind == 3:
        start = get(w, node + 24)
        end = start + get(w, node + 32)
        if byte(s, start) == 45:
            start = start + 1
            kind = 4
        while start < end:
            point = byte(s, start)
            if point < 48 or point > 57 or word > 1844674407370955161 or (word == 1844674407370955161 and point > 53):
                return 0
            word = word * 10 + point - 48
            start = start + 1
        if word == 0:
            kind = 3
    else:
        return 0
    if abi_scalar_valid(role, kind, word) == 0:
        return 0
    put(o, at, 0)
    put(o, at + 8, choose(kind == 4, 0 - word, word))
    put(o, at + 16, 0)
    put(o, at + 24, 0)
    put(o, at + 32, 0)
    put(o, at + 40, 0)
    return 1

# Owned effects hand the formatter PID/limits, opened artifact and loan
# descriptors, and the already admitted case plan and original sealed JSON.
# The runner still authenticates the PID and fstat/seals and isolates the call.
def bind_runner(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 169:
        return INVALID
    parent = read_word(s, 8)
    memory = read_word(s, 16)
    cpu = read_word(s, 24)
    artifact = read_word(s, 32)
    artifact_size = read_word(s, 40)
    warmup = read_word(s, 48)
    runs = read_word(s, 56)
    descriptors = read_word(s, 64)
    if parent == 0 or parent > 2147483647 or memory < 67108864 or memory > 4294967296:
        return INVALID
    if cpu == 0 or cpu > 86400 or valid_descriptor(artifact) == False or artifact_size == 0 or artifact_size > 67108864:
        return INVALID
    if warmup > 100 or runs == 0 or runs > 10000 or descriptors > 8:
        return INVALID
    plan = 80 + 8 * descriptors
    plan_size = read_word(s, 72)
    if plan > length(s) or plan_size < 80 or plan_size >= length(s) - plan:
        return INVALID
    if read_word(s, plan) != PLAN or read_word(s, plan + 8) != 0 or read_word(s, plan + 40) != descriptors:
        return INVALID
    count = read_word(s, plan + 16)
    role = read_word(s, plan + 24)
    if count > 128 or plan_size != 80 + 48 * count or (role > UNIT and role != 256):
        return INVALID
    if (role == 256) != (descriptors != 0):
        return INVALID
    limit = length(s) - plan - plan_size
    name_at = read_word(s, plan + 48)
    name_size = read_word(s, plan + 56)
    if name_at >= limit or name_size < 3 or name_size > 514 or name_size > limit - name_at:
        return INVALID
    name = plan + plan_size + name_at
    if byte(s, name) != 34 or byte(s, name + name_size - 1) != 34:
        return INVALID
    descriptor = 0
    while descriptor < descriptors:
        fd = read_word(s, 80 + 8 * descriptor)
        if valid_descriptor(fd) == False or fd == artifact:
            return INVALID
        n = 0
        while n < descriptor:
            if fd == read_word(s, 80 + 8 * n):
                return INVALID
            n = n + 1
        descriptor = descriptor + 1
    put(o, 0, RUNNER_REQUEST)
    at = 8
    while at <= 40:
        put(o, at, read_word(s, at))
        at = at + 8
    put(o, 48, count + descriptors)
    put(o, 56, descriptors)
    put(o, 64, name_size - 2)
    put(o, 72, warmup)
    put(o, 80, runs)
    expected = read_word(s, plan + 64)
    expected_size = read_word(s, plan + 72)
    if expected > limit or expected_size > limit - expected:
        return INVALID
    put(o, 88, choose(expected_size != 0, 1, 0))
    put(o, 96, direct_return_mask(role))
    if bind_argument_words(s, o, plan, count, descriptors) == False:
        return INVALID
    name_out = 104 + 8 * (count + descriptors) + 32 * descriptors
    index = 1
    while index < name_size - 1:
        point = byte(s, name + index)
        if point < 33 or point >= 127 or point == 92 or point == 34:
            return INVALID
        store(o, name_out + index - 1, point)
        index = index + 1
    return name_out + name_size - 2

def bind_argument_words(s:readbuf, o:mutbuf, plan:u64, count:u64, descriptors:u64) -> bool:
    word = 0
    loan = 0
    index = 0
    slots = 104 + 8 * (count + descriptors)
    total = 0
    while index < count:
        row = plan + 80 + 48 * index
        role = read_word(s, row)
        value = read_word(s, row + 8)
        if role == 0:
            put(o, 104 + 8 * word, value)
            word = word + 1
        else:
            if role > 2 or loan >= descriptors or value > 1048576:
                return False
            put(o, 104 + 8 * word, 0)
            put(o, 112 + 8 * word, value)
            slot = slots + 32 * loan
            put(o, slot, word)
            put(o, slot + 8, read_word(s, 80 + 8 * loan))
            put(o, slot + 16, value)
            put(o, slot + 24, choose(role == 1, 1, 0))
            word = word + 2
            loan = loan + 1
            total = total + value
        index = index + 1
    return loan == descriptors and total == read_word(s, plan + 32)

# Return snapshot bytes, not an open fd. The owner creates a distinct
# backing file per loan and checks its final physical extent independently.
def materialize_snapshot(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 105 or read_word(s, 24) != PLAN or read_word(s, 32) != 0:
        return INVALID
    index = read_word(s, 8)
    plan_size = read_word(s, 16)
    count = read_word(s, 40)
    if count > 128 or index >= count or plan_size != 80 + 48 * count or plan_size >= length(s) - 24:
        return INVALID
    row = 104 + index * 48
    role = read_word(s, row)
    size = read_word(s, row + 8)
    kind = read_word(s, row + 16)
    fill = read_word(s, row + 24)
    offset = read_word(s, row + 32)
    width = read_word(s, row + 40)
    if role < 1 or role > 2 or size > 1048576 or (kind != 1 and kind != 2):
        return INVALID
    physical = choose(size == 0, 1, size)
    if length(o) < 32 + physical:
        return INVALID
    if kind == 1:
        start = 24 + plan_size
        usable = length(s) - start
        if fill != 0 or offset < 1 or offset >= usable or width != 2 * size or width >= usable - offset:
            return INVALID
        start = start + offset
        if byte(s, start - 1) != 34 or byte(s, start + width) != 34:
            return INVALID
        at = 0
        while at < size:
            high = snapshot_nibble(byte(s, start + 2 * at))
            low = snapshot_nibble(byte(s, start + 2 * at + 1))
            if high > 15 or low > 15:
                return INVALID
            store(o, 32 + at, (high << 4) | low)
            at = at + 1
    else:
        if fill > 255 or offset != 0 or width != 0:
            return INVALID
        at = 0
        while at < size:
            store(o, 32 + at, fill)
            at = at + 1
    if size == 0:
        store(o, 32, 0)
    put(o, 0, SNAPSHOT_BYTES)
    put(o, 8, index)
    put(o, 16, role)
    put(o, 24, size)
    return 32 + physical

def valid_descriptor(fd:u64) -> bool:
    return fd >= 3 and fd <= 2147483647

def next(w:mutbuf, node:u64) -> u64:
    index = get(w, node + 16)
    return choose(index == NONE, NONE, 64 + index * 72)

def first(w:mutbuf, list:u64) -> u64:
    index = get(w, list + 24)
    return choose(index == NONE, NONE, 64 + index * 72)

def type_role(w:mutbuf, node:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return 0
    return abi_role(w, get(w, node + 24), get(w, node + 32))

def refusal(o:mutbuf, reason:u64) -> u64:
    put(o, 0, PLAN)
    put(o, 8, reason)
    return 16
'''


def source_program():
    constants = {f'K_{name}': index for index, name in enumerate(FIELDS, 1)}
    constants.update(INVALID=4294967293, NONE=(1 << 64) - 1,
                     PLAN=int.from_bytes(b'HIAEVC01', 'little'),
                     WORKLOAD_PLAN=int.from_bytes(b'HIAEVW01', 'little'), INPUT_BYTES=INPUT_BYTES,
                     CASE_INPUT_BYTES=CASE_INPUT_BYTES, CASE_BYTES=CASE_BYTES,
                     AUTHORITY_REQUEST=int.from_bytes(b'HIAEVA01', 'little'),
                     AUTHORITY_RESULT=int.from_bytes(b'HIAEVA02', 'little'),
                     SHARED_KIND=int.from_bytes(b'"shared"', 'little'),
                     RUNNER_BINDING=int.from_bytes(b'HIAEVR01', 'little'),
                     RUNNER_REQUEST=int.from_bytes(b'HIADRX02', 'little'),
                     SNAPSHOT_BINDING=int.from_bytes(b'HIAEVB01', 'little'),
                     SNAPSHOT_BYTES=int.from_bytes(b'HIAEVS01', 'little'),
                     UNIT=ABI_SCALAR_IDS['unit'], U32=ABI_SCALAR_IDS['u32'],
                     READBUF=len(TYPES) - 1, MUTBUF=len(TYPES))
    snapshot = function(WORKLOAD, 'snapshot')
    snapshot = re.sub(r'lookup\(w, row, ([789])\)',
                      lambda match: 'lookup(w, row, K_' + FIELDS[int(match[1])] + ')', snapshot)
    policy = '\n'.join((
        POLICY, snapshot, function(WORKLOAD, 'uint'), function(SNAPSHOT, 'snapshot_nibble'),
        *(function(VERIFICATION, name) for name in ('is_object', 'span')),
        *(function(identity(), name) for name in ('abi_scalar_valid', 'scalar_abi_type', 'direct_return_mask', 'read_word')),
        function(artifact_authority(), 'valid_hex'),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0], key_table(FIELDS),
        comparison_table('abi_role', TYPES), comparison_table('borrowed_profile', (PROFILE,)),
    ))
    decoder = json_decoder(wire_spans=True)
    guard = 'length(s) > 8388608'
    if decoder.count(guard) != 2:
        raise ValueError('Evaluate decoder input bounds changed')
    return (re.sub(r'\b(' + '|'.join(constants) + r')\b',
                   lambda match: str(constants[match[0]]), policy)
            + '\n' + decoder.replace(guard, f'length(s) > {INPUT_BYTES}'))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
