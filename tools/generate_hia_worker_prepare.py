"""Author the native provider's byte-preserving Worker request encoder.

The transport supplies canonical JSON fragments after schema, catalog and host
policy checks. HIA owns the envelope, hashes and durable job key. It must not
parse and reprint numbers: the existing transport's exact bytes are stored
as part of the durable job identity.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import WorkerRequestBuilder, worker_hash_program


SOURCE_PATH = 'examples/hia_bootstrap/worker_prepare.hepta'
INPUT_MAGIC = b'HIAWPR01'
OUTPUT_MAGIC = b'HIAWPO01'
JOB_INPUT_MAGIC = b'HIAJID01'
JOB_OUTPUT_MAGIC = b'HIAJDO01'
REUSE_INPUT_MAGIC = b'HIAJRE01'
REUSE_OUTPUT_MAGIC = b'HIAJRO01'
SCOPE_INPUT_MAGIC = b'HIASCO01'
SCOPE_OUTPUT_MAGIC = b'HIASCR01'
TRANSITION_INPUT_MAGIC = b'HIAJTR01'
TRANSITION_OUTPUT_MAGIC = b'HIAJTO01'
HTTP_AUTH_INPUT = b'HIAHAT01'
HTTP_AUTH_OUTPUT = b'HIAHAO01'
LAUNCH_ACK_INPUT = b'HIAJAK01'
LAUNCH_ACK_OUTPUT = b'HIAJAO01'
JOB_POLL_INPUT = b'HIAJPL01'
JOB_POLL_OUTPUT = b'HIAJPO01'
JOB_TERMINAL_INPUT = b'HIAJTS01'
JOB_TERMINAL_OUTPUT = b'HIAJTV01'
CAPTURE_POLICY_INPUT = b'HIACPQ01'
CAPTURE_POLICY_OUTPUT = b'HIACPV01'
JOB_LIFECYCLE_INPUT = b'HIAJSS01'
JOB_LIFECYCLE_OUTPUT = b'HIAJSV01'

SOURCE = '''
def prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n < 8 or n > 8388608 or length(w) < 4432:
        return 4294967293
    magic = word_load(s, 0)
    if magic == JOB_INPUT_MAGIC:
        return job_identity(s, o, w)
    if magic == REUSE_INPUT_MAGIC:
        return job_reuse(s, o)
    if magic == SCOPE_INPUT_MAGIC:
        return session_scope(s, o)
    if magic == TRANSITION_INPUT_MAGIC:
        return durable_transition(s, o)
    if magic == HTTP_AUTH_INPUT:
        return http_auth(s, o, w)
    if magic == LAUNCH_ACK_INPUT:
        return launch_ack(s, o)
    if magic == JOB_POLL_INPUT:
        return job_poll(s, o)
    if magic == JOB_TERMINAL_INPUT:
        return job_terminal_state(s, o)
    if magic == CAPTURE_POLICY_INPUT:
        return capture_policy(s, o)
    if magic == JOB_LIFECYCLE_INPUT:
        return job_lifecycle(s, o)
    if n < 112 or magic != INPUT_MAGIC:
        return 4294967293
    if length(o) < 524552:
        return 4294967294
    start = 112
    field = 0
    while field < 5:
        size = word_load(s, 8 + field * 8)
        if size > 524288 or size > n - start:
            return 4294967293
        if field < 3:
            if size < 2:
                return 4294967293
            if byte(s, start) != 123 or byte(s, start + size - 1) != 125:
                return 4294967293
        elif field == 3 or size != 0:
            if size < 2:
                return 4294967293
            if byte(s, start) != 34 or byte(s, start + size - 1) != 34:
                return 4294967293
        word_store(w, 256 + field * 16, start)
        word_store(w, 264 + field * 16, size)
        start = start + size
        field = field + 1
    if start != n:
        return 4294967293
    index = 48
    while index < 112:
        value = byte(s, index)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return 4294967293
        index = index + 1
    # Bound both the final envelope and the temporary key preimage.
    size = word_load(w, 296) + word_load(w, 312)
    if size > MAX_FRAGMENTS or word_load(w, 312) + word_load(w, 328) > 524288:
        return 4294967294
    count = append_field(s, o, w, 0, 0)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    count = append_field(s, o, w, 0, 1)
    if digest(o, w, count, 64) == 0:
        return 4294967293
    count = envelope_prefix(s, o, w, 0)
    count = envelope_tail(s, o, w, count)
    if digest(o, w, count, 128) == 0:
        return 4294967293
    if word_load(w, 328) == 0:
        count = readonly_start(o, 0)
        count = saved(w, o, count, 128, 64)
        count = readonly_tool(o, count)
    else:
        count = mutation_start(o, 0)
        count = append_field(s, o, w, count, 4)
        count = mutation_tool(o, count)
    count = append_field(s, o, w, count, 3)
    count = close(o, count)
    if digest(o, w, count, 192) == 0:
        return 4294967293
    count = envelope_prefix(s, o, w, 264)
    count = request_member(o, count)
    count = saved(w, o, count, 128, 64)
    count = envelope_tail(s, o, w, count)
    store(o, count, 10)
    word_store(o, 0, OUTPUT_MAGIC)
    saved(w, o, 8, 0, 256)
    return count + 1

def job_lifecycle(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 80 or length(o) < 16:
        return 4294967293
    owner = word_load(s, 8)
    incarnation = word_load(s, 16)
    witness = word_load(s, 24)
    process = word_load(s, 32)
    exited = word_load(s, 40)
    success = word_load(s, 48)
    loaded_size = word_load(s, 56)
    active_size = word_load(s, 64)
    sub_size = word_load(s, 72)
    if owner > 1 or incarnation > 1 or witness > 1 or process > 2 or exited > 1 or success > 1:
        return 4294967293
    if loaded_size > 128 or active_size > 128 or sub_size > 128:
        return 4294967293
    if length(s) != 80 + loaded_size + active_size + sub_size:
        return 4294967293
    state = lifecycle_state(s, owner, incarnation, witness, process, exited, success,
                            loaded_size, active_size, sub_size)
    word_store(o, 0, JOB_LIFECYCLE_OUTPUT)
    word_store(o, 8, state)
    return 16

def lifecycle_state(s:readbuf, owner:u64, incarnation:u64, witness:u64, process:u64,
                    exited:u64, success:u64, loaded_size:u64, active_size:u64, sub_size:u64) -> u64:
    if owner == 0:
        return 1
    missing = loaded_size == 9 and word_load(s, 80) == NOT_FOUND_HEAD and byte(s, 88) == 100
    if missing == False and incarnation == 0:
        return 2
    active_at = 80 + loaded_size
    sub_at = active_at + active_size
    active = active_size == 6 and lifecycle_text(s, active_at, 6, ACTIVE_WORD)
    activating = active_size == 10 and word_load(s, active_at) == ACTIVATING_HEAD and lifecycle_text(s, active_at + 8, 2, NG_TAIL)
    inactive_sub = sub_size == 6 and lifecycle_text(s, sub_at, 6, EXITED_WORD)
    dead = sub_size == 4 and lifecycle_text(s, sub_at, 4, DEAD_WORD)
    if (active or activating) and inactive_sub == False and dead == False:
        return choose(process == 1, 4, 3)
    if active_size == 6 and lifecycle_text(s, active_at, 6, FAILED_WORD):
        return choose(witness != 0, 5, 6)
    if active and inactive_sub:
        if witness != 0:
            return 5
        if exited != 0:
            return choose(success != 0, 7, 8)
        return 9
    if missing:
        return choose(witness != 0, 10, 11)
    return choose(witness != 0, 12, 13)

def lifecycle_text(s:readbuf, at:u64, size:u64, word:u64) -> bool:
    index = 0
    while index < size:
        if byte(s, at + index) != ((word >> (index * 8)) & 255):
            return False
        index = index + 1
    return True

def capture_policy(s:readbuf, o:mutbuf) -> u64:
    n = length(s)
    if n < 40 or length(o) < 16:
        return 4294967293
    same_host = word_load(s, 8)
    explicit_identity = word_load(s, 16)
    path_size = word_load(s, 24)
    count = word_load(s, 32)
    if same_host > 1 or explicit_identity > 1 or path_size > n - 40:
        return 4294967293
    end = 40 + path_size
    at = end
    matched = 0
    index = 0
    valid_path = capture_normal_path(s, end)
    while index < count:
        if n - at < 16:
            return 4294967293
        role = word_load(s, at)
        size = word_load(s, at + 8)
        at = at + 16
        if role < 1 or role > 3 or size > n - at:
            return 4294967293
        if valid_path and capture_under_root(s, end, at, size):
            matched = matched | (1 << role)
        at = at + size
        index = index + 1
    if at != n:
        return 4294967293
    decision = 0
    if same_host == 1 and explicit_identity == 0 and valid_path and matched == 6:
        decision = 1
    word_store(o, 0, CAPTURE_POLICY_OUTPUT)
    word_store(o, 8, decision)
    return 16

def capture_normal_path(s:readbuf, end:u64) -> bool:
    if end == 40 or end > 4136 or byte(s, 40) != 47:
        return False
    first = 41
    at = first
    while at < end:
        value = byte(s, at)
        if value == 0 or value == 10 or value == 13:
            return False
        if value == 47:
            if capture_dot_segment(s, first, at):
                return False
            first = at + 1
        at = at + 1
    return capture_dot_segment(s, first, end) == False

def capture_dot_segment(s:readbuf, first:u64, end:u64) -> bool:
    size = end - first
    return (size == 1 and byte(s, first) == 46) or (size == 2 and byte(s, first) == 46 and byte(s, first + 1) == 46)

def capture_under_root(s:readbuf, end:u64, root:u64, size:u64) -> bool:
    if size == 0:
        return True
    if byte(s, root) != 47:
        return False
    if size == 1:
        return True
    at = 40
    offset = 0
    while offset < size:
        if at == end:
            return False
        value = byte(s, root + offset)
        if byte(s, at) != value:
            return False
        at = at + 1
        if value == 47:
            while at < end and byte(s, at) == 47:
                at = at + 1
        offset = offset + 1
    return at == end or byte(s, at) == 47

def job_terminal_state(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 56 or length(o) < 16:
        return 4294967293
    effect_unknown = word_load(s, 8)
    timed_out = word_load(s, 16)
    cancelled = word_load(s, 24)
    exit_result = word_load(s, 32)
    output_complete = word_load(s, 40)
    output_durable = word_load(s, 48)
    if effect_unknown > 1 or timed_out > 1 or cancelled > 1 or exit_result > 2 or output_complete > 2 or output_durable > 2:
        return 4294967293
    state = 0
    if effect_unknown == 1:
        state = 1
    elif timed_out == 1:
        state = 2
    elif cancelled == 1:
        state = 3
    elif exit_result == 2 or (exit_result == 1 and (output_complete == 2 or output_durable == 2)):
        state = 4
    elif exit_result == 1:
        state = 5
    word_store(o, 0, JOB_TERMINAL_OUTPUT)
    word_store(o, 8, state)
    return 16

def job_poll(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 72 or length(o) < 24:
        return 4294967293
    stage = word_load(s, 8)
    wait_seconds = word_load(s, 16)
    age_ns = word_load(s, 24)
    size = word_load(s, 32)
    publication_pending = word_load(s, 40)
    state = word_load(s, 48)
    tail = word_load(s, 56)
    last = word_load(s, 64)
    if stage == 0:
        if age_ns != 0 or size != 0 or publication_pending != 0 or state != 0 or tail != 0 or last != 0:
            return 4294967293
        if wait_seconds > 30:
            wait_seconds = 30
        decision = wait_seconds
    else:
        if stage > 2 or wait_seconds > 30 or size > 24 or publication_pending > 1:
            return 4294967293
        running = size == 7 and state == RUNNING_WORD and tail == 0 and last == 0
        activating = stage == 2 and size == 10 and state == ACTIVATING_HEAD and tail == NG_TAIL and last == 0
        finalizing = stage == 2 and size == 10 and state == FINALIZING_HEAD and tail == NG_TAIL and last == 0
        completed_unknown = stage == 2 and size == 17 and state == COMPLETED_HEAD and tail == UNKNOWN_MIDDLE and last == 110
        expired = age_ns >= wait_seconds * 1000000000
        decision = 0
        if expired == False and (running or activating or finalizing or completed_unknown):
            decision = 100
        elif expired and publication_pending == 0 and (finalizing or completed_unknown):
            decision = 101
    word_store(o, 0, JOB_POLL_OUTPUT)
    word_store(o, 8, stage)
    word_store(o, 16, decision)
    return 24

def job_identity(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    n = length(s)
    if n < 10:
        return 4294967293
    if byte(s, 8) != 123 or byte(s, n - 1) != 125:
        return 4294967293
    count = n - 8
    if length(o) < count or length(o) < 72:
        return 4294967294
    external(s, o, 0, 8, count)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    word_store(o, 0, JOB_OUTPUT_MAGIC)
    return saved(w, o, 8, 0, 64)

def envelope_prefix(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = arguments_member(o, at)
    at = append_field(s, o, w, at, 2)
    at = catalog_member(o, at)
    at = external(s, o, at, 48, 64)
    at = profile_member(o, at)
    return saved(w, o, at, 64, 64)

def envelope_tail(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = schema_and_tool(o, at)
    at = append_field(s, o, w, at, 3)
    return close(o, at)

def append_field(s:readbuf, o:mutbuf, w:mutbuf, at:u64, field:u64) -> u64:
    record = 256 + field * 16
    return external(s, o, at, word_load(w, record), word_load(w, record + 8))

def external(s:readbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(s, start + i))
        i = i + 1
    return at + size

def saved(w:mutbuf, o:mutbuf, at:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(w, start + i))
        i = i + 1
    return at + size

def append_word(o:mutbuf, at:u64, word:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, (word >> (i * 8)) & 255)
        i = i + 1
    return at + size

def digest(o:mutbuf, w:mutbuf, size:u64, at:u64) -> u64:
    if widen(hash_sha256(o, w, size)) != 32:
        return 0
    start = length(w) - 4096 + 1088
    i = 0
    while i < 32:
        value = byte(w, start + i)
        store(w, at + 2 * i, hex(value >> 4))
        store(w, at + 2 * i + 1, hex(value & 15))
        i = i + 1
    return 1

def widen(value:u32) -> u64:
    return value

def hex(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def job_reuse(s:readbuf, o:mutbuf) -> u64:
    n = length(s)
    if n < 88 or n > 152:
        return 4294967293
    fingerprint = word_load(s, 8)
    present = word_load(s, 16)
    if present > 1 or (present == 0 and n != 88):
        return 4294967293
    if length(o) < 16:
        return 4294967294
    prefix = 0
    equal = 1
    index = 0
    while index < 64:
        value = byte(s, 24 + index)
        digit = 0
        if value >= 48 and value <= 57:
            digit = value - 48
        elif value >= 97 and value <= 102:
            digit = value - 87
        else:
            return 4294967293
        if index < 16:
            prefix = prefix * 16 + digit
        if n == 152 and byte(s, 88 + index) != value:
            equal = 0
        index = index + 1
    decision = 1
    if present == 0:
        decision = 2
    elif n == 152 and equal != 0 and fingerprint == prefix:
        decision = 0
    word_store(o, 0, REUSE_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16

def http_auth(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    n = length(s)
    if n < 104 or n > 4168:
        return 4294967293
    count = n - 72
    if length(o) < count:
        return 4294967294
    external(s, o, 0, 72, count)
    if digest(o, w, count, 0) == 0:
        return 4294967293
    # Compare every digest byte, including the last. The candidate header
    # length is public. Never return the candidate bytes or either digest.
    difference = 0
    index = 0
    while index < 64:
        difference = difference | (byte(s, 8 + index) ^ byte(w, index))
        index = index + 1
    word_store(o, 0, HTTP_AUTH_OUTPUT)
    word_store(o, 8, choose(difference == 0, 1, 0))
    return 16

def session_scope(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 160:
        return 4294967293
    if length(o) < 16:
        return 4294967294
    transport = word_load(s, 8)
    candidate_size = word_load(s, 16)
    prior_kind = word_load(s, 24)
    if transport > 1 or prior_kind > 2:
        return 4294967293
    if prior_kind != 0 and scope_digest(s, 96) == 0:
        return 4294967293
    # HTTP uses only verified middleware evidence. The stdio fallback is
    # never interpreted as a credential, even if every digest byte agrees.
    decision = 0
    if candidate_size != 64 or scope_digest(s, 32) == 0:
        if transport == 1:
            decision = 1
        else:
            decision = 2
    elif prior_kind != 0:
        different = prior_kind ^ (transport + 1)
        index = 0
        while index < 64:
            different = different | (byte(s, 32 + index) ^ byte(s, 96 + index))
            index = index + 1
        if different != 0:
            decision = 3
    word_store(o, 0, SCOPE_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16

def scope_digest(s:readbuf, at:u64) -> u64:
    index = 0
    while index < 64:
        value = byte(s, at + index)
        if value < 48 or (value > 57 and value < 97) or value > 102:
            return 0
        index = index + 1
    return 1

def launch_ack(s:readbuf, o:mutbuf) -> u64:
    # Flags: literal true ACK, isolated system jobctl, literal true remote
    # reuse, and presence (even null) of /status/job_id. Slots hold
    # backend, actual/expected job ID, actual/expected unit and remote state.
    if length(s) != 1608:
        return 4294967293
    if length(o) < 16:
        return 4294967294
    flags = word_load(s, 8)
    if flags > 15:
        return 4294967293
    field = 24
    while field < 1608:
        if word_load(s, field) > 256:
            return 4294967293
        field = field + 264
    if word_load(s, 552) == 0 or word_load(s, 1080) == 0:
        return 4294967293
    decision = launch_ack_state(s, flags, word_load(s, 24), word_load(s, 32))
    word_store(o, 0, LAUNCH_ACK_OUTPUT)
    word_store(o, 8, decision)
    return 16

def launch_ack_state(s:readbuf, flags:u64, size:u64, name:u64) -> u64:
    if flags & 1 == 0:
        return 0
    if flags & 2 != 0:
        if size != 14 or name != SYSTEM_HEAD or word_load(s, 40) & 0x0000ffffffffffff != SYSTEM_TAIL:
            return 0
        if flags & 8 != 0 and equal_launch_field(s, 288, 552) == 0:
            return 0
        if flags & 4 != 0:
            return reused_launch_state(s)
        return 1
    if size == 7 and name & 0x00ffffffffffffff == SYSTEMD_WORD:
        return equal_launch_field(s, 816, 1080)
    if size == 8 and name == DETACHED_WORD:
        pid = word_load(s, 16)
        return choose(pid != 0 and pid <= 2147483647, 1, 0)
    if flags & 4 != 0:
        if size == 9 and name == COMPLETED_HEAD and byte(s, 40) == 100:
            return 1
        if size == 13 and name == FAILED_HEAD and word_load(s, 40) & 0x000000ffffffffff == FAILED_TAIL:
            return 2
    return 0

def reused_launch_state(s:readbuf) -> u64:
    size = word_load(s, 1344)
    name = word_load(s, 1352)
    if size == 8 and name == LAUNCHED_WORD:
        return 1
    if size == 13 and name == FAILED_HEAD and word_load(s, 1360) & 0x000000ffffffffff == FAILED_TAIL:
        return 2
    if size == 7 and name & 0x00ffffffffffffff == PENDING_WORD:
        return 3
    if size == 9 and name == CANCELLED_HEAD and byte(s, 1360) == 100:
        return 4
    # A trusted reused ACK does not prove its status is authoritative.
    return 5

def equal_launch_field(s:readbuf, left:u64, right:u64) -> u64:
    size = word_load(s, left)
    if size != word_load(s, right):
        return 0
    index = 0
    while index < size:
        if byte(s, left + 8 + index) != byte(s, right + 8 + index):
            return 0
        index = index + 1
    return 1

def durable_transition(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 80:
        return 4294967293
    if length(o) < 16:
        return 4294967294
    flags = word_load(s, 8)
    size = word_load(s, 16)
    if flags > 7 or size > 56:
        return 4294967293
    first = word_load(s, 24)
    # Unknown state or incomplete outcomes remain serialized.
    # Only an already confirmed launch releases the lane for observation.
    decision = 0
    if size == 8 and first == LAUNCHED_WORD:
        decision = 1
    elif flags == 7:
        # All three authorities are required: caller route permits
        # reconciliation, and the bound owner is isolated system jobctl.
        if size == 7 and first & 0x00ffffffffffffff == PENDING_WORD:
            decision = 2
        elif size == 13 and first == FAILED_HEAD and word_load(s, 32) & 0x000000ffffffffff == FAILED_TAIL:
            decision = 2
    word_store(o, 0, TRANSITION_OUTPUT_MAGIC)
    word_store(o, 8, decision)
    return 16
'''

LITERALS = {
    'arguments_member': '{"arguments":',
    'catalog_member': ',"catalog_sha256":"',
    'profile_member': '","profile_sha256":"',
    'request_member': '","request_sha256":"',
    'schema_and_tool': '","schema":"hia-agent-worker-request-v1","tool":',
    'close': '}',
    'readonly_start': '{"readonly_request_sha256":"',
    'readonly_tool': '","tool":',
    'mutation_start': '{"key":',
    'mutation_tool': ',"tool":',
}


def source_program():
    envelope_fields = ('arguments_member', 'catalog_member', 'profile_member',
                       'request_member', 'schema_and_tool', 'close')
    fixed_bytes = sum(len(LITERALS[field]) for field in envelope_fields) + 3 * 64 + 1
    source = (SOURCE.replace('JOB_INPUT_MAGIC', str(int.from_bytes(JOB_INPUT_MAGIC, 'little')))
              .replace('JOB_OUTPUT_MAGIC', str(int.from_bytes(JOB_OUTPUT_MAGIC, 'little')))
              .replace('REUSE_INPUT_MAGIC', str(int.from_bytes(REUSE_INPUT_MAGIC, 'little')))
              .replace('REUSE_OUTPUT_MAGIC', str(int.from_bytes(REUSE_OUTPUT_MAGIC, 'little')))
              .replace('SCOPE_INPUT_MAGIC', str(int.from_bytes(SCOPE_INPUT_MAGIC, 'little')))
              .replace('SCOPE_OUTPUT_MAGIC', str(int.from_bytes(SCOPE_OUTPUT_MAGIC, 'little')))
              .replace('TRANSITION_INPUT_MAGIC', str(int.from_bytes(TRANSITION_INPUT_MAGIC, 'little')))
              .replace('TRANSITION_OUTPUT_MAGIC', str(int.from_bytes(TRANSITION_OUTPUT_MAGIC, 'little')))
              .replace('HTTP_AUTH_INPUT', str(int.from_bytes(HTTP_AUTH_INPUT, 'little')))
              .replace('HTTP_AUTH_OUTPUT', str(int.from_bytes(HTTP_AUTH_OUTPUT, 'little')))
              .replace('LAUNCH_ACK_INPUT', str(int.from_bytes(LAUNCH_ACK_INPUT, 'little')))
              .replace('LAUNCH_ACK_OUTPUT', str(int.from_bytes(LAUNCH_ACK_OUTPUT, 'little')))
              .replace('JOB_POLL_INPUT', str(int.from_bytes(JOB_POLL_INPUT, 'little')))
              .replace('JOB_POLL_OUTPUT', str(int.from_bytes(JOB_POLL_OUTPUT, 'little')))
              .replace('JOB_TERMINAL_INPUT', str(int.from_bytes(JOB_TERMINAL_INPUT, 'little')))
              .replace('JOB_TERMINAL_OUTPUT', str(int.from_bytes(JOB_TERMINAL_OUTPUT, 'little')))
              .replace('CAPTURE_POLICY_INPUT', str(int.from_bytes(CAPTURE_POLICY_INPUT, 'little')))
              .replace('CAPTURE_POLICY_OUTPUT', str(int.from_bytes(CAPTURE_POLICY_OUTPUT, 'little')))
              .replace('JOB_LIFECYCLE_INPUT', str(int.from_bytes(JOB_LIFECYCLE_INPUT, 'little')))
              .replace('JOB_LIFECYCLE_OUTPUT', str(int.from_bytes(JOB_LIFECYCLE_OUTPUT, 'little')))
              .replace('NOT_FOUND_HEAD', str(int.from_bytes(b'not-foun', 'little')))
              .replace('ACTIVE_WORD', str(int.from_bytes(b'active', 'little')))
              .replace('EXITED_WORD', str(int.from_bytes(b'exited', 'little')))
              .replace('DEAD_WORD', str(int.from_bytes(b'dead', 'little')))
              .replace('FAILED_WORD', str(int.from_bytes(b'failed', 'little')))
              .replace('RUNNING_WORD', str(int.from_bytes(b'running', 'little')))
              .replace('ACTIVATING_HEAD', str(int.from_bytes(b'activati', 'little')))
              .replace('FINALIZING_HEAD', str(int.from_bytes(b'finalizi', 'little')))
              .replace('UNKNOWN_MIDDLE', str(int.from_bytes(b'd_unknow', 'little')))
              .replace('NG_TAIL', str(int.from_bytes(b'ng', 'little')))
              .replace('SYSTEM_HEAD', str(int.from_bytes(b'systemd_', 'little')))
              .replace('SYSTEM_TAIL', str(int.from_bytes(b'system', 'little')))
              .replace('SYSTEMD_WORD', str(int.from_bytes(b'systemd', 'little')))
              .replace('DETACHED_WORD', str(int.from_bytes(b'detached', 'little')))
              .replace('COMPLETED_HEAD', str(int.from_bytes(b'complete', 'little')))
              .replace('CANCELLED_HEAD', str(int.from_bytes(b'cancelle', 'little')))
              .replace('LAUNCHED_WORD', str(int.from_bytes(b'launched', 'little')))
              .replace('PENDING_WORD', str(int.from_bytes(b'pending', 'little')))
              .replace('FAILED_HEAD', str(int.from_bytes(b'launch_f', 'little')))
              .replace('FAILED_TAIL', str(int.from_bytes(b'ailed', 'little')))
              .replace('INPUT_MAGIC', str(int.from_bytes(INPUT_MAGIC, 'little')))
              .replace('OUTPUT_MAGIC', str(int.from_bytes(OUTPUT_MAGIC, 'little')))
              .replace('MAX_FRAGMENTS', str(524288 - fixed_bytes)))
    for name, literal in LITERALS.items():
        source += f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
        raw = literal.encode('ascii')
        for start in range(0, len(raw), 8):
            part = raw[start:start + 8]
            source += f'    at = append_word(o, at, {int.from_bytes(part, "little")}, {len(part)})\n'
        source += '    return at\n'
    return source + worker_hash_program()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: f'f{i}' for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = WorkerRequestBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9',
                                 'module': 'worker_prepare', 'functions': functions})


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
