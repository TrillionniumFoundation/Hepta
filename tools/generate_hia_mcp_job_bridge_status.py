"""HIA projection of existing native terminal/lifecycle owner observations.

No raw process observation grants a terminal result. The existing Worker
prepare and terminal-receipt owners decide their own frozen protocols.
"""
from tools.generate_hia_mcp_job_bridge_common import authored

TEXT=dict(empty='',unknown='unknown')
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 90:
        return nonterminal(w)
    if phase == 0:
        put(w, 2304, 0)
        put(w, 2312, 0)
        put(w, 2320, 0)
        put(w, 2360, 0)
        return decode(o, w, 1, CHILD_OUT, get(w, 624))
    if phase == 1:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or string_eq(w, field(w, F_JOB_ID), S_JOB_ID) == False:
            return unavailable(w)
        if get(w, SYSTEM_JOBCTL) != 0:
            return system_status(w)
        terminal = field(w, F__HIA_TERMINAL)
        if terminal != NONE:
            return terminal_frame(o, w, terminal)
        if boolean(w, field(w, F_TERMINAL_PUBLICATION_CONFIRMED), 1):
            return unavailable(w)
        lifecycle = field(w, F__HIA_LIFECYCLE)
        if lifecycle != NONE:
            return lifecycle_frame(o, w, lifecycle)
        state = field(w, F_STATE)
        if state == NONE or get(w, state) != 4:
            return unavailable(w)
        flags = choose(str_is(w, field(w, F_EFFECT_OUTCOME), 0), 1, 0) | choose(str_is(w, field(w, F_OUTCOME), 0), 2, 0)
        put(w, 2360, flags)
        code = state_code(w, state)
        put(w, 2304, code)
        put(w, 2312, 0)
        put(w, 2320, 0)
        if code >= 2 and code <= 5 and boolean(w, field(w, F_STATUS_AUTHORITATIVE), 0) == False and flags == 0:
            return enter(w, 5, 0)
        return nonterminal(w)
    if phase == 10:
        # Canonical equality is serde Value equality, after folding only the
        # two IEEE signed-zero spellings. Integers remain distinct from floats.
        if result > 8388608:
            return unavailable(w)
        copy_state(w, ARENA, CHILD_ERR, result)
        put(w, 2336, result)
        return canonical(o, w, 11, RECORD_TMP, get(w, 2328))
    if phase == 11:
        if result > 8388608 or canonical_equal(w, CHILD_ERR, get(w, 2336), ARENA, result) == False:
            return unavailable(w)
        return child(w, 9, 12, 1, get(w, 2344), 16, 0, 5000000000, NONE)
    if phase == 12:
        if child_ok(w) == False or get(w, 624) != 16 or get(w, CHILD_OUT) != WITNESS_REPLY or get(w, CHILD_OUT + 8) > 4:
            return unavailable(w)
        if get(w, CHILD_OUT + 8) != 0:
            put(w, 2360, 2)
            return nonterminal(w)
        put(w, 0, 13)
        put(o, 0, RECORD_TMP)
        put(o, 8, get(w, 2328))
        put(o, 16, SCRATCH)
        put(o, 24, 8192)
        put(o, 32, ARENA)
        put(o, 40, ARENA_BYTES)
        return 5
    if phase == 13:
        if result != 16 or get(w, SCRATCH) != TERMINAL_REPLY or get(w, SCRATCH + 8) > 5:
            return unavailable(w)
        code = get(w, SCRATCH + 8)
        if code == 0:
            put(w, 2360, 2)
            return nonterminal(w)
        put(w, 2304, code)
        put(w, 2312, 1)
        put(w, 2320, 1)
        return decode(o, w, 14, RECORD_TMP, get(w, 2328))
    if phase == 14:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            return unavailable(w)
        flags = choose(str_is(w, field(w, F_EFFECT_OUTCOME), 0), 1, 0) | choose(str_is(w, field(w, F_OUTCOME), 0), 2, 0)
        put(w, 2360, flags)
        if get(w, 2304) == 1 or boolean(w, field(w, F_STATUS_AUTHORITATIVE), 0) or flags != 0:
            return nonterminal(w)
        return enter(w, 5, 0)
    if phase == 20:
        if child_ok(w) == False or get(w, 624) != 16 or get(w, CHILD_OUT) != TERMINAL_REPLY or get(w, CHILD_OUT + 8) > 5:
            return unavailable(w)
        code = get(w, CHILD_OUT + 8)
        if code == 0:
            put(w, 2360, 2)
            return nonterminal(w)
        put(w, 2304, code)
        put(w, 2312, 0)
        put(w, 2320, 1)
        return decode(o, w, 14, JSON, get(w, 2352))
    if phase == 30:
        if child_ok(w) == False or get(w, 624) != 32 or get(w, CHILD_OUT) != OWNER_REPLY:
            return unavailable(w)
        if get(w, CHILD_OUT + 8) > 1 or get(w, CHILD_OUT + 16) > 1 or get(w, CHILD_OUT + 24) < 1 or get(w, CHILD_OUT + 24) > 2:
            return unavailable(w)
        put(w, 2376, get(w, CHILD_OUT + 8))
        put(w, 2384, get(w, CHILD_OUT + 16))
        put(w, 2392, get(w, CHILD_OUT + 24))
        return decode(o, w, 31, JSON, get(w, 2352))
    if phase == 31:
        if result >= 4294967292:
            return unavailable(w)
        return lifecycle_decision(w)
    if phase == 32:
        if child_ok(w) == False or get(w, 624) != 16 or get(w, CHILD_OUT) != LIFECYCLE_REPLY:
            return unavailable(w)
        state = get(w, CHILD_OUT + 8)
        if state < 1 or state > 13:
            return unavailable(w)
        if state == 5 or state == 10 or state == 12:
            put(w, 2360, 2)
            return nonterminal(w)
        if state == 6 or state == 7 or state == 8:
            # Legacy lifecycle terminal classifications have no complete
            # durable byte witness. They reach the same publication refusal.
            if get(w, 1904) == 0:
                return nonterminal(w)
            put(w, 2200, choose(get(w, 1904) == 3, 13, 4))
            put(w, 2208, 5)
            return enter(w, 5, 700)
        return nonterminal(w)
    return 0

def system_status(w:mutbuf) -> u32:
    # The fixed root Jobctl has already performed its own typed receipt,
    # witness and capture checks. Preserve its public status Value; operator
    # envelope fields are unrelated data on this transport.
    state = field(w, F_STATE)
    if state == NONE or get(w, state) != 4:
        return unavailable(w)
    flags = choose(str_is(w, field(w, F_EFFECT_OUTCOME), 0), 1, 0) | choose(str_is(w, field(w, F_OUTCOME), 0), 2, 0)
    put(w, 2360, flags)
    code = state_code(w, state)
    put(w, 2304, code)
    put(w, 2312, choose(boolean(w, field(w, F_TERMINAL_PUBLICATION_CONFIRMED), 1), 1, 0))
    put(w, 2320, 0)
    if code >= 2 and code <= 5 and boolean(w, field(w, F_STATUS_AUTHORITATIVE), 0) == False and flags == 0:
        return enter(w, 5, 0)
    return nonterminal(w)

def unavailable(w:mutbuf) -> u32:
    if get(w, 1904) == 0:
        put(w, 2360, 2)
        return nonterminal(w)
    # status_record's failed projection becomes its ordinary unavailable
    # observation. It never supplies a terminal proof.
    if get(w, 1904) == 1:
        return enter(w, 5, 600)
    put(w, 2200, 13)
    put(w, 2208, 6)
    return enter(w, 5, 700)

def nonterminal(w:mutbuf) -> u32:
    if get(w, 1904) == 0:
        put(w, 1912, get(w, 2360) | choose(text_is(w, get(w, S_LAUNCH_STATE), get(w, S_LAUNCH_STATE + 8), 0), 4, 0))
        put(w, 1904, 1)
        return enter(w, 3, 200)
    if get(w, 1904) == 3:
        put(w, 2200, 13)
        put(w, 2208, 6)
        return enter(w, 5, 700)
    return enter(w, 5, 600)

def state_code(w:mutbuf, row:u64) -> u64:
    if str_is(w, row, 1):
        return 2
    if str_is(w, row, 2):
        return 3
    if str_is(w, row, 3):
        return 4
    if str_is(w, row, 4):
        return 5
    return 0

def terminal_frame(o:mutbuf, w:mutbuf, envelope:u64) -> u32:
    if object_count(w, ARENA + 64) != 2 or object_count(w, envelope) != 3 or boolean(w, lookup(w, envelope, F_CONFIRMED), 0) == False:
        return unavailable(w)
    receipt = lookup(w, envelope, F_RECEIPT)
    if receipt == NONE or get(w, receipt) != 6 or get(w, receipt + 64) > 1048576:
        return unavailable(w)
    end = raw(w, receipt, JSON)
    put(w, 2352, end - JSON)
    witness = lookup(w, envelope, F_WITNESS)
    if witness == NONE:
        if lookup(w, receipt, F_TERMINAL_PUBLICATION_PROTOCOL) != NONE:
            return unavailable(w)
        facts = lookup(w, envelope, F_FACTS)
        if facts == NONE or get(w, facts) != 5 or get(w, facts + 32) != 6:
            return unavailable(w)
        put(w, CHILD_IN, TERMINAL_MAGIC)
        child_id = get(w, facts + 24)
        index = 0
        while index < 6:
            row = ARENA + 64 + child_id * 72
            if valid_uint(w, row) == False:
                return unavailable(w)
            put(w, CHILD_IN + 8 + index * 8, number(w, row))
            child_id = get(w, row + 16)
            index = index + 1
        return child(w, 9, 20, 1, 56, 16, 0, 5000000000, NONE)
    if object_count(w, witness) != 6:
        return unavailable(w)
    versions = lookup(w, witness, F_PROTOCOL)
    if versions == NONE or get(w, versions) != 5 or get(w, versions + 32) != 3:
        return unavailable(w)
    child_id = get(w, versions + 24)
    index = 0
    put(w, CHILD_IN, WITNESS_MAGIC)
    while index < 3:
        row = ARENA + 64 + child_id * 72
        value = number(w, row)
        if value > 3:
            return unavailable(w)
        put(w, CHILD_IN + 8 + index * 8, value)
        child_id = get(w, row + 16)
        index = index + 1
    encoded = lookup(w, witness, F_RAW)
    if encoded == NONE or get(w, encoded) != 4 or get(w, encoded + 32) > 2097152 or get(w, encoded + 32) % 2 != 0:
        return unavailable(w)
    size = get(w, encoded + 32)
    source = ARENA + get(w, encoded + 24)
    if lowerhex(w, source, size) == False:
        return unavailable(w)
    index = 0
    while index < size:
        store(w, RECORD_TMP + index // 2, (hex_digit_value(byte(w, source + index)) << 4) | hex_digit_value(byte(w, source + index + 1)))
        index = index + 2
    put(w, 2328, size // 2)
    put(w, CHILD_IN + 32, get(w, S_JOB_ID + 8))
    at = cp(w, S_JOB_ID, CHILD_IN + 96)
    at = witness_string(w, at, CHILD_IN + 40, lookup(w, receipt, F_JOB_ID))
    at = witness_string(w, at, CHILD_IN + 48, lookup(w, witness, F_JOB))
    at = witness_string(w, at, CHILD_IN + 56, lookup(w, witness, F_REQUEST_NONCE))
    at = witness_string(w, at, CHILD_IN + 64, lookup(w, receipt, F_LAUNCH_NONCE))
    at = witness_string(w, at, CHILD_IN + 72, lookup(w, witness, F_NONCE))
    at = witness_string(w, at, CHILD_IN + 80, lookup(w, witness, F_DIGEST))
    put(w, CHILD_IN + 88, size // 2)
    at = copy_state(w, RECORD_TMP, at, size // 2)
    put(w, 2344, at - CHILD_IN)
    return canonical(o, w, 10, JSON, get(w, 2352))

def witness_string(w:mutbuf, at:u64, head:u64, row:u64) -> u64:
    size = 0
    if row != NONE and get(w, row) == 4 and get(w, row + 32) <= 128:
        size = get(w, row + 32)
        copy_state(w, ARENA + get(w, row + 24), at, size)
    put(w, head, size)
    return at + size

def lifecycle_frame(o:mutbuf, w:mutbuf, envelope:u64) -> u32:
    if object_count(w, ARENA + 64) != 2 or object_count(w, envelope) != 2:
        return unavailable(w)
    owner = lookup(w, envelope, F_OBSERVATIONS)
    props = lookup(w, envelope, F_SYSTEMD)
    if owner == NONE or get(w, owner) != 6 or props == NONE or get(w, props) != 6:
        return unavailable(w)
    if get(w, envelope + 64) > 4194304:
        return unavailable(w)
    end = raw(w, envelope, JSON)
    put(w, 2352, end - JSON)
    put(w, CHILD_IN, OWNER_MAGIC)
    put(w, CHILD_IN + 8, number(w, lookup(w, owner, F_STARTER_UID)))
    put(w, CHILD_IN + 16, number(w, lookup(w, owner, F_EFFECTIVE_UID)))
    put(w, CHILD_IN + 24, number(w, lookup(w, owner, F_STARTER_PID)))
    put(w, CHILD_IN + 32, number(w, lookup(w, owner, F_OBSERVED_UID)))
    put(w, CHILD_IN + 40, get(w, S_JOB_ID + 8))
    at = cp(w, S_JOB_ID, CHILD_IN + 144)
    index = 0
    while index < 12:
        key = lifecycle_key(index)
        parent = choose(index < 10, owner, props)
        row = lookup(w, parent, key)
        if index >= 10 and row != NONE and get(w, row) != 4:
            return unavailable(w)
        size = 0
        if row != NONE and get(w, row) == 4:
            size = get(w, row + 32)
            if size > 256:
                return unavailable(w)
            copy_state(w, ARENA + get(w, row + 24), at, size)
        put(w, CHILD_IN + 48 + index * 8, size)
        at = at + size
        index = index + 1
    return child(w, 9, 30, 1, at - CHILD_IN, 32, 0, 5000000000, NONE)

def lifecycle_key(index:u64) -> u64:
    value = F_REQUEST_JOB
    value = choose(index == 1, F_STARTER_JOB, value)
    value = choose(index == 2, F_REQUEST_NONCE, value)
    value = choose(index == 3, F_STARTER_NONCE, value)
    value = choose(index == 4, F_EXPECTED_KIND, value)
    value = choose(index == 5, F_STARTER_KIND, value)
    value = choose(index == 6, F_STARTER_IDENTITY, value)
    value = choose(index == 7, F_OBSERVED_KIND, value)
    value = choose(index == 8, F_OBSERVED_IDENTITY, value)
    value = choose(index == 9, F_STARTER_INVOCATION, value)
    value = choose(index == 10, F_INVOCATIONID, value)
    value = choose(index == 11, F_DESCRIPTION, value)
    return value

def lifecycle_decision(w:mutbuf) -> u32:
    owner = field(w, F_OBSERVATIONS)
    props = field(w, F_SYSTEMD)
    witnessed = lookup(w, owner, F_REQUEST_WITNESS)
    if boolean(w, witnessed, 0) == False and boolean(w, witnessed, 1) == False:
        return unavailable(w)
    put(w, CHILD_IN, LIFECYCLE_MAGIC)
    put(w, CHILD_IN + 8, get(w, 2376))
    put(w, CHILD_IN + 16, get(w, 2384))
    put(w, CHILD_IN + 24, choose(boolean(w, witnessed, 1), 1, 0))
    put(w, CHILD_IN + 32, get(w, 2392))
    code = lookup(w, props, F_EXECMAINCODE)
    status = lookup(w, props, F_EXECMAINSTATUS)
    if (code != NONE and get(w, code) != 4) or (status != NONE and get(w, status) != 4):
        return unavailable(w)
    put(w, CHILD_IN + 40, choose(str_is(w, code, 5), 1, 0))
    put(w, CHILD_IN + 48, choose(trimmed_zero(w, status), 1, 0))
    at = CHILD_IN + 80
    index = 0
    while index < 3:
        key = choose(index == 0, F_LOADSTATE, choose(index == 1, F_ACTIVESTATE, F_SUBSTATE))
        row = lookup(w, props, key)
        size = 0
        if row != NONE:
            if get(w, row) != 4 or get(w, row + 32) > 128:
                return unavailable(w)
            size = get(w, row + 32)
            copy_state(w, ARENA + get(w, row + 24), at, size)
        put(w, CHILD_IN + 56 + index * 8, size)
        at = at + size
        index = index + 1
    return child(w, 9, 32, 1, at - CHILD_IN, 16, 0, 5000000000, NONE)

def trimmed_zero(w:mutbuf, row:u64) -> bool:
    if row == NONE or get(w, row) != 4:
        return False
    source = ARENA + get(w, row + 24)
    size = get(w, row + 32)
    index = 0
    stage = 0
    digits = 0
    while index < size:
        c = byte(w, source + index)
        index = index + 1
        cp = c
        need = 0
        if c >= 240:
            cp = c & 7
            need = 3
        elif c >= 224:
            cp = c & 15
            need = 2
        elif c >= 192:
            cp = c & 31
            need = 1
        while need != 0:
            cp = (cp << 6) | (byte(w, source + index) & 63)
            index = index + 1
            need = need - 1
        whitespace = trim_space(cp)
        if stage == 0 and whitespace:
            stage = 0
        elif stage == 0 and (cp == 43 or cp == 45):
            stage = 1
        elif cp == 48 and stage < 3:
            stage = 2
            digits = digits + 1
        elif stage >= 2 and whitespace:
            stage = 3
        else:
            return False
    return digits != 0

def trim_space(value:u64) -> bool:
    return value == 32 or value - 9 <= 4 or value == 133 or value == 160 or value == 5760 or value - 8192 <= 10 or value - 8232 <= 1 or value == 8239 or value == 8287 or value == 12288
'''


def source():
    return authored(SOURCE,text=TEXT,extra={
      'WITNESS_MAGIC':int.from_bytes(b'HIAJWC01','little'),
      'WITNESS_REPLY':int.from_bytes(b'HIAJWR01','little'),
      'TERMINAL_MAGIC':int.from_bytes(b'HIAJTS01','little'),
      'TERMINAL_REPLY':int.from_bytes(b'HIAJTV01','little'),
      'OWNER_MAGIC':int.from_bytes(b'HIAJOQ01','little'),
      'OWNER_REPLY':int.from_bytes(b'HIAJOR01','little'),
      'LIFECYCLE_MAGIC':int.from_bytes(b'HIAJSS01','little'),
      'LIFECYCLE_REPLY':int.from_bytes(b'HIAJSV01','little'),
      '_checks':('unknown','timed_out','cancelled','failed','succeeded','1')})
