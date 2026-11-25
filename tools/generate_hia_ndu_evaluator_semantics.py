"""Original policy-bound NDU contribution, Pareto and digest semantics in HIA."""
SEMANTICS=r'''
def stable_id(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0:
        return error(w, 1016, 0, 0, 0)
    if size > 128:
        return error(w, 1017, 0, size, 0)
    i = 0
    while i < size:
        if byte(w, at + i) == 0:
            return error(w, 1018, 0, 0, 0)
        i = i + 1
    i = 0
    while i < size:
        ch = byte(w, at + i)
        allowed = (ch >= 48 and ch <= 57) or (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 46 or ch == 95 or ch == 45 or ch == 58
        if allowed == False:
            return error(w, 1019, 0, 0, 0)
        i = i + 1
    return 1

def match_literal(w:mutbuf, at:u64, size:u64, which:u64) -> u64:
    end = literal(w, 44032, which)
    return eq(w, at, size, 44032, end - 44032)

def admit(w:mutbuf) -> u64:
    count = get(w, 304)
    if match_literal(w, get(w, 256), get(w, 264), L_REQUEST_SCHEMA) == 0 or count == 0 or count > 128 or get(w, 296) >> 63 != 0:
        return error(w, 1010, 0, 0, 0)
    if hex_parse(w, get(w, 272), get(w, 280), 544) == 0:
        return 0
    if get(w, 288) == 0:
        return error(w, 1011, 0, 0, 0)
    abstain = 18446744073709551615
    i = 0
    while i < count:
        row = 4096 + i * 192
        j = 0
        while j < i:
            other = 4096 + j * 192
            if eq(w, get(w, row), get(w, row + 8), get(w, other), get(w, other + 8)) == 1:
                return error(w, 1014, 0, 0, 0)
            j = j + 1
        if (get(w, row + 16) | get(w, row + 24) | get(w, row + 32)) >> 63 != 0:
            return error(w, 1014, 0, 0, 0)
        if stable_id(w, get(w, row), get(w, row + 8)) == 0:
            return 0
        if hex_parse(w, get(w, row + 48), get(w, row + 56), row + 64) == 0:
            return 0
        if match_literal(w, get(w, row), get(w, row + 8), L_ABSTAIN) == 1:
            abstain = row
        i = i + 1
    if abstain == 18446744073709551615:
        return error(w, 1015, 0, 0, 0)
    put(w, 312, abstain)
    if nonzero(w, 544) == 0:
        return error(w, 1020, 0, 0, 0)
    i = 0
    while i < count:
        row = 4096 + i * 192
        if nonzero(w, row + 64) == 0:
            return error(w, 1021, 0, get(w, row), get(w, row + 8))
        i = i + 1
    return 1

def axis(w:mutbuf, which:u64, value:u64) -> u64:
    be32(w, 1)
    fixed_id(w, which)
    return be64(w, value)

def hash_literal(w:mutbuf, which:u64, out:u64) -> u64:
    put(w, 64, 2097152)
    text(w, which)
    return hash_segment(w, 2097152, get(w, 64) - 2097152, out)

def profile_digest(w:mutbuf) -> u64:
    hash_literal(w, L_AXIS_REGISTRY, 704)
    hash_literal(w, L_NORMALIZATION, 736)
    put(w, 64, 2097152)
    text(w, L_PROFILE_DOMAIN)
    fixed_id(w, L_PROFILE_ID)
    text_copy(w, 704, 64)
    be32(w, 1)
    fixed_id(w, L_TOTAL_MS)
    text_byte(w, 1)
    be32(w, 0)
    axis(w, L_SEARCH_MS, get(w, 296))
    be32(w, 1)
    fixed_id(w, L_ORGAN)
    return hash_segment(w, 2097152, get(w, 64) - 2097152, 576)

def policy_digest(w:mutbuf) -> u64:
    put(w, 64, 2097152)
    text(w, L_POLICY_DOMAIN)
    fixed_id(w, L_POLICY_ID)
    be32(w, 1)
    fixed_id(w, L_TOTAL_MS)
    text_byte(w, 3)
    be32(w, 0)
    be32(w, 1)
    fixed_id(w, L_SEARCH_MS)
    text_byte(w, 3)
    be32(w, 1)
    fixed_id(w, L_TOTAL_MS)
    text_byte(w, 1)
    axis(w, L_TOTAL_MS, 0)
    return hash_segment(w, 2097152, get(w, 64) - 2097152, 608)

def contribution_digest(w:mutbuf, row:u64) -> u64:
    put(w, 64, 2097152)
    text(w, L_CONTRIBUTION_DOMAIN)
    identifier(w, get(w, row), get(w, row + 8))
    fixed_id(w, L_ORGAN)
    text_copy(w, 544, 32)
    be64(w, get(w, 288))
    text_byte(w, get(w, row + 40))
    axis(w, L_TOTAL_MS, get(w, row + 16))
    be32(w, 0)
    axis(w, L_SEARCH_MS, get(w, row + 32))
    axis(w, L_TOTAL_MS, get(w, row + 24))
    text_copy(w, row + 64, 32)
    hash_segment(w, 2097152, get(w, 64) - 2097152, row + 96)
    return hash_segment(w, row + 96, 32, row + 128)

def emit_candidate(w:mutbuf, row:u64) -> u64:
    identifier(w, get(w, row), get(w, row + 8))
    axis(w, L_TOTAL_MS, get(w, row + 16))
    be32(w, 0)
    axis(w, L_SEARCH_MS, get(w, row + 32))
    axis(w, L_TOTAL_MS, get(w, row + 24))
    text_copy(w, row + 128, 32)
    return text_byte(w, 0)

def emit_rejected(w:mutbuf, row:u64) -> u64:
    identifier(w, get(w, row), get(w, row + 8))
    flags = get(w, row + 160)
    be32(w, (flags & 1) + (flags >> 1))
    if flags & 1 != 0:
        text_byte(w, 0)
    if flags & 2 != 0:
        text_byte(w, 2)
    return get(w, 64)

def sort_candidates(w:mutbuf) -> u64:
    count = get(w, 304)
    i = 0
    while i < count:
        row = 4096 + i * 192
        at = i
        shifting = True
        while at > 0 and shifting:
            prior = get(w, 40000 + (at - 1) * 8)
            if before(w, get(w, row), get(w, row + 8), get(w, prior), get(w, prior + 8)) == 0:
                shifting = False
            else:
                put(w, 40000 + at * 8, prior)
                at = at - 1
        put(w, 40000 + at * 8, row)
        i = i + 1
    return count

def evaluate(w:mutbuf) -> u64:
    count = sort_candidates(w)
    feasible = 0
    best = 18446744073709551615
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        flags = get(w, row + 40)
        if get(w, row + 32) > get(w, 296):
            flags = flags | 2
        put(w, row + 160, flags)
        contribution_digest(w, row)
        if flags == 0:
            feasible = feasible + 1
            cost = get(w, row + 16)
            if cost < best:
                best = cost
        i = i + 1
    if get(w, get(w, 312) + 160) != 0:
        return error(w, 1022, 0, 0, 0)
    frontier = 0
    winner = 0
    i = 0
    while i < count:
        row = get(w, 40000 + i * 8)
        if get(w, row + 160) == 0 and get(w, row + 16) == best:
            frontier = frontier + 1
            winner = row
        i = i + 1
    disposition = 2
    if feasible == 1:
        disposition = 0
    else:
        if frontier == 1:
            disposition = 1
    put(w, 320, feasible)
    put(w, 328, best)
    put(w, 336, frontier)
    put(w, 344, disposition)
    put(w, 352, winner)
    profile_digest(w)
    policy_digest(w)
    return 1

def evaluation_digest(w:mutbuf) -> u64:
    put(w, 64, 2097152)
    text(w, L_EVALUATION_DOMAIN)
    text_copy(w, 544, 32)
    text_copy(w, 576, 32)
    text_byte(w, 0)
    be64(w, get(w, 288))
    text_byte(w, get(w, 344))
    be32(w, get(w, 320))
    i = 0
    while i < get(w, 304):
        row = get(w, 40000 + i * 8)
        if get(w, row + 160) == 0:
            emit_candidate(w, row)
        i = i + 1
    be32(w, get(w, 304) - get(w, 320))
    i = 0
    while i < get(w, 304):
        row = get(w, 40000 + i * 8)
        if get(w, row + 160) != 0:
            emit_rejected(w, row)
        i = i + 1
    be32(w, get(w, 336))
    i = 0
    while i < get(w, 304):
        row = get(w, 40000 + i * 8)
        if get(w, row + 160) == 0 and get(w, row + 16) == get(w, 328):
            emit_candidate(w, row)
        i = i + 1
    if get(w, 344) != 2:
        text_byte(w, 1)
        row = get(w, 352)
        identifier(w, get(w, row), get(w, row + 8))
    else:
        text_byte(w, 0)
    hash_segment(w, 2097152, get(w, 64) - 2097152, 640)
    put(w, 64, 2097152)
    text(w, L_EVALUATION_V2_DOMAIN)
    text_copy(w, 640, 32)
    text_copy(w, 608, 32)
    text_byte(w, get(w, 344))
    return hash_segment(w, 2097152, get(w, 64) - 2097152, 672)

def success_json(w:mutbuf) -> u64:
    put(w, 64, 2097152)
    text(w, L_SUCCESS_OPEN)
    if get(w, 344) == 2:
        text(w, L_NULL)
    else:
        row = get(w, 352)
        quote(w, get(w, row), get(w, row + 8))
    text(w, L_SUCCESS_DISPOSITION)
    end = literal(w, 44032, L_DISPOSITION_0 + get(w, 344))
    quote(w, 44032, end - 44032)
    text(w, L_SUCCESS_EVALUATION)
    hex_output(w, 672)
    text(w, L_SUCCESS_POLICY)
    hex_output(w, 608)
    text(w, L_SUCCESS_GENERATION)
    decimal(w, get(w, 288))
    text(w, L_SUCCESS_OBJECTIVE)
    hex_output(w, 544)
    text(w, L_SUCCESS_FRONTIER)
    i = 0
    written = 0
    while i < get(w, 304):
        row = get(w, 40000 + i * 8)
        if get(w, row + 160) == 0 and get(w, row + 16) == get(w, 328):
            if written > 0:
                text_byte(w, 44)
            quote(w, get(w, row), get(w, row + 8))
            written = written + 1
        i = i + 1
    text(w, L_SUCCESS_REJECTED)
    i = 0
    written = 0
    while i < get(w, 304):
        row = get(w, 40000 + i * 8)
        flags = get(w, row + 160)
        if flags != 0:
            if written > 0:
                text_byte(w, 44)
            text(w, L_REJECT_ID)
            quote(w, get(w, row), get(w, row + 8))
            text(w, L_REJECT_REASONS)
            which = choose(flags == 1, L_REASON_HARD, choose(flags == 2, L_REASON_RESOURCE, L_REASON_BOTH))
            end = literal(w, 44032, which)
            quote(w, 44032, end - 44032)
            text_byte(w, 125)
            written = written + 1
        i = i + 1
    text(w, L_SUCCESS_REQUEST)
    hex_output(w, 512)
    text(w, L_SUCCESS_PROFILE)
    hex_output(w, 576)
    text_byte(w, 125)
    return text_byte(w, 10)
'''
