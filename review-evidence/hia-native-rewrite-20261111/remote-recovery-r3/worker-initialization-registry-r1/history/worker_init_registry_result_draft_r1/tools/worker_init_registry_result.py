"""Actual frozen Graph-merge result validation and registry commit, UNEXECUTED."""
BODY=r'''
def wr_plan(w:mutbuf) -> u64:
    left = iv_get(w, B_NODES)
    right = iv_get(w, R_RIGHT_NODES)
    le = iv_get(w, B_EDGES)
    re = iv_get(w, R_RIGHT_EDGES)
    lp = iv_get(w, B_POOL)
    rp = iv_get(w, R_RIGHT_POOL)
    if left >= IV_MAX - right or le > IV_MAX - 2 or re > IV_MAX - 2 - le:
        return iv_bad(w, 350)
    nodes = left + right + 1
    edges = le + re + 2
    if nodes > (IV_MAX - 64) >> 6:
        return iv_bad(w, 351)
    size = 64 + nodes * 64
    if edges > (IV_MAX - size) >> 3:
        return iv_bad(w, 352)
    size = size + edges * 8
    if lp > IV_MAX - rp or lp + rp > IV_MAX - size:
        return iv_bad(w, 353)
    pool = lp + rp
    size = size + pool
    if size > IV_MAX - 512:
        return iv_bad(w, 354)
    iv_put(w, R_NODES, nodes)
    iv_put(w, R_EDGES, edges)
    iv_put(w, R_POOL, pool)
    iv_put(w, R_OUT_BYTES, size)
    iv_put(w, R_OUT_NEED, size + 512)
    return 1

def wr_expected_header(s:readbuf, r:readbuf, w:mutbuf, action:u64) -> u64:
    at = WR_EXPECTED
    fill_range(w, at, 512, 0)
    iv_put(w, at, WR_MERGE_STATE)
    iv_put(w, at + 8, choose(action == 0, 2, 1))
    iv_put(w, at + 16, iv_get(w, R_OUTPUT))
    iv_put(w, at + 24, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, at + 32, iv_get(w, R_CHILD_SEQ) + 1)
    iv_put(w, at + 40, iv_get(w, R_WIRE_BYTES))
    iv_put(w, at + 48, iv_get(w, R_RIGHT_BYTES))
    iv_put(w, at + 56, iv_word(s, 24))
    iv_put(w, at + 64, iv_get(w, R_RIGHT_ROOT))
    iv_put(w, at + 72, iv_get(w, B_NODES))
    iv_put(w, at + 80, iv_get(w, R_RIGHT_NODES))
    iv_put(w, at + 88, iv_get(w, B_EDGES))
    iv_put(w, at + 96, iv_get(w, R_RIGHT_EDGES))
    iv_put(w, at + 104, iv_get(w, B_POOL))
    iv_put(w, at + 112, iv_get(w, R_RIGHT_POOL))
    iv_put(w, at + 120, iv_get(w, R_NODES))
    iv_put(w, at + 128, iv_get(w, R_EDGES))
    iv_put(w, at + 136, iv_get(w, R_POOL))
    iv_put(w, at + 144, iv_get(w, R_OUT_BYTES))
    iv_put(w, at + 152, iv_get(w, R_OUT_NEED))
    iv_put(w, at + 256, WR_MERGE_EVENT)
    iv_put(w, at + 264, action)
    iv_put(w, at + 272, iv_get(w, R_OUTPUT))
    iv_put(w, at + 280, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, at + 288, iv_get(w, R_CHILD_SEQ) + 1)
    iv_put(w, at + 296, iv_get(w, R_OUT_NEED))
    iv_put(w, at + 304, 512)
    iv_put(w, at + 312, iv_get(w, R_OUT_BYTES))
    iv_put(w, at + 328, iv_get(w, R_NODES))
    iv_put(w, at + 336, iv_get(w, R_EDGES))
    iv_put(w, at + 344, iv_get(w, R_POOL))
    iv_put(w, at + 352, iv_word(s, 24) + 1)
    iv_put(w, at + 360, iv_get(w, R_RIGHT_ROOT) + iv_get(w, B_NODES) + 1)
    copy_bytes(w, s, at + 384, 0, 64)
    copy_bytes(w, r, at + 448, 128, 64)
    return 1

def wr_merge_header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, B_PHASE) != 12 or iv_word(r, 32) != iv_get(w, B_ACTIVE_COMMAND):
        return iv_bad(w, 355)
    if iv_word(r, 72) != 384 or iv_word(r, 80) != 0:
        return iv_bad(w, 356)
    size = iv_word(r, 104)
    workspace = iv_word(r, 112)
    if size > length(r) - 128 or workspace != length(r) - 128 - size or workspace < 512:
        return iv_bad(w, 357)
    if wr_foreign(r, w, size) == 0 or wr_plan(w) == 0:
        return 0
    if iv_get(w, R_CHILD_SEQ) == IV_MAX:
        return iv_bad(w, 358)
    base = 128 + size
    iv_put(w, R_MBASE, base)
    action = choose(workspace < iv_get(w, R_OUT_NEED), 1, 0)
    wr_expected_header(s, r, w, action)
    index = 0
    while index < 512:
        if byte(r, base + index) != byte(w, WR_EXPECTED + index):
            return iv_bad(w, 359)
        index = index + 1
    return 1

def wr_node_equal(a:readbuf, b:readbuf, w:mutbuf, identifier:u64) -> u64:
    source = iv_get(w, R_C_SOURCE) + identifier * 64
    target = iv_get(w, R_C_TARGET) + (identifier + iv_get(w, R_C_NODE_DELTA)) * 64
    kind = iv_word(a, source)
    field = 0
    while field < 8:
        expected = iv_word(a, source + field * 8)
        if field == 1 and (kind == 2 or kind == 3 or kind == 4 or kind == 9):
            expected = iv_get(w, R_C_NEW_DATA) + iv_get(w, R_C_SCALAR_DELTA) + expected - iv_get(w, R_C_OLD_DATA)
        if field == 3 and (kind == 5 or kind == 6 or kind == 7):
            expected = expected + iv_get(w, R_C_EDGE_DELTA)
        if field == 5 and (kind == 5 or kind == 6 or kind == 7):
            expected = expected + iv_get(w, R_C_NODE_DELTA)
        if iv_word(b, target + field * 8) != expected:
            return iv_bad(w, 360)
        field = field + 1
    return 1

def wr_clone_equal(a:readbuf, b:readbuf, w:mutbuf, source:u64, nodes_delta:u64, edges_delta:u64, scalars_delta:u64) -> u64:
    iv_put(w, R_C_SOURCE, source)
    iv_put(w, R_C_TARGET, iv_get(w, R_MBASE) + 512)
    iv_put(w, R_C_NODES, iv_word(a, source + 16))
    iv_put(w, R_C_EDGES, iv_word(a, source + 32))
    iv_put(w, R_C_OLD_DATA, 64 + iv_word(a, source + 16) * 64 + iv_word(a, source + 32) * 8)
    iv_put(w, R_C_NEW_DATA, 64 + iv_get(w, R_NODES) * 64 + iv_get(w, R_EDGES) * 8)
    iv_put(w, R_C_NODE_DELTA, nodes_delta)
    iv_put(w, R_C_EDGE_DELTA, edges_delta)
    iv_put(w, R_C_SCALAR_DELTA, scalars_delta)
    identifier = 1
    while identifier <= iv_get(w, R_C_NODES):
        if wr_node_equal(a, b, w, identifier) == 0:
            return 0
        identifier = identifier + 1
    index = 0
    while index < iv_get(w, R_C_EDGES):
        value = iv_word(a, source + 64 + iv_get(w, R_C_NODES) * 64 + index * 8)
        target = iv_get(w, R_C_TARGET) + 64 + iv_get(w, R_NODES) * 64 + (index + edges_delta) * 8
        if iv_word(b, target) != value + nodes_delta:
            return iv_bad(w, 361)
        index = index + 1
    if pj_range_equal(a, b, source + iv_get(w, R_C_OLD_DATA),
        iv_get(w, R_C_TARGET) + iv_get(w, R_C_NEW_DATA) + scalars_delta,
        iv_word(a, source + 40)) == 0:
        return iv_bad(w, 362)
    return 1

def wr_graph_result(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    base = iv_get(w, R_MBASE) + 512
    if iv_shape(r, w, base, iv_get(w, R_OUT_BYTES), iv_get(w, R_OUTPUT)) == 0:
        return 0
    if iv_word(r, base + 16) != iv_get(w, R_NODES) or iv_word(r, base + 24) != 1:
        return iv_bad(w, 363)
    if iv_word(r, base + 32) != iv_get(w, R_EDGES) or iv_word(r, base + 40) != iv_get(w, R_POOL):
        return iv_bad(w, 364)
    fill_range(w, WR_EXPECTED, 64, 0)
    iv_put(w, WR_EXPECTED, 5)
    iv_put(w, WR_EXPECTED + 32, 2)
    iv_put(w, WR_EXPECTED + 40, 1)
    index = 0
    while index < 64:
        if byte(r, base + 64 + index) != byte(w, WR_EXPECTED + index):
            return iv_bad(w, 365)
        index = index + 1
    edges = base + 64 + iv_get(w, R_NODES) * 64
    if iv_word(r, edges) != iv_word(s, 24) + 1:
        return iv_bad(w, 366)
    if iv_word(r, edges + 8) != iv_get(w, R_RIGHT_ROOT) + iv_get(w, B_NODES) + 1:
        return iv_bad(w, 367)
    if wr_clone_equal(s, r, w, 0, 1, 2, 0) == 0:
        return 0
    if wr_clone_equal(r, r, w, 128, iv_get(w, B_NODES) + 1,
        iv_get(w, B_EDGES) + 2, iv_get(w, B_POOL)) == 0:
        return 0
    return 1

def wr_registry_valid(w:mutbuf) -> u64:
    count = iv_get(w, B_ISSUED)
    if count >= (length(w) - PJ_REGISTRY) >> 4:
        return iv_bad(w, 368)
    index = 0
    while index < count:
        at = PJ_REGISTRY + index * 16
        root = iv_get(w, at)
        nodes = iv_get(w, at + 8)
        if root == 0 or root > nodes or nodes > iv_get(w, B_NODES):
            return iv_bad(w, 369)
        index = index + 1
    return 1

def wr_commit(r:readbuf, w:mutbuf) -> u32:
    if wr_registry_valid(w) == 0:
        return wr_fail(w, 370)
    imported = iv_get(w, R_RIGHT_ROOT) + iv_get(w, B_NODES) + 1
    index = 0
    while index < iv_get(w, B_ISSUED):
        at = PJ_REGISTRY + index * 16
        iv_put(w, at, iv_get(w, at) + 1)
        iv_put(w, at + 8, iv_get(w, at + 8) + 1)
        index = index + 1
    handle = pj_issue(w, imported, iv_get(w, R_NODES))
    iv_put(w, B_HANDLE0, handle)
    iv_put(w, B_HANDLE1, 0)
    iv_put(w, R_ROOT, imported)
    copy_bytes(w, r, PJ_SOURCE_HEADER, iv_get(w, R_MBASE) + 512, 64)
    iv_put(w, B_LEASE, iv_get(w, R_OUTPUT))
    iv_put(w, B_BYTES, iv_get(w, R_OUT_BYTES))
    iv_put(w, B_NODES, iv_get(w, R_NODES))
    iv_put(w, B_EDGES, iv_get(w, R_EDGES))
    iv_put(w, B_POOL, iv_get(w, R_POOL))
    iv_put(w, B_NEED, 0)
    iv_put(w, B_LAST_COMMAND, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, B_PHASE, 0)
    return wr_event(w, 6)

def wr_merge_result(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if wr_merge_header(s, r, w) == 0:
        return wr_fail(w, 371)
    iv_put(w, R_CHILD_SEQ, iv_get(w, R_CHILD_SEQ) + 1)
    iv_put(w, R_CHILD_NEED, iv_get(w, R_OUT_NEED))
    if iv_word(r, iv_get(w, R_MBASE) + 264) == 1:
        iv_put(w, iv_get(w, R_WIRE_AT) + 8, 2)
        iv_put(w, iv_get(w, R_WIRE_AT) + 32, iv_get(w, R_CHILD_SEQ))
        return wr_event(w, 4)
    if wr_graph_result(s, r, w) == 0:
        return wr_fail(w, 372)
    return wr_commit(r, w)
'''
