"""Author the native read Worker input plan for retained Store artifacts."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_json_frontend import FRONTEND, packed
from tools.generate_hia_json_decode import source_program as json_decoder

SOURCE_PATH = 'examples/hia_bootstrap/agent_read_request.hepta'

POLICY = r'''
def read_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 16384 or length(o) < 8192 or length(w) < 32768:
        return 4294967294
    if length(s) >= 40 and input_word(s, 0) == FLOW_EVENT:
        return advance_read_effect(s, o, w)
    if length(s) >= 24 and input_word(s, 0) == BIND_PAGE:
        return bind_page(s, o)
    if length(s) >= 48 and input_word(s, 0) == BIND_RESOURCE:
        return bind_resource(s, o)
    if length(s) >= 136 and input_word(s, 0) == RESOURCE_ARGUMENTS:
        return resource_arguments(s, o)
    put(o, 48, 64)
    put(o, 56, 8)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    root = 0
    if kind(w, 0) == 6 and count(w, 0) == 5:
        root = admitted_worker_arguments(w)
        if root == NONE:
            return 4294967295
        if resource_tool(w):
            return resource_plan(s, o, w, root)
    fields = count(w, root)
    if kind(w, root) != 6 or fields < 2 or fields > 4:
        return 4294967295
    catalog = field(w, root, KEY_catalog_sha256)
    artifact = field(w, root, KEY_artifact)
    cursor = field(w, root, KEY_cursor)
    maximum = field(w, root, KEY_max_bytes)
    if read_digest(w, catalog) == False or kind(w, artifact) != 6 or count(w, artifact) != 3:
        return 4294967295
    identity = field(w, artifact, KEY_id)
    digest = field(w, artifact, KEY_sha256)
    uri = field(w, artifact, KEY_uri)
    if valid_identity(w, identity, False) == False or valid_identity(w, uri, True) == False or read_digest(w, digest) == False:
        return 4294967295
    flags = 0
    limit = 0
    found = 2
    if cursor != NONE:
        if valid_cursor(w, cursor) == False:
            return 4294967295
        flags = flags | 2
        found = found + 1
    if maximum != NONE:
        limit = page_limit(s, w, maximum)
        if limit == 0:
            return 4294967295
        flags = flags | 1
        found = found + 1
    if found != fields:
        return 4294967295
    at = 0
    while at < 8192:
        store(o, at, 0)
        at = at + 1
    put(o, 0, READ_PLAN)
    put(o, 8, flags)
    put(o, 16, limit)
    copy_text(w, o, catalog, 64)
    return encode_read_plan(w, o, identity, digest, uri, cursor)

# The standalone Worker admission executable has already verified the
# original six-field envelope and its hash. Its canonical, five-field output
# omits request_sha256. This worker-only shape is a routing input, never an
# authentication credential or authority to open the Store.
def admitted_worker_arguments(w:mutbuf) -> u64:
    tool = field(w, 0, KEY_tool)
    schema = field(w, 0, KEY_schema)
    catalog = field(w, 0, KEY_catalog_sha256)
    profile = field(w, 0, KEY_profile_sha256)
    arguments = field(w, 0, KEY_arguments)
    if kind(w, tool) != 4 or kind(w, schema) != 4 or kind(w, arguments) != 6:
        return NONE
    if read_digest(w, catalog) == False or read_digest(w, profile) == False:
        return NONE
    tool_text = get(w, 64 + tool * 56 + 24)
    resource = same(w, tool_text, count(w, tool), TOOL_RESOURCE_VIEW) != 0
    if same(w, tool_text, count(w, tool), TOOL_READ_VIEW) == 0 and resource == False:
        return NONE
    schema_text = get(w, 64 + schema * 56 + 24)
    if count(w, schema) != WORKER_SCHEMA_BYTES:
        return NONE
    if same(w, schema_text, 24, WORKER_SCHEMA_INITIAL) == 0:
        return NONE
    if same(w, schema_text + 24, WORKER_SCHEMA_BYTES - 24, WORKER_SCHEMA_REMAINING) == 0:
        return NONE
    if resource:
        return arguments
    argument_catalog = field(w, arguments, KEY_catalog_sha256)
    if read_digest(w, argument_catalog) == False:
        return NONE
    outer = get(w, 64 + catalog * 56 + 24)
    inner = get(w, 64 + argument_catalog * 56 + 24)
    at = 0
    while at < 64:
        if byte(w, outer + at) != byte(w, inner + at):
            return NONE
        at = at + 1
    return arguments

# A resource URI is resolved before the Journal changes tool 12 into tool 3.
# The original admitted call remains the sole source of its request identity.
def resource_tool(w:mutbuf) -> bool:
    tool = field(w, 0, KEY_tool)
    return same(w, get(w, 64 + tool * 56 + 24), count(w, tool), TOOL_RESOURCE_VIEW) != 0

def resource_plan(s:readbuf, o:mutbuf, w:mutbuf, arguments:u64) -> u64:
    uri = field(w, arguments, KEY_uri)
    maximum = field(w, arguments, KEY_max_bytes)
    fields = count(w, arguments)
    if fields != choose(maximum == NONE, 1, 2) or valid_identity(w, uri, True) == False:
        return 4294967295
    limit = 65536
    if maximum != NONE:
        limit = page_limit(s, w, maximum)
        if limit == 0:
            return 4294967295
    at = 0
    while at < 128:
        store(o, at, 0)
        at = at + 1
    put(o, 0, READ_PLAN)
    put(o, 8, 5)
    put(o, 16, limit)
    copy_text(w, o, field(w, 0, KEY_catalog_sha256), 64)
    end = lookup(w, o, uri, 128)
    put(o, 32, end - 128)
    put(o, end, RESOURCE_ADMISSION)
    put(o, end + 8, count(w, uri))
    put(o, end + 16, 0)
    end = copy_text(w, o, uri, end + 24)
    put(o, 48, 24 + count(w, uri))
    put(o, 56, end)
    return end

def resource_plan_valid(s:readbuf, at:u64, size:u64) -> bool:
    if size < 242 or size > 624 or input_word(s, at) != READ_PLAN:
        return False
    if input_word(s, at + 8) != 5 or input_word(s, at + 24) != 0 or input_word(s, at + 40) != 0:
        return False
    limit = input_word(s, at + 16)
    lookup = input_word(s, at + 32)
    admission = input_word(s, at + 48)
    if limit < 512 or limit > 65536 or lookup < 73 or lookup > 264:
        return False
    uri = lookup - 56
    if admission != 24 + uri or size != 128 + lookup + admission or input_word(s, at + 56) != size:
        return False
    if canonical_lookup(s, at + 128, lookup) == False:
        return False
    tail = at + 128 + lookup
    if input_word(s, tail) != RESOURCE_ADMISSION or input_word(s, tail + 8) != uri or input_word(s, tail + 16) != 0:
        return False
    return bound_identity(s, at + 184, tail + 24, uri)

# Only the independently validated Store row's identity and SHA spans are
# concatenated with this request's URI; arbitrary row metadata never enters
# the bounded plan compiler. The Store row remains sealed through settlement.
def bind_resource(s:readbuf, o:mutbuf) -> u64:
    plan = input_word(s, 8)
    identity = input_word(s, 16)
    if identity == 0 or identity > 192 or input_word(s, 24) != 64:
        return 4294967295
    if input_word(s, 32) != 0 or input_word(s, 40) != 0 or length(s) != 48 + plan + identity + 64:
        return 4294967295
    if resource_plan_valid(s, 48, plan) == False:
        return 4294967295
    id_at = 48 + plan
    sha_at = id_at + identity
    uri_at = 232
    uri = input_word(s, 80) - 56
    if raw_identity(s, id_at, identity, False) == False or raw_identity(s, uri_at, uri, True) == False:
        return 4294967295
    if raw_digest(s, sha_at) == False or raw_digest(s, 112) == False:
        return 4294967295
    at = 0
    while at < 128:
        store(o, at, 0)
        at = at + 1
    put(o, 0, READ_PLAN)
    put(o, 8, 1)
    put(o, 16, input_word(s, 64))
    copy_input(s, o, 112, 64, 64)
    at = literal(o, 128, REF_ID, 7)
    at = at + copy_input(s, o, id_at, at, identity)
    at = literal(o, at, REF_DIGEST_FIRST, 8)
    at = literal(o, at, REF_DIGEST_LAST, 4)
    at = at + copy_input(s, o, sha_at, at, 64)
    at = literal(o, at, REF_URI_FIRST, 8)
    at = literal(o, at, REF_URI_LAST, 1)
    at = at + copy_input(s, o, uri_at, at, uri)
    at = literal(o, at, REF_END, 2)
    put(o, 24, at - 128)
    put(o, at, STORE_LOOKUP)
    put(o, at + 8, 1)
    put(o, at + 16, 1)
    put(o, at + 24, 56 + identity)
    put(o, at + 32, 3)
    put(o, at + 40, 56)
    put(o, at + 48, identity)
    at = at + 56 + copy_input(s, o, id_at, at + 56, identity)
    put(o, 32, 56 + identity)
    put(o, at, ARTIFACT_ADMISSION)
    put(o, at + 8, identity)
    put(o, at + 16, uri)
    at = at + 24 + copy_input(s, o, sha_at, at + 24, 64)
    at = at + copy_input(s, o, id_at, at, identity)
    at = at + copy_input(s, o, uri_at, at, uri)
    put(o, 48, 88 + identity + uri)
    put(o, 56, at)
    return at

def raw_digest(s:readbuf, at:u64) -> bool:
    i = 0
    while i < 64:
        v = byte(s, at + i)
        if (v < 48 or v > 57) and (v < 97 or v > 102):
            return False
        i = i + 1
    return True

def raw_identity(s:readbuf, at:u64, size:u64, uri:bool) -> bool:
    i = 0
    if uri:
        if size <= 16 or size > 208 or input_word(s, at) != URI_0 or input_word(s, at + 8) != URI_1:
            return False
        i = 16
    elif size == 0 or size > 192:
        return False
    if alpha_numeric(byte(s, at + i)) == False:
        return False
    while i < size:
        ch = byte(s, at + i)
        other = choose(uri, ch == 126, ch == 47 or ch == 58)
        if (alpha_numeric(ch) or ch == 45 or ch == 46 or ch == 95 or other) == False:
            return False
        i = i + 1
    return True

# The lowered arguments still pass the ordinary public Read input schema.
def resource_arguments(s:readbuf, o:mutbuf) -> u64:
    plan = length(s) - 8
    reference = input_word(s, 32)
    limit = input_word(s, 24)
    if plan < 128 or plan > 8192 or input_word(s, 8) != READ_PLAN or input_word(s, 64) != plan:
        return 4294967295
    if input_word(s, 16) != 1 or reference == 0 or reference > 512 or limit < 512 or limit > 65536:
        return 4294967295
    if 128 + reference > plan or raw_digest(s, 72) == False:
        return 4294967295
    at = literal(o, 8, ARGS_FIRST, 8)
    at = literal(o, at, ARGS_REST, 4)
    at = at + copy_input(s, o, 136, at, reference)
    at = literal(o, at, ARGS_CATALOG_0, 8)
    at = literal(o, at, ARGS_CATALOG_1, 8)
    at = literal(o, at, ARGS_CATALOG_2, 3)
    at = at + copy_input(s, o, 72, at, 64)
    at = literal(o, at, ARGS_MAX_0, 8)
    at = literal(o, at, ARGS_MAX_1, 6)
    place = 10000
    started = False
    while place != 0:
        digit = 0
        while limit >= place:
            limit = limit - place
            digit = digit + 1
        if digit != 0 or started or place == 1:
            store(o, at, 48 + digit)
            at = at + 1
            started = True
        if place == 10000:
            place = 1000
        elif place == 1000:
            place = 100
        elif place == 100:
            place = 10
        elif place == 10:
            place = 1
        else:
            place = 0
    store(o, at, 125)
    put(o, 0, at + 1 - 8)
    return at + 1

# A Store result may only supply the cursor row. Keep the limit, identity,
# canonical reference and cursor key in the plan that admitted the request.
def bind_page(s:readbuf, o:mutbuf) -> u64:
    plan = input_word(s, 8)
    row = input_word(s, 16)
    if plan < 128 or plan > 8192 or row > 512 or length(s) != 24 + plan + row:
        return 4294967295
    if input_word(s, 24) != READ_PLAN or input_word(s, 80) != plan:
        return 4294967295
    flags = input_word(s, 32)
    limit = input_word(s, 40)
    ref_size = input_word(s, 48)
    lookup_size = input_word(s, 56)
    query_size = input_word(s, 64)
    admission_size = input_word(s, 72)
    if flags > 3 or ref_size == 0 or ref_size > 512:
        return 4294967295
    if lookup_size < 57 or lookup_size > 248 or query_size > 2104:
        return 4294967295
    if admission_size < 90 or admission_size > 488:
        return 4294967295
    if 128 + ref_size + lookup_size + query_size + admission_size != plan:
        return 4294967295
    if flags & 1 == 0:
        if limit != 0:
            return 4294967295
    elif limit < 512 or limit > 65536:
        return 4294967295
    lookup_at = 152 + ref_size
    query_at = lookup_at + lookup_size
    cursor = 0
    if flags & 2 != 0:
        if query_size < 57 or canonical_lookup(s, query_at, query_size) == False:
            return 4294967295
        if row != 0:
            cursor = query_size - 56
    elif query_size != 0 or row != 0:
        return 4294967295
    admission_at = query_at + query_size
    if input_word(s, admission_at) != ARTIFACT_ADMISSION or canonical_lookup(s, lookup_at, lookup_size) == False:
        return 4294967295
    identity = input_word(s, admission_at + 8)
    uri = input_word(s, admission_at + 16)
    if identity != lookup_size - 56 or uri == 0 or uri > 208:
        return 4294967295
    if 88 + identity + uri != admission_size or cursor > 128 or 120 + identity + cursor + row > 1024:
        return 4294967295
    identity_at = admission_at + 88
    if bound_identity(s, identity_at, lookup_at + 56, identity) == False:
        return 4294967295
    put(o, 0, BOUND_PAGE)
    put(o, 8, flags)
    put(o, 16, limit)
    put(o, 24, ref_size)
    put(o, 32, identity)
    put(o, 40, cursor)
    put(o, 48, row)
    copy_input(s, o, admission_at + 24, 56, 64)
    copy_input(s, o, identity_at, 120, identity)
    cursor_at = 120 + identity
    copy_input(s, o, query_at + 56, cursor_at, cursor)
    copy_input(s, o, 24 + plan, cursor_at + cursor, row)
    at = cursor_at + cursor + row
    while at < 1024:
        store(o, at, 0)
        at = at + 1
    copy_input(s, o, 152, 1024, ref_size)
    return 1024 + ref_size

def canonical_lookup(s:readbuf, at:u64, size:u64) -> bool:
    return input_word(s, at) == STORE_LOOKUP and input_word(s, at + 8) == 1 and input_word(s, at + 16) == 1 and input_word(s, at + 24) == size and input_word(s, at + 32) == 3 and input_word(s, at + 40) == 56 and input_word(s, at + 48) == size - 56

def bound_identity(s:readbuf, first:u64, second:u64, extent:u64) -> bool:
    at = 0
    while at < extent:
        if byte(s, first + at) != byte(s, second + at):
            return False
        at = at + 1
    return True

def copy_input(s:readbuf, o:mutbuf, source:u64, destination:u64, extent:u64) -> u64:
    at = 0
    while at < extent:
        store(o, destination + at, byte(s, source + at))
        at = at + 1
    return at

def input_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (8 * i))
        i = i + 1
    return value

def read_digest(w:mutbuf, node:u64) -> bool:
    if kind(w, node) != 4 or count(w, node) != 64:
        return False
    start = get(w, 64 + node * 56 + 24)
    i = 0
    while i < 64:
        ch = byte(w, start + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        i = i + 1
    return True

def alpha_numeric(ch:u64) -> bool:
    return (ch >= 48 and ch <= 57) or (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122)

def valid_identity(w:mutbuf, node:u64, uri:bool) -> bool:
    if kind(w, node) != 4:
        return False
    extent = count(w, node)
    start = get(w, 64 + node * 56 + 24)
    i = 0
    if uri:
        if extent <= 16 or extent > 208:
            return False
        if get(w, start) != URI_0 or get(w, start + 8) != URI_1:
            return False
        i = 16
    elif extent == 0 or extent > 192:
        return False
    if alpha_numeric(byte(w, start + i)) == False:
        return False
    while i < extent:
        ch = byte(w, start + i)
        unreserved = ch == 45 or ch == 46 or ch == 95
        other = choose(uri, ch == 126, ch == 47 or ch == 58)
        if (alpha_numeric(ch) or unreserved or other) == False:
            return False
        i = i + 1
    return True

def valid_cursor(w:mutbuf, node:u64) -> bool:
    if kind(w, node) != 4:
        return False
    extent = count(w, node)
    if extent == 0 or extent > 2048:
        return False
    start = get(w, 64 + node * 56 + 24)
    chars = 0
    at = 0
    while at < extent:
        if byte(w, start + at) & 192 != 128:
            chars = chars + 1
        at = at + 1
    return chars <= 512

def page_limit(s:readbuf, w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 3 or count(w, node) > 5:
        return 0
    start = get(w, 64 + node * 56 + 24)
    end = start + count(w, node)
    value = 0
    while start < end:
        ch = byte(s, start)
        if ch < 48 or ch > 57:
            return 0
        value = value * 10 + ch - 48
        start = start + 1
    if value < 512 or value > 65536:
        return 0
    return value

def encode_read_plan(w:mutbuf, o:mutbuf, identity:u64, digest:u64, uri:u64, cursor:u64) -> u64:
    at = plan_reference(w, o, identity, digest, uri)
    put(o, 24, at - 128)
    next = lookup(w, o, identity, at)
    put(o, 32, next - at)
    at = next
    if cursor != NONE:
        next = lookup(w, o, cursor, at)
        put(o, 40, next - at)
        at = next
    put(o, at, ARTIFACT_ADMISSION)
    put(o, at + 8, count(w, identity))
    put(o, at + 16, count(w, uri))
    next = copy_text(w, o, digest, at + 24)
    next = copy_text(w, o, identity, next)
    next = copy_text(w, o, uri, next)
    put(o, 48, next - at)
    put(o, 56, next)
    return next

def lookup(w:mutbuf, o:mutbuf, node:u64, at:u64) -> u64:
    extent = count(w, node)
    put(o, at, STORE_LOOKUP)
    put(o, at + 8, 1)
    put(o, at + 16, 1)
    put(o, at + 24, 56 + extent)
    put(o, at + 32, 3)
    put(o, at + 40, 56)
    put(o, at + 48, extent)
    return copy_text(w, o, node, at + 56)

def plan_reference(w:mutbuf, o:mutbuf, identity:u64, digest:u64, uri:u64) -> u64:
    at = literal(o, 128, REF_ID, 7)
    at = copy_text(w, o, identity, at)
    at = literal(o, at, REF_DIGEST_FIRST, 8)
    at = literal(o, at, REF_DIGEST_LAST, 4)
    at = copy_text(w, o, digest, at)
    at = literal(o, at, REF_URI_FIRST, 8)
    at = literal(o, at, REF_URI_LAST, 1)
    at = copy_text(w, o, uri, at)
    return literal(o, at, REF_END, 2)

def literal(o:mutbuf, at:u64, word:u64, extent:u64) -> u64:
    i = 0
    while i < extent:
        store(o, at + i, word >> (i * 8) & 255)
        i = i + 1
    return at + extent

def copy_text(w:mutbuf, o:mutbuf, node:u64, at:u64) -> u64:
    row = 64 + node * 56
    source = get(w, row + 24)
    extent = get(w, row + 32)
    i = 0
    while i < extent:
        store(o, at + i, byte(w, source + i))
        i = i + 1
    return at + extent

def next_node(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 16)
'''


# The owner reads observations from exact sealed descriptors supplied by
# the session carrier. It emits a next action and immutable operand spans,
# not an executable path. The carrier cannot select the continuation phase.
READ_EFFECT = r"""
def advance_read_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    event = input_word(s, 8)
    sequence = input_word(s, 16)
    extent = input_word(s, 24)
    body = input_word(s, 32)
    if body != length(s) - 40 or sequence != get(w, FLOW_STATE + 8) + 1:
        return 4294967295
    phase = get(w, FLOW_STATE)
    if phase == 0:
        if event != 1 or extent != 0:
            return 4294967295
        return begin_read_effect(s, o, w, body)
    if phase != event:
        return 4294967295
    if event == 2:
        return read_observe_artifact_row(o, w, body, extent)
    if event == 3:
        if get(w, FLOW_STATE + 64) == 1:
            return read_observe_resource_policy(s, o, w, body, extent)
        return read_observe_artifact_policy(s, o, w, body, extent)
    if event == 10:
        return read_observe_resource_plan(s, o, w, body, extent)
    if event == 4:
        return read_observe_capture(o, w, body, extent)
    if event == 5:
        return read_observe_metadata(o, w, body, extent)
    if event == 6:
        if body != 0 or extent > 512:
            return 4294967295
        return read_bind_action(o, w, extent)
    if event == 7:
        if body != 0 or extent != 1024 + get(w, FLOW_PLAN + 24):
            return 4294967295
        return read_flow_action(o, w, 7, 8, 0, extent, get(w, FLOW_STATE + 48), 0)
    if event == 8:
        return read_observe_page(s, o, w, body, extent)
    if event == 9:
        return read_observe_cursor_commit(s, o, w, body, extent)
    return 4294967295

def begin_read_effect(s:readbuf, o:mutbuf, w:mutbuf, plan:u64) -> u64:
    if plan < 128 or plan > 8192 or input_word(s, 40) != READ_PLAN or input_word(s, 96) != plan:
        return 4294967295
    flags = input_word(s, 48)
    reference = input_word(s, 64)
    lookup = input_word(s, 72)
    cursor = input_word(s, 80)
    admission = input_word(s, 88)
    if flags == 5 and reference == 0:
        if resource_plan_valid(s, 40, plan) == False:
            return 4294967295
        copy_input(s, w, 40, FLOW_PLAN, plan)
        put(w, FLOW_STATE + 16, plan)
        put(w, FLOW_STATE + 64, 1)
        size = read_flow_action(o, w, 1, 2, 0, 0, 3, lookup)
        copy_input(s, o, 168, 48, lookup)
        return size
    if flags > 3 or reference == 0 or reference > 512 or lookup < 57 or lookup > 248:
        return 4294967295
    if cursor > 2104 or admission < 90 or admission > 488:
        return 4294967295
    if (cursor == 0 and flags & 2 != 0) or (cursor != 0 and flags & 2 == 0):
        return 4294967295
    if 128 + reference + lookup + cursor + admission != plan:
        return 4294967295
    artifact_at = 168 + reference
    if canonical_lookup(s, artifact_at, lookup) == False:
        return 4294967295
    if cursor > 0 and (cursor < 57 or canonical_lookup(s, artifact_at + lookup, cursor) == False):
        return 4294967295
    if input_word(s, artifact_at + lookup + cursor) != ARTIFACT_ADMISSION:
        return 4294967295
    copy_input(s, w, 40, FLOW_PLAN, plan)
    put(w, FLOW_STATE + 16, plan)
    size = read_flow_action(o, w, 1, 2, 0, 0, 2, lookup)
    copy_input(s, o, artifact_at, 48, lookup)
    return size

def read_observe_resource_policy(s:readbuf, o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if body != 40 or extent != 0:
        return 4294967295
    decision = input_word(s, 40)
    identity_at = input_word(s, 48)
    identity = input_word(s, 56)
    sha_at = input_word(s, 64)
    sha = input_word(s, 72)
    if decision == 1 and identity_at == 0 and identity == 0 and sha_at == 0 and sha == 0:
        return read_flow_action(o, w, 10, 255, 0, 0, 3, 0)
    row = get(w, FLOW_STATE + 24)
    if decision != 0 or identity == 0 or identity > 192 or sha != 64:
        return 4294967295
    if identity_at < 176 or identity_at > row or identity > row - identity_at:
        return 4294967295
    if sha_at < 176 or sha_at > row or sha > row - sha_at:
        return 4294967295
    plan = get(w, FLOW_STATE + 16)
    size = read_flow_action(o, w, 11, 10, identity_at, identity, sha_at, 48 + plan)
    put(o, 48, BIND_RESOURCE)
    put(o, 56, plan)
    put(o, 64, identity)
    put(o, 72, 64)
    put(o, 80, 0)
    put(o, 88, 0)
    copy_flow_output(w, o, FLOW_PLAN, 96, plan)
    return size

def read_observe_resource_plan(s:readbuf, o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if get(w, FLOW_STATE + 64) != 1 or extent != body or body < 128 or body > 2048:
        return 4294967295
    if input_word(s, 40) != READ_PLAN or input_word(s, 48) != 1 or input_word(s, 96) != body:
        return 4294967295
    if input_word(s, 56) != get(w, FLOW_PLAN + 16) or input_word(s, 80) != 0:
        return 4294967295
    at = 0
    while at < 64:
        if byte(s, 104 + at) != byte(w, FLOW_PLAN + 64 + at):
            return 4294967295
        at = at + 1
    copy_input(s, w, 40, FLOW_PLAN, body)
    put(w, FLOW_STATE + 16, body)
    put(w, FLOW_STATE + 64, 2)
    admission = get(w, FLOW_PLAN + 48)
    if admission < 90 or admission > 488 or admission > body - 128:
        return 4294967295
    size = read_flow_action(o, w, 2, 3, 0, get(w, FLOW_STATE + 24), 0, admission)
    copy_flow_output(w, o, FLOW_PLAN + body - admission, 48, admission)
    return size

def read_observe_artifact_row(o:mutbuf, w:mutbuf, body:u64, row:u64) -> u64:
    if body != 0 or row > 1000000032 or (row > 0 and row < 176):
        return 4294967295
    put(w, FLOW_STATE + 24, row)
    extent = get(w, FLOW_PLAN + 48)
    source = FLOW_PLAN + get(w, FLOW_STATE + 16) - extent
    size = read_flow_action(o, w, 2, 3, 0, row, 0, extent)
    copy_flow_output(w, o, source, 48, extent)
    return size

def read_observe_artifact_policy(s:readbuf, o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if body != 40 or extent != 0 or input_word(s, 64) != 0 or input_word(s, 72) != 0:
        return 4294967295
    decision = input_word(s, 40)
    metadata = input_word(s, 48)
    count = input_word(s, 56)
    if decision == 1 and metadata == 0 and count == 0:
        return read_flow_action(o, w, 10, 255, 0, 0, 1, 0)
    row = get(w, FLOW_STATE + 24)
    if decision != 0 or metadata < 176 or metadata > row or count > row - metadata:
        return 4294967295
    put(w, FLOW_STATE + 32, metadata)
    put(w, FLOW_STATE + 40, count)
    source = FLOW_PLAN + get(w, FLOW_STATE + 16) - get(w, FLOW_PLAN + 48)
    size = read_flow_action(o, w, 3, 4, 0, 0, 1024 + get(w, FLOW_PLAN + 24), 64)
    copy_flow_output(w, o, source + 24, 48, 64)
    return size

def read_observe_capture(o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if body != 0 or extent > 67108864:
        return 4294967295
    put(w, FLOW_STATE + 48, extent)
    return read_flow_action(o, w, 4, 5, get(w, FLOW_STATE + 32), get(w, FLOW_STATE + 40), 0, 0)

def read_observe_metadata(o:mutbuf, w:mutbuf, body:u64, status:u64) -> u64:
    if body != 0:
        return 4294967295
    if status != 1:
        if status == 4294967295 or status == 4294967294 or status == 4294967292 or status == 4294967280:
            return read_flow_action(o, w, 10, 255, 0, 0, status, 0)
        return 4294967295
    if get(w, FLOW_STATE + 64) == 2:
        plan = get(w, FLOW_STATE + 16)
        size = read_flow_action(o, w, 12, 255, 0, 0, 0, plan)
        copy_flow_output(w, o, FLOW_PLAN, 48, plan)
        return size
    cursor = get(w, FLOW_PLAN + 40)
    if cursor == 0:
        return read_bind_action(o, w, 0)
    at = FLOW_PLAN + 128 + get(w, FLOW_PLAN + 24) + get(w, FLOW_PLAN + 32)
    size = read_flow_action(o, w, 5, 6, 0, 0, 6, cursor)
    copy_flow_output(w, o, at, 48, cursor)
    return size

def read_bind_action(o:mutbuf, w:mutbuf, row:u64) -> u64:
    plan = get(w, FLOW_STATE + 16)
    if plan > 8192 - 72:
        return 4294967295
    size = read_flow_action(o, w, 6, 7, 0, row, 0, 24 + plan)
    put(o, 48, BIND_PAGE)
    put(o, 56, plan)
    put(o, 64, row)
    copy_flow_output(w, o, FLOW_PLAN, 72, plan)
    return size

def read_observe_page(s:readbuf, o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if body == 40 and extent == 40 and input_word(s, 40) == CURSOR_REFUSAL:
        if input_word(s, 48) == 0 and input_word(s, 56) == 0 and input_word(s, 64) == 0 and input_word(s, 72) == 0:
            return read_flow_action(o, w, 10, 255, 0, 0, 2, 0)
        return 4294967295
    if body != 32 or input_word(s, 40) != PAGE_RESULT:
        return 4294967295
    next = input_word(s, 48)
    result = input_word(s, 56)
    retained = input_word(s, 64)
    if result < 2 or result > 394500 or retained > 533 or extent != 32 + result + retained:
        return 4294967295
    if retained == 0:
        if next != NONE:
            return 4294967295
        return read_flow_action(o, w, 9, 255, 32, result, 0, 0)
    if retained < 278 or next >= get(w, FLOW_STATE + 48):
        return 4294967295
    put(w, FLOW_STATE + 56, result)
    return read_flow_action(o, w, 8, 9, 32 + result, retained, 10, 0)

def read_observe_cursor_commit(s:readbuf, o:mutbuf, w:mutbuf, body:u64, extent:u64) -> u64:
    if body != 56 or extent != 0 or input_word(s, 40) != STORE_INTENT:
        return 4294967295
    if input_word(s, 48) != 5 or input_word(s, 56) != 8 or input_word(s, 64) > 1 or input_word(s, 72) != 0:
        return 4294967295
    return read_flow_action(o, w, 9, 255, 32, get(w, FLOW_STATE + 56), 0, 0)

def read_flow_action(o:mutbuf, w:mutbuf, role:u64, phase:u64, offset:u64, bytes:u64, auxiliary:u64, tail:u64) -> u64:
    sequence = get(w, FLOW_STATE + 8) + 1
    put(w, FLOW_STATE, phase)
    put(w, FLOW_STATE + 8, sequence)
    put(o, 0, FLOW_ACTION)
    put(o, 8, role)
    put(o, 16, sequence)
    put(o, 24, offset)
    put(o, 32, bytes)
    put(o, 40, auxiliary)
    return 48 + tail

def copy_flow_output(w:mutbuf, o:mutbuf, at:u64, destination:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, destination + i, byte(w, at + i))
        i = i + 1
    return 0
"""

VALUES = {
    'NONE': (1 << 64) - 1,
    'READ_PLAN': b'HIAARD01',
    'BIND_PAGE': b'HIAARP02',
    'BIND_RESOURCE': b'HIAURB01',
    'RESOURCE_ARGUMENTS': b'HIAURJ01',
    'RESOURCE_ADMISSION': b'HIAARU01',
    'BOUND_PAGE': b'HIAARB01',
    'STORE_LOOKUP': b'HIAQPA01',
    'ARTIFACT_ADMISSION': b'HIAARR01',
    'URI_0': b'hia://ar',
    'URI_1': b'tifacts/',
    'REF_ID': b'{"id":"',
    'REF_DIGEST_FIRST': b'","sha25',
    'REF_DIGEST_LAST': b'6":"',
    'REF_URI_FIRST': b'","uri":',
    'REF_URI_LAST': b'"',
    'REF_END': b'"}',
    'ARGS_FIRST': b'{"artifa',
    'ARGS_REST': b'ct":',
    'ARGS_CATALOG_0': b',"catalo',
    'ARGS_CATALOG_1': b'g_sha256',
    'ARGS_CATALOG_2': b'":"',
    'ARGS_MAX_0': b'","max_b',
    'ARGS_MAX_1': b'ytes":',
    'FLOW_EVENT': b'HIAFDE01',
    'FLOW_ACTION': b'HIAFDA01',
    'FLOW_STATE': 23808,
    'FLOW_PLAN': 24576,
    'CURSOR_REFUSAL': b'HIAARU03',
    'PAGE_RESULT': b'HIAARO05',
    'STORE_INTENT': b'HIASTCP1',
}
KEYS = ('artifact', 'catalog_sha256', 'cursor', 'max_bytes', 'id', 'sha256', 'uri',
        'arguments', 'profile_sha256', 'schema', 'tool')
WORKER_SCHEMA = 'hia-agent-worker-request-v1'
WORKER_LITERALS = {
    'TOOL_READ_VIEW': packed('hia_read'),
    'TOOL_RESOURCE_VIEW': packed('hia_resource_read'),
    'WORKER_SCHEMA_BYTES': [len(WORKER_SCHEMA)],
    'WORKER_SCHEMA_INITIAL': packed(WORKER_SCHEMA[:24]),
    'WORKER_SCHEMA_REMAINING': packed(WORKER_SCHEMA[24:]),
}


def source_program():
    import re

    source = POLICY + READ_EFFECT
    for name, value in VALUES.items():
        if isinstance(value, bytes):
            value = int.from_bytes(value, 'little')
        source = re.sub(rf'\b{name}\b', str(value), source)
    for name, value in WORKER_LITERALS.items():
        source = re.sub(rf'\b{name}\b', ', '.join(map(str, value)), source)
    source += FRONTEND[FRONTEND.index('def kind('):FRONTEND.index('def shape(')]
    matcher = FRONTEND[FRONTEND.index('def same('):]
    source += matcher.split('\ndef ', 1)[0] + '\n'
    source += '\ndef key_id(w:mutbuf, node:u64) -> u64:\n'
    source += '    row = 64 + node * 56\n    start = get(w, row + 40)\n    size = get(w, row + 48)\n'
    for index, name in enumerate(KEYS, start=1):
        pattern = ', '.join(map(str, packed(name)))
        source = source.replace(f'KEY_{name}', str(index))
        source += f'    if same(w, start, size, {pattern}) != 0:\n        return {index}\n'
    source += '    return 0\n'
    return source + json_decoder()


if __name__ == '__main__':
    Path(SOURCE_PATH).write_text(render_assembly(document(source_program(), 'agent_read_request')))
