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
    if length(s) >= 24 and input_word(s, 0) == BIND_PAGE:
        return bind_page(s, o)
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
    if same(w, tool_text, count(w, tool), TOOL_READ_VIEW) == 0:
        return NONE
    schema_text = get(w, 64 + schema * 56 + 24)
    if count(w, schema) != WORKER_SCHEMA_BYTES:
        return NONE
    if same(w, schema_text, 24, WORKER_SCHEMA_INITIAL) == 0:
        return NONE
    if same(w, schema_text + 24, WORKER_SCHEMA_BYTES - 24, WORKER_SCHEMA_REMAINING) == 0:
        return NONE
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

VALUES = {
    'NONE': (1 << 64) - 1,
    'READ_PLAN': b'HIAARD01',
    'BIND_PAGE': b'HIAARP02',
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
}
KEYS = ('artifact', 'catalog_sha256', 'cursor', 'max_bytes', 'id', 'sha256', 'uri',
        'arguments', 'profile_sha256', 'schema', 'tool')
WORKER_SCHEMA = 'hia-agent-worker-request-v1'
WORKER_LITERALS = {
    'TOOL_READ_VIEW': packed('hia_read'),
    'WORKER_SCHEMA_BYTES': [len(WORKER_SCHEMA)],
    'WORKER_SCHEMA_INITIAL': packed(WORKER_SCHEMA[:24]),
    'WORKER_SCHEMA_REMAINING': packed(WORKER_SCHEMA[24:]),
}


def source_program():
    import re

    source = POLICY
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
