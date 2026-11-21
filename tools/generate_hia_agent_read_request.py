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
    put(o, 48, 64)
    put(o, 56, 8)
    size = widen(decode_json(s, w, o))
    if size >= 4294967292:
        return size
    fields = count(w, 0)
    if kind(w, 0) != 6 or fields < 2 or fields > 4:
        return 4294967295
    catalog = field(w, 0, KEY_catalog_sha256)
    artifact = field(w, 0, KEY_artifact)
    cursor = field(w, 0, KEY_cursor)
    maximum = field(w, 0, KEY_max_bytes)
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
KEYS = ('artifact', 'catalog_sha256', 'cursor', 'max_bytes', 'id', 'sha256', 'uri')


def source_program():
    import re

    source = POLICY
    for name, value in VALUES.items():
        if isinstance(value, bytes):
            value = int.from_bytes(value, 'little')
        source = re.sub(rf'\b{name}\b', str(value), source)
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
