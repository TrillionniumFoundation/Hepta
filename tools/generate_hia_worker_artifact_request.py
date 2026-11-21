"""Author the native request plan for immutable artifact retention."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_json_frontend import FRONTEND, packed
from tools.generate_hia_agent_data_json import source_program as json_decoder

SOURCE = 'examples/hia_bootstrap/worker_artifact_request.hepta'
KEYS = ('artifact_profile', 'id', 'sha256', 'source', 'catalog_sha256', 'request_key',
        'kind', 'text', 'path', 'expected_sha256', 'max_bytes')

POLICY = r'''
# Input: [installed_profile, admitted_tool_arguments]. The public schema
# applies first; no path from this plan is authority to open a host file.
def artifact_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > MAX_INPUT or length(o) < MAX_OUTPUT:
        return 4294967293
    put(o, 48, 64)
    put(o, 56, 8)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967293
    if kind(w, 0) != 5 or count(w, 0) != 2:
        return 4294967293
    installed = child(w, 0)
    args = next_node(w, installed)
    if kind(w, args) != 6 or count(w, args) != 4:
        return 4294967293
    if kind(w, installed) == 4:
        return catalog_observation(w, o, installed, field(w, args, KEY_catalog_sha256))
    if matches_digest(w, field(w, args, KEY_catalog_sha256)) == False:
        return 4294967293
    if valid_profile(w, installed) == False:
        return 4294967293
    requested = field(w, args, KEY_artifact_profile)
    if kind(w, requested) != 6 or count(w, requested) != 2:
        return 4294967293
    if valid_profile(w, requested) == False:
        return 4294967289
    observed = field(w, requested, KEY_sha256)
    expected = field(w, installed, KEY_sha256)
    if same_text(w, observed, expected) == False:
        return 4294967289
    data = field(w, args, KEY_source)
    if kind(w, data) != 6:
        return 4294967293
    operation = field(w, data, KEY_kind)
    if kind(w, operation) != 4:
        return 4294967293
    if same(w, node_start(w, operation), count(w, operation), INLINE) != 0:
        if count(w, data) != 2:
            return 4294967293
        return inline_data(o, w, field(w, data, KEY_text))
    if same(w, node_start(w, operation), count(w, operation), PATH_KIND) != 0:
        if count(w, data) != 4:
            return 4294967293
        return file_data(s, o, w, data)
    return 4294967293

def catalog_observation(w:mutbuf, o:mutbuf, pinned:u64, actual:u64) -> u64:
    if matches_digest(w, pinned) == False or kind(w, actual) != 4:
        return 4294967293
    size = count(w, actual)
    start = node_start(w, actual)
    if size != 64 and (size != 65 or byte(w, start + 64) != 10):
        return 4294967293
    index = 0
    while index < 64:
        unit = byte(w, start + index)
        if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
            return 4294967293
        store(o, 25 + index, unit)
        index = index + 1
    out = 89
    if size == 65:
        store(o, out, 92)
        store(o, out + 1, 110)
        out = out + 2
    put(o, 0, out - 23)
    put(o, 8, 66)
    put(o, 16, 0)
    store(o, 24, 34)
    store(o, out, 34)
    store(o, out + 1, 34)
    out = copy_node(w, o, pinned, out + 2)
    store(o, out, 34)
    return out + 1

def inline_data(o:mutbuf, w:mutbuf, text:u64) -> u64:
    if kind(w, text) != 4 or count(w, text) > 262144:
        return 4294967293
    if scalar_text(w, text, 65536) == False:
        return 4294967293
    plan(o, 1, 0, count(w, text), 0)
    return copy_node(w, o, text, 48)

def file_data(s:readbuf, o:mutbuf, w:mutbuf, object:u64) -> u64:
    path = field(w, object, KEY_path)
    limit = capture_limit(s, w, field(w, object, KEY_max_bytes))
    digest = field(w, object, KEY_expected_sha256)
    if limit == 0 or kind(w, path) != 4 or count(w, path) == 0 or count(w, path) > 16384:
        return 4294967293
    if scalar_text(w, path, 4096) == False or digest == NONE:
        return 4294967293
    pin_bytes = 0
    if kind(w, digest) != 0:
        if matches_digest(w, digest) == False:
            return 4294967293
        pin_bytes = 64
    plan(o, 2, limit, count(w, path), pin_bytes)
    at = copy_node(w, o, path, 48)
    if pin_bytes != 0:
        at = copy_node(w, o, digest, at)
    return at

def scalar_text(w:mutbuf, node:u64, limit:u64) -> bool:
    at = node_start(w, node)
    end = at + count(w, node)
    scalars = 0
    while at < end:
        ch = byte(w, at)
        if ch & 192 != 128:
            scalars = scalars + 1
            if scalars > limit:
                return False
        if ch == 237 and at + 1 < end and byte(w, at + 1) >= 160:
            return False
        at = at + 1
    return True

def valid_profile(w:mutbuf, node:u64) -> bool:
    if kind(w, node) != 6 or count(w, node) != 2:
        return False
    name = field(w, node, KEY_id)
    if kind(w, name) != 4 or same(w, node_start(w, name), count(w, name), ARTIFACT_PROFILE) == 0:
        return False
    return matches_digest(w, field(w, node, KEY_sha256))

def same_text(w:mutbuf, left:u64, right:u64) -> bool:
    size = count(w, left)
    if size != count(w, right):
        return False
    a = node_start(w, left)
    b = node_start(w, right)
    index = 0
    while index < size:
        if byte(w, a + index) != byte(w, b + index):
            return False
        index = index + 1
    return True

def matches_digest(w:mutbuf, node:u64) -> bool:
    if kind(w, node) != 4 or count(w, node) != 64:
        return False
    at = node_start(w, node)
    end = at + 64
    while at < end:
        ch = byte(w, at)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        at = at + 1
    return True

def capture_limit(s:readbuf, w:mutbuf, node:u64) -> u64:
    tag = kind(w, node)
    if tag != 3 and tag != 7:
        return 0
    size = count(w, node)
    at = node_start(w, node)
    end = at + size
    if tag == 7:
        # Admitted binary64 integers in [1, 8388608] have the canonical .0 wire form.
        if size < 3 or byte(s, end - 2) != 46 or byte(s, end - 1) != 48:
            return 0
        end = end - 2
    if end <= at or end - at > 7:
        return 0
    number = 0
    while at < end:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return 0
        number = number * 10 + ch - 48
        at = at + 1
    if number > 8388608:
        return 0
    return number

def plan(o:mutbuf, mode:u64, limit:u64, extent:u64, digest:u64) -> u64:
    put(o, 0, PLAN)
    put(o, 8, mode)
    put(o, 16, limit)
    put(o, 24, extent)
    put(o, 32, digest)
    put(o, 40, 0)
    return 0

def next_node(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 16)

def node_start(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 24)

def copy_node(w:mutbuf, o:mutbuf, node:u64, out:u64) -> u64:
    start = node_start(w, node)
    size = count(w, node)
    index = 0
    while index < size:
        store(o, out + index, byte(w, start + index))
        index = index + 1
    return out + size
'''


def source_program():
    literals = {
        'MAX_INPUT': [1 << 20], 'MAX_OUTPUT': [(4 << 16) + 512], 'NONE': [(1 << 64) - 1],
        'INLINE': packed('utf8'), 'PATH_KIND': packed('path'), 'ARTIFACT_PROFILE': packed('hia-artifact-v1'),
        'PLAN': [int.from_bytes(b'HIARAP01', 'little')],
    }
    literals.update(('KEY_' + key, [index]) for index, key in enumerate(KEYS, 1))
    source = POLICY
    for name, values in literals.items():
        source = re.sub(rf'\b{name}\b', ', '.join(map(str, values)), source)
    source += FRONTEND[FRONTEND.index('def kind('):FRONTEND.index('def shape(')]
    source += FRONTEND[FRONTEND.index('def same('):].split('\ndef ', 1)[0] + '\n'
    source += '\ndef key_id(w:mutbuf, node:u64) -> u64:\n'
    source += '    row = 64 + node * 56\n    start = get(w, row + 40)\n    size = get(w, row + 48)\n'
    for index, key in enumerate(KEYS, 1):
        words = ', '.join(map(str, packed(key)))
        source += f'    if same(w, start, size, {words}) != 0:\n        return {index}\n'
    return source + '    return 0\n' + json_decoder()


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'artifact_request')), encoding='utf-8')
