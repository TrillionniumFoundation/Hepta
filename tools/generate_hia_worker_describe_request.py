"""Author the Worker-to-discovery frame without a host JSON projection."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_json_frontend import FRONTEND, packed
from tools.generate_hia_json_decode import source_program as json_decoder

SOURCE = 'examples/hia_bootstrap/worker_describe_request.hepta'
BACKEND = b'hia-backend-v1'
WORKER_SCHEMA = 'hia-agent-worker-request-v1'
KEYS = ('arguments', 'catalog_sha256', 'profile_sha256', 'schema', 'tool',
        'section', 'backend_profile', 'language_schema', 'cursor', 'max_bytes')

POLICY = r'''
def describe_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 16384 or length(o) < 8192 or length(w) < 32768:
        return 4294967294
    put(o, 48, 64)
    put(o, 56, 8)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 4294967295
    if kind(w, 0) != 6 or count(w, 0) != 5:
        return 4294967279
    args = field(w, 0, KEY_arguments)
    schema = field(w, 0, KEY_schema)
    tool = field(w, 0, KEY_tool)
    if kind(w, args) != 6 or kind(w, schema) != 4 or kind(w, tool) != 4:
        return 4294967279
    if same(w, node_start(w, tool), count(w, tool), TOOL) == 0:
        return 4294967275
    if count(w, schema) != SCHEMA_BYTES:
        return 4294967278
    schema_at = node_start(w, schema)
    if same(w, schema_at, 24, SCHEMA_FIRST) == 0:
        return 4294967278
    if same(w, schema_at + 24, SCHEMA_BYTES - 24, SCHEMA_LAST) == 0:
        return 4294967278
    if valid_pin(w, field(w, 0, KEY_catalog_sha256)) == False or valid_pin(w, field(w, 0, KEY_profile_sha256)) == False:
        return 4294967277
    section = field(w, args, KEY_section)
    requested = field(w, args, KEY_backend_profile)
    language = field(w, args, KEY_language_schema)
    cursor = field(w, args, KEY_cursor)
    maximum = field(w, args, KEY_max_bytes)
    if valid_text(w, section, 11) == False:
        return 4294967279
    flags = 0
    fields = 1
    if cursor != NONE:
        if valid_text(w, cursor, 2048) == False:
            return 4294967279
        flags = flags | 1
        fields = fields + 1
    requested_size = 0
    if requested != NONE:
        if valid_text(w, requested, 768) == False:
            return 4294967279
        requested_size = count(w, requested)
        flags = flags | 2
        fields = fields + 1
    language_size = 0
    if language != NONE:
        if valid_text(w, language, 512) == False:
            return 4294967279
        language_size = count(w, language)
        flags = flags | 4
        fields = fields + 1
    if maximum != NONE:
        if valid_bound(s, w, maximum) == False:
            return 4294967279
        fields = fields + 1
    if fields != count(w, args):
        return 4294967279
    put(o, 0, DISCOVERY_MAGIC)
    put(o, 8, flags)
    put(o, 16, count(w, section))
    put(o, 24, requested_size)
    put(o, 32, BACKEND_BYTES)
    put(o, 40, language_size)
    at = copy_text(w, o, section, 48)
    if requested_size != 0:
        at = copy_text(w, o, requested, at)
    at = installed_backend(o, at)
    if language_size != 0:
        at = copy_text(w, o, language, at)
    return at

def valid_text(w:mutbuf, node:u64, maximum:u64) -> bool:
    return kind(w, node) == 4 and count(w, node) > 0 and count(w, node) <= maximum

def valid_pin(w:mutbuf, node:u64) -> bool:
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

def valid_bound(s:readbuf, w:mutbuf, node:u64) -> bool:
    size = count(w, node)
    if kind(w, node) != 3 or size < 3 or size > 5:
        return False
    at = node_start(w, node)
    total = 0
    end = at + size
    while at < end:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return False
        total = total * 10 + ch - 48
        at = at + 1
    return total >= 512 and total <= 65536

def next_node(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 16)

def node_start(w:mutbuf, node:u64) -> u64:
    return get(w, 64 + node * 56 + 24)

def copy_text(w:mutbuf, o:mutbuf, node:u64, out:u64) -> u64:
    start = node_start(w, node)
    size = count(w, node)
    at = 0
    while at < size:
        store(o, out + at, byte(w, start + at))
        at = at + 1
    return out + size
'''


def source_program():
    literals = {'NONE': [(1 << 64) - 1], 'TOOL': packed('hia_describe'), 'SCHEMA_BYTES': [len(WORKER_SCHEMA)],
                'SCHEMA_FIRST': packed(WORKER_SCHEMA[:24]), 'SCHEMA_LAST': packed(WORKER_SCHEMA[24:]),
                'DISCOVERY_MAGIC': [int.from_bytes(b'HIADIS01', 'little')], 'BACKEND_BYTES': [len(BACKEND)]}
    source = POLICY
    for name, words in literals.items():
        source = re.sub(rf'\b{name}\b', ', '.join(map(str, words)), source)
    source += '\ndef installed_backend(o:mutbuf, at:u64) -> u64:\n'
    for index, value in enumerate(BACKEND):
        source += f'    store(o, at + {index}, {value})\n'
    source += f'    return at + {len(BACKEND)}\n'
    source += FRONTEND[FRONTEND.index('def kind('):FRONTEND.index('def shape(')]
    source += FRONTEND[FRONTEND.index('def same('):].split('\ndef ', 1)[0] + '\n'
    source += '\ndef key_id(w:mutbuf, node:u64) -> u64:\n'
    source += '    row = 64 + node * 56\n    start = get(w, row + 40)\n    size = get(w, row + 48)\n'
    for index, key in reversed(tuple(enumerate(KEYS, 1))):
        source = source.replace('KEY_' + key, str(index))
        source += f'    if same(w, start, size, {", ".join(map(str, packed(key)))}) != 0:\n        return {index}\n'
    return source + '    return 0\n' + json_decoder()


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'worker_describe_request')),
                            encoding='utf-8')
