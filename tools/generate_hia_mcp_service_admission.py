"""Author original HIA catalog, artifact-path and resource-URI admission.

The native owner supplies the authenticated administrative context and tool
ordinal. The caller's canonical arguments are preserved except the original
registered-SSH artifact-path normalization. Schema admission is a separate
mandatory stage before durable job submission.
"""
import ast
import re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_mcp_service_config import KEYS as CONFIG_KEYS, source_program as config_source
from tools.generate_hia_json_decode import source_program as decoder

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/mcp_service_admission.hepta'
LIMIT = 8 << 20
OUTPUT_BYTES = 512 << 10
WORKSPACE_BYTES = 64 + 262144 * 72 + LIMIT
KEYS = (*CONFIG_KEYS, 'context', 'arguments', 'tool', 'source', 'kind', 'path', 'uri', 'max_bytes')
FIELD = {key: i + 1 for i, key in enumerate(KEYS)}
REFUSED = 4294967264
CATALOG_CHANGED = REFUSED + 1
CAPTURE_REFUSED = REFUSED + 2
RESOURCE_REFUSED = REFUSED + 3

POLICY = r'''
def admission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_CAP or length(o) != OUTPUT_CAP or length(w) != WORKSPACE_CAP:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    if get(w, 64) != 6 or get(w, 96) != 3:
        return REFUSAL
    context = lookup(w, 64, K_CONTEXT)
    args = lookup(w, 64, K_ARGUMENTS)
    role = unsigned_default(s, w, lookup(w, 64, K_TOOL), 0, 1, 12)
    if object(w, context) == False or object(w, args) == False or role == 0 or role == NONE:
        return REFUSAL
    if get(w, args + 64) > OUTPUT_CAP:
        return REFUSAL
    profile = lookup(w, context, K_PROFILE)
    host = lookup(w, context, K_HOST)
    if object(w, profile) == False or object(w, host) == False:
        return REFUSAL
    if role != 1 and role != 12:
        required = lookup(w, profile, K_CATALOG_SHA256)
        observed = lookup(w, args, K_CATALOG_SHA256)
        if string(w, required) == False or string(w, observed) == False:
            return CATALOG_REFUSAL
        if get(w, required + 32) != 64 or get(w, observed + 32) != 64 or same(w, get(w, required + 24), get(w, observed + 24), 64) == False:
            return CATALOG_REFUSAL
    if role == 12:
        if resource(s, w, args) == False:
            return RESOURCE_REFUSAL
    if role != 2:
        return copy_argument(s, o, w, args)
    return artifact(s, o, w, context, args)

def resource(s:readbuf, w:mutbuf, args:u64) -> bool:
    uri = lookup(w, args, K_URI)
    if string(w, uri) == False:
        return False
    at = get(w, uri + 24)
    size = get(w, uri + 32)
    if size < 17 or size > 208 or match_word(w, at, 8) != URI_HEAD or match_word(w, at + 8, 8) != URI_TAIL:
        return False
    index = 16
    while index < size:
        ch = byte(w, at + index)
        alnum = (ch >= 48 and ch <= 57) or (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122)
        if alnum == False and (index == 16 or (ch != 46 and ch != 95 and ch != 126 and ch != 45)):
            return False
        index = index + 1
    if unsigned_default(s, w, lookup(w, args, K_MAX_BYTES), 65536, 512, 65536) == NONE:
        return False
    child = get(w, args + 24)
    while child != NONE:
        row = 64 + child * 72
        key = key_id(w, get(w, row + 40), get(w, row + 48))
        if key != K_URI and key != K_MAX_BYTES:
            return False
        child = get(w, row + 16)
    return True

def artifact(s:readbuf, o:mutbuf, w:mutbuf, context:u64, args:u64) -> u32:
    source = lookup(w, args, K_SOURCE)
    if object(w, source) == False:
        return CAPTURE_REFUSAL
    kind = lookup(w, source, K_KIND)
    if string(w, kind) == False:
        return CAPTURE_REFUSAL
    if get(w, kind + 32) != 4 or match_word(w, get(w, kind + 24), 4) != 1752457584:
        return copy_argument(s, o, w, args)
    path = lookup(w, source, K_PATH)
    profile = lookup(w, context, K_PROFILE)
    host = lookup(w, context, K_HOST)
    if string(w, path) == False:
        return CAPTURE_REFUSAL
    put(w, 0, get(w, path + 24))
    put(w, 8, get(w, path + 32))
    selected = lookup(w, profile, K_HOST)
    if string(w, selected) == False:
        return REFUSAL
    put(w, 16, get(w, selected + 24))
    put(w, 24, get(w, selected + 32))
    if resolve(w) == False or alias_allowed(w, lookup(w, context, K_ALIASES), selected) == False:
        return CAPTURE_REFUSAL
    # Replace only the private decoded string view for path policy. The raw
    # original span stays intact for the final wire edit and original digest.
    put(w, path + 24, get(w, 0))
    put(w, path + 32, get(w, 8))
    if normal_path(w, path, 1) == False or inside(w, path, lookup(w, profile, K_ARTIFACT_ROOTS)) == False:
        return CAPTURE_REFUSAL
    if inside(w, path, lookup(w, host, K_ALLOWED_READ_PATH_PREFIXES)) == False or inside(w, path, lookup(w, host, K_PROTECTED_PATH_PREFIXES)):
        return CAPTURE_REFUSAL
    put(w, 48, 0)
    put(w, 56, 0)
    copy(s, o, w, get(w, args + 56), get(w, path + 56) - get(w, args + 56))
    quote(o, w, get(w, path + 24), get(w, path + 32))
    after = get(w, path + 56) + get(w, path + 64)
    copy(s, o, w, after, get(w, args + 56) + get(w, args + 64) - after)
    return choose(get(w, 48) == 0, get(w, 56), REFUSAL)

def resolve(w:mutbuf) -> bool:
    at = get(w, 0)
    size = get(w, 8)
    if size == 0:
        return False
    if byte(w, at) == 47:
        return True
    scheme = 0
    if size >= 6 and match_word(w, at, 6) == SSH_SCHEME:
        scheme = 6
    if size >= 7 and match_word(w, at, 7) == SFTP_SCHEME:
        scheme = 7
    if scheme == 0:
        return False
    index = scheme
    while index < size:
        if byte(w, at + index) == 64:
            return False
        index = index + 1
    end = scheme
    while end < size and byte(w, at + end) != 47:
        end = end + 1
    if end == scheme:
        return False
    put(w, 16, at + scheme)
    put(w, 24, end - scheme)
    if end == size:
        store(w, 32, 47)
        store(w, 33, 126)
        put(w, 0, 32)
        put(w, 8, 2)
    else:
        put(w, 0, at + end)
        put(w, 8, size - end)
    return authority(w)

def authority(w:mutbuf) -> bool:
    at = get(w, 16)
    size = get(w, 24)
    if byte(w, at) == 91:
        index = 1
        while index < size:
            if byte(w, at + index) == 93:
                if index + 1 < size and byte(w, at + index + 1) == 58:
                    return False
                put(w, 16, at + 1)
                put(w, 24, index - 1)
                return True
            index = index + 1
        return True
    index = 0
    while index < size:
        if byte(w, at + index) == 58:
            return False
        index = index + 1
    return True

def alias_allowed(w:mutbuf, aliases:u64, selected:u64) -> bool:
    if aliases == NONE or get(w, aliases) != 5:
        return False
    item = get(w, aliases + 24)
    best = NONE
    while item != NONE:
        pair = 64 + item * 72
        if get(w, pair) != 5 or get(w, pair + 32) != 2:
            return False
        name = 64 + get(w, pair + 24) * 72
        target = 64 + get(w, name + 16) * 72
        if string(w, name) == False or string(w, target) == False:
            return False
        if matches_alias(w, name) or matches_alias(w, target):
            if best == NONE or string_less(w, name, best):
                best = name
        item = get(w, pair + 16)
    return best != NONE and get(w, best + 32) == get(w, selected + 32) and same(w, get(w, best + 24), get(w, selected + 24), get(w, best + 32))

def matches_alias(w:mutbuf, node:u64) -> bool:
    return get(w, node + 32) == get(w, 24) and same(w, get(w, node + 24), get(w, 16), get(w, 24))

def string_less(w:mutbuf, a:u64, b:u64) -> bool:
    size = choose(get(w, a + 32) < get(w, b + 32), get(w, a + 32), get(w, b + 32))
    index = 0
    while index < size:
        left = byte(w, get(w, a + 24) + index)
        right = byte(w, get(w, b + 24) + index)
        if left != right:
            return left < right
        index = index + 1
    return get(w, a + 32) < get(w, b + 32)

def copy_argument(s:readbuf, o:mutbuf, w:mutbuf, args:u64) -> u32:
    put(w, 48, 0)
    put(w, 56, 0)
    copy(s, o, w, get(w, args + 56), get(w, args + 64))
    return choose(get(w, 48) == 0, get(w, 56), REFUSAL)

def copy(s:readbuf, o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:
    index = 0
    while index < size:
        emit_byte(o, w, byte(s, start + index))
        index = index + 1
    return 0

def quote(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    emit_byte(o, w, 34)
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if ch == 34 or ch == 92:
            emit_byte(o, w, 92)
        if ch < 32:
            emit_byte(o, w, 92)
            escape = choose(ch == 8, 98, choose(ch == 9, 116, choose(ch == 10, 110, choose(ch == 12, 102, choose(ch == 13, 114, 0)))))
            if escape != 0:
                emit_byte(o, w, escape)
            else:
                emit_byte(o, w, 117)
                emit_byte(o, w, 48)
                emit_byte(o, w, 48)
                emit_byte(o, w, digit(ch >> 4))
                emit_byte(o, w, digit(ch & 15))
        else:
            emit_byte(o, w, ch)
        index = index + 1
    emit_byte(o, w, 34)
    return 0

def digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)
'''


def source_program():
    imported = config_source()
    nodes = {node.name: node for node in ast.parse(imported).body}
    own = ast.parse(POLICY).body
    own_names = {node.name for node in own}
    required = set()
    pending = own[:]
    while pending:
        node = pending.pop()
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                name = call.func.id
                if name in nodes and name not in own_names and name not in required and name != 'key_id':
                    required.add(name)
                    pending.append(nodes[name])
    # Keep the independently generated decoder as one original unit below.
    decoder_names = {node.name for node in ast.parse(decoder(wire_spans=True)).body}
    required -= decoder_names
    source = POLICY + '\n' + '\n\n'.join(ast.get_source_segment(imported, nodes[name])
                                           for name in nodes if name in required)
    groups = {}
    for key, index in FIELD.items():
        groups.setdefault(len(key), []).append((key.encode(), index))
    source += '\ndef key_id(w:mutbuf, at:u64, extent:u64) -> u64:\n'
    for size, rows in groups.items():
        source += f'    if extent == {size}:\n'
        for raw, index in rows:
            words = [f'(match_word(w, at + {at}, {len(raw[at:at + 8])}) ^ {int.from_bytes(raw[at:at + 8], "little")})'
                     for at in range(0, len(raw), 8)]
            source += '        if (' + ' | '.join(words) + f') == 0:\n            return {index}\n'
    source += '    return 0\n'
    values = {'INPUT_CAP': LIMIT, 'OUTPUT_CAP': OUTPUT_BYTES, 'WORKSPACE_CAP': WORKSPACE_BYTES,
              'NONE': (1 << 64) - 1, 'REFUSAL': REFUSED, 'CATALOG_REFUSAL': CATALOG_CHANGED,
              'CAPTURE_REFUSAL': CAPTURE_REFUSED, 'RESOURCE_REFUSAL': RESOURCE_REFUSED,
              'SSH_SCHEME': int.from_bytes(b'ssh://', 'little'),
              'SFTP_SCHEME': int.from_bytes(b'sftp://', 'little'),
              'URI_HEAD': int.from_bytes(b'hia://ar', 'little'),
              'URI_TAIL': int.from_bytes(b'tifacts/', 'little'),
              **{'K_' + key.upper(): index for key, index in FIELD.items()}}
    for key in sorted(values, key=len, reverse=True):
        source = re.sub(r'\b' + key + r'\b', str(values[key]), source)
    return source + '\n' + decoder(wire_spans=True)


def render():
    return render_assembly(document(source_program(), 'mcp_service_admission'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
