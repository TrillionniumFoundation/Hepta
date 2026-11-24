"""Author HIA admission of the MCP server's administrator-owned HIA profile.

The private JSON input contains configuration, default_state_dir and the
independently admitted catalog_sha256. This stage grants no filesystem effect:
the owner must first capture and authenticate the configuration and controller.
Unrelated runtime providers remain outside this HIA service's interface.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_json_decode import source_program as decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/mcp_service_config.hepta'
LIMIT = 8 << 20
OUTPUT_BYTES = 4 << 20
WORKSPACE_BYTES = 64 + 262144 * 72 + LIMIT
KEYS = (
    'configuration', 'default_state_dir', 'catalog_sha256', 'hia_worker', 'hosts',
    'state_dir', 'host', 'python_executable', 'working_directory', 'state_root',
    'artifact_roots', 'worker_sha256', 'backend_sha256', 'native_helpers_manifest',
    'native_helpers_sha256', 'timeout_seconds', 'memory_max_bytes', 'ssh_target',
    'platform', 'execution_mode', 'remote_state_dir', 'allow_execute', 'allow_write',
    'allow_job_network', 'allow_detached_fallback', 'allowed_cwd_prefixes',
    'allowed_read_path_prefixes', 'allowed_write_path_prefixes', 'protected_path_prefixes',
    'protected_argument_substrings', 'denied_executables', 'allowed_dangerous_executables',
    'native_jobs', 'entry', 'submit', 'observation', 'cancel', 'launcher', 'executable',
    'sha256', 'allow_pty', 'controller_workspace_roots', 'checkpoint_binary',
    'checkpoint_binary_sha256', 'privileged_actions', 'profile', 'aliases',
)
FIELD = {key: i + 1 for i, key in enumerate(KEYS)}

POLICY = r'''
def configuration(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > INPUT_CAP or length(o) != OUTPUT_CAP or length(w) != WORKSPACE_CAP:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    if get(w, 64) != 6 or get(w, 96) != 3:
        return REFUSAL
    config = lookup(w, 64, K_CONFIGURATION)
    default_state = lookup(w, 64, K_DEFAULT_STATE_DIR)
    catalog = lookup(w, 64, K_CATALOG_SHA256)
    if object(w, config) == False or normal_path(w, default_state, 0) == False or pin(w, catalog) == False:
        return REFUSAL
    hosts = lookup(w, config, K_HOSTS)
    profile = lookup(w, config, K_HIA_WORKER)
    if object(w, hosts) == False or get(w, hosts + 32) == 0 or object(w, profile) == False:
        return REFUSAL
    state = lookup(w, config, K_STATE_DIR)
    if state == NONE:
        state = default_state
    if normal_path(w, state, 0) == False:
        return REFUSAL
    host_name = lookup(w, profile, K_HOST)
    if name(w, host_name) == False:
        return REFUSAL
    host = named_host(w, hosts, host_name)
    if object(w, host) == False or hosts_shape(w, hosts) == False:
        return REFUSAL
    if host_policy(s, w, host) == False or profile_policy(s, w, profile, host, catalog) == False:
        return REFUSAL
    put(w, 48, 0)
    put(w, 56, 0)
    emit_byte(o, w, 123)
    emit_key(o, w, K_PROFILE)
    render_profile(s, o, w, profile)
    emit_byte(o, w, 44)
    emit_key(o, w, K_HOST)
    render_host(s, o, w, host)
    emit_byte(o, w, 44)
    emit_key(o, w, K_STATE_DIR)
    emit_node(s, o, w, state)
    emit_byte(o, w, 44)
    emit_key(o, w, K_ALIASES)
    render_aliases(s, o, w, hosts)
    emit_byte(o, w, 125)
    if get(w, 48) != 0:
        return 4294967293
    return get(w, 56)

def object(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6

def string(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 4

def named_host(w:mutbuf, hosts:u64, selected:u64) -> u64:
    node = get(w, hosts + 24)
    while node != NONE:
        row = 64 + node * 72
        if get(w, row + 48) == get(w, selected + 32) and same(w, get(w, row + 40), get(w, selected + 24), get(w, row + 48)):
            return row
        node = get(w, row + 16)
    return NONE

def hosts_shape(w:mutbuf, hosts:u64) -> bool:
    node = get(w, hosts + 24)
    while node != NONE:
        row = 64 + node * 72
        if object(w, row) == False or name_bytes(w, get(w, row + 40), get(w, row + 48)) == False:
            return False
        target = lookup(w, row, K_SSH_TARGET)
        if ssh_target(w, target) == False:
            return False
        node = get(w, row + 16)
    return True

def host_policy(s:readbuf, w:mutbuf, host:u64) -> bool:
    if literal(w, lookup(w, host, K_PLATFORM), 1, 1) == False:
        return False
    mode = lookup(w, host, K_EXECUTION_MODE)
    operator = literal(w, mode, 2, 0)
    if operator == False and literal(w, mode, 3, 1) == False:
        return False
    if flag(w, host, K_ALLOW_EXECUTE) != 1 or flag(w, host, K_ALLOW_WRITE) != 1:
        return False
    if flag(w, host, K_ALLOW_JOB_NETWORK) > 1 or flag(w, host, K_ALLOW_DETACHED_FALLBACK) > 1 or flag(w, host, K_ALLOW_PTY) > 1:
        return False
    if normal_path(w, lookup(w, host, K_REMOTE_STATE_DIR), 0) == False:
        return False
    field = K_ALLOWED_CWD_PREFIXES
    while field <= K_PROTECTED_PATH_PREFIXES:
        if string_array(w, lookup(w, host, field), 1) == False:
            return False
        field = field + 1
    field = K_PROTECTED_ARGUMENT_SUBSTRINGS
    while field <= K_ALLOWED_DANGEROUS_EXECUTABLES:
        if string_array(w, lookup(w, host, field), 0) == False:
            return False
        field = field + 1
    if operator:
        if flag(w, host, K_ALLOW_JOB_NETWORK) != 1:
            return False
        if count(w, lookup(w, host, K_ALLOWED_CWD_PREFIXES)) != 0 or count(w, lookup(w, host, K_PROTECTED_PATH_PREFIXES)) != 0:
            return False
        field = K_PROTECTED_ARGUMENT_SUBSTRINGS
        while field <= K_ALLOWED_DANGEROUS_EXECUTABLES:
            if count(w, lookup(w, host, field)) != 0:
                return False
            field = field + 1
    jobs = lookup(w, host, K_NATIVE_JOBS)
    if object(w, jobs) == False or get(w, jobs + 32) != 5:
        return False
    field = K_ENTRY
    while field <= K_LAUNCHER:
        role = lookup(w, jobs, field)
        if object(w, role) == False or get(w, role + 32) != 2:
            return False
        executable = lookup(w, role, K_EXECUTABLE)
        if normal_path(w, executable, 2) == False or pin(w, lookup(w, role, K_SHA256)) == False:
            return False
        if role_name(w, executable, field - K_ENTRY) == False:
            return False
        field = field + 1
    return True

def profile_policy(s:readbuf, w:mutbuf, profile:u64, host:u64, catalog:u64) -> bool:
    selected = lookup(w, profile, K_CATALOG_SHA256)
    if pin(w, selected) == False or same(w, get(w, selected + 24), get(w, catalog + 24), 64) == False:
        return False
    if pin(w, lookup(w, profile, K_WORKER_SHA256)) == False or pin(w, lookup(w, profile, K_BACKEND_SHA256)) == False:
        return False
    if unsigned_default(s, w, lookup(w, profile, K_TIMEOUT_SECONDS), 120, 1, 3600) == NONE:
        return False
    if unsigned_default(s, w, lookup(w, profile, K_MEMORY_MAX_BYTES), 1073741824, 67108864, 17179869184) == NONE:
        return False
    roots = lookup(w, profile, K_ARTIFACT_ROOTS)
    if string_array(w, roots, 0) == False or count(w, roots) > 32:
        return False
    field = K_PYTHON_EXECUTABLE
    while field <= K_STATE_ROOT:
        if admitted_path(w, lookup(w, profile, field), host) == False:
            return False
        field = field + 1
    node = choose(roots == NONE, NONE, get(w, roots + 24))
    while node != NONE:
        row = 64 + node * 72
        if admitted_path(w, row, host) == False:
            return False
        node = get(w, row + 16)
    state = lookup(w, profile, K_STATE_ROOT)
    cwd = lookup(w, profile, K_WORKING_DIRECTORY)
    if inside(w, state, lookup(w, host, K_ALLOWED_WRITE_PATH_PREFIXES)) == False:
        return False
    if prefix(w, state, cwd) or prefix(w, cwd, state):
        return False
    allowed_cwd = lookup(w, host, K_ALLOWED_CWD_PREFIXES)
    if count(w, allowed_cwd) != 0 and inside(w, cwd, allowed_cwd) == False:
        return False
    manifest = lookup(w, profile, K_NATIVE_HELPERS_MANIFEST)
    digest = lookup(w, profile, K_NATIVE_HELPERS_SHA256)
    manifest_absent = manifest == NONE or get(w, manifest) == 0
    digest_absent = digest == NONE or get(w, digest) == 0
    if manifest_absent != digest_absent:
        return False
    if manifest_absent == False:
        if admitted_path(w, manifest, host) == False or pin(w, digest) == False or prefix(w, manifest, state):
            return False
    return True

def admitted_path(w:mutbuf, node:u64, host:u64) -> bool:
    return normal_path(w, node, 1) and inside(w, node, lookup(w, host, K_ALLOWED_READ_PATH_PREFIXES)) and inside(w, node, lookup(w, host, K_PROTECTED_PATH_PREFIXES)) == False

def flag(w:mutbuf, parent:u64, key:u64) -> u64:
    node = lookup(w, parent, key)
    if node == NONE:
        return 0
    if get(w, node) == 1 or get(w, node) == 2:
        return get(w, node) - 1
    return 2

def count(w:mutbuf, node:u64) -> u64:
    if node == NONE:
        return 0
    return get(w, node + 32)

def unsigned_default(s:readbuf, w:mutbuf, node:u64, default:u64, minimum:u64, maximum:u64) -> u64:
    if node == NONE:
        return default
    if get(w, node) != 3:
        return NONE
    at = get(w, node + 24)
    size = get(w, node + 32)
    value = 0
    index = 0
    while index < size:
        ch = byte(s, at + index)
        if ch < 48 or ch > 57 or value > 1844674407370955161 or (value == 1844674407370955161 and ch > 53):
            return NONE
        value = value * 10 + ch - 48
        index = index + 1
    return choose(value >= minimum and value <= maximum, value, NONE)

def name(w:mutbuf, node:u64) -> bool:
    return string(w, node) and name_bytes(w, get(w, node + 24), get(w, node + 32))

def name_bytes(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 128:
        return False
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 46 and ch != 95 and ch != 45 and ch != 64:
            return False
        index = index + 1
    return True

def ssh_target(w:mutbuf, node:u64) -> bool:
    if string(w, node) == False or get(w, node + 32) == 0:
        return False
    at = get(w, node + 24)
    size = get(w, node + 32)
    if byte(w, at) == 45:
        return False
    meaningful = False
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if ch == 0 or ch == 10 or ch == 13:
            return False
        width = whitespace_width(w, at + index, size - index)
        if width == 0:
            meaningful = True
            width = 1
        index = index + width
    return meaningful

def whitespace_width(w:mutbuf, at:u64, size:u64) -> u64:
    ch = byte(w, at)
    if ch == 32 or (ch >= 9 and ch <= 13):
        return 1
    if size >= 2 and ch == 194 and (byte(w, at + 1) == 133 or byte(w, at + 1) == 160):
        return 2
    if size >= 3:
        word = match_word(w, at, 3)
        if word == 8428257 or word == 8421603 or word == 10453474:
            return 3
        if ch == 226 and byte(w, at + 1) == 128:
            end = byte(w, at + 2)
            if (end >= 128 and end <= 138) or end == 168 or end == 169 or end == 175:
                return 3
    return 0

def pin(w:mutbuf, node:u64) -> bool:
    if string(w, node) == False or get(w, node + 32) != 64:
        return False
    index = 0
    while index < 64:
        ch = byte(w, get(w, node + 24) + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True

def normal_path(w:mutbuf, node:u64, strict:u64) -> bool:
    if string(w, node) == False:
        return False
    at = get(w, node + 24)
    size = get(w, node + 32)
    if size == 0 or size > 4096 or byte(w, at) != 47:
        return False
    index = 1
    start = 1
    while index <= size:
        if index == size or byte(w, at + index) == 47:
            n = index - start
            if strict != 0 and ((n == 1 and byte(w, at + start) == 46) or (n == 2 and byte(w, at + start) == 46 and byte(w, at + start + 1) == 46)):
                return False
            if strict == 2 and n == 0:
                return False
            start = index + 1
        else:
            ch = byte(w, at + index)
            if ch == 0 or ch == 10 or ch == 13 or (strict == 2 and (ch < 32 or ch == 127)):
                return False
            if strict == 2 and ch == 194 and index + 1 < size and byte(w, at + index + 1) >= 128 and byte(w, at + index + 1) <= 159:
                return False
        index = index + 1
    return True

def string_array(w:mutbuf, node:u64, absolute:u64) -> bool:
    if node == NONE:
        return True
    if get(w, node) != 5:
        return False
    child = get(w, node + 24)
    while child != NONE:
        row = 64 + child * 72
        if string(w, row) == False:
            return False
        if absolute != 0:
            if get(w, row + 32) == 0 or byte(w, get(w, row + 24)) != 47:
                return False
        child = get(w, row + 16)
    return True

def prefix(w:mutbuf, path:u64, root:u64) -> bool:
    if string(w, path) == False or string(w, root) == False:
        return False
    a = get(w, path + 24)
    b = get(w, root + 24)
    an = get(w, path + 32)
    bn = get(w, root + 32)
    if an == 0 or bn == 0 or byte(w, a) != 47 or byte(w, b) != 47:
        return False
    ai = 1
    bi = 1
    while True:
        bi = next_component(w, b, bn, bi)
        if bi == bn:
            return True
        ai = next_component(w, a, an, ai)
        if ai == an:
            return False
        ae = end_component(w, a, an, ai)
        be = end_component(w, b, bn, bi)
        if ae - ai != be - bi or same(w, a + ai, b + bi, ae - ai) == False:
            return False
        ai = ae
        bi = be
    return False

def next_component(w:mutbuf, at:u64, size:u64, index:u64) -> u64:
    while index < size:
        if byte(w, at + index) == 47:
            index = index + 1
        elif byte(w, at + index) == 46 and (index + 1 == size or byte(w, at + index + 1) == 47):
            index = index + 1
        else:
            return index
    return index

def end_component(w:mutbuf, at:u64, size:u64, index:u64) -> u64:
    while index < size and byte(w, at + index) != 47:
        index = index + 1
    return index

def inside(w:mutbuf, node:u64, roots:u64) -> bool:
    if roots == NONE:
        return False
    child = get(w, roots + 24)
    while child != NONE:
        row = 64 + child * 72
        if prefix(w, node, row):
            return True
        child = get(w, row + 16)
    return False

def same(w:mutbuf, a:u64, b:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(w, a + index) != byte(w, b + index):
            return False
        index = index + 1
    return True

def literal(w:mutbuf, node:u64, expected:u64, absent:u64) -> bool:
    if node == NONE:
        return absent != 0
    return string(w, node) and value_id(w, get(w, node + 24), get(w, node + 32)) == expected

def role_name(w:mutbuf, node:u64, role:u64) -> bool:
    at = get(w, node + 24)
    size = get(w, node + 32)
    index = size
    while index > 0 and byte(w, at + index - 1) != 47:
        index = index - 1
    return value_id(w, at + index, size - index) == role + 4

def emit_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, 56)
    if at < length(o):
        store(o, at, value)
    else:
        put(w, 48, 1)
    put(w, 56, at + 1)
    return 0

def emit_word(o:mutbuf, w:mutbuf, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        emit_byte(o, w, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def emit_node(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    at = get(w, node + 56)
    size = get(w, node + 64)
    if get(w, node) <= 3:
        at = get(w, node + 24)
        size = get(w, node + 32)
    index = 0
    while index < size:
        emit_byte(o, w, byte(s, at + index))
        index = index + 1
    return 0

def emit_default(s:readbuf, o:mutbuf, w:mutbuf, parent:u64, key:u64, default:u64) -> u64:
    emit_key(o, w, key)
    node = lookup(w, parent, key)
    if node != NONE:
        return emit_node(s, o, w, node)
    return emit_literal(o, w, default)

def render_aliases(s:readbuf, o:mutbuf, w:mutbuf, hosts:u64) -> u64:
    emit_byte(o, w, 91)
    child = get(w, hosts + 24)
    while child != NONE:
        row = 64 + child * 72
        emit_byte(o, w, 91)
        emit_byte(o, w, 34)
        index = 0
        while index < get(w, row + 48):
            emit_byte(o, w, byte(w, get(w, row + 40) + index))
            index = index + 1
        emit_byte(o, w, 34)
        emit_byte(o, w, 44)
        emit_node(s, o, w, lookup(w, row, K_SSH_TARGET))
        emit_byte(o, w, 93)
        child = get(w, row + 16)
        if child != NONE:
            emit_byte(o, w, 44)
    emit_byte(o, w, 93)
    return 0
'''


def dispatch_writer(name, items):
    lines = [f'def {name}(o:mutbuf, w:mutbuf, key:u64) -> u64:']
    for index, raw in items:
        lines.append(f'    if key == {index}:')
        for at in range(0, len(raw), 8):
            part = raw[at:at + 8]
            lines.append(f'        emit_word(o, w, {int.from_bytes(part, "little")}, {len(part)})')
        lines.append('        return 0')
    lines.append('    return 0')
    return '\n'.join(lines)


def object_renderer(name, fields, optional=()):
    lines = [f'def {name}(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:',
             '    emit_byte(o, w, 123)']
    for i, (key, default) in enumerate(fields):
        if i:
            lines.append('    emit_byte(o, w, 44)')
        lines.append(f'    emit_default(s, o, w, parent, {FIELD[key]}, {default})')
    for key in optional:
        lines += [f'    node = lookup(w, parent, {FIELD[key]})',
                  '    if node != NONE and get(w, node) != 0:',
                  '        emit_byte(o, w, 44)', f'        emit_key(o, w, {FIELD[key]})',
                  '        emit_node(s, o, w, node)']
    lines += ['    emit_byte(o, w, 125)', '    return 0']
    return '\n'.join(lines)


def key_table():
    groups = {}
    for key, index in FIELD.items():
        groups.setdefault(len(key), []).append((key.encode(), index))
    lines = ['def key_id(w:mutbuf, at:u64, extent:u64) -> u64:']
    for size, rows in groups.items():
        lines.append(f'    if extent == {size}:')
        for raw, index in rows:
            words = [f'(match_word(w, at + {at}, {len(raw[at:at + 8])}) ^ {int.from_bytes(raw[at:at + 8], "little")})'
                     for at in range(0, len(raw), 8)]
            lines += ['        if (' + ' | '.join(words) + ') == 0:', f'            return {index}']
    lines.append('    return 0')
    return '\n'.join(lines)


def source_program():
    import re
    profile = [('artifact_roots', 1), ('backend_sha256', 0), ('catalog_sha256', 0),
               ('host', 0), ('memory_max_bytes', 5), ('python_executable', 0),
               ('state_root', 0), ('timeout_seconds', 4), ('worker_sha256', 0),
               ('working_directory', 0)]
    host = [('ssh_target', 0), ('remote_state_dir', 0), ('platform', 2), ('execution_mode', 3),
            ('allow_execute', 6), ('allow_write', 6), ('allow_job_network', 6),
            ('allow_detached_fallback', 6), ('allow_pty', 6), ('allowed_cwd_prefixes', 1),
            ('allowed_read_path_prefixes', 1), ('allowed_write_path_prefixes', 1),
            ('protected_path_prefixes', 1), ('protected_argument_substrings', 1),
            ('denied_executables', 1), ('allowed_dangerous_executables', 1), ('native_jobs', 0)]
    values = {'INPUT_CAP': LIMIT, 'OUTPUT_CAP': OUTPUT_BYTES, 'WORKSPACE_CAP': WORKSPACE_BYTES,
              'REFUSAL': 4294967280, 'NONE': (1 << 64) - 1,
              **{'K_' + key.upper(): index for key, index in FIELD.items()}}
    parts = [POLICY, WIRE_HELPERS, object_renderer('render_profile', profile,
             ('native_helpers_manifest', 'native_helpers_sha256')), object_renderer('render_host', host)]
    source = '\n'.join(parts)
    for key in sorted(values, key=len, reverse=True):
        source = re.sub(r'\b' + key + r'\b', str(values[key]), source)
    source += '\n' + dispatch_writer('emit_key', [(index, ('"' + key + '":').encode()) for key, index in FIELD.items()])
    source += '\n' + dispatch_writer('emit_literal', [(0, b'null'), (1, b'[]'), (2, b'"linux"'),
                         (3, b'"isolated"'), (4, b'120'), (5, b'1073741824'), (6, b'false')])
    source += '\n' + key_table()
    source += '\n' + comparison_table('value_id', ('linux', 'operator', 'isolated', 'hia-job-entry',
                           'hia-job-submit', 'hia-job-observation', 'hia-job-cancel', 'hia-job-launch'))
    return source + '\n' + decoder(wire_spans=True)


def render():
    return render_assembly(document(source_program(), 'mcp_service_config'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
