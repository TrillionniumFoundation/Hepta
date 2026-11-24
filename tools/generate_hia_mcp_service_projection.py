"""Typed administrator configuration projection in HIA.

RuntimeConfig, HostConfig and PrivilegedAction ignore unknown fields using
serde's IgnoredAny grammar. HiaWorkerProfile and native role pins deny them.
The process keeps the original authenticated bytes; this is a derived view.
The hosts and privileged-actions maps retain their last decoded string key.
Every overwritten struct still passes deserialization before replacement.
"""
from tools.generate_hia_mcp_service_config import FIELD
from tools.generate_hia_mcp_typed_json import IGNORED_VALUE

PROJECT_FIELDS = dict(FIELD)
for _name in ('weight_workers', 'rea_static_profiles', 'fixed_args',
              'allow_extra_args', 'extra_arg_patterns'):
    PROJECT_FIELDS.setdefault(_name, len(PROJECT_FIELDS) + 1)

STRUCT_FIELDS = {
    0: ('state_dir', 'controller_workspace_roots', 'hosts', 'hia_worker',
        'weight_workers', 'rea_static_profiles'),
    2: ('native_jobs', 'checkpoint_binary', 'checkpoint_binary_sha256',
        'execution_mode', 'ssh_target', 'platform', 'remote_state_dir',
        'allow_execute', 'allow_pty', 'allow_write', 'allow_job_network',
        'allow_detached_fallback', 'allowed_cwd_prefixes',
        'allowed_read_path_prefixes', 'allowed_write_path_prefixes',
        'protected_path_prefixes', 'protected_argument_substrings',
        'denied_executables', 'allowed_dangerous_executables', 'privileged_actions'),
    3: ('host', 'python_executable', 'working_directory', 'state_root',
        'artifact_roots', 'worker_sha256', 'backend_sha256', 'catalog_sha256',
        'native_helpers_manifest', 'native_helpers_sha256', 'timeout_seconds',
        'memory_max_bytes'),
    5: ('executable', 'fixed_args', 'allow_extra_args', 'extra_arg_patterns',
        'timeout_seconds'),
    6: ('entry', 'submit', 'observation', 'cancel', 'launcher'),
    7: ('executable', 'sha256'),
}
REQUIRED_FIELDS = {
    2: ('ssh_target', 'remote_state_dir'),
    3: ('host', 'python_executable', 'working_directory', 'state_root',
        'worker_sha256', 'backend_sha256', 'catalog_sha256'),
    5: ('executable',),
    6: STRUCT_FIELDS[6],
    7: STRUCT_FIELDS[7],
}

# Projection output, hash table, key bytes and insertion records do not overlap
# input, JSON arena, JSON scratch, role images, or the lifetime lease.
CONSTANTS = dict(PROJECT=304 << 20, PROJECT_END=312 << 20,
                 PROJECT_MAP=320 << 20, PROJECT_KEYS=336 << 20,
                 PROJECT_KEYS_END=344 << 20, PROJECT_RECORDS=344 << 20,
                 PROJECT_FRAMES=45056, PROJECT_SLOTS=262144,
                 PROJECT_RECORD_CAP=262144)

SOURCE = r'''
def project_start(o:mutbuf, w:mutbuf) -> u32:
    put(w, 1720, CONFIG_RAW)
    put(w, 1728, 0)
    put(w, 1736, PROJECT)
    put(w, 1744, 0)
    put(w, 1800, PROJECT_KEYS)
    put(w, 1808, 0)
    put(w, 1816, 0)
    put(w, 1824, CONFIG_RAW + get(w, 320))
    return project_open(o, w, 0)

def project_frame(w:mutbuf) -> u64:
    return PROJECT_FRAMES + (get(w, 1744) - 1) * 96

def project_byte(w:mutbuf, value:u64) -> bool:
    at = get(w, 1736)
    if at >= PROJECT_END:
        return False
    store(w, at, value)
    put(w, 1736, at + 1)
    return True

def project_copy(w:mutbuf, start:u64, size:u64) -> bool:
    at = get(w, 1736)
    if size > PROJECT_END - at:
        return False
    put(w, 1736, copy_state(w, start, at, size))
    return True

def project_open(o:mutbuf, w:mutbuf, kind:u64) -> u32:
    at = ignored_space(w, get(w, 1720), get(w, 1824))
    if at == get(w, 1824) or byte(w, at) != 123 or get(w, 1744) >= 8:
        return 0
    frame = PROJECT_FRAMES + get(w, 1744) * 96
    put(w, frame, kind)
    put(w, frame + 8, 0)
    put(w, frame + 16, get(w, 1736))
    put(w, frame + 24, 0)
    put(w, frame + 40, get(w, 1808))
    put(w, frame + 48, 0)
    put(w, frame + 56, 0)
    put(w, 1744, get(w, 1744) + 1)
    if kind == 1 or kind == 4:
        put(w, 1816, get(w, 1816) + 1)
        put(w, frame + 72, get(w, 1816))
    if project_byte(w, 123) == False:
        return 0
    at = ignored_space(w, at + 1, get(w, 1824))
    if at < get(w, 1824) and byte(w, at) == 125:
        put(w, 1720, at + 1)
        return project_close(o, w)
    return project_key(o, w, at)

def project_key(o:mutbuf, w:mutbuf, at:u64) -> u32:
    end = ignored_string(w, at, get(w, 1824))
    if end == NONE:
        return 0
    put(w, 1752, at)
    put(w, 1760, end)
    return decode(o, w, 100, at, end - at)

def project_key_ready(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result >= 4294967292 or get(w, ARENA + 64) != 4:
        return 0
    frame = project_frame(w)
    kind = get(w, frame)
    key = project_key_id(w, ARENA + get(w, ARENA + 88), get(w, ARENA + 96))
    known = project_mask(kind)
    at = ignored_space(w, get(w, 1760), get(w, 1824))
    if at == get(w, 1824) or byte(w, at) != 58:
        return 0
    at = ignored_space(w, at + 1, get(w, 1824))
    if at == get(w, 1824):
        return 0
    put(w, 1784, key)
    if kind != 1 and kind != 4:
        if key == 0 or (known >> key) & 1 == 0:
            if kind == 3 or kind == 6 or kind == 7:
                return 0
            end = ignored_value(w, at, get(w, 1824), SCRATCH, SCRATCH_BYTES)
            if end == NONE:
                return 0
            put(w, 1720, end)
            return project_next(o, w)
        bit = 1 << key
        if get(w, frame + 8) & bit != 0:
            return 0
        put(w, frame + 8, get(w, frame + 8) | bit)
    elif project_map_key(w, frame) == False:
        return 0
    if get(w, frame + 24) != 0 and project_byte(w, 44) == False:
        return 0
    put(w, frame + 32, get(w, 1736))
    if project_copy(w, get(w, 1752), get(w, 1760) - get(w, 1752)) == False or project_byte(w, 58) == False:
        return 0
    put(w, frame + 24, get(w, frame + 24) + 1)
    put(w, 1720, at)
    child = project_child(kind, key)
    if child != NONE:
        if byte(w, at) == 110 and (key == K_HIA_WORKER or key == K_NATIVE_JOBS):
            child = NONE
        else:
            return project_open(o, w, child)
    end = ignored_value(w, at, get(w, 1824), SCRATCH, SCRATCH_BYTES)
    if end == NONE:
        return 0
    put(w, 1776, end)
    return decode(o, w, 101, at, end - at)

def project_leaf_ready(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result >= 4294967292 or project_type(w, get(w, project_frame(w)), get(w, 1784)) == False:
        return 0
    key = get(w, 1784)
    if (key == K_PLATFORM or key == K_EXECUTION_MODE) and get(w, ARENA + 64) == 6:
        row = ARENA + 64 + get(w, ARENA + 88) * 72
        value = project_enum_id(w, ARENA + get(w, row + 40), get(w, row + 48))
        if project_enum_write(w, value) == False:
            return 0
    else:
        if project_copy(w, get(w, 1720), get(w, 1776) - get(w, 1720)) == False:
            return 0
    put(w, 1720, get(w, 1776))
    return project_next(o, w)

def project_next(o:mutbuf, w:mutbuf) -> u32:
    frame = project_frame(w)
    kind = get(w, frame)
    if (kind == 1 or kind == 4) and get(w, frame + 48) != 0:
        slot = get(w, frame + 48)
        record = PROJECT_RECORDS + get(w, 1808) * 32
        if get(w, 1808) >= PROJECT_RECORD_CAP:
            return 0
        put(w, record, slot)
        put(w, record + 8, get(w, frame + 32))
        put(w, record + 16, get(w, 1736))
        put(w, slot + 32, get(w, 1808))
        put(w, 1808, get(w, 1808) + 1)
        put(w, frame + 48, 0)
    at = ignored_space(w, get(w, 1720), get(w, 1824))
    if at == get(w, 1824):
        return 0
    if byte(w, at) == 125:
        put(w, 1720, at + 1)
        return project_close(o, w)
    if byte(w, at) != 44:
        return 0
    return project_key(o, w, ignored_space(w, at + 1, get(w, 1824)))

def project_close(o:mutbuf, w:mutbuf) -> u32:
    frame = project_frame(w)
    kind = get(w, frame)
    required = project_required(kind)
    if get(w, frame + 8) & required != required:
        return 0
    if kind == 1 or kind == 4:
        project_compact(w, frame)
    if project_byte(w, 125) == False:
        return 0
    put(w, 1744, get(w, 1744) - 1)
    if get(w, 1744) == 0:
        if ignored_space(w, get(w, 1720), get(w, 1824)) != get(w, 1824):
            return 0
        put(w, 1728, get(w, 1736) - PROJECT)
        return decode(o, w, 1, PROJECT, get(w, 1728))
    return project_next(o, w)

def project_map_key(w:mutbuf, frame:u64) -> bool:
    start = ARENA + get(w, ARENA + 88)
    size = get(w, ARENA + 96)
    scope = get(w, frame + 72)
    hash = 14695981039346656037 ^ scope
    index = 0
    while index < size:
        hash = (hash ^ byte(w, start + index)) * 1099511628211
        index = index + 1
    probe = hash & (PROJECT_SLOTS - 1)
    scanned = 0
    while scanned < PROJECT_SLOTS:
        slot = PROJECT_MAP + probe * 64
        if get(w, slot) == 0:
            at = get(w, 1800)
            if size > PROJECT_KEYS_END - at:
                return False
            copy_state(w, start, at, size)
            put(w, 1800, at + size)
            put(w, slot, scope)
            put(w, slot + 8, hash)
            put(w, slot + 16, at)
            put(w, slot + 24, size)
            put(w, frame + 48, slot)
            return True
        if get(w, slot) == scope and get(w, slot + 8) == hash and get(w, slot + 24) == size:
            if equal(w, get(w, slot + 16), start, size):
                put(w, frame + 48, slot)
                return True
        probe = (probe + 1) & (PROJECT_SLOTS - 1)
        scanned = scanned + 1
    return False

def project_compact(w:mutbuf, frame:u64) -> u64:
    out = get(w, frame + 16) + 1
    index = get(w, frame + 40)
    first = True
    while index < get(w, 1808):
        record = PROJECT_RECORDS + index * 32
        slot = get(w, record)
        if get(w, slot) == get(w, frame + 72) and get(w, slot + 32) == index:
            if first == False:
                store(w, out, 44)
                out = out + 1
            out = copy_state(w, get(w, record + 8), out, get(w, record + 16) - get(w, record + 8))
            first = False
        index = index + 1
    put(w, 1736, out)
    return 0

def project_strings(w:mutbuf, node:u64) -> bool:
    if get(w, node) != 5:
        return False
    child = get(w, node + 24)
    while child != NONE:
        row = ARENA + 64 + child * 72
        if get(w, row) != 4:
            return False
        child = get(w, row + 16)
    return True

def project_enum(w:mutbuf, node:u64, first:u64, second:u64) -> bool:
    if get(w, node) == 4:
        value = project_enum_id(w, ARENA + get(w, node + 24), get(w, node + 32))
        return value == first or value == second
    if get(w, node) != 6 or get(w, node + 32) != 1:
        return False
    row = ARENA + 64 + get(w, node + 24) * 72
    value = project_enum_id(w, ARENA + get(w, row + 40), get(w, row + 48))
    return get(w, row) == 0 and (value == first or value == second)

def project_enum_write(w:mutbuf, value:u64) -> bool:
    if PROJECT_END - get(w, 1736) < 12:
        return False
    at = get(w, 1736)
    store(w, at, 34)
    size = 5
    if value == 1:
        put(w, at + 1, 517366245740)
    elif value == 2:
        put(w, at + 1, 495790023021)
    elif value == 3:
        put(w, at + 1, 7234316338220462953)
        size = 8
    elif value == 4:
        put(w, at + 1, 8245937404618567791)
        size = 8
    else:
        return False
    store(w, at + 1 + size, 34)
    put(w, 1736, at + size + 2)
    return True
'''


def helpers():
    text = SOURCE + '\n' + IGNORED_VALUE
    for name, groups in (('project_mask', STRUCT_FIELDS), ('project_required', REQUIRED_FIELDS)):
        text += f'\ndef {name}(kind:u64) -> u64:\n'
        for kind, fields in groups.items():
            mask = sum(1 << PROJECT_FIELDS[field] for field in fields)
            text += f'    if kind == {kind}:\n        return {mask}\n'
        text += '    return 0\n'
    children = {0: {'hosts': 1, 'hia_worker': 3},
                1: {None: 2}, 2: {'privileged_actions': 4, 'native_jobs': 6},
                4: {None: 5}, 6: {name: 7 for name in STRUCT_FIELDS[6]}}
    text += '\ndef project_child(kind:u64, key:u64) -> u64:\n'
    for kind, fields in children.items():
        text += f'    if kind == {kind}:\n'
        for field, child in fields.items():
            if field is None:
                text += f'        return {child}\n'
            else:
                text += f'        if key == {PROJECT_FIELDS[field]}:\n            return {child}\n'
    text += '    return NONE\n'
    for name, values in [('project_key_id', PROJECT_FIELDS),
                         ('project_enum_id', dict(linux=1, macos=2, isolated=3, operator=4))]:
        text += f'\ndef {name}(w:mutbuf, at:u64, size:u64) -> u64:\n'
        groups = {}
        for field, value in values.items():
            groups.setdefault(len(field), []).append((field.encode(), value))
        for size, entries in groups.items():
            text += f'    if size == {size}:\n'
            for raw, value in entries:
                words = [f'(getn(w, at + {i}, {len(raw[i:i+8])}) ^ {int.from_bytes(raw[i:i+8], "little")})'
                         for i in range(0, len(raw), 8)]
                text += '        if (' + ' | '.join(words) + f') == 0:\n            return {value}\n'
        text += '    return 0\n'
    text += '\ndef project_type(w:mutbuf, parent:u64, key:u64) -> bool:\n    node = ARENA + 64\n    kind = get(w, node)\n'
    string_fields = ('state_dir', 'ssh_target', 'remote_state_dir', 'host', 'python_executable',
                     'working_directory', 'state_root', 'worker_sha256', 'backend_sha256',
                     'catalog_sha256', 'executable', 'sha256')
    optional_strings = ('checkpoint_binary', 'checkpoint_binary_sha256',
                        'native_helpers_manifest', 'native_helpers_sha256')
    arrays = ('controller_workspace_roots', 'artifact_roots', 'allowed_cwd_prefixes',
              'allowed_read_path_prefixes', 'allowed_write_path_prefixes',
              'protected_path_prefixes', 'protected_argument_substrings',
              'denied_executables', 'allowed_dangerous_executables', 'fixed_args',
              'extra_arg_patterns')
    booleans = ('allow_execute', 'allow_pty', 'allow_write', 'allow_job_network',
                'allow_detached_fallback', 'allow_extra_args')
    for fields, answer in ((string_fields, 'kind == 4'), (optional_strings, 'kind == 0 or kind == 4'),
                           (arrays, 'project_strings(w, node)'), (booleans, 'kind == 1 or kind == 2')):
        condition = ' or '.join(f'key == {PROJECT_FIELDS[field]}' for field in fields)
        text += f'    if {condition}:\n        return {answer}\n'
    for name, first, second in [('platform', 1, 2), ('execution_mode', 3, 4)]:
        text += f'    if key == {PROJECT_FIELDS[name]}:\n        return project_enum(w, node, {first}, {second})\n'
    condition = ' or '.join(f'key == {PROJECT_FIELDS[field]}' for field in ('timeout_seconds', 'memory_max_bytes'))
    text += f'    if {condition}:\n        return kind == 3 and number(w, node) != NONE\n'
    condition = ' or '.join(f'key == {PROJECT_FIELDS[field]}' for field in ('hia_worker', 'native_jobs'))
    text += f'    if {condition}:\n        return kind == 0\n'
    condition = ' or '.join(f'key == {PROJECT_FIELDS[field]}' for field in ('weight_workers', 'rea_static_profiles'))
    text += f'    if {condition}:\n        return kind == 6\n'
    text += '    return False\n'
    return text


EXTRA = {**CONSTANTS, **{'K_' + key.upper(): value for key, value in PROJECT_FIELDS.items()}}
