"""Shared authoring helpers for the native HIA MCP process owner."""
from __future__ import annotations
import ast
import re

STATE_BYTES = 384 << 20
NONE = (1 << 64) - 1
C = dict(STATE_BYTES=STATE_BYTES, INPUT_BYTES=0, NONE=NONE,
         NEG100=(1 << 64) - 100, NEG4=(1 << 64) - 4, NEG11=(1 << 64) - 11,
         NEG2=(1 << 64) - 2, NEG17=(1 << 64) - 17,
         CACHE=3 << 20, CACHE_END=4 << 20, INITIAL=16 << 20,
         SHA_INPUT=131072, SHA_OUTPUT=196608, SHA_WORK=200704,
         ARENA=160 << 20, ARENA_BYTES=32 << 20,
         SCRATCH=192 << 20, SCRATCH_BYTES=32 << 20,
         CHILD_IN=224 << 20, CHILD_OUT=240 << 20, CHILD_ERR=248 << 20,
         ENV=2 << 20, TABLE=32768,
         REQUEST=32 << 20, REQUEST_CAP=(16 << 20) - 1, READ_CHUNK=94 << 20,
         SESSION_OUT=48 << 20, SESSION_WORK=66 << 20,
         PURE_INPUT=96 << 20, PURE_OUTPUT=112 << 20, PURE_WORK=128 << 20,
         CONFIG_RAW=256 << 20, CATALOG_RAW=264 << 20, CATALOG_RESULT=265 << 20,
         CONTEXT=272 << 20, PROFILE=276 << 20, HOST=277 << 20,
         ORIGINAL_ARGS=278 << 20, NORMAL_ARGS=279 << 20,
         BRIDGE_IMAGE=288 << 20, BRIDGE_CAP=16 << 20,
         AUDIT_IMAGE=352 << 20, AUDIT_CAP=16 << 20,
         AUDIT_WIRE=368 << 20, AUDIT_REPLY=(368 << 20) + 8192,
         AUDIT_ERROR=(368 << 20) + 16384)
C.update(P_SESSION=0, P_REPLY=1, P_CANONICAL=2, P_CONFIG=3,
         P_ADMISSION=4, P_CATALOG=5, P_INPUT_SCHEMA=6, P_CONTROLLER_JSON=7,
         P_OUTPUT_SCHEMA=8, P_SDK=9)
C.update(W_SESSION=64 + 262144 * 72 + (8 << 20) + 256,
         W_REPLY=64 + 262144 * 72 + (9 << 20),
         W_CANONICAL=64 + 262144 * 56 + (8 << 20) + 16384,
         W_CONFIG=64 + 262144 * 72 + (9 << 20),
         W_ADMISSION=64 + 262144 * 72 + (8 << 20))
C.update(SESSION_PHASE=(66 << 20) + 27263040, SDK_STATUS=(66 << 20) + 27263048, SDK_DESCRIPTOR=(66 << 20) + 27263056, FRAME_DISCARD=2032)
C.update(TASK_TABLE=36864, TASK_BYTES=128, TASK_COUNT=32, SCHEDULE_DESCRIPTOR=35840)
SLOTS = (
    'config_path', 'config_sha', 'manifest_path', 'manifest_sha',
    'controller_dir', 'default_state', 'fence_root', 'self_owner',
    'catalog', 'catalog_result', 'context', 'profile', 'host_config', 'state_root',
    'original', 'arguments', 'tool', 'uri', 'response', 'request_id',
    'worker_host', 'entry_path', 'ssh_target', 'remote_command',
    'config_dir', 'config_name', 'manifest_name', 'ssh_dir', 'ssh_name',
    'worker_state', 'working_directory', 'catalog_pin', 'bridge_name',
    'audit_owner', 'audit_id',
)
SLOT = {name: 32768 + index * 16 for index, name in enumerate(SLOTS)}
FIELDS = ('profile', 'host', 'state_dir', 'aliases', 'native_jobs', 'entry', 'submit',
          'observation', 'cancel', 'launcher', 'executable', 'sha256', 'catalog_sha256',
          'configuration', 'default_state_dir', 'context', 'arguments', 'tool', 'uri',
          'id', 'kind', 'modern', 'payload', 'source', 'path', 'status', 'result',
          'error', 'request_key', 'timeout_seconds', 'python_executable')
FIELDS += ('execution_mode', 'working_directory', 'state_root', 'worker_sha256',
           'backend_sha256', 'native_helpers_manifest', 'native_helpers_sha256')
FIELD = {name: index + 1 for index, name in enumerate(FIELDS)}

# Filled from the reviewed scalar buffer and Linux plan helpers below. This is
# authoring source only; all executable policy is emitted as checked-in HIA.
COMMON = r'''
def signed_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value >> 63 == 1:
        store(w, at, 45)
        at = at + 1
        value = 0 - value
    return decimal(w, at, value)

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0

def uint(s:readbuf, at:u64) -> u64:
    return word_load(s, at)

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def failed(value:u64) -> bool:
    return value >> 63 != 0

def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pointers:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, pointers)
    return 1

def relocate(o:mutbuf, w:mutbuf, phase:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

def decode(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(w, 72, source)
    put(w, 80, size)
    put(w, SCRATCH + 48, 262144)
    put(w, SCRATCH + 56, 128)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, size:u64) -> u32:
    put(w, 0, phase)
    store(w, SHA_INPUT, command)
    put(o, 0, size)
    return 3

def enter(w:mutbuf, module:u64, phase:u64) -> u32:
    put(w, 16, module)
    put(w, 0, phase)
    put(w, 8, 0)
    return 6

def copy_input(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        put(w, target + index, uint(s, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return target + size

def copy_state(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        put(w, target + index, get(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return target + size

def equal(w:mutbuf, left:u64, right:u64, size:u64) -> bool:
    index = 0
    while index + 8 <= size:
        if get(w, left + index) != get(w, right + index):
            return False
        index = index + 8
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return False
        index = index + 1
    return True

def bind(w:mutbuf, slot:u64, at:u64, size:u64) -> u64:
    put(w, slot, at)
    put(w, slot + 8, size)
    return 0

def cp(w:mutbuf, slot:u64, target:u64) -> u64:
    return copy_state(w, get(w, slot), target, get(w, slot + 8))

def raw(w:mutbuf, field:u64, target:u64) -> u64:
    if field == NONE:
        return text_null(w, target)
    if get(w, field) < 4:
        return copy_state(w, get(w, 72) + get(w, field + 24), target, get(w, field + 32))
    return copy_state(w, get(w, 72) + get(w, field + 56), target, get(w, field + 64))

def raw_bind(w:mutbuf, field:u64, slot:u64) -> u64:
    if field == NONE:
        return 0
    if get(w, field) < 4:
        return bind(w, slot, get(w, 72) + get(w, field + 24), get(w, field + 32))
    return bind(w, slot, get(w, 72) + get(w, field + 56), get(w, field + 64))

def freeze_raw(w:mutbuf, field:u64, slot:u64) -> bool:
    if field == NONE:
        return False
    size = choose(get(w, field) < 4, get(w, field + 32), get(w, field + 64))
    start = get(w, 64)
    if size > CACHE_END - start:
        return False
    finish = raw(w, field, start)
    put(w, 64, finish)
    bind(w, slot, start, finish - start)
    return True

def freeze_string(w:mutbuf, field:u64, slot:u64) -> bool:
    if field == NONE or get(w, field) != 4:
        return False
    size = get(w, field + 32)
    start = get(w, 64)
    if size > CACHE_END - start - 1:
        return False
    finish = copy_state(w, ARENA + get(w, field + 24), start, size)
    store(w, finish, 0)
    put(w, 64, finish + 1)
    bind(w, slot, start, size)
    return True

def lookup(w:mutbuf, parent:u64, name:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    child = get(w, parent + 24)
    found = NONE
    while child != NONE:
        row = ARENA + 64 + child * 72
        if key_id(w, ARENA + get(w, row + 40), get(w, row + 48)) == name:
            found = row
        child = get(w, row + 16)
    return found

def field(w:mutbuf, name:u64) -> u64:
    return lookup(w, ARENA + 64, name)

def string_eq(w:mutbuf, row:u64, slot:u64) -> bool:
    if row == NONE or get(w, row) != 4 or get(w, row + 32) != get(w, slot + 8):
        return False
    return equal(w, ARENA + get(w, row + 24), get(w, slot), get(w, slot + 8))

def str_is(w:mutbuf, row:u64, literal:u64) -> bool:
    if row == NONE or get(w, row) != 4:
        return False
    return text_is(w, ARENA + get(w, row + 24), get(w, row + 32), literal)

def number(w:mutbuf, row:u64) -> u64:
    if row == NONE or get(w, row) != 3:
        return NONE
    at = get(w, 72) + get(w, row + 24)
    size = get(w, row + 32)
    if size == 0 or size > 20:
        return NONE
    value = 0
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if ch < 48 or ch > 57:
            return NONE
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return NONE
        value = value * 10 + digit
        index = index + 1
    return value

def boolean(w:mutbuf, row:u64, expected:u64) -> bool:
    return row != NONE and get(w, row) == 1 + expected

def is_null(w:mutbuf, row:u64) -> bool:
    return row != NONE and get(w, row) == 0

def quoted(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    store(w, at, 34)
    at = at + 1
    index = 0
    while index < size:
        ch = byte(w, source + index)
        if ch == 34 or ch == 92:
            store(w, at, 92)
            store(w, at + 1, ch)
            at = at + 2
        elif ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
            escape = choose(ch == 8, 98, choose(ch == 9, 116, choose(ch == 10, 110, choose(ch == 12, 102, 114))))
            store(w, at, 92)
            store(w, at + 1, escape)
            at = at + 2
        elif ch < 32:
            store(w, at, 92)
            store(w, at + 1, 117)
            store(w, at + 2, 48)
            store(w, at + 3, 48)
            store(w, at + 4, hex_digit(ch >> 4))
            store(w, at + 5, hex_digit(ch & 15))
            at = at + 6
        else:
            store(w, at, ch)
            at = at + 1
        index = index + 1
    store(w, at, 34)
    return at + 1

def qslot(w:mutbuf, at:u64, slot:u64) -> u64:
    return quoted(w, at, get(w, slot), get(w, slot + 8))

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        store(w, at, 48)
        return at + 1
    count = 0
    while value != 0:
        store(w, 24576 + count, 48 + value % 10)
        count = count + 1
        value = value // 10
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 24576 + count))
        at = at + 1
    return at

def hex_digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)

def hex_digit_value(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    if value >= 65 and value <= 70:
        return value - 55
    return NONE

def lowerhex(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        index = index + 1
    return True

def name_ok(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 128:
        return False
    index = 0
    while index < size:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 45 and ch != 46 and ch != 95:
            return False
        index = index + 1
    return True

def path_ok(w:mutbuf, at:u64, size:u64) -> bool:
    if size == 0 or size > 4096 or byte(w, at) != 47:
        return False
    index = 1
    start = 1
    while index <= size:
        if index == size or byte(w, at + index) == 47:
            part = index - start
            if part == 0 or (part == 1 and byte(w, at + start) == 46) or (part == 2 and getn(w, at + start, 2) == 11822):
                return False
            start = index + 1
        elif byte(w, at + index) == 0:
            return False
        index = index + 1
    return True

def same_stamp(w:mutbuf, left:u64, right:u64) -> bool:
    return equal(w, left, right, 72) and equal(w, left + 88, right + 88, 32)

def safe_regular(w:mutbuf, at:u64, private:u64) -> bool:
    mode = getn(w, at + 24, 4)
    return mode & 61440 == 32768 and get(w, at + 16) == 1 and getn(w, at + 28, 4) == get(w, 24) and (private == 0 or mode & 511 == 384)

def child(w:mutbuf, next_module:u64, next_phase:u64, role:u64, size:u64, out_cap:u64, err_cap:u64, timeout:u64, directory:u64) -> u32:
    put(w, 512, next_module)
    put(w, 520, next_phase)
    put(w, 528, role)
    put(w, 536, size)
    put(w, 544, out_cap)
    put(w, 552, err_cap)
    put(w, 560, timeout)
    put(w, 568, directory)
    return enter(w, 4, 0)

def child_ok(w:mutbuf) -> bool:
    return get(w, 600) == 0 and get(w, 608) == 0

def walk(w:mutbuf, module:u64, phase:u64, source:u64, size:u64, create:u64) -> u32:
    put(w, 1000, module)
    put(w, 1008, phase)
    put(w, 1016, 0)
    put(w, 1024, source)
    put(w, 1032, size)
    put(w, 1064, create)
    return enter(w, 7, 0)

def capture(w:mutbuf, module:u64, phase:u64, directory:u64, name:u64, cap:u64, target:u64, private:u64, missing:u64) -> u32:
    put(w, 1000, module)
    put(w, 1008, phase)
    put(w, 1016, 1)
    put(w, 1024, directory)
    put(w, 1032, name)
    put(w, 1080, cap)
    put(w, 1088, target)
    put(w, 1096, private)
    put(w, 1104, missing)
    return enter(w, 7, 0)

def finish(o:mutbuf, w:mutbuf, source:u64, size:u64) -> u32:
    put(w, 704, source)
    put(w, 712, size)
    put(w, 720, 0)
    return enter(w, 0, 900)
'''

EXTRA = r'''
def pure(o:mutbuf, w:mutbuf, phase:u64, role:u64, source:u64, size:u64, output:u64, capacity:u64, workspace:u64, workspace_size:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, role)
    put(o, 8, source)
    put(o, 16, size)
    put(o, 24, output)
    put(o, 32, capacity)
    put(o, 40, workspace)
    put(o, 48, workspace_size)
    return 5

def capture_role(w:mutbuf, module:u64, phase:u64, directory:u64, name:u64, cap:u64, target:u64, expected:u64, owner:u64) -> u32:
    put(w, 1000, module)
    put(w, 1008, phase)
    put(w, 1016, 1)
    put(w, 1024, directory)
    put(w, 1032, name)
    put(w, 1080, cap)
    put(w, 1088, target)
    put(w, 1096, owner)
    put(w, 1104, 0)
    put(w, 1136, expected)
    return enter(w, 7, 0)

def decode_hex(w:mutbuf, source:u64, size:u64, target:u64) -> bool:
    if size != 64 or lowerhex(w, source, size) == False:
        return False
    index = 0
    while index < 32:
        value = hex_digit_value(byte(w, source + index * 2)) * 16
        value = value + hex_digit_value(byte(w, source + index * 2 + 1))
        store(w, target + index, value)
        index = index + 1
    return True

def encode_hex(w:mutbuf, source:u64, target:u64) -> u64:
    index = 0
    while index < 32:
        ch = byte(w, source + index)
        store(w, target + index * 2, hex_digit(ch >> 4))
        store(w, target + index * 2 + 1, hex_digit(ch & 15))
        index = index + 1
    return target + 64

def role_record(role:u64) -> u64:
    return 4096 + role * 64

def audit(w:mutbuf, module:u64, phase:u64, operation:u64) -> u32:
    put(w, 1992, module)
    put(w, 2000, phase)
    put(w, 1920, operation)
    return enter(w, 9, 0)
'''


def authored(source, *, text=None, extra=None):
    literals = dict(null='null', true='true', false='false', comma=',', close='}', colon=':',
                    quote='"', newline='\n', empty='')
    literals.update(text or {})
    value = source + '\n' + COMMON + '\n' + EXTRA
    values = {**C, **{'S_' + key.upper(): val for key, val in SLOT.items()},
              **{'F_' + key.upper(): val for key, val in FIELD.items()}, **(extra or {})}
    for key in sorted(values, key=len, reverse=True):
        value = re.sub(r'\b' + re.escape(key) + r'\b', str(values[key]), value)
    for index, name in enumerate(literals):
        value = value.replace('text_' + name + '(w, ', f'text_bank_{index // 16}(w, {index % 16}, ')
    for first in range(0, len(literals), 16):
        value += f'\ndef text_bank_{first // 16}(w:mutbuf, kind:u64, at:u64) -> u64:\n'
        for index, (_, raw) in enumerate(list(literals.items())[first:first + 16]):
            raw = raw.encode()
            value += f'    if kind == {index}:\n'
            for offset in range(0, len(raw), 8):
                part = raw[offset:offset + 8]
                if len(part) == 8:
                    value += f'        put(w, at + {offset}, {int.from_bytes(part, "little")})\n'
                else:
                    for j, ch in enumerate(part):
                        value += f'        store(w, at + {offset + j}, {ch})\n'
            value += f'        return at + {len(raw)}\n'
        value += '    return at\n'
    value += '\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    groups = {}
    for name, index in FIELD.items():
        groups.setdefault(len(name), []).append((name.encode(), index))
    for size, rows in groups.items():
        value += f'    if size == {size}:\n'
        for raw, index in rows:
            words = [f'(getn(w, at + {off}, {len(raw[off:off + 8])}) ^ {int.from_bytes(raw[off:off + 8], "little")})'
                     for off in range(0, len(raw), 8)]
            value += '        if (' + ' | '.join(words) + f') == 0:\n            return {index}\n'
    value += '    return 0\n'
    checks = (extra or {}).get('_checks', ())
    value += '\ndef text_is(w:mutbuf, at:u64, size:u64, kind:u64) -> bool:\n'
    for index, raw in enumerate(checks):
        raw = raw.encode()
        words = [f'(getn(w, at + {off}, {len(raw[off:off + 8])}) ^ {int.from_bytes(raw[off:off + 8], "little")})'
                 for off in range(0, len(raw), 8)]
        value += f'    if kind == {index}:\n        return size == {len(raw)} and (' + ' | '.join(words or ['0']) + ') == 0\n'
    value += '    return False\n'
    tree = ast.parse(value)
    nodes = {node.name: node for node in tree.body}
    needed = {'advance'}
    pending = ['advance']
    while pending:
        for call in ast.walk(nodes[pending.pop()]):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                name = call.func.id
                if name in nodes and name not in needed:
                    needed.add(name)
                    pending.append(name)
    return '\n\n'.join(ast.get_source_segment(value, node) for node in tree.body if node.name in needed) + '\n'
