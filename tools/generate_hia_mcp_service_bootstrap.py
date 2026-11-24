"""Author pinned configuration and controller custody for the HIA MCP owner."""
from pathlib import Path
from hashlib import sha256
from tools.generate_hia_mcp_service_owner_common import authored

ROOT = Path(__file__).resolve().parents[1]
ROLES = (
    'hia-job-entry', 'hia-job-submit', 'hia-job-observation', 'hia-job-cancel',
    'hia-job-launch', 'HIA_AGENT_NATIVE_TOOL_CATALOG.json',
    'hia-agent-job-terminal-receipt', 'hia-agent-mcp-request', 'hia-agent-mcp-reply',
    'hia-agent-mcp-terminal', 'hia-agent-mcp-negotiation', 'hia-agent-mcp-catalog',
    'hia-agent-mcp-uri', 'hia-agent-mcp-input-schema', 'hia-agent-mcp-response-schema',
    'hia-agent-mcp-proof-schema', 'hia-worker-prepare', 'hia-job-receipt',
    'hia-job-supervisor',
)
CAPS = (2 << 20, 4 << 20, 2 << 20, 1 << 20, 1 << 20) + (1 << 20,) * 14

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if length(w) < STATE_BYTES or length(o) < 128 or get(w, 112) != 4 or get(w, 120) < 64 or get(w, 120) > BRIDGE_CAP or get(w, 128) < 64 or get(w, 128) > AUDIT_CAP:
            return 0
        put(w, 64, CACHE)
        put(w, 48, NONE)
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        if failed(result):
            return 0
        put(w, 24, result)
        return call(o, w, 2, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        if failed(result) or result == 0:
            return 0
        put(w, 32, result)
        put(w, 424, result)
        if arguments(w) == False:
            return 0
        return walk(w, 0, 10, get(w, S_CONFIG_DIR), get(w, S_CONFIG_DIR + 8), 0)
    if phase == 10:
        put(w, 304, get(w, 1040))
        return capture_role(w, 0, 11, get(w, 304), get(w, S_CONFIG_NAME), 8388608, CONFIG_RAW, 35584, 0)
    if phase == 11:
        if get(w, 1112) == 0:
            return 0
        put(w, 320, get(w, 1112))
        put(w, 336, get(w, 1128))
        return call(o, w, 12, 3, get(w, 304), 0, 0, 0, 0, 0, 0)
    if phase == 12:
        if failed(result):
            return 0
        return walk(w, 0, 20, get(w, S_CONTROLLER_DIR), get(w, S_CONTROLLER_DIR + 8), 0)
    if phase == 20:
        put(w, 304, get(w, 1040))
        return capture_role(w, 0, 21, get(w, 304), get(w, S_MANIFEST_NAME), 16384, INITIAL, 35616, 0)
    if phase == 21:
        put(w, 328, get(w, 1112))
        put(w, 360, get(w, 1128))
        clear_head(w, PURE_WORK)
        put(w, PURE_WORK, 6)
        put(w, PURE_WORK + 16, 32)
        put(w, PURE_WORK + 24, 4)
        return pure(o, w, 22, P_CONTROLLER_JSON, INITIAL, get(w, 328), PURE_OUTPUT, 16384, PURE_WORK, 33554432)
    if phase == 22:
        if result != 0 or get(w, PURE_WORK + 32) != 624 or get(w, PURE_OUTPUT) != 3544414559827741000 or get(w, PURE_OUTPUT + 8) != 19:
            return 0
        index = 0
        while index < 19:
            copy_state(w, PURE_OUTPUT + 16 + index * 32, role_record(index) + 16, 32)
            index = index + 1
        put(w, 312, 0)
        return next_role(w)
    if phase == 31:
        index = get(w, 312)
        if index == 5:
            if get(w, 1112) == 0 or equal(w, SHA_OUTPUT, 35648, 32) == False:
                return 0
            put(w, 344, get(w, 1112))
            bind(w, S_CATALOG, CATALOG_RAW, get(w, 1112))
        else:
            if elf(w, INITIAL, get(w, 1112), 0) == False or getn(w, 9496, 4) & 73 == 0:
                return 0
        put(w, role_record(index), get(w, 1128))
        put(w, role_record(index) + 8, get(w, 1112))
        put(w, 312, index + 1)
        return next_role(w)
    if phase == 33:
        return call(o, w, 32, 3, get(w, 304), 0, 0, 0, 0, 0, 0)
    if phase == 32:
        if failed(result):
            return 0
        return walk(w, 0, 40, get(w, S_SSH_DIR), get(w, S_SSH_DIR + 8), 0)
    if phase == 40:
        put(w, 304, get(w, 1040))
        return capture_role(w, 0, 41, get(w, 304), get(w, S_SSH_NAME), 16777216, INITIAL, NONE, 2)
    if phase == 41:
        if elf(w, INITIAL, get(w, 1112), 1) == False or getn(w, 9496, 4) & 73 == 0:
            return 0
        put(w, role_record(19), get(w, 1128))
        put(w, role_record(19) + 8, get(w, 1112))
        copy_state(w, SHA_OUTPUT, role_record(19) + 16, 32)
        return call(o, w, 42, 3, get(w, 304), 0, 0, 0, 0, 0, 0)
    if phase == 42:
        if failed(result) or elf(w, BRIDGE_IMAGE, get(w, 120), 0) == False:
            return 0
        put(w, 1000, 0)
        put(w, 1008, 50)
        put(w, 1016, 2)
        put(w, 1080, BRIDGE_CAP)
        put(w, 1088, BRIDGE_IMAGE)
        put(w, 1112, get(w, 120))
        put(w, 1136, role_record(20) + 16)
        return enter(w, 7, 0)
    if phase == 50:
        put(w, role_record(20), get(w, 1128))
        put(w, role_record(20) + 8, get(w, 1112))
        if elf(w, AUDIT_IMAGE, get(w, 128), 0) == False:
            return 0
        put(w, 1000, 0)
        put(w, 1008, 51)
        put(w, 1016, 2)
        put(w, 1080, AUDIT_CAP)
        put(w, 1088, AUDIT_IMAGE)
        put(w, 1112, get(w, 128))
        put(w, 1136, role_record(21) + 16)
        return enter(w, 7, 0)
    if phase == 51:
        put(w, role_record(21), get(w, 1128))
        put(w, role_record(21) + 8, get(w, 1112))
        return enter(w, 1, 0)
    return 0

def arguments(w:mutbuf) -> bool:
    index = 0
    while index < 4:
        at = get(w, 2048 + index * 16)
        size = get(w, 2056 + index * 16)
        if at < 65536 or at > 98304 or size > 4096 or size > 98304 - at or byte(w, at + size) != 0:
            return False
        bind(w, S_CONFIG_PATH + index * 16, at, size)
        index = index + 1
    if decode_hex(w, get(w, S_CONFIG_SHA), get(w, S_CONFIG_SHA + 8), 35584) == False or decode_hex(w, get(w, S_MANIFEST_SHA), get(w, S_MANIFEST_SHA + 8), 35616) == False:
        return False
    if split_path(w, S_CONFIG_PATH, S_CONFIG_DIR, S_CONFIG_NAME) == False or split_path(w, S_MANIFEST_PATH, S_CONTROLLER_DIR, S_MANIFEST_NAME) == False:
        return False
    if text_is(w, get(w, S_MANIFEST_NAME), get(w, S_MANIFEST_NAME + 8), 0) == False:
        return False
    at = get(w, 64)
    end = text_ssh_dir(w, at)
    store(w, end, 0)
    bind(w, S_SSH_DIR, at, end - at)
    at = end + 1
    end = text_ssh_name(w, at)
    store(w, end, 0)
    bind(w, S_SSH_NAME, at, end - at)
    at = end + 1
    end = text_catalog_pin(w, at)
    bind(w, S_CATALOG_PIN, at, end - at)
    if decode_hex(w, at, end - at, 35648) == False:
        return False
    put(w, 64, end)
    return True

def split_path(w:mutbuf, source:u64, directory:u64, name:u64) -> bool:
    at = get(w, source)
    size = get(w, source + 8)
    if path_ok(w, at, size) == False:
        return False
    split = size - 1
    while split > 0 and byte(w, at + split) != 47:
        split = split - 1
    if size - split - 1 == 0 or size - split - 1 > 255:
        return False
    first = get(w, 64)
    dir_size = choose(split == 0, 1, split)
    end = copy_state(w, at, first, dir_size)
    store(w, end, 0)
    bind(w, directory, first, dir_size)
    first = end + 1
    end = copy_state(w, at + split + 1, first, size - split - 1)
    store(w, end, 0)
    bind(w, name, first, end - first)
    put(w, 64, end + 1)
    return True

def next_role(w:mutbuf) -> u32:
    index = get(w, 312)
    if index == 19:
        return enter(w, 0, 33)
    end = role_name(w, index, 12800)
    store(w, end, 0)
    target = choose(index == 5, CATALOG_RAW, INITIAL)
    return capture_role(w, 0, 31, get(w, 304), 12800, role_cap(index), target, role_record(index) + 16, 0)

def clear_head(w:mutbuf, at:u64) -> u64:
    index = 0
    while index < 256:
        put(w, at + index, 0)
        index = index + 8
    return 0

def elf(w:mutbuf, at:u64, size:u64, dynamic:u64) -> bool:
    if size < 64 or getn(w, at, 4) != 1179403647 or getn(w, at + 4, 3) != 65794 or getn(w, at + 18, 2) != 62:
        return False
    kind = getn(w, at + 16, 2)
    return kind == 2 or (dynamic == 1 and kind == 3)
'''


def source():
    text = {'ssh_dir': '/usr/bin', 'ssh_name': 'ssh',
            'catalog_pin': sha256((ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()).hexdigest()}
    code = SOURCE
    code += '\ndef role_name(w:mutbuf, role:u64, at:u64) -> u64:\n'
    for i, name in enumerate(ROLES):
        text['role_' + str(i)] = name
        code += f'    if role == {i}:\n        return text_role_{i}(w, at)\n'
    code += '    return at\n\ndef role_cap(role:u64) -> u64:\n'
    for i, cap in enumerate(CAPS[:5]):
        code += f'    if role == {i}:\n        return {cap}\n'
    code += '    return 1048576\n'
    return authored(code, text=text, extra={'_checks': ('hia-controller.json',)})
