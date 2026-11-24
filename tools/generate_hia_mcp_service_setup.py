"""Author HIA MCP configuration, alias binding and native discovery setup."""
from tools.generate_hia_mcp_service_owner_common import authored
from tools.generate_hia_mcp_service_projection import helpers as projection_helpers, EXTRA as PROJECTION_EXTRA

ENV_KEYS = ('HEPTA_RUNTIME_STATE_DIR', 'XDG_STATE_HOME', 'HOME', 'TMPDIR',
            'HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF',
            'HEPTA_EFFECT_OWNER_FENCE_REQUIRED', 'v4', 'v11')

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if fences(w) == False:
            return 0
        return project_start(o, w)
    if phase == 100:
        return project_key_ready(o, w, result)
    if phase == 101:
        return project_leaf_ready(o, w, result)
    if phase == 1:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or select_state(w) == False:
            return 0
        at = text_config(w, PURE_INPUT)
        at = copy_state(w, PROJECT, at, get(w, 1728))
        at = text_default(w, at)
        at = qslot(w, at, S_STATE_ROOT)
        at = text_catalog(w, at)
        at = qslot(w, at, S_CATALOG_PIN)
        at = text_close(w, at)
        return pure(o, w, 2, P_CONFIG, PURE_INPUT, at - PURE_INPUT, PURE_OUTPUT, 4194304, PURE_WORK, W_CONFIG)
    if phase == 2:
        if result == 0 or result > 4194304:
            return 0
        return pure(o, w, 3, P_CANONICAL, PURE_OUTPUT, result, PURE_INPUT, 8388608, PURE_WORK, W_CANONICAL)
    if phase == 3:
        if result == 0 or result > 4194304:
            return 0
        copy_state(w, PURE_INPUT, CONTEXT, result)
        bind(w, S_CONTEXT, CONTEXT, result)
        return decode(o, w, 4, CONTEXT, result)
    if phase == 4:
        if result >= 4294967292 or retain_context(w) == False:
            return 0
        return pure(o, w, 10, P_CATALOG, CATALOG_RAW, get(w, 344), PURE_OUTPUT, 8389120, PURE_WORK, 33554432)
    if phase == 10:
        if result == 0 or result > 1048576:
            return 0
        return pure(o, w, 11, P_CANONICAL, PURE_OUTPUT, result, PURE_INPUT, 8388608, PURE_WORK, W_CANONICAL)
    if phase == 11:
        if result == 0 or result > 1048576:
            return 0
        copy_state(w, PURE_INPUT, CATALOG_RESULT, result)
        bind(w, S_CATALOG_RESULT, CATALOG_RESULT, result)
        return enter(w, 8, 0)
    if phase == 30:
        put(w, 176, get(w, 64))
        return enter(w, 2, 0)
    return 0

def environment(w:mutbuf, name:u64, slot:u64) -> bool:
    index = 0
    while index < get(w, 104):
        at = get(w, 53248 + index * 8)
        end = at
        while byte(w, end) != 0 and byte(w, end) != 61:
            end = end + 1
        if byte(w, end) == 61 and text_is(w, at, end - at, name):
            start = end + 1
            end = start
            while byte(w, end) != 0:
                end = end + 1
            bind(w, slot, start, end - start)
            return True
        index = index + 1
    bind(w, slot, 0, 0)
    return False

def fences(w:mutbuf) -> bool:
    directory = environment(w, 4, S_FENCE_ROOT)
    owner = environment(w, 5, S_SELF_OWNER)
    required = environment(w, 6, S_DEFAULT_STATE)
    put(w, 136, 0)
    if required:
        if get(w, S_DEFAULT_STATE + 8) != 1 or byte(w, get(w, S_DEFAULT_STATE)) != 49:
            return False
        put(w, 136, 1)
    if directory != owner or (required and directory == False):
        return False
    if directory:
        if get(w, S_FENCE_ROOT + 8) == 0 or get(w, S_FENCE_ROOT + 8) > 4096:
            return False
        if text_is(w, get(w, S_SELF_OWNER), get(w, S_SELF_OWNER + 8), 7) == False and text_is(w, get(w, S_SELF_OWNER), get(w, S_SELF_OWNER + 8), 8) == False:
            return False
    return True

def select_state(w:mutbuf) -> bool:
    value = field(w, F_STATE_DIR)
    if value != NONE:
        if freeze_string(w, value, S_STATE_ROOT) == False:
            return False
    elif environment(w, 0, S_STATE_ROOT):
        if cache_path(w, S_STATE_ROOT, 0) == False:
            return False
    elif environment(w, 1, S_STATE_ROOT):
        if cache_path(w, S_STATE_ROOT, 1) == False:
            return False
    else:
        if environment(w, 2, S_STATE_ROOT) == False and environment(w, 3, S_STATE_ROOT) == False:
            at = get(w, 64)
            end = text_tmp(w, at)
            store(w, end, 0)
            bind(w, S_STATE_ROOT, at, end - at)
            put(w, 64, end + 1)
        if cache_path(w, S_STATE_ROOT, 2) == False:
            return False
    size = get(w, S_STATE_ROOT + 8)
    return size > 0 and size < 4096 and byte(w, get(w, S_STATE_ROOT)) == 47

def cache_path(w:mutbuf, slot:u64, suffix:u64) -> bool:
    if get(w, slot + 8) > 4095:
        return False
    at = get(w, 64)
    end = cp(w, slot, at)
    if suffix != 0:
        if end > at and byte(w, end - 1) != 47:
            store(w, end, 47)
            end = end + 1
        if suffix == 1:
            end = text_runtime_suffix(w, end)
        else:
            end = text_home_suffix(w, end)
    if end - at > 4095:
        return False
    store(w, end, 0)
    bind(w, slot, at, end - at)
    put(w, 64, end + 1)
    return True

def retain_context(w:mutbuf) -> bool:
    profile = field(w, F_PROFILE)
    host = field(w, F_HOST)
    if profile == NONE or host == NONE or get(w, profile) != 6 or get(w, host) != 6:
        return False
    if get(w, profile + 64) > 524288 or get(w, host + 64) > 524288:
        return False
    raw_bind(w, profile, S_PROFILE)
    raw_bind(w, host, S_HOST_CONFIG)
    if freeze_string(w, lookup(w, profile, F_HOST), S_WORKER_HOST) == False or freeze_string(w, lookup(w, profile, F_WORKING_DIRECTORY), S_WORKING_DIRECTORY) == False or freeze_string(w, lookup(w, profile, F_STATE_ROOT), S_WORKER_STATE) == False:
        return False
    jobs = lookup(w, host, F_NATIVE_JOBS)
    if jobs == NONE:
        bind(w, S_ENTRY_PATH, 0, 0)
        return True
    if get(w, jobs) == 0:
        bind(w, S_ENTRY_PATH, 0, 0)
        return True
    index = 0
    while index < 5:
        role = lookup(w, jobs, F_ENTRY + index)
        digest = lookup(w, role, F_SHA256)
        if digest == NONE or get(w, digest) != 4:
            return False
        if decode_hex(w, ARENA + get(w, digest + 24), get(w, digest + 32), 35712) == False or equal(w, 35712, role_record(index) + 16, 32) == False:
            return False
        if index == 0 and freeze_string(w, lookup(w, role, F_EXECUTABLE), S_ENTRY_PATH) == False:
            return False
        index = index + 1
    return True
'''


def source():
    return authored(SOURCE + '\n' + projection_helpers(), text={
        'config': '{"configuration":', 'default': ',"default_state_dir":',
        'catalog': ',"catalog_sha256":', 'tmp': '/tmp',
        'runtime_suffix': 'hepta-runtime', 'home_suffix': '.local/state/hepta-runtime',
    }, extra={**PROJECTION_EXTRA, '_checks': ENV_KEYS})
