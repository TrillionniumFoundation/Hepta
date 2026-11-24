"""Exact provider preparation, including legacy durable identity bytes."""
from tools.generate_hia_mcp_job_bridge_common import authored, SLOT

TOOLS=('hia_describe','hia_artifact','hia_read','hia_context','hia_inspect',
       'hia_candidate','hia_verify','hia_emit','hia_evaluate','hia_adopt',
       'hia_rollback','hia_resource_read')
TEXT=dict(
 args_open='["-B","-E","-s","-m","hepta.hia_agent_worker","--state-root",',
 expected_worker=',"--expected-worker-sha256",',
 expected_backend=',"--expected-backend-sha256",',
 expected_catalog=',"--expected-catalog-sha256",',artifact_root=',"--artifact-root",',
 native_manifest=',"--native-helpers-manifest",',native_pin=',"--expected-native-helpers-sha256",',
 args_close=',"--request-json-stdin"]',job_key='hia-agent-',
 env_open='{"HIA_TRANSPORT_ARGUMENTS_SHA256":',env_close=',"LC_ALL":"C.UTF-8"}',
 binding_open='{"args":',cpu=',"cpu_quota_percent":100,"cwd":',env=',"env":',
 executable=',"executable":',host=',"host":',memory=',"memory_max_bytes":',
 stdin=',"nice":0,"stdin":',timeout=',"timeout_seconds":',
 expected_open='{"arguments":',backend=',"backend_sha256":',catalog=',"catalog_sha256":',
 helpers=',"native_helpers_sha256":',profile=',"profile_sha256":',request=',"request_sha256":',
 tool=',"tool":',worker=',"worker_sha256":',
 default_entry='/usr/local/libexec/hepta-runtime-job-entry')

SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        return decode(o, w, 1, get(w, S_PROFILE), get(w, S_PROFILE + 8))
    if phase == 1:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or profile(w) == 0:
            return 0
        return decode(o, w, 2, get(w, S_HOST_CONFIG), get(w, S_HOST_CONFIG + 8))
    if phase == 2:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or host(w) == 0:
            return 0
        return decode(o, w, 3, get(w, S_ARGUMENTS), get(w, S_ARGUMENTS + 8))
    if phase == 3:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            return 0
        key = field(w, F_REQUEST_KEY)
        if key != NONE and get(w, key) == 4:
            raw_bind(w, key, S_REQUEST_KEY)
        return decode(o, w, 4, get(w, S_TOOL), get(w, S_TOOL + 8))
    if phase == 4:
        if result >= 4294967292 or get(w, ARENA + 64) != 4:
            return 0
        tool = 0
        while tool < 12:
            if str_is(w, ARENA + 64, tool):
                put(w, 888, tool + 1)
            tool = tool + 1
        if get(w, 888) == 0:
            return 0
        return request_frame(o, w)
    if phase == 10:
        if child_ok(w) == False or get(w, 616) != 0 or get(w, 624) <= 266 or get(w, 624) > 524552 or get(w, CHILD_OUT) != WORKER_MAGIC:
            return 0
        index = 8
        while index < 264:
            if lowerhex(w, CHILD_OUT + index, 64) == False:
                return 0
            index = index + 64
        size = get(w, 624) - 264
        if byte(w, CHILD_OUT + 264) != 123 or byte(w, CHILD_OUT + get(w, 624) - 2) != 125 or byte(w, CHILD_OUT + get(w, 624) - 1) != 10:
            return 0
        copy_state(w, CHILD_OUT, WORKER, get(w, 624))
        bind(w, S_WORKER, WORKER + 264, size)
        bind(w, S_TRANSPORT_DIGEST, WORKER + 8, 64)
        bind(w, S_PROFILE_DIGEST, WORKER + 72, 64)
        bind(w, S_REQUEST_DIGEST, WORKER + 136, 64)
        at = text_job_key(w, get(w, 64))
        at = copy_state(w, WORKER + 200, at, 64)
        bind(w, S_JOB_KEY, get(w, 64), at - get(w, 64))
        put(w, 64, at)
        return binding_frame(o, w)
    if phase == 11:
        if child_ok(w) == False or get(w, 616) != 0 or get(w, 624) != 72 or get(w, CHILD_OUT) != BINDING_MAGIC or lowerhex(w, CHILD_OUT + 8, 64) == False:
            return 0
        at = get(w, 64)
        copy_state(w, CHILD_OUT + 8, at, 64)
        bind(w, S_JOB_DIGEST, at, 64)
        put(w, 64, at + 64)
        value = 0
        index = 0
        while index < 16:
            value = (value << 4) | hex_digit_value(byte(w, at + index))
            index = index + 1
        put(w, 896, value)
        expected(w)
        return enter(w, 2, 0)
    return 0

def profile(w:mutbuf) -> u64:
    if freeze_string(w, field(w, F_HOST), S_HOST) == False or name_ok(w, get(w, S_HOST), get(w, S_HOST + 8)) == False:
        return 0
    if freeze_string(w, field(w, F_PYTHON_EXECUTABLE), S_EXECUTABLE) == False or freeze_string(w, field(w, F_WORKING_DIRECTORY), S_CWD) == False or freeze_string(w, field(w, F_STATE_ROOT), S_WORKER_STATE) == False:
        return 0
    if path_ok(w, get(w, S_EXECUTABLE), get(w, S_EXECUTABLE + 8)) == False or path_ok(w, get(w, S_CWD), get(w, S_CWD + 8)) == False or path_ok(w, get(w, S_WORKER_STATE), get(w, S_WORKER_STATE + 8)) == False:
        return 0
    if freeze_string(w, field(w, F_WORKER_SHA256), S_WORKER_PIN) == False or freeze_string(w, field(w, F_BACKEND_SHA256), S_BACKEND_PIN) == False:
        return 0
    if get(w, S_WORKER_PIN + 8) != 64 or get(w, S_BACKEND_PIN + 8) != 64 or lowerhex(w, get(w, S_WORKER_PIN), 64) == False or lowerhex(w, get(w, S_BACKEND_PIN), 64) == False:
        return 0
    if string_eq(w, field(w, F_CATALOG_SHA256), S_CATALOG) == False:
        return 0
    timeout = number(w, field(w, F_TIMEOUT_SECONDS))
    memory = number(w, field(w, F_MEMORY_MAX_BYTES))
    if timeout == 0 or timeout > 3600 or memory < 67108864 or memory > 17179869184:
        return 0
    put(w, 800, timeout)
    put(w, 808, memory)
    if freeze_raw(w, field(w, F_TIMEOUT_SECONDS), S_TIMEOUT) == False or freeze_raw(w, field(w, F_MEMORY_MAX_BYTES), S_MEMORY) == False:
        return 0
    manifest = field(w, F_NATIVE_HELPERS_MANIFEST)
    digest = field(w, F_NATIVE_HELPERS_SHA256)
    has_manifest = manifest != NONE and is_null(w, manifest) == False
    has_digest = digest != NONE and is_null(w, digest) == False
    if has_manifest != has_digest:
        return 0
    if has_manifest:
        if freeze_string(w, manifest, S_NATIVE_MANIFEST) == False or freeze_string(w, digest, S_NATIVE_PIN) == False:
            return 0
        if path_ok(w, get(w, S_NATIVE_MANIFEST), get(w, S_NATIVE_MANIFEST + 8)) == False or get(w, S_NATIVE_PIN + 8) != 64 or lowerhex(w, get(w, S_NATIVE_PIN), 64) == False:
            return 0
    at = text_args_open(w, ARGS)
    at = qslot(w, at, S_WORKER_STATE)
    at = text_expected_worker(w, at)
    at = qslot(w, at, S_WORKER_PIN)
    at = text_expected_backend(w, at)
    at = qslot(w, at, S_BACKEND_PIN)
    at = text_expected_catalog(w, at)
    at = qslot(w, at, S_CATALOG)
    roots = field(w, F_ARTIFACT_ROOTS)
    if roots == NONE or get(w, roots) != 5 or get(w, roots + 32) > 32:
        return 0
    row = get(w, roots + 24)
    while row != NONE:
        record = ARENA + 64 + row * 72
        if get(w, record) != 4 or path_ok(w, ARENA + get(w, record + 24), get(w, record + 32)) == False:
            return 0
        at = text_artifact_root(w, at)
        at = quoted(w, at, ARENA + get(w, record + 24), get(w, record + 32))
        row = get(w, record + 16)
    if has_manifest:
        at = text_native_manifest(w, at)
        at = qslot(w, at, S_NATIVE_MANIFEST)
        at = text_native_pin(w, at)
        at = qslot(w, at, S_NATIVE_PIN)
    at = text_args_close(w, at)
    if at > BINDING:
        return 0
    bind(w, S_ARGS, ARGS, at - ARGS)
    return 1

def host(w:mutbuf) -> u64:
    isolated = str_is(w, field(w, F_EXECUTION_MODE), 18)
    if str_is(w, field(w, F_PLATFORM), 12) == False or (str_is(w, field(w, F_EXECUTION_MODE), 13) == False and isolated == False) or boolean(w, field(w, F_ALLOW_EXECUTE), 1) == False or boolean(w, field(w, F_ALLOW_WRITE), 1) == False:
        return 0
    put(w, HOST_ISOLATED, choose(isolated, 1, 0))
    put(w, SYSTEM_JOBCTL, choose(isolated, 1, 0))
    if freeze_string(w, field(w, F_SSH_TARGET), S_SSH_TARGET) == False or get(w, S_SSH_TARGET + 8) == 0 or get(w, S_SSH_TARGET + 8) > 1024:
        return 0
    if freeze_string(w, field(w, F_REMOTE_STATE_DIR), S_REMOTE_STATE) == False or get(w, S_REMOTE_STATE + 8) == 0 or byte(w, get(w, S_REMOTE_STATE)) != 47:
        return 0
    size = get(w, S_REMOTE_STATE + 8)
    while size != 0 and byte(w, get(w, S_REMOTE_STATE) + size - 1) == 47:
        size = size - 1
    put(w, S_REMOTE_STATE + 8, size)
    if freeze_raw(w, field(w, F_EXECUTION_MODE), S_EXECUTION_MODE) == False or freeze_raw(w, field(w, F_ALLOWED_CWD_PREFIXES), S_ALLOWED_CWD) == False:
        return 0
    if freeze_raw(w, field(w, F_ALLOW_JOB_NETWORK), S_ALLOW_NETWORK) == False or freeze_raw(w, field(w, F_ALLOW_DETACHED_FALLBACK), S_ALLOW_FALLBACK) == False:
        return 0
    native = field(w, F_NATIVE_JOBS)
    if native == NONE or is_null(w, native):
        put(w, NATIVE_JOBS_CONFIGURED, 0)
        start = get(w, 64)
        at = text_default_entry(w, start)
        bind(w, S_ENTRY_PATH, start, at - start)
        put(w, 64, at)
        return 1
    put(w, NATIVE_JOBS_CONFIGURED, 1)
    entry = lookup(w, native, F_ENTRY)
    if freeze_string(w, lookup(w, entry, F_EXECUTABLE), S_ENTRY_PATH) == False or path_ok(w, get(w, S_ENTRY_PATH), get(w, S_ENTRY_PATH + 8)) == False:
        return 0
    if freeze_string(w, lookup(w, entry, F_SHA256), S_ENTRY_PIN) == False or role_pin(w, S_ENTRY_PIN, 3) == False:
        return 0
    return native_roles(w, native)

def role_pin(w:mutbuf, slot:u64, role:u64) -> bool:
    if get(w, slot + 8) != 64 or lowerhex(w, get(w, slot), 64) == False:
        return False
    index = 0
    while index < 32:
        hi = hex_digit_value(byte(w, get(w, slot) + index * 2))
        lo = hex_digit_value(byte(w, get(w, slot) + index * 2 + 1))
        if (hi << 4) | lo != byte(w, 4112 + (role - 1) * 64 + index):
            return False
        index = index + 1
    return True

def native_roles(w:mutbuf, native:u64) -> u64:
    if native == NONE or get(w, native) != 6:
        return 0
    row = get(w, native + 24)
    selected = 0
    while row != NONE:
        record = ARENA + 64 + row * 72
        key_at = ARENA + get(w, record + 40)
        key_size = get(w, record + 48)
        role = 0
        if text_is(w, key_at, key_size, 14):
            role = 4
        elif text_is(w, key_at, key_size, 15):
            role = 5
        elif text_is(w, key_at, key_size, 16):
            role = 6
        elif text_is(w, key_at, key_size, 17):
            role = 7
        if role != 0:
            digest = lookup(w, record, F_SHA256)
            if digest == NONE or get(w, digest) != 4:
                return 0
            bind(w, 34000, ARENA + get(w, digest + 24), get(w, digest + 32))
            if role_pin(w, 34000, role) == False or selected & (1 << role) != 0:
                return 0
            selected = selected | (1 << role)
        row = get(w, record + 16)
    return choose(selected == 240, 1, 0)

def request_frame(o:mutbuf, w:mutbuf) -> u32:
    put(w, CHILD_IN, REQUEST_MAGIC)
    put(w, CHILD_IN + 8, get(w, S_ORIGINAL + 8))
    put(w, CHILD_IN + 16, get(w, S_PROFILE + 8))
    put(w, CHILD_IN + 24, get(w, S_ARGUMENTS + 8))
    put(w, CHILD_IN + 32, get(w, S_TOOL + 8))
    put(w, CHILD_IN + 40, get(w, S_REQUEST_KEY + 8))
    at = cp(w, S_CATALOG, CHILD_IN + 48)
    at = cp(w, S_ORIGINAL, at)
    at = cp(w, S_PROFILE, at)
    at = cp(w, S_ARGUMENTS, at)
    at = cp(w, S_TOOL, at)
    at = cp(w, S_REQUEST_KEY, at)
    return child(w, 1, 10, 1, at - CHILD_IN, 524552, 0, 5000000000, NONE)

def binding_frame(o:mutbuf, w:mutbuf) -> u32:
    at = text_env_open(w, get(w, 64))
    at = qslot(w, at, S_TRANSPORT_DIGEST)
    at = text_env_close(w, at)
    bind(w, S_ENV, get(w, 64), at - get(w, 64))
    put(w, 64, at)
    at = text_binding_open(w, BINDING)
    at = cp(w, S_ARGS, at)
    at = text_cpu(w, at)
    at = qslot(w, at, S_CWD)
    at = text_env(w, at)
    at = cp(w, S_ENV, at)
    at = text_executable(w, at)
    at = qslot(w, at, S_EXECUTABLE)
    at = text_host(w, at)
    at = qslot(w, at, S_HOST)
    at = text_memory(w, at)
    at = cp(w, S_MEMORY, at)
    at = text_stdin(w, at)
    at = qslot(w, at, S_WORKER)
    at = text_timeout(w, at)
    at = cp(w, S_TIMEOUT, at)
    at = text_close(w, at)
    if at > WORKER:
        return 0
    bind(w, S_BINDING, BINDING, at - BINDING)
    put(w, CHILD_IN, IDENTITY_MAGIC)
    at = cp(w, S_BINDING, CHILD_IN + 8)
    return child(w, 1, 11, 1, at - CHILD_IN, 72, 0, 5000000000, NONE)

def expected(w:mutbuf) -> u64:
    start = 27262976
    at = text_expected_open(w, start)
    at = cp(w, S_ARGUMENTS, at)
    at = text_backend(w, at)
    at = qslot(w, at, S_BACKEND_PIN)
    at = text_catalog(w, at)
    at = qslot(w, at, S_CATALOG)
    at = text_helpers(w, at)
    if get(w, S_NATIVE_PIN + 8) == 0:
        at = text_null(w, at)
    else:
        at = qslot(w, at, S_NATIVE_PIN)
    at = text_profile(w, at)
    at = qslot(w, at, S_PROFILE_DIGEST)
    at = text_request(w, at)
    at = qslot(w, at, S_REQUEST_DIGEST)
    at = text_tool(w, at)
    at = cp(w, S_TOOL, at)
    at = text_worker(w, at)
    at = qslot(w, at, S_WORKER_PIN)
    at = text_close(w, at)
    return bind(w, S_EXPECTED, start, at - start)
'''

def source():
    return authored(SOURCE,text=TEXT,extra={
      'REQUEST_MAGIC':int.from_bytes(b'HIAWPR01','little'),
      'WORKER_MAGIC':int.from_bytes(b'HIAWPO01','little'),
      'IDENTITY_MAGIC':int.from_bytes(b'HIAJID01','little'),
      'BINDING_MAGIC':int.from_bytes(b'HIAJDO01','little'),
      '_checks':TOOLS+('linux','operator','submit','observation','cancel','launcher','isolated')})
