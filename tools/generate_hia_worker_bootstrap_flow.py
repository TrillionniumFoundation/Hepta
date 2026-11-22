"""Author the native, descriptor-owned Discovery startup sequence."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_bootstrap_assemble import MANIFEST_SLOT
from tools.generate_hia_discovery_bootstrap_plan import BOOTSTRAP_FILES
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_describe_flow import POLICY as DESCRIBE, flow_source
from tools.generate_hia_worker_describe_reactor import program as entry_program
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_bootstrap_flow.hepta')

POLICY = r'''
def bootstrap(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(o) != 2048 or length(w) != 4096:
        return BAD
    state = get(w, 0)
    if state == 0:
        return begin(s, o, w)
    op = get(w, 16)
    if input_word(s, 0) != OBSERVATION or input_word(s, 8) != get(w, 8) or input_word(s, 16) != op:
        return BAD
    extent = input_word(s, 40)
    offset = choose(op == READ, input_word(s, 48), 0)
    captured = input_word(s, 56)
    if extent > DOCUMENT_LIMIT * 4 or offset > extent or captured > extent - offset or captured != length(s) - 64:
        return BAD
    if op == READ and (input_word(s, 32) != get(w, 72) or offset != get(w, 80) or captured != get(w, 88)):
        return BAD
    if op != PATH_EFFECT and input_word(s, 24) != 0:
        return BAD
    if state <= RESOURCE_NAME:
        return index_resources(s, o, w, state)
    if state <= RENDER:
        return prepare_documents(s, o, w, state)
    if state <= BOUND_STORE:
        return bind_storage(s, o, w, state)
    if state <= ACCUMULATED:
        return retain_documents(s, o, w, state)
    return assemble_response(s, o, w, state)

def begin(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 64 + ROLE_COUNT * 40 or input_word(s, 0) != ENTRY:
        return BAD
    cfg = input_word(s, 8)
    pack = input_word(s, 24)
    size = input_word(s, 32)
    if cfg < 179 or cfg > 4274 or valid_fd(pack) == False or pack < 3 or size < 16 or size > DOCUMENT_LIMIT * 4:
        return BAD
    if input_word(s, 40) != 15:
        return BAD
    i = 0
    while i < ROLE_COUNT:
        at = 64 + 40 * i
        fd = input_word(s, at)
        if fd < 3 or valid_fd(fd) == False or fd == pack or input_word(s, at + 8) != 15:
            return BAD
        if input_word(s, at + 16) != 32768 or input_word(s, at + 24) < 64 or input_word(s, at + 32) != ELF_MAGIC:
            return BAD
        j = 0
        while j < i:
            if fd == get(w, ROLE_BASE + j * 8):
                return BAD
            j = j + 1
        put(w, ROLE_BASE + 8 * i, fd)
        i = i + 1
    put(w, CONFIG_BYTES, cfg)
    put(w, PACK_FD, pack)
    put(w, PACK_BYTES, size)
    return read_span(o, w, CONFIG, 0, 0, 176)

def index_resources(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == CONFIG:
        identities = input_word(s, 80)
        digits = input_word(s, 88)
        if (input_word(s, 64) != PLAN_REQUEST or input_word(s, 72) != 0
                or identities < 2 or identities > 4096 or digits == 0 or digits > 2
                or get(w, CONFIG_BYTES) != 176 + identities + digits
                or input_word(s, 96) != 0 or input_word(s, 104) != 0):
            return BAD
        put(w, IDENTITY_BYTES, identities)
        return read_span(o, w, RESOURCE_HEAD, get(w, PACK_FD), 0, 16)
    if state == RESOURCE_HEAD:
        if input_word(s, 64) != DOCUMENT_PACK or input_word(s, 72) != RESOURCE_COUNT:
            return BAD
        put(w, PACK_AT, 16)
        return next_resource(o, w)
    seen = get(w, RESOURCE_INDEX)
    record = RESOURCE_TABLE + seen * RESOURCE_ROW
    if state == RESOURCE_SIZES:
        names = input_word(s, 64)
        body = input_word(s, 72)
        start = get(w, PACK_AT) + 16
        remaining = get(w, PACK_BYTES) - start
        if names < 3 or names > 128 or names > remaining or body == 0 or body > DOCUMENT_LIMIT or body > remaining - names:
            return BAD
        put(w, record, names)
        put(w, record + 8, start + names)
        put(w, record + 16, body)
        put(w, PACK_AT, start + names + body)
        return read_span(o, w, RESOURCE_NAME, get(w, PACK_FD), start, names)
    names = get(w, record)
    previous = 0
    while previous < seen:
        table = RESOURCE_TABLE + previous * RESOURCE_ROW
        if get(w, table) == names and same_name(s, w, table, names):
            return BAD
        previous = previous + 1
    copy_span(s, w, 64, record + 24, names)
    put(w, RESOURCE_INDEX, seen + 1)
    return next_resource(o, w)

def same_name(s:readbuf, w:mutbuf, record:u64, size:u64) -> bool:
    index = 0
    while index < size:
        if byte(s, 64 + index) != byte(w, record + 24 + index):
            return False
        index = index + 1
    return True

def next_resource(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, PACK_AT)
    size = get(w, PACK_BYTES)
    if get(w, RESOURCE_INDEX) == RESOURCE_COUNT:
        if at != size:
            return BAD
        return plan_document(o, w)
    if at > size or size - at < 16:
        return BAD
    return read_span(o, w, RESOURCE_SIZES, get(w, PACK_FD), at, 16)

def plan_document(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, PLAN_REQUEST)
    put(o, HEADER + 8, get(w, ORDINAL))
    fragment(o, 0, 0, 16, get(w, CONFIG_BYTES) - 16)
    return issue(o, w, PLAN, RUN, PLAN_ROLE, 0, 1, 16)

def prepare_documents(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PLAN:
        size = input_word(s, 40)
        fd = input_word(s, 32)
        width = input_word(s, 96)
        source = input_word(s, 80)
        version = input_word(s, 88)
        if prefixed(s) == False or size <= 40 or input_word(s, 72) != WORK_PLAN or width != size - 40:
            return BAD
        if source == 1 and version <= 16:
            put(w, DOC_VERSION, version)
            fragment(o, 0, fd, 40, width)
            return issue(o, w, RENDER, RUN, DISCOVERY_ROLE, 0, 1, 0)
        if source != 2 or version != 0 or width < 3 or width > 128:
            return BAD
        put(w, DOC_VERSION, 0)
        return read_span(o, w, PLAN_NAME, fd, 40, width)
    if state == PLAN_NAME:
        size = length(s) - 64
        j = 0
        while j < RESOURCE_COUNT:
            record = RESOURCE_TABLE + j * RESOURCE_ROW
            if size == get(w, record) and same_name(s, w, record, size):
                return remember_document(o, w, get(w, PACK_FD), get(w, record + 8), get(w, record + 16))
            j = j + 1
        return BAD
    return record_rendered(s, o, w)

def record_rendered(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if prefixed(s) == False or size <= 40 or size > 65576 or input_word(s, 72) == 0:
        return BAD
    if input_word(s, 80) != 0 or input_word(s, 88) != 0 or input_word(s, 96) != size - 40:
        return BAD
    return remember_document(o, w, input_word(s, 32), 40, size - 40)

def remember_document(o:mutbuf, w:mutbuf, fd:u64, offset:u64, size:u64) -> u64:
    ordinal = get(w, ORDINAL)
    at = DOC_TABLE + ordinal * 32
    put(w, at, fd)
    put(w, at + 8, offset)
    put(w, at + 16, size)
    put(w, at + 24, get(w, DOC_VERSION))
    if ordinal == MANIFEST_SLOT:
        return digest_document(o, w)
    put(w, ORDINAL, ordinal + 1)
    if ordinal + 1 < MANIFEST_SLOT:
        return plan_document(o, w)
    return issue(o, w, BOUND_ROOT, ROOT_BIND, 0, 0, 0, 0)

def put_document(w:mutbuf, o:mutbuf) -> u64:
    at = DOC_TABLE + 32 * get(w, ORDINAL)
    return fragment(o, 0, get(w, at), get(w, at + 8), get(w, at + 16))

def digest_document(o:mutbuf, w:mutbuf) -> u64:
    put(o, 384, STORE_HASH)
    put(o, 392, STORE_HASH_TAIL)
    put(o, 400, ARTIFACT_ROOT)
    put(o, 408, ARTIFACT_ROOT_TAIL)
    put(o, 416, 45)
    argv(o, 0, LITERAL_ARG, 384)
    argv(o, 1, JOINED_ARG, 400)
    argv(o, 2, LITERAL_ARG, 416)
    put_document(w, o)
    return issue(o, w, HASHED, RUN, PUBLISHER_ROLE, 3, 1, 0)

def retain_documents(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == HASHED:
        if size < 88 or size > 110 or length(s) < 128:
            return BAD
        return read_span(o, w, HASH_RECEIPT, input_word(s, 32), 0, size)
    if state == HASH_RECEIPT:
        return parse_hash_receipt(s, o, w)
    if state == RETAINED:
        if size < 200 or size > 400 or input_word(s, 64) != DOCUMENT_RECEIPT:
            return BAD
        put(o, TICKET, get(w, ORDINAL))
        copy_private(w, o, DIGEST, TICKET + 8, 64)
        prior = get(w, RECEIPT_BYTES)
        fragment(o, 0, get(w, RECEIPT_FD), 0, prior)
        fragment(o, 1, INLINE_FRAGMENT, TICKET, 72)
        fragment(o, 2, input_word(s, 32), 0, size)
        if prior == 0:
            fragment(o, 0, INLINE_FRAGMENT, TICKET, 72)
            fragment(o, 1, input_word(s, 32), 0, size)
        put(w, RECEIPT_EXPECTED, prior + 72 + size)
        # The ticket precedes this receipt, following the prior receipts.
        return issue(o, w, ACCUMULATED, MAKE, 0, 0, choose(prior == 0, 2, 3), 0)
    if size != get(w, RECEIPT_EXPECTED):
        return BAD
    put(w, RECEIPT_FD, input_word(s, 32))
    put(w, RECEIPT_BYTES, size)
    ordinal = get(w, ORDINAL)
    if ordinal == MANIFEST_SLOT:
        return assemble_manifest(o, w, METADATA, METADATA_REQUEST)
    put(w, ORDINAL, ordinal + 1)
    if ordinal + 1 == MANIFEST_SLOT:
        put(w, DOC_VERSION, 0)
        return assemble_manifest(o, w, MANIFEST_PLAN, MANIFEST_REQUEST)
    return digest_document(o, w)

def parse_hash_receipt(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 64) != HASH_PREFIX or byte(s, 72) != 34 or byte(s, 73) != 58 or byte(s, 74) != 34:
        return BAD
    if input_word(s, 139) != HASH_TAIL or byte(s, 147) != 34 or byte(s, 148) != 58:
        return BAD
    end = length(s)
    if end < 152 or byte(s, end - 2) != 125 or byte(s, end - 1) != 10:
        return BAD
    i = 75
    while i < 139:
        digit = byte(s, i)
        if is_hex(digit) == False:
            return BAD
        store(w, DIGEST + i - 75, digit)
        i = i + 1
    at = 149
    actual = 0
    while at < end - 2:
        digit = byte(s, at)
        if digit < 48 or digit > 57 or actual > DOCUMENT_LIMIT:
            return BAD
        actual = actual * 10 + digit - 48
        at = at + 1
    if actual != get(w, DOC_TABLE + 32 * get(w, ORDINAL) + 16):
        return BAD
    argv(o, 0, INPUT_ARG, 1)
    argv(o, 1, INPUT_ARG, 2)
    j = 0
    while j < 6:
        role = STORE_ROLE + j
        role_argument(w, o, 2 + j, role)
        j = j + 1
    version = get(w, DOC_TABLE + 32 * get(w, ORDINAL) + 24)
    argv(o, 8, DECIMAL_ARG, choose(version == 0, 2, 1))
    argv(o, 9, DECIMAL_ARG, version)
    put_document(w, o)
    return issue(o, w, RETAINED, RUN, CUSTODY_ROLE, 10, 1, 0)

def assemble_manifest(o:mutbuf, w:mutbuf, next:u64, magic:u64) -> u64:
    width = get(w, IDENTITY_BYTES)
    put(o, HEADER, magic)
    put(o, HEADER + 8, width)
    put(o, HEADER + 16, 0)
    fragment(o, 0, 0, 48, 64)
    fragment(o, 1, 0, 176, width)
    fragment(o, 2, get(w, RECEIPT_FD), 0, get(w, RECEIPT_BYTES))
    return issue(o, w, next, RUN, ASSEMBLE_ROLE, 0, 3, 24)

def assemble_response(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == MANIFEST_PLAN:
        if prefixed(s) == False:
            return BAD
        fragment(o, 0, input_word(s, 32), 8, input_word(s, 40) - 8)
        return issue(o, w, MANIFEST_RENDER, RUN, DISCOVERY_ROLE, 0, 1, 0)
    if state == MANIFEST_RENDER:
        return record_rendered(s, o, w)
    if state == METADATA:
        if prefixed(s) == False or input_word(s, 72) != BOOT_METADATA:
            return BAD
        put(w, METADATA_FD, input_word(s, 32))
        put(w, METADATA_BYTES, input_word(s, 40))
        return issue(o, w, ROOT_RECHECKED, ROOT_CHECK, 0, 0, 0, 0)
    if state == ROOT_RECHECKED:
        if same_root(s, w) == False:
            return BAD
        fragment(o, 0, get(w, METADATA_FD), 8, get(w, METADATA_BYTES) - 8)
        return issue(o, w, PUBLISHED, PUBLISH, 0, 0, 1, 0)
    if state == PUBLISHED and length(s) == 64:
        return issue(o, w, PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD
'''

ROOT_POLICY = r'''
def bind_storage(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    status = input_word(s, 24)
    if state == BOUND_ROOT:
        if owned_directory(s) == False:
            return BAD
        put(w, ROOT_FD, input_word(s, 32))
        put(w, ROOT_DEVICE, input_word(s, 72))
        put(w, ROOT_INODE, input_word(s, 80))
        return legacy_path(o, w, 0)
    if state == LEGACY_PATH:
        if status != 2 or length(s) != 64:
            return BAD
        probe = get(w, LEGACY_INDEX) + 1
        if probe < 4:
            return legacy_path(o, w, probe)
        put(o, HEADER, STORE)
        return path_action(o, w, STORE_PROBED, 2, 6)
    if state == STORE_PROBED:
        if status == 2 and length(s) == 64:
            return list_directory(o, w, ROOT_ENTRIES, get(w, ROOT_FD))
        if owned_directory(s) == False:
            return BAD
        put(w, EXISTING_STORE, 1)
        return make_artifacts(o, w)
    if state == ROOT_ENTRIES or state == ARTIFACT_ENTRIES:
        if status != 0 or input_word(s, 32) != get(w, LIST_FD):
            return BAD
        if input_word(s, 40) == 0:
            if state == ROOT_ENTRIES:
                return make_artifacts(o, w)
            return initialize_store(o, w)
        if clean_entries(s, state == ROOT_ENTRIES) == False:
            return BAD
        return list_directory(o, w, state, get(w, LIST_FD))
    if state == ARTIFACTS_CREATED:
        if (status != 0 and status != 17) or length(s) != 64:
            return BAD
        put(o, HEADER, ARTIFACTS_HEAD)
        put(o, HEADER + 8, 115)
        return path_action(o, w, ARTIFACTS_OPEN, 2, 10)
    if state == ARTIFACTS_OPEN:
        if owned_directory(s) == False:
            return BAD
        if get(w, EXISTING_STORE) != 0:
            return begin_retention(o, w)
        return list_directory(o, w, ARTIFACT_ENTRIES, input_word(s, 32))
    if state == INIT_RECEIPT:
        if input_word(s, 40) != 256 or input_word(s, 64) != STORE_INIT or input_word(s, 72) != 1:
            return BAD
        put(o, HEADER, STORE)
        return path_action(o, w, BOUND_STORE, 2, 6)
    if state == BOUND_STORE and owned_directory(s):
        return begin_retention(o, w)
    return BAD

def owned_directory(s:readbuf) -> bool:
    if length(s) != 104 or input_word(s, 24) != 0 or input_word(s, 32) < 3:
        return False
    if valid_fd(input_word(s, 32)) == False:
        return False
    mode = input_word(s, 88)
    return (mode & 61440) == 16384 and (mode & 18) == 0 and input_word(s, 64) == input_word(s, 96)

def same_root(s:readbuf, w:mutbuf) -> bool:
    return (owned_directory(s) and input_word(s, 32) == get(w, ROOT_FD)
            and input_word(s, 72) == get(w, ROOT_DEVICE) and input_word(s, 80) == get(w, ROOT_INODE))

def legacy_path(o:mutbuf, w:mutbuf, index:u64) -> u64:
    put(w, LEGACY_INDEX, index)
    put(o, HEADER, SQLITE_HEAD)
    if index == 0:
        put(o, HEADER + 8, SQLITE_TAIL)
        return path_action(o, w, LEGACY_PATH, 1, 14)
    if index == 1:
        put(o, HEADER + 8, SQLITE_WAL)
        put(o, HEADER + 16, 108)
        return path_action(o, w, LEGACY_PATH, 1, 18)
    if index == 2:
        put(o, HEADER + 8, SQLITE_SHM)
        put(o, HEADER + 16, 109)
        return path_action(o, w, LEGACY_PATH, 1, 18)
    put(o, HEADER + 8, SQLITE_JOURNAL)
    put(o, HEADER + 16, SQLITE_JOURNAL_TAIL)
    return path_action(o, w, LEGACY_PATH, 1, 22)

def path_action(o:mutbuf, w:mutbuf, next:u64, action:u64, size:u64) -> u64:
    put(o, 144, action)
    return issue(o, w, next, PATH_EFFECT, 0, 0, 0, size)

def list_directory(o:mutbuf, w:mutbuf, next:u64, fd:u64) -> u64:
    put(w, LIST_FD, fd)
    put(o, 72, fd)
    return issue(o, w, next, DIR_ENTRIES, 0, 0, 0, 0)

def clean_entries(s:readbuf, allow_artifacts:bool) -> bool:
    at = 64
    end = length(s)
    while at < end:
        if end - at < 20:
            return False
        extent = byte(s, at + 16) + 256 * byte(s, at + 17)
        if extent < 20 or extent > end - at:
            return False
        name = at + 19
        stop = at + extent
        j = name
        while j < stop and byte(s, j) != 0:
            j = j + 1
        width = j - name
        if j == stop or allowed_entry(s, name, width, allow_artifacts) == False:
            return False
        at = stop
    return True

def allowed_entry(s:readbuf, name:u64, width:u64, allow_artifacts:bool) -> bool:
    if width == 1:
        return byte(s, name) == 46
    if width == 2:
        return byte(s, name) == 46 and byte(s, name + 1) == 46
    if width != 9 or allow_artifacts == False:
        return False
    return input_word(s, name) == ARTIFACTS_HEAD and byte(s, name + 8) == 115

def make_artifacts(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, ARTIFACTS_HEAD)
    put(o, HEADER + 8, 115)
    return path_action(o, w, ARTIFACTS_CREATED, 3, 10)

def initialize_store(o:mutbuf, w:mutbuf) -> u64:
    put(o, 384, STORE)
    argv(o, 0, INPUT_ARG, 1)
    argv(o, 1, LITERAL_ARG, 384)
    return issue(o, w, INIT_RECEIPT, RUN, INIT_ROLE, 2, 0, 0)

def begin_retention(o:mutbuf, w:mutbuf) -> u64:
    put(w, ORDINAL, 0)
    return digest_document(o, w)
'''


def program():
    words = {
        'ENTRY': b'HIADRI01', 'COMMAND': b'HIADFC01', 'OBSERVATION': b'HIADFO01',
        'PLAN_REQUEST': b'HIADBQ01', 'DOCUMENT_PACK': b'HIADBF01', 'WORK_PLAN': b'HIADBP01',
        'STORE_HASH': b'store-ha', 'STORE_HASH_TAIL': b'sh', 'ARTIFACT_ROOT': b'/artifac',
        'ARTIFACT_ROOT_TAIL': b'ts', 'DOCUMENT_RECEIPT': b'HIADOC01',
        'HASH_PREFIX': b'{"sha256', 'HASH_TAIL': b'","bytes',
        'MANIFEST_REQUEST': b'HIADBM01', 'METADATA_REQUEST': b'HIADBT01', 'BOOT_METADATA': b'HIADMT01',
        'STORE_INIT': b'HIAWNA01', 'STORE': b'store', 'ARTIFACTS_HEAD': b'artifact',
        'SQLITE_HEAD': b'state.sq', 'SQLITE_TAIL': b'lite3', 'SQLITE_WAL': b'lite3-wa',
        'SQLITE_SHM': b'lite3-sh', 'SQLITE_JOURNAL': b'lite3-jo',
        'SQLITE_JOURNAL_TAIL': b'urnal',
    }
    values = {name: int.from_bytes(raw, 'little') for name, raw in words.items()}
    values.update(BAD=0xfffffffd, HEADER=512, TICKET=416, ARGUMENTS=192, ELF_MAGIC=0x464c457f,
                  ROLE_COUNT=11, RESOURCE_COUNT=len(BOOTSTRAP_FILES), MANIFEST_SLOT=MANIFEST_SLOT,
                  RESOURCE_TABLE=512, RESOURCE_ROW=152, DOC_TABLE=2112, DIGEST=3040, ROLE_BASE=352,
                  INLINE_FRAGMENT=(1 << 64) - 1, DEFAULT_CHILD_LEASE=10_000_000_000,
                  DOCUMENT_LIMIT=1048576,
                  RUN=1, READ=2, PUBLISH=3, FINISHED=5, MAKE=11,
                  ROOT_BIND=14, PATH_EFFECT=15, DIR_ENTRIES=16, ROOT_CHECK=17,
                  INPUT_ARG=1, LITERAL_ARG=2, DECIMAL_ARG=3, FD_ARG=4, JOINED_ARG=5,
                  PLAN_ROLE=0, DISCOVERY_ROLE=1, ASSEMBLE_ROLE=2, CUSTODY_ROLE=3,
                  INIT_ROLE=4, STORE_ROLE=5, PUBLISHER_ROLE=8)
    fields = (
        'CONFIG_BYTES', 'PACK_FD', 'PACK_BYTES', 'PACK_AT', 'RESOURCE_INDEX', 'IDENTITY_BYTES',
        'ORDINAL', 'DOC_VERSION', 'ROOT_FD', 'ROOT_DEVICE', 'ROOT_INODE', 'LEGACY_INDEX',
        'EXISTING_STORE', 'LIST_FD', 'RECEIPT_FD', 'RECEIPT_BYTES', 'RECEIPT_EXPECTED',
        'METADATA_FD', 'METADATA_BYTES',
    )
    values.update({name: 128 + i * 8 for i, name in enumerate(fields)})
    states = (
        'CONFIG', 'RESOURCE_HEAD', 'RESOURCE_SIZES', 'RESOURCE_NAME', 'PLAN', 'PLAN_NAME', 'RENDER',
        'BOUND_ROOT', 'LEGACY_PATH', 'STORE_PROBED', 'ROOT_ENTRIES', 'ARTIFACTS_CREATED',
        'ARTIFACTS_OPEN', 'ARTIFACT_ENTRIES', 'INIT_RECEIPT', 'BOUND_STORE',
        'HASHED', 'HASH_RECEIPT', 'RETAINED', 'ACCUMULATED',
        'MANIFEST_PLAN', 'MANIFEST_RENDER', 'METADATA', 'ROOT_RECHECKED', 'PUBLISHED',
    )
    values.update({name: i for i, name in enumerate(states, 1)})
    controls = (
        function(DESCRIBE, 'issue').replace('seq > 160', 'seq > 1536').replace(
            '    put(o, 152,', '    put(o, 136, 0)\n    put(o, 152,'),
        *(function(DESCRIBE, name) for name in
          ('read_span', 'argv', 'fragment', 'prefixed', 'copy_private', 'role_argument')),
        *(function(entry_program(), name) for name in ('valid_fd', 'is_hex', 'copy_span', 'input_word', 'put', 'write')),
        function(RELEASE_WRITER, 'get'),
    )
    return flow_source(POLICY, (ROOT_POLICY, *controls), values)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
