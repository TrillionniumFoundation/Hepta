"""Author HIA's native Store command and response protocol."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_artifact import DOCUMENT_KINDS, kind_match_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_store_transport.hepta'

WIRE = {
    'BUILD_COMMAND': b'HIASTCM1',
    'READ_ACK': b'HIASTAK1',
    'READ_ROW': b'HIASTRW1',
    'READ_EVENT': b'HIASTEV1',
    'READ_VALUES': b'HIASTVL1',
    'READ_TRANSACTION': b'HIASTTX1',
    'BUILD_PARAMETERS': b'HIASTPA1',
    'UNIQUE_START': b'HIASTUR1',
    'UNIQUE_REQUEST': b'HIASTUP1',
    'COMMIT_INTENT': b'HIASTCP1',
    'ARTIFACT_JOURNAL_ACK': b'HIAJMO01',
    'CONTEXT_CLAIM': b'HCTXRSP1',
    'UNIQUE_CONSUME': b'HIASTUC1',
    'COMMAND': b'HIATCM01',
    'ACK': b'HIATXR01',
    'ROW': b'HIAQRF01',
    'VALUES': b'HIAROW01',
    'WAL_TRANSACTION': b'HIAWTA01',
    'WAL_ANCHOR': b'HIAWAK01',
    'QUERY_PARAMETERS': b'HIAQPA01',
    'INSERT_PARAMETERS': b'HIAINS01',
    'UPDATE_PARAMETERS': b'HIAUPB01',
    'PROFILE_ID_PREFIX': b'{"id":"a',
    'PROFILE_DIGEST_PREFIX': b'","sha25',
    'PROFILE_DIGEST_TAIL': b'6":"',
    'PROFILE_URI_PREFIX': b'","uri":',
    'PROFILE_URI_MIDDLE': b'"hia://a',
    'PROFILE_URI_TAIL': b'rtifacts',
    'ARTIFACT_URI_HEAD': b'hia://ar',
    'ARTIFACT_URI_TAIL': b'tifacts/',
    'ARTIFACT_TOOL_HEAD': b'hia_arti',
    'ARTIFACT_TOOL_TAIL': b'fact',
    'CONTEXT_TOOL_HEAD': b'hia_cont',
    'CONTEXT_TOOL_TAIL': b'ext',
    'RUNNING_STATE': b'running',
}

POLICY = '''
def store_transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8:
        return 0
    role = read_word(s, 0)
    if length(w) == 8:
        if role == ACK:
            return store_ready(s, o)
        return 0
    if role == UNIQUE_START or role == UNIQUE_REQUEST or role == UNIQUE_CONSUME:
        return unique_stream(s, o, w, role)
    if role == BUILD_COMMAND:
        if length(s) != 40 or length(o) != 48 or read_word(s, 8) == 0:
            return 0
        write_word(o, 0, COMMAND)
        write_word(o, 8, 1)
        copy_fields(s, o, 8, 16, 32)
        return 48
    if role == READ_ACK:
        if length(s) != 104 or length(o) != 48:
            return 0
        if read_word(s, 24) != ACK or read_word(s, 32) != 1:
            return 0
        if read_word(s, 40) != read_word(s, 8) or read_word(s, 48) != read_word(s, 16):
            return 0
        copy_fields(s, o, 56, 0, 48)
        return 48
    if role == READ_ROW:
        if length(s) != 88 or length(o) != 56:
            return 0
        if read_word(s, 24) != ROW or read_word(s, 40) != read_word(s, 8):
            return 0
        if read_word(s, 64) > read_word(s, 16) or read_word(s, 80) != 0:
            return 0
        copy_fields(s, o, 32, 0, 56)
        return 56
    if role == READ_EVENT:
        if length(o) != 16 or length(s) < 104:
            return 0
        return store_query_event(s, o)
    if role == READ_VALUES:
        if length(o) != 16 or length(s) < 32:
            return 0
        return store_values(s, o)
    if role == READ_TRANSACTION:
        if length(o) != 16 or (length(s) != 48 and length(s) != 304):
            return 0
        return store_transaction(s, o)
    if role == BUILD_PARAMETERS:
        if length(s) < 40:
            return 0
        return store_parameters(s, o)
    return 0

# Only the first unsolicited acknowledgement of an actually started Store is
# valid here. The executable and private pipe custody belong to its caller.
def store_ready(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 80 or length(o) != 16:
        return 0
    if read_word(s, 8) != 1 or read_word(s, 16) != 0 or read_word(s, 24) != 0:
        return 0
    if read_word(s, 32) != 0 or read_word(s, 40) != 0:
        return 0
    if read_word(s, 56) != 0 or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 0
    return event_result(o, 1, read_word(s, 48))

# Indexed reads and typed durable inserts share this immutable transaction envelope.
# Mode 0 borrows an already-open transaction. Mode 1 owns BEGIN and ROLLBACK.
# Mode 2 owns ROLLBACK after readiness of a freshly connected Store.
def request_unique(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(w) != 2304 or length(s) < 105 or read_state(w, 0) != 0:
        return 0
    request = read_word(s, 8)
    plan = read_word(s, 16)
    mode = read_word(s, 24)
    generation = read_word(s, 32)
    size = read_word(s, 40)
    if request > 18446744073709551612 or mode > 2 or size != length(s) - 48:
        return 0
    if plan == 23:
        if mode != 0 or valid_reservation_ack(s, size) == False:
            return 0
    elif plan == 24:
        if mode != 0 or valid_context_record(s, size) == False:
            return 0
    elif plan == 25:
        if mode != 0 or valid_context_budget(s, size) == False:
            return 0
    elif plan == 26:
        if mode != 0 or valid_context_claim(s, size) == False:
            return 0
    elif plan == 4:
        if size != 92 or valid_context_lookup(s) == False:
            return 0
    elif plan == 12:
        if valid_worker_profile_lookup(s, size) == False:
            return 0
    elif plan == 10:
        if valid_cursor_retain(s, size) == False:
            return 0
    elif plan == 18:
        if valid_cost_insert(s, size) == False:
            return 0
    elif plan == 19:
        if valid_profile_insert(s, size) == False:
            return 0
    elif plan == 20:
        if valid_discovery_insert(s, size) == False:
            return 0
    elif plan == 21:
        if valid_request_reserve(s, size) == False:
            return 0
    elif plan == 22:
        if valid_request_complete(s, size) == False:
            return 0
    else:
        if plan != 1 and plan != 2 and plan != 3 and plan != 6 and plan != 9:
            return 0
        cap = choose(plan == 2, 192, choose(plan == 3, 208, 2048))
        if size > 56 + cap or read_word(s, 48) != QUERY_PARAMETERS:
            return 0
        if read_word(s, 56) != 1 or read_word(s, 64) != 1 or read_word(s, 72) != size:
            return 0
        if read_word(s, 80) != 3 or read_word(s, 88) != 56 or read_word(s, 96) != size - 56:
            return 0
        if (plan == 1 or plan == 9) and (size != 120 or valid_hex(s, 104, 64) == False):
            return 0
    configure_unique(w, request, plan)
    write_word(w, 112, mode)
    write_word(w, 120, generation)
    write_word(w, 128, size)
    write_word(w, 136, 1)
    if plan == 23 or plan == 26:
        write_word(w, 152, choose(plan == 23, 1, 2))
        return begin_unique_commit(o, w)
    if plan != 18 and plan != 22:
        copy_fields(s, w, 48, 192, size)
    if mode == 1:
        return send_unique(o, w, 21, 0, 0, 6)
    return issue_unique_query(o, w)

# The borrowed reservation may commit only after the Journal image has
# acknowledged its stage-2 state. This command sends no arbitrary Store bytes.
def valid_reservation_ack(s:readbuf, size:u64) -> bool:
    if size != 64 or read_word(s, 48) != ARTIFACT_JOURNAL_ACK:
        return False
    if read_word(s, 56) != 2 or read_word(s, 64) != 11 or read_word(s, 72) != 0:
        return False
    if read_word(s, 80) != 48 or read_word(s, 88) != 0 or read_word(s, 96) != 48:
        return False
    return read_word(s, 104) == 512

# Query ordinal 12 projects the one retained profile document reference.
def valid_worker_profile_lookup(s:readbuf, size:u64) -> bool:
    if size < 157 or size > 159 or read_word(s, 48) != QUERY_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 2 or read_word(s, 72) != size:
        return False
    width = size - 144
    if valid_cell(s, 80, 3, 80, width) == False or valid_cell(s, 104, 3, 80 + width, 64) == False:
        return False
    if worker_profile_id(s, 128, width) == False:
        return False
    return valid_hex(s, 128 + width, 64)

def valid_context_lookup(s:readbuf) -> bool:
    if read_word(s, 48) != QUERY_PARAMETERS or read_word(s, 56) != 1:
        return False
    if read_word(s, 64) != 1 or read_word(s, 72) != 92:
        return False
    return valid_cell(s, 80, 3, 56, 36) and context_id(s, 104)

def valid_context_claim(s:readbuf, size:u64) -> bool:
    if size != 80 or read_word(s, 48) != CONTEXT_CLAIM or read_word(s, 56) != 0:
        return False
    if read_word(s, 64) != 45 or read_word(s, 72) == 0 or read_word(s, 80) != 2 or read_word(s, 88) != 1:
        return False
    if read_word(s, 96) != 0 or read_word(s, 104) != 0:
        return False
    return (read_word(s, 112) | read_word(s, 120)) != 0

def context_id(s:readbuf, at:u64) -> bool:
    return byte(s, at) == 99 and byte(s, at + 1) == 116 and byte(s, at + 2) == 120 and byte(s, at + 3) == 45 and valid_hex(s, at + 4, 32)

def valid_context_record(s:readbuf, size:u64) -> bool:
    if size <= 412 or size > 432 or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 1 or read_word(s, 72) != 0 or read_word(s, 80) != 4:
        return False
    if valid_cell(s, 88, 3, 136, 36) == False or valid_cell(s, 112, 3, 172, 64) == False:
        return False
    if valid_cell(s, 136, 3, 236, 176) == False or valid_cell(s, 160, 3, 412, size - 412) == False:
        return False
    if context_id(s, 184) == False or valid_hex(s, 220, 64) == False:
        return False
    if read_word(s, 284) != PROFILE_ID_PREFIX or byte(s, 292) != 45 or valid_hex(s, 293, 32) == False:
        return False
    if read_word(s, 325) != PROFILE_DIGEST_PREFIX or (read_word(s, 333) & 4294967295) != PROFILE_DIGEST_TAIL:
        return False
    if read_word(s, 401) != PROFILE_URI_PREFIX or read_word(s, 409) != PROFILE_URI_MIDDLE:
        return False
    if read_word(s, 417) != PROFILE_URI_TAIL or byte(s, 425) != 47 or valid_hex(s, 426, 32) == False:
        return False
    if byte(s, 458) != 34 or byte(s, 459) != 125:
        return False
    index = 0
    while index < 64:
        if byte(s, 220 + index) != byte(s, 337 + index):
            return False
        index = index + 1
    return canonical_timestamp(s, 460, size - 412)

def valid_context_budget(s:readbuf, size:u64) -> bool:
    if size != 100 or read_word(s, 48) != INSERT_PARAMETERS or read_word(s, 56) != 1:
        return False
    if read_word(s, 64) != 3 or read_word(s, 72) != 0 or read_word(s, 80) != 1:
        return False
    return valid_cell(s, 88, 3, 64, 36) and context_id(s, 112)

# One previously issued page cursor, with its exact artifact digest and offset.
def valid_cursor_retain(s:readbuf, size:u64) -> bool:
    if size < 278 or size > 533 or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 10 or read_word(s, 72) != 0 or read_word(s, 80) != 4:
        return False
    offset = 136
    field = 0
    while field < 4:
        at = 88 + 24 * field
        kind = read_word(s, at)
        extent = read_word(s, at + 16)
        if read_word(s, at + 8) != offset or extent > size - offset:
            return False
        if kind != choose(field == 3, 1, 3):
            return False
        if field == 0 and extent != 69:
            return False
        if field == 1 and (extent == 0 or extent > 256):
            return False
        if field == 2 and extent != 64:
            return False
        if field == 3 and extent != 8:
            return False
        offset = offset + extent
        field = field + 1
    return offset == size


# A cost record is the existing Store INSERT ordinal 2, not query ordinal 2.
# Keep the large body in the same sealed control mapping; only the mechanical
# split command extent is handed back to the adapter after full validation.
def valid_cost_insert(s:readbuf, size:u64) -> bool:
    if size < 184 or size > 8390608 or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 2 or read_word(s, 72) != 0 or read_word(s, 80) != 6:
        return False
    offset = 184
    field = 0
    while field < 6:
        at = 88 + 24 * field
        extent = read_word(s, at + 16)
        kind = read_word(s, at)
        if read_word(s, at + 8) != offset or extent > size - offset:
            return False
        if kind != choose(field == 0 and extent == 0, 0, 3):
            return False
        if field < 2 and extent > 512:
            return False
        if field == 2 and extent != 66 and extent != 43:
            return False
        if field == 3 and (extent == 0 or extent > 20):
            return False
        if field == 4 and extent != 8 and extent != 9:
            return False
        if field == 5 and (extent < 31 or extent > 8388608):
            return False
        offset = offset + extent
        field = field + 1
    return offset == size

# Profile records bind a public profile name and content digest to an issued
# artifact. The existing Store INSERT ordinal is 11; its uniqueness semantics
# and WAL format do not change.
def valid_profile_insert(s:readbuf, size:u64) -> bool:
    if size < 353 or size > 544 or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 11 or read_word(s, 72) != 0 or read_word(s, 80) != 3:
        return False
    name = read_word(s, 104)
    if name == 0 or name > 192 or size != 352 + name:
        return False
    if read_word(s, 88) != 3 or read_word(s, 96) != 112:
        return False
    if read_word(s, 112) != 3 or read_word(s, 120) != 112 + name or read_word(s, 128) != 64:
        return False
    if read_word(s, 136) != 3 or read_word(s, 144) != 176 + name or read_word(s, 152) != 176:
        return False
    at = 160
    while at < 160 + name:
        ch = byte(s, at)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 122) and ch != 45 and ch != 46 and ch != 95:
            return False
        at = at + 1
    return profile_reference(s, at, at + 64)

def profile_reference(s:readbuf, digest:u64, reference:u64) -> bool:
    if read_word(s, reference) != PROFILE_ID_PREFIX or byte(s, reference + 8) != 45:
        return False
    if read_word(s, reference + 41) != PROFILE_DIGEST_PREFIX:
        return False
    if read_word(s, reference + 49) & 4294967295 != PROFILE_DIGEST_TAIL:
        return False
    if read_word(s, reference + 117) != PROFILE_URI_PREFIX:
        return False
    if read_word(s, reference + 125) != PROFILE_URI_MIDDLE or read_word(s, reference + 133) != PROFILE_URI_TAIL:
        return False
    if byte(s, reference + 141) != 47 or byte(s, reference + 174) != 34 or byte(s, reference + 175) != 125:
        return False
    index = 0
    while index < 64:
        ch = byte(s, digest + index)
        if lower_hex(ch) == False or byte(s, reference + 53 + index) != ch:
            return False
        if index < 32:
            if lower_hex(byte(s, reference + 9 + index)) == False or lower_hex(byte(s, reference + 142 + index)) == False:
                return False
        index = index + 1
    return True

def lower_hex(ch:u64) -> bool:
    return (ch >= 48 and ch <= 57) or (ch >= 97 and ch <= 102)

def valid_hex(s:readbuf, at:u64, count:u64) -> bool:
    end = at + count
    while at < end:
        if lower_hex(byte(s, at)) == False:
            return False
        at = at + 1
    return True

# Narrow immutable Agent artifact insert. Metadata is the original empty
# object; data custody and content verification occur before request delivery.
def valid_discovery_insert(s:readbuf, size:u64) -> bool:
    if (size != 401 and size != 403 and size != 405 and size != 406 and size != 411) or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 9 or read_word(s, 72) != 0 or read_word(s, 80) != 6:
        return False
    kind = size - 396
    offset = 184
    field = 0
    while field < 6:
        extent = choose(field == 0, 34, choose(field == 2, 48, choose(field == 3, kind, choose(field == 4, 2, 64))))
        at = 88 + field * 24
        if read_word(s, at) != 3 or read_word(s, at + 8) != offset or read_word(s, at + 16) != extent:
            return False
        offset = offset + extent
        field = field + 1
    if byte(s, 232) != 97 or byte(s, 233) != 45:
        return False
    if read_word(s, 330) != ARTIFACT_URI_HEAD or read_word(s, 338) != ARTIFACT_URI_TAIL:
        return False
    if document_kind_allowed(s, 378, kind) == False:
        return False
    if byte(s, 378 + kind) != 123 or byte(s, 379 + kind) != 125:
        return False
    return valid_hex(s, 234, 32) and valid_hex(s, 266, 64) and valid_hex(s, 346, 32) and valid_hex(s, 380 + kind, 64)

# Reserve binds the original request and compatibility tool identity, not
# a setter for arbitrary request-state rows.
def valid_request_reserve(s:readbuf, size:u64) -> bool:
    if size < 331 or size > 351 or read_word(s, 48) != INSERT_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 6 or read_word(s, 72) != 0 or read_word(s, 80) != 6:
        return False
    if valid_cell(s, 88, 3, 184, 64) == False or valid_cell(s, 112, 3, 248, 64) == False:
        return False
    tool = read_word(s, 360)
    width = 0
    if tool == ARTIFACT_TOOL_HEAD and read_word(s, 368) & 4294967295 == ARTIFACT_TOOL_TAIL:
        width = 12
    elif tool == CONTEXT_TOOL_HEAD and read_word(s, 368) & 16777215 == CONTEXT_TOOL_TAIL:
        width = 11
    if width == 0 or size <= 319 + width or size > 339 + width:
        return False
    if valid_cell(s, 136, 3, 312, width) == False or valid_cell(s, 160, 3, 312 + width, 7) == False:
        return False
    if valid_cell(s, 184, 0, 319 + width, 0) == False or valid_cell(s, 208, 3, 319 + width, size - 319 - width) == False:
        return False
    if valid_hex(s, 232, 64) == False or valid_hex(s, 296, 64) == False:
        return False
    return read_word(s, 360 + width) & 72057594037927935 == RUNNING_STATE and canonical_timestamp(s, 367 + width, size - 319 - width)

def canonical_timestamp(s:readbuf, at:u64, extent:u64) -> bool:
    if extent > 1 and byte(s, at) == 48:
        return False
    out = 0
    stop = at + extent
    while at < stop:
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return False
        digit = ch - 48
        if out > 1844674407370955161 or (out == 1844674407370955161 and digit > 5):
            return False
        out = out * 10 + digit
        at = at + 1
    return True

# The sealed tail is the already rendered terminal plus its exact journal key.
def valid_request_complete(s:readbuf, size:u64) -> bool:
    if size < 154 or size > 8388760 or read_word(s, 48) != UPDATE_PARAMETERS:
        return False
    if read_word(s, 56) != 1 or read_word(s, 64) != 1 or read_word(s, 72) != 0 or read_word(s, 80) != 2:
        return False
    width = size - 152
    if valid_cell(s, 88, 3, 88, width) == False or valid_cell(s, 112, 3, 88 + width, 64) == False:
        return False
    if byte(s, 136) != 123 or byte(s, 135 + width) != 125:
        return False
    return valid_hex(s, 136 + width, 64)

def valid_cell(s:readbuf, at:u64, kind:u64, offset:u64, size:u64) -> bool:
    return read_word(s, at) == kind and read_word(s, at + 8) == offset and read_word(s, at + 16) == size

def durable_write(plan:u64) -> bool:
    return plan == 10 or (plan >= 18 and plan <= 26)

def configure_unique(w:mutbuf, request:u64, plan:u64) -> u64:
    write_word(w, 8, request)
    write_word(w, 16, plan)
    write_word(w, 24, choose(plan == 4, 3, choose(plan == 6, 6, choose(plan == 9, 4, choose(plan == 12, 2, 1)))))
    write_word(w, 32, choose(plan == 4, 31, choose(plan == 6, 15, choose(plan == 12, 4, 63))))
    return write_word(w, 40, choose(plan == 4 or plan == 6 or plan == 12, 512, choose(plan == 9, 8389120, 1000000032)))

def issue_unique_query(o:mutbuf, w:mutbuf) -> u64:
    plan = read_state(w, 16)
    if plan == 18 or plan == 22:
        # The Store sees command 27 and normal write target 1. The adapter
        # transmits the already validated, immutable payload without recopying it.
        send_unique(o, w, 27, 1, 0, 10)
        extent = read_state(w, 128)
        write_word(o, 0, 7)
        write_word(o, 8, extent)
        write_word(o, 16, 48)
        write_word(o, 72, extent)
        return 80
    if durable_write(plan):
        return send_unique(o, w, 27, 1, read_state(w, 128), 10)
    return send_unique(o, w, 27, plan + 3, read_state(w, 128), 1)

def send_unique(o:mutbuf, w:mutbuf, kind:u64, target:u64, extent:u64, phase:u64) -> u64:
    request = read_state(w, 8) + 1
    write_word(w, 8, request)
    write_word(w, 0, phase)
    write_word(o, 0, 4)
    write_word(o, 8, 48 + extent)
    write_word(o, 16, 8)
    write_word(o, 32, COMMAND)
    write_word(o, 40, 1)
    write_word(o, 48, request)
    write_word(o, 56, kind)
    write_word(o, 64, target)
    write_word(o, 72, extent)
    at = 0
    while at < extent:
        store(o, 80 + at, byte(w, 192 + at))
        at = at + 1
    return 80 + extent

def unique_transaction(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if length(w) != 2304:
        return 0
    if phase >= 10:
        return durable_insert_result(s, o, w, phase)
    if phase == 6 or phase == 8:
        if length(s) != 16 or read_word(s, 8) != ACK:
            return 0
        return stream_read(o, w, phase + 1, 72)
    if length(s) != 80 or read_word(s, 8) != 1 or read_word(s, 16) != read_state(w, 8):
        return 0
    if read_word(s, 32) != 0:
        return 0
    generation = read_word(s, 48)
    if phase == 7:
        if read_word(s, 24) != 21 or generation < read_state(w, 120):
            return 0
        write_word(w, 120, generation)
        return issue_unique_query(o, w)
    if phase != 9 or read_word(s, 24) != 3 or generation != read_state(w, 120):
        return 0
    return finish_unique(o, w)

# Write acknowledgements, WAL transition receipts and source correlation are
# validated before a typed insert transaction may return a usable receipt.
def durable_insert_result(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    plan = read_state(w, 16)
    if durable_write(plan) == False:
        return 0
    if phase == 10 or phase == 12 or phase == 14:
        if length(s) != 16:
            return 0
        magic = read_word(s, 8)
        if phase == 12 and magic == WAL_TRANSACTION:
            return stream_read(o, w, 13, 248)
        if magic != ACK:
            return 0
        return stream_read(o, w, choose(phase == 10, 11, 15), 72)
    if phase == 13:
        if length(s) != 256 or read_word(s, 128) != WAL_ANCHOR or read_word(s, 136) != 1:
            return 0
        prior = read_state(w, 120)
        if prior == 18446744073709551615 or read_word(s, 144) != prior + 1:
            return 0
        write_word(w, 160, 1)
        return stream_read(o, w, 14, 8)
    if length(s) != 80 or read_word(s, 8) != 1 or read_word(s, 16) != read_state(w, 8):
        return 0
    if phase == 11:
        return durable_insert_ack(s, o, w)
    if phase != 15 or read_word(s, 24) != 2 or read_word(s, 32) != 0:
        return 0
    count = read_word(s, 40)
    if (plan == 23 and count != 1) or (plan == 26 and count != 2):
        return 0
    advanced = choose(count == 0, 0, 1)
    prior = read_state(w, 120)
    if advanced != read_state(w, 160) or advanced > 18446744073709551615 - prior:
        return 0
    if read_word(s, 48) != prior + advanced:
        return 0
    write_word(w, 120, prior + advanced)
    return finish_unique(o, w)

def must_write(plan:u64) -> bool:
    return plan == 18 or plan == 24 or plan == 25

def durable_insert_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if read_word(s, 24) != 27:
        return 0
    status = read_word(s, 32)
    skipped = read_word(s, 56)
    mode = read_state(w, 112)
    if status == 5 or status == 22:
        write_word(w, 144, 1)
        if mode == 0:
            return finish_unique(o, w)
        return send_unique(o, w, 3, 0, 0, 8)
    if status != 0 or skipped > 1 or (must_write(read_state(w, 16)) and skipped != 0):
        return 0
    write_word(w, 152, 1 - skipped)
    if mode == 0:
        return finish_unique(o, w)
    return begin_unique_commit(o, w)

def begin_unique_commit(o:mutbuf, w:mutbuf) -> u64:
    send_unique(o, w, 2, 0, 0, 12)
    # Publish intent into the private, unsealed sink before sending COMMIT.
    # Losing the final receipt after that point cannot become a clean refusal.
    write_word(w, 168, 1)
    write_word(o, 0, 6)
    write_word(o, 80, COMMIT_INTENT)
    return 88

def finish_unique(o:mutbuf, w:mutbuf) -> u64:
    write_word(o, 0, 5)
    plan = read_state(w, 16)
    if durable_write(plan):
        write_word(o, 8, read_state(w, 168) * 8)
        write_word(o, 16, read_state(w, 152))
        write_word(o, 24, read_state(w, 144))
    else:
        write_word(o, 8, read_state(w, 48))
        write_word(o, 16, read_state(w, 80))
    write_word(o, 32, read_state(w, 8))
    write_word(o, 40, read_state(w, 120))
    return 48

# A durable indexed read is exactly one authenticated summary and final
# acknowledgement around at most one row. The transport only delivers the
# requested byte extents and copies accepted fragments to its private sink.
def unique_stream(s:readbuf, o:mutbuf, w:mutbuf, role:u64) -> u64:
    if (length(w) != 128 and length(w) != 2304) or length(o) < 8160:
        return 0
    write_word(o, 16, 0)
    write_word(o, 24, 0)
    if role == UNIQUE_REQUEST:
        return request_unique(s, o, w)
    if role == UNIQUE_START:
        if length(s) != 24 or read_state(w, 0) != 0:
            return 0
        request = read_word(s, 8)
        plan = read_word(s, 16)
        if request == 0 or (plan != 1 and plan != 2 and plan != 3 and plan != 6 and plan != 9):
            return 0
        configure_unique(w, request, plan)
        return stream_read(o, w, 1, 8)
    phase = read_state(w, 0)
    if phase >= 6:
        return unique_transaction(s, o, w, phase)
    if phase == 1 and length(s) == 16:
        magic = read_word(s, 8)
        if magic == ACK and read_state(w, 56) == 1:
            return stream_read(o, w, 4, 72)
        if magic == ROW and read_state(w, 56) == 0:
            return stream_read(o, w, 2, 56)
    elif phase == 2 and length(s) == 64:
        return stream_header(s, o, w)
    elif phase == 3:
        return stream_payload(s, o, w)
    elif phase == 4 and length(s) == 80:
        if read_word(s, 8) != 1 or read_word(s, 16) != read_state(w, 8):
            return 0
        if read_word(s, 24) != 27 or read_word(s, 32) != 0:
            return 0
        if length(w) == 2304 and read_state(w, 136) == 1:
            if read_state(w, 112) == 0:
                return finish_unique(o, w)
            return send_unique(o, w, 3, 0, 0, 8)
        write_word(w, 0, 5)
        write_word(o, 0, 3)
        write_word(o, 8, read_state(w, 48))
        write_word(o, 16, read_state(w, 80))
        return 32
    return 0

def stream_header(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = read_word(s, 8)
    table = read_word(s, 16)
    identity = read_word(s, 24)
    offset = read_word(s, 32)
    extent = read_word(s, 40)
    active = read_state(w, 64)
    used = read_state(w, 48)
    if table != read_state(w, 24) or extent > 8128 or read_word(s, 56) != 0:
        return 0
    if kind == 1 and active == 0 and extent == 128 and offset == 0:
        write_word(w, 96, identity)
    elif kind == 4:
        if active != 0 or extent != 416:
            return 0
    else:
        if active != 1 or identity != read_state(w, 72) or offset != used:
            return 0
        if kind == 3 and extent == 0 and read_state(w, 80) == 0:
            write_word(w, 64, 0)
            write_word(w, 80, 1)
            return stream_read(o, w, 1, 8)
        if kind != 2 or extent == 0 or extent > read_state(w, 40) - used:
            return 0
    write_word(w, 88, kind)
    write_word(w, 104, extent)
    return stream_read(o, w, 3, extent)

def stream_payload(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    extent = read_state(w, 104)
    if length(s) != 8 + extent:
        return 0
    kind = read_state(w, 88)
    if kind == 1:
        if read_state(w, 80) != 0:
            return 0
        write_word(w, 64, 1)
        write_word(w, 72, read_state(w, 96))
    elif kind == 2:
        used = read_state(w, 48)
        write_word(w, 0, 1)
        write_word(w, 48, used + extent)
        write_word(o, 0, 2)
        write_word(o, 8, extent)
        write_word(o, 16, used)
        copy_fields(s, o, 8, 32, extent)
        return 32 + extent
    elif kind == 4:
        if read_word(s, 392) != read_state(w, 16) or read_word(s, 400) != read_state(w, 32):
            return 0
        if read_word(s, 416) != read_state(w, 80):
            return 0
        write_word(w, 56, 1)
    else:
        return 0
    return stream_read(o, w, 1, 8)

def stream_read(o:mutbuf, w:mutbuf, phase:u64, extent:u64) -> u64:
    write_word(w, 0, phase)
    write_word(o, 0, 1)
    write_word(o, 8, extent)
    return 32

def read_state(w:mutbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(w, at + count) << (count * 8))
        count = count + 1
    return value

def store_query_event(s:readbuf, o:mutbuf) -> u64:
    kind = read_word(s, 8)
    size = read_word(s, 32)
    active = read_word(s, 40)
    if active > 1 or read_word(s, 80) > 1:
        return 0
    if kind == 4 and active == 0 and size == 416 and length(s) == 520:
        return query_summary(s, o)
    if length(s) != 104:
        return 0
    if kind == 1 and active == 0 and size == 128 and read_word(s, 24) == 0:
        return event_result(o, 1, 0)
    if active == 1 and read_word(s, 16) == read_word(s, 48) and read_word(s, 24) == read_word(s, 56):
        if kind == 2:
            used = read_word(s, 56)
            limit = read_word(s, 64)
            if size == 0 or used > limit or size > limit - used:
                return event_result(o, 101, 0)
            return event_result(o, 2, 0)
        if kind == 3 and size == 0:
            if read_word(s, 80) != 0 and read_word(s, 72) != 0:
                return event_result(o, 102, 0)
            return event_result(o, 3, 0)
    return event_result(o, 104, 0)

def query_summary(s:readbuf, o:mutbuf) -> u64:
    if read_word(s, 488) != read_word(s, 88) or read_word(s, 496) != read_word(s, 96) or read_word(s, 512) != read_word(s, 72):
        return event_result(o, 103, 0)
    return event_result(o, 4, read_word(s, 504))

def store_values(s:readbuf, o:mutbuf) -> u64:
    extent = read_word(s, 24)
    if extent < 32:
        return event_result(o, 2, 0)
    if length(s) < 64 or read_word(s, 32) != VALUES or read_word(s, 40) != 1:
        return event_result(o, 3, 0)
    if read_word(s, 16) != read_word(s, 48):
        return event_result(o, 3, 0)
    count = read_word(s, 56)
    directory = length(s) - 64
    if count != read_word(s, 8) or count > directory:
        return event_result(o, 3, 0)
    if directory != count * 24 or extent < directory + 32:
        return event_result(o, 3, 0)
    offset = directory + 32
    index = 0
    while index < count:
        cell = 64 + index * 24
        kind = read_word(s, cell)
        size = read_word(s, cell + 16)
        if read_word(s, cell + 8) != offset or size > extent - offset:
            return event_result(o, 4, index)
        if kind > 4 or (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
            return event_result(o, 5, index)
        offset = offset + size
        index = index + 1
    if offset != extent:
        return event_result(o, 6, count)
    return event_result(o, 1, count)

def store_transaction(s:readbuf, o:mutbuf) -> u64:
    kind = read_word(s, 8)
    status = read_word(s, 16)
    count = read_word(s, 24)
    previous = read_word(s, 32)
    generation = read_word(s, 40)
    receipt = length(s) == 304
    if kind == 0 or kind == 21:
        if receipt or status != 0 or (kind == 21 and generation < previous):
            return event_result(o, 2, 0)
        return event_result(o, 1, generation)
    if kind != 2 and kind != 3:
        return 0
    advance = kind == 2 and count != 0
    if status != 0 or generation < previous or receipt != advance:
        return event_result(o, 3, 0)
    if advance:
        if generation - previous != 1:
            return event_result(o, 3, 0)
        if read_word(s, 48) != WAL_TRANSACTION or read_word(s, 176) != WAL_ANCHOR:
            return event_result(o, 4, 0)
        if read_word(s, 184) != 1 or read_word(s, 192) != generation:
            return event_result(o, 4, 0)
    elif generation != previous:
        return event_result(o, 3, 0)
    return event_result(o, 1, generation)

def store_parameters(s:readbuf, o:mutbuf) -> u64:
    form = read_word(s, 8)
    count = read_word(s, 24)
    limit = read_word(s, 32)
    fields = length(s) - 40
    if count > fields or fields != count * 16:
        return 0
    header = 40
    if form == QUERY_PARAMETERS:
        header = 32
    elif form != INSERT_PARAMETERS and form != UPDATE_PARAMETERS:
        return 0
    directory_end = header + count * 24
    if length(o) != directory_end or directory_end > limit:
        return 0
    offset = directory_end
    index = 0
    while index < count:
        cell = 40 + index * 16
        target = header + index * 24
        kind = read_word(s, cell)
        size = read_word(s, cell + 8)
        if size > limit - offset:
            return 0
        if kind > 4 or (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
            return 0
        write_word(o, target, kind)
        write_word(o, target + 8, offset)
        write_word(o, target + 16, size)
        offset = offset + size
        index = index + 1
    write_word(o, 0, form)
    write_word(o, 8, 1)
    if header == 32:
        write_word(o, 16, count)
        write_word(o, 24, offset)
    else:
        write_word(o, 16, read_word(s, 16))
        write_word(o, 24, 0)
        write_word(o, 32, count)
    return directory_end

def event_result(o:mutbuf, decision:u64, total:u64) -> u64:
    write_word(o, 0, decision)
    write_word(o, 8, total)
    return 16

def read_word(s:readbuf, at:u64) -> u64:
    count = 0
    value = 0
    while count < 8:
        value = value | (byte(s, at + count) << (count * 8))
        count = count + 1
    return value

def write_word(o:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(o, at + count, (value >> (count * 8)) & 255)
        count = count + 1
    return 0

def copy_fields(s:readbuf, o:mutbuf, start:u64, end:u64, extent:u64) -> u64:
    index = 0
    while index < extent:
        store(o, end + index, byte(s, start + index))
        index = index + 1
    return 0
'''


def source_program():
    import re

    profiles = []
    for kind in ('artifact', 'compiler', 'target'):
        name = ('hia-' + kind + '-v1').encode()
        predicate = ' and '.join(f'byte(s, at + {i}) == {byte}' for i, byte in enumerate(name))
        profiles.append(f'    if length == {len(name)} and {predicate}:\n        return True')
    profile_gate = '\ndef worker_profile_id(s:readbuf, at:u64, length:u64) -> bool:\n'
    profile_gate += '\n'.join(profiles) + '\n    return False\n'
    kinds = '\ndef document_kind_allowed(s:readbuf, at:u64, length:u64) -> bool:\n'
    for index, raw in enumerate(DOCUMENT_KINDS, 1):
        kinds += (f'    if length == {len(raw)} and document_kind_matches(s, at, {index}):\n'
                  '        return True\n')
    kinds += '    return False\n'
    return re.sub(r'\b(' + '|'.join(WIRE) + r')\b',
        lambda name: str(int.from_bytes(WIRE[name.group()], 'little')),
        POLICY + profile_gate + kinds + kind_match_source())


if __name__ == '__main__':
    program = document(source_program(), module='agent_store_transport')
    SOURCE.write_text(render_assembly(program))
