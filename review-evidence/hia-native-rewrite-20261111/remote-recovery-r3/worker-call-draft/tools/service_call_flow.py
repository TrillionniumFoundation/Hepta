"""Complete selected-call control decisions for the native Worker.

NEW UNEXECUTED DEVELOPMENT. This is the full call-order/state owner, not a
completed namespace, cached-value decoder, schema validator or business peer.
Only a fixed native coordinator may service its issued operations. A Python
operation switch is a development observation fixture, never production closure.
"""
CONSTANTS = {
 'CALL_COMMAND':int.from_bytes(b'HIASCC01','little'),
 'CALL_ACK':int.from_bytes(b'HIASCA01','little'),
 'CALL_STATE':int.from_bytes(b'HIASCW01','little'),
 'CALL_EVENT':int.from_bytes(b'HIASCE01','little'),
 'CALL_SOURCE':int.from_bytes(b'HIASCS01','little'),
 'CALL_BAD':0xfffffffd,'CALL_MAX':(1<<64)-1,
 'C_STATUS':8,'C_LEASE':16,'C_CALL':24,'C_SEQ':32,'C_PHASE':40,
 'C_PEER':48,'C_PROFILE':64,'C_DIGITS':72,'C_MAIN':80,
 'C_TOOL':1024,'C_ARGS':1032,'C_CATALOG':1040,'C_TOOLS':1048,
 'C_IDENTITIES':1056,'C_STORE':1064,'C_INSTALL':1072,'C_STARTED':1080,
 'C_REQUEST':1088,'C_RESPONSE':1096,'C_CONTEXT_ID':1104,'C_JOURNAL':1112,
 'C_KEY':1120,'C_DIGEST':1128,'C_TOOL_ID':1136,'C_RAW':1144,
 'C_CACHED':1152,'C_ROW_RESPONSE':1160,'C_CONTEXT':1168,
 'C_CONTEXT_REF':1176,'C_RESULT':1184,'C_BINDS':1192,'C_RETURN':1200,
 'C_FLAGS':1208,'C_STATUS_ENUM':1216,'C_RESPONSE_WIRE':1224,
 'C_COST_WIRE':1232,'C_STR_TOOL':1240,'C_WALL':1248,'C_SOURCE_EPOCH':1256,
 'C_PREPARE_ACTION':1264,
 'C_RESULTS':1280,
 'P_MONOTONIC':1,'P_UUID':2,'P_UNADMITTED':3,'P_INSTALL':4,
 'P_WIRE':5,'P_DATA':6,'P_ORIGINAL':7,'P_JOURNAL':8,
 'P_ALIAS_KEYS':9,'P_RESOLVE':10,'P_ALIAS':11,'P_BEGIN':12,
 'P_SQL':13,'P_COMMIT':14,'P_ROLLBACK':15,'P_LOOKUP_WIRE':16,
 'P_REALTIME':17,'P_INSERT':18,'P_CACHED':19,'P_INPUT_SCHEMA':20,
 'P_CATALOG':21,'P_IDENTITY':22,'P_CONTEXT_VIEW':23,'P_CONTEXT':24,
 'P_BUDGET':25,'P_BUSINESS':26,'P_SUCCESS':27,'P_OUTPUT_SCHEMA':28,
 'P_REPLAY':29,'P_REFUSAL':30,'P_ERROR':31,'P_INSTALL_WRAP':32,
 'P_STR':33,'P_WALL':34,'P_COST':35,'P_UPDATE':36,
 'P_CONTEXT_ID':37,'P_LOOKUP_BIND':38,'P_ARGUMENT_URI':39,'P_REQUEST_ID':40,
}
BODY = r'''
def service_call(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 4096:
        return CALL_BAD
    if get(w, C_STATUS) == 4:
        return CALL_BAD
    if get(w, C_STATUS) == 0:
        if call_initial(s, r, w) == 0:
            return call_refuse(w, 1)
    else:
        if get(w, 0) != CALL_STATE or get(w, C_STATUS) != 2 or length(s) != 64:
            return call_refuse(w, 2)
        i = 0
        while i < 64:
            if byte(s, i) != byte(w, 768 + i):
                return call_refuse(w, 3)
            i = i + 1
        if call_receive(r, w) == 0:
            return call_refuse(w, 4)
    while get(w, C_STATUS) == 1:
        phase = get(w, C_PHASE)
        result = 0
        if phase < 20:
            result = call_start(w)
        elif phase < 40:
            result = call_lookup(w)
        elif phase < 60:
            result = call_alias(w)
        elif phase < 72:
            result = call_validation(w)
        elif phase < 100:
            result = call_business(w)
        elif phase >= 800 and phase < 900:
            result = call_finish(w)
        elif phase >= 900:
            result = call_exception(w)
        else:
            return call_refuse(w, 5)
        if result != 0:
            return result
    return call_refuse(w, 6)

def call_initial(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != CALL_SOURCE or length(r) != 256:
        return 0
    if word(r, 0) != CALL_COMMAND or word(r, 8) == 0 or word(r, 16) == 0:
        return 0
    if word(s, 8) != word(r, 8) or word(s, 16) != word(r, 16) or word(s, 24) != word(r, 96):
        return 0
    i = 32
    while i < 64:
        if word(s, i) != 0:
            return 0
        i = i + 8
    i = 104
    while i < 256:
        if word(r, i) != 0:
            return 0
        i = i + 8
    i = 40
    while i < 96:
        if word(r, i) == 0:
            return 0
        i = i + 8
    i = 0
    while i < 4096:
        if byte(w, i) != 0:
            return 0
        i = i + 1
    put(w, 0, CALL_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, word(r, 8))
    put(w, C_CALL, word(r, 16))
    put(w, C_PROFILE, word(r, 24))
    put(w, C_DIGITS, word(r, 32))
    put(w, C_TOOL, word(r, 40))
    put(w, C_ARGS, word(r, 48))
    put(w, C_CATALOG, word(r, 56))
    put(w, C_TOOLS, word(r, 64))
    put(w, C_IDENTITIES, word(r, 72))
    put(w, C_STORE, word(r, 80))
    put(w, C_INSTALL, word(r, 88))
    put(w, C_SOURCE_EPOCH, word(r, 96))
    put(w, C_PHASE, 10)
    i = 0
    while i < 64:
        store(w, 768 + i, byte(s, i))
        i = i + 1
    return 1

def call_receive(r:readbuf, w:mutbuf) -> u64:
    if length(r) != 256 or word(r, 0) != CALL_ACK or word(r, 8) != get(w, C_LEASE):
        return 0
    if word(r, 16) != get(w, C_CALL) or word(r, 24) != get(w, C_SEQ) or word(r, 32) != get(w, C_PEER):
        return 0
    if word(r, 40) > 1:
        return 0
    i = 192
    while i < 256:
        if word(r, i) != 0:
            return 0
        i = i + 8
    if word(r, 40) == 0:
        if word(r, 48) != 0 or word(r, 56) != 0:
            return 0
    elif word(r, 48) == 0 or word(r, 56) == 0:
        return 0
    count = choose(word(r, 40) == 0, call_result_count(get(w, C_PEER)), 0)
    if count == CALL_MAX:
        return 0
    i = count
    while i < 16:
        if word(r, 64 + i * 8) != 0:
            return 0
        i = i + 1
    i = 0
    while i < 16:
        put(w, C_RESULTS + i * 8, word(r, 64 + i * 8))
        i = i + 1
    put(w, C_STATUS, 1)
    if get(w, C_PHASE) == 901:
        decision = call_rollback_observation(w, word(r, 40), word(r, 48), word(r, 56))
        call_unwind_phase(w, decision)
    elif word(r, 40) != 0:
        decision = call_failure(w, word(r, 48), word(r, 56))
        call_unwind_phase(w, decision)
    return 1

def call_result_count(peer:u64) -> u64:
    if peer == P_JOURNAL:
        return 13
    if peer == P_LOOKUP_WIRE or peer == P_CACHED or peer == P_CONTEXT_VIEW:
        return 2
    if peer == P_ALIAS_KEYS or peer == P_BEGIN or peer == P_COMMIT or peer == P_ROLLBACK:
        return 0
    if peer == P_INPUT_SCHEMA or peer == P_CATALOG or peer == P_IDENTITY or peer == P_BUDGET:
        return 0
    if peer == P_OUTPUT_SCHEMA or peer == P_REPLAY or peer == P_REFUSAL:
        return 0
    if peer >= 1 and peer <= 40:
        return 1
    return CALL_MAX

def call_unwind_phase(w:mutbuf, decision:u64) -> u64:
    if decision == UW_ROLLBACK:
        put(w, C_PHASE, 900)
    elif decision == UW_DOMAIN_HANDLER:
        put(w, C_PHASE, 910)
    elif decision == UW_INSTALL_WRAP:
        put(w, C_PHASE, 920)
    else:
        put(w, C_PHASE, 930)
    return 0

def call_issue(w:mutbuf, peer:u64, next_phase:u64, scope:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u32:
    put(w, C_PEER, peer)
    put(w, C_PHASE, next_phase)
    call_scope(w, scope)
    put(w, 640, a)
    put(w, 648, b)
    put(w, 656, c)
    put(w, 664, d)
    put(w, 672, e)
    put(w, 680, f)
    put(w, C_STATUS, 2)
    return call_event(w, 1)

def call_journal(w:mutbuf, stage:u64, raw:u64, next_phase:u64, scope:u64) -> u32:
    return call_issue(w, P_JOURNAL, next_phase, scope, get(w, C_JOURNAL), stage, raw, get(w, C_PROFILE), get(w, C_DIGITS), get(w, C_TOOL))

def call_journal_identity(w:mutbuf) -> u64:
    if get(w, C_RESULTS + 8) != get(w, C_JOURNAL):
        return 0
    if get(w, C_RESULTS + 40) > 12:
        return 0
    return 1

def call_start(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 10:
        return call_issue(w, P_MONOTONIC, 11, UW_SCOPE_INITIAL, 0, 0, 0, 0, 0, 0)
    if phase == 11:
        put(w, C_STARTED, get(w, C_RESULTS))
        return call_issue(w, P_UUID, 12, UW_SCOPE_INITIAL, 0, 0, 0, 0, 0, 0)
    if phase == 12:
        return call_issue(w, P_UNADMITTED, 13, UW_SCOPE_INITIAL, get(w, C_RESULTS), 0, 0, 0, 0, 0)
    if phase == 13:
        put(w, C_REQUEST, get(w, C_RESULTS))
        return call_issue(w, P_INSTALL, 14, UW_SCOPE_INSTALL, get(w, C_INSTALL), get(w, C_TOOLS), get(w, C_PROFILE), get(w, C_DIGITS), 0, 0)
    if phase == 14:
        if get(w, C_RESULTS) == 0:
            return call_refuse(w, 10)
        put(w, C_JOURNAL, get(w, C_RESULTS))
        put(w, C_MAIN, 1)
        return call_issue(w, P_WIRE, 15, UW_SCOPE_MAIN, get(w, C_ARGS), 0, 0, 0, 0, 0)
    if phase == 15:
        return call_issue(w, P_DATA, 16, UW_SCOPE_MAIN, get(w, C_RESULTS), get(w, C_PROFILE), get(w, C_DIGITS), 0, 0, 0)
    if phase == 16:
        put(w, C_ARGS, get(w, C_RESULTS))
        return call_issue(w, P_ORIGINAL, 17, UW_SCOPE_MAIN, get(w, C_TOOL), get(w, C_ARGS), 0, 0, 0, 0)
    if phase == 17:
        return call_issue(w, P_WIRE, 18, UW_SCOPE_MAIN, get(w, C_RESULTS), 0, 0, 0, 0, 0)
    if phase == 18:
        return call_journal(w, 0, get(w, C_RESULTS), 19, UW_SCOPE_NATIVE)
    if phase == 19:
        if call_journal_identity(w) == 0:
            return call_refuse(w, 11)
        put(w, C_KEY, get(w, C_RESULTS + 24))
        put(w, C_DIGEST, get(w, C_RESULTS + 32))
        put(w, C_TOOL_ID, get(w, C_RESULTS + 40))
        put(w, C_PREPARE_ACTION, get(w, C_RESULTS))
        return call_issue(w, P_REQUEST_ID, 9, UW_SCOPE_MAIN, get(w, C_JOURNAL), 0, 0, 0, 0, 0)
    if phase == 9:
        put(w, C_REQUEST, get(w, C_RESULTS))
        action = get(w, C_PREPARE_ACTION)
        if action == 11:
            return call_issue(w, P_REFUSAL, 999, UW_SCOPE_MAIN, get(w, C_JOURNAL), get(w, C_PROFILE), 0, 0, 0, 0)
        if action == 7:
            put(w, C_PHASE, 40)
        elif action == 2:
            put(w, C_PHASE, 20)
        elif action == 1:
            put(w, C_PHASE, 60)
        else:
            return call_refuse(w, 12)
        return 0
    return call_refuse(w, 13)

def call_lookup(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 20:
        return call_issue(w, P_BEGIN, 21, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
    if phase == 21:
        call_begin_transaction(w, 0)
        return call_issue(w, P_LOOKUP_BIND, 22, UW_SCOPE_MAIN, get(w, C_JOURNAL), 0, 0, 0, 0, 0)
    if phase == 22:
        return call_issue(w, P_SQL, 23, UW_SCOPE_MAIN, get(w, C_STORE), 7, get(w, C_RESULTS), 0, 0, 0)
    if phase == 23:
        return call_issue(w, P_LOOKUP_WIRE, 24, UW_SCOPE_NATIVE, get(w, C_RESULTS), 0, 0, 0, 0, 0)
    if phase == 24:
        put(w, C_ROW_RESPONSE, get(w, C_RESULTS + 8))
        return call_journal(w, 1, get(w, C_RESULTS), 25, UW_SCOPE_NATIVE)
    if phase == 25:
        if call_journal_identity(w) == 0:
            return call_refuse(w, 20)
        action = get(w, C_RESULTS)
        if action == 11:
            return call_issue(w, P_REFUSAL, 999, UW_SCOPE_MAIN, get(w, C_JOURNAL), get(w, C_PROFILE), 0, 0, 0, 0)
        if action == 3:
            return call_issue(w, P_REALTIME, 26, UW_SCOPE_MAIN, 0, 0, 0, 0, 0, 0)
        if action == 4:
            return call_issue(w, P_CACHED, 32, UW_SCOPE_NATIVE, get(w, C_JOURNAL), get(w, C_ROW_RESPONSE), get(w, C_PROFILE), get(w, C_DIGITS), 0, 0)
        return call_refuse(w, 21)
    if phase == 26:
        return call_issue(w, P_INSERT, 27, UW_SCOPE_MAIN, get(w, C_JOURNAL), get(w, C_TOOL), get(w, C_RESULTS), 0, 0, 0)
    if phase == 27:
        return call_issue(w, P_SQL, 28, UW_SCOPE_MAIN, get(w, C_STORE), 8, get(w, C_RESULTS), 0, 0, 0)
    if phase == 28:
        return call_journal(w, 2, 0, 29, UW_SCOPE_ACK)
    if phase == 29:
        if call_journal_identity(w) == 0 or get(w, C_RESULTS) != 1:
            return call_refuse(w, 22)
        call_before_commit(w)
        return call_issue(w, P_COMMIT, 30, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
    if phase == 30:
        call_after_commit(w)
        put(w, C_PHASE, 60)
        return 0
    if phase == 32:
        put(w, C_CACHED, get(w, C_RESULTS + 8))
        if get(w, C_RESULTS) == 6:
            return call_issue(w, P_REPLAY, 33, UW_SCOPE_MAIN, get(w, C_CACHED), get(w, C_ARGS), 0, 0, 0, 0)
        if get(w, C_RESULTS) != 5:
            return call_refuse(w, 23)
        put(w, C_PHASE, 33)
        return 0
    if phase == 33:
        put(w, C_RETURN, get(w, C_CACHED))
        call_before_commit(w)
        return call_issue(w, P_COMMIT, 34, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
    if phase == 34:
        call_after_commit(w)
        put(w, C_PHASE, 800)
        return 0
    return call_refuse(w, 24)

def call_alias(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 40:
        return call_issue(w, P_ALIAS_KEYS, 41, UW_SCOPE_MAIN, get(w, C_ARGS), 0, 0, 0, 0, 0)
    if phase == 41:
        return call_issue(w, P_ARGUMENT_URI, 42, UW_SCOPE_MAIN, get(w, C_ARGS), 0, 0, 0, 0, 0)
    if phase == 42:
        return call_issue(w, P_RESOLVE, 43, UW_SCOPE_MAIN, get(w, C_STORE), get(w, C_RESULTS), 0, 0, 0, 0)
    if phase == 43:
        return call_issue(w, P_ALIAS, 44, UW_SCOPE_MAIN, get(w, C_CATALOG), get(w, C_RESULTS), get(w, C_ARGS), 0, 0, 0)
    if phase == 44:
        put(w, C_ARGS, get(w, C_RESULTS))
        return call_journal(w, 4, 0, 45, UW_SCOPE_NATIVE)
    if phase == 45:
        if call_journal_identity(w) == 0 or get(w, C_RESULTS) != 1:
            return call_refuse(w, 30)
        put(w, C_TOOL_ID, get(w, C_RESULTS + 40))
        put(w, C_TOOL, get(w, C_RESULTS + 96))
        put(w, C_PHASE, 60)
        return 0
    return call_refuse(w, 31)

def call_validation(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 60:
        return call_issue(w, P_INPUT_SCHEMA, 61, UW_SCOPE_MAIN, get(w, C_TOOLS), get(w, C_TOOL), get(w, C_ARGS), 0, 0, 0)
    if phase == 61:
        if get(w, C_TOOL_ID) != 1:
            return call_issue(w, P_CATALOG, 62, UW_SCOPE_MAIN, get(w, C_ARGS), get(w, C_CATALOG), 0, 0, 0, 0)
        put(w, C_PHASE, 62)
        return 0
    if phase == 62:
        return call_issue(w, P_IDENTITY, 63, UW_SCOPE_MAIN, get(w, C_INSTALL), get(w, C_IDENTITIES), 0, 0, 0, 0)
    if phase == 63:
        return call_issue(w, P_CONTEXT_VIEW, 64, UW_SCOPE_MAIN, get(w, C_ARGS), 0, 0, 0, 0, 0)
    if phase == 64:
        if get(w, C_RESULTS) == 0:
            put(w, C_PHASE, 69)
            return 0
        if get(w, C_RESULTS) != 1:
            return call_refuse(w, 40)
        put(w, C_CONTEXT_REF, get(w, C_RESULTS + 8))
        return call_issue(w, P_CONTEXT, 65, UW_SCOPE_MAIN, get(w, C_STORE), get(w, C_CONTEXT_REF), get(w, C_IDENTITIES), get(w, C_CATALOG), 0, 0)
    if phase == 65:
        put(w, C_CONTEXT, get(w, C_RESULTS))
        return call_issue(w, P_CONTEXT_ID, 66, UW_SCOPE_MAIN, get(w, C_CONTEXT_REF), 0, 0, 0, 0, 0)
    if phase == 66:
        put(w, C_CONTEXT_ID, get(w, C_RESULTS))
        tool = get(w, C_TOOL_ID)
        if tool == 5 or tool == 11:
            put(w, C_PHASE, 69)
            return 0
        return call_issue(w, P_BUDGET, 67, UW_SCOPE_MAIN, get(w, C_STORE), get(w, C_CONTEXT), choose(tool == 6, 1, 0), 0, 0, 0)
    if phase == 67:
        put(w, C_PHASE, 69)
        return 0
    if phase == 69:
        return call_journal(w, 5, 0, 70, UW_SCOPE_NATIVE)
    if phase == 70:
        if call_journal_identity(w) == 0:
            return call_refuse(w, 41)
        if get(w, C_RESULTS) == 8:
            return call_issue(w, P_BEGIN, 71, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
        if get(w, C_RESULTS) != 1:
            return call_refuse(w, 42)
        put(w, C_PHASE, 73)
        return 0
    if phase == 71:
        call_begin_transaction(w, 1)
        put(w, C_PHASE, 73)
        return 0
    return call_refuse(w, 43)

def call_business(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 73:
        if get(w, C_TOOL_ID) == 0 or get(w, C_TOOL_ID) > 11:
            return call_refuse(w, 54)
        return call_issue(w, P_BUSINESS, 74, UW_SCOPE_MAIN, get(w, C_TOOL_ID), get(w, C_ARGS), get(w, C_STORE), get(w, C_IDENTITIES), get(w, C_CATALOG), 0)
    if phase == 74:
        put(w, C_RESULT, get(w, C_RESULTS))
        return call_issue(w, P_SUCCESS, 75, UW_SCOPE_MAIN, get(w, C_REQUEST), get(w, C_RESULT), 0, 0, 0, 0)
    if phase == 75:
        put(w, C_RESPONSE, get(w, C_RESULTS))
        return call_issue(w, P_OUTPUT_SCHEMA, 76, UW_SCOPE_MAIN, get(w, C_TOOLS), get(w, C_TOOL), get(w, C_RESPONSE), 0, 0, 0)
    if phase == 76:
        if get(w, UW_TX) == 2:
            return call_issue(w, P_WIRE, 77, UW_SCOPE_NATIVE, get(w, C_RESPONSE), 0, 0, 0, 0, 0)
        put(w, C_PHASE, 800)
        return 0
    if phase == 77:
        return call_journal(w, 6, get(w, C_RESULTS), 78, UW_SCOPE_NATIVE)
    if phase == 78:
        if call_journal_identity(w) == 0:
            return call_refuse(w, 50)
        if get(w, C_RESULTS) == 0:
            put(w, C_PHASE, 80)
            return 0
        if get(w, C_RESULTS) != 9:
            return call_refuse(w, 51)
        return call_issue(w, P_UPDATE, 79, UW_SCOPE_MAIN, get(w, C_RESULTS + 64), get(w, C_JOURNAL), 0, 0, 0, 0)
    if phase == 79:
        return call_issue(w, P_SQL, 82, UW_SCOPE_MAIN, get(w, C_STORE), 9, get(w, C_RESULTS), 0, 0, 0)
    if phase == 82:
        return call_journal(w, 7, 0, 83, UW_SCOPE_ACK)
    if phase == 83:
        if call_journal_identity(w) == 0 or get(w, C_RESULTS) != 0:
            return call_refuse(w, 52)
        put(w, C_PHASE, 80)
        return 0
    if phase == 80:
        call_before_commit(w)
        return call_issue(w, P_COMMIT, 81, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
    if phase == 81:
        call_after_commit(w)
        put(w, C_PHASE, 800)
        return 0
    return call_refuse(w, 53)

def call_finish(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 800:
        if call_finally_required(w) == 0:
            return call_terminal(w)
        if get(w, C_RESPONSE) == 0:
            return call_journal(w, 8, 0, 802, UW_SCOPE_FINALLY)
        return call_issue(w, P_WIRE, 801, UW_SCOPE_FINALLY, get(w, C_RESPONSE), 0, 0, 0, 0, 0)
    if phase == 801:
        return call_journal(w, 8, get(w, C_RESULTS), 802, UW_SCOPE_FINALLY)
    if phase == 802:
        if call_journal_identity(w) == 0:
            return call_refuse(w, 60)
        if get(w, C_RESULTS) != 0 and get(w, C_RESULTS) != 10:
            return call_refuse(w, 61)
        put(w, C_FLAGS, get(w, C_RESULTS + 48))
        put(w, C_STATUS_ENUM, get(w, C_RESULTS + 56))
        put(w, C_RESPONSE_WIRE, get(w, C_RESULTS + 64))
        put(w, C_COST_WIRE, get(w, C_RESULTS + 72))
        if get(w, C_FLAGS) > 3:
            return call_refuse(w, 62)
        if (get(w, C_FLAGS) & 1) != 0:
            return call_issue(w, P_STR, 803, UW_SCOPE_FINALLY, get(w, C_TOOL), 0, 0, 0, 0, 0)
        put(w, C_PHASE, 807)
        return 0
    if phase == 803:
        put(w, C_STR_TOOL, get(w, C_RESULTS))
        return call_issue(w, P_MONOTONIC, 804, UW_SCOPE_FINALLY, 0, 0, 0, 0, 0, 0)
    if phase == 804:
        return call_issue(w, P_WALL, 805, UW_SCOPE_FINALLY, get(w, C_RESULTS), get(w, C_STARTED), 0, 0, 0, 0)
    if phase == 805:
        put(w, C_WALL, get(w, C_RESULTS))
        return call_issue(w, P_COST, 806, UW_SCOPE_FINALLY, get(w, C_CONTEXT_ID), get(w, C_STR_TOOL), get(w, C_REQUEST), get(w, C_WALL), get(w, C_STATUS_ENUM), get(w, C_COST_WIRE))
    if phase == 806:
        return call_issue(w, P_SQL, 807, UW_SCOPE_FINALLY, get(w, C_STORE), 10, get(w, C_RESULTS), 0, 0, 0)
    if phase == 807:
        if (get(w, C_FLAGS) & 2) != 0:
            return call_issue(w, P_UPDATE, 808, UW_SCOPE_FINALLY, get(w, C_RESPONSE_WIRE), get(w, C_JOURNAL), 0, 0, 0, 0)
        return call_terminal(w)
    if phase == 808:
        return call_issue(w, P_SQL, 809, UW_SCOPE_FINALLY, get(w, C_STORE), 9, get(w, C_RESULTS), 0, 0, 0)
    if phase == 809:
        return call_terminal(w)
    return call_refuse(w, 63)

def call_exception(w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 900:
        return call_issue(w, P_ROLLBACK, 901, UW_SCOPE_MAIN, get(w, C_STORE), 0, 0, 0, 0, 0)
    if phase == 910:
        return call_issue(w, P_ERROR, 911, UW_SCOPE_ERROR_RECORD, get(w, C_REQUEST), get(w, UW_ERROR), 0, 0, 0, 0)
    if phase == 911:
        put(w, C_RESPONSE, get(w, C_RESULTS))
        put(w, C_RETURN, 0)
        put(w, C_PHASE, 800)
        return 0
    if phase == 920:
        return call_issue(w, P_INSTALL_WRAP, 921, UW_SCOPE_INSTALL_RECORD, get(w, UW_ERROR), 0, 0, 0, 0, 0)
    if phase == 921:
        call_install_wrapped(w, get(w, C_RESULTS))
        return call_issue(w, P_ERROR, 922, UW_SCOPE_INSTALL_RECORD, get(w, C_REQUEST), get(w, UW_ERROR), 0, 0, 0, 0)
    if phase == 922:
        put(w, C_RESPONSE, get(w, C_RESULTS))
        return call_terminal(w)
    if phase == 930:
        put(w, C_STATUS, 3)
        return call_event(w, 2)
    return call_refuse(w, 70)

def call_terminal(w:mutbuf) -> u32:
    if get(w, C_RETURN) == 0:
        put(w, C_RETURN, get(w, C_RESPONSE))
    if get(w, C_RETURN) == 0:
        return call_refuse(w, 71)
    put(w, C_STATUS, 3)
    return call_event(w, 0)

def call_event(w:mutbuf, action:u64) -> u32:
    if get(w, C_SEQ) == CALL_MAX:
        put(w, C_STATUS, 4)
        return CALL_BAD
    put(w, C_SEQ, get(w, C_SEQ) + 1)
    put(w, 256, CALL_EVENT)
    put(w, 264, action)
    put(w, 272, get(w, C_LEASE))
    put(w, 280, get(w, C_CALL))
    put(w, 288, get(w, C_SEQ))
    put(w, 296, get(w, C_PHASE))
    put(w, 304, get(w, C_PEER))
    put(w, 312, get(w, UW_SCOPE))
    i = 0
    while i < 6:
        put(w, 320 + i * 8, get(w, 640 + i * 8))
        i = i + 1
    put(w, 368, get(w, C_RETURN))
    put(w, 376, get(w, UW_CLASS))
    put(w, 384, get(w, UW_ERROR))
    put(w, 392, get(w, C_JOURNAL))
    put(w, 400, get(w, C_TOOL_ID))
    put(w, 408, get(w, C_CONTEXT_ID))
    put(w, 416, get(w, C_RESPONSE))
    put(w, 424, get(w, UW_TX))
    put(w, 432, get(w, UW_NATIVE_FAILED))
    put(w, 440, get(w, C_PROFILE))
    put(w, 448, get(w, C_DIGITS))
    put(w, 456, get(w, C_SOURCE_EPOCH))
    put(w, 464, get(w, C_MAIN))
    put(w, 472, get(w, 56))
    put(w, 480, 0)
    put(w, 488, 0)
    put(w, 496, 0)
    put(w, 504, 0)
    return 512

def call_refuse(w:mutbuf, reason:u64) -> u32:
    put(w, C_STATUS, 4)
    put(w, 56, reason)
    call_event(w, 3)
    return CALL_BAD
'''
