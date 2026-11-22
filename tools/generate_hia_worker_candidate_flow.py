"""Author the sealed-descriptor driver for the installed HIA Candidate effect."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_context_flow import flow_source, function
from tools import generate_hia_worker_inspection_flow as inspection

SOURCE = Path('examples/hia_bootstrap/worker_candidate_flow.hepta')

COMMANDS = r'''
def inspect_command(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    total = get(w, INSPECTION_BYTES)
    seq = get(w, INSPECTION_SEQUENCE) + 1
    fd = input_word(s, 32)
    if input_word(s, 40) != total or length(s) != total + 64 or valid_fd(fd) == False:
        return BAD
    if input_word(s, 64) != INSPECTION_ACTION_TAG or input_word(s, 80) != seq:
        return BAD
    bytes = total - 48
    if input_word(s, 96) != 0 or input_word(s, 104) != bytes:
        return BAD
    put(w, INSPECTION_SEQUENCE, seq)
    role = input_word(s, 72)
    tag = input_word(s, 88)
    hold(w, INSPECTION_ACTUAL, fd, 48, bytes)
    if role == 1 and seq == 1 and tag == 0 and bytes >= 2 and bytes <= 320:
        return inspection_context(o, w)
    if role == 2 and seq >= 2 and tag == 0 and bytes == 121:
        put(w, CANDIDATE_UPDATING, 1)
        return inspection_context(o, w)
    if role == 3 and tag >= 1 and tag <= 3 and bytes >= 2 and bytes <= 512:
        put(w, CANDIDATE_INPUT_KIND, tag)
        put(w, RETAINED_PURPOSE, CANDIDATE_READ_INPUT)
        move_fragment(w, INSPECTION_ACTUAL, INSPECTION_REFERENCE)
        return inspection_retained_query(o, w, 0)
    if role == 4 and tag >= 1 and tag <= 4 and bytes == 0:
        put(w, CANDIDATE_MODE, tag)
        return begin_transform(o, w, tag)
    if role == 5 and (tag == 8 or tag == 9):
        return publish_candidate(s, o, w, tag, bytes)
    if role == 6 or role == 7:
        return inspection_result(s, o, w, role, bytes)
    return BAD

def candidate_input_received(o:mutbuf, w:mutbuf, status:u64) -> u64:
    return inspection_feedback(o, w, choose(get(w, CANDIDATE_INPUT_KIND) == 3, 5, 4), status, 0)

def candidate_budget(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, CANDIDATE_BUDGET_PREFIX)
    put(o, HEADER + 8, CANDIDATE_BUDGET_MIDDLE)
    use_span(w, o, CANDIDATE_BUDGET, 0)
    put(o, 496, 23933)
    fragment(o, 1, INLINE_FRAGMENT, 496, 2)
    return action(o, w, CANDIDATE_BUDGET_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 11)

def candidate_budget_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == CANDIDATE_BUDGET_BOUND:
        if plan_ok(s) == False or input_word(s, 40) != 32 or input_word(s, 72) != CANDIDATE_BUDGET_TAG:
            return BAD
        put(w, CANDIDATE_ATTEMPTS, input_word(s, 80))
        put(w, CANDIDATE_WALL, input_word(s, 88))
        return clock_sample(o, w, CANDIDATE_CLOCK_BOUND, 1)
    if state == CANDIDATE_CLOCK_BOUND:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        put(w, CANDIDATE_NOW, input_word(s, 64))
        return inspection_feedback(o, w, 2, 0, 0)
    return BAD

def candidate_attempt(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, CANDIDATE_ATTEMPT_TAG)
    put(o, HEADER + 8, get(w, CANDIDATE_ATTEMPTS))
    put(o, HEADER + 16, get(w, CANDIDATE_WALL))
    put(o, HEADER + 24, get(w, CANDIDATE_NOW))
    fragment(o, 0, get(w, INSPECTION_ACTUAL), get(w, INSPECTION_ACTUAL + 8) + 7, 36)
    use_span(w, o, CANDIDATE_ROW, 1)
    return action(o, w, CANDIDATE_ATTEMPT_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 32)

def bind_attempt(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if reply_word(s, RETAINED_REFUSAL) or reply_word(s, RETAINED_CORRUPT):
        return inspection_feedback(o, w, 3, choose(reply_word(s, RETAINED_REFUSAL), 1, 2), 0)
    if plan_ok(s) == False or input_word(s, 40) != 172:
        return BAD
    observe_slot(s, w, QUERY_FD)
    return open_store(o, w, CANDIDATE_OPEN_WRITE)

def candidate_attempt_settled(o:mutbuf, w:mutbuf, bytes:u64, found:u64) -> u64:
    if bytes != 8:
        return BAD
    put(w, CANDIDATE_WRITE_STATUS, choose(found == 1, 0, 3))
    return close_store(o, w, CANDIDATE_CLOSE_WRITE)
'''

TRANSFORM = r'''
def candidate_ingress(o:mutbuf, w:mutbuf, status:u64) -> u64:
    put(o, HEADER, CANDIDATE_INGRESS_REFUSAL)
    put(o, HEADER + 8, status)
    return action(o, w, CANDIDATE_REFUSED, RUN, CANDIDATE_DIAGNOSTIC_ROLE, 0, 0, 16)

def begin_transform(o:mutbuf, w:mutbuf, mode:u64) -> u64:
    size = get(w, CANDIDATE_SOURCE + 16)
    if mode == 1:
        if size == 0 or size > 8388608:
            return candidate_ingress(o, w, choose(size == 0, 41, 2))
        use_span(w, o, CANDIDATE_SOURCE, 0)
        return action(o, w, CANDIDATE_INGRESS_CHECKED, RUN, CANDIDATE_INGRESS_ROLE, 0, 1, 0)
    if mode == 2:
        put(o, 384, COMPACT_HEAD)
        put(o, 392, COMPACT_TAIL)
        argv(o, 0, LITERAL_ARG, 384)
        use_span(w, o, CANDIDATE_SOURCE, 0)
        return action(o, w, CANDIDATE_TRANSFORMED, RUN, CANDIDATE_ASSEMBLY_ROLE, 1, 1, 0)
    if size == 0 or get(w, CANDIDATE_PATCH + 16) == 0:
        return BAD
    store(o, 448, 44)
    store(o, 449, 93)
    store(o, HEADER, 91)
    put(o, 384, choose(mode == 3, 12662, 12918))
    put(o, 392, STATUS_HEAD)
    put(o, 400, STATUS_TAIL)
    argv(o, 0, LITERAL_ARG, 384)
    argv(o, 1, LITERAL_ARG, 392)
    vector_span(w, o, CANDIDATE_SOURCE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 448, 1)
    vector_span(w, o, CANDIDATE_PATCH, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 449, 1)
    return wide_inspection(o, w, CANDIDATE_TRANSFORMED, CANDIDATE_PATCH_ROLE, 2, 4, 1)

def candidate_explain(o:mutbuf, w:mutbuf, mode:u64, span:u64) -> u64:
    put(w, CANDIDATE_EXPLAIN_MODE, mode)
    use_span(w, o, span, 0)
    return action(o, w, CANDIDATE_EXPLAINED, RUN,
                  choose(mode == 1, NOMINAL_ROLE, CANDIDATE_ASSEMBLY_ROLE), 0, 1, 0)

def candidate_admission(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    status = input_word(s, 24)
    mode = get(w, CANDIDATE_MODE)
    if status != 0:
        if mode >= 3 or size != 0 or (status != 512 and status != 768):
            return BAD
        return candidate_explain(o, w, mode, CANDIDATE_SOURCE)
    fd = input_word(s, 32)
    if mode >= 3 and size >= 8:
        tag = input_word(s, 64)
        if tag == CANDIDATE_PATCH_REFUSAL and size == 16:
            fragment(o, 0, fd, 0, size)
            return action(o, w, CANDIDATE_REFUSED, RUN, CANDIDATE_DIAGNOSTIC_ROLE, 0, 1, 0)
        if tag == CANDIDATE_PATCH_CORE_REFUSAL and size >= 10 and size <= 8388616:
            hold(w, CANDIDATE_REJECTED_CORE, fd, 8, size - 8)
            return candidate_explain(o, w, 1, CANDIDATE_REJECTED_CORE)
    head = choose(mode == 1, 64, choose(mode == 2, 0, 32))
    if size < head:
        return BAD
    sample_span(s, w, CANDIDATE_TRANSFORM)
    put(o, HEADER, CANDIDATE_ADMISSION_TAG)
    put(o, HEADER + 8, mode)
    put(o, HEADER + 16, size)
    put(o, HEADER + 24, 0)
    fragment(o, 0, fd, 0, head)
    return action(o, w, CANDIDATE_ADMISSION_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 32)

def candidate_admitted(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 128 or input_word(s, 72) != CANDIDATE_ADMISSION_RESULT or input_word(s, 40) != 72:
        return BAD
    return read_span(o, w, CANDIDATE_ADMISSION_EXTENTS, input_word(s, 32), 8, 64)

def candidate_extent(s:readbuf, w:mutbuf, field:u64, dest:u64) -> bool:
    at = input_word(s, field)
    bytes = input_word(s, field + 8)
    extent = get(w, CANDIDATE_TRANSFORM + 16)
    if bytes < 2 or bytes > 8388608 or at > extent or bytes > extent - at:
        return False
    hold(w, dest, get(w, CANDIDATE_TRANSFORM), at, bytes)
    return True

def candidate_bind_extents(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 64) != CANDIDATE_ADMISSION_RESULT or input_word(s, 72) > 4:
        return BAD
    if candidate_extent(s, w, 80, CANDIDATE_CORE) == False:
        return BAD
    put(w, CANDIDATE_PROFILE, input_word(s, 72))
    if get(w, CANDIDATE_MODE) < 3:
        if candidate_extent(s, w, 96, CANDIDATE_ORIGINAL) == False:
            return BAD
    elif candidate_extent(s, w, 112, CANDIDATE_DOCUMENT) == False:
        return BAD
    return inspection_hash(o, w, CANDIDATE_CORE_HASHED, CANDIDATE_CORE)

def candidate_rejected(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    mode = get(w, CANDIDATE_EXPLAIN_MODE)
    bytes = input_word(s, 40)
    if input_word(s, 24) != choose(mode == 1, 512, 256) or bytes < 2:
        return BAD
    put(o, HEADER, choose(mode == 1, JSON_REFUSAL_HEAD, ASSEMBLY_REFUSAL_HEAD))
    put(o, HEADER + 8, ASSEMBLY_REFUSAL_TAIL)
    fragment(o, 0, input_word(s, 32), 0, bytes)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, CANDIDATE_REFUSED, RUN, CANDIDATE_DIAGNOSTIC_ROLE, 0, 2,
                  choose(mode == 1, 8, 12))

def candidate_transform_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == CANDIDATE_INGRESS_CHECKED:
        if plan_ok(s) == False or input_word(s, 40) != 16:
            return BAD
        code = input_word(s, 72)
        if code != 0:
            return candidate_ingress(o, w, code)
        use_span(w, o, CANDIDATE_SOURCE, 0)
        return action(o, w, CANDIDATE_TRANSFORMED, RUN, NOMINAL_ROLE, 0, 1, 0)
    if state == CANDIDATE_TRANSFORMED:
        return candidate_admission(s, o, w)
    if state == CANDIDATE_ADMISSION_BOUND:
        return candidate_admitted(s, o, w)
    if state == CANDIDATE_ADMISSION_EXTENTS:
        return candidate_bind_extents(s, o, w)
    if state == CANDIDATE_EXPLAINED:
        return candidate_rejected(s, o, w)
    if state == CANDIDATE_REFUSED:
        if plan_ok(s) == False or input_word(s, 40) < 26 or input_word(s, 40) > 7908:
            return BAD
        body_span(s, w, CANDIDATE_DOCUMENT)
        return inspection_feedback(o, w, 6, 2, CANDIDATE_DOCUMENT)
    if state == CANDIDATE_DIAGNOSTIC_BOUND:
        if plan_ok(s) == False or input_word(s, 40) < 10:
            return BAD
        body_span(s, w, CANDIDATE_DOCUMENT)
        return inspection_hash(o, w, CANDIDATE_DIAGNOSTIC_HASHED, CANDIDATE_DOCUMENT)
    return BAD
'''

DOCUMENTS = r'''
def candidate_hashed(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    phase = get(w, INSPECTION_HASH_RESUME)
    if phase == CANDIDATE_CORE_HASHED:
        copy_span(s, w, at, CANDIDATE_DIGESTS, 64)
        if get(w, CANDIDATE_MODE) < 3:
            sample_span(s, w, CANDIDATE_CORE_HASH_RECEIPT)
            return inspection_hash(o, w, CANDIDATE_ORIGINAL_HASHED, CANDIDATE_ORIGINAL)
        return inspection_hash(o, w, CANDIDATE_DIAGNOSTIC_HASHED, CANDIDATE_DOCUMENT)
    if phase == CANDIDATE_ORIGINAL_HASHED:
        put(o, HEADER, CANDIDATE_IMPORT_DIAGNOSTIC)
        put(o, HEADER + 8, get(w, CANDIDATE_PROFILE))
        put(o, HEADER + 16, get(w, CANDIDATE_CORE + 16))
        put(o, HEADER + 24, get(w, CANDIDATE_ORIGINAL + 16))
        put(o, HEADER + 32, get(w, CANDIDATE_CORE_HASH_RECEIPT + 16))
        put(o, HEADER + 40, input_word(s, 40))
        use_span(w, o, CANDIDATE_CORE_HASH_RECEIPT, 0)
        fragment(o, 1, input_word(s, 32), 0, input_word(s, 40))
        return action(o, w, CANDIDATE_DIAGNOSTIC_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 48)
    if phase != CANDIDATE_DIAGNOSTIC_HASHED:
        return BAD
    copy_span(s, w, at, CANDIDATE_DIGESTS + 64, 64)
    put(o, HEADER, INSPECTION_EVENT_TAG)
    put(o, HEADER + 8, 6)
    put(o, HEADER + 16, get(w, INSPECTION_SEQUENCE) + 1)
    put(o, HEADER + 24, 0)
    put(o, HEADER + 32, 128)
    copy_private(w, o, CANDIDATE_DIGESTS, HEADER + 40, 128)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_SENT, SEND_PEER, 0, 0, 0, 168)

def publish_candidate(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, bytes:u64) -> u64:
    if bytes != choose(kind == 8, 185, 64):
        return BAD
    digest = CANDIDATE_DIGESTS + choose(kind == 8, 0, 64)
    at = 0
    while at < 64:
        if byte(s, 112 + at) != byte(w, digest + at):
            return BAD
        at = at + 1
    put(w, INSPECTION_KIND, kind)
    if kind == 8:
        fragment(o, 0, input_word(s, 32), 112, 121)
        return action(o, w, CANDIDATE_PUBLICATION_CONTEXT, MAKE, 0, 0, 1, 0)
    return run_candidate_publication(o, w, kind, 0)

def run_candidate_publication(o:mutbuf, w:mutbuf, kind:u64, context:u64) -> u64:
    launch_directory(w, o, 0)
    role_argument(w, o, 2, STORE_ROLE)
    role_argument(w, o, 3, READY_ROLE)
    role_argument(w, o, 4, UNIQUE_ROLE)
    role_argument(w, o, 5, PUBLISHER_ROLE)
    role_argument(w, o, 6, DOCUMENT_PLAN_ROLE)
    role_argument(w, o, 7, DOCUMENT_EFFECT_ROLE)
    argv(o, 8, DECIMAL_ARG, kind)
    argv(o, 9, DECIMAL_ARG, 0)
    if kind == 8:
        argv(o, 10, FD_ARG, context)
    use_span(w, o, choose(kind == 8, CANDIDATE_CORE, CANDIDATE_DOCUMENT), 0)
    return action(o, w, CANDIDATE_PUBLISHED, RUN, DOCUMENT_ROLE, choose(kind == 8, 11, 10), 1, 0)

def candidate_document_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 88 or size > 100:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state == CANDIDATE_PUBLICATION_CONTEXT:
        if input_word(s, 40) != 121:
            return BAD
        return run_candidate_publication(o, w, 8, input_word(s, 32))
    if state == CANDIDATE_PUBLISHED:
        if input_word(s, 40) < 2:
            return BAD
        sample_span(s, w, CANDIDATE_DOCUMENT_RECEIPT)
        kind = get(w, INSPECTION_KIND)
        return inspection_feedback(o, w, kind - 1, kind, CANDIDATE_DOCUMENT_RECEIPT)
    return BAD
'''

def replace_function(source, name, replacement):
    return source.replace(function(source, name), replacement.rstrip() + '\n')


def program():
    constants, controls = inspection.recipe()
    constants.update(ROLE_COUNT=38, ENTRY_BYTES=64 + 312 + 38 * 40, SCHEMA_TOOL=6)
    constants.update(CANDIDATE_ASSEMBLY_ROLE=34, CANDIDATE_PATCH_ROLE=35,
                     CANDIDATE_INGRESS_ROLE=36, CANDIDATE_DIAGNOSTIC_ROLE=37)
    states = (
        'CANDIDATE_BUDGET_BOUND', 'CANDIDATE_CLOCK_BOUND', 'CANDIDATE_ATTEMPT_BOUND',
        'CANDIDATE_INGRESS_CHECKED', 'CANDIDATE_TRANSFORMED', 'CANDIDATE_ADMISSION_BOUND',
        'CANDIDATE_ADMISSION_EXTENTS', 'CANDIDATE_EXPLAINED', 'CANDIDATE_REFUSED',
        'CANDIDATE_DIAGNOSTIC_BOUND', 'CANDIDATE_PUBLICATION_CONTEXT', 'CANDIDATE_PUBLISHED',
        'CANDIDATE_CORE_HASHED', 'CANDIDATE_ORIGINAL_HASHED', 'CANDIDATE_DIAGNOSTIC_HASHED',
    )
    constants.update({name: constants['INSPECTION_LOWERING_PROFILE_BOUND'] + 1 + index
                      for index, name in enumerate(states)})
    constants.update(CANDIDATE_OPEN_WRITE=constants['PROFILE_ROW'] + 1,
                     CANDIDATE_CLOSE_WRITE=constants['PROFILE_ROW'] + 2,
                     CANDIDATE_WRITE_ATTEMPT=constants['PROFILE_ROW'] + 3,
                     CANDIDATE_READ_INPUT=5)
    slots = (
        'CANDIDATE_ROW', 'CANDIDATE_BUDGET', 'CANDIDATE_SOURCE', 'CANDIDATE_PATCH',
        'CANDIDATE_REJECTED_CORE', 'CANDIDATE_TRANSFORM', 'CANDIDATE_CORE', 'CANDIDATE_ORIGINAL',
        'CANDIDATE_DOCUMENT', 'CANDIDATE_CORE_HASH_RECEIPT', 'CANDIDATE_DOCUMENT_RECEIPT',
    )
    scalars = (
        'CANDIDATE_UPDATING', 'CANDIDATE_INPUT_KIND', 'CANDIDATE_MODE', 'CANDIDATE_ATTEMPTS',
        'CANDIDATE_WALL', 'CANDIDATE_NOW', 'CANDIDATE_EXPLAIN_MODE', 'CANDIDATE_PROFILE',
        'CANDIDATE_WRITE_STATUS',
    )
    constants.update({name: 3144 + 24 * index for index, name in enumerate(slots)})
    constants.update({name: 3416 + 8 * index for index, name in enumerate(scalars)})
    constants['CANDIDATE_DIGESTS'] = 3496
    words = {
        'INSPECTION_ACTION_TAG': b'HIACNA01', 'INSPECTION_OUTCOME_TAG': b'HIACND01',
        'CANDIDATE_BUDGET_PREFIX': b'[{"budge', 'CANDIDATE_BUDGET_MIDDLE': b't":',
        'CANDIDATE_BUDGET_TAG': b'HIACAB01', 'CANDIDATE_ATTEMPT_TAG': b'HIACAP02',
        'CANDIDATE_INGRESS_REFUSAL': b'HIACIR01', 'CANDIDATE_PATCH_REFUSAL': b'HIAPRF01',
        'CANDIDATE_PATCH_CORE_REFUSAL': b'HIAPCR01', 'CANDIDATE_ADMISSION_TAG': b'HIACAF01',
        'CANDIDATE_ADMISSION_RESULT': b'HIACAE01', 'CANDIDATE_IMPORT_DIAGNOSTIC': b'HIACDM01',
        'COMPACT_HEAD': b'--agent-', 'COMPACT_TAIL': b'compact',
        'STATUS_HEAD': b'--agent-', 'STATUS_TAIL': b'status',
        'JSON_REFUSAL_HEAD': b'["json",', 'ASSEMBLY_REFUSAL_HEAD': b'["assemb',
        'ASSEMBLY_REFUSAL_TAIL': b'ly",',
    }
    constants.update({name: int.from_bytes(word, 'little') for name, word in words.items()})

    driver = inspection.DRIVER.replace(
        'if input_word(s, 16) != operation or input_word(s, 24) != 0:',
        'allow_exit = state == CANDIDATE_TRANSFORMED or state == CANDIDATE_EXPLAINED\n'
        '    if input_word(s, 16) != operation or (input_word(s, 24) != 0 and allow_exit == False):',
    ).replace(
        '    return inspection_render(s, o, w, state)',
        '    if state == CANDIDATE_ATTEMPT_BOUND:\n'
        '        return bind_attempt(s, o, w)\n'
        '    if state == CANDIDATE_BUDGET_BOUND or state == CANDIDATE_CLOCK_BOUND:\n'
        '        return candidate_budget_state(s, o, w, state)\n'
        '    if state >= CANDIDATE_INGRESS_CHECKED and state <= CANDIDATE_DIAGNOSTIC_BOUND:\n'
        '        return candidate_transform_state(s, o, w, state)\n'
        '    return candidate_document_state(s, o, w, state)',
    ).replace('return installation_profile_request(o, w, True)',
              'return candidate_request_admission(o, w)')
    admission = function(inspection.DRIVER, 'install_inspection')
    head = admission.index('        put(o, HEADER, ADMISSION)')
    admit = '\ndef candidate_request_admission(o:mutbuf, w:mutbuf) -> u64:\n'
    admit += ''.join(line[4:] for line in admission[head:admission.rindex('    return BAD')].splitlines(True))
    driver = (driver + admit).replace(
        '    if state == INSPECTION_LOWERING_PROFILE_BOUND:' +
        admission[admission.index('    if state == INSPECTION_LOWERING_PROFILE_BOUND:') +
                  len('    if state == INSPECTION_LOWERING_PROFILE_BOUND:'):],
        '    return BAD\n',
    )
    effect = replace_function(inspection.EFFECT_DRIVER, 'inspect_command', function(COMMANDS, 'inspect_command'))
    effect = effect[:effect.index('\ndef inspection_feedback_digest(')].replace(
        'input_word(s, 40) > 2608', 'input_word(s, 40) > 1544')
    command_helpers = COMMANDS[COMMANDS.index('\ndef candidate_input_received('):]
    retained = inspection.RETAINED_DRIVER.replace(
        '    if reason == READ_PROGRAM:',
        '    if reason == CANDIDATE_READ_INPUT:\n'
        '        return candidate_input_received(o, w, choose(corruption, 2, 1))\n'
        '    if reason == READ_PROGRAM:', 1,
    )
    retained = retained.replace(
        '            return inspection_feedback(o, w, 2, 1, 0)',
        '            if get(w, CANDIDATE_UPDATING) != 0:\n'
        '                return BAD\n'
        '            return inspection_feedback(o, w, 2, 1, 0)', 1,
    ).replace(
        '        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 40, 176)',
        '        hold(w, CANDIDATE_ROW, input_word(s, 32), 8, input_word(s, 40) - 8)\n'
        '        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 40, 176)',
    ).replace(
        '        return inspection_feedback(o, w, 2, 0, 0)',
        '        return candidate_budget(o, w)',
    ).replace(
        '    if reason == READ_PROGRAM:\n        fragment(o, 0,',
        '    if reason == CANDIDATE_READ_INPUT:\n'
        '        dest = choose(get(w, CANDIDATE_INPUT_KIND) == 3, CANDIDATE_PATCH, CANDIDATE_SOURCE)\n'
        '        sample_span(s, w, dest)\n'
        '        return candidate_input_received(o, w, 0)\n'
        '    if reason == READ_PROGRAM:\n        fragment(o, 0,',
    ).replace(
        '    if index == 6:',
        '    if index == 5:\n'
        '        hold(w, CANDIDATE_BUDGET, input_word(s, 32), at, size)\n'
        '    if index == 6:',
    )
    store = inspection.STORE_DRIVER.replace(
        '    if purpose == OPEN_CONTEXT_ROW:',
        '    if purpose == CANDIDATE_OPEN_WRITE:\n'
        '        return store_transaction(o, w, CANDIDATE_WRITE_ATTEMPT, 27, 1, query, 8, bytes - 8)\n'
        '    if purpose == OPEN_CONTEXT_ROW:',
    ).replace(
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
        '    if purpose == CANDIDATE_CLOSE_WRITE:\n'
        '        return inspection_feedback(o, w, 3, get(w, CANDIDATE_WRITE_STATUS), 0)\n'
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:\n'
        '        if get(w, CANDIDATE_UPDATING) != 0:\n'
        '            return BAD',
    ).replace(
        '    if purpose == CLOSE_CONTEXT_ROW:',
        '    if purpose == CLOSE_CONTEXT_ROW:\n'
        '        if get(w, CANDIDATE_UPDATING) != 0:\n'
        '            return candidate_attempt(o, w)',
    )
    specialized = []
    for control in controls:
        if control.startswith('\ndef settle_transaction('):
            control = control.replace('    if found != 1:', (
                '    if purpose == CANDIDATE_WRITE_ATTEMPT:\n'
                '        return candidate_attempt_settled(o, w, bytes, found)\n'
                '    if found != 1:'))
        if control.startswith('\ndef issue('):
            control = control.replace(
                '    alias = choose(role == NOMINAL_ROLE, 1, choose(role == INSPECTION_QUERY_ROLE, 2, '
                'choose(role == INSPECTION_EMIT_ROLE, 3, 0)))',
                '    alias = choose(role == NOMINAL_ROLE, 1, 0)\n'
                '    if role == CANDIDATE_ASSEMBLY_ROLE:\n'
                '        alias = 2\n'
                '    if role == CANDIDATE_PATCH_ROLE:\n'
                '        alias = 3\n'
                '    if next == CANDIDATE_EXPLAINED:\n'
                '        alias = choose(get(w, CANDIDATE_EXPLAIN_MODE) == 1, 4, 5)',
            )
        specialized.append(control)
    wire = (function(inspection.DOCUMENT_DRIVER, 'vector_span'),
            function(inspection.DOCUMENT_DRIVER, 'wide_inspection'))
    hash_functions = tuple(
        function(inspection.VIEW_DRIVER, name).replace('inspection_hash_bound(s, o, w, at + 10)',
                                                      'candidate_hashed(s, o, w, at + 10)')
        for name in ('inspection_hash', 'inspection_hash_result'))
    return flow_source(driver, (effect, command_helpers, TRANSFORM, DOCUMENTS, retained, store,
                                *wire, *hash_functions, *specialized), constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
