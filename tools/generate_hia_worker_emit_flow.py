"""Author the sealed-descriptor admission and effects of the native Emit Worker."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_readonly_worker_capsule import (
    EMIT_ROLES, PROOF_TRUST_BYTES, PROOF_TRUST_MAGIC, PROOF_TRUST_NATIVE_BYTES, PROOF_TRUST_NATIVE_OFFSET,
    PROOF_TRUST_RUNTIME_MAX,
)
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_artifact_authority import PROFILE_PORTS
from tools import generate_hia_worker_inspection_flow as worker
from tools.generate_hia_worker_emit_product import bound_run_controls, producer_constants, product_recipe
from tools.generate_hia_worker_emit_publication import publication_constants
from tools.generate_hia_worker_emit_record import record_constants
from tools.generate_hia_worker_emit_measurement import measurement_constants
from tools.generate_hia_worker_emit_proof import proof_constants, proof_recipe
from tools.generate_hia_worker_emit_scalar import scalar_constants

# Kept as separate HIA source recipes while the effect and product ports are
# migrated. These recipes use the same Worker action/observation ABI as the
# installed Inspection and Candidate flows.

REQUEST = r'''
def emit_projection(o:mutbuf, w:mutbuf) -> u64:
    inspection_catalog(o, w)
    after_prefix(w, o, ARGUMENT_FD, 0)
    store(o, 496, 93)
    fragment(o, 1, INLINE_FRAGMENT, 496, 1)
    return action(o, w, EMIT_PROJECTED, RUN, INSPECTION_REQUEST_ROLE, 0, 2, 68)

def emit_prepare(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_PROJECTED:
        if plan_ok(s) == False or input_word(s, 72) != EMIT_REQUEST or size < 100:
            return BAD
        body_span(s, w, EMIT_REQUEST_BODY)
        put(o, HEADER, EMIT_INDEX_REQUEST)
        use_span(w, o, EMIT_REQUEST_BODY, 0)
        return action(o, w, EMIT_INDEX_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 8)
    if state == EMIT_INDEX_BOUND:
        if plan_ok(s) == False or input_word(s, 72) != EMIT_INDEX_RESULT or size < 144 or size > 432:
            return BAD
        return read_span(o, w, EMIT_INDEX_FRAME, fd, 8, size - 8)
    if state == EMIT_INDEX_FRAME:
        return emit_bind_index(s, o, w)
    if state == EMIT_PEER_OPENED:
        if length(s) != 80 or size != 16:
            return BAD
        return emit_start(o, w)
    return BAD

def emit_bind_index(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 64) != EMIT_INDEX_RESULT:
        return BAD
    mode = input_word(s, 72)
    codegen = input_word(s, 80)
    receipts = input_word(s, 88)
    count = input_word(s, 96)
    if (mode != 1 and mode != 2) or (codegen != 1 and codegen != 2) or receipts > 16:
        return BAD
    if count != 5 + receipts + choose(codegen == 1, 1, 3) or length(s) != 104 + 16 * count:
        return BAD
    put(w, EMIT_OUTPUT_KIND, mode)
    put(w, EMIT_CODEGEN_KIND, codegen)
    put(w, EMIT_RECEIPT_COUNT, receipts)
    base = get(w, EMIT_REQUEST_BODY + 8)
    limit = get(w, EMIT_REQUEST_BODY + 16)
    i = 0
    end = 32
    while i < count:
        at = input_word(s, 104 + 16 * i)
        extent = input_word(s, 112 + 16 * i)
        if at != end + 8 or at > limit or extent < 2 or extent > limit - at:
            return BAD
        end = at + extent
        hold(w, EMIT_FIELDS + 24 * i, get(w, EMIT_REQUEST_BODY), base + at, extent)
        i = i + 1
    if end != limit:
        return BAD
    put(o, 176, INSPECTION_PEER)
    return action(o, w, EMIT_PEER_OPENED, START_PEER, INSPECTION_EFFECT_ROLE, 0, 0, 0)

def emit_start(o:mutbuf, w:mutbuf) -> u64:
    context = EMIT_FIELDS + 24
    extent = get(w, context + 16)
    if extent < 2 or extent > 320:
        return BAD
    put(o, HEADER, INSPECTION_EVENT_TAG)
    put(o, HEADER + 8, 1)
    put(o, HEADER + 16, 1)
    put(o, HEADER + 24, 0)
    put(o, HEADER + 32, 40 + extent)
    put(o, HEADER + 40, EMIT_REQUEST)
    put(o, HEADER + 48, get(w, EMIT_OUTPUT_KIND))
    put(o, HEADER + 56, get(w, EMIT_CODEGEN_KIND))
    put(o, HEADER + 64, get(w, EMIT_RECEIPT_COUNT))
    put(o, HEADER + 72, extent)
    use_span(w, o, context, 0)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_SENT, SEND_PEER, 0, 0, 1, 80)
'''

REACTOR = r'''
def emit_peer_observation(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_SENT:
        if length(s) != 64:
            return BAD
        return receive(o, w, INSPECTION_LENGTH, INSPECTION_PEER, 8, False)
    if state == INSPECTION_LENGTH:
        count = input_word(s, 64)
        if length(s) != 72 or input_word(s, 40) != 8 or count < 48 or count > 8192:
            return BAD
        put(w, INSPECTION_BYTES, count)
        return receive(o, w, INSPECTION_ACTION, INSPECTION_PEER, count, True)
    if state == INSPECTION_ACTION:
        return emit_action(s, o, w)
    if state == INSPECTION_PEER_CLOSED and length(s) == 64:
        return end_effect(o, w, get(w, INSPECTION_STATUS), 116)
    return BAD

def emit_action(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    count = get(w, INSPECTION_BYTES)
    seq = get(w, INSPECTION_SEQUENCE) + 1
    fd = input_word(s, 32)
    if input_word(s, 40) != count or length(s) != count + 64 or valid_fd(fd) == False:
        return BAD
    if input_word(s, 64) != INSPECTION_ACTION_TAG or input_word(s, 80) != seq:
        return BAD
    role = input_word(s, 72)
    offset = input_word(s, 88)
    bytes = count - 48
    if role < 2 or role > 20 or input_word(s, 96) != 0 or input_word(s, 104) != bytes:
        return BAD
    put(w, INSPECTION_SEQUENCE, seq)
    if role == 20:
        return emit_terminal(s, o, w, offset, bytes)
    proof = role == 15 or role == 16 or role == 18
    if bytes != choose(proof, 64, 0):
        return BAD
    if proof:
        copy_span(s, w, 112, EMIT_PUBLIC_AUTHORITY, 64)
    put(w, EMIT_STAGE, role)
    hold(w, EMIT_AUTHORIZATION, fd, 48, bytes)
    return emit_business(o, w, role, offset)

def emit_terminal(s:readbuf, o:mutbuf, w:mutbuf, status:u64, bytes:u64) -> u64:
    if bytes < 70 or input_word(s, 112) != INSPECTION_OUTCOME_TAG or input_word(s, 120) != status:
        return BAD
    context = input_word(s, 128)
    if (status != 1 and status != 2) or (context != 0 and context != 36) or input_word(s, 136) != bytes - 68:
        return BAD
    put(w, INSPECTION_STATUS, status)
    hold(w, INSPECTION_OUTCOME, input_word(s, 32), 48, bytes)
    observe_slot(s, w, EFFECT_FD)
    put(o, 176, INSPECTION_PEER)
    return action(o, w, INSPECTION_PEER_CLOSED, FINISH_PEER, 0, 0, 0, 0)
'''


def front_constants(shared, *, request_slot, field_slots, control_words):
    """Bind the Emit-specific descriptor bank to the Worker frame."""
    states = ('EMIT_PROJECTED', 'EMIT_INDEX_BOUND', 'EMIT_INDEX_FRAME', 'EMIT_PEER_OPENED')
    tags = {
        'EMIT_REQUEST': b'HIAERQ01',
        'EMIT_INDEX_REQUEST': b'HIAERIX1',
        'EMIT_INDEX_RESULT': b'HIAERIX2',
        'INSPECTION_ACTION_TAG': b'HIAEMA01',
    }
    constants = {name: i for i, name in enumerate(states, shared['INSPECTION_LOWERING_PROFILE_BOUND'] + 1)}
    constants.update({name: int.from_bytes(value, 'little') for name, value in tags.items()})
    constants.update(EMIT_REQUEST_BODY=request_slot, EMIT_FIELDS=field_slots, EMIT_PUBLIC_AUTHORITY=5472)
    for i, name in enumerate(('EMIT_OUTPUT_KIND', 'EMIT_CODEGEN_KIND', 'EMIT_RECEIPT_COUNT', 'EMIT_STAGE')):
        constants[name] = control_words + 8 * i
    constants['EMIT_AUTHORIZATION'] = request_slot + 24
    return constants


PROFILES = r'''
def emit_installed_profiles(o:mutbuf, w:mutbuf) -> u64:
    hold(w, EMIT_INSTALLATION, slot_fd(w, DOSSIER_FD), DOSSIER_HEAD + get(w, 40), get(w, 48))
    inspection_catalog(o, w)
    store(o, 494, 44)
    store(o, 495, 93)
    vector_span(w, o, EMIT_INSTALLATION, HEADER + 68)
    vector_part(o, HEADER + 92, INLINE_FRAGMENT, 494, 1)
    vector_span(w, o, INSPECTION_INSTALL_MANIFEST, HEADER + 116)
    vector_part(o, HEADER + 140, INLINE_FRAGMENT, 495, 1)
    return wide_inspection(o, w, EMIT_PROFILES_BOUND, EMIT_PROFILES_ROLE, 0, 4, 68)

def emit_profile_field(o:mutbuf, w:mutbuf) -> u64:
    cursor = get(w, EMIT_PROFILE_CURSOR)
    extent = get(w, EMIT_INSTALLED + 16)
    if cursor > extent or extent - cursor < 8:
        return BAD
    return read_span(o, w, EMIT_PROFILE_FIELD, get(w, EMIT_INSTALLED),
                     get(w, EMIT_INSTALLED + 8) + cursor, 8)

def emit_installation_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == EMIT_PROFILES_BOUND:
        if plan_ok(s) == False or input_word(s, 72) != EMIT_PROFILES_TAG or input_word(s, 80) != 7:
            return BAD
        body_span(s, w, EMIT_INSTALLED)
        put(w, EMIT_PROFILE_INDEX, 0)
        put(w, EMIT_PROFILE_CURSOR, 16)
        return emit_profile_field(o, w)
    if state != EMIT_PROFILE_FIELD or length(s) != 72:
        return BAD
    i = get(w, EMIT_PROFILE_INDEX)
    at = get(w, EMIT_PROFILE_CURSOR) + 8
    size = input_word(s, 64)
    extent = get(w, EMIT_INSTALLED + 16)
    if i >= 14 or at > extent or size < 2 or size > extent - at:
        return BAD
    if (i & 1) != 0 and size != 176:
        return BAD
    hold(w, EMIT_PROFILES + 24 * i, get(w, EMIT_INSTALLED), get(w, EMIT_INSTALLED + 8) + at, size)
    if i == 13:
        if at + size != extent:
            return BAD
        return emit_request_admission(o, w)
    put(w, EMIT_PROFILE_INDEX, i + 1)
    put(w, EMIT_PROFILE_CURSOR, at + size)
    return emit_profile_field(o, w)

def emit_request_admission(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, ADMISSION)
    put(o, HEADER + 8, get(w, 24))
    copy_private(w, o, TRUST, HEADER + 16, 64)
    whole_slot(w, o, ORIGINAL, 0)
    return action(o, w, REQUEST_ADMITTED, RUN, ADMIT_ROLE, 0, 1, 80)

def emit_open_profile(o:mutbuf, w:mutbuf, index:u64, requested:u64) -> u64:
    if index != 1 and index != 3 and index != 4 and index != 6:
        return BAD
    role = choose(index == 1, 4, choose(index == 3, 5, choose(index == 4, 6, 7)))
    profile = EMIT_PROFILES + 48 * index + 24
    put(w, EMIT_PROFILE_ROLE, role)
    hold(w, EMIT_PROFILE_PIN, get(w, profile), get(w, profile + 8) + 53, 64)
    put(o, HEADER, PROFILE_BY_REFERENCE)
    put(o, HEADER + 8, role)
    use_span(w, o, EMIT_PROFILE_PIN, 0)
    use_span(w, o, requested, 1)
    return action(o, w, EMIT_PROFILE_PLAN, RUN, PROFILE_ROLE, 0, 2, 16)

def emit_profile_closed(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    if purpose == EMIT_PROFILE_REFUSED:
        return emit_admission_error(o, w, 2, 2)
    put(w, RETAINED_PURPOSE, READ_EMIT_PROFILE)
    return inspection_retained_query(o, w, 0)

def emit_profile_observed(o:mutbuf, w:mutbuf, bytes:u64) -> u64:
    put(o, HEADER, PROFILE_OBSERVED_BY_REFERENCE)
    put(o, HEADER + 8, bytes)
    put(o, HEADER + 16, get(w, STORE_REQUEST))
    put(o, HEADER + 24, get(w, STORE_EPOCH))
    put(o, HEADER + 32, get(w, EMIT_PROFILE_ROLE))
    use_span(w, o, EMIT_PROFILE_PIN, 0)
    whole_slot(w, o, STORE_RESULT, 1)
    return action(o, w, EMIT_PROFILE_PROOF, RUN, PROFILE_ROLE, 0, 2, 40)

def emit_profile_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == EMIT_PROFILE_PLAN:
        if reply_word(s, PROFILE_STALE):
            return emit_admission_error(o, w, 2, 1)
        role = get(w, EMIT_PROFILE_ROLE)
        expected = choose(role == 4, EMIT_BACKEND_QUERY_BYTES, choose(role == 5, EMIT_LOWERING_QUERY_BYTES,
                          choose(role == 6, EMIT_PLAN_QUERY_BYTES, EMIT_VALIDATION_QUERY_BYTES)))
        if plan_ok(s) == False or input_word(s, 40) != expected:
            return BAD
        observe_slot(s, w, QUERY_FD)
        return open_store(o, w, EMIT_OPEN_PROFILE)
    if state == EMIT_PROFILE_PROOF:
        if reply_word(s, PROFILE_REFUSAL):
            return close_store(o, w, EMIT_PROFILE_REFUSED)
        if (plan_ok(s) == False or input_word(s, 40) != 290 or length(s) < 88
                or input_word(s, 72) != PROFILE_BINDING or input_word(s, 80) != 176):
            return BAD
        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 24, 176)
        return close_store(o, w, EMIT_PROFILE_AUTHORIZED)
    return BAD
'''


ADMISSION = r'''
def emit_admission_error(o:mutbuf, w:mutbuf, scope:u64, reason:u64) -> u64:
    zero_range(o, HEADER, 40)
    put(o, HEADER, ERROR_PACKET)
    put(o, HEADER + 8, scope)
    put(o, HEADER + 16, reason)
    return action(o, w, EMIT_ADMISSION_REFUSED, RUN, FLOW_ROLE, 0, 0, 40)

def emit_admission(o:mutbuf, w:mutbuf, stage:u64, operand:u64) -> u64:
    if stage == 2:
        move_fragment(w, EMIT_FIELDS + 24, INSPECTION_ACTUAL)
        return inspection_context(o, w)
    if stage == 3:
        put(o, HEADER, EMIT_BUDGET_PREFIX)
        put(o, HEADER + 8, EMIT_BUDGET_MIDDLE)
        put(o, 496, EMIT_BUDGET_END)
        use_span(w, o, EMIT_CONTEXT_BUDGET, 0)
        fragment(o, 1, INLINE_FRAGMENT, 496, 2)
        return action(o, w, EMIT_BUDGET_BOUND, RUN, EMIT_BUDGET_ROLE, 0, 2, 11)
    if stage == 4:
        return emit_open_profile(o, w, 1, EMIT_FIELDS)
    if stage == 5:
        move_fragment(w, EMIT_FIELDS + 48, INSPECTION_ACTUAL)
        return inspection_program(o, w)
    if stage == 7:
        codegen = get(w, EMIT_CODEGEN_KIND)
        if operand != codegen:
            return BAD
        requested = EMIT_FIELDS + 24 * (5 + get(w, EMIT_RECEIPT_COUNT))
        return emit_open_profile(o, w, codegen + 2, requested)
    if stage == 11:
        return emit_wall_start(o, w)
    return BAD

def emit_wall_start(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_WALL_LIMIT) == 0:
        return BAD
    # Reopen the immutable Context row immediately before each clock window,
    # without substituting the window from the earlier admission.
    move_fragment(w, EMIT_FIELDS + 24, INSPECTION_ACTUAL)
    return inspection_context(o, w)

def emit_wall_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == EMIT_BUDGET_BOUND:
        if plan_ok(s) == False or input_word(s, 40) != 32 or input_word(s, 72) != EMIT_BUDGET_TAG:
            return BAD
        put(w, EMIT_WALL_LIMIT, input_word(s, 88))
        return emit_wall_start(o, w)
    if state == EMIT_CLOCK_MONOTONIC or state == EMIT_CLOCK_REALTIME:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        if state == EMIT_CLOCK_MONOTONIC:
            put(w, EMIT_WALL_TICK, input_word(s, 64))
            return clock_sample(o, w, EMIT_CLOCK_REALTIME, 1)
        stage = get(w, EMIT_STAGE)
        launch = stage == 11
        if stage != 3 and launch == False:
            return BAD
        put(o, HEADER, choose(launch, EMIT_LAUNCH_WINDOW, EMIT_ADMISSION_WINDOW))
        put(o, HEADER + 8, choose(launch, 2, 1))
        put(o, HEADER + 16, get(w, EMIT_WALL_LIMIT))
        put(o, HEADER + 24, input_word(s, 64))
        put(o, HEADER + 32, get(w, EMIT_WALL_TICK))
        use_span(w, o, EMIT_FIELDS + 24, 0)
        use_span(w, o, EMIT_CONTEXT_ROW, 1)
        return action(o, w, EMIT_WALL_BOUND, RUN, INSPECTION_REQUEST_ROLE, 0, 2, choose(launch, 40, 32))
    if state == EMIT_WALL_BOUND:
        launch = get(w, EMIT_STAGE) == 11
        if (plan_ok(s) == False or input_word(s, 40) != choose(launch, 48, 32)
                or input_word(s, 72) != choose(launch, EMIT_LAUNCH_PERMIT, EMIT_WINDOW_RESULT)
                or input_word(s, 80) > 1):
            return BAD
        if input_word(s, 80) != 0:
            return emit_admission_error(o, w, 8, choose(launch, 4, 3))
        if launch:
            body_span(s, w, EMIT_WALL_PERMIT)
            put(w, EMIT_ABSOLUTE_DEADLINE, input_word(s, 104))
            return inspection_feedback(o, w, 11, 0, EMIT_WALL_PERMIT)
        return inspection_feedback(o, w, 3, 0, 0)
    if state == EMIT_ADMISSION_REFUSED:
        if input_word(s, 40) < 2 or input_word(s, 40) > 8192:
            return BAD
        sample_span(s, w, EMIT_PUBLIC_ERROR)
        return inspection_feedback(o, w, get(w, EMIT_STAGE), 1, EMIT_PUBLIC_ERROR)
    return BAD

def emit_retained_checked(o:mutbuf, w:mutbuf, event:u64, status:u64, ignored:u64) -> u64:
    stage = get(w, EMIT_STAGE)
    if event == 3:
        if status != 0:
            return emit_admission_error(o, w, 7, 1)
        return inspection_feedback(o, w, 5, 0, 0)
    if event != 2:
        return BAD
    if stage == 3 or stage == 11:
        return BAD
    if status != 0:
        if status == 1 or status == 2:
            return emit_admission_error(o, w, 8, status)
        if status == 5 or status == 6:
            return emit_admission_error(o, w, 7, status - 4)
        if status == 8:
            return emit_admission_error(o, w, 7, 1)
        if status == 3 or status == 7:
            return emit_admission_error(o, w, 2, choose(status == 3, 1, 2))
        return BAD
    if stage == 2:
        return inspection_feedback(o, w, 2, 0, EMIT_FIELDS + 24)
    return BAD

def emit_wall_row(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == 3:
        return clock_sample(o, w, EMIT_CLOCK_REALTIME, 1)
    if stage == 11:
        return clock_sample(o, w, EMIT_CLOCK_MONOTONIC, 0)
    return BAD
'''


def admission_constants(shared):
    constants = front_constants(shared, request_slot=3168, field_slots=3216, control_words=3800)
    constants.update(EMIT_PROFILES=4096, READ_EMIT_PROFILE=5, EMIT_PROFILES_ROLE=37, EMIT_BUDGET_ROLE=38)
    states = ('EMIT_PROFILES_BOUND', 'EMIT_PROFILE_FIELD', 'EMIT_PROFILE_PLAN', 'EMIT_PROFILE_PROOF',
              'EMIT_BUDGET_BOUND', 'EMIT_CLOCK_MONOTONIC', 'EMIT_CLOCK_REALTIME',
              'EMIT_WALL_BOUND', 'EMIT_ADMISSION_REFUSED')
    purposes = ('EMIT_OPEN_PROFILE', 'EMIT_READ_PROFILE', 'EMIT_PROFILE_AUTHORIZED',
                'EMIT_PROFILE_REFUSED', 'EMIT_CLOSE_WALL_ROW')
    spans = ('EMIT_INSTALLED', 'EMIT_PROFILE_PIN', 'EMIT_CONTEXT_BUDGET', 'EMIT_CONTEXT_ROW',
             'EMIT_WALL_PERMIT', 'EMIT_PUBLIC_ERROR')
    scalars = ('EMIT_PROFILE_CURSOR', 'EMIT_PROFILE_INDEX', 'EMIT_PROFILE_ROLE',
               'EMIT_WALL_LIMIT', 'EMIT_WALL_TICK', 'EMIT_PROFILE_LEVEL', 'EMIT_ABSOLUTE_DEADLINE')
    constants.update({name: constants['EMIT_PEER_OPENED'] + 1 + i for i, name in enumerate(states)})
    constants.update({name: shared['PROFILE_ROW'] + 1 + i for i, name in enumerate(purposes)})
    constants.update({name: 4432 + 24 * i for i, name in enumerate(spans)})
    constants.update({name: 4576 + 8 * i for i, name in enumerate(scalars)})
    words = {
        'EMIT_PROFILES_TAG': b'HIAEPR01', 'EMIT_BUDGET_TAG': b'HIACAB01',
        'EMIT_BUDGET_PREFIX': b'[{"budge', 'EMIT_BUDGET_MIDDLE': b't":', 'EMIT_BUDGET_END': b'}]',
        'EMIT_ADMISSION_WINDOW': b'HIAEMW01', 'EMIT_WINDOW_RESULT': b'HIAEMW02',
        'EMIT_LAUNCH_WINDOW': b'HIAEMW03', 'EMIT_LAUNCH_PERMIT': b'HIAEMW04',
    }
    constants.update({name: int.from_bytes(word, 'little') for name, word in words.items()})
    constants.update({f'EMIT_{profile.upper()}_QUERY_BYTES': 8 + 144 + len(f'hia-{profile}-v1')
                      for profile in PROFILE_PORTS[3:]})
    return constants


def retained_controls():
    retained = worker.RETAINED_DRIVER.replace('inspection_feedback(', 'emit_retained_checked(')
    retained = retained.replace(
        '    if reason == READ_PROFILE and corruption == False:\n'
        '        return emit_retained_checked(o, w, 2, 3, 0)',
        '    if reason == READ_PROFILE and corruption == False:\n'
        '        return emit_retained_checked(o, w, 2, 8, 0)',
    ).replace(
        '    if reason == READ_PROGRAM:\n        return emit_retained_checked(o, w, 3, 1, 0)',
        '    if reason == READ_EMIT_PROFILE and corruption == False:\n'
        '        return emit_admission_error(o, w, 7, 1)\n'
        '    if reason == READ_PROGRAM:\n        return emit_retained_checked(o, w, 3, 1, 0)',
    ).replace(
        '        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 40, 176)',
        '        if get(w, EMIT_STAGE) == 3 or get(w, EMIT_STAGE) == 11:\n'
        '            body_span(s, w, EMIT_CONTEXT_ROW)\n'
        '            return close_store(o, w, EMIT_CLOSE_WALL_ROW)\n'
        '        if get(w, EMIT_STAGE) == 6 or get(w, EMIT_STAGE) == 9:\n'
        '            body_span(s, w, EMIT_CONTEXT_ROW)\n'
        '        hold(w, INSPECTION_REFERENCE, input_word(s, 32), 40, 176)',
    ).replace(
        '    if reason == READ_PROFILE:\n',
        '    if reason == READ_EMIT_PROFILE:\n'
        '        return inspection_feedback(o, w, get(w, EMIT_STAGE), 0, 0)\n'
        '    if reason == READ_PROFILE:\n',
    ).replace(
        '    if profile != 0:',
        '    put(w, EMIT_PROFILE_LEVEL, profile)\n    if profile != 0:',
    ).replace(
        '    if index == 6:',
        '    if index == 5:\n        hold(w, EMIT_CONTEXT_BUDGET, input_word(s, 32), at, size)\n'
        '    if index == 6:',
    )
    return retained


def store_controls():
    store = worker.STORE_DRIVER.replace('inspection_feedback(', 'emit_retained_checked(')
    store = store.replace(
        '    if purpose == OPEN_CONTEXT_ROW:',
        '    if purpose == EMIT_OPEN_PROFILE:\n'
        '        return store_transaction(o, w, EMIT_READ_PROFILE, 12, 1, query, 8, bytes - 8)\n'
        '    if purpose == OPEN_CONTEXT_ROW:',
    ).replace(
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
        '    if purpose == EMIT_PROFILE_REFUSED or purpose == EMIT_PROFILE_AUTHORIZED:\n'
        '        return emit_profile_closed(o, w, purpose)\n'
        '    if purpose == EMIT_CLOSE_WALL_ROW:\n'
        '        return emit_wall_row(o, w)\n'
        '    if purpose == CLOSE_CONTEXT_UNAVAILABLE:',
    ).replace(
        '    if purpose == CONTEXT_ROW:',
        '    if purpose == EMIT_READ_PROFILE:\n'
        '        return emit_profile_observed(o, w, bytes)\n'
        '    if purpose == CONTEXT_ROW:',
    ).replace(
        '    if purpose == CLOSE_PROFILE_REFUSED:\n        return emit_retained_checked(o, w, 2, 3, 0)',
        '    if purpose == CLOSE_PROFILE_REFUSED:\n        return emit_retained_checked(o, w, 2, 7, 0)',
    )
    return store


def admission_recipe():
    """Reuse the Journal, Store, and retained Context transport for Emit."""
    constants, controls = worker.recipe()
    constants.update(admission_constants(constants))
    roles = len(EMIT_ROLES) + 1
    constants.update(ROLE_COUNT=roles, ENTRY_BYTES=64 + 312 + roles * 40, SCHEMA_TOOL=8, ROLE_BASE=8192,
                     INSPECTION_EFFECT_ROLE=34, INSPECTION_CONTEXT_ROLE=33, EMIT_INSTALLATION=5576,
                     EMIT_WORK_BYTES=9216, EMIT_EFFECT_LIMIT=1048576,
                     EMIT_TRUST_ROLE=len(EMIT_ROLES), EMIT_TRUST_HEADER=492,
                     EMIT_TRUST_MAGIC=int.from_bytes(PROOF_TRUST_MAGIC, 'little'),
                     EMIT_TRUST_FILE_MAGIC=int.from_bytes(PROOF_TRUST_MAGIC[:4], 'little'),
                     EMIT_TRUST_BYTES=PROOF_TRUST_BYTES, EMIT_TRUST_RUNTIME_MAX=PROOF_TRUST_RUNTIME_MAX,
                     EMIT_TRUST_NATIVE_OFFSET=PROOF_TRUST_NATIVE_OFFSET, EMIT_TRUST_NATIVE_BYTES=PROOF_TRUST_NATIVE_BYTES)
    driver = worker.DRIVER.replace('def inspection_flow(', 'def emit_flow(')
    driver = driver.replace('length(w) != 4096', 'length(w) != EMIT_WORK_BYTES')
    driver = driver.replace(
        '    if state <= INSPECTION_LOWERING_PROFILE_BOUND',
        '    if state == EMIT_TRUST_HEADER:\n'
        '        return emit_trust_spans(s, o, w)\n'
        '    if state <= INSPECTION_LOWERING_PROFILE_BOUND',
    )
    driver = driver.replace(
        '    if state <= INSPECTION_PEER_CLOSED:\n'
        '        return inspection_effect(s, o, w, state)\n'
        '    if state <= INSPECTION_PROFILE_BOUND:\n'
        '        return inspect_retained(s, o, w, state)\n'
        '    return inspection_render(s, o, w, state)',
        '    if state >= INSPECTION_SENT and state <= INSPECTION_PEER_CLOSED:\n'
        '        return emit_peer_observation(s, o, w, state)\n'
        '    if state >= INSPECTION_CONTEXT_REFERENCE and state <= INSPECTION_PROFILE_BOUND:\n'
        '        return inspect_retained(s, o, w, state)\n'
        '    if state >= EMIT_PROJECTED and state <= EMIT_PEER_OPENED:\n'
        '        return emit_prepare(s, o, w, state)\n'
        '    if state == EMIT_PROFILES_BOUND or state == EMIT_PROFILE_FIELD:\n'
        '        return emit_installation_state(s, o, w, state)\n'
        '    if state == EMIT_PROFILE_PLAN or state == EMIT_PROFILE_PROOF:\n'
        '        return emit_profile_state(s, o, w, state)\n'
        '    if state >= EMIT_BUDGET_BOUND and state <= EMIT_ADMISSION_REFUSED:\n'
        '        return emit_wall_state(s, o, w, state)\n'
        '    return emit_product_state(s, o, w, state)',
    ).replace(
        '        return installation_profile_request(o, w, True)',
        '        return emit_installed_profiles(o, w)',
    )
    support = (
        function(worker.EFFECT_DRIVER, 'inspection_feedback'),
        function(worker.DOCUMENT_DRIVER, 'vector_span'),
        function(worker.DOCUMENT_DRIVER, 'wide_inspection'),
    )
    filtered = []
    for control in controls:
        if control.startswith('\ndef settle_transaction('):
            control = control.replace(
                'if purpose >= CONTEXT_ROW and purpose <= PROFILE_ROW:',
                'if (purpose >= CONTEXT_ROW and purpose <= PROFILE_ROW) or purpose == EMIT_READ_PROFILE:',
            )
        filtered.append(control)
    return constants, driver, (REQUEST, REACTOR, PROFILES, ADMISSION, retained_controls(),
                               store_controls(), *support, *filtered)


DISPATCH = r'''
def emit_trust_spans(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 72)
    if (length(s) != 80 or input_word(s, 40) != EMIT_TRUST_BYTES or input_word(s, 64) != EMIT_TRUST_MAGIC
            or size < 2 or size > EMIT_TRUST_RUNTIME_MAX):
        return BAD
    hold(w, EMIT_PROOF_TRUST_SELECTION, fd, 16, 66)
    hold(w, EMIT_PROOF_TRUST_RUNTIME, fd, 82, size)
    return clock_sample(o, w, INSPECTION_CLOCK, 0)

def authorize_business(o:mutbuf, w:mutbuf) -> u64:
    return emit_projection(o, w)

def emit_business(o:mutbuf, w:mutbuf, stage:u64, operand:u64) -> u64:
    if stage >= 12:
        put(w, EMIT_OPERAND, operand)
        return EMIT_DEFER_PRODUCT
    if stage == 6 or stage == 9:
        put(w, EMIT_OPERAND, operand)
        put(w, EMIT_PROOF_PROFILE_PHASE, 1)
        move_fragment(w, EMIT_FIELDS + 24, INSPECTION_ACTUAL)
        return inspection_context(o, w)
    if stage == 8 or stage == 10:
        put(w, EMIT_OPERAND, operand)
        return EMIT_DEFER_PROOF
    return emit_admission(o, w, stage, operand)

def emit_proof_profile_finished(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, EMIT_PROOF_PROFILE_PHASE)
    if phase == 1:
        put(w, EMIT_PROOF_PROFILE_PHASE, 2)
        return emit_open_profile(o, w, 6, EMIT_PROFILES + 288)
    if phase == 2 or phase == 3:
        return EMIT_DEFER_PROOF
    return BAD

def emit_dispatch(w:mutbuf, state:u64) -> u64:
    if state == INSPECTION_HASH_RETURNED or state == INSPECTION_HASH_FRAME:
        return choose(get(w, INSPECTION_HASH_RESUME) >= EMIT_PROOF_BEGIN, EMIT_DEFER_PROOF, EMIT_DEFER_PRODUCT)
    if state >= EMIT_OBJECT_PRODUCED and state < EMIT_PROOF_BEGIN:
        return EMIT_DEFER_PRODUCT
    if state >= EMIT_PROOF_BEGIN and state < EMIT_PROOF_LIMIT:
        return EMIT_DEFER_PROOF
    return BAD
'''


def native_recipe():
    """Bind disjoint effect continuations without making them public tools."""
    constants, driver, parts = admission_recipe()
    constants.update(producer_constants(constants))
    constants.update(publication_constants(constants))
    constants.update(record_constants(constants))
    constants.update(measurement_constants(constants))
    constants.update(scalar_constants(constants))
    constants.update(proof_constants())
    constants.update(EMIT_OPERAND=4656, EMIT_PROOF_BEGIN=512, EMIT_PROOF_LIMIT=768,
                     EMIT_DEFER_PRODUCT=0xffffffe8, EMIT_DEFER_PROOF=0xffffffe9)
    driver = driver.replace(
        '    if input_word(s, 16) != operation or input_word(s, 24) != 0:',
        '    status = input_word(s, 24)\n'
        '    expired = (operation == RUN and status == EMIT_EXPIRED and\n'
        '               (state == EMIT_OBJECT_PRODUCED or state == EMIT_IMAGE_PRODUCED\n'
        '                or state == EMIT_SCALAR_REPORT_READY))\n'
        '    if input_word(s, 16) != operation or (status != 0 and expired == False):',
    ).replace(
        '    if (operation == RUN or operation == MAKE) and valid_fd(input_word(s, 32)) == False:',
        '    if (operation == RUN or operation == MAKE) and expired == False and valid_fd(input_word(s, 32)) == False:',
    ).replace('return emit_product_state(s, o, w, state)', 'return emit_dispatch(w, state)')
    controls = (product_store_dispatch(part) for part in parts)
    return constants, driver, (*bound_run_controls(controls), DISPATCH)


def product_store_dispatch(source):
    if source == ADMISSION:
        return source.replace(
            '    if stage == 2:\n        return inspection_feedback(o, w, 2, 0, EMIT_FIELDS + 24)',
            '    if stage == 2:\n        return inspection_feedback(o, w, 2, 0, EMIT_FIELDS + 24)\n'
            '    if (stage == 6 or stage == 9) and get(w, EMIT_PROOF_PROFILE_PHASE) == 1:\n'
            '        return emit_open_profile(o, w, 1, EMIT_PROFILES + 48)',
        )
    if source == retained_controls():
        return source.replace(
            '    if reason == READ_EMIT_PROFILE and corruption == False:',
            '    if reason == READ_EMIT_PLAN:\n'
            '        return emit_admission_error(o, w, 7, 1)\n'
            '    if reason == READ_EMIT_PROFILE and corruption == False:',
        ).replace(
            '        if plan_ok(s) == False or input_word(s, 40) != 80:\n'
            '            return BAD\n'
            '        observe_slot(s, w, PROFILE_FD)',
            '        expected = choose(get(w, RETAINED_KIND) >= 5, 96, 80)\n'
            '        if plan_ok(s) == False or input_word(s, 40) != expected:\n'
            '            return BAD\n'
            '        observe_slot(s, w, PROFILE_FD)',
        ).replace(
            '    if state == RETAINED_DIGEST:\n'
            '        return capture_retained_inspection(s, o, w)',
            '    if state == RETAINED_DIGEST:\n'
            '        if get(w, RETAINED_KIND) >= 5:\n'
            '            return EMIT_DEFER_PROOF\n'
            '        return capture_retained_inspection(s, o, w)',
        ).replace(
            '    if reason == READ_INSTALLATION:\n        sample_span',
            '    if reason >= READ_EMIT_PLAN:\n'
            '        return EMIT_DEFER_PROOF\n'
            '    if reason == READ_EMIT_PROFILE and (get(w, EMIT_STAGE) == 6 or get(w, EMIT_STAGE) == 9):\n'
            '        return emit_proof_profile_finished(o, w)\n'
            '    if reason == READ_INSTALLATION:\n        sample_span',
        )
    if source.startswith('\ndef artifact_entry('):
        capture = (
            '    entry = ENTRY_HEAD + DOSSIER_HEAD\n'
            '    object = entry + DESCRIPTOR_BYTES * INSPECTION_EMIT_ROLE\n'
            '    link = entry + DESCRIPTOR_BYTES * EMIT_LINK_ROLE\n'
            '    scalar = entry + DESCRIPTOR_BYTES * EMIT_SCALAR_EXE_ROLE\n'
            '    machine = entry + DESCRIPTOR_BYTES * EMIT_MACHINE_PROVER_ROLE\n'
            '    hold(w, EMIT_BORROWED_EXE, input_word(s, object), 0, input_word(s, object + 24))\n'
            '    hold(w, EMIT_LINK_EXE, input_word(s, link), 0, input_word(s, link + 24))\n'
            '    hold(w, EMIT_SCALAR_EXE, input_word(s, scalar), 0, input_word(s, scalar + 24))\n'
            '    hold(w, EMIT_MACHINE_IMAGE, input_word(s, machine), 0, input_word(s, machine + 24))\n'
        )
        return source.replace(
            '    i = 0\n    while i < ROLE_COUNT:', capture + '    i = 0\n    while i < ROLE_COUNT:',
        ).replace(
            '    return clock_sample(o, w, INSPECTION_CLOCK, 0)',
            '    return read_span(o, w, EMIT_TRUST_HEADER, get(w, ROLE_BASE + 8 * EMIT_TRUST_ROLE), 0, 16)',
        )
    if source.startswith('\ndef trusted_descriptors('):
        return source.replace(
            '        if input_word(s, at + 24) > 16777216 or input_word(s, at + 32) != ELF_MAGIC:',
            '        magic = choose(index == EMIT_TRUST_ROLE, EMIT_TRUST_FILE_MAGIC, ELF_MAGIC)\n'
            '        extent = input_word(s, at + 24)\n'
            '        if extent > 16777216 or input_word(s, at + 32) != magic or (index == EMIT_TRUST_ROLE and extent != EMIT_TRUST_BYTES):',
        ).replace(
            '            shared = previous == PLAN_ROLE and index == INSPECTION_CONTEXT_ROLE',
            '            shared = (previous == PLAN_ROLE and index == INSPECTION_CONTEXT_ROLE) or (previous == EMIT_SCALAR_ROLE and index == EMIT_SHARED_INVENTORY_ROLE)',
        )
    if source.startswith('\ndef inspection_store_opened('):
        return source.replace(
            '    if purpose == EMIT_OPEN_PROFILE:',
            '    if purpose == EMIT_PUB_OPEN:\n'
            '        return EMIT_DEFER_PRODUCT\n'
            '    if purpose == EMIT_OPEN_PROFILE:',
        ).replace(
            '    if purpose == EMIT_PROFILE_REFUSED or purpose == EMIT_PROFILE_AUTHORIZED:',
            '    if purpose == EMIT_PUB_CLOSE:\n'
            '        return EMIT_DEFER_PRODUCT\n'
            '    if purpose == EMIT_PROFILE_REFUSED or purpose == EMIT_PROFILE_AUTHORIZED:',
        ).replace(
            '        return read_span(o, w, RETAINED_DIGEST, slot_fd(w, PROFILE_FD), 8, 72)',
            '        size = choose(get(w, RETAINED_KIND) >= 5, 88, 72)\n'
            '        return read_span(o, w, RETAINED_DIGEST, slot_fd(w, PROFILE_FD), 8, size)',
        )
    if source.startswith('\ndef settle_transaction('):
        return source.replace(
            '    purpose = get(w, STORE_PURPOSE)\n    if (purpose >= CONTEXT_ROW',
            '    purpose = get(w, STORE_PURPOSE)\n'
            '    if purpose == EMIT_PUB_LOOKUP or purpose == EMIT_PUB_INSERT:\n'
            '        return EMIT_DEFER_PRODUCT\n'
            '    if (purpose >= CONTEXT_ROW',
        )
    return source


if __name__ == '__main__':
    from tools.generate_hia_worker_flow_packer import EMIT_POLICY, EMIT_PRODUCT, EMIT_PROOF

    values, front, controls = native_recipe()
    shared_error = function(ADMISSION, 'emit_admission_error')
    product, product_controls = product_recipe(values, shared_error)
    proof, proof_controls = proof_recipe(shared_error, function(PROFILES, 'emit_open_profile'))
    for name, entry, parts in ((EMIT_POLICY, front, controls),
                               (EMIT_PRODUCT, product, product_controls),
                               (EMIT_PROOF, proof, proof_controls)):
        target = Path(name)
        target.write_text(render_assembly(document(flow_source(entry, parts, values), target.stem)),
                          encoding='utf-8')
