"""Read-only Evaluate receipt replay using the installed Adopt proof and build engines."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_flow import recipe as adopt_recipe
from tools.generate_hia_worker_adopt_custody import custody_sections
from tools.generate_hia_worker_adopt_proof import adopt_proof_recipe, reachable_policy
from tools.generate_hia_worker_candidate_flow import replace_function
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_flow import native_recipe
from tools.generate_hia_worker_emit_measurement import splice_list
from tools.generate_hia_worker_inspection_flow import VIEW_DRIVER

FRONT = Path('examples/hia_bootstrap/worker_evaluate_proof_flow.hepta')
CUSTODY = Path('examples/hia_bootstrap/worker_evaluate_proof_custody.hepta')
REPLAY = Path('examples/hia_bootstrap/worker_evaluate_proof_replay.hepta')

# The request owner recomputes the envelope digest and returns its exact five-field
# canonical preimage. The installed schema then admits exactly Evaluate arguments.
PROJECT = r'''
def project_request(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == REQUEST_ADMITTED:
        size = input_word(s, 40)
        if size < TOOL_BYTES or size > MAX_INPUT:
            return BAD
        observe_slot(s, w, ADMITTED_FD)
        return read_span(o, w, PROOF_TOOL, input_word(s, 32), size - TOOL_BYTES, TOOL_BYTES)
    if state == ARGUMENT_PROJECTED:
        if prefixed(s) == False:
            return BAD
        observe_slot(s, w, ARGUMENT_FD)
        return schema_receipt(o, w, INPUT_SCHEMA, INPUT_SCHEMA_ROLE, ARGUMENT_FD)
    if state == INPUT_SCHEMA and reply_word(s, 0):
        inspection_catalog(o, w)
        after_prefix(w, o, ARGUMENT_FD, 0)
        store(o, 496, 93)
        fragment(o, 1, INLINE_FRAGMENT, 496, 1)
        return action(o, w, EMIT_PROJECTED, RUN, EVALUATE_REQUEST_ROLE, 0, 2, 68)
    return BAD

def proof_request_digest(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PROOF_TOOL:
        if length(s) != 64 + TOOL_BYTES or tool_suffix(s) == False:
            return BAD
        put(o, 416, 45)
        whole_slot(w, o, ADMITTED_FD, 0)
        return artifact_command(o, w, PROOF_HASH, STORE_HASH, STORE_HASH_END, 1)
    if state == PROOF_HASH:
        size = input_word(s, 40)
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, PROOF_DIGEST, input_word(s, 32), 0, size)
    return inspection_hash_result(s, o, w)

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    copy_span(s, w, at, PROOF_REQUEST_SHA, 64)
    return project_artifact(o, w, ARGUMENT_PROJECTED, ARGUMENT, ARGUMENT_ROLE)

def adopt_intake(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == EMIT_PROJECTED:
        if plan_ok(s) == False or size < 136 or size > 376 or input_word(s, 72) != EVALUATE_LAYOUT:
            return BAD
        return read_span(o, w, EMIT_INDEX_FRAME, input_word(s, 32), 0, size)
    count = input_word(s, 80)
    if state != EMIT_INDEX_FRAME or size != 120 + 16 * count or count < 1 or count > 16:
        return BAD
    if length(s) != 64 + size or input_word(s, 64) != size - 8 or input_word(s, 72) != EVALUATE_LAYOUT:
        return BAD
    put(w, EMIT_RECEIPT_COUNT, count)
    fd = slot_fd(w, ARGUMENT_FD)
    limit = slot_bytes(w, ARGUMENT_FD)
    i = 0
    while i < count + 4:
        pos = 88 + 16 * choose(i < 4, i, i + 2)
        at = input_word(s, pos)
        span = input_word(s, pos + 8)
        if span != choose(i == 0, 121, 176) or at < 68 or at - 60 > limit or span > limit - (at - 60):
            return BAD
        dest = 0
        if i == 0:
            dest = EMIT_FIELDS + 24
        elif i == 1:
            dest = ADOPT_EVAL_FIELDS + 96
        elif i == 2:
            dest = ADOPT_CLAIM_FIELDS + 24
        elif i == 3:
            dest = ADOPT_EVAL_FIELDS + 24
        else:
            dest = EMIT_FIELDS + 96 + (i - 4) * 24
        hold(w, dest, fd, at - 60, span)
        i = i + 1
    put(w, EMIT_STAGE, 1)
    return adopt_context(o, w)

def adopt_after_context(o:mutbuf, w:mutbuf) -> u64:
    stage = get(w, EMIT_STAGE)
    if stage == 1:
        put(w, 0, ADOPT_CUSTODY_SLOT)
        return ADOPT_DEFER_CUSTODY
    if stage == 6 and get(w, EMIT_PROOF_PROFILE_PHASE) == 1:
        return emit_open_profile(o, w, 1, EMIT_PROFILES + 48)
    return BAD

def adopt_continue(o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_PROFILES_REQUIRED and get(w, EMIT_STAGE) == 6 and get(w, EMIT_PROOF_PROFILE_PHASE) == 1:
        return adopt_context(o, w)
    if state == ADOPT_PREPARED:
        put(w, 0, ADOPT_PROOF_START)
        return EMIT_DEFER_PROOF
    if state == ADOPT_NATIVE_OPEN_CORE:
        put(w, EMIT_STAGE, 12)
        return inspection_program(o, w)
    if state == ADOPT_BUILD_READY:
        move_fragment(w, ADOPT_OBJECTIVE_REF, INSPECTION_REFERENCE)
        put(w, RETAINED_PURPOSE, READ_ADOPT_OBJECTIVE)
        return inspection_retained_query(o, w, 0)
    if state == ADOPT_CLAIMS_READY:
        put(w, 0, ADOPT_CUSTODY_CLAIMS)
        return ADOPT_DEFER_CUSTODY
    if state == ADOPT_CLAIMS_ACCEPTED:
        size = get(w, ADOPT_CLAIM_SCHEDULE + 16)
        if size < 25 or size > 89:
            return BAD
        put(o, HEADER, PROVED_TAG)
        put(o, HEADER + 8, size)
        copy_private(w, o, PROOF_REQUEST_SHA, HEADER + 16, 64)
        use_span(w, o, ADOPT_CLAIM_SCHEDULE, 0)
        return action(o, w, PROOF_MADE, MAKE, 0, 0, 1, 80)
    return BAD

def proof_publish(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == PROOF_MADE:
        size = input_word(s, 40)
        if size != 80 + get(w, ADOPT_CLAIM_SCHEDULE + 16):
            return BAD
        fragment(o, 0, input_word(s, 32), 0, size)
        return action(o, w, PROOF_PUBLISHED, PUBLISH, 0, 0, 1, 0)
    if length(s) != 64:
        return BAD
    return action(o, w, PROOF_PUBLISHED, FINISHED, 0, 0, 0, 0)
'''


def sources():
    constants, entry, controls = adopt_recipe()
    role = constants['ROLE_COUNT']
    constants.update(ROLE_COUNT=role + 1, ENTRY_BYTES=constants['ENTRY_BYTES'] + 40,
                     SCHEMA_TOOL=9, EVALUATE_REQUEST_ROLE=role, PROOF_REQUEST_SHA=11968, EMIT_ENCODING_REPORT_BOUND=767,
                     EVALUATE_LAYOUT=int.from_bytes(b'HIAEVQ01', 'little'),
                     PROVED_TAG=int.from_bytes(b'HIAEDP01', 'little'))
    states = ('PROOF_TOOL', 'PROOF_HASH', 'PROOF_DIGEST', 'PROOF_MADE', 'PROOF_PUBLISHED')
    constants.update({name: i for i, name in enumerate(states, 1270)})
    tail = b',"tool":"hia_evaluate"}'
    constants['TOOL_BYTES'] = len(tail)
    suffix = 'def tool_suffix(s:readbuf) -> bool:\n    return (' + ' and\n            '.join(
        f'byte(s, {64 + i}) == {b}' for i, b in enumerate(tail)) + ')\n'
    entry = entry.replace('def adopt_flow(', 'def evaluate_proof_flow(')
    entry = entry.replace('    if state == EMIT_TRUST_HEADER:', '''    if state >= PROOF_TOOL and state <= PROOF_DIGEST:
        return proof_request_digest(s, o, w, state)
    if state == PROOF_MADE or state == PROOF_PUBLISHED:
        return proof_publish(s, o, w, state)
    if state == EMIT_TRUST_HEADER:''')
    # This entry has no Journal or slot continuation. A refusal closes the owner
    # without publishing bytes. Only typed Store reads and authenticated replays
    # are reachable from the admitted request.
    a = entry.index('    if state <= JOURNAL_RECIPE:')
    b = entry.index('    if state >= INSPECTION_CONTEXT_REFERENCE', a)
    entry = entry[:a] + '''    if state >= PEER_STARTED and state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
''' + entry[b:]
    source = '\n'.join((entry, *controls))
    for name in ('project_request', 'adopt_intake', 'adopt_after_context', 'adopt_continue'):
        source = replace_function(source, name, function(PROJECT, name))
    for name in ('adopt_outcome', 'emit_admission_error'):
        old = function(source, name)
        source = replace_function(source, name, old[:old.index('\n', 1)] + '\n    return BAD\n')
    source += '\n'.join((suffix, function(PROJECT, 'proof_request_digest'), function(PROJECT, 'proof_publish'),
                         function(VIEW_DRIVER, 'inspection_hash_result'), function(PROJECT, 'inspection_hash_bound')))
    front, controls = reachable_policy(source, 'evaluate_proof_flow')
    _, _, original_controls = native_recipe()
    entry, parts = custody_sections(constants, original_controls)
    source = '\n'.join((entry, *parts))
    # Phase 4 opens the baseline from the request, checks its installation,
    # context, actual Core hash, signatures and exports before preserving that
    # digest. Phase 0 and every scheduled recheck use unchanged build custody.
    source = source.replace('return adopt_image(o, w, 1, ADOPT_CLAIM_FIELDS + 24)',
                            'return adopt_image(o, w, 4, ADOPT_EVAL_FIELDS + 96)')
    needle = '        if phase == 1:\n'
    assert source.count(needle) == 1
    source = source.replace(needle, '''        if phase == 4:
            move_fragment(w, EMIT_PROOF_CANDIDATE_SHA, ADOPT_CLAIM_FIELDS + 48)
            put(w, ADOPT_IMAGE_PHASE, 0)
            move_fragment(w, ADOPT_CLAIM_FIELDS + 24, EMIT_CUSTODY_NATIVE_REF)
            move_fragment(w, ADOPT_EVAL_FIELDS + 24, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_CUSTODY_BUILD, 5)
''' + needle)
    custody, parts = reachable_policy(source, 'adopt_custody')
    proof, proof_parts = adopt_proof_recipe(constants)
    proof = proof.replace('    if state == RETAINED_DIGEST:', """    if state == EMIT_ENCODING_REPORT_BOUND:
        if plan_ok(s) == False or input_word(s, 40) != 24 or input_word(s, 72) != EMIT_CUSTODY_PACKET or input_word(s, 80) != 0:
            return BAD
        return emit_proof_scope_request(o, w)
    if state == RETAINED_DIGEST:""")
    source = '\n'.join((proof, *proof_parts))
    pattern = '        return emit_proof_scope_request(o, w)\n    if state == EMIT_PROOF_SCOPE_BOUND:'
    assert source.count(pattern) == 1
    source = source.replace(pattern, """        if get(w, EMIT_PROOF_SUBJECT) == 4 and get(w, EMIT_PROOF_CLAIM_KIND) == 4:
            return evaluate_encoding_report(o, w)
""" + pattern)
    source += splice_list('evaluate_encoding_report', 'EMIT_ENCODING_REPORT_BOUND',
                          ('EMIT_CUSTODY_BUILD', 'EMIT_PROOF_EVIDENCE'), role='EMIT_CUSTODY_ROLE')
    proof, proof_parts = reachable_policy(source, 'adopt_proof_flow')
    return (flow_source(front, controls, constants), flow_source(custody, parts, constants),
            flow_source(proof, proof_parts, constants))


if __name__ == '__main__':
    for path, source in zip((FRONT, CUSTODY, REPLAY), sources(), strict=True):
        path.write_text(render_assembly(document(source, path.stem)), encoding='utf-8')
