"""Read-only Evaluate receipt replay using the installed Adopt proof and build engines."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_adopt_flow import recipe as adopt_recipe
from tools.generate_hia_worker_adopt_custody import custody_sections
from tools.generate_hia_worker_rollback_flow import NATIVE as ROLLBACK_NATIVE
from tools.generate_hia_worker_adopt_proof import adopt_proof_recipe, reachable_policy
from tools.generate_hia_worker_candidate_flow import replace_function
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_flow import native_recipe
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
        return read_span(o,w,PROOF_BASE_TYPE,get(w,BASE_IMAGE),get(w,BASE_IMAGE+8),24)
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

def physical_kind(s:readbuf) -> u64:
    if length(s) != 88 or input_word(s,64) != ELF64 or (input_word(s,80) >> 16 & 65535) != 62:
        return 0
    kind = input_word(s,80) & 65535
    if kind != 1 and kind != 3:
        return 0
    return kind

def compare_build_profiles(s:readbuf,o:mutbuf,w:mutbuf,state:u64) -> u64:
    if state == PROOF_BASE_TYPE or state == PROOF_CAND_TYPE:
        kind = physical_kind(s)
        if kind == 0:
            return BAD
        if state == PROOF_BASE_TYPE:
            put(w,BASE_TYPE,kind)
            return read_span(o,w,PROOF_CAND_TYPE,get(w,CAND_IMAGE),get(w,CAND_IMAGE+8),24)
        if kind == 1 or get(w,BASE_TYPE) == 1:
            return build_refused(o,w,24)
        return rollback_compare(o,w,PROOF_ABI,BASE_SIGNATURE,CAND_SIGNATURE)
    if state == PROOF_ABI:
        if rollback_binding(s) == False:
            return BAD
        if input_word(s,80) == 0:
            return build_refused(o,w,25)
        move_fragment(w, ADOPT_OBJECTIVE_REF, INSPECTION_REFERENCE)
        put(w, RETAINED_PURPOSE, READ_ADOPT_OBJECTIVE)
        return inspection_retained_query(o,w,0)
    if state != PROOF_REFUSED or input_word(s,40) != 80 or input_word(s,64) != BUILD_REFUSAL:
        return BAD
    fragment(o,0,input_word(s,32),0,80)
    return action(o,w,PROOF_PUBLISHED,PUBLISH,0,0,1,0)

def build_refused(o:mutbuf,w:mutbuf,reason:u64) -> u64:
    put(o,HEADER,BUILD_REFUSAL)
    put(o,HEADER+8,reason)
    copy_private(w,o,PROOF_REQUEST_SHA,HEADER+16,64)
    return action(o,w,PROOF_REFUSED,MAKE,0,0,0,80)

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
                     SCHEMA_TOOL=9, EVALUATE_REQUEST_ROLE=role, PROOF_REQUEST_SHA=11968,
                     EVALUATE_LAYOUT=int.from_bytes(b'HIAEVQ01', 'little'),
                     PROVED_TAG=int.from_bytes(b'HIAEDP01', 'little'))
    constants.update(BASE_IMAGE=12040,CAND_IMAGE=12064,BASE_SIGNATURE=12088,CAND_SIGNATURE=12112,BASE_TYPE=12136,
                     ELF64=int.from_bytes(b'\x7fELF\x02\x01\x01\x00','little'),BUILD_REFUSAL=int.from_bytes(b'HIAEFP01','little'))
    states = ('PROOF_TOOL', 'PROOF_HASH', 'PROOF_DIGEST', 'PROOF_MADE', 'PROOF_PUBLISHED',
              'PROOF_BASE_TYPE', 'PROOF_CAND_TYPE', 'PROOF_ABI', 'PROOF_REFUSED')
    constants.update({name: i for i, name in enumerate(states, 1270)})
    tail = b',"tool":"hia_evaluate"}'
    constants['TOOL_BYTES'] = len(tail)
    suffix = 'def tool_suffix(s:readbuf) -> bool:\n    return (' + ' and\n            '.join(
        f'byte(s, {64 + i}) == {b}' for i, b in enumerate(tail)) + ')\n'
    entry = entry.replace('def adopt_flow(', 'def evaluate_proof_flow(')
    entry = entry.replace('    if state == EMIT_TRUST_HEADER:', '''    if state >= PROOF_TOOL and state <= PROOF_DIGEST:
        return proof_request_digest(s, o, w, state)
    if state >= PROOF_BASE_TYPE and state <= PROOF_REFUSED:
        return compare_build_profiles(s,o,w,state)
    if state == PROOF_MADE or state == PROOF_PUBLISHED:
        return proof_publish(s, o, w, state)
    if state == EMIT_TRUST_HEADER:''')
    # The proof owner performs typed Store reads and authenticated replays.
    # It can return a physically verified build refusal to the Journal owner.
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
    source += '\n'.join(function(PROJECT,name) for name in ('physical_kind','compare_build_profiles','build_refused'))
    source += '\n'.join(function(ROLLBACK_NATIVE,name) for name in ('rollback_compare','rollback_binding'))
    front, controls = reachable_policy(source, 'evaluate_proof_flow')
    _, _, original_controls = native_recipe()
    entry, parts = custody_sections(constants, original_controls)
    source = '\n'.join((entry, *parts))
    # Phase 4 opens the baseline from the request, checks its installation,
    # context, actual Core hash, signatures and exports before preserving that
    # digest. Keep its image and computed ABI separate from the candidate.
    # Phase 0 and every scheduled recheck use the original build custody.
    source = source.replace('return adopt_image(o, w, 1, ADOPT_CLAIM_FIELDS + 24)',
                            'return adopt_image(o, w, 4, ADOPT_EVAL_FIELDS + 96)')
    needle = '        if phase == 1:\n'
    assert source.count(needle) == 1
    source = source.replace(needle, '''        if phase == 0 and get(w,ADOPT_RECHECK_MODE) == 0:
            move_fragment(w,ADOPT_NATIVE_SIGNATURES,CAND_SIGNATURE)
            move_fragment(w,ADOPT_NATIVE_IMAGE,CAND_IMAGE)
        if phase == 4:
            move_fragment(w,ADOPT_NATIVE_SIGNATURES,BASE_SIGNATURE)
            move_fragment(w,ADOPT_NATIVE_IMAGE,BASE_IMAGE)
            move_fragment(w, EMIT_PROOF_CANDIDATE_SHA, ADOPT_CLAIM_FIELDS + 48)
            put(w, ADOPT_IMAGE_PHASE, 0)
            move_fragment(w, ADOPT_CLAIM_FIELDS + 24, EMIT_CUSTODY_NATIVE_REF)
            move_fragment(w, ADOPT_EVAL_FIELDS + 24, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_CUSTODY_BUILD, 5)
''' + needle)
    custody, parts = reachable_policy(source, 'adopt_custody')
    proof, proof_parts = adopt_proof_recipe(constants)
    return (flow_source(front, controls, constants), flow_source(custody, parts, constants),
            flow_source(proof, proof_parts, constants))


if __name__ == '__main__':
    for path, source in zip((FRONT, CUSTODY, REPLAY), sources(), strict=True):
        path.write_text(render_assembly(document(source, path.stem)), encoding='utf-8')
