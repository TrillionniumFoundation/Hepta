"""Replay Adopt's native image and mandatory build custody before its proofs."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as release_policy
from tools.generate_hia_worker_context_effect import POLICY as context_effect
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_adopt_slot import slot_sections, slot_store_control
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_emit_custody_replay import CUSTODY, custody_replay_source
from tools.generate_hia_worker_emit_flow import native_recipe
from tools.generate_hia_worker_emit_proof import PLAN
from tools.generate_hia_worker_emit_record import RECORD
from tools import generate_hia_worker_inspection_flow as inspection
from tools.generate_hia_worker_rollback_flow import NATIVE as ROLLBACK_NATIVE

SOURCE = Path('examples/hia_bootstrap/worker_adopt_custody.hepta')

POLICY = r'''
def adopt_custody(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 2048 or length(w) != EMIT_WORK_BYTES:
        return BAD
    state = get(w, 0)
    if state == ADOPT_CUSTODY_START:
        put(w, ADOPT_CUSTODY_ACTIVE, 1)
        move_fragment(w, ADOPT_CLAIM_FIELDS + 24, EMIT_CUSTODY_NATIVE_REF)
        move_fragment(w, ADOPT_EVAL_FIELDS + 24, INSPECTION_REFERENCE)
        return emit_proof_read(o, w, READ_EMIT_CUSTODY_BUILD, 5)
    if state == ADOPT_CUSTODY_CLAIMS:
        size = get(w, ADOPT_CLAIM_SCHEDULE + 16)
        if size < 25 or size > 89:
            return BAD
        return read_span(o, w, ADOPT_CLAIM_FRAME, get(w, ADOPT_CLAIM_SCHEDULE), get(w, ADOPT_CLAIM_SCHEDULE + 8), size)
    if state == ADOPT_CUSTODY_SLOT:
        put(w, ADOPT_CUSTODY_ACTIVE, 1)
        return adopt_image(o, w, 1, ADOPT_CLAIM_FIELDS + 24)
    if state == ADOPT_SLOT_CONDITIONAL:
        return adopt_open_slot(o, w)
    if state == ADOPT_SLOT_RENDER_ERROR:
        at = adopt_error_body(o, get(w, ADOPT_CUSTODY_ERROR))
        if at == HEADER:
            return BAD
        return action(o, w, ADOPT_ERROR_BODY, MAKE, 0, 0, 0, at - HEADER)
    if state >= ADOPT_SLOT_OPENED and state <= RB_RESULT_JSON:
        return adopt_slot_state(s, o, w, state)
    if state >= ADOPT_CLAIM_FRAME and state <= ADOPT_CLAIM_BUILD_BOUND:
        return adopt_claim_build(s, o, w, state)
    if state == ADOPT_NATIVE_CORE_READY:
        return inspection_hash(o, w, ADOPT_NATIVE_CORE_HASH, INSPECTION_CORE)
    if state == RETAINED_DIGEST:
        return emit_proof_typed_artifact(s, o, w)
    if state == RETAINED_BYTES:
        if get(w, RETAINED_PURPOSE) == READ_ADOPT_NATIVE:
            return adopt_native_loaded(s, o, w)
        return emit_proof_custody_reopened(s, o, w, get(w, RETAINED_PURPOSE))
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state >= ADOPT_NATIVE_METADATA and state <= ADOPT_NATIVE_SIGNATURE_MATCH:
        return adopt_native_state(s, o, w, state)
    if state == ADOPT_ABI_MATCH or state == ADOPT_EXPECTED_BOUND:
        return adopt_slot_admission(s, o, w, state)
    if state >= EMIT_CUSTODY_PROJECTED and state <= EMIT_CUSTODY_VERIFIED:
        return emit_proof_custody_state(s, o, w, state)
    return BAD

def adopt_build_candidate(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if plan_ok(s) == False or input_word(s, 72) != EMIT_CUSTODY_PROJECTION:
        return BAD
    if size == 24 and input_word(s, 80) == 1:
        return adopt_custody_error(w, 4)
    if size == 24 and input_word(s, 80) == 2:
        return adopt_custody_error(w, 5)
    if (size != 376 and size != 552) or input_word(s, 80) != 0:
        return BAD
    fd = input_word(s, 32)
    hold(w, EMIT_CUSTODY_OBJECT_REF, fd, 200, 176)
    hold(w, EMIT_CUSTODY_PLAN_REF, fd, 376, choose(size == 552, 176, 0))
    hold(w, ADOPT_BUILD_CORE, fd, 24, 176)
    move_fragment(w, EMIT_CUSTODY_NATIVE_REF, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_ADOPT_NATIVE, 7)

def adopt_native_loaded(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if input_word(s, 40) < 64:
        return BAD
    sample_span(s, w, ADOPT_NATIVE_IMAGE)
    use_span(w, o, ADOPT_NATIVE_META, 0)
    return action(o, w, ADOPT_NATIVE_METADATA, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 1, 0)

def adopt_native_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    fd = input_word(s, 32)
    if state == ADOPT_NATIVE_METADATA:
        if plan_ok(s) == False or size != 120:
            return BAD
        return read_span(o, w, ADOPT_NATIVE_FIELDS, fd, 8, 112)
    if state == ADOPT_NATIVE_FIELDS:
        return rollback_metadata(s, o, w)
    if state == ADOPT_NATIVE_SIGNED:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, ADOPT_NATIVE_SIGNATURES)
        return rollback_compare(o, w, ADOPT_NATIVE_SIGNATURE_MATCH, ADOPT_NATIVE_SIGNATURES, RB_NATIVE_FIELDS + 120)
    if rollback_binding(s) == False:
        return BAD
    if input_word(s, 80) != 1:
        if state == ADOPT_NATIVE_INSTALL_MATCH or state == ADOPT_NATIVE_CONTEXT_MATCH:
            return adopt_custody_error(w, 6)
        return adopt_custody_error(w, choose(state == ADOPT_NATIVE_BUILD_CORE_MATCH, 5, 7))
    if state == ADOPT_NATIVE_INSTALL_MATCH:
        if get(w, ADOPT_IMAGE_PHASE) == 3:
            put(w, 0, ADOPT_LIVE_CONTEXT)
            return ADOPT_DEFER_FRONT
        return rollback_compare(o, w, ADOPT_NATIVE_CONTEXT_MATCH, RB_NATIVE_FIELDS + 24, EMIT_FIELDS + 24)
    if state == ADOPT_NATIVE_CONTEXT_MATCH:
        if get(w, ADOPT_IMAGE_PHASE) == 0:
            return rollback_compare(o, w, ADOPT_NATIVE_BUILD_CORE_MATCH, RB_NATIVE_FIELDS + 48, ADOPT_BUILD_CORE)
        return adopt_open_native_core(w)
    if state == ADOPT_NATIVE_BUILD_CORE_MATCH:
        return adopt_open_native_core(w)
    if state == ADOPT_NATIVE_CORE_MATCH:
        if get(w, RB_NATIVE_FIELDS + 112) != 0:
            return rollback_compare(o, w, ADOPT_NATIVE_EXPORT_MATCH, RB_NATIVE_FIELDS + 96, INSPECTION_EXPORTS)
        if get(w, INSPECTION_EXPORTS + 16) != 2:
            return adopt_custody_error(w, 7)
        return adopt_native_signature(o, w)
    if state == ADOPT_NATIVE_EXPORT_MATCH:
        return adopt_native_signature(o, w)
    if state == ADOPT_NATIVE_SIGNATURE_MATCH:
        phase = get(w, ADOPT_IMAGE_PHASE)
        if phase == 1:
            move_fragment(w, ADOPT_NATIVE_SIGNATURES, ADOPT_CANDIDATE_SIGNATURE)
            return adopt_image(o, w, 2, ADOPT_EVAL_FIELDS + 96)
        if phase == 2:
            return rollback_compare(o, w, ADOPT_ABI_MATCH, ADOPT_CANDIDATE_SIGNATURE, ADOPT_NATIVE_SIGNATURES)
        if phase == 3:
            return inspection_hash(o, w, ADOPT_LIVE_HASH, ADOPT_NATIVE_IMAGE)
        if phase != 0:
            return BAD
        if get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0:
            move_fragment(w, EMIT_CUSTODY_PLAN_REF, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_CUSTODY_PLAN, 0)
        return emit_custody_inputs(o, w)
    return BAD

def adopt_open_native_core(w:mutbuf) -> u64:
    move_fragment(w, RB_NATIVE_FIELDS + 48, EMIT_FIELDS + 48)
    move_fragment(w, EMIT_FIELDS + 48, INSPECTION_ACTUAL)
    put(w, 0, ADOPT_NATIVE_OPEN_CORE)
    return ADOPT_DEFER_FRONT

def adopt_image(o:mutbuf, w:mutbuf, phase:u64, reference:u64) -> u64:
    if get(w, reference + 16) != 176:
        return BAD
    put(w, ADOPT_IMAGE_PHASE, phase)
    put(w, ADOPT_CUSTODY_ACTIVE, 1)
    move_fragment(w, reference, INSPECTION_REFERENCE)
    return emit_proof_read(o, w, READ_ADOPT_NATIVE, 7)

def adopt_slot_admission(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_ABI_MATCH:
        if rollback_binding(s) == False:
            return BAD
        if input_word(s, 80) == 0:
            return adopt_custody_error(w, 14)
        return inspection_hash(o, w, ADOPT_CANDIDATE_ABI_HASH, ADOPT_CANDIDATE_SIGNATURE)
    if plan_ok(s) == False:
        return BAD
    status = input_word(s, 80)
    if input_word(s, 72) == ADOPT_EVAL_TAG and input_word(s, 40) == 24 and (status == 8 or status == 9):
        return adopt_custody_error(w, status + 7)
    if input_word(s, 72) != ADOPT_EXPECTED_VALUES or input_word(s, 40) != 32:
        return BAD
    put(w, ADOPT_EXPECT_GENERATION, status)
    put(w, ADOPT_EXPECT_EPOCH, input_word(s, 88))
    put(w, ADOPT_CUSTODY_ACTIVE, 0)
    put(w, 0, ADOPT_SLOT_CONDITIONAL)
    return ADOPT_DEFER_FRONT

def adopt_expected_request(o:mutbuf, w:mutbuf) -> u64:
    generation = ADOPT_INTAKE_FIELDS + 24
    epoch = ADOPT_INTAKE_FIELDS + 48
    gen_bytes = get(w, generation + 16)
    epoch_bytes = get(w, epoch + 16)
    # Bounds are already established by the schema and the projection; do
    # not let malformed extent metadata become an unbounded decimal read.
    if gen_bytes < 3 or gen_bytes > 22:
        return adopt_custody_error(w, 15)
    if epoch_bytes < 3 or epoch_bytes > 22:
        return adopt_custody_error(w, 16)
    put(o, HEADER, ADOPT_EXPECTED_REQUEST)
    put(o, HEADER + 8, gen_bytes - 2)
    put(o, HEADER + 16, epoch_bytes - 2)
    fragment(o, 0, get(w, generation), get(w, generation + 8) + 1, gen_bytes - 2)
    fragment(o, 1, get(w, epoch), get(w, epoch + 8) + 1, epoch_bytes - 2)
    return action(o, w, ADOPT_EXPECTED_BOUND, RUN, ADOPT_AUTHORITY_ROLE, 0, 2, 24)

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume == ADOPT_NATIVE_CORE_HASH:
        hold(w, EMIT_PROOF_CANDIDATE_SHA, input_word(s, 32), at - 65, 66)
        hold(w, ADOPT_NATIVE_CORE_DIGEST, input_word(s, 32), at - 64, 64)
        return rollback_compare(o, w, ADOPT_NATIVE_CORE_MATCH, ADOPT_NATIVE_CORE_DIGEST, RB_NATIVE_FIELDS + 72)
    if resume == ADOPT_CANDIDATE_ABI_HASH:
        hold(w, ADOPT_CANDIDATE_ABI, input_word(s, 32), at - 64, 64)
        return adopt_expected_request(o, w)
    if resume == ADOPT_LIVE_HASH:
        put(w, ADOPT_CUSTODY_ACTIVE, 0)
        hold(w, ADOPT_LIVE_SHA, input_word(s, 32), at - 64, 64)
        baseline = ADOPT_EVAL_FIELDS + 96
        if get(w, baseline + 16) != 176:
            return BAD
        hold(w, RB_FIELDS, get(w, baseline), get(w, baseline + 8) + ARTIFACT_SHA_OFFSET, 64)
        return rollback_compare(o, w, ADOPT_LIVE_BASELINE, ADOPT_LIVE_SHA, RB_FIELDS)
    if resume == RB_DOCUMENT_HASH:
        copy_span(s, w, at, RB_DOC_HASH, 64)
        return rollback_doc_lookup(o, w)
    if resume == RB_DOC_STORED:
        i = 0
        while i < 64:
            if byte(s, at + i) != byte(w, RB_DOC_HASH + i):
                return BAD
            i = i + 1
        put(o, 144, 32)
        return action(o, w, RB_DOC_NONCE, RANDOM, 0, 0, 0, 0)
    return emit_custody_hash(s, o, w, at, resume)

def adopt_build_verified(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if plan_ok(s) == False or input_word(s, 72) != EMIT_CUSTODY_PACKET:
        return BAD
    size = input_word(s, 40)
    status = input_word(s, 80)
    if size == 24 and status >= 1 and status <= 5:
        return adopt_custody_error(w, choose(status == 1, 4, choose(status == 2, 5, choose(status == 4, 9, 8))))
    if size != 32 or status != 0 or input_word(s, 88) < 1 or input_word(s, 88) > 2:
        return BAD
    if get(w, ADOPT_RECHECK_MODE) != 0:
        put(w, ADOPT_RECHECK_CURSOR, get(w, ADOPT_RECHECK_CURSOR) + 1)
        return adopt_recheck(o, w)
    put(w, ADOPT_CUSTODY_ACTIVE, 0)
    if get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0:
        move_fragment(w, EMIT_CUSTODY_PLAN_REF, ADOPT_CLAIM_FIELDS + 72)
    else:
        # The issued evaluation ref keeps canonical null out of the request
        # authority. Seal the exact not-planned operand before claim replay.
        put(o, HEADER, 1819047278)
        return action(o, w, ADOPT_NO_PLAN, MAKE, 0, 0, 0, 4)
    put(w, 0, ADOPT_BUILD_READY)
    return ADOPT_DEFER_FRONT

def adopt_claim_build(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == ADOPT_CLAIM_FRAME:
        total = input_word(s, 80)
        if input_word(s, 64) != ADOPT_CLAIM_TAG or input_word(s, 72) > 4 or total > 64 or length(s) != 89 + total:
            return BAD
        missing = byte(s, 88 + total)
        if missing > 4:
            return BAD
        copy_span(s, w, 88, ADOPT_RECHECK_INDEXES, total)
        put(w, ADOPT_RECHECK_MISSING, missing)
        put(w, ADOPT_RECHECK_TOTAL, total)
        put(w, ADOPT_RECHECK_CURSOR, 0)
        put(w, ADOPT_RECHECK_MODE, 1)
        put(w, ADOPT_CUSTODY_ACTIVE, 1)
        return adopt_recheck(o, w)
    if state == ADOPT_CLAIM_BUILD_PACKET:
        if input_word(s, 40) <= 192:
            return BAD
        fragment(o, 0, input_word(s, 32), 0, input_word(s, 40))
        return action(o, w, ADOPT_CLAIM_BUILD_BOUND, RUN, ADOPT_AUTHORITY_ROLE, 0, 1, 0)
    if plan_ok(s) == False or input_word(s, 40) != 192 or input_word(s, 72) != ADOPT_PROOF_BUILD:
        return BAD
    hold(w, INSPECTION_REFERENCE, input_word(s, 32), 16, 176)
    move_fragment(w, ADOPT_CLAIM_FIELDS + 24, EMIT_CUSTODY_NATIVE_REF)
    return emit_proof_read(o, w, READ_EMIT_CUSTODY_BUILD, 5)

def adopt_recheck(o:mutbuf, w:mutbuf) -> u64:
    current = get(w, ADOPT_RECHECK_CURSOR)
    total = get(w, ADOPT_RECHECK_TOTAL)
    if current > total or total > 64:
        return BAD
    if current < total:
        index = byte(w, ADOPT_RECHECK_INDEXES + current)
        if index >= get(w, EMIT_RECEIPT_COUNT):
            return BAD
        move_fragment(w, ADOPT_RECEIPTS + index * 24, ADOPT_RECHECK_RECEIPT)
        return adopt_claim_build_request(o, w)
    put(w, ADOPT_RECHECK_MODE, 0)
    put(w, ADOPT_CUSTODY_ACTIVE, 0)
    missing = get(w, ADOPT_RECHECK_MISSING)
    if missing < 4:
        return adopt_custody_error(w, 10 + missing)
    put(w, 0, ADOPT_CLAIMS_ACCEPTED)
    return ADOPT_DEFER_FRONT

def adopt_claim_build_request(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, ADOPT_PROOF_BUILD_SUFFIX)
    vector_span(w, o, ADOPT_RECHECK_RECEIPT, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, ADOPT_CLAIM_FIELDS + 24, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 6)
    return emit_wide_make(o, w, ADOPT_CLAIM_BUILD_PACKET, 4, 1)

def adopt_custody_error(w:mutbuf, reason:u64) -> u64:
    put(w, ADOPT_CUSTODY_ACTIVE, 0)
    put(w, ADOPT_CUSTODY_ERROR, reason)
    put(w, 0, ADOPT_CUSTODY_REFUSED)
    return ADOPT_DEFER_FRONT
'''


def custody_constants(constants):
    names = (
        'ADOPT_NATIVE_METADATA', 'ADOPT_NATIVE_FIELDS', 'ADOPT_NATIVE_INSTALL_MATCH',
        'ADOPT_NATIVE_CONTEXT_MATCH', 'ADOPT_NATIVE_BUILD_CORE_MATCH', 'ADOPT_NATIVE_CORE_MATCH',
        'ADOPT_NATIVE_EXPORT_MATCH', 'ADOPT_NATIVE_SIGNED', 'ADOPT_NATIVE_SIGNATURE_MATCH',
        'ADOPT_NATIVE_OPEN_CORE', 'ADOPT_NATIVE_CORE_READY', 'ADOPT_NATIVE_CORE_HASH',
        'ADOPT_BUILD_READY', 'ADOPT_NO_PLAN', 'ADOPT_CUSTODY_REFUSED',
        'ADOPT_CLAIM_FRAME', 'ADOPT_CLAIM_BUILD_PACKET', 'ADOPT_CLAIM_BUILD_BOUND',
        'ADOPT_ABI_MATCH', 'ADOPT_CANDIDATE_ABI_HASH', 'ADOPT_EXPECTED_BOUND', 'ADOPT_SLOT_CONDITIONAL',
    )
    constants.update({name: 1170 + i for i, name in enumerate(names)})
    constants.update(
        READ_ADOPT_NATIVE=20, READ_ADOPT_OBJECTIVE=21,
        RB_NATIVE_ROLE=constants['EMIT_NATIVE_ARTIFACT_ROLE'], RB_COMPARE=constants['EMIT_COMPARE_REQUEST'],
        RB_MATCH=constants['EMIT_COMPARE_RESULT'], RB_METADATA_TAG=int.from_bytes(b'HIAANM01', 'little'),
        RB_INSTALLED_MATCH=constants['ADOPT_NATIVE_INSTALL_MATCH'], ADOPT_CUSTODY_ACTIVE=10120,
        ADOPT_CUSTODY_ERROR=10128, ADOPT_NATIVE_META=10240, ADOPT_NATIVE_IMAGE=10264,
        ADOPT_NATIVE_SIGNATURES=10288, ADOPT_NATIVE_CORE_DIGEST=10312, ADOPT_BUILD_CORE=10336,
        RB_NATIVE_FIELDS=10360, RB_INSTALLATION=constants['EMIT_INSTALLATION'], RB_NATIVE_METADATA=10240,
        ADOPT_RECHECK_INDEXES=10504, ADOPT_RECHECK_RECEIPT=10568, ADOPT_RECHECK_MODE=10136,
        ADOPT_RECHECK_MISSING=10144, ADOPT_RECHECK_TOTAL=10152, ADOPT_RECHECK_CURSOR=10160,
        ADOPT_PROOF_BUILD=int.from_bytes(b'HIAADBR1', 'little'),
        ADOPT_PROOF_BUILD_SUFFIX=int.from_bytes(b',null]', 'little'),
        ADOPT_IMAGE_PHASE=10168, ADOPT_EXPECT_GENERATION=10176, ADOPT_EXPECT_EPOCH=10184,
        ADOPT_CANDIDATE_SIGNATURE=10592, ADOPT_CANDIDATE_ABI=10616,
        ADOPT_EXPECTED_REQUEST=int.from_bytes(b'HIAADU01', 'little'),
        ADOPT_EXPECTED_VALUES=int.from_bytes(b'HIAADU02', 'little'),
    )


def custody_sections(constants, front_controls):
    from tools.generate_hia_worker_adopt_flow import outcome_errors

    custody = CUSTODY.replace(
        'purpose == READ_EMIT_CUSTODY_NATIVE or purpose == READ_EMIT_CUSTODY_OBJECT:',
        'purpose == READ_EMIT_CUSTODY_NATIVE or purpose == READ_EMIT_CUSTODY_OBJECT or purpose == READ_ADOPT_NATIVE:',
        1,
    ).replace(
        '        hold(w, metadata, slot_fd(w, STORE_RESULT), at, size)',
        '        hold(w, choose(purpose == READ_ADOPT_NATIVE, ADOPT_NATIVE_META, metadata), slot_fd(w, STORE_RESULT), at, size)',
    )
    start = custody.index('    if state == EMIT_CUSTODY_PROJECTED:')
    end = custody.index('    if state == EMIT_CUSTODY_CANONICAL:', start)
    custody = custody[:start] + '''    if state == EMIT_CUSTODY_PROJECTED:
        return adopt_build_candidate(s, o, w)
''' + custody[end:]
    start = custody.index('        return emit_custody_verified(s, o, w)')
    end = custody.index('\ndef emit_custody_inputs', start)
    custody = custody[:start] + '        return adopt_build_verified(s, o, w)\n    return BAD\n' + custody[end:]
    reused = custody_replay_source(function(RECORD, 'emit_signature'))[1:]
    compatible = (
        function(ROLLBACK_NATIVE, 'rollback_metadata'), function(ROLLBACK_NATIVE, 'rollback_compare'),
        function(ROLLBACK_NATIVE, 'rollback_binding'),
        function(inspection.VIEW_DRIVER, 'inspection_hash'),
        function(inspection.VIEW_DRIVER, 'inspection_hash_result'),
        function(PLAN, 'emit_proof_read'),
        function(inspection.DOCUMENT_DRIVER, 'wide_inspection').replace(
            'def wide_inspection(o:mutbuf, w:mutbuf, state:u64, role:u64, args:u64, parts:u64, inline:u64)',
            'def emit_wide_make(o:mutbuf, w:mutbuf, state:u64, parts:u64, inline:u64)',
        ).replace('RUN, role, args, parts', 'MAKE, 0, 0, parts'),
        function(release_policy, 'decimal'), function(release_policy, 'divide10'),
        function(context_effect, 'quotient'),
        function(RECORD, 'emit_signature').replace('emit_signature(', 'adopt_native_signature(')
            .replace('EMIT_SIGNATURE_BOUND', 'ADOPT_NATIVE_SIGNED'),
    )
    controls = (slot_store_control(control) if control.startswith('\ndef store_transaction(') else control
                for control in front_controls)
    policy = '\n'.join((POLICY, custody, slot_sections(), outcome_errors(), *reused, *compatible, *controls))
    return reachable_policy(policy, 'adopt_custody')


def program():
    from tools.generate_hia_worker_adopt_flow import recipe
    constants, _, _ = recipe()
    _, _, controls = native_recipe()
    entry, parts = custody_sections(constants, controls)
    return flow_source(entry, parts, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
