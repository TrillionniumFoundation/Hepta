"""Replay Adopt's native image and mandatory build custody before its proofs."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_exec_release import POLICY_SOURCE as release_policy
from tools.generate_hia_worker_context_effect import POLICY as context_effect
from tools.generate_hia_worker_adopt_proof import reachable_policy
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
        return rollback_compare(o, w, ADOPT_NATIVE_CONTEXT_MATCH, RB_NATIVE_FIELDS + 24, EMIT_FIELDS + 24)
    if state == ADOPT_NATIVE_CONTEXT_MATCH:
        return rollback_compare(o, w, ADOPT_NATIVE_BUILD_CORE_MATCH, RB_NATIVE_FIELDS + 48, ADOPT_BUILD_CORE)
    if state == ADOPT_NATIVE_BUILD_CORE_MATCH:
        move_fragment(w, RB_NATIVE_FIELDS + 48, EMIT_FIELDS + 48)
        move_fragment(w, EMIT_FIELDS + 48, INSPECTION_ACTUAL)
        put(w, 0, ADOPT_NATIVE_OPEN_CORE)
        return ADOPT_DEFER_FRONT
    if state == ADOPT_NATIVE_CORE_MATCH:
        if get(w, RB_NATIVE_FIELDS + 112) != 0:
            return rollback_compare(o, w, ADOPT_NATIVE_EXPORT_MATCH, RB_NATIVE_FIELDS + 96, INSPECTION_EXPORTS)
        if get(w, INSPECTION_EXPORTS + 16) != 2:
            return adopt_custody_error(w, 7)
        return adopt_native_signature(o, w)
    if state == ADOPT_NATIVE_EXPORT_MATCH:
        return adopt_native_signature(o, w)
    if state == ADOPT_NATIVE_SIGNATURE_MATCH:
        if get(w, EMIT_CUSTODY_PLAN_REF + 16) != 0:
            move_fragment(w, EMIT_CUSTODY_PLAN_REF, INSPECTION_REFERENCE)
            return emit_proof_read(o, w, READ_EMIT_CUSTODY_PLAN, 0)
        return emit_custody_inputs(o, w)
    return BAD

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume == ADOPT_NATIVE_CORE_HASH:
        hold(w, EMIT_PROOF_CANDIDATE_SHA, input_word(s, 32), at - 65, 66)
        hold(w, ADOPT_NATIVE_CORE_DIGEST, input_word(s, 32), at - 64, 64)
        return rollback_compare(o, w, ADOPT_NATIVE_CORE_MATCH, ADOPT_NATIVE_CORE_DIGEST, RB_NATIVE_FIELDS + 72)
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
    )


def custody_sections(constants, front_controls):
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
    policy = '\n'.join((POLICY, custody, *reused, *compatible, *front_controls))
    return reachable_policy(policy, 'adopt_custody')


def program():
    from tools.generate_hia_worker_adopt_flow import recipe
    constants, _, _ = recipe()
    _, _, controls = native_recipe()
    entry, parts = custody_sections(constants, controls)
    return flow_source(entry, parts, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
