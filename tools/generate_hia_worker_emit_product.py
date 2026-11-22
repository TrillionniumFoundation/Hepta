"""Author the Emit Worker descriptor handoff for actual machine products."""

from tools.generate_hia_worker_context_flow import function
from tools import generate_hia_worker_inspection_flow as worker
from tools.generate_hia_exec_release import POLICY_SOURCE as release_policy
from tools.generate_hia_worker_emit_measurement import measurement_source
from tools.generate_hia_worker_emit_publication import PUBLICATION
from tools.generate_hia_worker_emit_record import RECORD, render_functions
from tools.generate_hia_worker_emit_scalar import SCALAR


PRODUCTION = r'''
def emit_product(o:mutbuf, w:mutbuf, stage:u64, deadline:u64) -> u64:
    absolute = get(w, EMIT_ABSOLUTE_DEADLINE)
    expected = absolute
    if stage == 13:
        sampled = get(w, EMIT_OBJECT_FINISHED_AT)
        if sampled == 0:
            return BAD
        if sampled < absolute and absolute - sampled > EMIT_LINK_LEASE:
            expected = sampled + EMIT_LINK_LEASE
    if deadline == 0 or deadline != expected:
        return BAD
    if get(w, INSPECTION_EXPORTS + 16) < 2:
        return BAD
    if get(w, INSPECTION_EXPORTS + 16) == 2:
        return emit_scalar_product(o, w, stage, deadline)
    if stage == 12:
        if get(w, INSPECTION_CORE + 16) == 0:
            return BAD
        return emit_borrowed_object(o, w, deadline)
    if stage != 13 or get(w, EMIT_OUTPUT_KIND) != 2 or get(w, EMIT_OBJECT + 16) < 64:
        return BAD
    use_span(w, o, EMIT_OBJECT, 0)
    count = action(o, w, EMIT_IMAGE_PRODUCED, RUN, EMIT_LINK_ROLE, 0, 1, 0)
    put(o, 144, deadline)
    return count

def emit_borrowed_object(o:mutbuf, w:mutbuf, deadline:u64) -> u64:
    args = 0
    if get(w, EMIT_CODEGEN_KIND) == 2:
        registers = get(w, EMIT_LAYOUT_FORMAT) == 4
        selected = choose(registers, EMIT_REGISTER_JSON, EMIT_LAYOUT)
        if get(w, selected + 8) != 0 or get(w, selected + 16) < 24:
            return BAD
        put(o, 384, EMIT_LAYOUT_OPTION_0)
        put(o, 392, choose(registers, EMIT_REGISTER_OPTION_1, EMIT_LAYOUT_OPTION_1))
        put(o, 400, choose(registers, EMIT_REGISTER_OPTION_2, 0))
        argv(o, 0, LITERAL_ARG, 384)
        argv(o, 1, FD_ARG, get(w, selected))
        args = 2
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, OBJECT_EXPORT_SUFFIX)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 5)
    count = wide_inspection(o, w, EMIT_OBJECT_PRODUCED, INSPECTION_EMIT_ROLE, args, 4, 1)
    put(o, 144, deadline)
    return count

def emit_product_observed(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    object = state == EMIT_OBJECT_PRODUCED
    if input_word(s, 24) == EMIT_EXPIRED:
        if input_word(s, 40) != 0 or length(s) != 64:
            return BAD
        return emit_admission_error(o, w, 8, choose(object, 7, 6))
    if input_word(s, 24) != 0 or length(s) != 128 or input_word(s, 40) < 64:
        return BAD
    if (input_word(s, 64) & EMIT_IDENT_MASK) != EMIT_IDENT:
        return BAD
    if (input_word(s, 80) & 4294967295) != choose(object, EMIT_ELF_OBJECT, EMIT_ELF_SHARED):
        return BAD
    slot = choose(object, EMIT_OBJECT, EMIT_IMAGE)
    sample_span(s, w, slot)
    if object and get(w, EMIT_OUTPUT_KIND) == 1:
        move_fragment(w, EMIT_OBJECT, EMIT_IMAGE)
    return inspection_hash(o, w, choose(object, EMIT_OBJECT_HASHED, EMIT_IMAGE_HASHED), slot)

def emit_hash_capture(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    resume = get(w, INSPECTION_HASH_RESUME)
    if resume == EMIT_RECORD_HASHED:
        return emit_record_hash(s, o, w, at)
    if (resume >= EMIT_MEASURE_CORE_HASH and resume <= EMIT_MEASURE_LINK_HASH) or resume == EMIT_MEASURE_SCALAR_HASH:
        return emit_measurement_hash(s, o, w, at, resume)
    if resume != EMIT_OBJECT_HASHED and resume != EMIT_IMAGE_HASHED:
        return emit_publication_hash(s, o, w, at, resume)
    object = resume == EMIT_OBJECT_HASHED
    span = choose(object, EMIT_OBJECT_DIGEST, EMIT_IMAGE_DIGEST)
    hold(w, span, input_word(s, 32), at - 64, 64)
    hold(w, choose(object, EMIT_OBJECT_QUOTED, EMIT_IMAGE_QUOTED), input_word(s, 32), at - 65, 66)
    if object:
        copy_span(s, w, at, EMIT_OBJECT_TEXT, 64)
        if get(w, EMIT_OUTPUT_KIND) == 1:
            move_fragment(w, EMIT_OBJECT_DIGEST, EMIT_IMAGE_DIGEST)
            move_fragment(w, EMIT_OBJECT_QUOTED, EMIT_IMAGE_QUOTED)
        return clock_sample(o, w, EMIT_OBJECT_TIME, 0)
    return inspection_feedback(o, w, 13, 0, EMIT_IMAGE_DIGEST)

def emit_product_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == EMIT_OBJECT_PRODUCED or state == EMIT_IMAGE_PRODUCED:
        return emit_product_observed(s, o, w, state)
    if state == INSPECTION_HASH_RETURNED:
        size = input_word(s, 40)
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state == EMIT_OBJECT_TIME:
        if length(s) != 72 or input_word(s, 40) != 8:
            return BAD
        sampled = input_word(s, 64)
        put(w, EMIT_OBJECT_FINISHED_AT, sampled)
        put(o, 400, EMIT_OBJECT_OBSERVED)
        put(o, 408, sampled)
        copy_private(w, o, EMIT_OBJECT_TEXT, 416, 64)
        hold(w, EMIT_PRODUCT_REPLY, INLINE_FRAGMENT, 400, 80)
        return inspection_feedback(o, w, 12, 0, EMIT_PRODUCT_REPLY)
    return BAD
'''


def producer_constants(constants):
    states = ('EMIT_OBJECT_PRODUCED', 'EMIT_IMAGE_PRODUCED', 'EMIT_OBJECT_HASHED',
              'EMIT_IMAGE_HASHED', 'EMIT_OBJECT_TIME')
    spans = ('EMIT_LAYOUT', 'EMIT_OBJECT', 'EMIT_IMAGE', 'EMIT_OBJECT_DIGEST',
             'EMIT_IMAGE_DIGEST', 'EMIT_PRODUCT_REPLY')
    words = {
        'EMIT_OBJECT_OBSERVED': b'HIAEMO01', 'EMIT_LAYOUT_OPTION_0': b'--planne',
        'EMIT_LAYOUT_OPTION_1': b'd-layout', 'EMIT_IDENT': b'\x7fELF\x02\x01\x01',
        'EMIT_REGISTER_OPTION_1': b'd-regist', 'EMIT_REGISTER_OPTION_2': b'ers',
        'STORE_HASH': b'store-ha', 'STORE_HASH_END': b'sh',
    }
    return {
        **{name: constants['EMIT_ADMISSION_REFUSED'] + 1 + i for i, name in enumerate(states)},
        **{name: 4688 + 24 * i for i, name in enumerate(spans)},
        **{name: int.from_bytes(value, 'little') for name, value in words.items()},
        'EMIT_OBJECT_TEXT': 4832, 'EMIT_EXPIRED': (1 << 64) - 110,
        'EMIT_OBJECT_FINISHED_AT': 4664, 'EMIT_LINK_LEASE': 60_000_000_000,
        'EMIT_IDENT_MASK': (1 << 56) - 1, 'EMIT_ELF_OBJECT': 0x003e0001,
        'EMIT_ELF_SHARED': 0x003e0003, 'INSPECTION_EMIT_ROLE': 47, 'EMIT_LINK_ROLE': 52,
    }


def bound_run_controls(controls):
    for control in controls:
        if control.startswith('\ndef issue('):
            control = control.replace(
                'seq > 4096', 'seq > EMIT_EFFECT_LIMIT',
            ).replace(
                '    put(o, 136, 0)',
                '    put(o, 136, 0)\n    if op == RUN:\n        put(o, 184, 0)\n        put(o, 144, 0)',
            )
        yield control


def producer_controls(controls):
    yield from bound_run_controls(controls)
    yield function(worker.VIEW_DRIVER, 'inspection_hash')
    yield function(worker.VIEW_DRIVER, 'inspection_hash_result').replace('inspection_hash_bound(', 'emit_hash_capture(')


ENTRY = r'''
def emit_product_flow(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    state = get(w, 0)
    if state == INSPECTION_ACTION:
        stage = get(w, EMIT_STAGE)
        operand = get(w, EMIT_OPERAND)
        if stage == 12 or stage == 13:
            return emit_product(o, w, stage, operand)
        return emit_finish_build(o, w, stage)
    if state == PEER_ADMITTED or state == PEER_CLOSED or state == STORE_SETTLED:
        return emit_publication_store(s, o, w, state)
    if state >= EMIT_PUB_QUERY and state <= EMIT_PUB_COMPARE:
        return emit_publication_state(s, o, w, state)
    if state >= EMIT_OBJECT_META_BOUND and state <= EMIT_RESULT_BOUND:
        return emit_record_state(s, o, w, state)
    if state == EMIT_BUILD_FACTS_BOUND or (state >= EMIT_MEASURE_LITERALS and state <= EMIT_MEASURE_CHECKED):
        return emit_measurement_state(s, o, w, state)
    if state == EMIT_MEASURE_CUSTODY_TAIL or state == EMIT_MEASURE_CUSTODY:
        return emit_custody_state(s, o, w, state)
    if state >= EMIT_SCALAR_NONCE and state <= EMIT_SCALAR_SNAPSHOT:
        return emit_scalar_state(s, o, w, state)
    return emit_product_state(s, o, w, state)
'''


def product_recipe(constants, shared_error):
    """Collect only the common descriptor operations used by the product port."""
    _, controls = worker.recipe()
    names = ('action', 'issue', 'get', 'put', 'write', 'input_word', 'argv', 'fragment', 'use_span',
             'sample_span', 'hold', 'body_span', 'read_span', 'is_hex', 'copy_span',
             'copy_private', 'zero_range', 'vector_part', 'clock_sample', 'artifact_command',
             'open_store', 'close_store', 'store_transaction', 'whole_slot', 'slot_fd', 'slot_bytes', 'plan_ok')
    required = {f'\ndef {name}(' for name in names}
    used = tuple(control for control in controls if control.split('(', 1)[0] + '(' in required)
    helpers = (
        function(worker.RETAINED_DRIVER, 'move_fragment'),
        function(worker.EFFECT_DRIVER, 'inspection_feedback'),
        function(worker.DOCUMENT_DRIVER, 'vector_span'),
        function(worker.DOCUMENT_DRIVER, 'wide_inspection'),
        function(release_policy, 'decimal'),
        function(release_policy, 'divide10'),
        shared_error,
    )
    return ENTRY, (PRODUCTION, PUBLICATION, RECORD, SCALAR, render_functions(), measurement_source(),
                   *producer_controls(used), *helpers)
