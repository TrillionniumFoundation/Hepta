"""Author Emit receipt materialization from held, checked descriptors."""


RECORD = r'''
def emit_finish_build(o:mutbuf, w:mutbuf, stage:u64) -> u64:
    if stage == 14:
        return emit_measure_products(o, w)
    if stage == 15:
        return emit_object_metadata(o, w)
    if stage == 16:
        return emit_signature(o, w)
    if stage == 17:
        return emit_retained_report(o, w)
    if stage == 18:
        return emit_publish(o, w, 14, EMIT_BUILD_RECORD, EMIT_EMPTY_METADATA)
    if stage == 19:
        return emit_render_result(o, w)
    return BAD

def emit_render(o:mutbuf, w:mutbuf, kind:u64, state:u64, fields:u64) -> u64:
    return emit_render_arguments(o, w, EMIT_RENDER_REQUEST, EMIT_RECEIPT_ROLE, kind, state, fields)

def emit_render_arguments(o:mutbuf, w:mutbuf, tag:u64, role:u64, kind:u64, state:u64, fields:u64) -> u64:
    if fields == 0 or fields > 16:
        return BAD
    put(o, HEADER, tag)
    put(o, HEADER + 8, kind)
    i = 0
    while i < fields:
        slot = get(w, EMIT_RENDER_FIELDS + 8 * i)
        length_at = 384 + 8 * i
        descriptor_at = HEADER + 16 + 48 * i
        size = get(w, slot + 16)
        if size == 0 or size > 4194304:
            return BAD
        put(o, length_at, size)
        vector_part(o, descriptor_at, INLINE_FRAGMENT, length_at, 8)
        vector_span(w, o, slot, descriptor_at + 24)
        i = i + 1
    return wide_inspection(o, w, state, role, 0, fields * 2, 16)

def emit_signature(o:mutbuf, w:mutbuf) -> u64:
    level = get(w, EMIT_PROFILE_LEVEL)
    if level > 4:
        return BAD
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, EMIT_SIGNATURE_SUFFIX)
    store(o, 489, 48 + level)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 5)
    return wide_inspection(o, w, EMIT_SIGNATURE_BOUND, EMIT_SIGNATURE_ROLE, 0, 4, 1)

def emit_retained_report(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, EMIT_BORROWED_REPORT_SUFFIX)
    store(o, 499, 93)
    borrowed = get(w, INSPECTION_EXPORTS + 16) > 2
    vector_span(w, o, EMIT_ARTIFACT_REFS, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, EMIT_PRODUCT_REPORT, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, choose(borrowed, 488, 499), choose(borrowed, 3, 1))
    return wide_inspection(o, w, EMIT_RETAINED_REPORT_BOUND, EMIT_RETAINED_REPORT_ROLE, 0, 4, 1)

def emit_record_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if plan_ok(s) == False or input_word(s, 40) < 10:
        return BAD
    if state == EMIT_OBJECT_META_BOUND:
        body_span(s, w, EMIT_OBJECT_METADATA)
        return emit_publish(o, w, 12, EMIT_OBJECT, EMIT_OBJECT_METADATA)
    if state == EMIT_SIGNATURE_BOUND:
        body_span(s, w, EMIT_SIGNATURES)
        return emit_native_metadata(o, w)
    if state == EMIT_NATIVE_META_BOUND:
        body_span(s, w, EMIT_NATIVE_METADATA)
        return emit_publish(o, w, 13, EMIT_IMAGE, EMIT_NATIVE_METADATA)
    if state == EMIT_RETAINED_REPORT_BOUND:
        body_span(s, w, EMIT_RETAINED_REPORT)
        return emit_render_record(o, w)
    if state == EMIT_RECORD_BOUND:
        body_span(s, w, EMIT_BUILD_RECORD)
        return inspection_hash(o, w, EMIT_RECORD_HASHED, EMIT_BUILD_RECORD)
    if state == EMIT_RESULT_BOUND:
        body_span(s, w, EMIT_BUILD_RESULT)
        return inspection_feedback(o, w, 19, 0, EMIT_BUILD_RESULT)
    return BAD

def emit_record_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    hold(w, EMIT_PRODUCT_REPLY, input_word(s, 32), at - 64, 64)
    return inspection_feedback(o, w, 17, 0, EMIT_PRODUCT_REPLY)
'''


def render_functions():
    codegen = 'EMIT_FIELDS + 24 * (4 + get(w, EMIT_RECEIPT_COUNT))'
    context = 'EMIT_FIELDS + 24'
    candidate = 'EMIT_FIELDS + 48'
    receipts = 'EMIT_FIELDS + 72'
    native = 'EMIT_ARTIFACT_REFS + 24'
    receipt = 'EMIT_ARTIFACT_REFS + 48'
    target = 'EMIT_PROFILES + 240'
    layouts = (
        ('emit_object_metadata', '1', 'EMIT_OBJECT_META_BOUND',
         ('EMIT_CORE_QUOTED', 'EMIT_INSTALLATION', 'EMIT_PLAN_DIGEST')),
        ('emit_native_metadata', '2', 'EMIT_NATIVE_META_BOUND',
         (candidate, codegen, context, 'EMIT_CORE_QUOTED', 'INSPECTION_EXPORTS', 'EMIT_INSTALLATION',
          'EMIT_PLAN_JSON', 'EMIT_ARTIFACT_REFS', 'EMIT_OBJECT_QUOTED', 'EMIT_BUILD_KIND', 'EMIT_SIGNATURES')),
        ('emit_render_record', '3', 'EMIT_RECORD_BOUND',
         ('EMIT_FIELDS', candidate, codegen, context, 'EMIT_CORE_QUOTED', 'INSPECTION_EXPORTS',
          'EMIT_INSTALLATION', 'EMIT_PLAN_JSON', native, 'EMIT_RETAINED_REPORT',
          'EMIT_ARTIFACT_REFS', 'EMIT_OBJECT_QUOTED', 'EMIT_BUILD_KIND', 'EMIT_SIGNATURES', target, receipts)),
        ('emit_render_result', 'choose(get(w, EMIT_OUTPUT_KIND) == 2, 5, 4)', 'EMIT_RESULT_BOUND',
         ('EMIT_FIELDS', receipt, candidate, native, target)),
        ('emit_render_facts', '6', 'EMIT_BUILD_FACTS_BOUND',
         ('EMIT_IMAGE_DECIMAL', 'EMIT_IMAGE_QUOTED', 'EMIT_CORE_QUOTED', 'INSPECTION_EXPORTS',
          'EMIT_IMPL_QUOTED', 'EMIT_INPUT_QUOTED', 'EMIT_BUILD_KIND', 'EMIT_PLAN_DIGEST', 'EMIT_OBJECT_QUOTED')),
    )
    source = []
    for name, kind, state, fields in layouts:
        source.append(f'\ndef {name}(o:mutbuf, w:mutbuf) -> u64:')
        for index, slot in enumerate(fields):
            source.append(f'    put(w, EMIT_RENDER_FIELDS + {index * 8}, {slot})')
        source.append(f'    return emit_render(o, w, {kind}, {state}, {len(fields)})')
    return '\n'.join(source) + '\n'


def record_constants(constants):
    states = (
        'EMIT_OBJECT_META_BOUND', 'EMIT_SIGNATURE_BOUND', 'EMIT_NATIVE_META_BOUND', 'EMIT_RETAINED_REPORT_BOUND',
        'EMIT_RECORD_BOUND', 'EMIT_RESULT_BOUND', 'EMIT_RECORD_HASHED', 'EMIT_BUILD_FACTS_BOUND',
    )
    spans = (
        'EMIT_CORE_QUOTED', 'EMIT_INSTALLATION', 'EMIT_PLAN_DIGEST', 'EMIT_PLAN_JSON',
        'EMIT_OBJECT_QUOTED', 'EMIT_IMAGE_QUOTED', 'EMIT_BUILD_KIND', 'EMIT_EMPTY_METADATA',
        'EMIT_SIGNATURES', 'EMIT_OBJECT_METADATA', 'EMIT_NATIVE_METADATA', 'EMIT_PRODUCT_REPORT',
        'EMIT_RETAINED_REPORT', 'EMIT_BUILD_RECORD', 'EMIT_BUILD_RESULT', 'EMIT_IMAGE_DECIMAL',
        'EMIT_IMPL_QUOTED', 'EMIT_INPUT_QUOTED',
    )
    words = {
        'EMIT_RENDER_REQUEST': b'HIAERR01', 'EMIT_SIGNATURE_SUFFIX': b',0,3]',
        'EMIT_BORROWED_REPORT_SUFFIX': b',1]',
    }
    return {
        **{name: constants['EMIT_PUB_HASHED_METADATA'] + 1 + i for i, name in enumerate(states)},
        **{name: 5552 + i * 24 for i, name in enumerate(spans)},
        **{name: int.from_bytes(value, 'little') for name, value in words.items()},
        'EMIT_RENDER_FIELDS': 6000, 'EMIT_SIGNATURE_ROLE': 40, 'EMIT_RECEIPT_ROLE': 35,
        'EMIT_RETAINED_REPORT_ROLE': 41,
    }
