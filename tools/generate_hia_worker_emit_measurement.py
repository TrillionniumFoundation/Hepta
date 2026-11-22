"""Author independent measurement of Emit producer output."""


MEASUREMENT = r'''
def emit_measure_products(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_IMAGE + 16) < 64 or get(w, EMIT_OBJECT + 16) < 64:
        return BAD
    # Keep literals and lengths in a sealed descriptor, not a subsequent
    # command's inline area, which the carrier is free to overwrite.
    put(o, HEADER, EMIT_LITERALS)
    put(o, HEADER + 8, choose(get(w, EMIT_OUTPUT_KIND) == 1, EMIT_KIND_OBJECT, EMIT_KIND_SHARED))
    end = decimal(o, HEADER + 16, get(w, EMIT_IMAGE + 16))
    return action(o, w, EMIT_MEASURE_LITERALS, MAKE, 0, 0, 0, end - HEADER)

def emit_measured_names(o:mutbuf, w:mutbuf) -> u64:
    store(o, HEADER, 91)
    store(o, 480, 44)
    put(o, 488, EMIT_NAMES_SUFFIX)
    vector_span(w, o, INSPECTION_CORE, HEADER + 1)
    vector_part(o, HEADER + 25, INLINE_FRAGMENT, 480, 1)
    vector_span(w, o, INSPECTION_EXPORTS, HEADER + 49)
    vector_part(o, HEADER + 73, INLINE_FRAGMENT, 488, 5)
    return wide_inspection(o, w, EMIT_MEASURE_NAMES, EMIT_SIGNATURE_ROLE, 0, 4, 1)

def emit_measure_object(o:mutbuf, w:mutbuf, state:u64, role:u64) -> u64:
    format = get(w, EMIT_LAYOUT_FORMAT)
    if format >= 2 and format <= 4:
        put(o, HEADER, EMIT_LAYOUT_OBSERVATION)
        put(o, HEADER + 8, get(w, EMIT_LAYOUT + 16))
        use_span(w, o, EMIT_LAYOUT, 0)
        use_span(w, o, EMIT_OBJECT, 1)
        return action(o, w, state, RUN, role, 0, 2, 16)
    use_span(w, o, EMIT_OBJECT, 0)
    return action(o, w, state, RUN, role, 0, 1, 0)

def emit_measure_shared(o:mutbuf, w:mutbuf) -> u64:
    put(o, HEADER, get(w, EMIT_EXPECTED_NAMES + 16) + 8)
    fragment(o, 0, get(w, EMIT_EXPECTED_NAMES), get(w, EMIT_EXPECTED_NAMES + 8) - 8,
             get(w, EMIT_EXPECTED_NAMES + 16) + 8)
    use_span(w, o, EMIT_IMAGE, 1)
    count = action(o, w, EMIT_MEASURE_SHARED_MASK, RUN, EMIT_SHARED_INVENTORY_ROLE, 0, 2, 8)
    put(o, 168, 6)
    return count

def emit_measurement_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    fd = input_word(s, 32)
    size = input_word(s, 40)
    if state == EMIT_MEASURE_LITERALS:
        if size < 17 or size > 36:
            return BAD
        hold(w, EMIT_PLAN_JSON, fd, 0, 4)
        hold(w, EMIT_PLAN_DIGEST, fd, 0, 4)
        hold(w, EMIT_EMPTY_METADATA, fd, 4, 2)
        hold(w, EMIT_TOOLCHAIN, fd, 0, 4)
        hold(w, EMIT_BUILD_KIND, fd, 8, 8)
        hold(w, EMIT_IMAGE_DECIMAL, fd, 16, size - 16)
        if get(w, EMIT_CODEGEN_KIND) == 2:
            if get(w, EMIT_CANONICAL_PLAN + 16) == 0 or get(w, EMIT_CANONICAL_PLAN_SHA + 16) != 66:
                return BAD
            move_fragment(w, EMIT_CANONICAL_PLAN, EMIT_PLAN_JSON)
            move_fragment(w, EMIT_CANONICAL_PLAN_SHA, EMIT_PLAN_DIGEST)
        return inspection_hash(o, w, EMIT_MEASURE_CORE_HASH, INSPECTION_CORE)
    if state == EMIT_MEASURE_NAMES:
        if plan_ok(s) == False or size < 20 or input_word(s, 72) != EMIT_NAMES_FACTS:
            return BAD
        hold(w, EMIT_EXPECTED_NAMES, fd, 16, size - 16)
        return emit_measure_object(o, w, EMIT_MEASURE_OBJECT_INVENTORY, EMIT_OBJECT_INVENTORY_ROLE)
    if state == EMIT_MEASURE_OBJECT_INVENTORY:
        names = get(w, EMIT_EXPECTED_NAMES + 16)
        if plan_ok(s) == False or size <= 19 + names or names > 1048576:
            return BAD
        body_span(s, w, EMIT_INVENTORY)
        put(o, HEADER, EMIT_COMPARE_REQUEST)
        put(o, HEADER + 8, names)
        put(o, HEADER + 16, names)
        use_span(w, o, EMIT_EXPECTED_NAMES, 0)
        fragment(o, 1, fd, 19, names)
        return action(o, w, EMIT_MEASURE_MATCHED_NAMES, RUN, EMIT_NATIVE_ARTIFACT_ROLE, 0, 2, 24)
    if state == EMIT_MEASURE_MATCHED_NAMES:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != EMIT_COMPARE_RESULT or input_word(s, 80) != 1:
            return BAD
        if get(w, EMIT_OUTPUT_KIND) == 2:
            return emit_measure_shared(o, w)
        return emit_measure_object(o, w, EMIT_MEASURE_GEOMETRY, EMIT_GEOMETRY_ROLE)
    if state == EMIT_MEASURE_SHARED_MASK:
        if size != 8:
            return BAD
        put(o, HEADER, EMIT_BORROWED_REPORT)
        put(o, HEADER + 8, 3)
        fragment(o, 0, fd, 0, 8)
        return action(o, w, EMIT_MEASURE_SHARED_IMPORTS, RUN, EMIT_BORROWED_REPORT_ROLE, 0, 1, 16)
    if state == EMIT_MEASURE_SHARED_IMPORTS:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_SHARED_IMPORTS)
        put(w, EMIT_RENDER_FIELDS, EMIT_EXPECTED_NAMES)
        put(w, EMIT_RENDER_FIELDS + 8, EMIT_SHARED_IMPORTS)
        return emit_borrowed_render(o, w, 2, EMIT_MEASURE_SHARED_INVENTORY, 2)
    if state == EMIT_MEASURE_SHARED_INVENTORY:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_INVENTORY)
        return emit_measure_object(o, w, EMIT_MEASURE_GEOMETRY, EMIT_GEOMETRY_ROLE)
    if state == EMIT_MEASURE_GEOMETRY:
        return emit_measure_geometry(s, o, w)
    if state == EMIT_MEASURE_FRAME_CONTROL:
        if size != 9480 or plan_ok(s) == False:
            return BAD
        fragment(o, 0, fd, 8, 9472)
        use_span(w, o, INSPECTION_CORE, 1)
        return action(o, w, EMIT_MEASURE_FRAMES, RUN, EMIT_FRAMES_ROLE, 0, 2, 0)
    if state == EMIT_MEASURE_FRAMES:
        if plan_ok(s) == False or size < 10:
            return BAD
        put(o, HEADER, get(w, 24))
        fragment(o, 0, fd, 8, size - 8)
        return action(o, w, EMIT_MEASURE_CANONICAL, RUN, EMIT_CANONICAL_ROLE, 0, 1, 8)
    if state == EMIT_MEASURE_CANONICAL:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_CANONICAL_FRAMES)
        end = decimal(o, HEADER, get(w, EMIT_TEXT_SPAN + 16))
        return action(o, w, EMIT_MEASURE_TEXT_LENGTH, MAKE, 0, 0, 0, end - HEADER)
    if state == EMIT_MEASURE_TEXT_LENGTH:
        if size == 0 or size > 20:
            return BAD
        sample_span(s, w, EMIT_TEXT_LENGTH)
        return inspection_hash(o, w, EMIT_MEASURE_TEXT_HASH, EMIT_TEXT_SPAN)
    if state == EMIT_MEASURE_TOOLCHAIN_JSON:
        if size < 130 or size > 220:
            return BAD
        sample_span(s, w, EMIT_TOOLCHAIN)
        return emit_borrowed_report(o, w)
    if state == EMIT_MEASURE_REPORT:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_PRODUCT_REPORT)
        return emit_measurement_list(o, w)
    if state == EMIT_MEASURE_LIST:
        if size < 12:
            return BAD
        sample_span(s, w, EMIT_MEASUREMENTS)
        return emit_render_facts(o, w)
    if state == EMIT_BUILD_FACTS_BOUND:
        if plan_ok(s) == False or size < 10:
            return BAD
        body_span(s, w, EMIT_MEASURE_FACTS)
        if get(w, INSPECTION_EXPORTS + 16) == 2:
            return emit_send_scalar_facts(o, w)
        return emit_send_facts(o, w)
    if state == EMIT_MEASURE_CHECKED:
        if plan_ok(s) == False or size != 24 or input_word(s, 72) != EMIT_OBSERVED or input_word(s, 80) != 0:
            return BAD
        body_span(s, w, EMIT_PRODUCT_REPLY)
        return inspection_feedback(o, w, 14, 0, EMIT_PRODUCT_REPLY)
    return BAD

def emit_measure_geometry(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = input_word(s, 40)
    if plan_ok(s) == False or size < 48 or size > 8232 or input_word(s, 72) != EMIT_GEOMETRY:
        return BAD
    at = input_word(s, 80)
    extent = input_word(s, 88)
    entries = input_word(s, 96)
    object_size = get(w, EMIT_OBJECT + 16)
    if entries > 1024 or size != 40 + 8 * entries or at > object_size or extent > object_size - at or extent == 0:
        return BAD
    hold(w, EMIT_TEXT_SPAN, get(w, EMIT_OBJECT), get(w, EMIT_OBJECT + 8) + at, extent)
    put(o, HEADER, EMIT_FRAME_PADDING)
    fragment(o, 0, input_word(s, 32), 8, size - 8)
    return action(o, w, EMIT_MEASURE_FRAME_CONTROL, RUN, INSPECTION_REQUEST_ROLE, 0, 1, 8)

def emit_measurement_hash(s:readbuf, o:mutbuf, w:mutbuf, at:u64, state:u64) -> u64:
    fd = input_word(s, 32)
    if state == EMIT_MEASURE_CORE_HASH:
        hold(w, EMIT_CORE_QUOTED, fd, at - 65, 66)
        source = choose(get(w, EMIT_PROFILE_LEVEL) != 0, INSPECTION_STRUCTURED, INSPECTION_CORE)
        return inspection_hash(o, w, EMIT_MEASURE_INPUT_HASH, source)
    if state == EMIT_MEASURE_INPUT_HASH:
        hold(w, EMIT_INPUT_QUOTED, fd, at - 65, 66)
        if get(w, INSPECTION_EXPORTS + 16) == 2:
            return emit_scalar_implementation(o, w)
        return inspection_hash(o, w, EMIT_MEASURE_IMPL_HASH, EMIT_BORROWED_EXE)
    if state == EMIT_MEASURE_IMPL_HASH:
        hold(w, EMIT_IMPL_QUOTED, fd, at - 65, 66)
        return emit_measured_names(o, w)
    if state == EMIT_MEASURE_SCALAR_HASH:
        hold(w, EMIT_IMPL_QUOTED, fd, at - 65, 66)
        return emit_render_facts(o, w)
    if state == EMIT_MEASURE_TEXT_HASH:
        hold(w, EMIT_TEXT_QUOTED, fd, at - 65, 66)
        if get(w, EMIT_OUTPUT_KIND) == 2:
            return inspection_hash(o, w, EMIT_MEASURE_LINK_HASH, EMIT_LINK_EXE)
        return emit_borrowed_report(o, w)
    if state == EMIT_MEASURE_LINK_HASH:
        hold(w, EMIT_LINK_QUOTED, fd, at - 65, 66)
        return emit_measure_toolchain(o, w)
    return BAD

def emit_borrowed_render(o:mutbuf, w:mutbuf, kind:u64, state:u64, fields:u64) -> u64:
    return emit_render_arguments(o, w, EMIT_BORROWED_REPORT, EMIT_BORROWED_REPORT_ROLE, kind, state, fields)

def emit_measure_toolchain(o:mutbuf, w:mutbuf) -> u64:
    EMIT_TOOLCHAIN_PREFIX
    EMIT_TOOLCHAIN_SUFFIX
    use_span(w, o, EMIT_LINK_QUOTED, 0)
    fragment(o, 1, INLINE_FRAGMENT, 384, EMIT_TOOLCHAIN_SUFFIX_BYTES)
    return action(o, w, EMIT_MEASURE_TOOLCHAIN_JSON, MAKE, 0, 0, 2, EMIT_TOOLCHAIN_PREFIX_BYTES)

def emit_wide_make(o:mutbuf, w:mutbuf, state:u64, parts:u64, lead:u64) -> u64:
    total = action(o, w, state, MAKE, 0, 0, parts, lead)
    if total == BAD:
        return BAD
    put(o, 136, 1)
    return total + 24 * parts

def emit_confirm_custody(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_ARTIFACT_BYTES + 16) != get(w, EMIT_OBJECT + 16):
        return BAD
    if get(w, EMIT_ARTIFACT_BYTES + 40) != get(w, EMIT_IMAGE + 16):
        return BAD
    if get(w, EMIT_CODEGEN_KIND) == 2:
        return emit_custody_tail_planned(o, w)
    return emit_custody_tail(o, w)

def emit_custody_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    size = input_word(s, 40)
    if state == EMIT_MEASURE_CUSTODY_TAIL:
        if size < 280:
            return BAD
        sample_span(s, w, EMIT_CUSTODY_NESTED)
        return emit_custody_bundle(o, w)
    if (plan_ok(s) == False or size != 32 or input_word(s, 72) != EMIT_CUSTODY_PACKET
            or input_word(s, 80) != 0 or input_word(s, 88) != 2):
        return BAD
    return inspection_feedback(o, w, 18, 0, EMIT_PUB_RECEIPT)
'''


def measurement_constants(constants):
    states = (
        'LITERALS', 'NAMES', 'OBJECT_INVENTORY', 'MATCHED_NAMES', 'SHARED_MASK',
        'SHARED_IMPORTS', 'SHARED_INVENTORY', 'GEOMETRY', 'FRAME_CONTROL', 'FRAMES',
        'CANONICAL', 'TEXT_LENGTH', 'TOOLCHAIN_JSON', 'REPORT', 'LIST', 'CHECKED',
        'CORE_HASH', 'INPUT_HASH', 'IMPL_HASH', 'TEXT_HASH', 'LINK_HASH', 'CUSTODY_TAIL', 'CUSTODY',
    )
    spans = (
        'BORROWED_EXE', 'LINK_EXE', 'EXPECTED_NAMES', 'INVENTORY', 'SHARED_IMPORTS',
        'TEXT_SPAN', 'CANONICAL_FRAMES', 'TEXT_LENGTH', 'TEXT_QUOTED', 'LINK_QUOTED',
        'TOOLCHAIN', 'MEASUREMENTS', 'MEASURE_FACTS', 'CUSTODY_NESTED',
        'CANONICAL_PLAN', 'CANONICAL_PLAN_SHA', 'PHYSICAL_PLAN_SHA',
    )
    words = {
        'EMIT_LITERALS': b'null{}\0\0', 'EMIT_KIND_OBJECT': b'"object"', 'EMIT_KIND_SHARED': b'"shared"',
        'EMIT_NAMES_SUFFIX': b',0,4]', 'EMIT_NAMES_FACTS': b'HIASEN01', 'EMIT_GEOMETRY': b'HIAILF01',
        'EMIT_LAYOUT_OBSERVATION': b'HIAILP02', 'EMIT_FRAME_PADDING': b'HIAERP01',
        'EMIT_BORROWED_REPORT': b'HIAWBR01', 'EMIT_OBSERVED': b'HIABOR01', 'EMIT_CUSTODY_PACKET': b'HIABCO01',
        'EMIT_TRUE': b'true', 'EMIT_FALSE': b'false',
    }
    return {
        **{f'EMIT_MEASURE_{name}': constants['EMIT_BUILD_FACTS_BOUND'] + 1 + i for i, name in enumerate(states)},
        **{f'EMIT_{name}': 6144 + 24 * i for i, name in enumerate(spans)},
        **{name: int.from_bytes(value, 'little') for name, value in words.items()},
        'EMIT_LAYOUT_FORMAT': 6552, 'EMIT_GEOMETRY_ROLE': 48, 'EMIT_FRAMES_ROLE': 49,
        'EMIT_CANONICAL_ROLE': 50, 'EMIT_OBJECT_INVENTORY_ROLE': 51,
        'EMIT_SHARED_INVENTORY_ROLE': 53, 'EMIT_BORROWED_REPORT_ROLE': 54,
        'EMIT_OBSERVER_ROLE': 36, 'EMIT_CUSTODY_ROLE': 43,
    }


def literal_words(offset, value):
    return '\n'.join(f'put(o, {offset + i}, {int.from_bytes(value[i:i + 8], "little")})'
                     for i in range(0, len(value), 8))


def splice_list(name, state, fields, *, prefix=b'[', suffix=b']', role=None):
    """Emit the exact JSON punctuation between already-sealed value spans."""
    lines = [f'def {name}(o:mutbuf, w:mutbuf) -> u64:',
             '    ' + literal_words(384, b','), '    ' + literal_words(512, prefix)]
    lines += [
        '    put(o, 392, choose(get(w, EMIT_OUTPUT_KIND) == 1, EMIT_TRUE, EMIT_FALSE))',
        '    ' + literal_words(400, suffix),
    ]
    parts = []
    for index, slot in enumerate(fields):
        if index:
            parts.append('vector_part(o, {at}, INLINE_FRAGMENT, 384, 1)')
        if slot == 'EQUALITY':
            parts.append('vector_part(o, {at}, INLINE_FRAGMENT, 392, choose(get(w, EMIT_OUTPUT_KIND) == 1, 4, 5))')
        elif isinstance(slot, tuple):
            descriptor, offset, size = slot
            parts.append(f'vector_part(o, {{at}}, get(w, {descriptor}), {offset}, {size})')
        else:
            parts.append(f'vector_span(w, o, {slot}, {{at}})')
    if suffix:
        parts.append(f'vector_part(o, {{at}}, INLINE_FRAGMENT, 400, {len(suffix)})')
    for index, part in enumerate(parts):
        lines.append('    ' + part.format(at=f'HEADER + {len(prefix) + 24 * index}'))
    if role is None:
        lines.append(f'    return emit_wide_make(o, w, {state}, {len(parts)}, {len(prefix)})')
    else:
        lines.append(f'    return wide_inspection(o, w, {state}, {role}, 0, {len(parts)}, {len(prefix)})')
    return '\n' + '\n'.join(lines) + '\n'


def measurement_source():
    prefix = (b'{"default_target":"elf_x86_64","mode":"hia","path":null,'
              b'"role":"link_generated_object_only","sha256":')
    suffix = b',"version":"hia-elf-shared-linker.v1"}'
    source = MEASUREMENT.replace(
        'EMIT_TOOLCHAIN_PREFIX_BYTES', str(len(prefix)),
    ).replace('EMIT_TOOLCHAIN_SUFFIX_BYTES', str(len(suffix))).replace(
        '    EMIT_TOOLCHAIN_PREFIX', '    ' + literal_words(512, prefix).replace('\n', '\n    '),
    ).replace('    EMIT_TOOLCHAIN_SUFFIX', '    ' + literal_words(384, suffix).replace('\n', '\n    '))
    fields = ('EMIT_IMAGE_DECIMAL', 'EMIT_IMAGE_QUOTED', 'EMIT_INVENTORY', 'EMIT_CORE_QUOTED',
              'EMIT_EXPECTED_NAMES', 'INSPECTION_EXPORTS', 'EMIT_CANONICAL_FRAMES', 'EMIT_IMPL_QUOTED',
              'EMIT_INPUT_QUOTED', 'EMIT_BUILD_KIND', 'EMIT_PLAN_DIGEST', 'EMIT_TEXT_LENGTH',
              'EMIT_TEXT_QUOTED', 'EMIT_OBJECT_QUOTED', 'EMIT_TOOLCHAIN')
    source += '\ndef emit_borrowed_report(o:mutbuf, w:mutbuf) -> u64:\n'
    source += ''.join(f'    put(w, EMIT_RENDER_FIELDS + {i * 8}, {slot})\n' for i, slot in enumerate(fields))
    source += '    return emit_borrowed_render(o, w, 1, EMIT_MEASURE_REPORT, 15)\n'
    tail = ('EMIT_CORE_QUOTED', 'EMIT_INPUT_QUOTED', 'EMIT_SIGNATURES', 'INSPECTION_EXPORTS',
            'EMIT_OBJECT_QUOTED', 'EMIT_IMAGE_QUOTED', 'EMIT_IMAGE_DECIMAL', 'EQUALITY')
    source += splice_list('emit_custody_tail', 'EMIT_MEASURE_CUSTODY_TAIL', tail, suffix=b']]')
    source += splice_list('emit_custody_tail_planned', 'EMIT_MEASURE_CUSTODY_TAIL',
                          (*tail, 'EMIT_PLAN_JSON', 'EMIT_PHYSICAL_PLAN_SHA', 'EMIT_PLAN_DIGEST'), suffix=b']]')
    source += splice_list('emit_custody_bundle', 'EMIT_MEASURE_CUSTODY',
                          ('EMIT_INSTALLATION', 'EMIT_IMPL_QUOTED', 'EMIT_FIELDS + 24', 'EMIT_FIELDS',
                           'EMIT_PROFILES + 240', 'EMIT_ARTIFACT_REFS + 24', 'EMIT_ARTIFACT_BYTES + 48',
                           'EMIT_NATIVE_METADATA', 'EMIT_OBJECT_METADATA', 'EMIT_CUSTODY_NESTED'),
                          suffix=b'', role='EMIT_CUSTODY_ROLE')
    source += splice_list('emit_measurement_list', 'EMIT_MEASURE_LIST',
                          ('EMIT_INVENTORY', 'EMIT_EXPECTED_NAMES', 'EMIT_CANONICAL_FRAMES',
                           'EMIT_TEXT_LENGTH', 'EMIT_TEXT_QUOTED', 'EMIT_TOOLCHAIN'))
    source += splice_list('emit_send_facts', 'EMIT_MEASURE_CHECKED',
                          ('EMIT_MEASURE_FACTS', 'EMIT_PRODUCT_REPORT', 'EMIT_MEASUREMENTS'),
                          role='EMIT_OBSERVER_ROLE')
    source += splice_list('emit_send_scalar_facts', 'EMIT_MEASURE_CHECKED',
                          ('EMIT_MEASURE_FACTS', 'EMIT_PRODUCT_REPORT'), role='EMIT_OBSERVER_ROLE')
    return source
