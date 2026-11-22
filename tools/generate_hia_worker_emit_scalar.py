"""Author the scalar Emit producer, with the same absolute physical deadline."""


SCALAR = r'''
def emit_scalar_product(o:mutbuf, w:mutbuf, stage:u64, deadline:u64) -> u64:
    if stage != 12 and (stage != 13 or get(w, EMIT_OUTPUT_KIND) != 2 or get(w, EMIT_OBJECT + 16) < 64):
        return BAD
    if deadline == 0 or get(w, INSPECTION_CORE + 16) == 0:
        return BAD
    put(w, EMIT_SCALAR_STAGE, stage)
    put(w, EMIT_SCALAR_DEADLINE, deadline)
    count = action(o, w, EMIT_SCALAR_NONCE, RANDOM, 0, 0, 0, 0)
    put(o, 144, 16)
    return count

def emit_scalar_scratch(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) != 80 or input_word(s, 40) != 16:
        return BAD
    put(o, HEADER, EMIT_SCRATCH_PREFIX)
    i = 0
    while i < 16:
        part = byte(s, 64 + i)
        store(o, HEADER + 6 + 2 * i, emit_hex_byte(part >> 4))
        store(o, HEADER + 7 + 2 * i, emit_hex_byte(part & 15))
        i = i + 1
    store(o, HEADER + 38, 0)
    put(o, HEADER + 39, EMIT_PROGRAM_STEM)
    put(o, HEADER + 47, choose(get(w, EMIT_SCALAR_STAGE) == 12, 111, 28531))
    return action(o, w, EMIT_SCALAR_PREPARED, EMIT_PREPARE_PRODUCT, 0, 0, 0, 51)

def emit_hex_byte(value:u64) -> u64:
    return value + choose(value < 10, 48, 87)

def emit_scalar_build(o:mutbuf, w:mutbuf) -> u64:
    arguments = 1
    if get(w, EMIT_CODEGEN_KIND) == 2:
        if get(w, EMIT_LAYOUT_PERMIT + 8) != 0 or get(w, EMIT_LAYOUT_PERMIT + 16) < 168:
            return BAD
        put(o, 384, EMIT_LAYOUT_OPTION_0)
        put(o, 392, EMIT_LAYOUT_OPTION_1)
        store(o, 400, 0)
        argv(o, 0, LITERAL_ARG, 384)
        argv(o, 1, EMIT_HEX_FD_ARG, get(w, EMIT_LAYOUT_PERMIT))
        arguments = 3
    argv(o, arguments - 1, EMIT_PRODUCT_ARG, 0)
    input = choose(get(w, EMIT_PROFILE_LEVEL) != 0, INSPECTION_STRUCTURED, INSPECTION_CORE)
    if get(w, input + 16) == 0:
        return BAD
    use_span(w, o, input, 0)
    count = action(o, w, EMIT_SCALAR_REPORT_READY, RUN, EMIT_SCALAR_ROLE, arguments, 1, 0)
    put(o, 168, choose(get(w, EMIT_SCALAR_STAGE) == 12, 7, 8))
    put(o, 144, get(w, EMIT_SCALAR_DEADLINE))
    return count

def emit_scalar_state(s:readbuf, o:mutbuf, w:mutbuf, state:u64) -> u64:
    if state == EMIT_SCALAR_NONCE:
        return emit_scalar_scratch(s, o, w)
    if state == EMIT_SCALAR_PREPARED and length(s) == 64 and input_word(s, 40) == 0:
        return emit_scalar_build(o, w)
    if state == EMIT_SCALAR_REPORT_READY:
        size = input_word(s, 40)
        if input_word(s, 24) == EMIT_EXPIRED and size == 0 and length(s) == 64:
            return action(o, w, EMIT_SCALAR_EXPIRED, EMIT_DISCARD_PRODUCT, 0, 0, 0, 0)
        if input_word(s, 24) != 0 or size < 16 or size > 4194304 or byte(s, 64) != 123:
            return BAD
        sample_span(s, w, EMIT_PRODUCT_REPORT)
        return action(o, w, EMIT_SCALAR_SNAPSHOT, EMIT_SNAPSHOT_PRODUCT, 0, 0, 0, 0)
    if state == EMIT_SCALAR_EXPIRED and length(s) == 64 and input_word(s, 40) == 0:
        return emit_admission_error(o, w, 8, choose(get(w, EMIT_SCALAR_STAGE) == 12, 7, 6))
    if state == EMIT_SCALAR_SNAPSHOT and input_word(s, 48) == 15:
        target = choose(get(w, EMIT_SCALAR_STAGE) == 12, EMIT_OBJECT_PRODUCED, EMIT_IMAGE_PRODUCED)
        return emit_product_observed(s, o, w, target)
    return BAD

def emit_scalar_implementation(o:mutbuf, w:mutbuf) -> u64:
    if get(w, EMIT_SCALAR_EXE + 16) < 64:
        return BAD
    return inspection_hash(o, w, EMIT_MEASURE_SCALAR_HASH, EMIT_SCALAR_EXE)
'''


def scalar_constants(constants):
    states = ('NONCE', 'PREPARED', 'REPORT_READY', 'EXPIRED', 'SNAPSHOT')
    return {
        **{f'EMIT_SCALAR_{state}': constants['EMIT_MEASURE_CUSTODY'] + 1 + i for i, state in enumerate(states)},
        'EMIT_MEASURE_SCALAR_HASH': constants['EMIT_MEASURE_CUSTODY'] + 1 + len(states),
        'EMIT_SCALAR_STAGE': 6560, 'EMIT_SCALAR_EXE': 6568, 'EMIT_LAYOUT_PERMIT': 6592,
        'EMIT_SCALAR_DEADLINE': 4672,
        'EMIT_SCALAR_ROLE': 39, 'EMIT_SCALAR_EXE_ROLE': 55,
        'EMIT_PREPARE_PRODUCT': 22, 'EMIT_SNAPSHOT_PRODUCT': 23, 'EMIT_DISCARD_PRODUCT': 24,
        'EMIT_PRODUCT_ARG': 7, 'EMIT_HEX_FD_ARG': 8,
        'EMIT_SCRATCH_PREFIX': int.from_bytes(b'.emit-', 'little'),
        'EMIT_PROGRAM_STEM': int.from_bytes(b'program.', 'little'),
    }
