"""Generate the HIA word projection for the independently decoded SIMD data blocks."""

from tools.hia_verified_simd_induction import (
    WordCircuit, entry_guards, loop_initiation, packed_transport, prefix_suffix_partition, short_entry,
)
from hepta.hia_cnf_native import CIRCUIT_REQUEST


# Each instruction includes its actual operand registers, lane count and unsigned
# displacement. The linked bytes must match the independently decoded sequence
# before its semantics is admitted. Branches, relocation and label targets are
# checked independently by the supplied coordinator.
def semantic_instruction(row):
    op, a = row.op, row.args
    if op in ('paddq', 'por', 'psadbw'):
        op = {'paddq': 'vpaddq', 'por': 'vpor', 'psadbw': 'vpsadbw'}[op]
        a = (128, a[0], a[0], a[1])
    if op in ('vpaddq', 'vpor', 'vpsadbw', 'vpxor'):
        bits, dest, left, right = a
        return ({'vpaddq': 1, 'vpor': 2, 'vpsadbw': 3, 'vpxor': 4}[op], bits // 64, dest, left, right)
    if op in ('vpsadbw_mem', 'vpor_mem'):
        bits, dest, left, pointer, disp = a
        assert pointer == 7
        return (5 if op == 'vpsadbw_mem' else 6, bits // 64, dest, left, disp)
    if op in ('vload', 'load128'):
        bits, dest, pointer, disp = (128, *a) if op == 'load128' else a
        return (7, bits // 64, dest, pointer, disp)
    if op in ('vstore', 'store128'):
        bits, pointer, disp, reg = (128, *a) if op == 'store128' else a
        return (8, bits // 64, reg, pointer, disp)
    if op == 'vextract':
        origin, bits, dest, src, part = a
        return 9, bits // 64, dest, src, part * (bits // 64)
    if op in ('xmm_to_gpr', 'vmovq'):
        return 10, 1, a[0], a[1], 0
    if op == 'vgpr_to_xmm':
        return 11, 1, a[0], a[1], 0
    if op in ('psrldq', 'vpsrldq'):
        width, dest, src, amount = (128, a[0], a[0], a[1]) if op == 'psrldq' else a
        assert width == 128 and amount % 8 == 0
        return 12, 2, dest, src, amount // 8
    if op in ('copy_load', 'load8'):
        bits, dest, ptr, disp = (8, *a) if op == 'load8' else a
        return 13, bits // 8, dest, ptr, disp
    if op == 'store8':
        ptr, disp, src = a
        return 14, 1, src, ptr, disp
    if op in ('add', 'or'):
        return (15 if op == 'add' else 16), 1, a[0], a[1], 0
    raise ValueError('unsupported SIMD data instruction ' + str(row))


def stages(isa, kind):
    if kind == 3:
        return {42: 'bulk', 43: 'vector', **({52: 'scalar'} if isa == 1 else {})}
    if isa == 1:
        return {42: 'bulk', 43: 'vector', **({44: 'bulk_merge'} if kind == 2 else {}),
                47: 'horizontal', 52: 'scalar'}
    return {40: 'initialize', 41: 'short_initialize', 42: 'bulk', 43: 'vector', 44: 'bulk_merge',
            45: 'wide_fold', 46: 'narrow_vector', 47: 'narrow_horizontal',
            **{48 + i: 'word_' + str(1 << i) for i in range(4)}}


def blocks():
    from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
    from hepta.hia_verified_simd_check import decode_simd, _structure

    vocabulary, profiles = {}, {}
    for kind, name in enumerate(('sum_u8', 'all_zero_u8', 'copy_u8'), 1):
        for isa, target in enumerate(('sse2', 'avx2', 'avx512'), 1):
            # These bytes are only a source of instruction samples for the
            # authoring decoder. The HIA consumer matches the supplied linked
            # bytes itself. The call is outside every data block.
            text = emit_verified_simd(simd_kernel_program(name), isa=target).text_bytes
            rows = decode_simd(text)
            call, = (r for r in rows if r.op == 'call')
            _, parts = _structure(rows, name, {'calls': {call.pc: 'abort'}})
            forms = {}
            for role, stage in stages(isa, kind).items():
                selected = parts[stage]
                if any(a.pc + a.size != b.pc for a, b in zip(selected, selected[1:])):
                    raise ValueError('a SIMD data block is not contiguous')
                raw = text[selected[0].pc:selected[-1].pc + selected[-1].size]
                program = tuple(semantic_instruction(r) for r in selected)
                identity = raw, program
                index = vocabulary.setdefault(identity, len(vocabulary) + 1)
                forms[role] = (selected[0].pc, index)
            profiles[isa, kind] = forms
    return vocabulary, profiles


def block_source():
    vocabulary, profiles = blocks()
    out = ['def simd_data_program(w:mutbuf, isa:u64, shape:u64, role:u64) -> u64:']
    for (isa, kind), rows in profiles.items():
        out.append(f'    if isa == {isa} and shape == {kind}:')
        for role, (pc, index) in rows.items():
            out.extend((f'        if role == {role}:', f'            return block{index}(w, {pc})'))
        out.append('        return 0')
    out.append('    return 0')
    for (raw, program), index in vocabulary.items():
        out.extend(('', f'def block{index}(w:mutbuf, pc:u64) -> u64:',
                    f'    if pc + {len(raw)} > get(w, SD_SPAN):', '        return 0',
                    '    at = SD_TEXT + pc'))
        for at in range(0, len(raw), 8):
            part = raw[at:at + 8]
            mask = (1 << (8 * len(part))) - 1
            out.extend((f'    if (get(w, at + {at}) & {mask}) != {int.from_bytes(part, "little")}:',
                        '        return 0'))
        for i, instruction in enumerate(program):
            packed = sum(n << (8 * j) for j, n in enumerate(instruction))
            out.append(f'    put(w, SD_OPS + {8 * i}, {packed})')
        out.append(f'    return {len(program)}')
    return '\n'.join(out)


def source_separation():
    g = WordCircuit()
    write, first, second, read = (g.node(1, 2) for _ in range(4))
    # Under a classified nonwrapping entry and the separately proved loop
    # bounds, the earlier interval has write < end <= other_start <= read.
    # Four rank values preserve every comparison for four arbitrary addresses.
    order = g.both(g.node(12, 1, write, first), g.node(13, 1, first, second),
                   g.node(13, 1, second, read))
    return g.function('simd_source_separation', g.both(order, g.node(7, 1, write, read)))


def data_law_source():
    """Bit-level laws used when comparing the additive/OR bases of SIMD blocks."""
    g = WordCircuit()
    g.node(1, 64)  # arbitrary mask for the subsequent coefficient-table miter
    g.node(1, 8)   # symbolic row of that table
    byte, partial = g.node(1, 8), g.node(1, 16)
    a, b, c = (g.node(1, 1) for _ in range(3))
    zero = g.constant(0, 8)
    abs_byte = g.node(11, 8, g.node(15, 1, byte, zero),
                      g.node(10, 8, byte, zero), g.node(10, 8, zero, byte))
    subtotal = g.node(9, 16, partial, g.node(30, 16, abs_byte))
    bounds = g.both(g.node(13, 1, partial, g.constant(7 * 255, 16)),
                    g.node(14, 1, subtotal, g.constant(8 * 255, 16)))
    full_sum = g.node(9, 2, g.node(9, 2, g.node(30, 2, a), g.node(30, 2, b)), g.node(30, 2, c))
    low = g.node(5, 1, g.node(5, 1, a, b), c)
    carry = g.either(g.both(a, b), g.both(a, c), g.both(b, c))
    sum_bad = g.node(8, 1, full_sum, g.node(27, 2, carry, low))
    or_bad = g.node(8, 1, g.node(6, 1, g.either(a, b)), g.both(g.node(6, 1, a), g.node(6, 1, b)))
    bad = g.either(g.node(8, 1, abs_byte, byte), bounds, sum_bad, or_bad)
    source = g.function('data_laws', bad)
    false = len(g.nodes) - 1
    lines = source.splitlines()[:-1]
    lines += [f'    put(w, SD_NODE_COUNT, {len(g.nodes)})', f'    put(w, SD_BAD_NODE, {bad})',
              f'    put(w, SD_FALSE_NODE, {false})', '    return 0']
    return '\n'.join(lines)


def source():
    from tools.hia_verified_simd_data_projection import SOURCE
    return '\n\n'.join((SOURCE, packed_transport(), source_separation(), data_law_source(), block_source(),
                        prefix_suffix_partition(), entry_guards(False), entry_guards(True),
                        loop_initiation(False), loop_initiation(True), short_entry()))
