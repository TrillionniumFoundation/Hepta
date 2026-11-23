"""Build word-circuit queries for the closed, independently decoded SIMD templates."""

from hepta.hia_cnf_native import CIRCUIT_REQUEST


WIDTHS = (1, 2, 3, 4, 5, 7, 8, 16, 32, 64)


class WordCircuit:
    """A word node has an operation, width, two producer indices and an immediate."""

    def __init__(self):
        self.nodes = []

    def node(self, operation, width, left=0, right=0, immediate=0):
        index = len(self.nodes)
        self.nodes.append((operation, width, left, right, immediate))
        return index

    def constant(self, value, width=64):
        return self.node(2, width, immediate=value)

    def both(self, *predicates):
        value = predicates[0]
        for predicate in predicates[1:]:
            value = self.node(3, 1, value, predicate)
        return value

    def either(self, *predicates):
        value = predicates[0]
        for predicate in predicates[1:]:
            value = self.node(4, 1, value, predicate)
        return value

    def function(self, name, predicate):
        false = self.constant(0, 1)
        encoded = []
        overrides = []
        for index, (operation, width, left, right, immediate) in enumerate(self.nodes):
            slot = operation - (11 if operation >= 26 else 1)
            if slot < 0 or operation not in (*range(1, 16), *range(26, 33)):
                raise ValueError('unsupported SIMD proof word operation')
            tag = 10 * slot + WIDTHS.index(width)
            if type(immediate) is not int or not 0 <= immediate < 256:
                overrides.append((index, immediate))
                immediate = 0
            encoded.append(tag | (left << 8) | (right << 16) | (immediate << 24))
        lines = [f'def {name}(w:mutbuf, delta:u64) -> u64:']
        pairs = []
        for i in range(0, len(encoded), 2):
            upper = encoded[i + 1] if i + 1 < len(encoded) else 0xffffffff
            pairs.append(encoded[i] | (upper << 32))
        used = len(pairs) // 8 * 8
        for i in range(0, used, 8):
            words = ', '.join(str(word) for word in pairs[i:i + 8])
            lines.append(f'    simd_word_pairs8(w, {2 * i}, {words})')
        for i in range(used, len(pairs)):
            lines.append(f'    simd_word_pair(w, {2 * i}, {pairs[i]})')
        for index, value in overrides:
            lines.append(f'    put(w, FRAME + {64 + 40 * index}, {value})')
        lines.append(f'    return simd_miter(w, {len(encoded)}, {predicate}, {false})')
        return '\n'.join(lines)


def caller_contract(copy):
    """Existential nonvacuity has a constructive nonempty, nonoverlapping subdomain."""
    g = WordCircuit()
    selector = g.node(1, 8)
    count, extent, zero = g.constant(1), g.constant(64), g.constant(0)
    offset = g.node(30, 64, selector)
    source = g.node(9, 64, g.constant(4096), offset)
    source_end = g.node(9, 64, source, count)
    valid = g.both(g.node(8, 1, source, zero), g.node(15, 1, source_end, source))
    fits = g.node(13, 1, count, extent)
    if copy:
        dest = g.node(9, 64, g.constant(8192), offset)
        dest_end = g.node(9, 64, dest, count)
        separate = g.either(g.node(13, 1, source_end, dest), g.node(13, 1, dest_end, source))
        valid = g.both(valid, g.node(8, 1, dest, zero), g.node(15, 1, dest_end, dest), separate)
        fits = g.both(fits, g.node(13, 1, count, extent))
    allowed = g.both(fits, g.either(g.node(7, 1, count, zero), valid))
    return g.function('simd_copy_caller' if copy else 'simd_read_caller', allowed)


def abort_stack():
    g = WordCircuit()
    sp = g.node(1, 64)
    eight, sixteen, delta = g.constant(8), g.constant(16), g.constant('delta')
    last = g.node(6, 64, eight)
    low = g.node(26, 4, sp)
    entry = g.both(g.node(7, 1, low, g.constant(8, 4)), g.node(15, 1, sp, sixteen),
                   g.node(13, 1, sp, last))
    at_call = g.node(10, 4, low, g.node(26, 4, delta))
    # For 0 <= k < 2^64, (sp-k) mod 2^64 > sp iff sp < k. The CALL pushes
    # eight more bytes. Its slot ends at sp-delta. The caller's slot ends at sp+8.
    # The alignment test uses exactly the low four bits of that 64-bit subtraction.
    bad = g.either(g.node(8, 1, at_call, g.constant(0, 4)),
                   g.node(12, 1, sp, g.node(9, 64, delta, eight)),
                   g.node(12, 1, sp, delta), g.node(14, 1, sp, last))
    return g.function('simd_abort_stack', g.both(entry, bad))


def interval_step():
    g = WordCircuit()
    remaining = g.node(1, 64)
    guard = g.constant('get(w, SIMD_GUARD_SLOT)')
    advance = g.constant('get(w, SIMD_ADVANCE_SLOT)')
    other_advance = g.constant('get(w, SIMD_OTHER_ADVANCE_SLOT)')
    decrement = g.constant('get(w, SIMD_DECREMENT_SLOT)')
    last_access = g.constant('delta')
    enters = g.node(15, 1, remaining, guard)
    # The original natural-number invariant has count = index + remaining and
    # base + count < 2^64. Subtracting base+index from both endpoints reduces
    # every offset/size bound to distance <= remaining. The independent grammar
    # validates each nonnegative access offset, so checking the furthest end
    # covers all accesses in a four-vector block as well as one-vector and tail
    # steps. Equal advances preserve the pointer/count relation. A positive
    # decrement fitting remaining makes the natural variant strictly decrease.
    bad = g.either(g.node(14, 1, advance, remaining), g.node(14, 1, decrement, remaining),
                   g.node(7, 1, decrement, g.constant(0)), g.node(8, 1, advance, decrement),
                   g.node(8, 1, other_advance, decrement), g.node(14, 1, last_access, remaining))
    return g.function('simd_interval_step', g.both(enters, bad))


def endpoint_dispatch():
    g = WordCircuit()
    remaining = g.node(1, 7)
    vector = g.constant('delta', 7)
    zero = g.constant(0, 7)
    hit = g.node(7, 1, remaining, zero)
    duplicate = g.constant(0, 1)
    for width in (1, 2, 4, 8, 16, 32):
        lower = g.constant(width, 7)
        upper = g.constant(2 * width, 7)
        here = g.both(g.node(12, 1, lower, vector), g.node(15, 1, remaining, lower),
                      g.node(12, 1, remaining, upper))
        duplicate = g.either(duplicate, g.both(here, hit))
        hit = g.either(hit, here)
    outside_partition = g.either(duplicate, g.node(6, 1, hit))
    return g.function('simd_endpoint_partition', g.both(g.node(12, 1, remaining, vector), outside_partition))


def endpoint_query(effects):
    g = WordCircuit()
    remaining, point, outside = g.node(1, 7), g.node(1, 7), g.node(1, 1)
    if effects:
        source, before, other = g.node(1, 8), g.node(1, 8), g.node(1, 8)
    width = g.constant('delta', 7)
    decrement = g.constant('get(w, SIMD_DECREMENT_SLOT)', 7)
    zero, one = g.constant(0, 7), g.constant(1, 7)
    upper = g.node(9, 7, width, width)
    path = g.both(g.node(15, 1, remaining, width), g.node(12, 1, remaining, upper))
    inside = g.node(6, 1, outside)
    target = g.both(inside, g.node(12, 1, point, remaining))
    suffix = g.node(10, 7, remaining, decrement)
    end = g.node(9, 7, suffix, width)
    second = g.node(8, 1, width, one)
    in_first = g.both(inside, g.node(12, 1, point, width))
    in_last = g.both(inside, second, g.node(15, 1, point, suffix), g.node(12, 1, point, end))
    # 0 <= remaining < 2*width <= 64. Every mathematical byte outside
    # [0,127] is represented by outside. The caller invariant makes its
    # absolute addresses equivalent to these relative offset checks.
    bounds = g.either(g.node(14, 1, width, remaining),
                      g.both(second, g.either(g.node(14, 1, decrement, remaining),
                                              g.node(14, 1, end, remaining))))
    if effects:
        # The decoded schedule loads source before either store. At a symbolic
        # destination byte j, an in-range store selects source[j - dst + src].
        # Equal read/write offsets make both overlapping writes select the same
        # source byte. An arbitrary other byte models every unequal address.
        source_end = g.node(10, 7, remaining, decrement)
        effective = g.node(9, 7, g.node(10, 7, point, suffix), source_end)
        from_last = g.node(11, 8, g.node(7, 1, effective, point), source, other)
        actual = g.node(11, 8, in_last, from_last, g.node(11, 8, in_first, source, before))
        expected = g.node(11, 8, target, source, before)
        bad = g.either(bounds, g.node(8, 1, actual, expected))
    else:
        bad = g.either(bounds, g.node(8, 1, g.either(in_first, in_last), target))
    return g.function('simd_endpoint_effects' if effects else 'simd_endpoint_bounds', g.both(path, bad))


def bounded_word_partition():
    g = WordCircuit()
    remaining, point, outside = g.node(1, 5), g.node(1, 5), g.node(1, 1)
    zero = g.constant(0, 5)
    inactive = g.constant(0, 1)
    inside = g.node(6, 1, outside)
    cursor, rest, hit, bad = zero, remaining, inactive, inactive
    for width in (8, 4, 2, 1):
        boundary = g.constant(width, 5)
        take = g.node(15, 1, rest, boundary)
        end = g.node(9, 5, cursor, boundary)
        here = g.both(inside, take, g.node(13, 1, cursor, point), g.node(12, 1, point, end))
        consumed = g.node(11, 5, take, boundary, zero)
        rest = g.node(10, 5, rest, consumed)
        bad = g.either(bad, g.both(take, g.node(14, 1, end, remaining)), g.both(hit, here),
                       g.node(15, 1, rest, boundary))
        hit = g.either(hit, here)
        cursor = g.node(9, 5, cursor, consumed)
    target = g.both(inside, g.node(12, 1, point, remaining))
    bad = g.either(bad, g.node(8, 1, rest, zero), g.node(8, 1, cursor, remaining),
                   g.node(8, 1, hit, target))
    return g.function('simd_bounded_partition', g.both(g.node(12, 1, remaining, g.constant(16, 5)), bad))


def endpoint_geometry_source():
    from tools.generate_hia_verified_simd_avx512_check import VOCABULARY

    # Both wide profiles use the same endpoint instructions at these widths.
    # Read the actual SUB operand between exact loads/stores and pointer adds.
    lines = ['def simd_endpoint_extent(w:mutbuf, at:u64, end:u64, width:u64) -> u64:']
    for width in (1, 2, 4, 8, 16, 32):
        bits = width * 8
        vector = width >= 16
        load = 'vload' if vector else 'copy_load'
        store = 'vstore' if vector else 'copy_store'
        first, last = (1, 2) if vector else (9, 11)
        rows = [(load, bits, first, 2, 0)]
        if width != 1:
            rows.extend([('alu_imm', 'sub', 10, width), ('add', 2, 10), (load, bits, last, 2, 0)])
        rows.append((store, bits, 7, 0, first))
        if width != 1:
            rows.extend([('add', 7, 10), (store, bits, 7, 0, last)])
        encoded = [bytes.fromhex(VOCABULARY[op]) for op in rows]
        raw = b''.join(encoded)
        operand = len(encoded[0]) + 3 if width != 1 else None
        lines.extend((f'    if width == {width}:', f'        if end - at < {len(raw)}:', '            return 0'))
        for pos in range(0, len(raw), 8):
            part = raw[pos:pos + 8]
            mask = (1 << (len(part) * 8)) - 1
            if operand is not None and pos <= operand < pos + len(part):
                mask ^= 255 << (8 * (operand - pos))
            value = int.from_bytes(part, 'little') & mask
            lines.extend((f'        if (get(w, at + {pos}) & {mask}) != {value}:', '            return 0'))
        if operand is None:
            lines.append('        return 1')
        else:
            lines.append(f'        return byte(w, at + {operand})')
    return '\n'.join((*lines, '    return 0'))


def prefix_suffix_partition():
    g = WordCircuit()
    rank_n, rank_i, rank_q = (g.node(1, 2) for _ in range(3))
    nbit, ibit, qbit, borrow = (g.node(1, 1) for _ in range(4))
    diff = g.node(5, 1, g.node(5, 1, nbit, ibit), borrow)
    next_borrow = g.either(g.both(g.node(6, 1, nbit), g.either(ibit, borrow)), g.both(ibit, borrow))
    restored = g.node(5, 1, g.node(5, 1, ibit, diff), borrow)
    carry = g.either(g.both(ibit, diff), g.both(ibit, borrow), g.both(diff, borrow))
    # Start both chains at zero. At each bit the carry equals the borrow
    # and the restored bit equals count. Hence index + (count-index) = count.
    violations = [g.node(8, 1, restored, nbit), g.node(8, 1, carry, next_borrow)]
    count, index, point = (g.node(27, 3, r, b) for r, b in
                           ((rank_n, nbit), (rank_i, ibit), (rank_q, qbit)))
    # Three ordered prefixes have at most three distinct ranks. Replacing each
    # by its rank preserves every relevant comparison, including equality.
    # Appending a bit orders by rank first, then by that bit. This quotient is
    # exact at every width; all equal ranks represent the initial empty words.
    for a, b, abit, bbit, appended_a, appended_b in (
            (rank_q, rank_i, qbit, ibit, point, index),
            (rank_i, rank_n, ibit, nbit, index, count),
            (rank_q, rank_n, qbit, nbit, point, count)):
        less = g.either(g.node(12, 1, a, b),
                        g.both(g.node(7, 1, a, b), g.node(6, 1, abit), bbit))
        violations.append(g.node(8, 1, less, g.node(12, 1, appended_a, appended_b)))
    left = g.node(12, 1, point, count)
    right = g.either(g.node(12, 1, point, index), g.both(g.node(15, 1, point, index), left))
    violations.append(g.both(g.node(13, 1, index, count), g.node(8, 1, left, right)))
    return g.function('simd_prefix_suffix_partition', g.either(*violations))


def branch_condition(g, opcode_offset, carry, zero):
    code = g.constant(f'byte(w, BINDING + {81 + opcode_offset}) & 15', 4)
    # This terminal grammar admits JB, JE, JBE and JA. Their carry/zero
    # truth tables are applied to the condition byte read from the final ELF.
    conditions = [(2, carry), (4, zero), (6, g.either(carry, zero)),
                  (7, g.node(6, 1, g.either(carry, zero)))]
    return g.either(*(g.both(g.node(7, 1, code, g.constant(cc, 4)), take) for cc, take in conditions))


def entry_guards(copy):
    g = WordCircuit()
    # All possible CMP flags are covered. Impossible combinations may add
    # cases to this miter, which preserves an UNSAT implication.
    names = ('extent_lt', 'extent_eq', 'empty', 'null', 'wrap', 'sum_zero',
             'dest_lt', 'dest_eq', 'other_null', 'other_wrap', 'other_zero',
             'before_lt', 'before_eq', 'after_lt', 'after_eq', 'left_bit', 'right_bit', 'carry')
    v = {name: g.node(1, 1) for name in names}
    false = g.constant(0, 1)
    not_ = lambda a: g.node(6, 1, a)
    def condition(at, cf, zf):
        return branch_condition(g, at, cf, zf)
    fits = g.either(v['extent_lt'], v['extent_eq'])
    failed = condition(6 if copy else 8, v['extent_lt'], v['extent_eq'])
    if copy:
        fits = g.both(fits, g.either(v['dest_lt'], v['dest_eq']))
        failed = g.either(failed, condition(15, v['dest_lt'], v['dest_eq']))
    empty = condition(24 if copy else 17, false, v['empty'])
    done = g.both(not_(failed), empty)
    live = g.both(not_(failed), not_(empty))
    guard = g.either(condition(33 if copy else 26, false, v['null']),
                     condition(45 if copy else 38, v['wrap'], v['sum_zero']))
    allowed = g.both(not_(v['null']), not_(v['wrap']))
    if copy:
        guard = g.either(guard, condition(54, false, v['other_null']),
                         condition(66, v['other_wrap'], v['other_zero']))
        first = condition(75, v['before_lt'], v['before_eq'])
        last = condition(84, v['after_lt'], v['after_eq'])
        guard = g.either(guard, g.both(not_(first), last))
        allowed = g.both(allowed, not_(v['other_null']), not_(v['other_wrap']),
                         g.either(v['before_lt'], v['before_eq'], v['after_lt'], v['after_eq']))
    valid = g.both(fits, g.either(v['empty'], allowed))
    abort = g.either(failed, g.both(live, guard))
    entered = g.both(live, not_(guard))
    faults = [g.node(8, 1, abort, not_(valid)), g.node(8, 1, done, g.both(valid, v['empty'])),
              g.node(8, 1, entered, g.both(valid, not_(v['empty'])))]
    # A word addition wraps iff its unsigned result is less than its first
    # operand. At bit zero both carry and prior comparison are false. Appending
    # each next bit to the two low prefixes preserves their carry/ULT invariant.
    a, b, carry = (v[k] for k in ('left_bit', 'right_bit', 'carry'))
    out = g.node(5, 1, g.node(5, 1, a, b), carry)
    next_carry = g.either(g.both(a, b), g.both(a, carry), g.both(b, carry))
    next_lt = g.either(g.both(not_(out), a), g.both(g.node(7, 1, out, a), carry))
    faults.append(g.node(8, 1, next_carry, next_lt))
    return g.function('simd_copy_guards' if copy else 'simd_read_guards', g.either(*faults))


def short_entry():
    g = WordCircuit()
    count, admitted = g.node(1, 64), g.node(1, 1)
    width = g.constant('delta')
    threshold = g.constant('byte(w, BINDING + 130)')
    cf, zf = g.node(12, 1, count, threshold), g.node(7, 1, count, threshold)
    branch = branch_condition(g, 51, cf, zf)
    short = g.node(12, 1, count, width)
    # The preceding nonzero admitted path is separately proved by entry_guards.
    path = g.both(admitted, g.node(8, 1, count, g.constant(0)))
    bad = g.either(g.node(8, 1, g.both(path, branch), g.both(path, short)),
                   g.node(8, 1, g.both(path, g.node(6, 1, branch)),
                          g.both(path, g.node(15, 1, count, width))))
    return g.function('simd_short_entry', bad)


def loop_initiation(copy):
    g = WordCircuit()
    # One arbitrary bit from each input register suffices for register moves:
    # full-width MOV transfers all bit positions identically. For MOV EAX,imm
    # include the entire 32-bit immediate in the zero-result check.
    registers = [g.node(1, 1) for _ in range(16)]
    before = list(registers)
    zero = g.constant(0, 1)
    def move(slot, checked):
        src = g.constant(f'get(w, {slot}) & 15', 4)
        dst = g.constant(f'(get(w, {slot}) >> 4) & 15', 4)
        value = registers[0]
        for i in range(1, 16):
            value = g.node(11, 1, g.node(7, 1, src, g.constant(i, 4)), registers[i], value)
        for i in checked:
            registers[i] = g.node(11, 1, g.node(7, 1, dst, g.constant(i, 4)), value, registers[i])
    faults = []
    if copy:
        move('SIMD_RESULT_MOVE_SLOT', (0, 2, 7, 8, 10))
    else:
        faults.append(g.node(8, 1, g.constant('get(w, SIMD_RESULT_MOVE_SLOT)', 32), g.constant(0, 32)))
        registers[0] = zero
    move('SIMD_COUNT_MOVE_SLOT', (0, 2, 7, 10))
    expected = before[8 if copy else 2]
    faults += [g.node(8, 1, registers[10], expected), g.node(8, 1, registers[0], expected if copy else zero),
               g.node(8, 1, registers[7], before[7]), g.node(8, 1, registers[2], before[2])]
    return g.function('simd_copy_init' if copy else 'simd_read_init', g.either(*faults))


def scalar_tail_exit():
    g = WordCircuit()
    count, index = g.node(1, 64), g.node(1, 64)
    remaining = g.node(10, 64, count, index)
    bad = g.both(g.node(13, 1, index, count), g.node(7, 1, remaining, g.constant(0)),
                 g.node(8, 1, index, count))
    return g.function('simd_scalar_tail_exit', bad)


TRANSPORT = '''
def simd_word_pair(w:mutbuf, index:u64, pair:u64) -> u64:
    simd_packed_word(w, index, pair & 4294967295)
    upper = pair >> 32
    if upper != 4294967295:
        simd_packed_word(w, index + 1, upper)
    return 0

def simd_packed_word(w:mutbuf, index:u64, packed:u64) -> u64:
    tag = packed & 255
    slot = tag // 10
    code = tag % 10
    widths = PACKED_WIDTHS
    width = choose(code < 8, (widths >> ((code & 7) * 8)) & 255, choose(code == 8, 32, 64))
    at = FRAME + 32 + 40 * index
    put(w, at, slot + choose(slot >= 15, 11, 1))
    put(w, at + 8, width)
    put(w, at + 16, (packed >> 8) & 255)
    put(w, at + 24, (packed >> 16) & 255)
    put(w, at + 32, packed >> 24)
    return 0

def simd_miter(w:mutbuf, nodes:u64, predicate:u64, false:u64) -> u64:
    put(w, FRAME, CIRCUIT_MAGIC)
    put(w, FRAME + 8, nodes)
    put(w, FRAME + 16, 3)
    put(w, FRAME + 24, 0)
    at = FRAME + 32 + nodes * 40
    put(w, at, predicate)
    i = 8
    while i < 48:
        put(w, at + i, false)
        i = i + 8
    return 80 + nodes * 40
'''


def word_pair_writer():
    words = [f'pair{i}' for i in range(8)]
    args = ', '.join(name + ':u64' for name in words)
    lines = [f'def simd_word_pairs8(w:mutbuf, at:u64, {args}) -> u64:']
    lines.extend(f'    simd_word_pair(w, at + {2 * i}, {name})' for i, name in enumerate(words))
    return '\n'.join([*lines, '    return 0'])


def packed_transport():
    packed = TRANSPORT.replace('CIRCUIT_MAGIC', str(CIRCUIT_REQUEST)).replace(
        'PACKED_WIDTHS', str(int.from_bytes(bytes(WIDTHS[:8]), 'little')))
    return word_pair_writer() + '\n' + packed


def source():
    return '\n\n'.join((packed_transport(), caller_contract(False), caller_contract(True),
                        abort_stack(), scalar_tail_exit(), interval_step(), endpoint_dispatch(),
                        endpoint_query(False), endpoint_query(True), bounded_word_partition(),
                        endpoint_geometry_source()))
