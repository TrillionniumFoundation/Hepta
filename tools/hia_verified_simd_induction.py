"""Build word-circuit queries for the closed, independently decoded SIMD templates."""

from hepta.hia_cnf_native import CIRCUIT_REQUEST


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
        count = len(self.nodes)
        lines = [f'def {name}(w:mutbuf, delta:u64) -> u64:']
        for index, (operation, width, left, right, immediate) in enumerate(self.nodes):
            descriptor = operation | (width << 8) | (left << 16) | (right << 24)
            lines.append(f'    simd_word_node(w, {index}, {descriptor}, {immediate})')
        lines.append(f'    return simd_miter(w, {count}, {predicate}, {false})')
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


def scalar_tail_exit():
    g = WordCircuit()
    count, index = g.node(1, 64), g.node(1, 64)
    remaining = g.node(10, 64, count, index)
    bad = g.both(g.node(13, 1, index, count), g.node(7, 1, remaining, g.constant(0)),
                 g.node(8, 1, index, count))
    return g.function('simd_scalar_tail_exit', bad)


TRANSPORT = '''
def simd_word_node(w:mutbuf, index:u64, descriptor:u64, immediate:u64) -> u64:
    at = FRAME + 32 + 40 * index
    put(w, at, descriptor & 255)
    put(w, at + 8, (descriptor >> 8) & 255)
    put(w, at + 16, (descriptor >> 16) & 255)
    put(w, at + 24, (descriptor >> 24) & 255)
    put(w, at + 32, immediate)
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


def source():
    return '\n\n'.join((TRANSPORT.replace('CIRCUIT_MAGIC', str(CIRCUIT_REQUEST)),
                        caller_contract(False), caller_contract(True), abort_stack(), scalar_tail_exit(), interval_step()))
