"""Finite live payload-byte upper bound for existing verified HIA Core.

This is a strictly opt-in resource-budget analysis, not a second ownership
checker. The canonical HIA verifier provides SSA, typed ownership and CFG
validity. We refuse unknown allocation extents, owner-valued call boundaries,
loops and recursion instead of inventing bounds from caller assumptions.
The bound counts requested live byte payload, NOT allocator overhead or RSS.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import WIDTHS, integer_range, verify_program

MAX_REQUEST = (1 << 63) - 1
# The complete domain is small enough to express and can flow through checked
# conversions without ever admitting an out-of-range allocation size.
_SMALL_CAST_DOMAINS = frozenset({"i8", "i16", "i32", "u8", "u16", "u32"})
# Versioned closed interpretation: a future schema could change the semantics
# of an existing opcode and must never inherit this byte bound automatically.
_ALLOWED_SCHEMAS = frozenset(f"hepta.hia.program.v{version}" for version in range(1, 7))
# New executable Core opcodes must be explicitly audited before any native
# resource policy can rely on this analysis. Never guess "does not allocate".
# A separately audited, explicit whitelist for arbitrary CFG cycles.
# If *every* executable opcode in a verified function is pure scalar, it can
# never create, transfer or free a HIA heap owner regardless of iteration count.
# Do not derive this from the broader _NO_ALLOCATION_OPS: that set also
# includes memory operations and can grow independently in future schemas.
_ZERO_HEAP_CYCLIC_SCALARS = frozenset({
    "const", "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
})

_NO_ALLOCATION_OPS = frozenset({
    "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
    "buffer.len", "borrow.read", "borrow.mut", "loan.end",
    "buffer.load", "buffer.store", "buffer.fill", "buffer.copy",
    "buffer.move_within", "buffer.fill_range", "buffer.copy_range", "buffer.swap",
})



# P1 finite peak for a narrowly qualified cyclic owner scope.  Each block
# starts/ends without an owner/loan; each allocation has a bounded usize
# extent established within that SAME block from a constant or a checked
# typed cast. Therefore no
# outstanding heap bytes accumulate over any number of backedges.  This does
# NOT bound cumulative allocator interactions, steps, termination or RSS.
# Keep try_new, calls, memory operations and borrowed owners out of scope.
_SCOPED_CYCLE_OPS = _ZERO_HEAP_CYCLIC_SCALARS | frozenset({
    "buffer.new", "owner.move", "owner.drop",
})


def _scoped_allocating_cycle_peak(fn: dict) -> int | None:
    """Finite live HIA payload bound with no owned value crossing any edge.

    The *whole* program must already pass the canonical executable Core
    verifier. Here we independently enforce the stronger single-block
    allocation lifetime profile before admitting cycles. Each iteration can
    allocate again, but every ordinary outgoing edge has zero live owners.
    """
    if any(p["type"] in {"buffer", "readbuf", "mutbuf"}
           for block in fn["blocks"] for p in block["params"]):
        return None
    peak = 0
    saw_allocation = False
    for block in fn["blocks"]:
        # Seed the preexisting abstract domain with intrinsic machine-type
        # bounds, independent of caller values. Only constants and the
        # reviewed cast transfer may refine sizes inside this block.
        known = _typed_entry_bounds(block["params"])
        live: dict[str, int] = {}
        live_bytes = 0
        for ins in block["ops"]:
            op, args, outputs, attrs = ins["op"], ins["args"], ins["out"], ins["attrs"]
            if op not in _SCOPED_CYCLE_OPS:
                return None
            if op == "const":
                if (len(outputs) == 1 and type(attrs.get("value")) is int):
                    known[outputs[0]["name"]] = attrs["value"]
            elif op == "int.cast":
                # Reuse the preexisting source-typed, trap-aware cast
                # interval transfer. Unknown source values can still be
                # bounded by the destination machine type after a successful
                # checked cast; wrapped small destinations have a complete
                # finite domain as well.
                folded = _bounded_cast(known.get(args[0]),
                                       outputs[0]["type"], attrs["mode"])
                if folded is not None:
                    known[outputs[0]["name"]] = folded
            elif op == "buffer.new":
                # Exclude proven-all-zero and fallible owners from this narrow
                # cycle proof. A size derived from an unproved SSA operation
                # or another block is not a repeated-allocation invariant.
                if len(args) != 1 or len(outputs) != 1:
                    return None
                extent = _span(known.get(args[0]))
                if (extent is None or extent.lo < 0
                        or extent.hi <= 0 or extent.hi > MAX_REQUEST):
                    return None
                # Worst successful request within the independently typed
                # interval; no owner survives the current block.
                amount = extent.hi
                key = outputs[0]["name"]
                if key in live:
                    return None
                live[key] = amount
                live_bytes += amount
                peak = max(peak, live_bytes)
                saw_allocation = True
            elif op == "owner.move":
                if len(args) != 1 or len(outputs) != 1 or args[0] not in live:
                    return None
                key = outputs[0]["name"]
                if key in live:
                    return None
                live[key] = live.pop(args[0])
            elif op == "owner.drop":
                if len(args) != 1 or args[0] not in live:
                    return None
                live_bytes -= live.pop(args[0])
            # Other admitted scalar instructions can alter future branch
            # decisions but cannot create/destroy HIA ownership. We do not
            # infer allocator extents from their results in this profile.
        # A path can revisit this block only via an edge; enforce a fully
        # balanced owner state at EVERY normal outgoing edge. A trap has no
        # continuation, and promises no eventual destructor cleanup.
        if live and block["term"]["op"] != "trap":
            return None
        if live_bytes < 0:
            return None
    return peak if saw_allocation else None


class HIAHeapBoundRejected(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject(detail: str) -> None:
    raise HIAHeapBoundRejected("E_HIA_BUDGET_UNBOUNDED", detail)


@dataclass(frozen=True)
class _Span:
    """Closed abstract integer interval, never an unproved input assumption."""
    lo: int
    hi: int


def _span(value):
    if type(value) is int:
        return _Span(value, value)
    return value if isinstance(value, _Span) else None


def _bounded(lo, hi):
    if type(lo) is not int or type(hi) is not int or lo > hi:
        return None
    return lo if lo == hi else _Span(lo, hi)


def _combine_known(a, b):
    # Exactly typed booleans cannot silently act as integer constants.
    if type(a) is bool and type(b) is bool:
        return a if a == b else None
    left, right = _span(a), _span(b)
    if left is None or right is None:
        return None
    return _bounded(min(left.lo, right.lo), max(left.hi, right.hi))


def _wrap(value, typ):
    bits = WIDTHS[typ]
    value &= (1 << bits) - 1
    if typ.startswith("i") and value >= (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _bounded_binary(op, lhs, rhs, typ):
    """Conservative arithmetic over verified same-width SSA integer values.

    Checked overflow can trap; a partly overflowing interval loses precision.
    Wrapping arithmetic is admitted only when the full interval does not wrap,
    or for an exact pair for which modular arithmetic is computed directly.
    """
    a, b = _span(lhs), _span(rhs)
    if a is None or b is None:
        return None
    kind = op.split(".")[1]
    if kind == "add":
        lo, hi = a.lo + b.lo, a.hi + b.hi
    elif kind == "sub":
        lo, hi = a.lo - b.hi, a.hi - b.lo
    else:
        endpoints = (a.lo*b.lo, a.lo*b.hi, a.hi*b.lo, a.hi*b.hi)
        lo, hi = min(endpoints), max(endpoints)
    minimum, maximum = integer_range(typ)
    if minimum <= lo <= hi <= maximum:
        return _bounded(lo, hi)
    if op.endswith(".wrap") and a.lo == a.hi and b.lo == b.hi:
        return _wrap(lo, typ)
    if op.endswith(".checked") and a.lo == a.hi and b.lo == b.hi:
        _reject("checked constant arithmetic may trap")
    return None


def _bounded_cast(value, typ, mode):
    """Bound *successful* HIA casts without assuming a caller's input.

    Checked casts trap outside the destination domain, so intersecting an
    incoming interval with that domain is sound for every continuing path.
    Wrapped casts may be nonmonotone; when partial modular wrap is possible,
    only a complete *small* destination domain can safely be propagated.
    """
    if type(mode) is not str or mode not in {"checked", "wrap"}:
        _reject("unreviewed integer cast mode cannot qualify a heap budget")
    source = _span(value)
    minimum, maximum = integer_range(typ)
    if source is None:
        # Even with an arbitrary/unbounded source, any successful cast to a
        # small integer has a destination-type upper and lower bound.
        return _bounded(minimum, maximum) if typ in _SMALL_CAST_DOMAINS else None
    if mode == "checked":
        low, high = max(source.lo, minimum), min(source.hi, maximum)
        return _bounded(low, high) if low <= high else None
    if minimum <= source.lo <= source.hi <= maximum:
        return _bounded(source.lo, source.hi)
    if mode == "wrap" and source.lo == source.hi:
        return _wrap(source.lo, typ)
    if mode == "wrap" and typ in _SMALL_CAST_DOMAINS:
        return _bounded(minimum, maximum)
    return None



def _bounded_shift(op, lhs, count, typ):
    """Conservatively propagate the VM's checked-count shift semantics.

    HIA's "checked" shifts trap on an invalid *count*, not when bits are
    discarded. The left operand's integer type still wraps after a valid
    left shift. Only admit interval endpoints when every mathematical
    left-shift result fits; exact wrapped pairs may be folded separately.
    Right shifts use signed arithmetic/unsigned logical Python semantics.
    """
    value, amount = _span(lhs), _span(count)
    if value is None or amount is None:
        return None
    bits = WIDTHS[typ]
    if amount.lo < 0 or amount.hi >= bits:
        if value.lo == value.hi and amount.lo == amount.hi:
            _reject("checked constant shift count traps")
        return None
    left = op == "int.shl.checked"
    corners = tuple((x << n if left else x >> n)
                    for x in (value.lo, value.hi)
                    for n in (amount.lo, amount.hi))
    low, high = min(corners), max(corners)
    if left:
        minimum, maximum = integer_range(typ)
        if not minimum <= low <= high <= maximum:
            if value.lo == value.hi and amount.lo == amount.hi:
                return _wrap(low, typ)
            # Modulo wrapping can make an interval nonmonotone.
            # Treat any partially wrapped interval as UNKNOWN, not its
            # unwrapped mathematical endpoints.
            return None
    return _bounded(low, high)

def _bounded_positive_or_xor(lhs, rhs, typ):
    """Sound bit envelope for two proven nonnegative typed intervals.

    If 0 <= a <= A and 0 <= b <= B, neither bitwise OR nor XOR can set
    a bit above the highest bit present in max(A, B). The result therefore
    lies in [0, 2**max(A.bit_length(), B.bit_length()) - 1].
    Negative or unbounded inputs do NOT qualify; both bounds are required.
    """
    left, right = _span(lhs), _span(rhs)
    if left is None or right is None:
        return None
    minimum, maximum = integer_range(typ)
    if (left.lo < 0 or right.lo < 0 or left.lo > left.hi or right.lo > right.hi
            or left.hi > maximum or right.hi > maximum):
        return None
    top = max(left.hi, right.hi)
    ceiling = (1 << top.bit_length()) - 1
    return _bounded(0, ceiling) if ceiling <= maximum else None


def _bounded_bitnot(value, typ):
    """Fixed-width ones' complement reverses a *verified* interval.

    For signed two's-complement integers, ~x = -x - 1 and the signed
    domain maps to itself. For unsigned w-bit integers, the result is
    (2**w - 1) - x. Both maps reverse interval endpoints exactly,
    with no caller-derived assumptions or undefined shifts.
    """
    interval = _span(value)
    if interval is None:
        return None
    minimum, maximum = integer_range(typ)
    if not minimum <= interval.lo <= interval.hi <= maximum:
        return None
    if typ.startswith("i"):
        return _bounded(-interval.hi - 1, -interval.lo - 1)
    word_mask = (1 << WIDTHS[typ]) - 1
    return _bounded(word_mask - interval.hi, word_mask - interval.lo)


def _bounded_nonnegative_and_mask(lhs, rhs, typ):
    """Any proven nonnegative mask interval bounds the AND result.

    For fixed-width two's-complement integers, every set bit in x & mask
    is also set in mask. If 0 <= mask <= M within its source integer type,
    then 0 <= x & mask <= M for *any* x, including negative signed x.
    A mask that might be negative cannot certify this property. These are
    typed abstract values from the canonical HIA verifier; a malformed
    direct interval must not mint an allocation-size certificate.
    """
    _, type_max = integer_range(typ)
    bounds = []
    for value in (lhs, rhs):
        candidate = _span(value)
        if (candidate is not None and 0 <= candidate.lo <= candidate.hi
                and candidate.hi <= type_max):
            bounds.append(candidate.hi)
    return _bounded(0, min(bounds)) if bounds else None


def _bounded_divrem(op, lhs, rhs, typ):
    """Conservative checked div/rem transfer consistent with HIA's VM.

    Exact pairs retain the VM's truncation-toward-zero signed behavior.
    With independently proven strictly-positive divisors, unsigned division
    and signed/unsigned remainder and quotient admit conservative intervals,
    even for full-width unknown arguments. Signed division rounds toward zero
    as the VM/LLVM do, not Python's floor division. A possibly-zero divisor,
    unsafe signed overflow case, or out-of-type interval never mints a bound.
    """
    a, b = _span(lhs), _span(rhs)
    if b is None:
        return None
    if b.lo == b.hi == 0:
        _reject("checked constant division or remainder traps")
    if (op == "int.rem.checked" and not typ.startswith("i")
            and b.lo > 0
            and (a is None or a.lo != a.hi or b.lo != b.hi)):
        # No caller assumption: HIA's unsigned division produces a remainder
        # strictly below the positive divisor on every nontrapping execution.
        # In particular, no arithmetic on an unknown usize is performed here.
        return _bounded(0, b.hi - 1)
    if op == "int.div.checked" and not typ.startswith("i") and b.lo > 0:
        # The checked HIA verifier guarantees same-width unsigned operands.
        # Use the COMPLETE unsigned type domain for an unknown input rather
        # than a guessed caller value. With strictly positive d:
        # floor(x_min / d_max) <= x/d <= floor(x_max / d_min).
        # Overflow cannot occur for unsigned division; zero never reaches
        # the continuation. The allocator enforces MAX_REQUEST separately.
        type_lo, type_hi = integer_range(typ)
        numerator = a if a is not None else _Span(type_lo, type_hi)
        if (type_lo <= numerator.lo <= numerator.hi <= type_hi
                and type_lo < b.lo <= b.hi <= type_hi):
            if (numerator.lo != numerator.hi or b.lo != b.hi):
                return _bounded(numerator.lo // b.hi,
                                numerator.hi // b.lo)
        else:
            # Malformed direct abstract-domain input must not mint a bound.
            return None
    if typ.startswith("i") and b.lo > 0:
        # Positive denominators eliminate MIN/-1 signed overflow. Use the
        # COMPLETE signed machine domain for unknown numerators, not caller
        # samples. The quotient is truncation-towards-zero (unlike Python //).
        minimum, maximum = integer_range(typ)
        numerator = a if a is not None else _Span(minimum, maximum)
        if (minimum <= numerator.lo <= numerator.hi <= maximum
                and 1 <= b.lo <= b.hi <= maximum):
            if (a is None or a.lo != a.hi or b.lo != b.hi):
                if op == "int.div.checked":
                    # The smallest positive divisor maximizes quotient
                    # magnitude. Negative quotients round toward zero:
                    # no negation of MIN as a fixed-width machine operation
                    # occurs in this pure mathematical transfer.
                    low = -(abs(min(numerator.lo, 0)) // b.lo)
                    high = max(numerator.hi, 0) // b.lo
                    return _bounded(low, high)
                if op == "int.rem.checked":
                    # Signed remainder has dividend sign and abs(r) < d.
                    # Preserve an independently proven numerator sign where
                    # possible; otherwise keep both outcomes.
                    max_abs = b.hi - 1
                    low = -max_abs if numerator.lo < 0 else 0
                    high = max_abs if numerator.hi > 0 else 0
                    return _bounded(low, high)
        else:
            return None
    if a is None or a.lo != a.hi or b.lo != b.hi:
        return None
    dividend, divisor = a.lo, b.lo
    minimum, _ = integer_range(typ)
    if divisor == 0 or (typ.startswith("i") and dividend == minimum and divisor == -1):
        _reject("checked constant division or remainder traps")
    quotient = abs(dividend) // abs(divisor)
    if (dividend < 0) != (divisor < 0):
        quotient = -quotient
    return (quotient if op == "int.div.checked"
            else dividend - quotient * divisor)


def _exact_scalar(op, inputs, typ):
    """Only fold values that are exact in already verified typed HIA SSA.

    Never infer a finite allocation extent from a partial interval, unknown
    argument, throwing arithmetic result, or Python's unbounded integer rules.
    Integer output uses the same fixed-width operations as the canonical VM.
    """
    if op.startswith("compare."):
        a, b = inputs
        if type(a) is bool or type(b) is bool:
            if type(a) is not bool or type(b) is not bool or op not in {
                    "compare.eq", "compare.ne"}:
                return None
            return a == b if op == "compare.eq" else a != b
    spans = [_span(value) for value in inputs]
    if any(span is None or span.lo != span.hi for span in spans):
        return None
    vals = [span.lo for span in spans]

    if op.startswith("compare."):
        a, b = vals
        return {
            "compare.eq": a == b, "compare.ne": a != b,
            "compare.lt": a < b, "compare.le": a <= b,
            "compare.gt": a > b, "compare.ge": a >= b,
        }[op]
    if op == "bit.not":
        return _wrap(~vals[0], typ)
    if op in {"bit.and", "bit.or", "bit.xor"}:
        a, b = vals
        result = (a & b if op == "bit.and" else
                  a | b if op == "bit.or" else a ^ b)
        return _wrap(result, typ)
    # Reuse the stronger interval-aware P1 transfer implementations imported
    # verbatim from the parallel reviewed HIA shift/divrem branch.
    if op in {"int.div.checked", "int.rem.checked"}:
        return _bounded_divrem(op, vals[0], vals[1], typ)
    if op in {"int.shl.checked", "int.shr.checked"}:
        return _bounded_shift(op, vals[0], vals[1], typ)
    return None


def _paths(term: dict) -> list[dict]:
    if term["op"] == "jump":
        return [{"target": term["target"], "args": term["args"]}]
    if term["op"] == "branch":
        return [term["then"], term["else"]]
    return []


def _dag(names, edges, context):
    # Share the established cycle policy rather than weakening it.
    from .hia_static_budget import _topological
    return _topological(names, edges, context)


def _merge(previous, proposed, label):
    """Join HIA edges by maximum possible owner and scalar value bounds."""
    old_owners, old_known, old_loans = previous
    new_owners, new_known, new_loans = proposed
    if old_owners.keys() != new_owners.keys():
        _reject(f"{label}: incompatible owner inventory at a CFG join")
    # The canonical Core checker enforces loan normalization. Repeat the
    # critical root relation here rather than estimating an allocation size
    # using the wrong owner's extent after a CFG join.
    if old_loans != new_loans:
        _reject(f"{label}: incompatible borrowed owner roots")
    owners = {key: max(old_owners[key], new_owners[key]) for key in old_owners}
    known = {}
    for key in old_known.keys() & new_known.keys():
        bound = _combine_known(old_known[key], new_known[key])
        if bound is not None:
            known[key] = bound
    return owners, known, dict(old_loans)


def _typed_entry_bounds(parameters):
    """Intrinsic complete type intervals, including negative signed inputs.

    Successful checked casts can refine negative/oversized operands by
    trapping *before* allocation; they do not assume all callers are positive.
    Full-width 64-bit public parameters remain unknown for this finite-budget
    profile. No sample inputs or external caller promises are trusted.
    """
    return {
        param["name"]: _Span(*integer_range(param["type"]))
        for param in parameters if param["type"] in _SMALL_CAST_DOMAINS
    }

def _function(fn: dict, functions: dict[str, dict], calculated: dict[str, int]) -> int:
    from .hia_program import WIDTHS

    if any(param["type"] in {"buffer", "readbuf", "mutbuf"} for param in fn["params"]):
        _reject(f"{fn['name']}: resource arguments have unbounded external extent")
    if any(t in {"buffer", "readbuf", "mutbuf"} for t in fn["returns"]):
        _reject(f"{fn['name']}: owned return needs a caller-size invariant")
    # P1 zero-heap proof for verifier-accepted scalar CFGs, including loops.
    # No function calls, allocators, buffer accesses, loans, drops, or unknown
    # opcodes are admitted. A loop may be nonterminating; this proves only
    # live HIA payload bytes == 0, NEVER finite VM ticks or CPU time.
    # The caller has already independently run verify_program on *all* blocks.
    if all(ins["op"] in _ZERO_HEAP_CYCLIC_SCALARS
           for block in fn["blocks"] for ins in block["ops"]):
        return 0
    blocks = {b["id"]: b for b in fn["blocks"]}
    edges = {key: {e["target"] for e in _paths(block["term"])}
             for key, block in blocks.items()}
    try:
        order = _dag(list(blocks), edges, f"{fn['name']} heap control flow")
    except ValueError as exc:
        # Preserve the canonical DAG rejection for malformed dependencies,
        # unsupported cyclic allocators, calls or cross-block owner lifetimes.
        # Only the recognized cycle diagnostic may request this strictly
        # limited independent live-heap proof.
        if getattr(exc, "code", None) != "E_HIA_BUDGET_UNBOUNDED":
            raise
        scoped_peak = _scoped_allocating_cycle_peak(fn)
        if scoped_peak is None:
            raise
        return scoped_peak
    # owners: SSA owner -> max requested bytes; known: scalar intervals;
    # loans: live readbuf/mutbuf -> root owner SSA name.
    states = {fn["entry"]: ({}, _typed_entry_bounds(fn["params"]), {})}
    peak = 0
    for name in order:
        if name not in states:
            _reject(f"{fn['name']}: missing reachable CFG input")
        owner, known, loans = (dict(row) for row in states[name])
        block = blocks[name]
        peak = max(peak, sum(owner.values()))
        for ins in block["ops"]:
            op, args, outputs, attrs = ins["op"], ins["args"], ins["out"], ins["attrs"]
            out_names = [p["name"] for p in outputs]
            if op == "const":
                value = attrs["value"]
                if type(value) in {int, bool}:
                    known[out_names[0]] = value
                # unit constants are intentionally not used as sizes.
            elif op in {"int.add.checked", "int.sub.checked", "int.mul.checked",
                        "int.add.wrap", "int.sub.wrap", "int.mul.wrap"}:
                folded = _bounded_binary(op, known.get(args[0]), known.get(args[1]),
                                         outputs[0]["type"])
                if folded is not None:
                    known[out_names[0]] = folded
            elif op == "int.cast":
                folded = _bounded_cast(known.get(args[0]), outputs[0]["type"],
                                       attrs["mode"])
                if folded is not None:
                    known[out_names[0]] = folded
            elif op in {"int.shl.checked", "int.shr.checked"}:
                folded = _bounded_shift(op, known.get(args[0]), known.get(args[1]),
                                        outputs[0]["type"])
                if folded is not None:
                    known[out_names[0]] = folded
            elif op in {"int.div.checked", "int.rem.checked"}:
                folded = _bounded_divrem(op, known.get(args[0]),
                                         known.get(args[1]), outputs[0]["type"])
                if folded is not None:
                    known[out_names[0]] = folded
            elif op in {
                    "bit.not", "bit.and", "bit.or", "bit.xor",
                    "compare.eq", "compare.ne", "compare.lt", "compare.le",
                    "compare.gt", "compare.ge"}:
                folded = _exact_scalar(op, [known.get(arg) for arg in args],
                                       outputs[0]["type"])
                if folded is None and op == "bit.and":
                    # A verified *interval* of nonnegative bit masks is enough
                    # to bound arbitrary typed inputs, not just exact masks.
                    folded = _bounded_nonnegative_and_mask(
                        known.get(args[0]), known.get(args[1]), outputs[0]["type"])
                elif folded is None and op == "bit.not":
                    # Typed fixed-width ones' complement reverses a proven
                    # interval without assuming any particular caller input.
                    folded = _bounded_bitnot(known.get(args[0]), outputs[0]["type"])
                elif folded is None and op in {"bit.or", "bit.xor"}:
                    # Only two independently proven nonnegative intervals
                    # can authorize the finite highest-bit envelope.
                    folded = _bounded_positive_or_xor(
                        known.get(args[0]), known.get(args[1]), outputs[0]["type"])
                if folded is not None:
                    known[out_names[0]] = folded
            elif op == "int.neg.checked":
                # Negation reverses interval endpoints. Propagate ONLY when
                # the complete source interval fits the destination integer
                # type: a partially overflowing interval remains unknown and
                # cannot authorize a subsequent allocation-size budget.
                # In particular -MIN_SIGNED is NOT a representable value.
                operand = _span(known.get(args[0]))
                if operand is not None:
                    lo, hi = -operand.hi, -operand.lo
                    minimum, maximum = integer_range(outputs[0]["type"])
                    if minimum <= lo <= hi <= maximum:
                        known[out_names[0]] = _bounded(lo, hi)
                    elif operand.lo == operand.hi:
                        _reject(f"{fn['name']}/{name}: checked constant negation may trap")
            elif op == "select":
                condition = known.get(args[0])
                folded = (known.get(args[1] if condition else args[2])
                          if type(condition) is bool else
                          _combine_known(known.get(args[1]), known.get(args[2])))
                if folded is not None:
                    known[out_names[0]] = folded
            elif op == "bool.not":
                if type(known.get(args[0])) is bool:
                    known[out_names[0]] = not known[args[0]]
            elif op in {"bool.and", "bool.or"}:
                lhs, rhs = known.get(args[0]), known.get(args[1])
                if type(lhs) is bool and type(rhs) is bool:
                    known[out_names[0]] = lhs and rhs if op == "bool.and" else lhs or rhs
            elif op in {"buffer.new", "buffer.try_new"}:
                size = _span(known.get(args[0]))
                if size is None or size.lo < 0 or size.hi > MAX_REQUEST:
                    _reject(f"{fn['name']}/{name}: allocator extent lacks a finite verified bound")
                # Count the largest successful fallible allocation, never
                # infer that try_new must fail or return only empty storage.
                owner[out_names[0]] = size.hi
                peak = max(peak, sum(owner.values()))
            elif op in {"borrow.read", "borrow.mut"}:
                # A live borrow's length is bounded by the same root owner's
                # allocation, including nested reborrows. Borrow creation
                # does not add payload bytes and never creates ownership.
                source = args[0]
                root = source if source in owner else loans.get(source)
                if root is None or root not in owner:
                    _reject(f"{fn['name']}/{name}: borrowed extent lacks a bounded owner root")
                loans[out_names[0]] = root
            elif op == "loan.end":
                if args[0] not in loans:
                    _reject(f"{fn['name']}/{name}: ending a loan without a bounded root")
                del loans[args[0]]
            elif op == "owner.move":
                if args[0] not in owner or args[0] in loans.values():
                    _reject(f"{fn['name']}/{name}: owner move lacks a free bounded source")
                owner[out_names[0]] = owner.pop(args[0])
            elif op == "owner.drop":
                if args[0] not in owner or args[0] in loans.values():
                    _reject(f"{fn['name']}/{name}: drop lacks a free bounded source")
                owner.pop(args[0])
            elif op == "call":
                child = functions[attrs["function"]]
                if (any(p["type"] in {"buffer", "readbuf", "mutbuf"} for p in child["params"])
                        or any(t in {"buffer", "readbuf", "mutbuf"} for t in child["returns"])):
                    _reject(f"{fn['name']}/{name}: interprocedural resource transfer requires a separate proof")
                if child["name"] not in calculated:
                    _reject(f"{fn['name']}/{name}: callee heap bound not available")
                peak = max(peak, sum(owner.values()) + calculated[child["name"]])
            elif op == "buffer.len":
                # An owner or any checked read/mut reborrow shares its root's
                # allocation extent. A fallible try_new can yield zero bytes,
                # so propagate [0, upper], NEVER an assumed exact maximum.
                root = args[0] if args[0] in owner else loans.get(args[0])
                if root is None or root not in owner:
                    _reject(f"{fn['name']}/{name}: buffer.len lacks a bounded root")
                known[out_names[0]] = _Span(0, owner[root])
            elif op not in _NO_ALLOCATION_OPS:
                _reject(f"{fn['name']}/{name}: unreviewed opcode {op} has no heap accounting")
            # Unreviewed or nonconstant arithmetic stays unknown and cannot
            # subsequently qualify an allocation extent.
        for edge in _paths(block["term"]):
            target = blocks[edge["target"]]
            next_owner, next_known, next_loans = {}, {}, {}
            # Normalize loan-root identities through the SAME block-parameter
            # remapping as verified executable Core. No edge may forge a
            # borrowed length without forwarding its bound owner.
            remap = {source: param["name"]
                     for source, param in zip(edge["args"], target["params"])
                     if param["type"] in {"buffer", "readbuf", "mutbuf"}}
            for source_name, param in zip(edge["args"], target["params"]):
                if param["type"] == "buffer":
                    if source_name not in owner:
                        _reject(f"{fn['name']}/{name}: missing bounded owner at edge")
                    next_owner[param["name"]] = owner[source_name]
                elif param["type"] in {"readbuf", "mutbuf"}:
                    root = loans.get(source_name)
                    if root is None or root not in remap:
                        _reject(f"{fn['name']}/{name}: loan edge lacks its bounded owner")
                    next_loans[param["name"]] = remap[root]
                elif (param["type"] in WIDTHS or param["type"] in {"bool", "unit"}) and source_name in known:
                    next_known[param["name"]] = known[source_name]
            proposed = (next_owner, next_known, next_loans)
            dest = edge["target"]
            states[dest] = (_merge(states[dest], proposed, f"{fn['name']}/{dest}")
                            if dest in states else proposed)
    return peak


def analyze_constant_live_heap(program) -> dict:
    """Bound all function entries; verified program is the *sole* admission.

    The result's integer is a conservative peak of requested live HIA buffer
    payload bytes on normal, nontrapping CFG paths. It never bounds allocator
    metadata, transient OS memory or native process RSS.
    """
    checked = verify_program(program)
    document = checked.as_dict()
    if type(document) is not dict or document.get("schema") not in _ALLOWED_SCHEMAS:
        _reject("unknown HIA executable schema needs a fresh heap-bound review")
    functions = document["functions"]
    by_name = {fn["name"]: fn for fn in functions}
    calls = {fn["name"]: {ins["attrs"]["function"]
                          for block in fn["blocks"] for ins in block["ops"]
                          if ins["op"] == "call"} for fn in functions}
    order = _dag(list(by_name), calls, "HIA heap call graph")
    calculated = {}
    for fn_name in reversed(order):
        calculated[fn_name] = _function(by_name[fn_name], by_name, calculated)
    return {fn["name"]: calculated[fn["name"]] for fn in functions}


def qualify_live_heap_budget(program, *, max_live_heap_bytes: int) -> dict:
    """Admit ONLY a finite requested-live-HIA-byte budget.

    Unlike analyze_static_budget this narrow admission may cover cyclic
    block-scoped buffers, but says nothing about allocation *count*, VM
    steps, termination or process RSS. The immutable reverified Program
    is the sole input to the analyzer; caller-supplied receipts are ignored.
    """
    if (type(max_live_heap_bytes) is not int
            or not 0 <= max_live_heap_bytes <= MAX_REQUEST):
        raise HIAHeapBoundRejected(
            "E_HIA_BUDGET_POLICY",
            "requested-live-payload policy must be an integer in 0..2^63-1")
    checked = verify_program(program)
    peaks = analyze_constant_live_heap(checked)
    bounded = {name: peaks[name] for name in sorted(peaks)}
    exceeded = [name for name, upper in bounded.items()
                if type(upper) is not int or upper < 0 or upper > max_live_heap_bytes]
    if exceeded:
        raise HIAHeapBoundRejected(
            "E_HIA_BUDGET_EXCEEDED",
            "live payload budget is exceeded by " + ", ".join(exceeded))
    return {
        "schema": "hepta.hia.live-heap-admission.v1",
        "status": "standalone_verified_hia_payload_only",
        "program_sha256": checked.sha256,
        "limit_bytes": max_live_heap_bytes,
        "peak_bounds": bounded,
        "claims": {
            "canonical_core_reverified": True,
            "requested_live_payload_bounded": True,
            "source_origin_authenticated": False,
            "allocator_interactions_bounded": False,
            "vm_ticks_bounded": False,
            "process_rss_bounded": False,
            "native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
