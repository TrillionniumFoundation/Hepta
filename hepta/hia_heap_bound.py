"""Finite live payload-byte upper bound for existing verified HIA Core.

This is a strictly opt-in resource-budget analysis, not a second ownership
checker. The canonical HIA verifier provides SSA, typed ownership and CFG
validity. Unknown allocation extents and unqualified call/cycle boundaries
remain rejected instead of importing caller assumptions. The separate v8
public-entry profile reuses this analyzer with borrowed local-peak summaries;
it does not widen the legacy all-function meaning. The bound counts requested
live byte payload, NOT allocator overhead or RSS.
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
# Keep calls, memory operations and borrowed owners out of scope.
# The fallible allocator returns either a valid owner of at most the requested
# size or a logical empty owner. Both must still be linearly consumed.
# Reuse the already-audited typed interval transfer: no second arithmetic oracle.
_SCOPED_CYCLE_INTERVAL_ARITH = frozenset({
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
})
_SCOPED_CYCLE_OPS = _ZERO_HEAP_CYCLIC_SCALARS | frozenset({
    "buffer.new", "buffer.try_new", "owner.move", "owner.drop",
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
        # bounds, independent of caller values. Only constants, the
        # reviewed cast transfer and audited integer interval arithmetic
        # may refine sizes inside this block.
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
            elif op in _SCOPED_CYCLE_INTERVAL_ARITH:
                # Reuse the finite, machine-width, checked-vs-wrapping
                # arithmetic interval transfer already used by the acyclic
                # analyzer. A partially overflowing interval returns unknown.
                # No previous block's inferred value or caller-side assertion
                # is imported; this SSA definition must be in this block.
                folded = _bounded_binary(op, known.get(args[0]), known.get(args[1]),
                                         outputs[0]["type"])
                if folded is not None:
                    known[outputs[0]["name"]] = folded
            elif op in {"buffer.new", "buffer.try_new"}:
                # In this strict local profile, both allocation paths
                # produce exactly one linear owner. try_new additionally
                # returns a scalar success flag, never an owner alias.
                # On failure its owner is empty, so charging the full
                # requested size still bounds every possible execution.
                # Unknown/zero-only extents and all cross-block resources
                # remain conservatively refused.
                expected_outputs = 1 if op == "buffer.new" else 2
                if len(args) != 1 or len(outputs) != expected_outputs:
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
            # Remaining scalar instructions may affect control flow but cannot
            # mint a resource bound without an explicit reviewed transfer.
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


@dataclass(frozen=True)
class _InvocationHeapResult:
    """A context's peak and bounds on its ordinary returned values.

    None for returned means no normal return; a tuple containing None means
    an ordinary return whose scalar value is unknown. Owned values always
    carry an integer extent, including a real zero-byte logical owner.
    """
    peak: int
    returned: tuple | None


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
    owners = {}
    for key, old_bound in old_owners.items():
        new_bound = new_owners[key]
        # Only the explicitly selected borrowed-call profile uses None:
        # an external loan root has an unknown caller-owned extent. It is
        # never interchangeable with a locally allocated owner at a join.
        if (old_bound is None) != (new_bound is None):
            _reject(f"{label}: local owner and external loan roots disagree")
        owners[key] = None if old_bound is None else max(old_bound, new_bound)
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

def _local_payload_bytes(roots: dict[str, int | None]) -> int:
    # None denotes caller-owned storage, not a zero-byte owner. The v8 entry
    # profile adds a callee's additional LOCAL peak to its caller's live local
    # payload. This excludes external payload from private summaries without
    # excluding it from the public entry's total or charging it twice.
    return sum(size for size in roots.values() if size is not None)


def _function(fn: dict, functions: dict[str, dict], calculated: dict[str, int], *,
              borrowed_local_peaks: bool = False, invocation=None,
              argument_bounds: tuple | None = None):
    from .hia_program import WIDTHS

    boundary_resources = {"buffer"} if borrowed_local_peaks else {"buffer", "readbuf", "mutbuf"}
    if invocation is None and any(param["type"] in boundary_resources for param in fn["params"]):
        _reject(f"{fn['name']}: resource arguments have unbounded external extent")
    if invocation is None and any(t in boundary_resources for t in fn["returns"]):
        _reject(f"{fn['name']}: owned return needs a caller-size invariant")
    # P1 zero-heap proof for verifier-accepted scalar CFGs, including loops.
    # No function calls, allocators, buffer accesses, loans, drops, or unknown
    # opcodes are admitted. A loop may be nonterminating; this proves only
    # live HIA payload bytes == 0, NEVER finite VM ticks or CPU time.
    # The caller has already independently run verify_program on *all* blocks.
    if invocation is None and all(ins["op"] in _ZERO_HEAP_CYCLIC_SCALARS
           for block in fn["blocks"] for ins in block["ops"]):
        return 0
    blocks = {b["id"]: b for b in fn["blocks"]}
    edges = {key: {e["target"] for e in _paths(block["term"])}
             for key, block in blocks.items()}
    try:
        order = _dag(list(blocks), edges, f"{fn['name']} heap control flow")
    except ValueError as exc:
        if invocation is not None:
            # The v7 invocation profile requires every CFG to be a DAG. It
            # must not inherit either of the historical cyclic heap profiles.
            raise
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
    # roots: SSA local owner -> max requested bytes, or external loan -> None;
    # known: scalar intervals; loans: readbuf/mutbuf -> root SSA name.
    # An external borrowed root is counted in its caller, never as a new
    # allocation. Its extent stays UNKNOWN; None is not a zero-byte owner.
    external = {p["name"]: None for p in fn["params"]
                if (borrowed_local_peaks or invocation is not None)
                and p["type"] in {"readbuf", "mutbuf"}}
    initial_known = _typed_entry_bounds(fn["params"])
    if invocation is not None:
        if argument_bounds is None or len(argument_bounds) != len(fn["params"]):
            _reject(f"{fn['name']}: finite invocation argument inventory differs")
        for param, bound in zip(fn["params"], argument_bounds):
            if param["type"] == "buffer":
                if type(bound) is not int or not 0 <= bound <= MAX_REQUEST:
                    _reject(f"{fn['name']}: owned argument needs a proved finite extent")
                external[param["name"]] = bound
            elif param["type"] in {"readbuf", "mutbuf"}:
                if bound is not None:
                    _reject(f"{fn['name']}: external borrowed extent promises are not admitted")
            elif bound is not None:
                initial_known[param["name"]] = bound
    # Owned parameters are roots but are not loans. External loan formals are
    # the only self-rooted views in this existing abstract state representation.
    initial_loans = {p["name"]: p["name"] for p in fn["params"]
                     if p["type"] in {"readbuf", "mutbuf"} and p["name"] in external}
    states = {fn["entry"]: (external, initial_known, initial_loans)}
    peak = 0
    returned = None
    for name in order:
        if invocation is not None:
            invocation.step()
        if name not in states:
            if invocation is not None:
                # A preceding call or independently proved allocation trap
                # ends this path. This is not a supplied reachability premise.
                continue
            _reject(f"{fn['name']}: missing reachable CFG input")
        owner, known, loans = (dict(row) for row in states[name])
        block = blocks[name]
        peak = max(peak, _local_payload_bytes(owner))
        path_stopped = False
        for ins in block["ops"]:
            if invocation is not None:
                invocation.step()
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
                if invocation is not None and size is not None and size.lo > MAX_REQUEST:
                    # Canonical v7's object-size guard runs before the heap
                    # policy or allocator attempt. For the ENTIRE interval
                    # above that guard, try_new returns a real empty owner
                    # plus false; new traps without creating an owner. Keep
                    # all earlier live bytes in the prefix peak. This exact
                    # semantic guard does not admit unknown/crossing extents
                    # or change either historical all-function/v8 profile.
                    if op == "buffer.new":
                        path_stopped = True
                        break
                    owner[out_names[0]] = 0
                    known[out_names[1]] = False
                    continue
                if size is None or size.lo < 0 or size.hi > MAX_REQUEST:
                    _reject(f"{fn['name']}/{name}: allocator extent lacks a finite verified bound")
                # Below the semantic guard, count the largest successful
                # request; never assume a host/injected allocator failure.
                owner[out_names[0]] = size.hi
                peak = max(peak, _local_payload_bytes(owner))
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
                if args[0] not in owner or owner[args[0]] is None or args[0] in loans.values():
                    _reject(f"{fn['name']}/{name}: owner move lacks a free bounded source")
                owner[out_names[0]] = owner.pop(args[0])
            elif op == "owner.drop":
                if args[0] not in owner or owner[args[0]] is None or args[0] in loans.values():
                    _reject(f"{fn['name']}/{name}: drop lacks a free bounded source")
                owner.pop(args[0])
            elif op == "call":
                child = functions[attrs["function"]]
                if invocation is not None:
                    actual_bounds, transferred = [], []
                    for param, actual in zip(child["params"], args):
                        if param["type"] == "buffer":
                            if (actual not in owner or owner[actual] is None
                                    or actual in loans.values() or actual in transferred):
                                _reject(f"{fn['name']}/{name}: call lacks a free bounded owned argument")
                            actual_bounds.append(owner[actual])
                            transferred.append(actual)
                        elif param["type"] in {"readbuf", "mutbuf"}:
                            root = loans.get(actual)
                            if root is None or root not in owner:
                                _reject(f"{fn['name']}/{name}: borrowed call lacks its retained caller root")
                            actual_bounds.append(None)
                        else:
                            actual_bounds.append(known.get(actual))
                    # Ownership moves to the callee. Its peak already includes
                    # these bytes; adding the old caller sum would double count
                    # them. Borrowed actuals leave their caller roots untouched.
                    for actual in transferred:
                        owner.pop(actual)
                    result = invocation.invoke(child, tuple(actual_bounds))
                    peak = max(peak, _local_payload_bytes(owner) + result.peak)
                    if result.returned is None:
                        path_stopped = True
                        break
                    if len(result.returned) != len(outputs):
                        _reject(f"{fn['name']}/{name}: callee return inventory differs")
                    for output, bound in zip(outputs, result.returned):
                        if output["type"] == "buffer":
                            if type(bound) is not int or not 0 <= bound <= MAX_REQUEST:
                                _reject(f"{fn['name']}/{name}: returned owner lacks a bounded extent")
                            owner[output["name"]] = bound
                        elif output["type"] in {"readbuf", "mutbuf"}:
                            _reject(f"{fn['name']}/{name}: v7 invocation cannot return a loan")
                        elif bound is not None:
                            known[output["name"]] = bound
                    # Independent per-position joins may overestimate correlated
                    # returned owners, but may never erase their payload bytes.
                    peak = max(peak, _local_payload_bytes(owner))
                elif (any(p["type"] in boundary_resources for p in child["params"])
                        or any(t in boundary_resources for t in child["returns"])):
                    _reject(f"{fn['name']}/{name}: interprocedural resource transfer requires a separate proof")
                elif child["name"] not in calculated:
                    _reject(f"{fn['name']}/{name}: callee heap bound not available")
                elif invocation is None:
                    peak = max(peak, _local_payload_bytes(owner) + calculated[child["name"]])
                if invocation is None and borrowed_local_peaks:
                    bindings = {p["name"]: argument for p, argument in zip(child["params"], args)}
                    # Canonical Core has already checked all return origins,
                    # permissions and parent suspension. Reuse that declared
                    # caller relation for extent tracking, not a guessed fresh
                    # allocation or an independently fabricated provenance.
                    for output, origin in zip(outputs, child.get("return_loans", [None] * len(outputs))):
                        if output["type"] in {"readbuf", "mutbuf"}:
                            source = bindings.get(origin)
                            root = loans.get(source)
                            if root is None or root not in owner:
                                _reject(f"{fn['name']}/{name}: returned loan lacks its caller root")
                            loans[output["name"]] = root
            elif op == "buffer.len":
                # An owner or any checked read/mut reborrow shares its root's
                # allocation extent. A fallible try_new can yield zero bytes,
                # so propagate [0, upper], NEVER an assumed exact maximum.
                root = args[0] if args[0] in owner else loans.get(args[0])
                if root is None or root not in owner:
                    _reject(f"{fn['name']}/{name}: buffer.len lacks a bounded root")
                if owner[root] is not None:
                    known[out_names[0]] = _Span(0, owner[root])
            elif op not in _NO_ALLOCATION_OPS:
                _reject(f"{fn['name']}/{name}: unreviewed opcode {op} has no heap accounting")
            # Unreviewed or nonconstant arithmetic stays unknown and cannot
            # subsequently qualify an allocation extent.
        if path_stopped:
            continue
        if invocation is not None:
            invocation.step()
            if block["term"]["op"] == "ret":
                values = []
                for typ, value in zip(fn["returns"], block["term"]["values"]):
                    if typ == "buffer":
                        if value not in owner or owner[value] is None:
                            _reject(f"{fn['name']}/{name}: returned owner has no bounded root")
                        values.append(owner[value])
                    elif typ in {"readbuf", "mutbuf"}:
                        _reject(f"{fn['name']}/{name}: v7 borrowed returns are unsupported")
                    else:
                        values.append(known.get(value))
                if returned is None:
                    returned = tuple(values)
                else:
                    returned = tuple(max(old, new) if typ == "buffer"
                                     else _combine_known(old, new)
                                     for typ, old, new in zip(fn["returns"], returned, values))
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
                    if source_name not in owner or owner[source_name] is None:
                        _reject(f"{fn['name']}/{name}: missing bounded owner at edge")
                    next_owner[param["name"]] = owner[source_name]
                elif param["type"] in {"readbuf", "mutbuf"}:
                    root = loans.get(source_name)
                    if root is None or root not in remap:
                        _reject(f"{fn['name']}/{name}: loan edge lacks its bounded owner")
                    next_loans[param["name"]] = remap[root]
                    if owner[root] is None:
                        next_owner[remap[root]] = None
                elif (param["type"] in WIDTHS or param["type"] in {"bool", "unit"}) and source_name in known:
                    next_known[param["name"]] = known[source_name]
            proposed = (next_owner, next_known, next_loans)
            dest = edge["target"]
            states[dest] = (_merge(states[dest], proposed, f"{fn['name']}/{dest}")
                            if dest in states else proposed)
    return _InvocationHeapResult(peak, returned) if invocation is not None else peak


_FINITE_MAX_CONTEXTS = 1024
_FINITE_MAX_TRANSFER_STEPS = 32768
_FINITE_MAX_ANALYSIS_DEPTH = 64


class _FiniteInvocationAnalysis:
    """Bounded context specialization of the same interval/owner transfer.

    The canonical verifier and the static v7 profile have already checked the
    entire module and both graphs. Exact abstract arguments form the memo key;
    private owned extents come only from that caller's proved live roots.
    These independent limits also cover acyclic programs with exponentially
    many distinct call contexts. Hitting a limit is UNKNOWN, never a bound.
    """
    def __init__(self, functions):
        self.functions = functions
        self.cache = {}
        self.contexts = self.transfer_steps = self.depth = self.peak_depth = 0

    def step(self):
        self.transfer_steps += 1
        if self.transfer_steps > _FINITE_MAX_TRANSFER_STEPS:
            raise HIAHeapBoundRejected("E_HIA_BUDGET_LIMIT",
                                       "finite invocation abstract-transfer work limit exceeded")

    def invoke(self, fn, argument_bounds):
        key = (fn["name"], argument_bounds)
        if key in self.cache:
            return self.cache[key]
        if (self.contexts >= _FINITE_MAX_CONTEXTS
                or self.depth >= _FINITE_MAX_ANALYSIS_DEPTH):
            raise HIAHeapBoundRejected("E_HIA_BUDGET_LIMIT",
                                       "finite invocation context/depth analysis limit exceeded")
        self.contexts += 1
        self.depth += 1
        self.peak_depth = max(self.peak_depth, self.depth)
        try:
            result = _function(fn, self.functions, {}, invocation=self,
                               argument_bounds=argument_bounds)
        finally:
            self.depth -= 1
        self.cache[key] = result
        return result


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


def qualify_entry_live_heap_budget(program, function: str, *, max_live_heap_bytes: int) -> dict:
    """Bound one scalar public v8 entry across borrowed-call boundaries.

    Reuse the existing interval/CFG analyzer with a distinct local-peak
    summary meaning. Caller-owned loan roots have UNKNOWN extents, not zero
    lengths. Private summaries count only their additional local payload;
    at each call that peak is added to the caller's still-live local owners.
    The public scalar entry has no external resource inputs, so its local
    peak is a bound on the total live HIA byte payload for that invocation.

    Owned call inputs/results, chains, recursion and allocations depending on
    unbounded external lengths remain unqualified. Return contracts are
    checked by canonical Core and used only to retain caller-root extents.
    The existing all-function v1 heap admission is deliberately unchanged.
    """
    from hashlib import sha256
    import json
    from .hia_static_budget import _audit_v8_resource_profile

    if (type(max_live_heap_bytes) is not int
            or not 0 <= max_live_heap_bytes <= MAX_REQUEST
            or type(function) is not str):
        raise HIAHeapBoundRejected(
            "E_HIA_BUDGET_POLICY",
            "entry requires a function name and integer payload policy in 0..2^63-1")
    checked = verify_program(program)
    document = checked.as_dict()
    _audit_v8_resource_profile(document, allow_chain=False)
    if function not in checked.scalar_entrypoints:
        raise HIAHeapBoundRejected(
            "E_HIA_BUDGET_PROFILE", "payload entry must be an admitted public scalar function")
    functions = document["functions"]
    by_name = {fn["name"]: fn for fn in functions}
    calls = {fn["name"]: {instruction["attrs"]["function"]
                          for block in fn["blocks"] for instruction in block["ops"]
                          if instruction["op"] == "call"} for fn in functions}
    order = _dag(list(by_name), calls, "v8 borrowed-call heap graph")
    calculated = {}
    for name in reversed(order):
        calculated[name] = _function(by_name[name], by_name, calculated,
                                     borrowed_local_peaks=True)
    peak = calculated[function]
    if peak > max_live_heap_bytes:
        raise HIAHeapBoundRejected(
            "E_HIA_BUDGET_EXCEEDED", f"{function}: live payload entry bound exceeds policy")
    report = {
        "schema": "hepta.hia.entry-live-heap-admission.v1",
        "profile": "borrowed-call-local-peaks-v8",
        "status": "qualified_public_entry_requested_payload_only",
        "core_schema": document["schema"],
        "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256,
        "function": function,
        "limit_bytes": max_live_heap_bytes,
        "peak_bound_bytes": peak,
        "local_peak_summaries": [
            {"function": fn["name"], "max_additional_local_payload_bytes": calculated[fn["name"]]}
            for fn in functions
        ],
        "claims": {
            "canonical_core_and_return_origins_reverified": True,
            "public_entry_total_requested_payload_bounded": True,
            "callee_external_payload_excluded_from_local_summaries": True,
            "all_private_entry_total_payload_bounded": False,
            "caller_values_or_external_extent_promises_trusted": False,
            "owned_call_transfer_or_chain_storage_bounded": False,
            "allocator_interactions_or_vm_ticks_bounded": False,
            "termination_or_unwinding_proved": False,
            "process_rss_or_native_stack_bytes_bounded": False,
            "source_or_native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    report["sha256"] = sha256(raw).hexdigest()
    return report


def qualify_finite_entry_live_heap_budget(program, function: str, arguments, *,
                                         max_live_heap_bytes: int) -> dict:
    """Bound one exact scalar invocation of acyclic, chain-free primitive v7.

    This is deliberately a separate contract from both historical all-function
    heap admission and v8 borrowed-local summaries. Private owners may move
    into and out of calls: the existing transfer tracks their finite extents
    and returned scalar intervals in a bounded, memoized calling context.
    Borrowed actuals keep their root payload in the caller; their callee-local
    root is UNKNOWN and is never used as a zero or exact allocation extent.

    Every syntactic branch is conservatively included. Thus the bound covers
    allocation failure, explicit cleanup, traps and execution-budget prefixes;
    it neither proves branch reachability nor promises cleanup after a stop.
    The exact scalar arguments are part of the certificate, not a claim over
    every input value or arbitrary external resource extents.
    """
    from hashlib import sha256
    import json
    from .hia_program import scalar_value_valid
    from .hia_static_budget import (HIAStaticBudgetRejected, analyze_static_budget,
                                    _audit_v7_byte_resource_profile)

    if (type(max_live_heap_bytes) is not int
            or not 0 <= max_live_heap_bytes <= MAX_REQUEST):
        raise HIAHeapBoundRejected("E_HIA_BUDGET_POLICY",
                                   "finite invocation payload policy must be an integer in 0..2^63-1")
    checked = verify_program(program)
    document = checked.as_dict()
    try:
        _audit_v7_byte_resource_profile(document)
        # Reuse the reviewed all-function per-op event audit and strict DAG
        # checks. In particular a pure scalar or block-scoped allocating cycle
        # cannot inherit the legacy live-heap-only acceptance here.
        static = analyze_static_budget(checked)
    except HIAStaticBudgetRejected as error:
        raise HIAHeapBoundRejected(error.code, str(error)) from error
    if (type(function) is not str or function not in checked.scalar_entrypoints
            or type(arguments) not in (list, tuple)):
        raise HIAHeapBoundRejected("E_HIA_BUDGET_INPUT",
                                   "finite invocation requires a public scalar entry and exact arguments")
    # Capture caller-owned containers once. Validation, contextual transfer
    # and the certificate must describe these same immutable scalar values,
    # even if the caller changes its original list while analysis is running.
    arguments = tuple(arguments)
    functions = {fn["name"]: fn for fn in document["functions"]}
    fn = functions[function]
    if (len(arguments) != len(fn["params"])
            or any(not scalar_value_valid(value, param["type"])
                   for param, value in zip(fn["params"], arguments))):
        raise HIAHeapBoundRejected("E_HIA_BUDGET_INPUT",
                                   "entry arguments are not exactly typed machine values")
    analysis = _FiniteInvocationAnalysis(functions)
    try:
        result = analysis.invoke(fn, arguments)
    except HIAStaticBudgetRejected as error:
        raise HIAHeapBoundRejected(error.code, str(error)) from error
    if result.peak > max_live_heap_bytes:
        raise HIAHeapBoundRejected("E_HIA_BUDGET_EXCEEDED",
                                   f"{function}: finite invocation payload bound exceeds policy")
    static_row = next(row for row in static["functions"] if row["function"] == function)
    report = {
        "schema": "hepta.hia.finite-entry-live-heap-admission.v1",
        "profile": "acyclic-byte-owner-transfer-v7",
        "status": "qualified_exact_scalar_invocation_requested_payload_only",
        "core_schema": document["schema"],
        "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256,
        "function": function,
        "arguments": list(arguments),
        "limit_bytes": max_live_heap_bytes,
        "peak_bound_bytes": result.peak,
        "max_vm_ticks": static_row["max_vm_ticks"],
        "max_allocator_interactions": static_row["max_allocator_interactions"],
        "max_call_depth": static_row["max_call_depth"],
        "static_budget_sha256": static["sha256"],
        "analysis_work": {
            "contexts": analysis.contexts,
            "transfer_steps": analysis.transfer_steps,
            "peak_analysis_call_depth": analysis.peak_depth,
            "max_contexts": _FINITE_MAX_CONTEXTS,
            "max_transfer_steps": _FINITE_MAX_TRANSFER_STEPS,
            "max_analysis_call_depth": _FINITE_MAX_ANALYSIS_DEPTH,
        },
        "claims": {
            "canonical_core_reverified": True,
            "whole_module_acyclic_byte_profile_checked": True,
            "exact_scalar_invocation_only": True,
            "owned_call_transfer_accounted": True,
            "external_borrow_payload_counted_in_caller": True,
            "allocation_failure_and_stop_prefixes_in_bound": True,
            "all_function_input_extents_bounded": False,
            "caller_supplied_resource_extents_trusted": False,
            "branch_reachability_proved": False,
            "cleanup_after_trap_or_budget_stop_proved": False,
            "recursive_chain_storage_bounded": False,
            "process_rss_or_native_stack_bytes_bounded": False,
            "source_or_native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    report["sha256"] = sha256(raw).hexdigest()
    return report


# This profile counts newly requested payload over a complete entry invocation,
# instead of tracking the live extent of each owner. It deliberately does NOT
# extend any historical/native admission above. Resource-accessing loops are
# permitted only when their entire call closure has no allocator opcode.
_ENTRY_PAYLOAD_V1_SCALARS = frozenset({
    "i8", "i16", "i32", "i64", "isize", "u8", "u16", "u32", "u64", "usize",
    "bool", "unit",
})
_ENTRY_PAYLOAD_V1_TYPES = _ENTRY_PAYLOAD_V1_SCALARS | {"buffer", "readbuf", "mutbuf"}
_ENTRY_PAYLOAD_V1_ALLOCATORS = frozenset({"buffer.new", "buffer.try_new"})
_ENTRY_PAYLOAD_V1_OPS = frozenset({
    "const", "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or", "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap", "int.div.checked", "int.rem.checked",
    "int.shl.checked", "int.shr.checked", "buffer.new", "buffer.try_new", "buffer.len",
    "borrow.read", "borrow.mut", "loan.end", "owner.move", "owner.drop",
    "buffer.load", "buffer.store", "call",
})


def _payload_components(edges: dict[str, set[str]]) -> list[list[str]]:
    """Exact CFG SCCs, with iterative traversals bounded by the verified graph.

    Merely keeping Kahn's unremoved nodes would incorrectly label a cycle's
    acyclic exit as cyclic. Kosaraju's two traversals distinguish that exit.
    Neither traversal consumes Python call-stack depth proportional to the CFG.
    """
    seen, finished = set(), []
    reverse = {name: set() for name in edges}
    for source, targets in edges.items():
        for target in targets:
            reverse[target].add(source)
    for start in sorted(edges):
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(sorted(edges[start])))]
        while stack:
            name, targets = stack[-1]
            target = next(targets, None)
            if target is None:
                finished.append(name)
                stack.pop()
            elif target not in seen:
                seen.add(target)
                stack.append((target, iter(sorted(edges[target]))))
    seen, components = set(), []
    for start in reversed(finished):
        if start in seen:
            continue
        seen.add(start)
        pending, component = [start], []
        while pending:
            name = pending.pop()
            component.append(name)
            for source in sorted(reverse[name]):
                if source not in seen:
                    seen.add(source)
                    pending.append(source)
        components.append(sorted(component))
    return sorted(components)


def analyze_entry_payload_bound(program, function: str) -> dict:
    """Bound v1 scalar-entry allocation requests and logical byte payload.

    Reverify the actual Core; audit every definition against a closed v1
    inventory; reject recursion, nonlocal/dynamic sizes and allocator-bearing
    operations/calls in CFG cycles. Each remaining allocating block executes
    at most once per invocation. Sum all branch sites and callee summaries,
    counting each syntactic call site separately. No branch feasibility,
    termination, destructor completion or incoming private-owner extent is
    assumed. A scalar entry starts without external owners, so live payload
    is at most the cumulative requested payload at every finite trace prefix.

    This is a checkable structural analysis conditional on the canonical Core
    checker and its operational semantics, not a language-soundness theorem or
    a native optimization/installation authority. Existing budget admissions
    retain their previous acceptance domains.
    """
    from hashlib import sha256
    import json
    from .hia_static_budget import HIAStaticBudgetRejected

    checked = verify_program(program)
    document = checked.as_dict()
    if (document["schema"] != "hepta.hia.program.v1"
            or checked.structured_bytes is not None):
        raise HIAHeapBoundRejected("E_HIA_BUDGET_PROFILE",
                                   "entry payload analysis requires primitive Core v1")
    functions = {fn["name"]: fn for fn in document["functions"]}
    if (type(function) is not str or function not in checked.scalar_entrypoints
            or function not in functions
            or any(p["type"] not in _ENTRY_PAYLOAD_V1_SCALARS
                   for p in functions[function]["params"])
            or any(t not in _ENTRY_PAYLOAD_V1_SCALARS
                   for t in functions[function]["returns"])):
        raise HIAHeapBoundRejected("E_HIA_BUDGET_INPUT",
                                   "payload bound requires an admitted public scalar entry")
    calls = {}
    for name, fn in functions.items():
        calls[name] = set()
        declared = [p["type"] for p in fn["params"]] + fn["returns"]
        for block in fn["blocks"]:
            declared.extend(p["type"] for p in block["params"])
            if block["term"]["op"] not in {"ret", "trap", "jump", "branch"}:
                raise HIAHeapBoundRejected("E_HIA_BUDGET_PROFILE", "unreviewed v1 terminator")
            for ins in block["ops"]:
                if ins["op"] not in _ENTRY_PAYLOAD_V1_OPS:
                    raise HIAHeapBoundRejected("E_HIA_BUDGET_PROFILE",
                                               f"{name}: unreviewed v1 payload opcode")
                declared.extend(p["type"] for p in ins["out"])
                if ins["op"] == "call":
                    calls[name].add(ins["attrs"]["function"])
        if any(typ not in _ENTRY_PAYLOAD_V1_TYPES for typ in declared):
            raise HIAHeapBoundRejected("E_HIA_BUDGET_PROFILE", f"{name}: unreviewed v1 type")
    # Validate the whole module, including unused private definitions. No
    # producer purity flag/effect declaration substitutes for examining bodies.
    try:
        order = _dag(list(functions), calls, "entry payload call graph")
    except HIAStaticBudgetRejected as error:
        raise HIAHeapBoundRejected(error.code, str(error)) from error
    summaries = {}
    for name in reversed(order):
        fn = functions[name]
        edges = {block["id"]: {edge["target"] for edge in _paths(block["term"])}
                 for block in fn["blocks"]}
        cyclic = [part for part in _payload_components(edges)
                  if len(part) > 1 or part[0] in edges[part[0]]]
        cycle_nodes = {node for part in cyclic for node in part}
        op_count = requests = requested_bytes = 0
        has_allocator, blocks = False, []
        for block in fn["blocks"]:
            constants, allocation_sites, call_sites = {}, [], []
            for index, ins in enumerate(block["ops"]):
                opcode = ins["op"]
                if opcode == "const" and ins["out"][0]["type"] == "usize":
                    constants[ins["out"][0]["name"]] = (index, ins["attrs"]["value"])
                elif opcode in _ENTRY_PAYLOAD_V1_ALLOCATORS:
                    if block["id"] in cycle_nodes:
                        _reject(f"{name}/{block['id']}: allocator opcode in a CFG cycle")
                    extent = constants.get(ins["args"][0])
                    if extent is None or type(extent[1]) is not int or not 0 <= extent[1] <= MAX_REQUEST:
                        _reject(f"{name}/{block['id']}: allocation size needs an earlier same-block "
                                "const usize in 0..2^63-1")
                    const_index, size = extent
                    has_allocator = True
                    op_count += 1
                    # The existing Core runtime skips the allocator for size 0.
                    requests += int(size > 0)
                    requested_bytes += size
                    allocation_sites.append({"op_index": index, "opcode": opcode,
                                             "size_value": ins["args"][0],
                                             "const_op_index": const_index,
                                             "constant_bytes": size})
                elif opcode == "call":
                    callee = ins["attrs"]["function"]
                    child = summaries[callee]
                    if block["id"] in cycle_nodes and child["contains_allocator_opcode"]:
                        _reject(f"{name}/{block['id']}: CFG cycle calls allocator-bearing {callee}")
                    has_allocator |= child["contains_allocator_opcode"]
                    for key in ("max_allocation_op_executions", "max_nonzero_allocation_requests",
                                "max_cumulative_requested_payload_bytes"):
                        # Cyclic calls can execute unboundedly, but their
                        # independently calculated allocation summaries are 0.
                        if block["id"] in cycle_nodes and child["bounds"][key] != 0:
                            _reject(f"{name}/{block['id']}: nonzero cyclic call payload summary")
                    op_count += child["bounds"]["max_allocation_op_executions"]
                    requests += child["bounds"]["max_nonzero_allocation_requests"]
                    requested_bytes += child["bounds"]["max_cumulative_requested_payload_bytes"]
                    call_sites.append({"op_index": index, "function": callee})
            blocks.append({"block": block["id"], "successors": sorted(edges[block["id"]]),
                           "cyclic": block["id"] in cycle_nodes,
                           "allocation_sites": allocation_sites, "call_sites": call_sites})
        summaries[name] = {
            "function": name, "entry_block": fn["entry"],
            "contains_allocator_opcode": has_allocator,
            "bounds": {"max_allocation_op_executions": op_count,
                       "max_nonzero_allocation_requests": requests,
                       "max_cumulative_requested_payload_bytes": requested_bytes},
            "cyclic_components": cyclic, "blocks": blocks,
        }
    entry_bounds = dict(summaries[function]["bounds"])
    entry_bounds["max_live_payload_bytes"] = entry_bounds["max_cumulative_requested_payload_bytes"]
    report = {
        "schema": "hepta.hia.entry-payload-analysis.v1",
        "profile": "primitive-v1-local-constant-allocation-free-cycles",
        "status": "checked_static_payload_bound_not_runtime_admission",
        "core_schema": document["schema"], "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256, "function": function,
        "entry_bounds": entry_bounds,
        "call_graph": {name: sorted(calls[name]) for name in sorted(calls)},
        "callee_first_order": list(reversed(order)),
        "function_summaries": [summaries[name] for name in sorted(summaries)],
        "claims": {
            "canonical_core_reverified": True,
            "entire_module_closed_v1_profile_checked": True,
            "all_typed_scalar_inputs_and_allocation_outcomes": True,
            "finite_trace_prefixes_including_trap_and_budget_stop": True,
            "private_summaries_count_only_new_requests": True,
            "owner_transfer_not_counted_as_new_allocation": True,
            "branch_feasibility_or_tightest_bound_proved": False,
            "private_external_owner_extents_bounded": False,
            "termination_or_cleanup_after_abort_proved": False,
            "free_calls_vm_ticks_or_owner_metadata_bounded": False,
            "native_stack_allocator_overhead_or_rss_bounded": False,
            "source_or_native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
            "native_runtime_or_optimizer_admission_authority": False,
        },
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    report["sha256"] = sha256(raw).hexdigest()
    return report
