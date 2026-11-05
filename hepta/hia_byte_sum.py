"""Closed native vectorization for a pure forward wrapping byte-sum loop.

The complete Core is verified before this structural matcher runs. It never
authorizes a checked addition, a changed stride, a write/call, or a different
backedge transport. The original Core and its checked fallback stay unchanged.

On the existing x86_64 target, SSE2's two unsigned eight-byte sums implement
sixteen additions modulo 2**64. A vector read is reached only when both the loop
bound and actual buffer extent contain all sixteen bytes. Other targets and
unrecognized loops keep the ordinary scalar emitter. This remains part of the
trusted LLVM backend, not a machine-checked backend-refinement theorem.
"""
from __future__ import annotations

LANES = 16
INTRINSIC = "llvm.x86.sse2.psad.bw"


def _one(operation, opcode, typ, arguments=None, attrs=None):
    if (operation["op"] != opcode or len(operation["out"]) != 1
            or operation["out"][0]["type"] != typ
            or operation["attrs"] != ({} if attrs is None else attrs)
            or (arguments is not None and operation["args"] != arguments)):
        return None
    return operation["out"][0]["name"]


def _successors(block):
    term = block["term"]
    if term["op"] == "jump":
        return [term["target"]]
    if term["op"] == "branch":
        return [term["then"]["target"], term["else"]["target"]]
    return []


def _plans(function):
    blocks = {b["id"]: b for b in function["blocks"]}
    if len(blocks) != len(function["blocks"]):
        return {}
    predecessors = {name: [] for name in blocks}
    for block in function["blocks"]:
        for target in _successors(block):
            predecessors[target].append(block["id"])
    plans = {}
    for header in function["blocks"]:
        if len(header["ops"]) != 1 or header["term"]["op"] != "branch":
            continue
        hp = header["params"]
        hn = [p["name"] for p in hp]
        comparison = header["ops"][0]
        condition = _one(comparison, "compare.lt", "bool")
        term = header["term"]
        if (condition is None or len(comparison["args"]) != 2
                or term["cond"] != condition or term["then"]["args"] != hn):
            continue
        first, stop = comparison["args"]
        if first not in hn or stop not in hn or first == stop:
            continue
        ip, np = hn.index(first), hn.index(stop)
        if hp[ip]["type"] != "usize" or hp[np]["type"] != "usize":
            continue
        body = blocks[term["then"]["target"]]
        if (body["id"] == function["entry"] or predecessors[body["id"]] != [header["id"]]
                or len(body["ops"]) != 7
                or [p["type"] for p in body["params"]] != [p["type"] for p in hp]):
            continue
        bp = body["params"]
        bn = [p["name"] for p in bp]
        operations = body["ops"]
        borrow, load, end, widen, add, one, advance = operations
        if len(borrow["args"]) != 1 or borrow["args"][0] not in bn:
            continue
        owner = borrow["args"][0]
        if bp[bn.index(owner)]["type"] != "buffer":
            continue
        loan = _one(borrow, "borrow.read", "readbuf", [owner])
        byte = _one(load, "buffer.load", "u8", [loan, bn[ip]])
        wide = _one(widen, "int.cast", "u64", [byte], {"mode": "wrap"})
        if (loan is None or byte is None or wide is None
                or end != {"op": "loan.end", "args": [loan], "out": [], "attrs": {}}
                or len(add["args"]) != 2 or add["args"][0] not in bn):
            continue
        total = add["args"][0]
        ap = bn.index(total)
        if bp[ap]["type"] != "u64":
            continue
        summed = _one(add, "int.add.wrap", "u64", [total, wide])
        increment = _one(one, "const", "usize", [], {"value": 1})
        if increment is None or type(one["attrs"]["value"]) is not int:
            continue
        advanced = _one(advance, "int.add.wrap", "usize", [bn[ip], increment])
        if summed is None or advanced is None:
            continue
        backedge = list(bn)
        backedge[ap], backedge[ip] = summed, advanced
        if body["term"] != {"op": "jump", "target": header["id"], "args": backedge}:
            continue
        plans[body["id"]] = {"owner": owner, "index": bn[ip], "limit": bn[np],
                            "accumulator": total, "sum_result": summed,
                            "index_result": advanced, "header": header["id"]}
    return plans


def byte_sum_plans(function):
    """Fail closed for every CFG outside the exact side-effect-free loop body."""
    try:
        return _plans(function)
    except (KeyError, IndexError, TypeError, ValueError):
        return {}


def render_byte_sum(emitter, block, plan):
    """Consume a vector prefix, then a separate fixed-stride scalar tail.

    The original header/body is a pure wrapping reduction with identity
    transport. Its complete remaining iterations may therefore be grouped.
    The scalar tail is never sent back through the vector range checks.
    """
    e = emitter
    original_values = dict(e.values)
    owner = e.argument(plan["owner"])[0]
    index = e.argument(plan["index"])[0]
    limit = e.argument(plan["limit"])[0]
    accumulator = e.argument(plan["accumulator"])[0]
    pointer, extent = e.buffer_parts(owner)
    prefix = e.lines

    e.serial += 1
    suffix = str(e.serial)
    start = "byte_sum_start_" + suffix
    vector_head = "byte_sum_vector_head_" + suffix
    vector_body = "byte_sum_vector_body_" + suffix
    scalar_head = "byte_sum_scalar_head_" + suffix
    scalar_body = "byte_sum_scalar_body_" + suffix
    scalar_done = "byte_sum_scalar_done_" + suffix
    finished = "byte_sum_finished_" + suffix
    vector_index_phi, vector_sum_phi = e.tmp(), e.tmp()
    scalar_index_phi, scalar_sum_phi = e.tmp(), e.tmp()

    # Render both bodies first so their exact SSA backedge values are known
    # before composing the two header phis. Named SSA values may be forward
    # references on a backedge; the normal module regeneration still checks
    # every emitted byte before Clang receives it.
    e.lines = []
    address = e.instruction("getelementptr i8, ptr " + pointer + ", i64 " + vector_index_phi)
    lanes = e.instruction("load <16 x i8>, ptr " + address + ", align 1")
    pair = e.instruction("call <2 x i64> @" + INTRINSIC +
                         "(<16 x i8> " + lanes + ", <16 x i8> zeroinitializer)")
    left = e.instruction("extractelement <2 x i64> " + pair + ", i32 0")
    right = e.instruction("extractelement <2 x i64> " + pair + ", i32 1")
    subtotal = e.instruction("add i64 " + left + ", " + right)
    vector_sum = e.instruction("add i64 " + vector_sum_phi + ", " + subtotal)
    vector_index = e.instruction("add i64 " + vector_index_phi + ", 16")
    vector_lines = list(e.lines)

    e.lines = []
    e.values = dict(original_values)
    e.values[plan["index"]] = (scalar_index_phi, "usize")
    e.values[plan["accumulator"]] = (scalar_sum_phi, "u64")
    for operation in block["ops"]:
        e.operation(operation)
    scalar_sum = e.argument(plan["sum_result"])[0]
    scalar_index = e.argument(plan["index_result"])[0]
    scalar_lines = list(e.lines)

    e.lines = prefix
    e.line("br label %" + start)
    e.lines.append(start + ":")
    e.line("br label %" + vector_head)
    e.lines.append(vector_head + ":")
    e.line(vector_index_phi + " = phi i64 [ " + index + ", %" + start +
           " ], [ " + vector_index + ", %" + vector_body + " ]")
    e.line(vector_sum_phi + " = phi i64 [ " + accumulator + ", %" + start +
           " ], [ " + vector_sum + ", %" + vector_body + " ]")

    def contains_chunk(bound):
        # Ordered comparison prevents wrapped subtraction from granting a read.
        ordered = e.instruction("icmp ule i64 " + vector_index_phi + ", " + bound)
        remaining = e.instruction("sub i64 " + bound + ", " + vector_index_phi)
        enough = e.instruction("icmp uge i64 " + remaining + ", 16")
        return e.instruction("and i1 " + ordered + ", " + enough)

    logical = contains_chunk(limit)
    physical = contains_chunk(extent)
    eligible = e.instruction("and i1 " + logical + ", " + physical)
    e.line("br i1 " + eligible + ", label %" + vector_body + ", label %" + scalar_head)
    e.lines.append(vector_body + ":")
    e.lines.extend(vector_lines)
    e.line("br label %" + vector_head)

    e.lines.append(scalar_head + ":")
    e.line(scalar_index_phi + " = phi i64 [ " + vector_index_phi + ", %" + vector_head +
           " ], [ " + scalar_index + ", %" + scalar_done + " ]")
    e.line(scalar_sum_phi + " = phi i64 [ " + vector_sum_phi + ", %" + vector_head +
           " ], [ " + scalar_sum + ", %" + scalar_done + " ]")
    more = e.instruction("icmp ult i64 " + scalar_index_phi + ", " + limit)
    e.line("br i1 " + more + ", label %" + scalar_body + ", label %" + finished)
    e.lines.append(scalar_body + ":")
    e.lines.extend(scalar_lines)
    # Original scalar bounds guards can introduce internal labels; this stub
    # fixes the phi predecessor while retaining their exact abort behavior.
    e.line("br label %" + scalar_done)
    e.lines.append(scalar_done + ":")
    e.line("br label %" + scalar_head)
    e.lines.append(finished + ":")
    e.values = original_values
    e.values[plan["sum_result"]] = (scalar_sum_phi, "u64")
    e.values[plan["index_result"]] = (scalar_index_phi, "usize")
    e.parent.byte_sum_intrinsic = True
