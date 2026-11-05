"""Explicit, bounded synchronous C loans for an independently verified HIA Core.

A native C caller remains responsible for allocation validity and synchronization.
Numeric admission checks cannot authenticate arbitrary, dangling C pointers.
The wrapper never acquires ownership, retains a pointer, or frees caller memory.
"""
from __future__ import annotations

import re

PROFILE = "hepta.hia.program.llvm-linux-x86_64-foreign-buffers.v1"
MAX_EXTENT = 1 << 20
MAX_RANGES = 8
ABI_OK = 0
ABI_EXTENT = 1
ABI_NULL = 2
ABI_ADDRESS = 3
ABI_ALIAS = 4
_LOANS = frozenset({"readbuf", "mutbuf"})


def normalize_exports(exports, document):
    """Validate an explicit immutable manifest without broadening Core exports.

    One (function name, maximum byte extent) pair per selected function.  This
    first finite profile admits acyclic bodies with direct Core operations;
    calls, owner creation/transfer, and returned capabilities are not admitted.
    """
    from .hia_program import SCALARS
    from .hia_program_llvm import _reject, _RUNTIME_NAMES
    if type(exports) is not tuple or len(exports) > 128:
        _reject("foreign buffer exports must be a bounded immutable tuple", "E_HIA_FOREIGN_ABI")
    if exports and "exports" in document:
        _reject("foreign buffer v1 cannot extend an explicit scalar export contract", "E_HIA_FOREIGN_ABI")
    functions = {fn["name"]: fn for fn in document["functions"]}
    checked = []
    names = set()
    for pair in exports:
        if (type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not int
                or not 1 <= pair[1] <= MAX_EXTENT or pair[0] in names):
            _reject("invalid or duplicate foreign buffer export", "E_HIA_FOREIGN_ABI")
        name, extent = pair
        if name in _RUNTIME_NAMES or name.startswith("__hia_") or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is None:
            _reject("foreign function name conflicts with the closed native ABI", "E_HIA_FOREIGN_ABI")
        names.add(name)
        fn = functions.get(name)
        if fn is None:
            _reject("foreign export names a missing function", "E_HIA_FOREIGN_ABI")
        loans = [p for p in fn["params"] if p["type"] in _LOANS]
        if (not 1 <= len(loans) <= MAX_RANGES or fn["returns"] != ["u32"]
                or any(p["type"] not in (SCALARS - {"unit"}) | _LOANS for p in fn["params"])):
            _reject("foreign function requires bounded loans, scalars and one u32 result", "E_HIA_FOREIGN_ABI")
        # Explicit scalar exports remain a distinct complete contract. The
        # caller must opt in here rather than putting capabilities in it.
        if name in document.get("exports", []):
            _reject("foreign loans cannot appear in scalar exports", "E_HIA_FOREIGN_ABI")
        if "alloc" in fn["effects"]:
            _reject("foreign buffer v1 does not admit allocation", "E_HIA_FOREIGN_ABI")
        graph = {}
        for block in fn["blocks"]:
            values = list(block["params"])
            for ins in block["ops"]:
                values.extend(ins["out"])
                if (ins["op"] == "call" or ins["op"].startswith(("owner.", "chain."))
                        or ins["op"] in {"buffer.new", "buffer.try_new"}):
                    _reject("foreign buffer v1 admits no calls or owners", "E_HIA_FOREIGN_ABI")
            if any(p["type"] not in SCALARS | _LOANS for p in values):
                _reject("foreign buffer v1 admits no owner values", "E_HIA_FOREIGN_ABI")
            term = block["term"]
            if term["op"] == "jump":
                edges = [term["target"]]
            elif term["op"] == "branch":
                edges = [term["then"]["target"], term["else"]["target"]]
            else:
                edges = []
            graph[block["id"]] = edges
        # Kahn's algorithm bounds this admission pass and rejects loops without
        # relying on Python recursion depth or an unproved loop trip bound.
        indegree = {name: 0 for name in graph}
        for targets in graph.values():
            for target in targets:
                indegree[target] += 1
        ready = [name for name, degree in indegree.items() if not degree]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for target in graph[current]:
                indegree[target] -= 1
                if not indegree[target]:
                    ready.append(target)
        if visited != len(graph):
            _reject("foreign buffer v1 requires an acyclic body", "E_HIA_FOREIGN_ABI")
        checked.append((name, extent))
    return tuple(sorted(checked))


def render_wrapper(fn, number, extent, target):
    """Render checked C pointer/length admission followed by actual Core code.

    uint64_t return packs ABI status in high 32 bits and the original u32 Core
    result in low 32 bits. A valid call's ABI status is zero, including when
    the Core returns its own application error. Admission failures do not
    enter the Core and have an application result of zero.
    """
    from .hia_program_llvm import _abi_attr, _llvm_type
    parameters = []
    arguments = []
    ranges = []
    lines = []
    serial = 0

    def value(expression):
        nonlocal serial
        serial += 1
        result = "%fb" + str(serial)
        lines.append("  " + result + " = " + expression)
        return result

    def guard(ok, status):
        nonlocal serial
        serial += 1
        label = "fb_ok_" + str(serial)
        bad = "fb_reject_" + str(serial)
        lines.append("  br i1 " + ok + ", label %" + label + ", label %" + bad)
        lines.extend([bad + ":", "  ret i64 " + str(status << 32), label + ":"])

    for index, param in enumerate(fn["params"]):
        arg = "%a" + str(index)
        typ = param["type"]
        if typ in _LOANS:
            pointer, length = arg + "_data", arg + "_len"
            parameters.extend(["ptr " + pointer, "i64 " + length])
            ranges.append((pointer, length, typ == "mutbuf"))
        else:
            parameters.append(_llvm_type(typ) + " " + _abi_attr(typ, target) + arg)
    admitted = []
    for pointer, length, mutable in ranges:
        bounded = value("icmp ule i64 " + length + ", " + str(extent))
        guard(bounded, ABI_EXTENT)
        empty = value("icmp eq i64 " + length + ", 0")
        nonnull = value("icmp ne ptr " + pointer + ", null")
        guard(value("or i1 " + empty + ", " + nonnull), ABI_NULL)
        start = value("ptrtoint ptr " + pointer + " to i64")
        end = value("add i64 " + start + ", " + length)
        guard(value("icmp uge i64 " + end + ", " + start), ABI_ADDRESS)
        admitted.append((pointer, length, mutable, empty, start, end))
    for index, left in enumerate(admitted):
        for right in admitted[index + 1:]:
            if not (left[2] or right[2]):
                continue
            separate1 = value("icmp ule i64 " + left[5] + ", " + right[4])
            separate2 = value("icmp ule i64 " + right[5] + ", " + left[4])
            disjoint = value("or i1 " + separate1 + ", " + separate2)
            one_empty = value("or i1 " + left[3] + ", " + right[3])
            guard(value("or i1 " + disjoint + ", " + one_empty), ABI_ALIAS)
    for index, param in enumerate(fn["params"]):
        arg = "%a" + str(index)
        typ = param["type"]
        if typ in _LOANS:
            first = value("insertvalue %hia.buffer zeroinitializer, ptr " + arg + "_data, 0")
            buf = value("insertvalue %hia.buffer " + first + ", i64 " + arg + "_len, 1")
            arguments.append("%hia.buffer " + buf)
        else:
            arguments.append(_llvm_type(typ) + " " + arg)
    result = value("call i32 @__hia_fn_" + str(number) + "(" + ", ".join(arguments) + ")")
    packed = value("zext i32 " + result + " to i64")
    lines.append("  ret i64 " + packed)
    return "\n".join(["define i64 @" + fn["name"] + "(" + ", ".join(parameters) + ") {", "entry:", *lines, "}"])
