"""Explicit synchronous borrowed-byte boundary for the direct x86-64 backend.

This is a separate profile from scalar exports and from the earlier experimental
LLVM foreign-buffer ABI.  Caller allocations must be live and correctly sized;
numeric guards cannot authenticate arbitrary native pointers.  The direct Core
verifier still owns type, effect, alias and loan-lifetime admission inside Core.
"""
from __future__ import annotations

PROFILE = "hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1"
MAX_EXTENT = 1 << 20
MAX_RANGES = 8
ABI_OK, ABI_EXTENT, ABI_NULL, ABI_ADDRESS, ABI_ALIAS = range(5)
LOANS = frozenset({"readbuf", "mutbuf"})


def _reference_normalize_exports(exports, program):
    """Validate an immutable opt-in manifest; never extend scalar contracts.

Unlike the LLVM acyclic experiment, this profile admits existing verified Core
loops and internal calls.  It therefore makes no termination or native quota
claim.  The public call cannot return a loan or transfer a foreign owner.
"""
    from .hia_program import SCALARS
    from .hia_program_native import IMPORTS, _LOADER_HOOKS, _reject

    if type(exports) is not tuple or len(exports) > 128:
        _reject("borrowed-byte exports require a bounded immutable tuple", "E_HIA_BYTE_ABI")
    if not exports:
        return ()
    document = program.as_dict()
    if program.structured_bytes is not None or "exports" in document:
        _reject("borrowed-byte profile cannot extend a nominal/scalar export contract", "E_HIA_BYTE_ABI")
    functions = {fn["name"]: fn for fn in document["functions"]}
    names, checked = set(), []
    for pair in exports:
        if (type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not int
                or not 1 <= pair[1] <= MAX_EXTENT or pair[0] in names):
            _reject("invalid or duplicate borrowed-byte export", "E_HIA_BYTE_ABI")
        name, extent = pair
        if name in IMPORTS or name in _LOADER_HOOKS or name.startswith("__hia_"):
            _reject("borrowed-byte export conflicts with the closed native ABI", "E_HIA_BYTE_ABI")
        fn = functions.get(name)
        if fn is None:
            _reject("borrowed-byte export names a missing function", "E_HIA_BYTE_ABI")
        loans = [p for p in fn["params"] if p["type"] in LOANS]
        if (not 1 <= len(loans) <= MAX_RANGES or fn["returns"] != ["u32"]
                or any(p["type"] not in (SCALARS - {"unit"}) | LOANS for p in fn["params"])):
            _reject("borrowed-byte export requires loans, scalars and one u32 result", "E_HIA_BYTE_ABI")
        names.add(name)
        checked.append((name, extent))
    return tuple(sorted(checked))


def _reference_emit_wrapper(emitter, fn, extent):
    """Emit guards before the Core call, then pack ABI status / Core u32 result.

Every loan expands in place to (pointer, uint64 length).  All incoming words are
saved before scratch registers are used, including mixed stack/register arity.
No error path enters Core or touches caller bytes.
"""
    from .hia_program_native import MAX_FRAME_BYTES, _ARG_REGS, _normalize, _prologue, _reject

    words = []
    ranges = []
    for param in fn["params"]:
        typ = param["type"]
        if typ in LOANS:
            ranges.append((len(words), typ == "mutbuf"))
            words.extend(("u64", "u64"))
        else:
            words.append(typ)
    frame = ((len(words) + 1) * 8 + 15) & -16
    if frame > MAX_FRAME_BYTES:
        _reject("borrowed-byte wrapper exceeds the stack budget", "E_HIA_PROGRAM_LIMIT")
    c = emitter.c
    begin = len(c.data)
    _prologue(c, frame)
    input_slot, result_slot = -frame, -8
    for i, typ in enumerate(words):
        if i < len(_ARG_REGS):
            c.mov_rr("rax", _ARG_REGS[i])
        else:
            c.load("rax", "rbp", 16 + 8 * (i - len(_ARG_REGS)))
        _normalize(c, "rax", typ)
        c.store("rbp", input_slot + 8 * i, "rax")
    failures = {status: emitter.label("byte_abi_reject_" + str(status))
                for status in (ABI_EXTENT, ABI_NULL, ABI_ADDRESS, ABI_ALIAS)}

    def load(word, register):
        c.load(register, "rbp", input_slot + word * 8)

    for word, _mutable in ranges:
        load(word + 1, "rcx")
        c.mov_imm("rdx", extent)
        c.cmp("rcx", "rdx"); c.jcc("a", failures[ABI_EXTENT])
        load(word, "rax")
        admitted_empty = emitter.label("byte_abi_range")
        c.test("rcx", "rcx"); c.jcc("e", admitted_empty)
        c.test("rax", "rax"); c.jcc("e", failures[ABI_NULL])
        c.add("rax", "rcx"); c.jcc("b", failures[ABI_ADDRESS])
        c.label(admitted_empty)
    for i, (left, left_mutable) in enumerate(ranges):
        for right, right_mutable in ranges[i + 1:]:
            if not (left_mutable or right_mutable):
                continue
            separate = emitter.label("byte_abi_disjoint")
            load(left + 1, "rcx"); c.test("rcx", "rcx"); c.jcc("e", separate)
            load(right + 1, "rdx"); c.test("rdx", "rdx"); c.jcc("e", separate)
            load(left, "rax"); c.add("rax", "rcx")
            load(right, "rcx"); c.cmp("rax", "rcx"); c.jcc("be", separate)
            c.add("rcx", "rdx"); load(left, "rax")
            c.cmp("rcx", "rax"); c.jcc("be", separate)
            c.jmp(failures[ABI_ALIAS])
            c.label(separate)
    c.lea("rdi", "rbp", input_slot); c.lea("rsi", "rbp", result_slot)
    c.call(emitter.function_symbol(fn["name"]))
    c.load("rax", "rbp", result_slot); _normalize(c, "rax", "u32")
    c.leave(); c.ret()
    for status, label in failures.items():
        c.label(label); c.mov_imm("rax", status << 32); c.leave(); c.ret()
    emitter.symbols.append({"name": fn["name"], "offset": begin,
                            "size": len(c.data) - begin, "global": True})
    emitter.exports.append(fn["name"])


# The exact original policies above remain unselected owners and independent
# oracles. An explicit admitted image never falls back after refusal.
def normalize_exports(exports, program):
    from .hia_byte_wrapper_selection import selected_byte_wrapper
    owner = selected_byte_wrapper(globals())
    if owner is not None:
        return owner.invoke('normalize_exports', (exports, program))
    return _reference_normalize_exports(exports, program)


def emit_wrapper(emitter, fn, extent):
    from .hia_byte_wrapper_selection import selected_byte_wrapper
    owner = selected_byte_wrapper(globals())
    if owner is not None:
        return owner.invoke('emit_wrapper', (emitter, fn, extent))
    return _reference_emit_wrapper(emitter, fn, extent)
