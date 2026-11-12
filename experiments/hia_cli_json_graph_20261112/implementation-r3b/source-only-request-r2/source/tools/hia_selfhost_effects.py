"""Native source helpers for exact Core effect declarations.

The table is authored independently of the Python Core checker. The emitted
HIA source parses declarations and enforces these masks at every instruction
and call; there is no host checker callback during successor compilation.
"""
from __future__ import annotations


EFFECT_BITS = {"alloc": 1, "read": 2, "write": 4, "trap": 8}
OPERATION_EFFECTS = {
    "int.add.checked": 8, "int.sub.checked": 8, "int.mul.checked": 8,
    "int.div.checked": 8, "int.rem.checked": 8, "int.neg.checked": 8,
    "int.shl.checked": 8, "int.shr.checked": 8,
    "buffer.new": 9, "buffer.try_new": 1, "owner.drop": 1,
    "chain.try_push": 1, "chain.pop": 1,
    "chain.head_read": 10, "chain.head_mut": 10,
    "buffer.load": 10, "buffer.store": 12, "buffer.fill": 4,
    "buffer.fill_range": 12, "buffer.copy": 14, "buffer.copy_range": 14,
    "buffer.move_within": 14, "buffer.swap": 14,
}


SOURCE = r'''
def parse_effects(s:readbuf, w:mutbuf) -> u64:
    mask = 0
    token = get(w, 8)
    failed = get(w, 40)
    while token != 41 and failed == 0:
        flag = 1
        if token != @alloc@:
            if token < @read@ or token > @trap@:
                return fail(w, 65)
            flag = 2 << (token - @read@)
        if (mask & flag) != 0:
            return fail(w, 65)
        mask = mask | flag
        account_nodes(w, 1)
        next_token(s, w)
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                return fail(w, 65)
        token = get(w, 8)
        failed = get(w, 40)
    expect(s, w, 41)
    return mask

def require_effects(w:mutbuf, required:u64) -> u64:
    declared = get(w, FBASE + get(w, 72) * FSTRIDE + 176)
    if (declared & required) != required:
        return fail(w, 65)
    return 0
'''


def source(words):
    """Append a compact, explicit nibble lookup without increasing workspace."""
    start, stop = words["const"], words["chain.head_mut"]
    if not set(OPERATION_EFFECTS) <= words.keys():
        raise AssertionError("effect inventory has an unknown native keyword")
    masks = {words[name]: mask for name, mask in OPERATION_EFFECTS.items()}
    lines = ["def instruction_effects(op:u64) -> u64:"]
    for first in range(start, stop + 1, 16):
        last = min(first + 15, stop)
        packed = sum(masks.get(token, 0) << (4 * (token - first))
                     for token in range(first, last + 1))
        lines += [f"    if op >= {first} and op <= {last}:",
                  f"        return ({packed} >> ((op - {first}) * 4)) & 15"]
    lines.append("    return 0")
    return SOURCE + "\n" + "\n".join(lines) + "\n"


def _program(body, effects, *, elf=False, helpers=""):
    module = "selfhost_elf" if elf else "selfhost"
    return (f"hia-asm.v1 hepta.hia.program.v8 {module}\n"
            f"fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects({','.join(effects)}) entry(b0)\n"
            "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n" + body + "end\n" + helpers).encode()


def cases():
    """Every ordered declaration and finite real operations/call witnesses."""
    from itertools import combinations, permutations

    rows = []
    pure = '  v3:u32 = const() {"value":7}\n  ret(v3)\n'
    initial, data = bytes(range(8)), bytes([11, 22, 33, 44, 55, 66, 77, 88])

    def add(name, body, effects, *, elf=False, result=7, output=initial, helpers="", opcode=None):
        rows.append({"id": name, "source": _program(body, effects, elf=elf, helpers=helpers).decode(),
                     "effects": list(effects), "opcode": opcode, "expected_result": result,
                     "source_hex": data.hex(), "initial_hex": initial.hex(), "expected_hex": output.hex()})

    for count in range(5):
        for combination in combinations(EFFECT_BITS, count):
            for order in permutations(combination):
                add("declaration-" + ("-".join(order) or "empty"), pure, order)

    arithmetic = {"add": 11, "sub": 3, "mul": 28, "div": 1, "rem": 3, "shl": 112, "shr": 0}
    for op, result in arithmetic.items():
        opcode = "int." + op + ".checked"
        body = ('  v3:u64 = const() {"value":7}\n  v4:u64 = const() {"value":4}\n'
                f'  v5:u64 = {opcode}(v3,v4)\n'
                '  v6:u32 = int.cast(v5) {"mode":"wrap"}\n  ret(v6)\n')
        add(opcode, body, ("trap",), result=result, opcode=opcode)
    add("int.neg.checked", '  v3:u64 = const() {"value":0}\n  v4:u64 = int.neg.checked(v3)\n'
        '  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\n', ("trap",), result=0,
        opcode="int.neg.checked")

    # The v15 checked-cast mode adds a conditional trap effect even when this
    # particular value fits, and widening/same-width casts retain that contract.
    for source_type, target_type, value in (("u64", "u8", 255), ("u8", "u64", 255), ("u64", "usize", 7)):
        add("int.cast-checked-" + source_type + "-" + target_type,
            f'  v3:{source_type} = const() {{"value":{value}}}\n'
            f'  v4:{target_type} = int.cast(v3) {{"mode":"checked"}}\n'
            '  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\n',
            ("trap",), result=value, opcode="int.cast")
    add("int.cast-wrap-pure", '  v3:u64 = const() {"value":256}\n'
        '  v4:u8 = int.cast(v3) {"mode":"wrap"}\n'
        '  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\n', (), result=0, opcode="int.cast")

    consts = ('  v3:usize = const() {"value":0}\n  v4:usize = const() {"value":1}\n'
              '  v5:usize = const() {"value":2}\n  v6:u8 = const() {"value":91}\n')
    tail = '  v7:u32 = const() {"value":7}\n  ret(v7)\n'
    add("buffer.load", consts + '  v7:u8 = buffer.load(v0,v3)\n'
        '  v8:u32 = int.cast(v7) {"mode":"wrap"}\n  ret(v8)\n', ("read", "trap"),
        result=11, opcode="buffer.load")
    memory = {
        "buffer.store": ("v1,v3,v6", ("write", "trap"), bytes([91]) + initial[1:]),
        "buffer.fill": ("v1,v6", ("write",), bytes([91]) * 8),
        "buffer.fill_range": ("v1,v4,v5,v6", ("write", "trap"), initial[:1] + bytes([91, 91]) + initial[3:]),
        "buffer.copy": ("v1,v0,v5", ("read", "write", "trap"), data[:2] + initial[2:]),
        "buffer.copy_range": ("v1,v0,v4,v4,v5", ("read", "write", "trap"), initial[:1] + data[1:3] + initial[3:]),
        "buffer.move_within": ("v1,v4,v3,v5", ("read", "write", "trap"), initial[:1] + initial[:2] + initial[3:]),
        "buffer.swap": ("v1,v3,v4", ("read", "write", "trap"), bytes([1, 0]) + initial[2:]),
    }
    for opcode, (arguments, effects, output) in memory.items():
        add(opcode, consts + f"  _ = {opcode}({arguments})\n" + tail,
            effects, output=output, opcode=opcode)

    alloc = '  v3:usize = const() {"value":1}\n'
    finish = '  v20:u32 = const() {"value":7}\n  ret(v20)\n'
    add("buffer.new", alloc + '  v4:buffer = buffer.new(v3)\n  _ = owner.drop(v4)\n' + finish,
        ("alloc", "trap"), elf=True, opcode="buffer.new")
    for opcode in ("buffer.try_new", "owner.drop"):
        add(opcode, alloc + '  v4:buffer,v5:bool = buffer.try_new(v3)\n  _ = owner.drop(v4)\n' + finish,
            ("alloc",), elf=True, opcode=opcode)
    push = (alloc + '  v4:buffer,v5:bool = buffer.try_new(v3)\n  v6:chain = chain.empty()\n'
            '  v7:chain,v8:buffer,v9:bool = chain.try_push(v6,v4)\n')
    drop = '  _ = owner.drop(v7)\n  _ = owner.drop(v8)\n'
    add("chain.try_push", push + drop + finish, ("alloc",), elf=True, opcode="chain.try_push")
    add("chain.pop", '  v3:chain = chain.empty()\n  v4:chain,v5:buffer,v6:bool = chain.pop(v3)\n'
        '  _ = owner.drop(v4)\n  _ = owner.drop(v5)\n' + finish,
        ("alloc",), elf=True, opcode="chain.pop")
    for suffix, typ in (("read", "readbuf"), ("mut", "mutbuf")):
        opcode = "chain.head_" + suffix
        add(opcode, push + f"  v10:{typ} = {opcode}(v7)\n  _ = loan.end(v10)\n" + drop + finish,
            ("alloc", "read", "trap"), elf=True, opcode=opcode)

    for effect in EFFECT_BITS:
        helper = (f"fn f1() -> (u32) effects({effect}) entry(b0)\nblock b0()\n"
                  '  v0:u32 = const() {"value":7}\n  ret(v0)\nend\n')
        add("call-forward-" + effect, '  v3:u32 = call() {"function":"f1"}\n  ret(v3)\n',
            (effect,), helpers=helper)
        middle = (f"fn f2() -> (u32) effects({effect}) entry(b0)\nblock b0()\n"
                  '  v0:u32 = call() {"function":"f1"}\n  ret(v0)\nend\n')
        add("call-backward-" + effect, '  v3:u32 = call() {"function":"f2"}\n  ret(v3)\n',
            (effect,), helpers=helper + middle)
    return rows


def refusals():
    import re

    rows = []
    for row in cases():
        if row["opcode"] is None and not row["id"].startswith("call-"):
            continue
        for effect in row["effects"]:
            effects = [value for value in row["effects"] if value != effect]
            bad = re.sub(r"effects\([^()]*\)", "effects(" + ",".join(effects) + ")", row["source"], count=1)
            rows.append({"id": row["id"] + "-missing-" + effect, "source": bad})
    # An unused helper's declaration still constrains its own call sites, and
    # a middle call cannot borrow its caller's larger declared authority.
    for row in cases():
        if row["id"].startswith("call-backward-"):
            effect = row["effects"][0]
            bad = row["source"].replace(f"fn f2() -> (u32) effects({effect})", "fn f2() -> (u32) effects()")
            rows.append({"id": "call-middle-missing-" + effect, "source": bad})
            dormant = bad.replace('  v3:u32 = call() {"function":"f2"}', '  v3:u32 = const() {"value":7}')
            rows.append({"id": "call-dormant-missing-" + effect, "source": dormant})
    seed = cases()[0]["source"]
    for text in ("read,read", "alloc,alloc", "write,trap,write", "io", "read,", ",read"):
        rows.append({"id": "malformed-" + text.replace(",", "_"),
                     "source": seed.replace("effects()", "effects(" + text + ")")})
    return rows


def permutation_batch(declarations):
    """Execute all declaration orders within one bounded Core compilation.

    Separate canonical-order modules still observe each of the sixteen
    declaration sets and their exact node counts. This batch exercises every
    permutation's actual call without 49 redundant process startups per
    compiler. It does not cache or reuse any native process.
    """
    body, helpers = ['  v3:u32 = const() {"value":0}\n'], []
    previous = 3
    for index, row in enumerate(declarations, 1):
        value, total = 2 * index + 2, 2 * index + 3
        body += [f'  v{value}:u32 = call() {{"function":"f{index}"}}\n',
                 f'  v{total}:u32 = int.add.wrap(v{previous},v{value})\n']
        previous = total
        helpers.append(f"fn f{index}() -> (u32) effects({','.join(row['effects'])}) entry(b0)\n"
                       'block b0()\n  v0:u32 = const() {"value":7}\n  ret(v0)\nend\n')
    body.append(f"  ret(v{previous})\n")
    seed = declarations[0]
    return {**seed, "id": "all-declaration-permutations-called",
            "source": _program("".join(body), tuple(EFFECT_BITS), helpers="".join(helpers)).decode(),
            "effects": list(EFFECT_BITS), "expected_result": 7 * len(declarations),
            "declaration_case_ids": [row["id"] for row in declarations]}


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from tools.hia_selfhost_capacity import count_nodes
    from tools.hia_selfhost_loans import reference_source

    accepted, rejected = [], []
    ordinary = cases()
    declarations = [row for row in ordinary if row["id"].startswith("declaration-")]
    for row in [*ordinary, permutation_batch(declarations)]:
        checked = assemble_program(row["source"])
        wrapped = reference_source(row)
        result = execute_program(assemble_program(wrapped), "reference_entry", [])
        expected = [row["expected_result"], *bytes.fromhex(row["expected_hex"])]
        if result["status"] != "returned" or result["values"] != expected:
            raise AssertionError((row["id"], expected, result))
        accepted.append({**row, "core_sha256": checked.sha256, "core_nodes": count_nodes(checked.as_dict()),
                         "reference_source": wrapped.decode(), "reference_result": result})
    for row in refusals():
        try:
            assemble_program(row["source"])
        except HIAProgramRejected as error:
            rejected.append({**row, "code": error.code, "message": str(error)})
        else:
            raise AssertionError("Core accepted an invalid effect witness: " + row["id"])
    native_ids = [row["id"] for row in accepted if not row["id"].startswith("declaration-")
                  or row["effects"] == [effect for effect in EFFECT_BITS if effect in row["effects"]]]
    return {"cases": accepted, "refusals": rejected, "native_case_ids": native_ids, "before_B0": True,
            "scope": "finite exact effect declarations, operations and call propagation",
            "all_input_correctness_proved": False}


def qualify(directory, compilers, checks, reference):
    # This existing qualifier independently executes each byte fixture, checks
    # exact node accounting and unchanged resource ceilings, and rejects bad
    # inputs before any output write. Its parser/compiler is not shared here.
    from tools.hia_selfhost_cfg_worklist import qualify as qualify_inputs
    selection = set(reference["native_case_ids"])
    selected = [row for row in reference["cases"] if row["id"] in selection]
    if len(selection) != len(selected) or len(selection) != len(reference["native_case_ids"]):
        raise ValueError("effect fixture selection differs from the immutable reference")
    return qualify_inputs(directory, compilers, checks, {**reference, "cases": selected}, prefix="effect-contract")
