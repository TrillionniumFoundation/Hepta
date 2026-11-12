"""New HIA ordinary-impact continuation with three actual Core admissions.

This is source-only development. The exact ordinary patch coordinator is
retained as authoring input; no original patch or static-impact PASS is inherited.
The native continuation owns the extra candidate recheck, complete byte equality,
the issued impact transport and the exact final candidate/receipt/report result.
"""
import ast
from pathlib import Path
from hashlib import sha1
import ordinary_patch_reference as patch
base = patch.base

def gitsha(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

assert gitsha(Path(patch.__file__).read_bytes()) == "1ec25d1a9e579fe077f680b7d34ff40e6db66ee1"
CONSTANTS = dict(patch.CONSTANTS)
CONSTANTS.update(IMPACT_EVENT=patch.magic("HIAIMP01"),
    I_EXPECT_NEW=37000, I_COMPARE_AT=37008, I_COMPARE_BYTES=37016,
    I_ENVELOPE_BYTES=37024, I_REPORT_BYTES=37032,
    I_COMPARE=37376, I_SUFFIX=37632)

def once(text, before, after):
    assert text.count(before) == 1, (before, text.count(before))
    return text.replace(before, after, 1)

BODY = patch.BODY
BODY = once(BODY,
    "        elif phase >= 90 and phase < 120:\n            result = ordinary_receipt_step(o, w)\n",
    "        elif phase >= 90 and phase < 110:\n            result = ordinary_receipt_step(o, w)\n"
    "        elif phase >= 110 and phase < 170:\n            result = impact_step(o, w)\n")
BODY = BODY.replace("lease > MAX - 5", "lease > MAX - 7")
BODY = once(BODY,
    "if cap(w, B_PROGRAM_FRAME) != 0 or get(w, C_LEASE) > MAX - 5:",
    "if cap(w, B_PROGRAM_FRAME) != 0 or get(w, C_LEASE) > MAX - 7:")
BODY = once(BODY, "if generation > 1:", "if generation > 2:")
BODY = once(BODY,
    "if (generation == 0 and source != B_PROGRAM) or (generation == 1 and source != 25):",
    "if (generation == 0 and source != B_PROGRAM) or (generation == 1 and source != 25) or (generation == 2 and source != 26):")
BODY = once(BODY,
    "        return grow(o, w, get(w, O_CORE_SLOT), get(w, E_CORE_BYTES), 4)\n",
    "        if get(w, O_ADMISSION) == 2 and (get(w, E_KIND) != 0 or get(w, E_INPUT_BYTES) != get(w, I_EXPECT_NEW)):\n"
    "            return refuse(w, 6101)\n"
    "        return grow(o, w, get(w, O_CORE_SLOT), get(w, E_CORE_BYTES), 4)\n")
BODY = once(BODY,
    "        return release(o, w, 25, 90)\n",
    "        if get(w, O_ADMISSION) == 2:\n"
    "            put(w, C_PHASE, 120)\n"
    "            return 0\n"
    "        return release(o, w, 25, 90)\n")
BODY = once(BODY,
    "        return edit_result_start(w, B_CORE, 0, get(w, O_BASE_BYTES), 26, 0, get(w, O_NEW_BYTES), 28, 128, size)\n",
    "        put(w, I_EXPECT_NEW, get(w, O_NEW_BYTES))\n"
    "        put(w, C_PHASE, 110)\n"
    "        return 0\n")
BODY += r'''
def impact_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 110:
        return protect(o, w, 28, 1, 111)
    if phase == 111:
        return release(o, w, 27, 112)
    if phase == 112:
        return release(o, w, 29, 113)
    if phase == 113:
        if cap(w, 32) != 0 or cap(w, 33) != 0 or cap(w, 34) != 0 or cap(w, 35) != 0:
            return refuse(w, 6102)
        put(w, O_ADMISSION, 2)
        put(w, O_SOURCE, 26)
        put(w, O_CORE_SLOT, 32)
        put(w, C_PHASE, 1)
        return 0
    if phase == 120:
        if get(w, O_NEW_BYTES) != get(w, I_EXPECT_NEW):
            return impact_changed(w)
        put(w, I_COMPARE_AT, 0)
        put(w, C_PHASE, 121)
        return 0
    if phase == 121:
        at = get(w, I_COMPARE_AT)
        size = get(w, I_EXPECT_NEW)
        if at > size:
            return refuse(w, 6103)
        if at == size:
            return release(o, w, 26, 130)
        count = minimum(256, size - at)
        put(w, I_COMPARE_BYTES, count)
        return view(o, w, 26, at, count, 122)
    if phase == 122:
        count = get(w, I_COMPARE_BYTES)
        at = 0
        while at < count:
            store(w, I_COMPARE + at, byte(w, OBS + at))
            at = at + 1
        return view(o, w, 32, get(w, I_COMPARE_AT), count, 123)
    if phase == 123:
        count = get(w, I_COMPARE_BYTES)
        at = 0
        while at < count:
            if byte(w, I_COMPARE + at) != byte(w, OBS + at):
                return impact_changed(w)
            at = at + 1
        put(w, I_COMPARE_AT, get(w, I_COMPARE_AT) + count)
        put(w, C_PHASE, 121)
        return 0
    if phase == 130:
        first = get(w, O_BASE_BYTES)
        second = get(w, O_NEW_BYTES)
        receipt = get(w, O_RECEIPT_BYTES)
        if first == 0 or first > INPUT_LIMIT or second == 0 or second > INPUT_LIMIT or receipt == 0:
            return refuse(w, 6104)
        size = first + second + receipt + 71
        if size > 25167872 or size < first or size < second or size < receipt:
            return refuse(w, 6105)
        put(w, I_ENVELOPE_BYTES, size)
        store(w, I_SUFFIX, 44)
        store(w, I_SUFFIX + 1, 34)
        hex_digest(w, O_INPUT_HASH, I_SUFFIX + 2)
        store(w, I_SUFFIX + 66, 34)
        store(w, I_SUFFIX + 67, 93)
        store(w, WIRE + 128, 91)
        store(w, WIRE + 129, 44)
        return grow(o, w, 33, size, 131)
    if phase == 131:
        return copy(o, w, B_CONTROLLER, WIRE + 128, 33, 0, 1, 132)
    if phase == 132:
        return copy(o, w, B_CORE, 0, 33, 1, get(w, O_BASE_BYTES), 133)
    if phase == 133:
        return copy(o, w, B_CONTROLLER, WIRE + 129, 33, 1 + get(w, O_BASE_BYTES), 1, 134)
    if phase == 134:
        return copy(o, w, 32, 0, 33, 2 + get(w, O_BASE_BYTES), get(w, O_NEW_BYTES), 135)
    if phase == 135:
        return copy(o, w, B_CONTROLLER, WIRE + 129, 33, 2 + get(w, O_BASE_BYTES) + get(w, O_NEW_BYTES), 1, 136)
    if phase == 136:
        return copy(o, w, 28, 128, 33, 3 + get(w, O_BASE_BYTES) + get(w, O_NEW_BYTES), get(w, O_RECEIPT_BYTES), 137)
    if phase == 137:
        return copy(o, w, B_CONTROLLER, I_SUFFIX, 33, 3 + get(w, O_BASE_BYTES) + get(w, O_NEW_BYTES) + get(w, O_RECEIPT_BYTES), 68, 138)
    if phase == 138:
        return protect(o, w, 33, 1, 139)
    if phase == 139:
        return grow(o, w, 34, 128, 140)
    if phase == 140:
        return grow(o, w, 35, 128, 141)
    if phase == 141:
        return invoke(o, w, 60, 33, 0, get(w, I_ENVELOPE_BYTES), 34, cap(w, 34), 35, cap(w, 35), 34, 0, 128, 142)
    if phase == 142:
        if ordinary_leaf_header(w, IMPACT_EVENT, 34, 35, 112) == 0:
            return refuse(w, 6106)
        action = get(w, OBS + 16)
        reason = get(w, OBS + 24)
        size = get(w, OBS + 56)
        if action != 0:
            at = 64
            while at < 112:
                if get(w, OBS + at) != 0:
                    return refuse(w, 6107)
                at = at + 8
        if action == 1:
            put(w, C_PHASE, 143)
            return 0
        if action == 2:
            if reason < 1 or reason > 8 or size != 0:
                return refuse(w, 6108)
            count = impact_message(w, reason)
            if count == 0:
                return refuse(w, 6109)
            return edit_error_start(w, 2, 60, reason, B_CONTROLLER, PREFIX_TEXT, count)
        functions = get(w, OBS + 64)
        if reason != 0 or size == 0 or functions == 0 or functions > 1024:
            return refuse(w, 6110)
        if get(w, OBS + 72) > 1048576 or get(w, OBS + 80) > 1048576:
            return refuse(w, 6111)
        if get(w, OBS + 88) > functions or get(w, OBS + 96) > functions or get(w, OBS + 104) > functions:
            return refuse(w, 6112)
        put(w, I_REPORT_BYTES, size)
        return protect(o, w, 34, 1, 145)
    if phase == 143:
        return grow(o, w, 34, get(w, O_NEED_OUTPUT), 144)
    if phase == 144:
        return grow(o, w, 35, get(w, O_NEED_WORK), 141)
    if phase == 145:
        return edit_result_start(w, 32, 0, get(w, O_NEW_BYTES), 28, 128, get(w, O_RECEIPT_BYTES), 34, 128, get(w, I_REPORT_BYTES))
    return refuse(w, 6113)
'''

def literal_source():
    messages = patch.source_literal(Path(__file__).with_name("generate_static_impact_r1.py"), "MESSAGES")
    result = [patch.literal_source(), "def impact_message(w:mutbuf, message:u64) -> u64:"]
    assert set(messages) == set(range(1, 9))
    for number, value in sorted(messages.items()):
        raw = value.encode("utf-8") if isinstance(value, str) else value
        result.append(f"    if message == {number}:")
        result.extend(base.writes(raw, "PREFIX_TEXT", "        "))
        result.append(f"        return {len(raw)}")
    result.append("    return 0")
    changed = b"E_HIA_IMPACT: patch output changed after validation"
    result.append("def impact_changed(w:mutbuf) -> u64:")
    result.extend(base.writes(changed, "PREFIX_TEXT", "    "))
    result.append(f"    return edit_error_start(w, 2, 60, 9, B_CONTROLLER, PREFIX_TEXT, {len(changed)})")
    return "\n".join(result) + "\n"

def source_program():
    admissions = [n for n in ast.parse(base.ADMISSION).body if n.name != "program_child"]
    failures = [n for n in ast.parse(base.SOURCE).body if n.name == "prefix_failure"]
    assert len(admissions) == 2 and len(failures) == 1
    failure = once(ast.unparse(failures[0]),
        "return start_result(w, 4, 1, 2, 0, 0, 0, B_CONTROLLER, PREFIX_TEXT, size)",
        "return edit_error_start(w, 2, group, error, B_CONTROLLER, PREFIX_TEXT, size)")
    common = once(base.COMMON, "or (image >= 56 and image <= 59):", "or image == 56 or image == 58:")
    source = (BODY + "\n" + ast.unparse(ast.Module(body=admissions, type_ignores=[]))
        + "\n" + failure + "\n" + base.HASH + "\n" + base.HEX + "\n" + base.HELPERS
        + "\n" + common + "\n" + literal_source())
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body}
    assert len(functions) == len(tree.body)
    live, pending = {"ordinary_patch"}, ["ordinary_patch"]
    while pending:
        for node in ast.walk(functions[pending.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in functions and node.func.id not in live:
                live.add(node.func.id)
                pending.append(node.func.id)
    tree.body = [functions["ordinary_patch"]] + [n for n in tree.body if n.name != "ordinary_patch" and n.name in live]
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    tree = ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name != "ordinary_patch":
            assert node.returns.id in ("u32", "u64")
            node.returns.id = "u64"
    return ast.unparse(tree) + "\n"

def document():
    value = base.document(source_program())
    value["module"] = "ordinary_impact_actual_three_admissions_r1"
    return value
