"""HIA continuation for the fifteen ordinary CLI actions.

The command numbers are transport ABI, not host dispatch policy. HIA chooses
every action, read budget, sequencing branch, report update and exit code.
Named retained semantic/presentation callees are explicit foreign owners; this
component does not claim those bodies have already been rewritten.
"""
from __future__ import annotations

COMMANDS = {
    1: "capabilities", 2: "catalog", 3: "read_bounded", 4: "verify_program",
    5: "assemble_program", 6: "diagnose_assembly", 7: "render_assembly",
    8: "program_as_dict", 9: "program_report", 10: "inspect_program",
    11: "build_machine", 12: "decode_json", 13: "apply_patch",
    14: "analyze_impact", 15: "prepare_edit", 16: "apply_edit",
    17: "prepare_batch", 18: "apply_batch", 19: "publish_program",
    20: "publish_json_view", 21: "publish_assembly",
    22: "print_json", 23: "print_text", 24: "copy_mapping",
    25: "dict_set", 26: "new_dict", 27: "new_list",
    28: "list_append", 29: "field_slice", 30: "accepted_truth",
    31: "ok_is_true", 32: "str_exception", 33: "format_driver_error",
    34: "print_formatted_error",
}
# These remain foreign implementation boundaries and are not called HIA
# implementations merely because the continuation selects their invocation.
RETAINED_OWNERS = (
    "semantic action bodies", "read_bounded file policy", "publication bodies",
    "ordinary successful pretty-JSON presentation",
)
LITERALS = (
    False, True, "schema", "ok", "status", "native_executed", "publication",
    "program", "patch", "impact", "verified_new_snapshot_published",
    "standalone_core_checked", "hepta.hia.impact-query.v1",
    "verified_unpublished",
)
SYMBOLS = {
    "C_MAGIC": 2048, "C_PHASE": 2056, "C_SEQ": 2064, "C_PENDING": 2072,
    "C_CLOSED": 2080, "C_ACTION": 2088, "C_NS": 2096, "C_PROGRAM": 2104,
    "C_REVISED": 2112, "C_RECEIPT": 2120, "C_VALUE": 2128, "C_QUERY": 2136,
    "C_RESPONSE": 2144, "C_OUTPUT": 2152, "C_LIST": 2160,
    "C_SPLIT_START": 2168, "C_SPLIT_END": 2176, "C_SPLIT_DONE": 2184,
    "C_A": 2192, "C_B": 2200, "C_C": 2208, "C_HANDLER": 2216,
    "C_CATCH": 2224, "C_EXCEPTION": 2232, "C_COMMAND": 2304,
    "COMMAND_MAGIC": int.from_bytes(b"HCLICMD4", "little"),
    "C_LITERAL_BASE": 4096, "C_LITERAL_DATA": 6144,
}
for _name, _index in {
    "V_FALSE": 0, "V_TRUE": 1, "K_SCHEMA": 2, "K_OK": 3, "K_STATUS": 4,
    "K_NATIVE": 5, "K_PUBLICATION": 6, "K_PROGRAM": 7, "K_PATCH": 8,
    "K_IMPACT": 9, "V_PUBLISHED": 10, "V_VERIFIED": 11,
    "V_IMPACT_SCHEMA": 12, "V_UNPUBLISHED": 13,
}.items():
    SYMBOLS[_name] = (1 << 63) | _index

SOURCE = r'''
def control_seed(w:mutbuf, action:u64, output:u64) -> u64:
    index = C_MAGIC
    while index < C_COMMAND + 128:
        store(w, index, 0)
        index = index + 1
    put(w, C_MAGIC, CONTROL_MAGIC)
    put(w, C_ACTION, action)
    put(w, C_OUTPUT, output)
    control_constants(w)
    return 0

def control_refuse(w:mutbuf) -> u32:
    put(w, C_CLOSED, 1)
    put(w, C_PENDING, 0)
    return 199

def control_ask(w:mutbuf, operation:u64, next_phase:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    sequence = get(w, C_SEQ) + 1
    put(w, C_SEQ, sequence)
    put(w, C_PENDING, operation)
    put(w, C_PHASE, next_phase)
    catching = choose(get(w, C_HANDLER) == 0, 1, 0)
    put(w, C_CATCH, catching)
    index = C_COMMAND
    while index < C_COMMAND + 128:
        store(w, index, 0)
        index = index + 1
    put(w, C_COMMAND, COMMAND_MAGIC)
    put(w, C_COMMAND + 8, operation)
    put(w, C_COMMAND + 16, sequence)
    put(w, C_COMMAND + 24, catching)
    put(w, C_COMMAND + 32, a)
    put(w, C_COMMAND + 40, b)
    put(w, C_COMMAND + 48, c)
    put(w, C_COMMAND + 56, d)
    return 1

def control_done(w:mutbuf, code:u64) -> u64:
    put(w, C_CLOSED, 1)
    put(w, C_PENDING, 0)
    index = C_COMMAND
    while index < C_COMMAND + 128:
        store(w, index, 0)
        index = index + 1
    put(w, C_COMMAND, COMMAND_MAGIC)
    put(w, C_COMMAND + 16, get(w, C_SEQ))
    put(w, C_COMMAND + 32, code)
    return 2

def control_step(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 96 or length(o) < 128 or length(w) < 65536:
        return control_refuse(w)
    if get(w, C_MAGIC) != CONTROL_MAGIC or get(w, C_CLOSED) != 0:
        return control_refuse(w)
    if read64(s, 8) != 4 or read64(s, 16) != get(w, C_SEQ) or read64(s, 24) != get(w, C_PENDING):
        return control_refuse(w)
    if read64(s, 32) > 1 or read64(s, 64) != 0 or read64(s, 72) != 0 or read64(s, 80) != 0 or read64(s, 88) != 0:
        return control_refuse(w)
    if get(w, C_SEQ) >= 9223372036854775807:
        return control_refuse(w)
    if get(w, C_PENDING) == 0 and get(w, C_PHASE) != 0:
        return control_refuse(w)
    if read64(s, 32) == 1:
        if get(w, C_CATCH) != 1 or read64(s, 40) == 0:
            return control_refuse(w)
        put(w, C_HANDLER, 1)
        put(w, C_EXCEPTION, read64(s, 40))
        put(w, C_PHASE, 900)
    put(w, C_PENDING, 0)
    put(w, C_A, read64(s, 40))
    put(w, C_B, read64(s, 48))
    put(w, C_C, read64(s, 56))
    result = 0
    while result == 0:
        phase = get(w, C_PHASE)
        if phase < 40:
            result = control_initial(w)
        else:
            if phase < 80:
                result = control_edits(w)
            else:
                if phase < 200:
                    result = control_reports(w)
                else:
                    result = control_terminal(w)
    if result == 199:
        return control_refuse(w)
    index = 0
    while index < 128:
        store(o, index, byte(w, C_COMMAND + index))
        index = index + 1
    return result

def control_initial(w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    action = get(w, C_ACTION)
    value = get(w, C_A)
    if phase == 0:
        if value == 0 or action < 1 or action > 15:
            return 199
        put(w, C_NS, value)
        if action == 1:
            return control_ask(w, 1, 200, 0, 0, 0, 0)
        if action == 2:
            return control_ask(w, 2, 200, value, 2, 0, 0)
        return control_ask(w, 3, 10, value, 15, 8388608, 0)
    if phase == 10:
        if action == 3:
            return control_ask(w, 5, 11, value, 0, 0, 0)
        if action == 5:
            return control_ask(w, 6, 14, value, 0, 0, 0)
        return control_ask(w, 4, 20, value, 0, 0, 0)
    if phase == 11:
        put(w, C_PROGRAM, value)
        put(w, C_PHASE, 80)
        return 0
    if phase == 12:
        return control_ask(w, 7, 13, get(w, C_PROGRAM), 0, 0, 0)
    if phase == 13:
        if get(w, C_OUTPUT) != 0:
            return control_ask(w, 21, 200, get(w, C_PROGRAM), value, get(w, C_NS), 3)
        return control_ask(w, 23, 201, value, 0, 0, 0)
    if phase == 14:
        put(w, C_VALUE, value)
        return control_ask(w, 22, 15, value, 0, 0, 0)
    if phase == 15:
        return control_ask(w, 30, 16, get(w, C_VALUE), 0, 0, 0)
    if phase == 16:
        if value > 1:
            return 199
        return control_done(w, 1 - value)
    if phase == 20:
        put(w, C_PROGRAM, value)
        if action == 4:
            put(w, C_PHASE, 12)
            return 0
        if action == 6:
            return control_ask(w, 9, 21, value, 0, 0, 0)
        if action == 7:
            return control_ask(w, 10, 200, value, 0, 0, 0)
        if action == 8:
            put(w, C_PHASE, 80)
            return 0
        if action == 9:
            return control_ask(w, 11, 24, value, get(w, C_NS), 3, 0)
        if action == 10 or action == 11:
            return control_ask(w, 3, 30, get(w, C_NS), 7, 8388608, 0)
        if action == 12:
            return control_ask(w, 27, 50, 0, 0, 0, 0)
        if action == 13:
            return control_ask(w, 3, 60, get(w, C_NS), 13, 8388608, 0)
        if action == 14:
            return control_ask(w, 3, 65, get(w, C_NS), 12, 8388608, 0)
        if action == 15:
            return control_ask(w, 3, 67, get(w, C_NS), 13, 1048576, 0)
        return 199
    if phase == 21:
        return control_ask(w, 24, 22, value, 0, 0, 0)
    if phase == 22:
        put(w, C_VALUE, value)
        return control_ask(w, 25, 23, value, K_STATUS, V_VERIFIED, 0)
    if phase == 23:
        return control_ask(w, 25, 202, get(w, C_VALUE), K_NATIVE, V_FALSE, 0)
    if phase == 24:
        put(w, C_VALUE, value)
        return control_ask(w, 22, 25, value, 0, 0, 0)
    if phase == 25:
        return control_ask(w, 31, 26, get(w, C_VALUE), 0, 0, 0)
    if phase == 26:
        if value > 1:
            return 199
        return control_done(w, 1 - value)
    if phase == 30:
        if action == 10:
            return control_ask(w, 13, 70, get(w, C_PROGRAM), value, 0, 0)
        return control_ask(w, 14, 90, get(w, C_PROGRAM), value, 0, 0)
    return 199

def control_edits(w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    value = get(w, C_A)
    if phase == 50:
        put(w, C_LIST, value)
        put(w, C_SPLIT_START, 0)
        put(w, C_SPLIT_DONE, 0)
        put(w, C_PHASE, 53)
        return 0
    if phase == 51:
        return control_ask(w, 28, 52, get(w, C_LIST), value, 0, 0)
    if phase == 52:
        put(w, C_SPLIT_START, get(w, C_SPLIT_END) + 1)
        put(w, C_PHASE, 53)
        return 0
    if phase == 53:
        if get(w, C_SPLIT_DONE) != 0:
            return control_ask(w, 15, 55, get(w, C_PROGRAM), get(w, C_NS), get(w, C_LIST), 0)
        field = FIELD_BASE + 11 * FIELD_STRIDE
        if get(w, field) != 2:
            return 199
        start = get(w, C_SPLIT_START)
        end = start
        size = get(w, field + 16)
        at = get(w, 152) + get(w, field + 8)
        while end < size and get32(w, at + end * 4) != 44:
            end = end + 1
        put(w, C_SPLIT_END, end)
        if end == size:
            put(w, C_SPLIT_DONE, 1)
        return control_ask(w, 29, 51, get(w, C_NS), 11, start, end - start)
    if phase == 55:
        if get(w, C_OUTPUT) != 0:
            return control_ask(w, 20, 200, value, get(w, C_NS), 3, 0)
        put(w, C_VALUE, value)
        put(w, C_PHASE, 202)
        return 0
    if phase == 60:
        return control_ask(w, 12, 61, value, 0, 0, 0)
    if phase == 61:
        put(w, C_QUERY, value)
        return control_ask(w, 3, 62, get(w, C_NS), 14, 16384, 0)
    if phase == 62:
        return control_ask(w, 16, 70, get(w, C_PROGRAM), get(w, C_QUERY), value, 0)
    if phase == 65:
        return control_ask(w, 12, 66, value, 0, 0, 0)
    if phase == 66:
        return control_ask(w, 17, 55, get(w, C_PROGRAM), value, 0, 0)
    if phase == 67:
        put(w, C_QUERY, value)
        return control_ask(w, 3, 68, get(w, C_NS), 14, 65536, 0)
    if phase == 68:
        return control_ask(w, 18, 70, get(w, C_PROGRAM), get(w, C_QUERY), value, 0)
    if phase == 70:
        put(w, C_REVISED, value)
        put(w, C_RECEIPT, get(w, C_B))
        if get(w, C_OUTPUT) != 0:
            return control_ask(w, 19, 71, value, get(w, C_NS), 3, 0)
        return control_ask(w, 8, 73, value, 0, 0, 0)
    if phase == 71:
        return control_ask(w, 25, 72, get(w, C_RECEIPT), K_PUBLICATION, value, 0)
    if phase == 72:
        return control_ask(w, 25, 74, get(w, C_RECEIPT), K_STATUS, V_PUBLISHED, 0)
    if phase == 73:
        return control_ask(w, 25, 74, get(w, C_RECEIPT), K_PROGRAM, value, 0)
    if phase == 74:
        put(w, C_VALUE, get(w, C_RECEIPT))
        put(w, C_PHASE, 202)
        return 0
    return 199

def control_reports(w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    value = get(w, C_A)
    if phase == 80:
        if get(w, C_OUTPUT) != 0:
            return control_ask(w, 19, 200, get(w, C_PROGRAM), get(w, C_NS), 3, 0)
        return control_ask(w, 8, 200, get(w, C_PROGRAM), 0, 0, 0)
    if phase == 90:
        put(w, C_RECEIPT, get(w, C_B))
        put(w, C_RESPONSE, get(w, C_C))
        return control_ask(w, 26, 91, 0, 0, 0, 0)
    if phase == 91:
        put(w, C_VALUE, value)
        return control_ask(w, 25, 92, value, K_SCHEMA, V_IMPACT_SCHEMA, 0)
    if phase == 92:
        return control_ask(w, 25, 93, get(w, C_VALUE), K_OK, V_TRUE, 0)
    if phase == 93:
        return control_ask(w, 25, 94, get(w, C_VALUE), K_STATUS, V_UNPUBLISHED, 0)
    if phase == 94:
        return control_ask(w, 25, 95, get(w, C_VALUE), K_PATCH, get(w, C_RECEIPT), 0)
    if phase == 95:
        return control_ask(w, 25, 202, get(w, C_VALUE), K_IMPACT, get(w, C_RESPONSE), 0)
    return 199

def control_terminal(w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    value = get(w, C_A)
    if phase == 200:
        put(w, C_VALUE, value)
        put(w, C_PHASE, 202)
        return 0
    if phase == 201:
        return control_done(w, 0)
    if phase == 202:
        return control_ask(w, 22, 201, get(w, C_VALUE), 0, 0, 0)
    if phase == 900:
        return control_ask(w, 32, 901, get(w, C_EXCEPTION), 0, 0, 0)
    if phase == 901:
        return control_ask(w, 33, 902, value, 0, 0, 0)
    if phase == 902:
        return control_ask(w, 34, 903, value, 0, 0, 0)
    if phase == 903:
        return control_done(w, 2)
    return 199
'''

def _constant_source():
    writes = []
    cursor = SYMBOLS["C_LITERAL_DATA"]
    for index, value in enumerate(LITERALS):
        record = SYMBOLS["C_LITERAL_BASE"] + index * 32
        if type(value) is bool:
            writes += [(record, 1), (record + 8, int(value)), (record + 16, 0)]
        else:
            raw = value.encode("ascii")
            writes += [(record, 2), (record + 8, cursor), (record + 16, len(raw))]
            for offset in range(0, len(raw), 8):
                writes.append((cursor + offset, int.from_bytes(raw[offset:offset + 8].ljust(8, b"\0"), "little")))
            cursor += (len(raw) + 7) & ~7
    if cursor > 8192:
        raise ValueError("CLI control constants crossed argv literal table")
    return "\n".join(["def control_constants(w:mutbuf) -> u64:"] +
                     [f"    put(w, {at}, {value})" for at, value in writes] +
                     ["    return 0", ""])

SOURCE += "\n" + _constant_source()
