"""Author ordinary CLI argv admission in HIA; Python is authoring only.

This is a new recovery revision, not the unavailable earlier prototype.
The selected runtime must not call argparse. Action execution is a separate
HIA continuation composed into this image; retained semantic callees stay
explicit foreign owners.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = "examples/hia_bootstrap/cli_control.hepta"
ACTIONS = (
    "capabilities", "catalog", "import-assembly", "render-assembly",
    "check-assembly", "verify", "inspect", "normalize", "build", "patch",
    "impact", "edit-query", "edit-apply", "edit-batch-query", "edit-batch-apply",
)
FIELDS = ("help", "version", "schema", "output", "backend", "kind", "target",
          "request", "function", "block", "value", "fields", "selections",
          "query", "response", "input", "hia_action", "selfhost_manifest", "selfhost_manifest_sha256")
OUTPUT_ACTIONS = frozenset((3, 4, 8, 9, 10, 12, 13, 14, 15))
TOKENS = (
    ("-h", 0), ("--help", 0), ("--version", 1), ("--schema", 2),
    ("--output", 3), ("-o", 3), ("--backend", 4), ("--kind", 5),
    ("--target", 6), ("--request", 7), ("--function", 8), ("--block", 9),
    ("--value", 10), ("--fields", 11), ("--selections", 12),
    ("--query", 13), ("--response", 14),
    ("--selfhost-manifest", 17), ("--selfhost-manifest-sha256", 18),
)
SCHEMAS = tuple("hepta.hia.program.v" + str(n) for n in range(1, 9))
DEFAULTS = {2: SCHEMAS[-1], 4: "native", 5: "object",
            6: "x86_64-unknown-linux-gnu"}
LITERALS = tuple(dict.fromkeys(
    [text for text, _ in TOKENS] + list(ACTIONS) + list(FIELDS) +
    list(SCHEMAS) + list(DEFAULTS.values()) + ["selfhost"]))
LITERAL_IDS = {text: i for i, text in enumerate(LITERALS)}
SYMBOLS = {
    "ARGV_MAGIC": int.from_bytes(b"HCLIARG4", "little"),
    "RESULT_MAGIC": int.from_bytes(b"HCLIRES4", "little"),
    "STEP_MAGIC": int.from_bytes(b"HCLISTP4", "little"),
    "CONTROL_MAGIC": int.from_bytes(b"HCLICTL4", "little"),
    "TOKEN_COUNT": len(TOKENS), "ACTION_COUNT": len(ACTIONS),
    "FIELD_BASE": 256, "FIELD_STRIDE": 32,
    "ARG_BASE": 32768, "ARG_STRIDE": 48, "EXTRA_STRIDE": 24,
    "LITERAL_BASE": 8192, "LITERAL_DATA": 16384,
    "CONTROL_BASE": 2048,
}
# Header: result kind/action/scope/reason/option/bad span/matches/required/
# extras/argc/presence/frame bytes/exit/descriptor/profile/seen.
# Fields: kind(0 absent,1 None,2 input UTF32,3 literal ASCII), offset, length,
# native literal identifier for the namespace key.
SOURCE = r'''
def cli(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 65536:
        if length(w) >= C_CLOSED + 8:
            put(w, C_MAGIC, CONTROL_MAGIC)
            put(w, C_CLOSED, 1)
            put(w, C_PENDING, 0)
        return 199
    if length(s) < 8 or length(o) < 128:
        return control_refuse(w)
    if read64(s, 0) == STEP_MAGIC:
        return control_step(s, o, w)
    if get(w, C_MAGIC) == CONTROL_MAGIC:
        return control_refuse(w)
    if read64(s, 0) != ARGV_MAGIC or length(s) < 192:
        return control_refuse(w)
    if read64(s, 8) != 4:
        return control_refuse(w)
    argc = read64(s, 16)
    profile = read64(s, 24)
    if profile != 312 and profile != 314 and profile != 31410:
        return control_refuse(w)
    if argc > (length(s) - 192) >> 4:
        return control_refuse(w)
    if length(w) < 65536 + argc * 80 + length(s):
        return control_refuse(w)
    if read64(s, 40) > 1 or read64(s, 48) > 1 or read64(s, 72) > 63:
        return control_refuse(w)
    if read64(s, 64) != 0 or read64(s, 80) != 0 or read64(s, 88) != 0:
        return control_refuse(w)
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        begin = read64(s, record)
        size = read64(s, record + 8)
        if begin != cursor or size > (length(s) - cursor) >> 2:
            return control_refuse(w)
        end = begin + size * 4
        while cursor < end:
            if read32(s, cursor) > 1114111:
                return control_refuse(w)
            cursor = cursor + 4
        record = record + 16
    if cursor != length(s):
        return control_refuse(w)
    index = 0
    while index < 4096:
        store(w, index, 0)
        index = index + 1
    constants(w)
    put(w, 0, RESULT_MAGIC)
    put(w, 88, argc)
    put(w, 104, length(s))
    put(w, 128, profile)
    put(w, 120, 1)
    field = 0
    while field < 19:
        put(w, FIELD_BASE + field * FIELD_STRIDE + 24, field_literal(field))
        field = field + 1
    copy_at = 65536 + argc * 80
    index = 0
    while index < length(s):
        store(w, copy_at + index, byte(s, index))
        index = index + 1
    put(w, 152, copy_at)
    parse_root(s, w)
    if get(w, 8) == 0:
        backend = field_equal(s, w, 4, SELFHOST_LITERAL)
        if get(w, 16) == 9:
            if backend == 1:
                if field_truth(w, 17) == 0 or field_truth(w, 18) == 0:
                    put(w, 24, 0)
                    refusal(w, 8, 0, 0, 0, 0)
            else:
                if get(w, FIELD_BASE + 17 * FIELD_STRIDE) > 1 or get(w, FIELD_BASE + 18 * FIELD_STRIDE) > 1:
                    put(w, 24, 0)
                    refusal(w, 9, 0, 0, 0, 0)
        if get(w, 8) == 0:
            control_seed(w, get(w, 16), field_truth(w, 3), backend)
    index = 0
    while index < 128:
        store(o, index, byte(w, index))
        index = index + 1
    return 0

def field_equal(s:readbuf, w:mutbuf, field:u64, literal:u64) -> u64:
    base = FIELD_BASE + field * FIELD_STRIDE
    if get(w, base) != 2:
        return 0
    if literal_equal(s, w, get(w, base + 8), get(w, base + 16), literal):
        return 1
    return 0

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def read32(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def get32(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value >> (index * 8))
        index = index + 1
    return 0

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(w, at + index, value >> (index * 8))
        index = index + 1
    return 0

def literal_equal(s:readbuf, w:mutbuf, begin:u64, size:u64, literal:u64) -> bool:
    at = LITERAL_BASE + literal * 16
    if size != get(w, at + 8):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, get(w, at) + index):
            return False
        index = index + 1
    return True

def literal_prefix(s:readbuf, w:mutbuf, begin:u64, size:u64, literal:u64) -> bool:
    at = LITERAL_BASE + literal * 16
    if size > get(w, at + 8):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, get(w, at) + index):
            return False
        index = index + 1
    return True

def token_find(s:readbuf, w:mutbuf, scope:u64, begin:u64, size:u64, prefix:bool) -> u64:
    allowed = token_mask(scope)
    matches = 0
    token = 0
    while token < TOKEN_COUNT:
        if (allowed & (1 << token)) != 0:
            same = literal_equal(s, w, begin, size, token_literal(token))
            if prefix:
                same = literal_prefix(s, w, begin, size, token_literal(token))
            if same:
                matches = matches | (1 << token)
        token = token + 1
    return matches

def negative_number(s:readbuf, w:mutbuf, begin:u64, size:u64) -> bool:
    if size < 2:
        return False
    if get(w, 128) != 312:
        index = 1
        if read32(s, begin + index * 4) == 46:
            index = index + 1
        if index == size:
            return False
        return decimal(read32(s, begin + index * 4), get(w, 128)) != 0
    end = size
    if read32(s, begin + (end - 1) * 4) == 10:
        end = end - 1
    index = 1
    while index < end:
        if decimal(read32(s, begin + index * 4), get(w, 128)) == 0:
            if read32(s, begin + index * 4) != 46:
                return False
            index = index + 1
            if index == end:
                return False
            while index < end:
                if decimal(read32(s, begin + index * 4), get(w, 128)) == 0:
                    return False
                index = index + 1
            return True
        index = index + 1
    return end > 1

def classify_one(s:readbuf, w:mutbuf, scope:u64, index:u64) -> u64:
    record = ARG_BASE + index * ARG_STRIDE
    begin = read64(s, 192 + index * 16)
    size = read64(s, 200 + index * 16)
    put(w, record, 1)
    put(w, record + 8, 0)
    put(w, record + 16, 0)
    put(w, record + 24, 0)
    put(w, record + 32, 0)
    if size == 0 or read32(s, begin) != 45:
        return 0
    if size == 1:
        return 0
    if size == 2 and read32(s, begin + 4) == 45:
        put(w, record, 3)
        return 0
    matches = token_find(s, w, scope, begin, size, False)
    if matches != 0:
        put(w, record, 2)
        put(w, record + 8, matches)
        return 0
    equal = 0
    scan = 0
    while scan < size:
        if read32(s, begin + scan * 4) == 61 and equal == 0:
            equal = scan
        scan = scan + 1
    prefix_size = choose(equal == 0, size, equal)
    if equal != 0:
        matches = token_find(s, w, scope, begin, prefix_size, False)
        if matches != 0:
            put(w, record, 2)
            put(w, record + 8, matches)
            put(w, record + 16, begin + (equal + 1) * 4)
            put(w, record + 24, size - equal - 1)
            put(w, record + 32, 1)
            return 0
    if read32(s, begin + 4) == 45:
        matches = token_find(s, w, scope, begin, prefix_size, True)
        if matches != 0 and equal != 0:
            put(w, record + 16, begin + (equal + 1) * 4)
            put(w, record + 24, size - equal - 1)
            put(w, record + 32, 1)
    else:
        matches = token_find(s, w, scope, begin, 2, False)
        if matches != 0:
            put(w, record + 16, begin + 8)
            put(w, record + 24, size - 2)
    if matches != 0:
        put(w, record, 2)
        put(w, record + 8, matches)
        return 0
    if negative_number(s, w, begin, size):
        return 0
    scan = 0
    while scan < size:
        if read32(s, begin + scan * 4) == 32:
            return 0
        scan = scan + 1
    put(w, record, 2)
    return 0

def classify_scope(s:readbuf, w:mutbuf, scope:u64, start:u64) -> u64:
    after_dash = False
    index = start
    while index < get(w, 88):
        if after_dash:
            put(w, ARG_BASE + index * ARG_STRIDE, 1)
        else:
            classify_one(s, w, scope, index)
            if get(w, ARG_BASE + index * ARG_STRIDE) == 3:
                after_dash = True
        index = index + 1
    return 0

def set_field(w:mutbuf, field:u64, kind:u64, begin:u64, size:u64, seen:bool) -> u64:
    at = FIELD_BASE + field * FIELD_STRIDE
    put(w, at, kind)
    put(w, at + 8, begin)
    put(w, at + 16, size)
    put(w, 96, get(w, 96) | (1 << field))
    if seen:
        put(w, 144, get(w, 144) | (1 << field))
    return 0

def field_truth(w:mutbuf, field:u64) -> u64:
    at = FIELD_BASE + field * FIELD_STRIDE
    return choose(get(w, at) > 1 and get(w, at + 16) > 0, 1, 0)

def add_extra(w:mutbuf, begin:u64, size:u64, hyphen:u64) -> u64:
    at = ARG_BASE + get(w, 88) * ARG_STRIDE + get(w, 80) * EXTRA_STRIDE
    put(w, at, begin)
    put(w, at + 8, size)
    put(w, at + 16, hyphen)
    put(w, 80, get(w, 80) + 1)
    return 0

def refusal(w:mutbuf, reason:u64, option:u64, begin:u64, size:u64, mask:u64) -> u64:
    put(w, 8, 3)
    put(w, 32, reason)
    put(w, 40, option)
    put(w, 48, begin)
    put(w, 56, size)
    put(w, 64, mask)
    put(w, 112, 2)
    put(w, 120, 2)
    return 0

def consume_option(s:readbuf, w:mutbuf, scope:u64, index:u64) -> u64:
    record = ARG_BASE + index * ARG_STRIDE
    matches = get(w, record + 8)
    begin = read64(s, 192 + index * 16)
    size = read64(s, 200 + index * 16)
    if matches == 0:
        add_extra(w, begin, size, 0)
        return index + 1
    if (matches & (matches - 1)) != 0:
        refusal(w, 3, 0, begin, size, matches)
        return get(w, 88)
    token = 0
    while (matches & (1 << token)) == 0:
        token = token + 1
    explicit = get(w, record + 16)
    explicit_size = get(w, record + 24)
    separator = get(w, record + 32)
    stop = index + 1
    queued_help = False
    queued_version = False
    final_field = 0
    value_begin = 0
    value_size = 0
    done = False
    while done == False:
        field = token_field(token)
        if field < 2:
            if explicit != 0:
                if token == 0 and explicit_size > 0:
                    if separator != 0 or read32(s, explicit) == 45:
                        refusal(w, 5, field, explicit, explicit_size, 0)
                        return get(w, 88)
                    queued_help = True
                    char = read32(s, explicit)
                    explicit = explicit + 4
                    explicit_size = explicit_size - 1
                    if char == 104:
                        token = 0
                    else:
                        if char == 111 and (token_mask(scope) & 32) != 0:
                            token = 5
                        else:
                            add_extra(w, explicit - 4, explicit_size + 1, 1)
                            done = True
                    if explicit_size == 0:
                        explicit = 0
                        separator = 0
                    else:
                        if read32(s, explicit) == 61:
                            explicit = explicit + 4
                            explicit_size = explicit_size - 1
                            separator = 1
                        else:
                            separator = 0
                else:
                    refusal(w, 5, field, explicit, explicit_size, 0)
                    return get(w, 88)
            else:
                if field == 0:
                    queued_help = True
                else:
                    queued_version = True
                done = True
        else:
            if explicit == 0:
                if stop >= get(w, 88) or get(w, ARG_BASE + stop * ARG_STRIDE) != 1:
                    refusal(w, 4, field, 0, 0, 0)
                    return get(w, 88)
                explicit = read64(s, 192 + stop * 16)
                explicit_size = read64(s, 200 + stop * 16)
                stop = stop + 1
            final_field = field
            value_begin = explicit
            value_size = explicit_size
            done = True
    if queued_help:
        put(w, 8, 1)
        return get(w, 88)
    if queued_version:
        put(w, 8, 2)
        return get(w, 88)
    if choice_ok(s, w, final_field, value_begin, value_size) == 0:
        refusal(w, 6, final_field, value_begin, value_size, 0)
        return get(w, 88)
    set_field(w, final_field, 2, value_begin, value_size, True)
    return stop

def parse_child(s:readbuf, w:mutbuf, scope:u64, start:u64) -> u64:
    put(w, 24, scope)
    namespace_defaults(w, scope)
    classify_scope(s, w, scope, start)
    index = start
    input_seen = False
    while index < get(w, 88):
        kind = get(w, ARG_BASE + index * ARG_STRIDE)
        if kind == 2:
            index = consume_option(s, w, scope, index)
            if get(w, 8) != 0:
                return 0
        else:
            selected = index
            if kind == 3:
                selected = selected + 1
            if scope > 2 and input_seen == False and selected < get(w, 88) and get(w, ARG_BASE + selected * ARG_STRIDE) == 1:
                set_field(w, 15, 2, read64(s, 192 + selected * 16), read64(s, 200 + selected * 16), True)
                input_seen = True
                index = selected + 1
                if index < get(w, 88) and get(w, ARG_BASE + index * ARG_STRIDE) == 3:
                    index = index + 1
            else:
                add_extra(w, read64(s, 192 + index * 16), read64(s, 200 + index * 16), 0)
                index = index + 1
    required = required_mask(scope)
    missing = required ^ (required & get(w, 144))
    if missing != 0:
        put(w, 72, missing)
        refusal(w, 1, 0, 0, 0, 0)
    return 0

def parse_root(s:readbuf, w:mutbuf) -> u64:
    classify_scope(s, w, 0, 0)
    index = 0
    while index < get(w, 88):
        kind = get(w, ARG_BASE + index * ARG_STRIDE)
        if kind == 2:
            index = consume_option(s, w, 0, index)
            if get(w, 8) != 0:
                return 0
        else:
            selected = index
            if kind == 3:
                selected = selected + 1
            if selected < get(w, 88) and get(w, ARG_BASE + selected * ARG_STRIDE) == 1:
                begin = read64(s, 192 + selected * 16)
                size = read64(s, 200 + selected * 16)
                action = action_value(s, w, begin, size)
                if action == 0:
                    refusal(w, 2, 16, begin, size, 0)
                    return 0
                put(w, 16, action)
                set_field(w, 16, 2, begin, size, True)
                parse_child(s, w, action, selected + 1)
                if get(w, 8) == 0 and get(w, 80) != 0:
                    put(w, 24, 0)
                    refusal(w, 7, 0, 0, 0, 0)
                return 0
            add_extra(w, read64(s, 192 + index * 16), read64(s, 200 + index * 16), 0)
            index = index + 1
    put(w, 72, 65536)
    refusal(w, 1, 0, 0, 0, 0)
    return 0
'''

def allowed_fields(scope):
    if scope == 0:
        return (0, 1)
    result = [0]
    if scope == 2:
        result.append(2)
    if scope in OUTPUT_ACTIONS:
        result.append(3)
    if scope == 9:
        result += [4, 5, 6, 17, 18]
    if scope in (10, 11):
        result.append(7)
    if scope == 12:
        result += [8, 9, 10, 11]
    if scope == 14:
        result.append(12)
    if scope in (13, 15):
        result += [13, 14]
    return tuple(result)

def required_fields(scope):
    result = [15] if scope > 2 else []
    if scope == 9:
        result.append(3)
    if scope in (10, 11):
        result.append(7)
    if scope == 12:
        result += [8, 9, 10, 11]
    if scope == 14:
        result.append(12)
    if scope in (13, 15):
        result += [13, 14]
    return tuple(result)

def _lookup(name, parameter, values, default=0):
    lines = [f"def {name}({parameter}:u64) -> u64:"]
    for key, value in values:
        lines += [f"    if {parameter} == {key}:", f"        return {value}"]
    return "\n".join(lines + [f"    return {default}", ""])

def _tables():
    pieces = [
        _lookup("token_literal", "token", ((i, LITERAL_IDS[t]) for i, (t, _) in enumerate(TOKENS))),
        _lookup("token_field", "token", ((i, field) for i, (_, field) in enumerate(TOKENS))),
        _lookup("field_literal", "field", ((i, LITERAL_IDS[t]) for i, t in enumerate(FIELDS))),
        _lookup("token_mask", "scope", ((scope, sum(1 << i for i, (_, field) in enumerate(TOKENS)
                                                   if field in allowed_fields(scope))) for scope in range(16))),
        _lookup("required_mask", "scope", ((scope, sum(1 << field for field in required_fields(scope)))
                                          for scope in range(1, 16))),
    ]
    lines = ["def action_value(s:readbuf, w:mutbuf, begin:u64, size:u64) -> u64:"]
    for index, text in enumerate(ACTIONS, 1):
        lines += [f"    if literal_equal(s, w, begin, size, {LITERAL_IDS[text]}):", f"        return {index}"]
    pieces.append("\n".join(lines + ["    return 0", ""]))
    lines = ["def choice_ok(s:readbuf, w:mutbuf, field:u64, begin:u64, size:u64) -> u64:"]
    for field in (2, 4, 5, 6):
        values = SCHEMAS if field == 2 else ("native", "selfhost") if field == 4 else (DEFAULTS[field],)
        lines.append(f"    if field == {field}:")
        for value in values:
            lines += [f"        if literal_equal(s, w, begin, size, {LITERAL_IDS[value]}):", "            return 1"]
        lines.append("        return 0")
    pieces.append("\n".join(lines + ["    return 1", ""]))
    lines = ["def namespace_defaults(w:mutbuf, scope:u64) -> u64:"]
    for scope in range(1, 16):
        lines.append(f"    if scope == {scope}:")
        fields = [field for field in allowed_fields(scope) if field > 1]
        for field in fields:
            if field in DEFAULTS:
                literal = LITERAL_IDS[DEFAULTS[field]]
                lines.append(f"        set_field(w, {field}, 3, get(w, LITERAL_BASE + {literal} * 16), {len(DEFAULTS[field])}, False)")
            else:
                lines.append(f"        set_field(w, {field}, 1, 0, 0, False)")
        lines.append("        return 0")
    pieces.append("\n".join(lines + ["    return 0", ""]))
    return "\n".join(pieces)

def _constants():
    writes = []
    cursor = SYMBOLS["LITERAL_DATA"]
    for index, text in enumerate(LITERALS):
        raw = text.encode("ascii")
        writes += [(SYMBOLS["LITERAL_BASE"] + index * 16, cursor),
                   (SYMBOLS["LITERAL_BASE"] + index * 16 + 8, len(raw))]
        for offset in range(0, len(raw), 8):
            writes.append((cursor + offset, int.from_bytes(raw[offset:offset + 8].ljust(8, b"\0"), "little")))
        cursor += (len(raw) + 7) & ~7
    if cursor >= SYMBOLS["ARG_BASE"]:
        raise ValueError("CLI literal table crossed private extent")
    functions = []
    chunks = [writes[i:i + 128] for i in range(0, len(writes), 128)]
    lines = ["def constants(w:mutbuf) -> u64:"]
    for index in range(len(chunks)):
        lines.append(f"    constants_{index}(w)")
    functions.append("\n".join(lines + ["    return 0", ""]))
    for index, chunk in enumerate(chunks):
        functions.append("\n".join([f"def constants_{index}(w:mutbuf) -> u64:"] +
                                  [f"    put(w, {at}, {value})" for at, value in chunk] +
                                  ["    return 0", ""]))
    return "\n".join(functions)

def _decimal():
    path = Path(__file__).with_name("hia_cli_unicode_tables.json")
    tables = json.loads(path.read_text())
    pieces = ["def decimal(point:u64, profile:u64) -> u64:\n"
              "    if profile == 312:\n        return decimal_312(point)\n"
              "    return decimal_314(point)\n"]
    for profile in (312, 314):
        lines = [f"def decimal_{profile}(point:u64) -> u64:"]
        for lower, upper in tables["profiles"][str(profile)]["decimal_ranges"]:
            lines += [f"    if point >= {lower} and point <= {upper}:", "        return 1"]
        pieces.append("\n".join(lines + ["    return 0", ""]))
    return "\n".join(pieces)

def source_program():
    from tools.hia_cli_control_phases import SOURCE as PHASE_SOURCE, SYMBOLS as PHASE_SYMBOLS
    values = dict(SYMBOLS)
    values["SELFHOST_LITERAL"] = LITERAL_IDS["selfhost"]
    values.update(PHASE_SYMBOLS)
    class Replace(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(values[node.id]), node) if node.id in values else node
    tree = Replace().visit(ast.parse(SOURCE + "\n" + _tables() + "\n" + _constants() +
                                    "\n" + _decimal() + "\n" + PHASE_SOURCE))
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "cli_control",
                                  "functions": functions})

if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
