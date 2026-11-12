"""New full public assembly syntax owner; authoring only, no inherited tests.
The HIA source gate, regex-equivalent grammar, list validation, both original
strict JSON gates and integer-production budget precede the returned syntax
document. The result is construction data, never a Core admission receipt.
"""
from hashlib import sha256
from pathlib import Path
import ast
import sys
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE

PREFLIGHT_SHA="293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
CONSTANTS=dict(BAD=0xfffffffd,GROW=0xfffffffe,MAX=(1<<64)-1,
 COMMAND=magic("HIAASC01"),STATE=magic("HIAASS01"),EVENT=magic("HIAASE01"),
 PHASE=16,LEASE=24,SEQ=32,SOURCE_KIND=40,DIGITS=48,SOURCE_N=56,
 SOURCE_CHARS=64,NEEDED=72,OUT=80,OUT_N=88,MODE=96,CURSOR=104,
 ERROR=112,ERROR_LINE=120,PREFIX_OK=128,LINE=136,LINE_COUNT=144,
 DOCUMENT=152,FUNCTION=160,BLOCK=168,TERMINATED=176,FUNCTIONS=184,
 BLOCKS=192,OPERATIONS=200,EXPORTS=208,EXPORT_A=216,EXPORT_B=224,
 SCHEMA=232,LOANS=240,LOAN_A=248,LOAN_B=384,FN_BLOCKS=392,BLOCK_OPS=400,
 LINE_A=408,LINE_B=416,POSITION=424,SPAN_A=432,SPAN_B=440,ITEMS=448,
 PARAM_A=456,PARAM_B=464,PARAM_TA=472,PARAM_TB=480,WRITE_END=488,
 CAP=640,HEADER=768,LITERAL_INDEX=1024,LITERAL_DATA=4096,ERROR_TEXT=6144,
 JSON_START=8000,JSON_N=8008,JSON_STATE=8192,JSON_STATE_CAP=8192,
 JSON_KEYS=16384,JSON_KEYS_CAP=131072,BASE=163840)
MESSAGES=[
 "source must be UTF-8 text or bytes",
 "source exceeds byte budget",
 "source is not valid UTF-8",
 "unsupported control character or byte-order mark",
 "source exceeds line budget",
 "line exceeds byte budget",
 "carriage return must be part of CRLF",
 "expected hia-asm.v1, explicit primitive v6/v7/v8 schema, and module",
 "list exceeds item budget",
 "empty list item",
 "expected explicit ASCII names",
 "expected name:type for every value",
 "exports may occur once, before all functions",
 "expected explicit function header",
 "function inventory exceeds budget",
 "return_loans requires explicit Core v8",
 "function must end after a block terminator",
 "block inventory exceeds budget",
 "previous block has no terminator",
 "expected block header or function end",
 "expected typed instruction or explicit terminator",
 "operation inventory exceeds budget",
 "attributes require bounded strict JSON",
 "attributes must be one JSON object",
 "return_loans requires bounded strict JSON",
 "return_loans requires a list of formal names or null",
 "missing assembly header",
 "unterminated function; explicit end required",
]
LITERALS={
 "head":"hia-asm.v1","fn":"fn","block":"block","exports":"exports",
 "effects":"effects","entry":"entry","loans":"return_loans","arrow":"->",
 "ret":"ret","jump":"jump","branch":"branch","trap":"trap","end":"end",
 "schema6":"hepta.hia.program.v6","schema7":"hepta.hia.program.v7","schema8":"hepta.hia.program.v8",
 "doc":'{"schema":',"module":',"module":',"functions":',"functions":[',
 "exports_json":',"exports":',"name":'{"name":',"params":',"params":',
 "returns":',"returns":',"effects_json":',"effects":',"entry_json":',"entry":',
 "blocks":',"blocks":[',"loans_json":',"return_loans":',"id":'{"id":',
 "ops":',"ops":[',"op":'{"op":',"args":',"args":',"out":',"out":',
 "attrs":',"attrs":',"type":',"type":',"term":'],"term":',
 "ret_json":'{"op":"ret","values":',"jump_json":'{"op":"jump","target":',
 "branch_json":'{"op":"branch","cond":',"then":',"then":{"target":',
 "else":',"else":{"target":',"trap_json":'{"op":"trap","code":',
 "empty":"[]","empty_object":"{}","null":"null",
 "error":"E_HIA_ASSEMBLY: ","error_limit":"E_HIA_ASSEMBLY_LIMIT: ","line_prefix":"line ",
 "colon":": ",
}
for i,message in enumerate(MESSAGES,1):LITERALS["message_"+str(i)]=message
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if command(s, r) == 0:
        return poison(w)
    if get(w, 0) == 0:
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(r, 16))
        put(w, SEQ, uint(r, 24))
        put(w, SOURCE_KIND, uint(r, 32))
        put(w, DIGITS, uint(r, 40))
        put(w, SOURCE_N, length(s))
        copy_read(w, r, HEADER, 0, 96)
        literal_table(w)
        if source_gate(s, w) == 0:
            if get(w, ERROR) == 0:
                return poison(w)
            return failure(w)
        put(w, OUT, BASE + length(s))
    else:
        if get(w, 0) != STATE or get(w, PHASE) == 0 or get(w, PHASE) > 2:
            return poison(w)
        if get(w, SOURCE_N) != length(s) or get(w, OUT) != BASE + length(s):
            return poison(w)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, HEADER + i):
                return poison(w)
            i = i + 1
    if length(w) < get(w, OUT):
        return growing(w, get(w, OUT))
    if get(w, PHASE) == 1:
        copy_read(w, s, BASE, 0, length(s))
        put(w, MODE, 0)
        if parse(s, w) == 0:
            if get(w, ERROR) == 0:
                return poison(w)
            return failure(w)
        put(w, OUT_N, get(w, CURSOR) - get(w, OUT))
        put(w, NEEDED, get(w, CURSOR))
        put(w, PHASE, 2)
    else:
        i = 0
        while i < length(s):
            if byte(s, i) != byte(w, BASE + i):
                return poison(w)
            i = i + 1
    if get(w, NEEDED) < get(w, OUT) or get(w, OUT_N) != get(w, NEEDED) - get(w, OUT):
        return poison(w)
    if get(w, NEEDED) > length(w):
        return growing(w, get(w, NEEDED))
    put(w, MODE, 1)
    put(w, WRITE_END, get(w, NEEDED))
    if parse(s, w) == 0 or get(w, CURSOR) != get(w, NEEDED) or get(w, 8) != 0:
        return poison(w)
    put(w, PHASE, 3)
    emit(w, 0, get(w, OUT), get(w, OUT_N), get(w, NEEDED))
    return 128

def command(s:readbuf, r:readbuf) -> u64:
    if length(r) != 96 or uint(r, 0) != COMMAND or uint(r, 8) != 1:
        return 0
    if uint(r, 16) == 0 or uint(r, 24) == 0 or uint(r, 48) != length(s):
        return 0
    if length(s) > MAX - BASE or uint(r, 32) > 2:
        return 0
    if uint(r, 40) != 0 and uint(r, 40) < 640:
        return 0
    at = 56
    while at < 96:
        if uint(r, at) != 0:
            return 0
        at = at + 8
    return 1

def poison(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 3, 0, 0, 0)
    return BAD

def growing(w:mutbuf, need:u64) -> u32:
    emit(w, 1, 0, 0, need)
    return GROW

def emit(w:mutbuf, action:u64, at:u64, n:u64, need:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, ERROR))
    put(w, 296, get(w, ERROR_LINE))
    put(w, 304, get(w, PREFIX_OK))
    put(w, 312, at)
    put(w, 320, n)
    put(w, 328, get(w, SOURCE_CHARS))
    put(w, 336, get(w, SOURCE_N))
    put(w, 344, need)
    put(w, 352, is_limit(get(w, ERROR)))
    return 0

def fail(w:mutbuf, code:u64, line:u64) -> u64:
    put(w, ERROR, code)
    put(w, ERROR_LINE, line)
    return 0

def is_limit(code:u64) -> u64:
    if code == 2 or code == 5 or code == 6 or code == 9 or code == 15 or code == 18 or code == 22:
        return 1
    return 0

def failure(w:mutbuf) -> u32:
    put(w, MODE, 1)
    put(w, WRITE_END, ERROR_TEXT + 1024)
    put(w, CURSOR, ERROR_TEXT)
    if is_limit(get(w, ERROR)) == 0:
        text(w, L_error)
    else:
        text(w, L_error_limit)
    line = get(w, ERROR_LINE)
    if line != 0:
        text(w, L_line_prefix)
        decimal(w, line)
        text(w, L_colon)
    if get(w, ERROR) == 0 or get(w, ERROR) > 28:
        return poison(w)
    text(w, L_message_1 + get(w, ERROR) - 1)
    if get(w, 8) != 0:
        return poison(w)
    put(w, PHASE, 3)
    emit(w, 2, ERROR_TEXT, get(w, CURSOR) - ERROR_TEXT, 0)
    return 128

def source_gate(s:readbuf, w:mutbuf) -> u64:
    kind = get(w, SOURCE_KIND)
    if kind == 0:
        return fail(w, 1, 0)
    if kind == 2 and length(s) > 1048576:
        return fail(w, 2, 0)
    at = 0
    count = 0
    bad = 0
    control = 0
    lines = 1
    while at < length(s):
        unit = point(s, at, length(s), 1)
        if unit == MAX:
            if kind == 1:
                return 0
            return fail(w, 3, 0)
        cp = unit & 4294967295
        at = unit >> 32
        count = count + 1
        if cp >= 55296 and cp <= 57343:
            bad = 1
        if cp <= 8 or cp == 11 or cp == 12 or (cp >= 14 and cp <= 31) or cp == 65279:
            control = 1
        if cp == 10:
            lines = lines + 1
    put(w, SOURCE_CHARS, count)
    if kind == 1 and count > 1048576:
        return fail(w, 2, 0)
    if bad != 0:
        return fail(w, 3, 0)
    if length(s) > 1048576:
        return fail(w, 2, 0)
    if control != 0:
        return fail(w, 4, 0)
    if lines > 16384:
        return fail(w, 5, 0)
    put(w, LINE_COUNT, lines)
    begin = 0
    line = 1
    while begin <= length(s):
        end = begin
        while end < length(s) and byte(s, end) != 10:
            end = end + 1
        if end - begin > 16384:
            return fail(w, 6, line)
        at = begin
        while at < end:
            if byte(s, at) == 13 and at + 1 != end:
                return fail(w, 7, line)
            at = at + 1
        if end == length(s):
            break
        begin = end + 1
        line = line + 1
    put(w, PREFIX_OK, 1)
    return 1

def parse(s:readbuf, w:mutbuf) -> u64:
    put(w, DOCUMENT, 0)
    put(w, FUNCTION, 0)
    put(w, BLOCK, 0)
    put(w, TERMINATED, 0)
    put(w, FUNCTIONS, 0)
    put(w, BLOCKS, 0)
    put(w, OPERATIONS, 0)
    put(w, EXPORTS, 0)
    put(w, ERROR, 0)
    put(w, ERROR_LINE, 0)
    put(w, CURSOR, get(w, OUT))
    begin = 0
    line = 1
    while begin <= length(s):
        end = begin
        while end < length(s) and byte(s, end) != 10:
            end = end + 1
        next_line = end + 1
        if end > begin and byte(s, end - 1) == 13:
            end = end - 1
        while begin < end and (byte(s, begin) == 32 or byte(s, begin) == 9):
            begin = begin + 1
        while end > begin and (byte(s, end - 1) == 32 or byte(s, end - 1) == 9):
            end = end - 1
        put(w, LINE, line)
        put(w, LINE_A, begin)
        put(w, LINE_B, end)
        if begin != end:
            if parse_line(s, w, begin, end) == 0:
                return 0
        begin = next_line
        line = line + 1
    if get(w, DOCUMENT) == 0:
        return fail(w, 27, 0)
    if get(w, FUNCTION) != 0:
        return fail(w, 28, get(w, LINE_COUNT))
    append(w, 93)
    if get(w, EXPORTS) != 0:
        text(w, L_exports_json)
        list_emit(s, w, get(w, EXPORT_A), get(w, EXPORT_B), 0)
    append(w, 125)
    return 1

def parse_line(s:readbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    if get(w, DOCUMENT) == 0:
        if header(s, w, begin, end) == 0:
            return fail(w, 8, get(w, LINE))
        put(w, DOCUMENT, 1)
        text(w, L_doc)
        quote(s, w, capture_a(w, 0), capture_b(w, 0))
        text(w, L_module)
        quote(s, w, capture_a(w, 1), capture_b(w, 1))
        text(w, L_functions)
        return 1
    if get(w, FUNCTION) == 0:
        return outside(s, w, begin, end)
    if exact(s, w, begin, end, L_end) != 0:
        if get(w, BLOCK) == 0 or get(w, TERMINATED) == 0:
            return fail(w, 17, get(w, LINE))
        append(w, 93)
        if get(w, LOANS) != 0:
            text(w, L_loans_json)
            span(s, w, get(w, LOAN_A), get(w, LOAN_B))
        append(w, 125)
        put(w, FUNCTION, 0)
        put(w, BLOCK, 0)
        return 1
    if block_header(s, w, begin, end) != 0:
        if get(w, BLOCK) != 0 and get(w, TERMINATED) == 0:
            return fail(w, 19, get(w, LINE))
        count = get(w, BLOCKS) + 1
        put(w, BLOCKS, count)
        if count > 4096:
            return fail(w, 18, get(w, LINE))
        if list_check(s, w, capture_a(w, 1), capture_b(w, 1), 1) == 0:
            return 0
        if get(w, FN_BLOCKS) != 0:
            append(w, 44)
        text(w, L_id)
        quote(s, w, capture_a(w, 0), capture_b(w, 0))
        text(w, L_params)
        list_emit(s, w, capture_a(w, 1), capture_b(w, 1), 1)
        text(w, L_ops)
        put(w, FN_BLOCKS, get(w, FN_BLOCKS) + 1)
        put(w, BLOCK, 1)
        put(w, TERMINATED, 0)
        put(w, BLOCK_OPS, 0)
        return 1
    if get(w, BLOCK) == 0 or get(w, TERMINATED) != 0:
        return fail(w, 20, get(w, LINE))
    return inside(s, w, begin, end)

def outside(s:readbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    if unary(s, w, begin, end, L_exports) != 0:
        if get(w, EXPORTS) != 0 or get(w, FUNCTIONS) != 0:
            return fail(w, 13, get(w, LINE))
        if list_check(s, w, capture_a(w, 0), capture_b(w, 0), 0) == 0:
            return 0
        put(w, EXPORTS, 1)
        put(w, EXPORT_A, capture_a(w, 0))
        put(w, EXPORT_B, capture_b(w, 0))
        return 1
    if function_header(s, w, begin, end) == 0:
        return fail(w, 14, get(w, LINE))
    if get(w, FUNCTIONS) >= 256:
        return fail(w, 15, get(w, LINE))
    if list_check(s, w, capture_a(w, 1), capture_b(w, 1), 1) == 0:
        return 0
    if list_check(s, w, capture_a(w, 2), capture_b(w, 2), 0) == 0:
        return 0
    if list_check(s, w, capture_a(w, 3), capture_b(w, 3), 0) == 0:
        return 0
    if get(w, LOANS) != 0:
        if get(w, SCHEMA) != 8:
            return fail(w, 16, get(w, LINE))
        if json_check(s, w, capture_a(w, 5), capture_b(w, 5), 2) == 0:
            return 0
        put(w, LOAN_A, capture_a(w, 5))
        put(w, LOAN_B, capture_b(w, 5))
    if get(w, FUNCTIONS) != 0:
        append(w, 44)
    text(w, L_name)
    quote(s, w, capture_a(w, 0), capture_b(w, 0))
    text(w, L_params)
    list_emit(s, w, capture_a(w, 1), capture_b(w, 1), 1)
    text(w, L_returns)
    list_emit(s, w, capture_a(w, 2), capture_b(w, 2), 0)
    text(w, L_effects_json)
    list_emit(s, w, capture_a(w, 3), capture_b(w, 3), 0)
    text(w, L_entry_json)
    quote(s, w, capture_a(w, 4), capture_b(w, 4))
    text(w, L_blocks)
    put(w, FUNCTIONS, get(w, FUNCTIONS) + 1)
    put(w, FUNCTION, 1)
    put(w, BLOCK, 0)
    put(w, TERMINATED, 0)
    put(w, FN_BLOCKS, 0)
    return 1

def inside(s:readbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    if unary(s, w, begin, end, L_ret) != 0:
        if list_check(s, w, capture_a(w, 0), capture_b(w, 0), 0) == 0:
            return 0
        text(w, L_term)
        text(w, L_ret_json)
        list_emit(s, w, capture_a(w, 0), capture_b(w, 0), 0)
        append(w, 125)
    elif jump_header(s, w, begin, end) != 0:
        if list_check(s, w, capture_a(w, 1), capture_b(w, 1), 0) == 0:
            return 0
        text(w, L_term)
        text(w, L_jump_json)
        quote(s, w, capture_a(w, 0), capture_b(w, 0))
        text(w, L_args)
        list_emit(s, w, capture_a(w, 1), capture_b(w, 1), 0)
        append(w, 125)
    elif branch_header(s, w, begin, end) != 0:
        if list_check(s, w, capture_a(w, 2), capture_b(w, 2), 0) == 0:
            return 0
        if list_check(s, w, capture_a(w, 4), capture_b(w, 4), 0) == 0:
            return 0
        text(w, L_term)
        text(w, L_branch_json)
        quote(s, w, capture_a(w, 0), capture_b(w, 0))
        text(w, L_then)
        quote(s, w, capture_a(w, 1), capture_b(w, 1))
        text(w, L_args)
        list_emit(s, w, capture_a(w, 2), capture_b(w, 2), 0)
        append(w, 125)
        text(w, L_else)
        quote(s, w, capture_a(w, 3), capture_b(w, 3))
        text(w, L_args)
        list_emit(s, w, capture_a(w, 4), capture_b(w, 4), 0)
        append(w, 125)
        append(w, 125)
    elif trap_header(s, w, begin, end) != 0:
        text(w, L_term)
        text(w, L_trap_json)
        quote(s, w, capture_a(w, 0), capture_b(w, 0))
        append(w, 125)
    elif instruction(s, w, begin, end) != 0:
        return operation(s, w)
    else:
        return fail(w, 21, get(w, LINE))
    append(w, 125)
    put(w, TERMINATED, 1)
    return 1

def operation(s:readbuf, w:mutbuf) -> u64:
    count = get(w, OPERATIONS) + 1
    put(w, OPERATIONS, count)
    if count > 16384:
        return fail(w, 22, get(w, LINE))
    if list_check(s, w, capture_a(w, 2), capture_b(w, 2), 0) == 0:
        return 0
    trim(s, w, capture_a(w, 0), capture_b(w, 0))
    first = get(w, SPAN_A)
    last = get(w, SPAN_B)
    empty = 0
    if last == first + 1 and byte(s, first) == 95:
        empty = 1
    elif list_check(s, w, capture_a(w, 0), capture_b(w, 0), 1) == 0:
        return 0
    if get(w, CAP + 96) != 0:
        if json_check(s, w, capture_a(w, 3), capture_b(w, 3), 1) == 0:
            return 0
    if get(w, BLOCK_OPS) != 0:
        append(w, 44)
    text(w, L_op)
    quote(s, w, capture_a(w, 1), capture_b(w, 1))
    text(w, L_args)
    list_emit(s, w, capture_a(w, 2), capture_b(w, 2), 0)
    text(w, L_out)
    if empty != 0:
        text(w, L_empty)
    else:
        list_emit(s, w, capture_a(w, 0), capture_b(w, 0), 1)
    text(w, L_attrs)
    if get(w, CAP + 96) != 0:
        span(s, w, capture_a(w, 3), capture_b(w, 3))
    else:
        text(w, L_empty_object)
    append(w, 125)
    put(w, BLOCK_OPS, get(w, BLOCK_OPS) + 1)
    return 1

def header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = literal(s, w, a, b, L_head)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    start = p
    while p < b:
        u = point(s, p, b, 0)
        if space(u & 4294967295) != 0:
            break
        p = u >> 32
    capture(w, 0, start, p)
    schema = 0
    if exact(s, w, start, p, L_schema6) != 0:
        schema = 6
    elif exact(s, w, start, p, L_schema7) != 0:
        schema = 7
    elif exact(s, w, start, p, L_schema8) != 0:
        schema = 8
    if schema == 0:
        return 0
    p = space1(s, p, b)
    if p == MAX or name(s, p, b, 0) == 0:
        return 0
    capture(w, 1, p, b)
    put(w, SCHEMA, schema)
    return 1

def function_header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = literal(s, w, a, b, L_fn)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    next = name_end(s, p, b, 0)
    if next == MAX:
        return 0
    capture(w, 0, p, next)
    p = group(s, w, next, b, 1)
    if p == MAX:
        return 0
    p = space0(s, p, b)
    p = literal(s, w, p, b, L_arrow)
    if p == MAX:
        return 0
    p = space0(s, p, b)
    p = group(s, w, p, b, 2)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    p = literal(s, w, p, b, L_effects)
    if p == MAX:
        return 0
    p = group(s, w, p, b, 3)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    p = literal(s, w, p, b, L_entry)
    if p == MAX:
        return 0
    p = group(s, w, p, b, 4)
    if p == MAX or name(s, capture_a(w, 4), capture_b(w, 4), 0) == 0:
        return 0
    put(w, LOANS, 0)
    if p == b:
        return 1
    p = space1(s, p, b)
    if p == MAX:
        return 0
    p = literal(s, w, p, b, L_loans)
    if p == MAX:
        return 0
    p = group(s, w, p, b, 5)
    if p != b:
        return 0
    put(w, LOANS, 1)
    return 1

def block_header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    return named_group(s, w, a, b, L_block)

def jump_header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    return named_group(s, w, a, b, L_jump)

def named_group(s:readbuf, w:mutbuf, a:u64, b:u64, code:u64) -> u64:
    p = literal(s, w, a, b, code)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    next = name_end(s, p, b, 0)
    if next == MAX:
        return 0
    capture(w, 0, p, next)
    p = group(s, w, next, b, 1)
    if p == b:
        return 1
    return 0

def unary(s:readbuf, w:mutbuf, a:u64, b:u64, code:u64) -> u64:
    p = literal(s, w, a, b, code)
    if p == MAX:
        return 0
    p = group(s, w, p, b, 0)
    if p == b:
        return 1
    return 0

def branch_header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = literal(s, w, a, b, L_branch)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    next = name_end(s, p, b, 0)
    if next == MAX:
        return 0
    capture(w, 0, p, next)
    p = space1(s, next, b)
    if p == MAX:
        return 0
    next = name_end(s, p, b, 0)
    if next == MAX:
        return 0
    capture(w, 1, p, next)
    p = group(s, w, next, b, 2)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX:
        return 0
    next = name_end(s, p, b, 0)
    if next == MAX:
        return 0
    capture(w, 3, p, next)
    p = group(s, w, next, b, 4)
    if p == b:
        return 1
    return 0

def trap_header(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = literal(s, w, a, b, L_trap)
    if p == MAX:
        return 0
    p = space1(s, p, b)
    if p == MAX or name(s, p, b, 0) == 0:
        return 0
    capture(w, 0, p, b)
    return 1

def instruction(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = a
    while p < b and byte(s, p) != 61:
        p = p + 1
    if p == a or p == b:
        return 0
    capture(w, 0, a, p)
    p = space0(s, p + 1, b)
    next = name_end(s, p, b, 1)
    if next == MAX:
        return 0
    capture(w, 1, p, next)
    p = group(s, w, next, b, 2)
    if p == MAX:
        return 0
    put(w, CAP + 96, 0)
    if p == b:
        return 1
    p = space1(s, p, b)
    if p == MAX:
        return 0
    capture(w, 3, p, b)
    put(w, CAP + 96, 1)
    return 1

def group(s:readbuf, w:mutbuf, at:u64, end:u64, field:u64) -> u64:
    if at >= end or byte(s, at) != 40:
        return MAX
    start = at + 1
    p = start
    while p < end:
        c = byte(s, p)
        if c == 40:
            return MAX
        if c == 41:
            capture(w, field, start, p)
            return p + 1
        p = p + 1
    return MAX

def capture(w:mutbuf, field:u64, a:u64, b:u64) -> u64:
    put(w, CAP + field * 16, a)
    put(w, CAP + field * 16 + 8, b)
    return 0

def capture_a(w:mutbuf, field:u64) -> u64:
    return get(w, CAP + field * 16)

def capture_b(w:mutbuf, field:u64) -> u64:
    return get(w, CAP + field * 16 + 8)

def literal(s:readbuf, w:mutbuf, at:u64, end:u64, code:u64) -> u64:
    n = get(w, LITERAL_INDEX + code * 16 + 8)
    start = get(w, LITERAL_INDEX + code * 16)
    if at > end or n > end - at:
        return MAX
    i = 0
    while i < n:
        if byte(s, at + i) != byte(w, start + i):
            return MAX
        i = i + 1
    return at + n

def exact(s:readbuf, w:mutbuf, at:u64, end:u64, code:u64) -> u64:
    if literal(s, w, at, end, code) == end:
        return 1
    return 0

def letter(c:u64) -> u64:
    if c == 95 or (c >= 65 and c <= 90) or (c >= 97 and c <= 122):
        return 1
    return 0

def name_end(s:readbuf, at:u64, end:u64, opcode:u64) -> u64:
    if at >= end or letter(byte(s, at)) == 0:
        return MAX
    p = at + 1
    while p < end:
        c = byte(s, p)
        if letter(c) == 0 and (c < 48 or c > 57) and (opcode == 0 or c != 46):
            break
        p = p + 1
    if p - at > 128:
        return MAX
    return p

def name(s:readbuf, at:u64, end:u64, opcode:u64) -> u64:
    if name_end(s, at, end, opcode) == end:
        return 1
    return 0

def space(cp:u64) -> u64:
    if (cp >= 9 and cp <= 13) or (cp >= 28 and cp <= 32) or cp == 133 or cp == 160 or cp == 5760:
        return 1
    if (cp >= 8192 and cp <= 8202) or cp == 8232 or cp == 8233 or cp == 8239 or cp == 8287 or cp == 12288:
        return 1
    return 0

def space0(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        u = point(s, at, end, 0)
        if space(u & 4294967295) == 0:
            break
        at = u >> 32
    return at

def space1(s:readbuf, at:u64, end:u64) -> u64:
    next = space0(s, at, end)
    if next == at:
        return MAX
    return next

def trim(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    a = space0(s, a, b)
    p = a
    last = a
    while p < b:
        u = point(s, p, b, 0)
        p = u >> 32
        if space(u & 4294967295) == 0:
            last = p
    put(w, SPAN_A, a)
    put(w, SPAN_B, last)
    return 0

def list_check(s:readbuf, w:mutbuf, a:u64, b:u64, parameters:u64) -> u64:
    trim(s, w, a, b)
    if get(w, SPAN_A) == get(w, SPAN_B):
        put(w, ITEMS, 0)
        return 1
    count = 1
    p = a
    while p < b:
        if byte(s, p) == 44:
            count = count + 1
        p = p + 1
    if count > 256:
        return fail(w, 9, get(w, LINE))
    put(w, ITEMS, count)
    p = a
    while p <= b:
        next = p
        while next < b and byte(s, next) != 44:
            next = next + 1
        trim(s, w, p, next)
        if get(w, SPAN_A) == get(w, SPAN_B):
            return fail(w, 10, get(w, LINE))
        p = next + 1
    p = a
    while p <= b:
        next = p
        while next < b and byte(s, next) != 44:
            next = next + 1
        trim(s, w, p, next)
        if parameters == 0:
            if name(s, get(w, SPAN_A), get(w, SPAN_B), 0) == 0:
                return fail(w, 11, get(w, LINE))
        elif parameter(s, w, get(w, SPAN_A), get(w, SPAN_B)) == 0:
            return fail(w, 12, get(w, LINE))
        p = next + 1
    return 1

def parameter(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    p = name_end(s, a, b, 0)
    if p == MAX:
        return 0
    put(w, PARAM_A, a)
    put(w, PARAM_B, p)
    p = space0(s, p, b)
    if p >= b or byte(s, p) != 58:
        return 0
    p = space0(s, p + 1, b)
    if name(s, p, b, 0) == 0:
        return 0
    put(w, PARAM_TA, p)
    put(w, PARAM_TB, b)
    return 1

def list_emit(s:readbuf, w:mutbuf, a:u64, b:u64, parameters:u64) -> u64:
    append(w, 91)
    trim(s, w, a, b)
    if get(w, SPAN_A) != get(w, SPAN_B):
        p = a
        count = 0
        while p <= b:
            next = p
            while next < b and byte(s, next) != 44:
                next = next + 1
            trim(s, w, p, next)
            if count != 0:
                append(w, 44)
            if parameters == 0:
                quote(s, w, get(w, SPAN_A), get(w, SPAN_B))
            else:
                parameter(s, w, get(w, SPAN_A), get(w, SPAN_B))
                text(w, L_name)
                quote(s, w, get(w, PARAM_A), get(w, PARAM_B))
                text(w, L_type)
                quote(s, w, get(w, PARAM_TA), get(w, PARAM_TB))
                append(w, 125)
            count = count + 1
            p = next + 1
    return append(w, 93)

def json_check(s:readbuf, w:mutbuf, a:u64, b:u64, kind:u64) -> u64:
    put(w, JSON_START, a)
    put(w, JSON_N, b - a)
    zero(w, JSON_STATE, JSON_STATE_CAP)
    maximum = 2048
    depth = 16
    error = 23
    shape = 24
    if kind == 2:
        maximum = 257
        depth = 2
        error = 25
        shape = 26
    put(w, JSON_STATE + 48, maximum)
    put(w, JSON_STATE + 56, depth)
    first = jp_preflight(s, w)
    if first != 0:
        return fail(w, error, get(w, LINE))
    zero(w, JSON_STATE, JSON_STATE_CAP)
    put(w, JSON_STATE + 48, 262144)
    put(w, JSON_STATE + 56, 128)
    second = jp_preflight(s, w)
    if second != 0 or integer_values(s, w, a, b) == 0:
        return fail(w, error, get(w, LINE))
    p = ascii_space(s, a, b)
    if p == b:
        return fail(w, error, get(w, LINE))
    if kind == 1:
        if byte(s, p) != 123:
            return fail(w, shape, get(w, LINE))
    elif origins(s, w, p, b) == 0:
        return fail(w, shape, get(w, LINE))
    return 1

def integer_values(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    at = a
    while at < b:
        c = byte(s, at)
        if c == 34:
            at = at + 1
            while at < b:
                c = byte(s, at)
                at = at + 1
                if c == 34:
                    break
                if c == 92:
                    at = at + 1
        elif c >= 48 and c <= 57:
            first = at
            while at < b and byte(s, at) >= 48 and byte(s, at) <= 57:
                at = at + 1
            if get(w, DIGITS) != 0 and at - first > get(w, DIGITS):
                return 0
        else:
            at = at + 1
    return 1

def origins(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    if byte(s, at) != 91:
        return 0
    at = ascii_space(s, at + 1, end)
    if at < end and byte(s, at) == 93:
        return 1
    count = 0
    while at < end:
        count = count + 1
        if count > 256:
            return 0
        if byte(s, at) == 34:
            relative = at - get(w, JSON_START) + 1
            n = 0
            while True:
                unit = jp_decoded(s, w, relative)
                cp = unit & 4294967295
                relative = unit >> 32
                if cp == 1114112:
                    break
                if cp == 1114113 or (n == 0 and letter(cp) == 0):
                    return 0
                if letter(cp) == 0 and (cp < 48 or cp > 57):
                    return 0
                n = n + 1
                if n > 128:
                    return 0
            if n == 0:
                return 0
            at = get(w, JSON_START) + relative
        else:
            next = literal(s, w, at, end, L_null)
            if next == MAX:
                return 0
            at = next
        at = ascii_space(s, at, end)
        if at < end and byte(s, at) == 93:
            return 1
        if at >= end or byte(s, at) != 44:
            return 0
        at = ascii_space(s, at + 1, end)
    return 0

def ascii_space(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        c = byte(s, at)
        if c != 32 and c != 9 and c != 10 and c != 13:
            break
        at = at + 1
    return at

def point(s:readbuf, at:u64, end:u64, surrogate:u64) -> u64:
    if at >= end:
        return MAX
    c = byte(s, at)
    next = at + 1
    if c < 128:
        return (next << 32) | c
    count = 0
    cp = 0
    minimum = 0
    if c >= 194 and c <= 223:
        count = 1
        cp = c & 31
        minimum = 128
    elif c >= 224 and c <= 239:
        count = 2
        cp = c & 15
        minimum = 2048
    elif c >= 240 and c <= 244:
        count = 3
        cp = c & 7
        minimum = 65536
    if count == 0 or count > end - next:
        return MAX
    i = 0
    while i < count:
        c = byte(s, next)
        if c < 128 or c > 191:
            return MAX
        cp = (cp << 6) | (c & 63)
        next = next + 1
        i = i + 1
    if cp < minimum or cp > 1114111 or (surrogate == 0 and cp >= 55296 and cp <= 57343):
        return MAX
    return (next << 32) | cp

def append(w:mutbuf, value:u64) -> u64:
    at = get(w, CURSOR)
    if at == MAX:
        put(w, 8, 1)
        return 0
    if get(w, MODE) != 0:
        if at >= length(w) or at >= get(w, WRITE_END):
            put(w, 8, 1)
            return 0
        store(w, at, value)
    put(w, CURSOR, at + 1)
    return 1

def text(w:mutbuf, code:u64) -> u64:
    at = get(w, LITERAL_INDEX + code * 16)
    n = get(w, LITERAL_INDEX + code * 16 + 8)
    i = 0
    while i < n:
        append(w, byte(w, at + i))
        i = i + 1
    return 1

def span(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    while a < b:
        append(w, byte(s, a))
        a = a + 1
    return 1

def quote(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    append(w, 34)
    span(s, w, a, b)
    return append(w, 34)

def decimal(w:mutbuf, value:u64) -> u64:
    scale = 1
    while scale <= value >> 1:
        if scale > MAX >> 4:
            break
        next = scale * 10
        if next > value:
            break
        scale = next
    while scale != 0:
        digit = 0
        while value >= scale:
            value = value - scale
            digit = digit + 1
        append(w, 48 + digit)
        if scale == 1:
            break
        old = scale
        scale = 0
        # Decimal scales in this owner are bounded by MAX_LINES, so this
        # exact small division never depends on host decimal conversion.
        while old >= 10:
            old = old - 10
            scale = scale + 1
    return 1

def jp_byte(s:readbuf, w:mutbuf, at:u64) -> u64:
    return byte(s, get(w, JSON_START) + at)

def copy_read(w:mutbuf, s:readbuf, target:u64, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, at + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, 0)
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
def preflight_rebased():
    """Exact algorithm, one explicit source-span/private-arena adaptation.
    The original o key table and w stack remain disjoint in the parser arena.
    Every source helper gains the same private w; no grammar statement changes.
    """
    nodes=ast.parse(PREFLIGHT_SOURCE).body
    old={n.name:n for n in nodes};names=set(old)-{"get","put"}
    original={n:[a.arg for a in old[n].args.args] for n in names}
    class Rebase(ast.NodeTransformer):
        def visit_Call(self,n):
            if not isinstance(n.func,ast.Name):return self.generic_visit(n)
            fn=n.func.id
            if fn=="get" or fn=="put":
                assert isinstance(n.args[0],ast.Name)
                which=n.args[0].id;assert which in ("o","w")
                args=[ast.Name("w",ast.Load()),ast.BinOp(ast.Name("JSON_KEYS" if which=="o" else "JSON_STATE",ast.Load()),ast.Add(),self.visit(n.args[1]))]
                args.extend(self.visit(x) for x in n.args[2:])
                return ast.copy_location(ast.Call(ast.Name(fn,ast.Load()),args,[]),n)
            if fn=="length":
                assert len(n.args)==1 and isinstance(n.args[0],ast.Name)
                which=n.args[0].id
                if which=="s":return ast.parse("get(w, JSON_N)",mode="eval").body
                return ast.Name("JSON_KEYS_CAP" if which=="o" else "JSON_STATE_CAP",ast.Load())
            if fn=="byte":
                assert isinstance(n.args[0],ast.Name) and n.args[0].id=="s"
                return ast.copy_location(ast.Call(ast.Name("jp_byte",ast.Load()),[ast.Name("s",ast.Load()),ast.Name("w",ast.Load()),self.visit(n.args[1])],[]),n)
            if fn in names:
                args=[self.visit(a) for name,a in zip(original[fn],n.args) if name!="o"]
                assert len(n.args)==len(original[fn])
                if "w" not in original[fn]:args.insert(1,ast.Name("w",ast.Load()))
                return ast.copy_location(ast.Call(ast.Name("jp_"+fn,ast.Load()),args,[]),n)
            return self.generic_visit(n)
    result=[]
    for n in nodes:
        if n.name not in names:continue
        name=n.name
        n=Rebase().visit(n)
        n.name="jp_"+name
        n.args.args=[a for a in n.args.args if a.arg!="o"]
        if "w" not in original[name]:n.args.args.insert(1,ast.arg(arg="w",annotation=ast.Name("mutbuf",ast.Load())))
        if name=="preflight":n.returns=ast.Name("u64",ast.Load())
        result.append(ast.fix_missing_locations(n))
    return "\n".join(ast.unparse(n) for n in result)+"\n"

def source():
    import tools.generate_hia_json_preflight as original
    assert sha256(Path(original.__file__).read_bytes()).hexdigest()==PREFLIGHT_SHA
    constants=dict(CONSTANTS)
    raw=bytearray(constants["LITERAL_DATA"])
    for i,(name,text) in enumerate(LITERALS.items()):
        constants["L_"+name]=i
        data=text.encode("utf-8");at=len(raw);raw.extend(data)
        row=constants["LITERAL_INDEX"]+16*i
        raw[row:row+8]=at.to_bytes(8,"little")
        raw[row+8:row+16]=len(data).to_bytes(8,"little")
    assert len(raw)<constants["ERROR_TEXT"],len(raw)
    writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little")) for at in range(constants["LITERAL_INDEX"],len(raw),8) if any(raw[at:at+8])]
    functions=[];calls=[]
    for start in range(0,len(writes),24):
        name="literals_"+str(start//24);calls.append("    "+name+"(w)")
        lines=["def "+name+"(w:mutbuf) -> u64:"]
        lines+=["    put(w, "+str(at)+", "+str(value)+")" for at,value in writes[start:start+24]]
        lines+=["    return 0"];functions.append("\n".join(lines))
    table="def literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"
    result=BODY+"\n"+preflight_rebased()+"\n"+table+"\n".join(functions)+"\n"
    return result,constants,dict(status="AUTHORING_ONLY",reference_sha256="e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03",
        preflight_source_sha256=PREFLIGHT_SHA,source_bytes=1048576,lines=16384,line_bytes=16384,
        functions=256,blocks=4096,operations=16384,list_items=256,attribute_budget=[2048,16],
        origins_budget=[257,2],decode_budget=[262144,128],integer_digits_from_command=True,
        utf8_before_controls_before_all_lines_before_syntax=True,syntax_json_is_not_core_authority=True,
        private_immutable_source_required_before_first_GROW=True)
