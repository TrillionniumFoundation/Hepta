"""Author native rmcp HTTP metadata and standard-header decisions.

Only the checked-in HIA source runs in the service. The private entry consumes
fresh header and SDK projections produced by the captured native roles.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_mcp_canonical import source_program
from tools.generate_hia_mcp_sdk_request import program as sdk_program

ASCII=(
 'protocolVersion','capabilities','experimental','session','workdir','name','uri','taskId',
 'initialize','tools/call','prompts/get','resources/read','resources/subscribe','resources/unsubscribe',
 'tasks/get','tasks/update','tasks/cancel',
 '2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28',
 'mcp-protocol-version','mcp-session-id','last-event-id','mcp-method','mcp-name',
 '=?base64?','?=',
)
LITERALS=(
 'Bad Request: Invalid MCP-Protocol-Version header encoding',
 'Bad Request: Unsupported MCP-Protocol-Version: ',
 'Invalid Request: MCP-Protocol-Version header (',
 ') does not match initialize params.protocolVersion (',
 ')',
 'Invalid params: request _meta is missing or has malformed required fields: ',
 'io.modelcontextprotocol/protocolVersion',
 ', ',
 'io.modelcontextprotocol/clientCapabilities',
 'request _meta protocolVersion requires MCP-Protocol-Version header',
 'MCP-Protocol-Version header (',
 ') does not match request _meta protocolVersion (',
 'multiple Mcp-Method header values supplied; initialize requires exactly one',
 'Mcp-Method header \x60',
 '\x60 does not match body method \x60',
 '\x60',
 'duplicate Mcp-Method header',
 'Mcp-Method header contains invalid characters',
 'missing required Mcp-Method header',
 'duplicate Mcp-Name header',
 'Mcp-Name header contains invalid characters',
 'missing required Mcp-Name header for \x60',
 'Mcp-Name header is not valid Base64',
 'Mcp-Name header \x60',
 '\x60 does not match body value \x60',
 '{"jsonrpc":"2.0","id":',
 'null',
 ',"error":{"code":',
 '-32600',
 '-32602',
 '-32020',
 ',"message":',
 '}}',
 '{"jsonrpc":"2.0"',
)
SOURCE=r'''
def metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 8388608 or length(o) < 8388608 or length(w) != 46137344:
        return 4294967293
    if word_load(s, 0) != INPUT_MAGIC or word_load(s, 8) > 2 or word_load(s, 56) != 0:
        return 4294967293
    mode = word_load(s, 8)
    head = word_load(s, 16)
    desc = word_load(s, 24)
    body = word_load(s, 32)
    sdk = word_load(s, 40)
    catalog = word_load(s, 48)
    if head > 417792 or desc > 3328 or body > 4194304 or sdk > 160 or catalog > 8388608:
        return 4294967293
    if 64 + head + desc + body + sdk + catalog != length(s):
        return 4294967293
    if sdk != 0 and sdk != 160:
        return 4294967293
    if (body == 0) != (sdk == 0):
        return 4294967293
    if mode == 2:
        if head != 0 or desc != 0 or catalog != 0 or sdk != 160:
            return 4294967293
    else:
        if desc < 128 or word_load(s, 64 + head) != HEADER_MAGIC:
            return 4294967293
        count = word_load(s, 64 + head + 56)
        if count > 100 or desc != 128 + 32 * count or word_load(s, 64 + head + 8) > head:
            return 4294967293
        index = 0
        while index < count:
            row = 64 + head + 128 + 32 * index
            start = word_load(s, row)
            size = word_load(s, row + 8)
            value = word_load(s, row + 16)
            amount = word_load(s, row + 24)
            if start > head or size == 0 or size > head - start or value > head or amount > head - value:
                return 4294967293
            index = index + 1
    sdk_at = 64 + head + desc + body
    if sdk != 0:
        if word_load(s, sdk_at) != SDK_MAGIC or word_load(s, sdk_at + 8) < 1 or word_load(s, sdk_at + 8) > 4:
            return 4294967293
        if word_load(s, sdk_at + 16) > 14 or word_load(s, sdk_at + 64) > 2 or word_load(s, sdk_at + 104) > 3:
            return 4294967293
        if word_load(s, sdk_at + 144) != 0 or word_load(s, sdk_at + 152) != 0:
            return 4294967293
        index = 24
        while index <= 120:
            if index <= 48 or index == 80 or index == 88 or index == 96 or index == 120:
                span = word_load(s, sdk_at + index) & 9223372036854775807
                if span != 0:
                    lo = span & 16777215
                    hi = (span >> 24) & 16777215
                    if lo == 0 or hi < lo or hi > body or span >> 48 != 0:
                        return 4294967293
            index = index + 8
    index = 30000
    while index < 30336:
        put(w, index, 0)
        index = index + 8
    put(w, 30000, mode)
    put(w, 30008, 64 + head)
    put(w, 30016, 64 + head + desc)
    put(w, 30024, sdk_at)
    put(w, 30032, body)
    index = 0
    while index < 128:
        put(o, index, 0)
        index = index + 8
    put(o, 0, OUTPUT_MAGIC)
    put(o, 16, 1)
    if mode != 2:
        index = 0
        while index < 5:
            hit = md_header_find(s, w, 23 + index)
            put(w, 30040 + index * 8, hit)
            if index < 3:
                put(o, 40 + index * 8, hit & 4294967295)
            index = index + 1
    if sdk != 0:
        put(w, 30080, word_load(s, sdk_at + 8))
        put(w, 30088, word_load(s, sdk_at + 16))
        put(w, 30096, md_absolute(word_load(s, sdk_at + 24), get(w, 30016)))
        put(w, 30104, word_load(s, sdk_at + 64))
        put(w, 30112, word_load(s, sdk_at + 72))
        put(w, 30120, md_absolute(word_load(s, sdk_at + 32), get(w, 30016)))
        put(w, 30128, md_absolute(word_load(s, sdk_at + 40), get(w, 30016)))
        put(w, 30136, md_absolute(word_load(s, sdk_at + 88), get(w, 30016)))
        put(w, 30144, word_load(s, sdk_at + 96) & 9223372036854775807)
        put(w, 30152, word_load(s, sdk_at + 104))
        put(w, 30160, word_load(s, sdk_at + 112))
    if mode == 2:
        md_capabilities(s, o, w, 1)
        return 128
    result = md_protocol(s, o, w)
    if result != 0:
        return result
    md_capabilities(s, o, w, choose(get(o, 16) == 0, 1, 0))
    if mode == 1:
        result = md_standard(s, o, w)
        if result != 0:
            return result
    return 128

def md_absolute(span:u64, offset:u64) -> u64:
    span = span & 9223372036854775807
    if span == 0:
        return 0
    return (((span >> 24) + offset) << 24) | ((span & 16777215) + offset)

def md_relative(span:u64, offset:u64) -> u64:
    if span == 0:
        return 0
    return ((((span >> 24) & 16777215) - offset) << 24) | ((span & 16777215) - offset)

def md_header_find(s:readbuf, w:mutbuf, code:u64) -> u64:
    desc = get(w, 30008)
    count = word_load(s, desc + 56)
    index = 0
    first = 0
    matches = 0
    while index < count:
        row = desc + 128 + index * 32
        at = 64 + word_load(s, row)
        size = word_load(s, row + 8)
        if md_raw_match(s, at, size, code, 1) == 1:
            if first == 0:
                first = index + 1
            matches = matches + 1
        index = index + 1
    return (matches << 32) | first

def md_header_span(s:readbuf, w:mutbuf, hit:u64) -> u64:
    row = hit & 4294967295
    if row == 0:
        return 0
    row = get(w, 30008) + 128 + (row - 1) * 32
    return (word_load(s, row + 24) << 32) | (64 + word_load(s, row + 16))

def md_raw_match(s:readbuf, at:u64, size:u64, code:u64, fold:u64) -> u64:
    if size != md_ascii_size(code):
        return 0
    index = 0
    while index < size:
        ch = byte(s, at + index)
        if fold == 1 and ch >= 65 and ch <= 90:
            ch = ch + 32
        if ch != md_ascii_byte(code, index):
            return 0
        index = index + 1
    return 1

def md_json_match(s:readbuf, at:u64, code:u64) -> u64:
    if at >= length(s) or byte(s, at) != 34:
        return 0
    at = at + 1
    index = 0
    size = md_ascii_size(code)
    while index <= size:
        unit = decoded(s, at)
        cp = unit & 4294967295
        at = unit >> 32
        if index == size:
            return choose(cp == 1114112, 1, 0)
        if cp != md_ascii_byte(code, index):
            return 0
        index = index + 1
    return 0

def md_find(s:readbuf, object:u64, code:u64) -> u64:
    if object == 0 or byte(s, (object & 16777215) - 1) != 123:
        return 0
    at = whitespace(s, (object & 16777215))
    answer = 0
    while byte(s, at) != 125:
        matches = md_json_match(s, at, code)
        at = whitespace(s, sdk_skip(s, at))
        at = whitespace(s, at + 1)
        end = sdk_skip(s, at)
        if matches == 1:
            answer = (end << 24) | (at + 1)
        at = whitespace(s, end)
        if byte(s, at) == 44:
            at = whitespace(s, at + 1)
    return answer

def md_ascii_valid(s:readbuf, span:u64) -> u64:
    at = span & 4294967295
    end = at + (span >> 32)
    while at < end:
        ch = byte(s, at)
        if ch != 9 and (ch < 32 or ch >= 127):
            return 0
        at = at + 1
    return 1

def md_known(s:readbuf, span:u64) -> u64:
    code = 18
    while code <= 22:
        if md_raw_match(s, span & 4294967295, span >> 32, code, 0) == 1:
            return code - 17
        code = code + 1
    return 0

def md_new_version(s:readbuf, span:u64) -> u64:
    at = span & 4294967295
    size = span >> 32
    index = 0
    while index < size and index < 10:
        ch = byte(s, at + index)
        expected = md_ascii_byte(22, index)
        if ch < expected:
            return 0
        if ch > expected:
            return 1
        index = index + 1
    return choose(size >= 10, 1, 0)

def md_new_json_version(s:readbuf, span:u64) -> u64:
    at = (span & 16777215)
    index = 0
    while index <= 10:
        unit = decoded(s, at)
        cp = unit & 4294967295
        at = unit >> 32
        if index == 10:
            return 1
        if cp == 1114112:
            return 0
        expected = md_ascii_byte(22, index)
        if cp < expected:
            return 0
        if cp > expected:
            return 1
        index = index + 1
    return 0

def md_protocol(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    header = md_header_span(s, w, get(w, 30040))
    request = choose(get(w, 30080) == 1, 1, 0)
    role = get(w, 30088)
    missing = get(w, 30152)
    has_meta_version = choose(request == 1 and (missing & 1) == 0, 1, 0)
    if header != 0:
        if md_ascii_valid(s, header) == 0:
            at = md_literal(w, 1048576, 1)
            return md_error(s, o, w, 0, at)
        if has_meta_version == 0 and md_known(s, header) == 0:
            at = md_literal(w, 1048576, 2)
            at = md_append_input(s, w, at, header & 4294967295, header >> 32)
            return md_error(s, o, w, 0, at)
        put(w, 30168, md_new_version(s, header))
    if request == 1 and role == 1:
        if header != 0:
            version = md_find(s, get(w, 30128), 1)
            size = md_decode_string(s, w, version, 12582912)
            if md_raw_work_same(s, header & 4294967295, header >> 32, w, 12582912, size) == 0:
                at = md_literal(w, 1048576, 3)
                at = md_append_input(s, w, at, header & 4294967295, header >> 32)
                at = md_literal(w, at, 4)
                at = md_append_work(w, at, 12582912, size)
                at = md_literal(w, at, 5)
                return md_error(s, o, w, 1, at)
        put(o, 16, 1)
        return 0
    if request == 1:
        if has_meta_version == 0:
            if role == 10 or get(w, 30168) == 1:
                at = md_literal(w, 1048576, 6)
                if (missing & 1) != 0:
                    at = md_literal(w, at, 7)
                if missing == 3:
                    at = md_literal(w, at, 8)
                if (missing & 2) != 0:
                    at = md_literal(w, at, 9)
                return md_error(s, o, w, 2, at)
        else:
            if header == 0:
                at = md_literal(w, 1048576, 10)
                return md_error(s, o, w, 3, at)
            size = md_decode_string(s, w, get(w, 30136), 12582912)
            if md_raw_work_same(s, header & 4294967295, header >> 32, w, 12582912, size) == 0:
                at = md_literal(w, 1048576, 11)
                at = md_append_input(s, w, at, header & 4294967295, header >> 32)
                at = md_literal(w, at, 12)
                at = md_append_work(w, at, 12582912, size)
                at = md_literal(w, at, 5)
                return md_error(s, o, w, 3, at)
    legacy = 1
    if request == 1 and missing == 0:
        legacy = 0
    elif has_meta_version == 1:
        legacy = 1 - md_new_json_version(s, get(w, 30136))
    elif header != 0:
        legacy = 1 - get(w, 30168)
    put(o, 16, legacy)
    return 0

def md_capabilities(s:readbuf, o:mutbuf, w:mutbuf, allow_meta:u64) -> u64:
    if get(w, 30080) != 1:
        return 0
    cap = 0
    if allow_meta == 1 and (get(w, 30152) & 2) == 0:
        cap = md_absolute(get(w, 30144), get(w, 30016))
    elif get(w, 30088) == 1:
        cap = md_find(s, get(w, 30128), 2)
    if cap == 0:
        return 0
    put(o, 64, md_relative(cap, get(w, 30016)))
    experimental = 0
    at = (cap & 16777215) - 1
    if byte(s, at) == 123:
        experimental = md_find(s, cap, 3)
    elif byte(s, at) == 91:
        at = whitespace(s, at + 1)
        if byte(s, at) != 93:
            experimental = (sdk_skip(s, at) << 24) | (at + 1)
    session = md_find(s, experimental, 4)
    workdir = md_find(s, session, 5)
    if workdir != 0 and byte(s, (workdir & 16777215) - 1) == 34:
        put(o, 72, md_relative(workdir, get(w, 30016)))
    return 0

def md_standard(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 30168) == 0:
        return 0
    kind = get(w, 30080)
    if kind != 1 and kind != 2:
        return 0
    hit = get(w, 30064)
    header = md_header_span(s, w, hit)
    method = get(w, 30120)
    if kind == 1 and get(w, 30088) == 1:
        if hit == 0:
            return 0
        if hit >> 32 != 1:
            at = md_literal(w, 1048576, 13)
            return md_error(s, o, w, 3, at)
        if md_raw_match(s, header & 4294967295, header >> 32, 9, 0) == 0:
            at = md_literal(w, 1048576, 14)
            count = md_append_input(s, w, 10485760, header & 4294967295, header >> 32)
            at = md_lossy(w, at, 10485760, count)
            at = md_literal(w, at, 15)
            at = md_ascii_emit(w, at, 9)
            at = md_literal(w, at, 16)
            return md_error(s, o, w, 3, at)
        return 0
    result = md_single_header(s, o, w, 4)
    if result != 0:
        return result
    if header == 0:
        at = md_literal(w, 1048576, 19)
        return md_error(s, o, w, 3, at)
    size = md_decode_string(s, w, method, 12582912)
    if md_raw_work_same(s, header & 4294967295, header >> 32, w, 12582912, size) == 0:
        at = md_literal(w, 1048576, 14)
        at = md_append_input(s, w, at, header & 4294967295, header >> 32)
        at = md_literal(w, at, 15)
        at = md_append_work(w, at, 12582912, size)
        at = md_literal(w, at, 16)
        return md_error(s, o, w, 3, at)
    namekey = 0
    start = (method & 16777215) - 1
    if md_json_match(s, start, 10) == 1 or md_json_match(s, start, 11) == 1:
        namekey = 6
    elif md_json_match(s, start, 12) == 1 or md_json_match(s, start, 13) == 1 or md_json_match(s, start, 14) == 1:
        namekey = 7
    elif md_json_match(s, start, 15) == 1 or md_json_match(s, start, 16) == 1 or md_json_match(s, start, 17) == 1:
        namekey = 8
    if namekey == 0:
        return 0
    name = md_find(s, get(w, 30128), namekey)
    if name == 0 or byte(s, (name & 16777215) - 1) != 34:
        return 0
    result = md_single_header(s, o, w, 5)
    if result != 0:
        return result
    header = md_header_span(s, w, get(w, 30072))
    if header == 0:
        at = md_literal(w, 1048576, 22)
        at = md_append_work(w, at, 12582912, size)
        at = md_literal(w, at, 16)
        return md_error(s, o, w, 3, at)
    decoded_size = md_header_decode(s, w, header)
    if decoded_size == 18446744073709551615:
        at = md_literal(w, 1048576, 23)
        return md_error(s, o, w, 3, at)
    expected = md_decode_string(s, w, name, 12582912)
    if md_work_same(w, 10485760, decoded_size, 12582912, expected) == 0:
        at = md_literal(w, 1048576, 24)
        at = md_append_work(w, at, 10485760, decoded_size)
        at = md_literal(w, at, 25)
        at = md_append_work(w, at, 12582912, expected)
        at = md_literal(w, at, 16)
        return md_error(s, o, w, 3, at)
    return 0

def md_single_header(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:
    hit = get(w, 30040 + (index - 1) * 8)
    if hit >> 32 > 1:
        at = md_literal(w, 1048576, choose(index == 4, 17, 20))
        return md_error(s, o, w, 3, at)
    span = md_header_span(s, w, hit)
    if span != 0 and md_ascii_valid(s, span) == 0:
        at = md_literal(w, 1048576, choose(index == 4, 18, 21))
        return md_error(s, o, w, 3, at)
    return 0

def md_header_decode(s:readbuf, w:mutbuf, span:u64) -> u64:
    start = span & 4294967295
    size = span >> 32
    md_append_input(s, w, 10485760, start, size)
    if size >= 11 and md_raw_match(s, start, 9, 28, 0) == 1 and md_raw_match(s, start + size - 2, 2, 29, 0) == 1:
        if (size - 11) & 3 != 0:
            return 18446744073709551615
        at = 9
        end = size - 2
        used = 0
        while at < end:
            aa = md_b64(byte(w, 10485760 + at))
            bb = md_b64(byte(w, 10485761 + at))
            cc = md_b64(byte(w, 10485762 + at))
            dd = md_b64(byte(w, 10485763 + at))
            if aa >= 64 or bb >= 64 or cc > 64 or dd > 64:
                return 18446744073709551615
            store(w, 10485760 + used, (aa << 2) | (bb >> 4))
            used = used + 1
            if cc == 64:
                if at + 4 != end or dd != 64 or (bb & 15) != 0:
                    return 18446744073709551615
            else:
                store(w, 10485760 + used, ((bb & 15) << 4) | (cc >> 2))
                used = used + 1
                if dd == 64:
                    if at + 4 != end or (cc & 3) != 0:
                        return 18446744073709551615
                else:
                    store(w, 10485760 + used, ((cc & 3) << 6) | dd)
                    used = used + 1
            at = at + 4
        size = used
    at = 10485760
    end = at + size
    while at < end:
        unit = md_utf8(w, at, end)
        if (unit & 4294967295) > 1114111:
            return 18446744073709551615
        at = unit >> 32
    return size

def md_b64(ch:u64) -> u64:
    if ch >= 65 and ch <= 90:
        return ch - 65
    if ch >= 97 and ch <= 122:
        return ch - 71
    if ch >= 48 and ch <= 57:
        return ch + 4
    if ch == 43:
        return 62
    if ch == 47:
        return 63
    if ch == 61:
        return 64
    return 65

def md_utf8(w:mutbuf, at:u64, end:u64) -> u64:
    ch = byte(w, at)
    if ch < 128:
        return ((at + 1) << 32) | ch
    count = 0
    cp = 0
    low = 128
    high = 191
    if ch >= 194 and ch <= 223:
        count = 2
        cp = ch & 31
    elif ch >= 224 and ch <= 239:
        count = 3
        cp = ch & 15
        if ch == 224:
            low = 160
        if ch == 237:
            high = 159
    elif ch >= 240 and ch <= 244:
        count = 4
        cp = ch & 7
        if ch == 240:
            low = 144
        if ch == 244:
            high = 143
    if count == 0:
        return ((at + 1) << 32) | 1114112
    index = 1
    while index < count:
        if at + index >= end:
            return (end << 32) | 1114112
        ch = byte(w, at + index)
        if ch < low or ch > high:
            return ((at + index) << 32) | 1114112
        cp = cp * 64 + (ch & 63)
        low = 128
        high = 191
        index = index + 1
    return ((at + count) << 32) | cp

def md_lossy(w:mutbuf, target:u64, at:u64, end:u64) -> u64:
    while at < end:
        unit = md_utf8(w, at, end)
        cp = unit & 4294967295
        at = unit >> 32
        if cp > 1114111:
            cp = 65533
        target = md_scalar(w, target, cp)
    return target

def md_scalar(w:mutbuf, at:u64, cp:u64) -> u64:
    if cp < 128:
        store(w, at, cp)
        return at + 1
    if cp < 2048:
        store(w, at, 192 | (cp >> 6))
        store(w, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(w, at, 224 | (cp >> 12))
        store(w, at + 1, 128 | ((cp >> 6) & 63))
        store(w, at + 2, 128 | (cp & 63))
        return at + 3
    store(w, at, 240 | (cp >> 18))
    store(w, at + 1, 128 | ((cp >> 12) & 63))
    store(w, at + 2, 128 | ((cp >> 6) & 63))
    store(w, at + 3, 128 | (cp & 63))
    return at + 4

def md_decode_string(s:readbuf, w:mutbuf, span:u64, target:u64) -> u64:
    if span == 0 or byte(s, (span & 16777215) - 1) != 34:
        return 0
    start = target
    at = span & 16777215
    end = (span >> 24) & 16777215
    while at < end:
        unit = decoded(s, at)
        cp = unit & 4294967295
        at = unit >> 32
        if cp == 1114112:
            return target - start
        target = md_scalar(w, target, cp)
    return target - start

def md_append_input(s:readbuf, w:mutbuf, at:u64, start:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, byte(s, start + index))
        index = index + 1
    return at + size

def md_append_work(w:mutbuf, at:u64, start:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, byte(w, start + index))
        index = index + 1
    return at + size

def md_raw_work_same(s:readbuf, start:u64, size:u64, w:mutbuf, other:u64, amount:u64) -> u64:
    if size != amount:
        return 0
    index = 0
    while index < size:
        if byte(s, start + index) != byte(w, other + index):
            return 0
        index = index + 1
    return 1

def md_work_same(w:mutbuf, start:u64, size:u64, other:u64, amount:u64) -> u64:
    if size != amount:
        return 0
    index = 0
    while index < size:
        if byte(w, start + index) != byte(w, other + index):
            return 0
        index = index + 1
    return 1

def md_error(s:readbuf, o:mutbuf, w:mutbuf, code:u64, end:u64) -> u64:
    put(o, 8, 400)
    put(o, 64, 0)
    put(o, 72, 0)
    at = 128
    if code == 0:
        put(o, 24, 1)
        index = 1048576
        while index < end:
            store(o, at, byte(w, index))
            at = at + 1
            index = index + 1
    else:
        put(o, 24, 2)
        at = md_literal(o, at, choose(get(w, 30080) == 1, 26, 34))
        if get(w, 30080) == 1:
            if get(w, 30104) == 0:
                at = md_literal(o, at, 27)
            elif get(w, 30104) == 1:
                value = get(w, 30112)
                if value >> 63 == 1:
                    store(o, at, 45)
                    at = at + 1
                    value = 0 - value
                at = md_decimal(o, at, value)
            else:
                store(o, at, 34)
                at = at + 1
                cursor = get(w, 30096) & 16777215
                going = 1
                while going == 1:
                    unit = decoded(s, cursor)
                    cp = unit & 4294967295
                    cursor = unit >> 32
                    if cp == 1114112:
                        going = 0
                    else:
                        at = sdk_id_scalar(o, at, cp)
                store(o, at, 34)
                at = at + 1
        at = md_literal(o, at, 28)
        at = md_literal(o, at, 28 + code)
        at = md_literal(o, at, 32)
        store(o, at, 34)
        at = at + 1
        cursor = 1048576
        while cursor < end:
            ch = byte(w, cursor)
            if ch < 128:
                at = sdk_id_scalar(o, at, ch)
            else:
                store(o, at, ch)
                at = at + 1
            cursor = cursor + 1
        store(o, at, 34)
        at = at + 1
        at = md_literal(o, at, 33)
    put(o, 32, at - 128)
    return at

def md_decimal(o:mutbuf, at:u64, value:u64) -> u64:
    digits = 1
    copy = value
    while copy >= 10:
        copy = sdk_divide_ten(copy)
        digits = digits + 1
    end = at + digits
    cursor = end
    while cursor > at:
        cursor = cursor - 1
        quotient = sdk_divide_ten(value)
        store(o, cursor, value - quotient * 10 + 48)
        value = quotient
    return end

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0
'''

def program():
    source=SOURCE
    for name,value in [('INPUT_MAGIC',int.from_bytes(b'HIAHMD01','little')),
                       ('OUTPUT_MAGIC',int.from_bytes(b'HIAHMO01','little')),
                       ('HEADER_MAGIC',int.from_bytes(b'HIAHHR01','little')),
                       ('SDK_MAGIC',int.from_bytes(b'HIASDK01','little'))]:
        source=source.replace(name,str(value))
    generated=[]
    sizes=['def md_ascii_size(code:u64) -> u64:']
    values=['def md_ascii_byte(code:u64, index:u64) -> u64:']
    for index,string in enumerate(ASCII,1):
        raw=string.encode('ascii')
        sizes.extend((f'    if code == {index}:',f'        return {len(raw)}'))
        values.append(f'    if code == {index}:')
        for start in range(0,len(raw),8):
            part=raw[start:start+8];word=int.from_bytes(part,'little')
            values.extend((f'        if index < {start+len(part)}:',f'            return ({word} >> ((index - {start}) * 8)) & 255'))
    sizes.append('    return 0');values.append('    return 0')
    generated.extend(('\n'.join(sizes),'\n'.join(values)))
    generated.append('''def md_ascii_emit(w:mutbuf, at:u64, code:u64) -> u64:
    index = 0
    while index < md_ascii_size(code):
        store(w, at + index, md_ascii_byte(code, index))
        index = index + 1
    return at + index
''')
    dispatch=['def md_literal(w:mutbuf, at:u64, code:u64) -> u64:']
    for group in range((len(LITERALS)+3)//4):
        name=f'md_literal_{group}'
        dispatch.extend((f'    if code <= {(group+1)*4}:',f'        return {name}(w, at, code)'))
        lines=[f'def {name}(w:mutbuf, at:u64, code:u64) -> u64:']
        for index,string in enumerate(LITERALS[group*4:group*4+4],group*4+1):
            raw=string.encode('utf-8')
            lines.append(f'    if code == {index}:')
            for start in range(0,len(raw),8):
                part=raw[start:start+8]
                if len(part)==8:lines.append(f'        word_store(w, at + {start}, {int.from_bytes(part,"little")})')
                else:
                    for off,ch in enumerate(part):lines.append(f'        store(w, at + {start+off}, {ch})')
            lines.append(f'        return at + {len(raw)}')
        lines.append('    return at');generated.append('\n'.join(lines))
    dispatch.append('    return at');generated.append('\n'.join(dispatch))
    tree=ast.parse(source_program()+'\n'+sdk_program()+'\n'+source+'\n'+'\n\n'.join(generated))
    functions={fn.name:fn for fn in tree.body if isinstance(fn,ast.FunctionDef)}
    selected={'metadata'}
    previous=set()
    while selected!=previous:
        previous=set(selected)
        for name in previous:
            selected.update(n.func.id for n in ast.walk(functions[name]) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in functions)
    output='\n\n'.join(ast.unparse(functions[name]) for name in ['metadata',*sorted(selected-{'metadata'})])
    return document(output,'mcp_http_metadata')

def render():
    return render_assembly(program())

if __name__=='__main__':
    (Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_metadata.hepta').write_text(render())
