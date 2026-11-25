"""Native HTTP authentication-order and request-header admission policy."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document

LITERALS = (
    '', 'GET', 'HEAD', 'POST', 'DELETE', '/healthz', '/readyz', '/mcp',
    'origin', 'host', 'accept', 'content-type', 'mcp-protocol-version',
    'mcp-session-id', 'localhost', '127.0.0.1', '::1',
    'application/json', 'text/event-stream', 'q',
    '2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28',
    'ok\n', 'ready\n', 'not ready\n', 'Method Not Allowed',
    'Bad Request: missing Host header',
    'Bad Request: Invalid Host header',
    'Forbidden: Host header is not allowed',
    'Not Acceptable: Client must accept text/event-stream',
    'Not Acceptable: Client must accept both application/json and text/event-stream',
    'Unsupported Media Type: Content-Type must be application/json',
    'Bad Request: Invalid MCP-Protocol-Version header encoding',
    'Bad Request: Unsupported MCP-Protocol-Version: ',
    'Bad Request: Session ID is required',
    'Bad Request: Invalid Host header encoding',
)
SOURCE = r'''
def admit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 192 or length(o) < 524288 or length(w) < 8192:
        return 4294967293
    if word_load(s, 0) != MAGIC:
        return 4294967293
    head = word_load(s, 8)
    desc_size = word_load(s, 16)
    auth = word_load(s, 24)
    ready = word_load(s, 32)
    if head > 417792 or desc_size < 128 or desc_size > 3328 or auth > 1 or ready > 1:
        return 4294967293
    if word_load(s, 40) != 0 or word_load(s, 48) != 0 or word_load(s, 56) != 0:
        return 4294967293
    if length(s) != 64 + head + desc_size:
        return 4294967293
    desc = 64 + head
    if word_load(s, desc) != HEADER_MAGIC or word_load(s, desc + 8) != head or word_load(s, desc + 48) > 1:
        return 4294967293
    count = word_load(s, desc + 56)
    if count > 100 or desc_size != 128 + count * 32:
        return 4294967293
    index = 16
    while index < 48:
        point = word_load(s, desc + index)
        size = word_load(s, desc + index + 8)
        if point > head or size > head - point:
            return 4294967293
        index = index + 16
    index = 0
    while index < count * 2:
        point = word_load(s, desc + 128 + index * 16)
        size = word_load(s, desc + 136 + index * 16)
        if point > head or size > head - point:
            return 4294967293
        index = index + 1
    index = 0
    while index < desc_size:
        word_store(w, index, word_load(s, desc + index))
        index = index + 8
    method = 0
    index = 1
    while index <= 4:
        if eq(s, word_load(w, 16) + 64, word_load(w, 24), index, False):
            method = index
        index = index + 1
    flags = choose(method == 2, 1, 0)
    path_at = 64 + word_load(w, 32)
    if target_path(s, w, path_at, word_load(w, 40)) == False:
        return reply(o, 400, 0, flags, 0, 0)
    path_at = word_load(w, 4096)
    path_end = path_at + word_load(w, 4104)
    health = eq(s, path_at, path_end - path_at, 5, False)
    readiness = eq(s, path_at, path_end - path_at, 6, False)
    if health or readiness:
        if method != 1 and method != 2:
            return reply(o, 405, 0, flags, 1, 0)
        if health:
            return reply(o, 200, 0, flags | 2, 0, 25)
        if ready == 1:
            return reply(o, 200, 0, flags | 2, 0, 26)
        return reply(o, 503, 0, flags | 2, 0, 27)
    if field(s, w, 8, 0) != NONE:
        return reply(o, 403, 0, flags, 0, 0)
    if auth == 0:
        return reply(o, 401, 0, flags, 0, 0)
    if eq(s, path_at, path_end - path_at, 7, False) == False:
        if path_end - path_at < 5 or eq(s, path_at, 4, 7, False) == False or byte(s, path_at + 4) != 47:
            return reply(o, 404, 0, flags, 0, 0)
    host = field(s, w, 9, 0)
    host_at = word_load(w, 4112)
    host_size = word_load(w, 4120)
    if host == NONE:
        if host_size == 0:
            return reply(o, 400, 0, flags, 0, 29)
    else:
        host_at = 64 + word_load(w, host + 16)
        host_size = word_load(w, host + 24)
        if ascii_text(s, host_at, host_size) == False:
            return reply(o, 400, 0, flags, 0, 38)
    authority = host_allowed(s, host_at, host_size)
    if authority == 0:
        return reply(o, 400, 0, flags, 0, 30)
    if authority != 2:
        return reply(o, 403, 0, flags, 0, 31)
    if method == 3:
        if accepts(s, w) != 3:
            return reply(o, 406, 0, flags, 0, 33)
        content = field(s, w, 11, 0)
        if content == NONE:
            return reply(o, 415, 0, flags, 0, 34)
        first = 64 + word_load(w, content + 16)
        end = first + word_load(w, content + 24)
        if ascii_text(s, first, end - first) == False:
            return reply(o, 415, 0, flags, 0, 34)
        end = delimiter(s, first, end, 59, False)
        first = trim_start(s, first, end)
        end = trim_end(s, first, end)
        if eq(s, first, end - first, 17, True) == False:
            return reply(o, 415, 0, flags, 0, 34)
        return reply(o, 0, 1, flags, 0, 0)
    if method == 1:
        if accepts(s, w) & 2 == 0:
            return reply(o, 406, 0, flags, 0, 32)
    if method != 1 and method != 4:
        return reply(o, 405, 0, flags, 2, 28)
    version = field(s, w, 12, 0)
    if version != NONE:
        first = 64 + word_load(w, version + 16)
        size = word_load(w, version + 24)
        if ascii_text(s, first, size) == False:
            return reply(o, 400, 0, flags, 0, 35)
        index = 20
        selected = 0
        while index <= 24:
            if eq(s, first, size, index, False):
                selected = index
            index = index + 1
        if selected == 0:
            stop = literal(o, 64, 36)
            index = 0
            while index < size:
                store(o, stop + index, byte(s, first + index))
                index = index + 1
            response_head(o, 400, 0, flags, 0, stop + size - 64)
            return stop + size
        if selected == 24:
            return reply(o, 405, 0, flags, 3, 28)
    session = field(s, w, 13, 0)
    if session == NONE or ascii_text(s, 64 + word_load(w, session + 16), word_load(w, session + 24)) == False:
        return reply(o, 400, 0, flags, 0, 37)
    return reply(o, 0, choose(method == 1, 2, 3), flags, 0, 0)

def reply(o:mutbuf, status:u64, route:u64, flags:u64, allow:u64, text:u64) -> u32:
    end = literal(o, 64, text)
    response_head(o, status, route, flags, allow, end - 64)
    return end

def response_head(o:mutbuf, status:u64, route:u64, flags:u64, allow:u64, size:u64) -> u64:
    word_store(o, 0, RESPONSE_MAGIC)
    word_store(o, 8, status)
    word_store(o, 16, route)
    word_store(o, 24, flags)
    word_store(o, 32, size)
    word_store(o, 40, allow)
    word_store(o, 48, 0)
    word_store(o, 56, 0)
    return 0

def field(s:readbuf, w:mutbuf, key:u64, first:u64) -> u64:
    count = word_load(w, 56)
    index = first
    found = NONE
    while index < count and found == NONE:
        row = 128 + index * 32
        if eq(s, word_load(w, row) + 64, word_load(w, row + 8), key, True):
            found = row
        index = index + 1
    return found

def ascii_text(s:readbuf, at:u64, size:u64) -> bool:
    index = 0
    valid = True
    while index < size:
        ch = byte(s, at + index)
        if (ch < 32 and ch != 9) or ch > 126:
            valid = False
        index = index + 1
    return valid

def trim_start(s:readbuf, first:u64, end:u64) -> u64:
    while first < end and (byte(s, first) == 32 or byte(s, first) == 9):
        first = first + 1
    return first

def trim_end(s:readbuf, first:u64, end:u64) -> u64:
    while first < end and (byte(s, end - 1) == 32 or byte(s, end - 1) == 9):
        end = end - 1
    return end

def delimiter(s:readbuf, at:u64, end:u64, ch:u64, quoted_lists:bool) -> u64:
    quoted = False
    escaped = False
    found = end
    while at < end and found == end:
        value = byte(s, at)
        if quoted_lists and escaped:
            escaped = False
        elif quoted_lists and quoted and value == 92:
            escaped = True
        elif quoted_lists and value == 34:
            quoted = quoted == False
        elif quoted == False and value == ch:
            found = at
        at = at + 1
    return found

def accepts(s:readbuf, w:mutbuf) -> u64:
    mask = 0
    row = field(s, w, 10, 0)
    while row != NONE:
        start = 64 + word_load(w, row + 16)
        end = start + word_load(w, row + 24)
        if ascii_text(s, start, end - start):
            while start <= end:
                stop = delimiter(s, start, end, 44, True)
                semicolon = delimiter(s, start, stop, 59, True)
                first = trim_start(s, start, semicolon)
                last = trim_end(s, first, semicolon)
                good = True
                parameter = semicolon + 1
                while parameter <= stop:
                    finish = delimiter(s, parameter, stop, 59, True)
                    equal_at = delimiter(s, parameter, finish, 61, False)
                    if equal_at < finish:
                        name_at = trim_start(s, parameter, equal_at)
                        name_end = trim_end(s, name_at, equal_at)
                        if eq(s, name_at, name_end - name_at, 19, True):
                            value_at = trim_start(s, equal_at + 1, finish)
                            value_end = trim_end(s, value_at, finish)
                            if quality(s, value_at, value_end) == False:
                                good = False
                    parameter = finish + 1
                if good:
                    if eq(s, first, last - first, 17, True):
                        mask = mask | 1
                    if eq(s, first, last - first, 18, True):
                        mask = mask | 2
                start = stop + 1
        row = field(s, w, 10, (row - 128) // 32 + 1)
    return mask

def quality(s:readbuf, first:u64, end:u64) -> bool:
    dot = delimiter(s, first, end, 46, False)
    fraction = choose(dot == end, end, dot + 1)
    if end - fraction > 3:
        return True
    index = fraction
    nonzero = False
    while index < end:
        ch = byte(s, index)
        if ch < 48 or ch > 57:
            return True
        if ch != 48:
            nonzero = True
        index = index + 1
    return dot - first != 1 or byte(s, first) != 48 or nonzero

def uri_char(ch:u64) -> bool:
    if ch >= 48 and ch <= 57:
        return True
    if ch >= 65 and ch <= 90:
        return True
    if ch >= 97 and ch <= 122:
        return True
    return ch == 33 or ch == 35 or ch == 36 or ch == 38 or ch == 39 or ch == 40 or ch == 41 or ch == 42 or ch == 43 or ch == 44 or ch == 45 or ch == 46 or ch == 47 or ch == 58 or ch == 59 or ch == 61 or ch == 63 or ch == 64 or ch == 91 or ch == 93 or ch == 95 or ch == 126

def host_allowed(s:readbuf, first:u64, size:u64) -> u64:
    if size == 0:
        return 0
    end = first + size
    cursor = first
    colons = 0
    open = False
    close = False
    percent = False
    host = first
    while cursor < end:
        ch = byte(s, cursor)
        if ch == 47 or ch == 63 or ch == 35:
            return 0
        if uri_char(ch) == False:
            if ch != 37:
                return 0
            percent = True
        elif ch == 58:
            if colons >= 8:
                return 0
            colons = colons + 1
        elif ch == 91:
            if percent or open:
                return 0
            open = True
        elif ch == 93:
            if open == False or close:
                return 0
            close = True
            colons = 0
            percent = False
        elif ch == 64:
            host = cursor + 1
            colons = 0
            percent = False
        cursor = cursor + 1
    if open != close or colons > 1 or host == end or percent:
        return 0
    host_end = host
    if byte(s, host) == 91:
        host_end = delimiter(s, host, end, 93, False)
        if host_end == end:
            return 0
        host = host + 1
    else:
        host_end = delimiter(s, host, end, 58, False)
    while host < host_end and byte(s, host) == 91:
        host = host + 1
    while host < host_end and byte(s, host_end - 1) == 93:
        host_end = host_end - 1
    if eq(s, host, host_end - host, 14, True) or eq(s, host, host_end - host, 15, True) or eq(s, host, host_end - host, 16, True):
        return 2
    return 1
def target_path(s:readbuf, w:mutbuf, first:u64, size:u64) -> bool:
    if size == 0 or size > 65534:
        return False
    end = first + size
    word_store(w, 4096, first)
    word_store(w, 4104, size)
    word_store(w, 4112, 0)
    word_store(w, 4120, 0)
    if size == 1 and byte(s, first) == 42:
        return True
    path = first
    default_slash = first
    has_scheme = False
    if byte(s, first) != 47:
        cursor = first
        if size > 3:
            scanning = True
            while cursor < end and scanning:
                ch = byte(s, cursor)
                if ch == 58:
                    if end - cursor >= 3 and byte(s, cursor + 1) == 47 and byte(s, cursor + 2) == 47:
                        if cursor - first > 64:
                            return False
                        has_scheme = True
                        default_slash = cursor + 1
                        path = cursor + 3
                    scanning = False
                elif scheme_char(ch):
                    cursor = cursor + 1
                else:
                    scanning = False
        authority_start = path
        authority_end = path
        while authority_end < end and byte(s, authority_end) != 47 and byte(s, authority_end) != 63 and byte(s, authority_end) != 35:
            authority_end = authority_end + 1
        if authority_end == authority_start or host_allowed(s, authority_start, authority_end - authority_start) == 0:
            return False
        word_store(w, 4112, authority_start)
        word_store(w, 4120, authority_end - authority_start)
        if has_scheme == False:
            if authority_end != end:
                return False
            word_store(w, 4104, 0)
            return True
        path = authority_end
        if path == end:
            word_store(w, 4096, default_slash)
            word_store(w, 4104, 1)
            return True
    cursor = path
    path_end = end
    query = False
    scanning = True
    while cursor < end and scanning:
        ch = byte(s, cursor)
        if ch == 35:
            if query == False:
                path_end = cursor
            scanning = False
        elif ch == 63 and query == False:
            query = True
            path_end = cursor
        elif path_char(ch, query) == False:
            return False
        cursor = cursor + 1
    if path_end == path:
        word_store(w, 4096, default_slash)
        word_store(w, 4104, 1)
    else:
        word_store(w, 4096, path)
        word_store(w, 4104, path_end - path)
    return True

def scheme_char(ch:u64) -> bool:
    return ch == 43 or ch == 45 or ch == 46 or ch == 126 or (ch >= 48 and ch <= 57) or (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122)

def path_char(ch:u64, query:bool) -> bool:
    if ch >= 128:
        return True
    if query:
        return ch == 33 or (ch >= 36 and ch <= 59) or ch == 61 or (ch >= 63 and ch <= 126)
    return ch == 33 or ch == 34 or (ch >= 36 and ch <= 59) or ch == 61 or (ch >= 64 and ch <= 95) or (ch >= 97 and ch <= 126 and ch != 96)

'''

def source():
    s=SOURCE
    for key,value in {'MAGIC':int.from_bytes(b'HIAHTA01','little'),'HEADER_MAGIC':int.from_bytes(b'HIAHHR01','little'),'RESPONSE_MAGIC':int.from_bytes(b'HIAHTR01','little'),'NONE':(1<<64)-1}.items():
        import re
        s=re.sub(r'\b'+key+r'\b',str(value),s)
    s+='\ndef eq(s:readbuf, at:u64, size:u64, key:u64, fold:bool) -> bool:\n'
    for bank, first in enumerate(range(0,25,4)):
        s+=f'    if key < {min(first+4,25)}:\n        return eq_{bank}(s, at, size, key, fold)\n'
    s+='    return False\n'
    for bank, first in enumerate(range(0,25,4)):
        s+=f'\ndef eq_{bank}(s:readbuf, at:u64, size:u64, key:u64, fold:bool) -> bool:\n'
        for index in range(first,min(first+4,25)):
            raw=LITERALS[index].encode()
            s+=f'    if key == {index}:\n        if size != {len(raw)}:\n            return False\n'
            for i,ch in enumerate(raw):
                if 97<=ch<=122:
                    s+=f'        if lower(byte(s, at + {i}), fold) != {ch}:\n            return False\n'
                else:
                    s+=f'        if byte(s, at + {i}) != {ch}:\n            return False\n'
            s+='        return True\n'
        s+='    return False\n'
    s+='    return False\n\ndef lower(ch:u64, fold:bool) -> u64:\n    if fold and ch >= 65 and ch <= 90:\n        return ch + 32\n    return ch\n'
    s+='\ndef literal(o:mutbuf, at:u64, key:u64) -> u64:\n'
    for index,value in enumerate(LITERALS):
        raw=value.encode()
        s+=f'    if key == {index}:\n'
        for i in range(0,len(raw),8):
            part=raw[i:i+8]
            if len(part)==8:s+=f'        word_store(o, at + {i}, {int.from_bytes(part,"little")})\n'
            else:
                for j,ch in enumerate(part):s+=f'        store(o, at + {i+j}, {ch})\n'
        s+=f'        return at + {len(raw)}\n'
    s+='    return at\n'
    return s

def render():
    return render_assembly(document(source(),'mcp_http_admission'))

if __name__=='__main__':
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_admission.hepta'
    raw=render();p.write_text(raw);print(p.name,len(raw.encode()))
