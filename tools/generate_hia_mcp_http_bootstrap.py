"""Authenticated native HTTP listener startup and credential binding."""
from tools.generate_hia_mcp_http_common import authored
from tools.generate_hia_mcp_service import document
from hepta.hia_agent_assembly import render_assembly
from pathlib import Path

SOURCE=r"""
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        put(w, H_TOKEN_FD, NONE)
        put(w, H_LISTENER, NONE)
        put(w, H_EPOLL, NONE)
        put(w, H_CONNECTIONS, NONE)
        put(w, H_SESSIONS, NONE)
        put(w, H_SIGNAL, NONE)
        put(w, H_READY, 0)
        if get(w, 112) != 6:
            return error(w, 0)
        return pure(o, w, 1, P_HTTP_BIND, get(w, 2112), get(w, 2120), H_BINDING, 128, H_PARSE_WORK, 128)
    if phase == 1:
        if result != 128:
            return error(w, 1)
        if get(w, H_BINDING + 24) != 1:
            return error(w, 2)
        return token_open(o, w)
    if phase == 10:
        if result == NEG4:
            return token_open(o, w)
        if failed(result):
            return error(w, 3)
        put(w, H_TOKEN_FD, result)
        return call(o, w, 11, 5, result, H_STAT_BEFORE, 0, 0, 0, 0, 12)
    if phase == 11:
        if failed(result):
            return token_error(o, w, 4)
        mode = getn(w, H_STAT_BEFORE + 24, 4)
        if mode & 61440 != 32768 or mode & 4095 != 384 or get(w, H_STAT_BEFORE + 16) != 1 or getn(w, H_STAT_BEFORE + 28, 4) != get(w, 24):
            return token_error(o, w, 5)
        put(w, H_TOKEN_N, 0)
        return token_read(o, w)
    if phase == 12:
        if result == NEG4:
            return token_read(o, w)
        if failed(result) or result > 4098 - get(w, H_TOKEN_N):
            return token_error(o, w, 4)
        put(w, H_TOKEN_N, get(w, H_TOKEN_N) + result)
        if result != 0 and get(w, H_TOKEN_N) != 4098:
            return token_read(o, w)
        return call(o, w, 13, 5, get(w, H_TOKEN_FD), H_STAT_AFTER, 0, 0, 0, 0, 12)
    if phase == 13:
        if failed(result):
            return token_error(o, w, 4)
        if getn(w, H_STAT_AFTER + 28, 4) != getn(w, H_STAT_BEFORE + 28, 4) or getn(w, H_STAT_AFTER + 24, 4) & 4095 != 384 or get(w, H_STAT_AFTER + 16) != 1 or get(w, H_STAT_AFTER + 48) != get(w, H_STAT_BEFORE + 48) or equal(w, H_STAT_AFTER + 88, H_STAT_BEFORE + 88, 32) == False:
            return token_error(o, w, 6)
        size = get(w, H_TOKEN_N)
        if size > 0 and byte(w, H_TOKEN + size - 1) == 10:
            size = size - 1
        if size < 32 or size > 4096:
            return token_error(o, w, 7)
        index = 0
        while index < size:
            value = byte(w, H_TOKEN + index)
            if value < 33 or value > 126:
                return token_error(o, w, 7)
            index = index + 1
        put(w, H_TOKEN_N, size)
        return call(o, w, 14, 3, get(w, H_TOKEN_FD), 0, 0, 0, 0, 0, 0)
    if phase == 14:
        put(w, H_TOKEN_FD, NONE)
        return sha(o, w, 20, 0, 1)
    if phase == 20:
        if result != 0:
            return error(w, 4)
        copy_state(w, H_TOKEN, SHA_INPUT + 1, get(w, H_TOKEN_N))
        return sha(o, w, 21, 1, get(w, H_TOKEN_N) + 1)
    if phase == 21:
        if result != 0:
            return error(w, 4)
        return sha(o, w, 22, 2, 1)
    if phase == 22:
        if result != 32:
            return error(w, 4)
        copy_state(w, SHA_OUTPUT, H_TOKEN_HASH, 32)
        return sha(o, w, 23, 0, 1)
    if phase == 23:
        if result != 0:
            return error(w, 4)
        end = text_owner_domain(w, SHA_INPUT + 1)
        end = copy_state(w, H_TOKEN, end, get(w, H_TOKEN_N))
        return sha(o, w, 24, 1, end - SHA_INPUT)
    if phase == 24:
        if result != 0:
            return error(w, 4)
        return sha(o, w, 25, 2, 1)
    if phase == 25:
        if result != 32:
            return error(w, 4)
        encode_hex(w, SHA_OUTPUT, H_OWNER)
        bind(w, S_AUDIT_OWNER, H_OWNER, 64)
        index = 0
        while index < 4098:
            store(w, H_TOKEN + index, 0)
            index = index + 1
        return call(o, w, 30, 41, get(w, H_BINDING + 8), 526337, 0, 0, 0, 0, 0)
    if phase == 30:
        if failed(result):
            return error(w, 8)
        put(w, H_LISTENER, result)
        put(w, H_TEMP, 1)
        return call(o, w, 31, 54, result, 1, 2, H_TEMP, 4, 0, 192)
    if phase == 31:
        if failed(result):
            return error(w, 8)
        return call(o, w, 32, 49, get(w, H_LISTENER), H_BINDING + 64, get(w, H_BINDING + 16), 0, 0, 0, 12)
    if phase == 32:
        if failed(result):
            return error(w, 8)
        return call(o, w, 33, 50, get(w, H_LISTENER), 1024, 0, 0, 0, 0, 0)
    if phase == 33:
        if failed(result):
            return error(w, 8)
        return call(o, w, 34, 291, 524288, 0, 0, 0, 0, 0, 0)
    if phase == 34:
        if failed(result):
            return error(w, 8)
        put(w, H_EPOLL, result)
        put(w, H_EVENTS, 1)
        put(w, H_EVENTS + 4, 1)
        return call(o, w, 35, 233, result, 1, get(w, H_LISTENER), H_EVENTS, 0, 0, 192)
    if phase == 35:
        if failed(result):
            return error(w, 8)
        end = text_connections(w, H_ERROR)
        store(w, end, 0)
        return call(o, w, 36, 319, H_ERROR, 3, 0, 0, 0, 0, 3)
    if phase == 36:
        if failed(result):
            return error(w, 8)
        put(w, H_CONNECTIONS, result)
        end = text_sessions(w, H_ERROR)
        store(w, end, 0)
        return call(o, w, 37, 319, H_ERROR, 3, 0, 0, 0, 0, 3)
    if phase == 37:
        if failed(result):
            return error(w, 8)
        put(w, H_SESSIONS, result)
        put(w, H_TEMP, 16386)
        return call(o, w, 38, 14, 0, H_TEMP, 0, 8, 0, 0, 12)
    if phase == 38:
        if failed(result):
            return error(w, 8)
        return call(o, w, 39, 289, NONE, H_TEMP, 8, 526336, 0, 0, 12)
    if phase == 39:
        if failed(result):
            return error(w, 8)
        put(w, H_SIGNAL, result)
        put(w, H_EVENTS, 1)
        put(w, H_EVENTS + 4, 2)
        return call(o, w, 40, 233, get(w, H_EPOLL), 1, result, H_EVENTS, 0, 0, 192)
    if phase == 40:
        if failed(result):
            return error(w, 8)
        put(w, H_READY, 1)
        put(w, H_GENERATION, 1)
        put(w, H_NEXT_SESSION, 1)
        put(w, H_STOP, 0)
        return enter(w, HTTP_IO, 0)
    if phase >= 200 and phase <= 204:
        return authenticate(o, w, phase, result)
    if phase == 890:
        put(w, H_TOKEN_FD, NONE)
        return error(w, get(w, H_TEMP))
    if phase == 900:
        return write_error(o, w)
    if phase == 901:
        if result == NEG4:
            return write_error(o, w)
        if failed(result) or result == 0 or result > get(w, H_ERROR_N) - get(w, H_ERROR_USED):
            return call(o, w, 999, 60, 1, 0, 0, 0, 0, 0, 0)
        put(w, H_ERROR_USED, get(w, H_ERROR_USED) + result)
        if get(w, H_ERROR_USED) < get(w, H_ERROR_N):
            return write_error(o, w)
        return call(o, w, 999, 60, 1, 0, 0, 0, 0, 0, 0)
    return 0

def authenticate(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 200:
        put(w, H_AUTH_OK, 0)
        put(w, H_AUTH_CURSOR, 0)
        return sha(o, w, 201, 0, 1)
    if phase == 201:
        if result != 0:
            return 0
        return authentication_chunk(o, w)
    if phase == 202:
        if result != 0:
            return 0
        put(w, H_AUTH_CURSOR, get(w, H_AUTH_CURSOR) + get(w, H_TEMP))
        return authentication_chunk(o, w)
    if phase == 203:
        if result != 32:
            return 0
        index = 0
        difference = 0
        while index < 32:
            difference = difference | (byte(w, SHA_OUTPUT + index) ^ byte(w, H_TOKEN_HASH + index))
            index = index + 1
        put(w, H_AUTH_OK, choose(difference == 0, 1, 0))
        return enter(w, get(w, H_RETURN_MODULE), get(w, H_RETURN_PHASE))
    return 0

def authentication_chunk(o:mutbuf, w:mutbuf) -> u32:
    offset = get(w, H_AUTH_CURSOR)
    if offset == get(w, H_AUTH_N):
        return sha(o, w, 203, 2, 1)
    count = get(w, H_AUTH_N) - offset
    if count > 65536:
        count = 65536
    copy_state(w, get(w, H_AUTH_AT) + offset, SHA_INPUT + 1, count)
    put(w, H_TEMP, count)
    return sha(o, w, 202, 1, count + 1)

def token_open(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 10, 257, NEG100, get(w, 2128), 657408, 0, 0, 0, 12)

def token_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 12, 0, get(w, H_TOKEN_FD), H_TOKEN + get(w, H_TOKEN_N), 4098 - get(w, H_TOKEN_N), 0, 0, 0, 12)

def token_error(o:mutbuf, w:mutbuf, kind:u64) -> u32:
    put(w, H_TEMP, kind)
    return call(o, w, 890, 3, get(w, H_TOKEN_FD), 0, 0, 0, 0, 0, 0)

def error(w:mutbuf, kind:u64) -> u32:
    end = text_error_prefix(w, H_ERROR)
    if kind == 1:
        end = text_invalid_bind(w, end)
        end = copy_state(w, get(w, 2112), end, get(w, 2120))
        end = text_invalid_bind_suffix(w, end)
    elif kind == 2:
        end = text_loopback(w, end)
    elif kind == 3:
        end = text_unavailable(w, end)
    elif kind == 5:
        end = text_private(w, end)
    elif kind == 6:
        end = text_changed(w, end)
    elif kind == 7:
        end = text_printable(w, end)
    else:
        end = text_failure(w, end)
    end = text_newline(w, end)
    put(w, H_ERROR_N, end - H_ERROR)
    put(w, H_ERROR_USED, 0)
    return enter(w, HTTP_BOOT, 900)

def write_error(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 901, 1, 2, H_ERROR + get(w, H_ERROR_USED), get(w, H_ERROR_N) - get(w, H_ERROR_USED), 0, 0, 0, 12)
"""
def source():
 return authored(SOURCE,text={
  'owner_domain':'hepta-runtime/private-operator-credential/v1\0',
  'connections':'hia-http-connections','sessions':'hia-http-sessions',
  'error_prefix':'Error: ','invalid_bind':"Invalid bind address '",
  'invalid_bind_suffix':"': invalid socket address syntax",
  'loopback':'HTTP MCP must bind to loopback; use an SSH or TLS tunnel for remote access',
  'unavailable':'private runtime token file unavailable',
  'private':'runtime token requires an account-owned single-link 0600 regular file',
  'changed':'runtime token changed while reading',
  'printable':'runtime token must contain 32..4096 printable non-whitespace ASCII bytes',
  'failure':'HTTP MCP startup failed'})
def render():return render_assembly(document(source(),'mcp_http_bootstrap'))
if __name__=='__main__':
 root=Path(__file__).resolve().parents[1];raw=render()
 (root/'examples/hia_bootstrap/mcp_http_bootstrap.hepta').write_text(raw)
 print('mcp_http_bootstrap.hepta',len(raw.encode()))
