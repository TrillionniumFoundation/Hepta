"""HIA-owned one-shot and 256-request framed NDU stdio transport."""
from pathlib import Path
import ast,re
from tools.generate_hia_ndu_evaluator import document
from tools.generate_hia_ndu_evaluator_common import COMMON
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
L={
'L_FLAG':'--stream-v1',
'L_ARGS':'expected --stream-v1 SESSION_HEX MAX_REQUESTS',
'L_EMPTY_INT':'cannot parse integer from empty string',
'L_INVALID_INT':'invalid digit found in string',
'L_LARGE_INT':'number too large to fit in target type',
'L_SESSION':'invalid stream session or request allowance',
'L_FRAME':'stream frame exceeds byte bounds',
'L_ALLOWANCE':'session byte allowance exhausted',
'L_SEQUENCE':'stream sequence or session mismatch',
'L_EOF':'failed to fill whole buffer',
'L_RESPONSE':'stream response exceeds byte bounds',
'L_ERROR_OPEN':'{"authority":"NONE","error":',
'L_ONESHOT_END':',"schema":"hepta.hia.ndu-error.v1"}\n',
'L_STREAM_END':',"schema":"hepta.hia.ndu-stream-error.v1"}\n',
'L_HELLO_A':'{"authority":"ADVISORY_ONLY","entry_point":"hepta.hia.ndu_evaluator.v1","evaluates_each_request":true,"max_frame_json_bytes":1048576,"max_requests":',
'L_HELLO_B':',"max_session_bytes":8388608,"reference_entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy","result_cache":false,"schema":"hepta.hia.ndu-native-stream-hello.v1","transport_profile":"hepta.hia.ndu-ranking-persistent-framed.v1","upstream_commit":"d3c2d760eca5065fc966820379c35c6e8d56e855"}',
'L_IO_BADF':'Bad file descriptor','L_IO_INTR':'Interrupted system call','L_IO_AGAIN':'Resource temporarily unavailable','L_IO_ISDIR':'Is a directory','L_IO_PIPE':'Broken pipe','L_IO_INVAL':'Invalid argument','L_IO_IO':'Input/output error','L_IO_UNKNOWN':'Unknown error ',
'L_OS':' (os error ',
}
ENTRY=r'''
def ndu_transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 50331648:
        return 65
    phase = get(w, 0)
    if phase == 0:
        put(w, 1024, 1)
        put(w, 1032, 0)
        put(w, 1040, 0)
        put(w, 1048, 0)
        return syscall(o, w, 13, 13, 1024, 0, 8, 12, 1)
    if phase == 1:
        if get(w, 8) != 0:
            return exit_process(o, w, 65)
        if get(w, 16) == 0:
            put(w, 32, 0)
            put(w, 72, 0)
            return read_one(o, w)
        put(w, 32, 1)
        if get(w, 16) != 3:
            return literal_error(o, w, L_ARGS)
        first = get(w, 1048576)
        if same(w, 1048584, first, L_FLAG) == 0:
            return literal_error(o, w, L_ARGS)
        at = 1048584 + first
        session_size = get(w, at)
        session = at + 8
        at = session + session_size
        maximum_size = get(w, at)
        maximum = at + 8
        result = allowance(w, maximum, maximum_size)
        if result == 1:
            return literal_error(o, w, L_EMPTY_INT)
        if result == 2:
            return literal_error(o, w, L_INVALID_INT)
        if result == 3:
            return literal_error(o, w, L_LARGE_INT)
        if session_size != 64 or get(w, 40) == 0 or get(w, 40) > 256:
            return literal_error(o, w, L_SESSION)
        i = 0
        while i < 64:
            ch = byte(w, session + i)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                return literal_error(o, w, L_SESSION)
            store(w, 512 + i, ch)
            i = i + 1
        put(w, 48, 1)
        put(w, 56, 0)
        put(w, 64, 9441280)
        text(w, L_HELLO_A)
        decimal(w, get(w, 40))
        text(w, L_HELLO_B)
        return frame_output(o, w, 0, get(w, 64) - 9441280)
    if phase == 10:
        result = get(w, 8)
        if result == 18446744073709551612:
            return read_one(o, w)
        if result >= 9223372036854775808:
            return io_error(o, w, 0 - result)
        cursor = get(w, 72) + result
        if cursor > 1048577:
            return exit_process(o, w, 65)
        put(w, 72, cursor)
        if result == 0 or cursor == 1048577:
            return evaluate(o, w, 1048576, cursor)
        return read_one(o, w)
    if phase == 20:
        result = get(w, 8)
        size = result & 2147483647
        failed = result & 2147483648
        if size > 8388608:
            return exit_process(o, w, 74)
        if get(w, 32) == 0:
            return write_output(o, w, 9441280, size, choose(failed != 0, 2, 1), 90, choose(failed != 0, 2, 0))
        if failed != 0:
            return plain_error(o, w, 27262976, get(w, 18874528))
        sequence = get(w, 48)
        put(w, 48, sequence + 1)
        return frame_output(o, w, sequence, size)
    if phase == 30:
        if get(w, 48) > get(w, 40):
            return exit_process(o, w, 0)
        put(w, 72, 0)
        put(w, 80, 4)
        return read_header(o, w)
    if phase == 31:
        result = get(w, 8)
        cursor = get(w, 72)
        if result == 18446744073709551612 and cursor != 0:
            return read_header(o, w)
        if result >= 9223372036854775808:
            return io_error(o, w, 0 - result)
        if result == 0:
            if cursor == 0:
                return exit_process(o, w, 0)
            return literal_error(o, w, L_EOF)
        cursor = cursor + result
        if cursor > 4:
            return exit_process(o, w, 65)
        put(w, 72, cursor)
        if cursor < 4:
            return read_header(o, w)
        size = read_be32(w, 1048576)
        if size < 69 or size > 1048644:
            return literal_error(o, w, L_FRAME)
        if charge(w, size + 4) == 0:
            return literal_error(o, w, L_ALLOWANCE)
        put(w, 80, size + 4)
        return read_body(o, w)
    if phase == 32:
        result = get(w, 8)
        if result == 18446744073709551612:
            return read_body(o, w)
        if result >= 9223372036854775808:
            return io_error(o, w, 0 - result)
        if result == 0:
            return literal_error(o, w, L_EOF)
        cursor = get(w, 72) + result
        if cursor > get(w, 80):
            return exit_process(o, w, 65)
        put(w, 72, cursor)
        if cursor < get(w, 80):
            return read_body(o, w)
        if read_be32(w, 1048580) != get(w, 48) or eq(w, 1048584, 64, 512, 64) == 0:
            return literal_error(o, w, L_SEQUENCE)
        return evaluate(o, w, 1048648, get(w, 80) - 72)
    if phase == 50:
        result = get(w, 8)
        if result == 18446744073709551612:
            return continue_write(o, w)
        if result >= 9223372036854775808 or result == 0:
            if get(w, 120) == 2:
                return exit_process(o, w, 101)
            if result == 0:
                return exit_process(o, w, 101)
            return io_error(o, w, 0 - result)
        cursor = get(w, 88) + result
        if cursor > get(w, 96):
            return exit_process(o, w, 65)
        put(w, 88, cursor)
        if cursor < get(w, 96):
            return continue_write(o, w)
        put(w, 0, get(w, 104))
        return 4
    if phase == 90:
        return exit_process(o, w, get(w, 112))
    return exit_process(o, w, 65)

def syscall(o:mutbuf, w:mutbuf, number:u64, a:u64, b:u64, c:u64, d:u64, pointers:u64, next:u64) -> u32:
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, pointers)
    put(w, 0, next)
    return 1

def exit_process(o:mutbuf, w:mutbuf, code:u64) -> u32:
    return syscall(o, w, 60, code, 0, 0, 0, 0, 999)

def read_one(o:mutbuf, w:mutbuf) -> u32:
    return syscall(o, w, 0, 0, 1048576 + get(w, 72), 1048577 - get(w, 72), 0, 12, 10)

def read_header(o:mutbuf, w:mutbuf) -> u32:
    amount = choose(get(w, 72) == 0, 1, 4 - get(w, 72))
    return syscall(o, w, 0, 0, 1048576 + get(w, 72), amount, 0, 12, 31)

def read_body(o:mutbuf, w:mutbuf) -> u32:
    return syscall(o, w, 0, 0, 1048576 + get(w, 72), get(w, 80) - get(w, 72), 0, 12, 32)

def evaluate(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u32:
    put(o, 0, at)
    put(o, 8, size)
    put(o, 16, 9441280)
    put(o, 24, 8388608)
    put(o, 32, 18874368)
    put(o, 40, 25165824)
    put(w, 0, 20)
    return 2

def write_output(o:mutbuf, w:mutbuf, at:u64, size:u64, fd:u64, next:u64, code:u64) -> u32:
    put(w, 88, at)
    put(w, 96, at + size)
    put(w, 104, next)
    put(w, 112, code)
    put(w, 120, fd)
    return continue_write(o, w)

def continue_write(o:mutbuf, w:mutbuf) -> u32:
    return syscall(o, w, 1, get(w, 120), get(w, 88), get(w, 96) - get(w, 88), 0, 12, 50)

def charge(w:mutbuf, amount:u64) -> u64:
    current = get(w, 56)
    if amount > 8388608 - current:
        return 0
    put(w, 56, current + amount)
    return 1

def frame_output(o:mutbuf, w:mutbuf, sequence:u64, size:u64) -> u32:
    if size == 0 or size > 1048576:
        return literal_error(o, w, L_RESPONSE)
    if charge(w, size + 72) == 0:
        return literal_error(o, w, L_ALLOWANCE)
    write_be32(w, 9441208, size + 68)
    write_be32(w, 9441212, sequence)
    cp(w, 9441216, 512, 64)
    return write_output(o, w, 9441208, size + 72, 1, 30, 0)

def allowance(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0:
        return 1
    i = 0
    if byte(w, at) == 43:
        i = 1
    if i == size:
        return 2
    value = 0
    while i < size:
        ch = byte(w, at + i)
        if ch < 48 or ch > 57:
            return 2
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 3
        value = value * 10 + digit
        i = i + 1
    put(w, 40, value)
    return 0

def same(w:mutbuf, at:u64, size:u64, which:u64) -> u64:
    end = literal(w, 65536, which)
    return eq(w, at, size, 65536, end - 65536)

def literal_error(o:mutbuf, w:mutbuf, which:u64) -> u32:
    end = literal(w, 65536, which)
    return plain_error(o, w, 65536, end - 65536)

def plain_error(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u32:
    if get(w, 32) != 0:
        i = 0
        count = 0
        while i < size and count < 2048:
            ch = byte(w, at + i)
            i = i + choose(ch < 128, 1, choose(ch < 224, 2, choose(ch < 240, 3, 4)))
            count = count + 1
        size = i
    put(w, 64, 9441280)
    text(w, L_ERROR_OPEN)
    quote(w, at, size)
    text(w, choose(get(w, 32) == 0, L_ONESHOT_END, L_STREAM_END))
    return write_output(o, w, 9441280, get(w, 64) - 9441280, 2, 90, 2)

def io_error(o:mutbuf, w:mutbuf, code:u64) -> u32:
    put(w, 64, 65536)
    which = L_IO_UNKNOWN
    if code == 9:
        which = L_IO_BADF
    if code == 4:
        which = L_IO_INTR
    if code == 11:
        which = L_IO_AGAIN
    if code == 21:
        which = L_IO_ISDIR
    if code == 32:
        which = L_IO_PIPE
    if code == 22:
        which = L_IO_INVAL
    if code == 5:
        which = L_IO_IO
    text(w, which)
    if which == L_IO_UNKNOWN:
        decimal(w, code)
    text(w, L_OS)
    decimal(w, code)
    text_byte(w, 41)
    return plain_error(o, w, 65536, get(w, 64) - 65536)

def read_be32(w:mutbuf, at:u64) -> u64:
    return (byte(w, at) << 24) | (byte(w, at + 1) << 16) | (byte(w, at + 2) << 8) | byte(w, at + 3)

def write_be32(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value >> 24)
    store(w, at + 1, value >> 16)
    store(w, at + 2, value >> 8)
    store(w, at + 3, value)
    return 0
'''
def literals():
    pieces=[];items=list(L.items())
    for g in range((len(items)+7)//8):
        lines=[f'def literal_{g}(w:mutbuf, at:u64, which:u64) -> u64:']
        for i,(_,text)in enumerate(items[g*8:(g+1)*8],g*8):
            raw=text.encode();lines.append(f'    if which == {i+1}:')
            for k in range(0,len(raw)//8*8,8):lines.append(f'        put(w, at + {k}, {int.from_bytes(raw[k:k+8],"little")})')
            for k in range(len(raw)//8*8,len(raw)):lines.append(f'        store(w, at + {k}, {raw[k]})')
            lines.append(f'        return at + {len(raw)}')
        lines.append('    return at');pieces.append('\n'.join(lines))
    lines=['def literal(w:mutbuf, at:u64, which:u64) -> u64:']
    for g in range((len(items)+7)//8):lines += [f'    if which <= {(g+1)*8}:',f'        return literal_{g}(w, at, which)']
    lines.append('    return at')
    return '\n\n'.join(['\n'.join(lines),*pieces])
def program():
    names={'get','put','cp','eq','text_byte','text_copy','text','decimal','quote','hex_digit'}
    helpers='\n\n'.join(ast.get_source_segment(COMMON,n)for n in ast.parse(COMMON).body if n.name in names)
    source=ENTRY+'\n\n'+helpers+'\n\n'+literals()
    for i,name in enumerate(L,1):source=re.sub(r'\b'+name+r'\b',str(i),source)
    return source
def render():return render_assembly(document(program(),'ndu_evaluator_transport'))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/ndu_evaluator_transport.hepta';p.write_text(render());print(p.name,p.stat().st_size)
