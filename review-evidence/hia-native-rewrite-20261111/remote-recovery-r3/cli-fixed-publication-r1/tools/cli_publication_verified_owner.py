"""New native exact-byte hard-link publication controller, authoring revision 1.

Owns the complete publish_verified transaction after its parent has produced
normalized absolute filesystem paths. The parent still owns Path.absolute,
mkdir/resolve, temporary-stage creation, and public OS-error presentation.
No existing publication/native-wrapper qualification is inherited.

The only peers are mechanical filesystem primitives and the fixed HIA SHA256
owner. Both command and reply are private immutable leases. Headers correlate
already-issued leases; they are not authentication of arbitrary external bytes.
"""
CONSTANTS={
    "BAD":4294967293,"GROW":4294967294,"MAX":18446744073709551615,
    "STATE":int.from_bytes(b"HIAPVS01","little"),
    "COMMAND":int.from_bytes(b"HIAPVC01","little"),
    "EVENT":int.from_bytes(b"HIAPVE01","little"),
    "ACK":int.from_bytes(b"HIAPVA01","little"),
    "BASE":4096,"DIAG":2048,"RECEIPT":2304,
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_admission(s, w) == 0:
            return refuse(w)
        put(w, 0, STATE)
        put(w, 16, 1)
        put(w, 24, uint(s, 16))
        put(w, 32, uint(s, 24))
        put(w, 112, 64)
        put(w, 120, uint(s, 32))
        put(w, 128, 65 + uint(s, 32))
        put(w, 136, uint(s, 40))
        put(w, 144, 66 + uint(s, 32) + uint(s, 40))
        put(w, 152, uint(s, 48))
        put(w, 176, BASE + uint(s, 40) + 1)
        put(w, 184, length(s))
        copy_bytes(w, s, 384, 0, 64)
    elif get(w, 0) != STATE or command_equal(s, w) == 0:
        return refuse(w)
    phase = get(w, 16)
    if phase == 1:
        if length(r) != 0 or get(w, 40) != 0 or get(w, 48) != 0:
            return refuse(w)
        if length(w) < get(w, 176):
            output(w, 1)
            return GROW
        return initialize(s, w)
    if phase == 99 or phase == 0 or get(w, 40) == 0:
        return refuse(w)
    if reply_admission(r, w) == 0:
        return refuse(w)
    if phase >= 10 and phase <= 17:
        return read_step(s, r, w, phase)
    if phase >= 20 and phase <= 23:
        return publish_step(r, w, phase)
    if phase == 30 or phase == 31:
        return cleanup_step(r, w, phase)
    if phase == 40:
        return hashed(r, w)
    return refuse(w)

def source_admission(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 66 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0 or uint(s, 56) != length(s):
        return 0
    a = uint(s, 32)
    b = uint(s, 40)
    n = uint(s, 48)
    if a == 0 or b == 0 or a > length(s) - 66:
        return 0
    if b > length(s) - 66 - a or n != length(s) - 66 - a - b:
        return 0
    if b > MAX - BASE - 1:
        return 0
    if byte(s, 64) != 47 or byte(s, 65 + a) != 47:
        return 0
    if byte(s, 64 + a) != 0 or byte(s, 65 + a + b) != 0:
        return 0
    i = 0
    while i < a:
        if byte(s, 64 + i) == 0:
            return 0
        i = i + 1
    i = 0
    while i < b:
        if byte(s, 65 + a + i) == 0:
            return 0
        i = i + 1
    return 1

def command_equal(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, 184) or length(s) < 66:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, 384 + i):
            return 0
        i = i + 1
    if get(w, 112) != 64 or get(w, 120) != uint(s, 32):
        return 0
    if get(w, 128) != 65 + get(w, 120) or get(w, 136) != uint(s, 40):
        return 0
    if get(w, 144) != get(w, 128) + get(w, 136) + 1 or get(w, 152) != uint(s, 48):
        return 0
    if get(w, 176) != BASE + get(w, 136) + 1 or get(w, 48) > 1 or get(w, 56) > 2:
        return 0
    return 1

def initialize(s:readbuf, w:mutbuf) -> u32:
    same = 0
    if get(w, 120) == get(w, 136):
        same = 1
        i = 0
        while i < get(w, 120):
            if byte(s, get(w, 112) + i) != byte(s, get(w, 128) + i):
                same = 0
            i = i + 1
    if same != 0 or get(w, 152) == 0:
        return failed(w, 1)
    end = get(w, 136)
    while end > 0 and byte(s, get(w, 128) + end - 1) != 47:
        end = end - 1
    if end == 0:
        return refuse(w)
    if end > 1:
        end = end - 1
        if end == 1 and get(w, 136) >= 2 and byte(s, get(w, 128) + 1) == 47:
            end = 2
    copy_bytes(w, s, BASE, get(w, 128), end)
    store(w, BASE + end, 0)
    put(w, 160, BASE)
    put(w, 168, end)
    put(w, 56, 0)
    put(w, 80, 0)
    put(w, 88, 0)
    put(w, 96, 0)
    put(w, 208, 0)
    return begin_read(w)

def begin_read(w:mutbuf) -> u32:
    if get(w, 48) != 0 or get(w, 56) > 2:
        return refuse(w)
    put(w, 64, 0)
    put(w, 72, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    return issue(w, 1, 10)

def issue(w:mutbuf, op:u64, phase:u64) -> u32:
    if get(w, 32) == MAX or op == 0 or op > 9:
        return refuse(w)
    put(w, 32, get(w, 32) + 1)
    put(w, 40, op)
    put(w, 16, phase)
    output(w, 2)
    if op == 9:
        output(w, 3)
    return 128

def refuse(w:mutbuf) -> u32:
    put(w, 8, 1)
    output(w, 6)
    return BAD

def expected_op(phase:u64) -> u64:
    if phase == 10 or phase == 17 or phase == 21 or phase == 30:
        return 1
    if phase == 20 or phase == 22:
        return 2
    if phase == 11:
        return 3
    if phase == 12 or phase == 13 or phase == 15:
        return 4
    if phase == 14:
        return 5
    if phase == 16:
        return 6
    if phase == 23:
        return 7
    if phase == 31:
        return 8
    if phase == 40:
        return 9
    return 0

def reply_admission(r:readbuf, w:mutbuf) -> u64:
    phase = get(w, 16)
    op = get(w, 40)
    if expected_op(phase) != op or op == 0:
        return 0
    if length(r) < 64 or uint(r, 0) != ACK or uint(r, 8) != get(w, 24):
        return 0
    if uint(r, 16) != get(w, 32) or uint(r, 24) != op or uint(r, 32) > 1:
        return 0
    if uint(r, 56) != length(r) - 64:
        return 0
    if (phase >= 12 and phase <= 16) and get(w, 48) != 1:
        return 0
    if (phase < 12 or phase > 16) and get(w, 48) != 0:
        return 0
    if uint(r, 32) != 0:
        if op == 9 or length(r) != 64 or uint(r, 40) != 0 or uint(r, 48) == 0 or uint(r, 48) > 4095:
            return 0
        return 1
    if uint(r, 48) != 0:
        return 0
    if op == 1 or op == 2 or op == 4:
        if length(r) != 208 or uint(r, 40) != 0:
            return 0
    elif op == 3:
        if length(r) != 64 or uint(r, 40) != 1:
            return 0
    elif op == 5:
        if uint(r, 40) != length(r) - 64 or uint(r, 40) > get(w, 192):
            return 0
    elif op == 9:
        if length(r) != 96 or uint(r, 40) != 0:
            return 0
    elif length(r) != 64 or uint(r, 40) != 0:
        return 0
    return 1

def read_step(s:readbuf, r:readbuf, w:mutbuf, phase:u64) -> u32:
    status = uint(r, 32)
    if phase == 10:
        if status != 0:
            return failed(w, 9)
        copy_bytes(w, r, 512, 64, 144)
        if regular(w, 512) == 0:
            return failed(w, 2)
        if get(w, 56) == 2 and identity(w, 512, 800, 1) == 0:
            return failed(w, 2)
        return issue(w, 3, 11)
    if phase == 11:
        if status != 0:
            if uint(r, 48) == 4:
                return issue(w, 3, 11)
            return failed(w, 9)
        put(w, 48, 1)
        return issue(w, 4, 12)
    if phase == 12:
        if status == 0:
            if (uint(r, 88) & 61440) == 16384:
                put(w, 200, 1)
                return close_failure(w, 9)
        elif uint(r, 48) == 9:
            put(w, 200, 1)
            return close_failure(w, 9)
        return issue(w, 4, 13)
    if phase == 13:
        if status != 0:
            return close_failure(w, 9)
        copy_bytes(w, r, 944, 64, 144)
        if identity(w, 512, 944, 1) == 0:
            return close_failure(w, 3)
        return request_read(w)
    if phase == 14:
        if get(w, 64) > get(w, 152) + 1 or get(w, 192) > get(w, 152) + 1 - get(w, 64):
            return refuse(w)
        if status != 0:
            if uint(r, 48) == 4:
                return issue(w, 5, 14)
            if uint(r, 48) != 11:
                return close_failure(w, 9)
            return read_finished(w)
        count = uint(r, 40)
        i = 0
        while i < count:
            at = get(w, 64) + i
            if at >= get(w, 152):
                put(w, 72, 1)
            elif byte(r, 64 + i) != byte(s, get(w, 144) + at):
                put(w, 72, 1)
            i = i + 1
        put(w, 64, get(w, 64) + count)
        if count == 0 or get(w, 64) == get(w, 152) + 1:
            return read_finished(w)
        return request_read(w)
    if phase == 15:
        if status != 0:
            return close_failure(w, 9)
        copy_bytes(w, r, 944, 64, 144)
        if identity(w, 512, 944, 1) == 0:
            return close_failure(w, 4)
        return issue(w, 6, 16)
    if phase == 16:
        put(w, 48, 0)
        if status != 0 and get(w, 200) == 0:
            put(w, 80, 9)
        put(w, 200, 0)
        if get(w, 80) != 0:
            return failed(w, get(w, 80))
        return issue(w, 1, 17)
    if phase == 17:
        if status != 0:
            return failed(w, 9)
        copy_bytes(w, r, 944, 64, 144)
        if identity(w, 512, 944, 1) == 0:
            return failed(w, 5)
        if get(w, 56) == 0:
            copy_local(w, 656, 512, 144)
            return issue(w, 2, 20)
        if get(w, 56) == 1:
            if identity(w, 656, 512, 0) == 0:
                return failed(w, 8)
            copy_local(w, 800, 512, 144)
            put(w, 56, 2)
            return begin_read(w)
        if get(w, 56) != 2:
            return refuse(w)
        return issue(w, 9, 40)
    return refuse(w)

def request_read(w:mutbuf) -> u32:
    if get(w, 64) > get(w, 152):
        return refuse(w)
    count = get(w, 152) + 1 - get(w, 64)
    if count > 65536:
        count = 65536
    put(w, 192, count)
    return issue(w, 5, 14)

def read_finished(w:mutbuf) -> u32:
    if get(w, 64) != get(w, 152) or get(w, 72) != 0:
        return close_failure(w, 4)
    return issue(w, 4, 15)

def close_failure(w:mutbuf, error:u64) -> u32:
    if get(w, 48) != 1 or error == 0 or error > 9:
        return refuse(w)
    put(w, 80, error)
    return issue(w, 6, 16)

def ignored_errno(value:u64) -> u64:
    if value == 2 or value == 20 or value == 9 or value == 40:
        return 1
    return 0

def publish_step(r:readbuf, w:mutbuf, phase:u64) -> u32:
    status = uint(r, 32)
    if phase == 20:
        if status == 0:
            return failed(w, 6)
        if ignored_errno(uint(r, 48)) == 0:
            return raw_error(w, uint(r, 48), 0, get(w, 128), get(w, 136))
        return issue(w, 1, 21)
    if phase == 21:
        if status == 0:
            if (uint(r, 88) & 61440) == 40960:
                return failed(w, 6)
        elif ignored_errno(uint(r, 48)) == 0:
            return raw_error(w, uint(r, 48), 0, get(w, 128), get(w, 136))
        return issue(w, 2, 22)
    if phase == 22:
        if status == 0:
            if (uint(r, 88) & 61440) != 16384:
                return failed(w, 6)
        elif ignored_errno(uint(r, 48)) == 0:
            return raw_error(w, uint(r, 48), 1, get(w, 160), get(w, 168))
        else:
            return failed(w, 6)
        return issue(w, 7, 23)
    if phase == 23:
        if status != 0:
            return failed(w, 7)
        put(w, 208, 1)
        put(w, 56, 1)
        return begin_read(w)
    return refuse(w)

def failed(w:mutbuf, error:u64) -> u32:
    if get(w, 48) != 0 or error == 0 or error > 9:
        return refuse(w)
    put(w, 80, error)
    put(w, 88, 1)
    put(w, 96, 0)
    if get(w, 208) != 0:
        return issue(w, 1, 30)
    return finish(w)

def cleanup_step(r:readbuf, w:mutbuf, phase:u64) -> u32:
    if get(w, 208) != 1 or get(w, 80) == 0 or get(w, 88) != 1:
        return refuse(w)
    if phase == 30 and uint(r, 32) == 0:
        copy_bytes(w, r, 944, 64, 144)
        if regular(w, 944) != 0 and get(w, 944) == get(w, 656) and get(w, 952) == get(w, 664):
            return issue(w, 8, 31)
    put(w, 208, 0)
    return finish(w)

def raw_error(w:mutbuf, code:u64, source:u64, at:u64, count:u64) -> u32:
    if get(w, 48) != 0 or get(w, 208) != 0 or code == 0 or code > 4095:
        return refuse(w)
    put(w, 88, 2)
    put(w, 96, code)
    put(w, 216, source)
    put(w, 224, at)
    put(w, 232, count)
    return finish(w)

def hashed(r:readbuf, w:mutbuf) -> u32:
    if get(w, 56) != 2 or get(w, 80) != 0 or get(w, 48) != 0 or get(w, 208) != 1:
        return refuse(w)
    receipt(r, w)
    put(w, 88, 0)
    put(w, 96, 0)
    return finish(w)

def finish(w:mutbuf) -> u32:
    if get(w, 48) != 0:
        return refuse(w)
    put(w, 16, 99)
    put(w, 40, 0)
    if get(w, 88) == 1:
        message(w, get(w, 80))
        if get(w, 8) != 0:
            return refuse(w)
    output(w, 0)
    return 128

def output(w:mutbuf, action:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 24))
    put(w, 280, get(w, 32))
    put(w, 288, get(w, 40))
    put(w, 296, get(w, 88))
    put(w, 304, get(w, 80))
    put(w, 312, get(w, 96))
    put(w, 368, get(w, 176))
    put(w, 376, get(w, 16))
    if action == 0:
        if get(w, 88) == 2:
            put(w, 320, get(w, 216))
            put(w, 328, get(w, 224))
            put(w, 336, get(w, 232))
        else:
            put(w, 320, 1)
            put(w, 328, DIAG)
            put(w, 336, get(w, 240))
            if get(w, 88) == 0:
                put(w, 328, RECEIPT)
                put(w, 336, get(w, 248))
    elif action == 2:
        op = get(w, 40)
        phase = get(w, 16)
        source = 0
        at = get(w, 112)
        count = get(w, 120)
        if get(w, 56) == 2 or phase == 20 or phase == 21 or phase == 30 or phase == 31:
            at = get(w, 128)
            count = get(w, 136)
        if phase == 22:
            source = 1
            at = get(w, 160)
            count = get(w, 168)
        if op == 1 or op == 2 or op == 3 or op == 8:
            put(w, 320, source)
            put(w, 328, at)
            put(w, 336, count + 1)
        if op == 3:
            put(w, 344, 657408)
        if op == 5:
            put(w, 336, get(w, 192))
        if op == 7:
            put(w, 328, get(w, 112))
            put(w, 336, get(w, 120) + 1)
            put(w, 352, get(w, 128))
            put(w, 360, get(w, 136) + 1)
    elif action == 3:
        put(w, 328, get(w, 144))
        put(w, 336, get(w, 152))
    return 0

def regular(w:mutbuf, at:u64) -> u64:
    if (get(w, at + 24) & 61440) == 32768:
        return 1
    return 0

def identity(w:mutbuf, a:u64, b:u64, ctime:u64) -> u64:
    if get(w, a) != get(w, b) or get(w, a + 8) != get(w, b + 8):
        return 0
    if (get(w, a + 24) & 4294967295) != (get(w, b + 24) & 4294967295):
        return 0
    if get(w, a + 48) != get(w, b + 48):
        return 0
    if get(w, a + 88) != get(w, b + 88) or get(w, a + 96) != get(w, b + 96):
        return 0
    if ctime != 0:
        if get(w, a + 104) != get(w, b + 104) or get(w, a + 112) != get(w, b + 112):
            return 0
    return 1

def receipt(r:readbuf, w:mutbuf) -> u64:
    write(w, RECEIPT, 2482439370538361467, 8)
    value = get(w, 152)
    count = 0
    while value != 0:
        next = divide10(value)
        store(w, 1200 + count, 48 + value - next * 10)
        count = count + 1
        value = next
    out = RECEIPT + 9
    store(w, RECEIPT + 8, 58)
    if count == 0:
        store(w, out, 48)
        out = out + 1
    while count != 0:
        count = count - 1
        store(w, out, byte(w, 1200 + count))
        out = out + 1
    write(w, out, 3906083645759365676, 8)
    write(w, out + 8, 2243106, 3)
    out = out + 11
    i = 0
    while i < 32:
        store(w, out, hex_digit(byte(r, 64 + i) >> 4))
        store(w, out + 1, hex_digit(byte(r, 64 + i) & 15))
        out = out + 2
        i = i + 1
    store(w, out, 34)
    store(w, out + 1, 125)
    put(w, 248, out + 2 - RECEIPT)
    return 0

def divide10(value:u64) -> u64:
    bit = 64
    quotient = 0
    remainder = 0
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def copy_bytes(w:mutbuf, s:readbuf, at:u64, start:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, byte(s, start + i))
        i = i + 1
    return 0

def copy_local(w:mutbuf, at:u64, start:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, byte(w, start + i))
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

def get(s:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    return write(w, at, value, 8)

def write(w:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
MESSAGES=(
    b"E_PUBLISH_INPUT: distinct file and nonempty exact bytes required",
    b"E_PUBLISH_IDENTITY: ordinary file identity mismatch",
    b"E_PUBLISH_RACE: file changed before read",
    b"E_PUBLISH_BYTES: staged/published content changed",
    b"E_PUBLISH_RACE: pathname changed during verification",
    b"E_PUBLISH_EXISTS: output must be a new file",
    b"E_PUBLISH_LINK: no-replace link failed",
    b"E_PUBLISH_RACE: staged identity or payload changed",
    b"E_PUBLISH_IO: file not available for exact read",
)
def message_body():
    out=["def message(w:mutbuf, code:u64) -> u64:"]
    for i,raw in enumerate(MESSAGES,1):
        out.append(("    if" if i==1 else "    elif")+f" code == {i}:")
        for at in range(0,len(raw),8):
            chunk=raw[at:at+8]
            out.append(f"        write(w, DIAG + {at}, {int.from_bytes(chunk,'little')}, {len(chunk)})")
        out.append(f"        put(w, 240, {len(raw)})")
    out.extend(("    else:","        put(w, 8, 1)","    return 0"))
    return "\n".join(out)+"\n"
