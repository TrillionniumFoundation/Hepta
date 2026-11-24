"""Author the HIA release-build owner and its mechanical Linux syscall capsule."""
from pathlib import Path
import ast
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_filter import LINK_SOURCE, REFERENCE_CLI_ADAPTER
from tools.build_hia_direct_call import ROLES
from tools.build_hia_agent_batch_commit import VARIANTS

POLICY = r'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    if phase < 100:
        return admission(s, o, w, phase, get(w, 8))
    if phase < 200:
        return invocation(s, o, w, phase, get(w, 8))
    if phase < 250:
        return transfer(s, o, w, phase, get(w, 8))
    if phase < 300:
        return hashing(s, o, w, phase, get(w, 8))
    if phase < 350:
        return publication(s, o, w, phase, get(w, 8))
    return business(s, o, w, phase, get(w, 8))

def admission(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 0:
        constants(w)
        if admit_request(s, w) == 0:
            return finish(o, w, 65)
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1 or phase == 3:
        if r < 2 or (uint(s, 8) != 0 and r != uint(s, 8)):
            return finish(o, w, 65)
        if phase == 1:
            put(w, 3168, r)
            return call(o, w, 2, 157, 1, 15, 0, 0, 0, 0, 0)
        if r != get(w, 3168):
            return finish(o, w, 65)
        return call(o, w, 4, 39, 0, 0, 0, 0, 0, 0, 0)
    if failed(r):
        return finish(o, w, 74)
    if phase == 2:
        return call(o, w, 3, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 4:
        put(w, 16, r)
        return call(o, w, 5, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        put(w, 24, r)
        put(w, 32, 0)
        return inspect_initial(s, o, w)
    if phase == 10:
        if getn(w, 1224, 4) & 61440 != 16384:
            return finish(o, w, 65)
        if get(w, 32) == 1 or get(w, 32) == 2:
            if getn(w, 1224, 4) & 63 != 0 or getn(w, 1228, 4) != get(w, 24):
                return finish(o, w, 65)
        copyw(w, 2048 + get(w, 32) * 144, 1200, 144)
        put(w, 32, get(w, 32) + 1)
        return inspect_initial(s, o, w)
    if phase == 11:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) < 1 or get(w, 1248) > 67108864:
            return finish(o, w, 65)
        put(w, 48, get(w, 1248))
        put(w, 3000 + (get(w, 32) - 5) * 8, get(w, 1248))
        return call(o, w, 12, 72, uint(s, 48 + (get(w, 32) - 5) * 8), 1034, 0, 0, 0, 0, 0)
    if phase == 12:
        if r & 15 != 15:
            return finish(o, w, 65)
        return hash_view(o, w, uint(s, 48 + (get(w, 32) - 5) * 8), 0, get(w, 48), 13)
    if phase == 13:
        if same_input(s, w, 128 + (get(w, 32) - 5) * 32, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 32, get(w, 32) + 1)
        return inspect_initial(s, o, w)
    if phase == 20:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 21, 217, uint(s, 32), 49152, 16384, 0, 0, 0, 12)
    if phase == 21:
        if r == 0:
            return audit_start(s, o, w, 1000)
        if r > 16384 or only_dots(w, r) == 0:
            return finish(o, w, 65)
        return call(o, w, 21, 217, uint(s, 32), 49152, 16384, 0, 0, 0, 12)
    return finish(o, w, 65)

def inspect_initial(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 32)
    if index < 5:
        source = choose(index < 3, 24 + index * 8, 88 + (index - 3) * 8)
        return call(o, w, 10, 5, uint(s, source), 1200, 0, 0, 0, 0, 12)
    if index < 10:
        return call(o, w, 11, 5, uint(s, 48 + (index - 5) * 8), 1200, 0, 0, 0, 0, 12)
    if same(w, 2048, 2192, 16) == 1 or same(w, 2048, 2336, 16) == 1 or same(w, 2192, 2336, 16) == 1:
        return finish(o, w, 65)
    put(w, 216, uint(s, 56))
    put(w, 224, uint(s, 64))
    put(w, 232, uint(s, 48))
    return call(o, w, 20, 8, uint(s, 32), 0, 0, 0, 0, 0, 0)

def admit_request(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 305 or length(s) > 1048576 or uint(s, 0) != MAGIC_OWNER:
        return 0
    if uint(s, 8) == 1 or uint(s, 8) > 2147483647 or uint(s, 16) == 0:
        return 0
    n = uint(s, 104)
    if n == 0 or n > 255 or uint(s, 112) < 16 or uint(s, 120) > 256:
        return 0
    if 288 + n + uint(s, 112) != length(s):
        return 0
    i = 0
    while i < n:
        ch = byte(s, 288 + i)
        if ch == 0 or ch == 47 or ch > 127:
            return 0
        i = i + 1
    if n == 1 and byte(s, 288) == 46:
        return 0
    if n == 2 and byte(s, 288) == 46 and byte(s, 289) == 46:
        return 0
    i = 0
    while i < 10:
        fd = uint(s, 24 + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < i:
            if fd == uint(s, 24 + j * 8):
                return 0
            j = j + 1
        i = i + 1
    start = 288 + n
    if uint(s, start) != MAGIC_PINS or uint(s, start + 8) == 0 or uint(s, start + 8) > 4096:
        return 0
    put(w, 80, uint(s, start + 8))
    put(w, 88, start)
    at = start + 16
    i = 0
    while i < get(w, 80):
        at = pin_entry(s, w, at, i)
        if at == 0:
            return 0
        i = i + 1
    return choose(at == length(s), 1, 0)

def pin_entry(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    if at > length(s) or length(s) - at < 41:
        return 0
    n = uint(s, at)
    if n == 0 or n > 4095 or n > length(s) - at - 40 or valid_path(s, at + 40, n) == 0:
        return 0
    if index != 0:
        previous = get(w, 131200 + (index - 1) * 16)
        if ordered(s, previous + 40, uint(s, previous), at + 40, n) == 0:
            return 0
    put(w, 131200 + index * 16, at)
    put(w, 131208 + index * 16, n)
    return at + 40 + n

def ordered(s:readbuf, first:u64, a:u64, second:u64, b:u64) -> u64:
    i = 0
    while i < a and i < b:
        if byte(s, first + i) < byte(s, second + i):
            return 1
        if byte(s, first + i) > byte(s, second + i):
            return 0
        i = i + 1
    return choose(a < b, 1, 0)

def valid_path(s:readbuf, at:u64, n:u64) -> u64:
    if byte(s, at) == 47 or byte(s, at + n - 1) == 47:
        return 0
    i = 0
    part = 0
    while i <= n:
        if i == n or byte(s, at + i) == 47:
            size = i - part
            if size == 0 or (size == 1 and byte(s, at + part) == 46):
                return 0
            if size == 2 and byte(s, at + part) == 46 and byte(s, at + part + 1) == 46:
                return 0
            part = i + 1
        else:
            if plain(byte(s, at + i)) == 0:
                return 0
        i = i + 1
    return 1

def plain(c:u64) -> u64:
    if (c >= 65 and c <= 90) or (c >= 97 and c <= 122) or (c >= 48 and c <= 57):
        return 1
    if c == 45 or c == 46 or c == 95:
        return 1
    return 0

def only_dots(w:mutbuf, size:u64) -> u64:
    at = 0
    while at < size:
        if at + 20 > size:
            return 0
        n = getn(w, 49152 + at + 16, 2)
        if n < 21 or n > size - at:
            return 0
        if byte(w, 49152 + at + 19) != 46:
            return 0
        if byte(w, 49152 + at + 20) != 0:
            if n < 22 or byte(w, 49152 + at + 20) != 46 or byte(w, 49152 + at + 21) != 0:
                return 0
        at = at + n
    return 1

def launch(o:mutbuf, w:mutbuf, image:u64, source:u64, operation:u64, pass_source:u64, resume:u64) -> u32:
    put(w, 512, resume)
    put(w, 520, image)
    put(w, 528, source)
    put(w, 536, operation)
    put(w, 544, pass_source)
    put(w, 552, 0)
    return call(o, w, 100, 8, source, 0, 0, 0, 0, 0, 0)

def invocation(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 150:
        return runner_child(s, o, w, phase, r)
    if phase == 112 and r == 18446744073709551612:
        return call(o, w, 112, 61, get(w, 592), 600, 0, 0, 0, 0, 12)
    if failed(r):
        return finish(o, w, 74)
    if phase == 100 or phase == 103:
        if phase == 100 and r != 0:
            return finish(o, w, 65)
        if phase == 103:
            put(w, 552, get(w, 552) + 1)
        if get(w, 552) == 4:
            job_request(s, w)
            return writing(o, w, get(w, 584), 458752, get(w, 608), 104)
        return call(o, w, 101, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 101:
        if r < 3:
            return finish(o, w, 74)
        put(w, 560 + get(w, 552) * 8, r)
        return call(o, w, 103, 91, r, 384, 0, 0, 0, 0, 0)
    if phase == 104:
        return call(o, w, 105, 72, get(w, 584), 1033, 15, 0, 0, 0, 0)
    if phase == 105:
        put(w, 3904, C_RUNNER)
        put(w, 3912, 18446744073709551615)
        put(w, 4056, 0)
        put(w, 0, 110)
        put(o, 0, 3904)
        put(o, 8, 2)
        put(o, 16, 4000)
        return 2
    if phase == 110:
        return call(o, w, 111, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 111:
        if r == 0:
            return call(o, w, 150, 157, 1, 15, 0, 0, 0, 0, 0)
        put(w, 592, r)
        return call(o, w, 112, 61, r, 600, 0, 0, 0, 0, 12)
    if phase == 112:
        if r != get(w, 592) or getn(w, 600, 4) != 0:
            return finish(o, w, 74)
        return call(o, w, 113, 17, get(w, 576), 5376, 128, 0, 0, 0, 12)
    if phase == 113:
        if r != 128 or receipt(w) == 0:
            return finish(o, w, 74)
        put(w, 144, get(w, 560))
        put(w, 152, get(w, 5424))
        return call(o, w, 114, 5, get(w, 144), 1200, 0, 0, 0, 0, 12)
    if phase == 114:
        if get(w, 1248) != get(w, 152) or get(w, 1216) != 0 or getn(w, 1224, 4) & 61440 != 32768:
            return finish(o, w, 74)
        return call(o, w, 115, 72, get(w, 144), 1033, 15, 0, 0, 0, 0)
    if phase == 115:
        put(w, 552, 1)
        return call(o, w, 116, 3, get(w, 568), 0, 0, 0, 0, 0, 0)
    if phase == 116:
        put(w, 552, get(w, 552) + 1)
        if get(w, 552) < 4:
            return call(o, w, 116, 3, get(w, 560 + get(w, 552) * 8), 0, 0, 0, 0, 0, 0)
        return call(o, w, 117, 3, get(w, 528), 0, 0, 0, 0, 0, 0)
    if phase == 117:
        return resume(s, o, w, get(w, 512))
    return finish(o, w, 65)

def runner_child(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r) or phase == 153:
        return finish(o, w, 127)
    if phase == 150:
        return call(o, w, 151, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 151:
        if r != get(w, 16):
            return finish(o, w, 127)
        return call(o, w, 152, 33, get(w, 584), 0, 0, 0, 0, 0, 0)
    return call(o, w, 153, 322, get(w, 232), C_EMPTY, 4000, 4056, 4096, 0, 252)

def job_request(s:readbuf, w:mutbuf) -> u64:
    at = 458752
    put(w, at, MAGIC_SUB)
    put(w, at + 8, get(w, 16))
    put(w, at + 16, uint(s, 16))
    put(w, at + 24, get(w, 520))
    put(w, at + 32, get(w, 528))
    put(w, at + 40, get(w, 560))
    put(w, at + 48, get(w, 568))
    put(w, at + 56, uint(s, 40))
    put(w, at + 64, get(w, 576))
    put(w, at + 72, choose(get(w, 536) == 0, 1, choose(get(w, 536) >= 17, 3, 2)))
    put(w, at + 80, 1)
    put(w, at + 88, 67108864)
    put(w, at + 96, 16384)
    put(w, at + 104, 1000000000)
    put(w, at + 112, 2147483648)
    put(w, at + 120, 0)
    at = arg(w, at + 128, C_CHILD, L_CHILD)
    if get(w, 536) != 0:
        at = operation_arg(w, at, get(w, 536))
    at = arg(w, at, C_ENV, 5)
    if get(w, 544) == 1:
        put(w, at, MAGIC_PASS)
        put(w, at + 8, 1)
        put(w, at + 16, uint(s, 24))
        at = at + 24
    if get(w, 544) == 2:
        put(w, at, MAGIC_PASS)
        put(w, at + 8, 9)
        i = 0
        while i < 9:
            put(w, at + 16 + i * 8, get(w, 1530000 + i * 8))
            i = i + 1
        at = at + 88
    put(w, 608, at - 458752)
    return 0

def operation_arg(w:mutbuf, at:u64, operation:u64) -> u64:
    if operation >= 17 and operation <= 25:
        at = arg(w, at, C_SCHEMA_FLAG, L_SCHEMA_FLAG)
        copyw(w, 62000, C_SCHEMA_NAME, L_SCHEMA_NAME)
        store(w, 62000 + L_SCHEMA_NAME - 1, operation - 16 + 48)
        return arg(w, at, 62000, L_SCHEMA_NAME)
    if operation == 1:
        return arg(w, at, C_SOURCES, 7)
    if operation == 2:
        return arg(w, at, C_PACK, 4)
    if operation == 3:
        return arg(w, at, C_BUILD, 5)
    return arg(w, at, C_COMPILE, 7)

def receipt(w:mutbuf) -> u64:
    if get(w, 5376) != MAGIC_SUBRECEIPT or get(w, 5384) != 0 or get(w, 5392) != 0 or get(w, 5400) != 0:
        return 0
    if get(w, 5408) < 2 or get(w, 5416) == 0 or get(w, 5416) != get(w, 5424) or get(w, 5424) > 67108864:
        return 0
    if get(w, 5432) != 0 or get(w, 5440) != 0 or get(w, 5448) != 0 or get(w, 5456) != 0 or get(w, 5464) != 0:
        return 0
    return choose(get(w, 5472) == 1 and get(w, 5480) == 1 and get(w, 5496) == 1, 1, 0)

def writing(o:mutbuf, w:mutbuf, fd:u64, buffer:u64, count:u64, resume:u64) -> u32:
    return writing_at(o, w, fd, buffer, count, 0, resume)

def writing_at(o:mutbuf, w:mutbuf, fd:u64, buffer:u64, count:u64, offset:u64, resume:u64) -> u32:
    if count == 0:
        put(w, 0, resume)
        put(w, 8, 0)
        return 4
    put(w, 768, fd)
    put(w, 776, buffer)
    put(w, 784, count)
    put(w, 792, offset)
    put(w, 800, resume)
    return call(o, w, 200, 18, fd, buffer, count, offset, 0, 0, 12)

def reading(o:mutbuf, w:mutbuf, fd:u64, buffer:u64, count:u64, offset:u64, resume:u64) -> u32:
    put(w, 808, fd)
    put(w, 816, buffer)
    put(w, 824, count)
    put(w, 832, offset)
    put(w, 840, resume)
    return call(o, w, 201, 17, fd, buffer, count, offset, 0, 0, 12)

def copying(o:mutbuf, w:mutbuf, source:u64, target:u64, offset:u64, count:u64, resume:u64) -> u32:
    if count == 0:
        put(w, 0, resume)
        put(w, 8, 0)
        return 4
    put(w, 848, source)
    put(w, 856, target)
    put(w, 864, count)
    put(w, 872, offset)
    put(w, 880, resume)
    return call(o, w, 202, 40, target, source, 872, count, 0, 0, 48)

def transfer(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 200:
        if r == 18446744073709551612:
            return call(o, w, 200, 18, get(w, 768), get(w, 776), get(w, 784), get(w, 792), 0, 0, 12)
        if failed(r) or r == 0 or r > get(w, 784):
            return finish(o, w, 74)
        put(w, 776, get(w, 776) + r)
        put(w, 784, get(w, 784) - r)
        put(w, 792, get(w, 792) + r)
        if get(w, 784) != 0:
            return call(o, w, 200, 18, get(w, 768), get(w, 776), get(w, 784), get(w, 792), 0, 0, 12)
        return resume(s, o, w, get(w, 800))
    if phase == 201:
        if r == 18446744073709551612:
            return call(o, w, 201, 17, get(w, 808), get(w, 816), get(w, 824), get(w, 832), 0, 0, 12)
        if failed(r) or r == 0 or r > get(w, 824):
            return finish(o, w, 74)
        put(w, 816, get(w, 816) + r)
        put(w, 824, get(w, 824) - r)
        put(w, 832, get(w, 832) + r)
        if get(w, 824) != 0:
            return call(o, w, 201, 17, get(w, 808), get(w, 816), get(w, 824), get(w, 832), 0, 0, 12)
        return resume(s, o, w, get(w, 840))
    if phase == 202:
        if r == 18446744073709551612:
            return call(o, w, 202, 40, get(w, 856), get(w, 848), 872, get(w, 864), 0, 0, 48)
        if failed(r) or r == 0 or r > get(w, 864):
            return finish(o, w, 74)
        put(w, 864, get(w, 864) - r)
        if get(w, 864) != 0:
            return call(o, w, 202, 40, get(w, 856), get(w, 848), 872, get(w, 864), 0, 0, 48)
        return resume(s, o, w, get(w, 880))
    if failed(r):
        return finish(o, w, 74)
    if phase == 210:
        if r < 3:
            return finish(o, w, 74)
        put(w, 888, r)
        return writing(o, w, r, get(w, 904), get(w, 912), 211)
    if phase == 211:
        return call(o, w, 212, 72, get(w, 888), 1033, 15, 0, 0, 0, 0)
    if phase == 212:
        put(w, 144, get(w, 888))
        put(w, 152, get(w, 912))
        return resume(s, o, w, get(w, 896))
    return finish(o, w, 65)

def seal_buffer(o:mutbuf, w:mutbuf, buffer:u64, count:u64, resume:u64) -> u32:
    if buffer > 4194304 or count > 4194304 - buffer:
        return finish(o, w, 65)
    put(w, 896, resume)
    put(w, 904, buffer)
    put(w, 912, count)
    return call(o, w, 210, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)

def hash_view(o:mutbuf, w:mutbuf, file:u64, offset:u64, size:u64, resume:u64) -> u32:
    put(w, 40, file)
    put(w, 48, size)
    put(w, 56, 0)
    put(w, 64, offset)
    put(w, 72, resume)
    return sha(o, w, 250, 0, 1)

def hashing(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 250 or phase == 252:
        if r != 0:
            return finish(o, w, 74)
        if get(w, 56) == get(w, 48):
            return sha(o, w, 253, 2, 1)
        return call(o, w, 251, 17, get(w, 40), 65537, minimum(65536, get(w, 48) - get(w, 56)), get(w, 64) + get(w, 56), 0, 0, 12)
    if phase == 251:
        if r == 18446744073709551612:
            return call(o, w, 251, 17, get(w, 40), 65537, minimum(65536, get(w, 48) - get(w, 56)), get(w, 64) + get(w, 56), 0, 0, 12)
        if failed(r) or r == 0 or r > minimum(65536, get(w, 48) - get(w, 56)):
            return finish(o, w, 74)
        put(w, 56, get(w, 56) + r)
        return sha(o, w, 252, 1, r + 1)
    if phase == 253:
        if r != 32:
            return finish(o, w, 74)
        return resume(s, o, w, get(w, 72))
    return finish(o, w, 65)

def publish(o:mutbuf, w:mutbuf, file:u64, size:u64, name:u64, count:u64, mode:u64, after:u64) -> u32:
    if size == 0 or size > 67108864 or count == 0 or count > 127:
        return finish(o, w, 65)
    put(w, 920, file)
    put(w, 936, size)
    put(w, 944, name)
    put(w, 952, count)
    put(w, 960, mode)
    put(w, 968, after)
    return hash_view(o, w, file, 0, size, 300)

def publication(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 300:
        put(w, 6144, get(w, 952))
        put(w, 6152, 64)
        copyw(w, 6160, get(w, 944), get(w, 952))
        hex_digest(w, 6160 + get(w, 952))
        copyw(w, 8100, get(w, 944), get(w, 952))
        store(w, 8100 + get(w, 952), 0)
        return call(o, w, 301, 257, uint(s, 32), C_DOT, 4259842, 384, 0, 0, 12)
    if phase == 301:
        if r < 3:
            return finish(o, w, 74)
        put(w, 984, r)
        return copying(o, w, get(w, 920), r, 0, get(w, 936), 302)
    if phase == 302:
        return call(o, w, 303, 91, get(w, 984), get(w, 960), 0, 0, 0, 0, 0)
    if phase == 303:
        return call(o, w, 304, 74, get(w, 984), 0, 0, 0, 0, 0, 0)
    if phase == 304:
        copyw(w, 8000, C_PROC, 14)
        at = decimal(w, 8014, get(w, 984))
        store(w, at, 0)
        return call(o, w, 305, 265, 18446744073709551516, 8000, uint(s, 32), 8100, 1024, 0, 204)
    if phase == 305:
        return call(o, w, 306, 74, uint(s, 32), 0, 0, 0, 0, 0, 0)
    if phase == 306:
        return writing_at(o, w, get(w, 200), 6144, 80 + get(w, 952), get(w, 256), 307)
    if phase == 307:
        put(w, 192, get(w, 192) + 1)
        put(w, 256, get(w, 256) + 80 + get(w, 952))
        return call(o, w, 308, 3, get(w, 984), 0, 0, 0, 0, 0, 0)
    if phase == 308:
        return resume(s, o, w, get(w, 968))
    return finish(o, w, 65)

def hex_digest(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 32:
        ch = byte(w, 4096 + i)
        store(w, at + i * 2, hex_digit(ch >> 4))
        store(w, at + i * 2 + 1, hex_digit(ch & 15))
        i = i + 1
    return 0

def hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def capture_begin(s:readbuf, w:mutbuf, tag:u64, count:u64) -> u64:
    put(w, 393216, MAGIC_CAPTURE)
    put(w, 393224, uint(s, 24))
    put(w, 393232, tag)
    put(w, 393240, count)
    return 393248

def capture_row(s:readbuf, w:mutbuf, at:u64, path:u64, pn:u64, alias:u64, an:u64) -> u64:
    if pn == 0 or pn > 4095 or an == 0 or an > 127 or at > 458752 or 56 + pn + an > 458752 - at:
        return 0
    pin = pin_for(s, w, path, pn)
    if pin == 0:
        return 0
    put(w, at, pn)
    put(w, at + 8, an)
    put(w, at + 16, 0)
    copy(s, w, at + 24, pin, 32)
    copyw(w, at + 56, path, pn)
    copyw(w, at + 56 + pn, alias, an)
    return at + 56 + pn + an

def pin_for(s:readbuf, w:mutbuf, path:u64, n:u64) -> u64:
    i = 0
    while i < get(w, 80):
        row = get(w, 131200 + i * 16)
        if get(w, 131208 + i * 16) == n and same_input(s, w, row + 40, path, n) == 1:
            return row + 8
        i = i + 1
    return 0

def capture_relative(s:readbuf, w:mutbuf, at:u64, source:u64, count:u64, alias:u64, size:u64) -> u64:
    if count == 0 or count > 255:
        return 0
    copyw(w, 530000, C_CORE_PREFIX, L_CORE_PREFIX)
    copyw(w, 530000 + L_CORE_PREFIX, source, count)
    return capture_row(s, w, at, 530000, L_CORE_PREFIX + count, alias, size)

def capture_kit(s:readbuf, w:mutbuf, policy:u64, pn:u64, packer:u64, kn:u64, tag:u64) -> u64:
    at = capture_begin(s, w, tag, 3)
    at = capture_relative(s, w, at, policy, pn, C_POLICY_ROLE, L_POLICY_ROLE)
    if at == 0:
        return 0
    at = capture_relative(s, w, at, C_SELFHOST, L_SELFHOST, C_SELFHOST, L_SELFHOST)
    if at == 0:
        return 0
    at = capture_relative(s, w, at, packer, kn, C_PACKER_ROLE, L_PACKER_ROLE)
    if at == 0:
        return 0
    return at - 393216

def capture_one(s:readbuf, w:mutbuf, path:u64, pn:u64, alias:u64, an:u64, tag:u64) -> u64:
    at = capture_begin(s, w, tag, 1)
    at = capture_row(s, w, at, path, pn, alias, an)
    return choose(at == 0, 0, at - 393216)

def capture_request(o:mutbuf, w:mutbuf, size:u64, after:u64) -> u32:
    if size == 0:
        return finish(o, w, 65)
    put(w, 1064, after)
    return seal_buffer(o, w, 393216, size, 1090)

def business(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 1090:
        return launch(o, w, get(w, 224), get(w, 144), 0, 1, get(w, 1064))
    if phase >= 6000 and phase < 6100:
        return frontend(s, o, w, phase, r)
    if phase >= 6100 and phase < 6200:
        return worker_frontend(s, o, w, phase, r)
    if phase >= 5000 and phase < 6000:
        return 5
    if phase >= 4500 and phase < 4600:
        return source_audit(s, o, w, phase, r)
    if phase >= 4300 and phase < 4400:
        return cold_admission(s, o, w, phase, r)
    if phase >= 1200 and phase < 1300:
        return member_loop(s, o, w, phase, r)
    if phase >= 1400 and phase < 1500:
        return materialize(s, o, w, phase, r)
    if phase >= 1600 and phase < 1700:
        return frame_step(s, o, w, phase, r)
    if phase >= 2000 and phase < 2100:
        return compiler_manifest(s, o, w, phase, r)
    if phase == 1000:
        return call(o, w, 1001, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 1001:
        if r < 3:
            return finish(o, w, 74)
        put(w, 200, r)
        put(w, 256, 24)
        put(w, 6144, MAGIC_INVENTORY)
        put(w, 6152, 0)
        put(w, 6160, 0)
        return writing(o, w, r, 6144, 24, 1002)
    if phase == 1002:
        return capture_request(o, w, capture_kit(s, w, C_POLICY_ROLE, L_POLICY_ROLE, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_NAMED), 1003)
    if phase == 1003:
        return launch(o, w, get(w, 216), get(w, 144), 1, 0, 1004)
    if phase == 1004:
        return launch(o, w, get(w, 216), get(w, 144), 2, 0, 1005)
    if phase == 1005:
        return hash_view(o, w, get(w, 144), 0, get(w, 152), 1006)
    if phase == 1006:
        if same_input(s, w, 160, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 216, get(w, 144))
        return call(o, w, 1007, 91, get(w, 216), 320, 0, 0, 0, 0, 0)
    if phase == 1007:
        return publish(o, w, get(w, 216), get(w, 152), C_SEED_NAME, L_SEED_NAME, 320, 1010)
    if phase == 1010:
        return capture_request(o, w, capture_kit(s, w, C_COMPOSER_POLICY, L_COMPOSER_POLICY, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_NAMED), 1011)
    if phase == 1011:
        return launch(o, w, get(w, 216), get(w, 144), 1, 0, 1012)
    if phase == 1012:
        return launch(o, w, get(w, 216), get(w, 144), 2, 0, 1013)
    if phase == 1013:
        put(w, 120, get(w, 144))
        return call(o, w, 4300, 91, get(w, 120), 320, 0, 0, 0, 0, 0)
    if phase == 1014:
        return capture_request(o, w, capture_kit(s, w, C_PLAN_POLICY, L_PLAN_POLICY, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_KIT), 1015)
    if phase == 1015:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 1016)
    if phase == 1016:
        put(w, 128, get(w, 144))
        return call(o, w, 1017, 91, get(w, 128), 320, 0, 0, 0, 0, 0)
    if phase == 1017:
        return capture_request(o, w, capture_one(s, w, C_RECIPE_PATH, L_RECIPE_PATH, C_DATA_ALIAS, L_DATA_ALIAS, MAGIC_RAW), 1018)
    if phase == 1018:
        return launch(o, w, get(w, 128), get(w, 144), 3, 0, 1019)
    if phase == 1019:
        if get(w, 152) < 16 or get(w, 152) > 65536:
            return finish(o, w, 65)
        put(w, 112, get(w, 152))
        return reading(o, w, get(w, 144), 200704, get(w, 152), 0, 1020)
    if phase == 1020:
        if admit_recipes(s, w) == 0:
            return finish(o, w, 65)
        return launch(o, w, get(w, 128), get(w, 144), 3, 0, 1021)
    if phase == 1021:
        if get(w, 152) != 16 + get(w, 104) * 8:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 286720, get(w, 152), 0, 1022)
    if phase == 1022:
        if admit_reuse(w) == 0:
            return finish(o, w, 65)
        return call(o, w, 1023, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 1023:
        return capture_request(o, w, capture_kit(s, w, C_STAGE_POLICY, L_STAGE_POLICY, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_KIT), 1024)
    if phase == 1024:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 1025)
    if phase == 1025:
        put(w, 321000, get(w, 144))
        return call(o, w, 1026, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 1026:
        put(w, 96, 0)
        return member_loop(s, o, w, 1200, 0)
    if phase == 1300:
        put(w, 1104, 0)
        return resume(s, o, w, 1301)
    if phase == 1301:
        if get(w, 1104) == 8:
            return compiler_manifest(s, o, w, 2000, 0)
        row = C_RESOURCE_TABLE + get(w, 1104) * 32
        return capture_request(o, w, capture_one(s, w, get(w, row), get(w, row + 8), get(w, row + 16), get(w, row + 24), MAGIC_RAW), 1302)
    if phase == 1302:
        put(w, 320000 + get(w, 1104) * 16, get(w, 144))
        put(w, 320008 + get(w, 1104) * 16, get(w, 152))
        row = C_RESOURCE_TABLE + get(w, 1104) * 32
        return publish(o, w, get(w, 144), get(w, 152), get(w, row + 16), get(w, row + 24), 256, 1303)
    if phase == 1303:
        put(w, 1104, get(w, 1104) + 1)
        return resume(s, o, w, 1301)
    if phase == 4000:
        return audit_start(s, o, w, 4006)
    if phase == 4006:
        put(w, 6144, MAGIC_INVENTORY)
        put(w, 6152, get(w, 192))
        put(w, 6160, 0)
        return writing(o, w, get(w, 200), 6144, 24, 4001)
    if phase == 4001:
        return call(o, w, 4002, 72, get(w, 200), 1033, 15, 0, 0, 0, 0)
    if phase == 4002:
        if final_frame(s, w) == 0:
            return finish(o, w, 65)
        view(w, 0, get(w, 200), 0, get(w, 256))
        return frame(o, w, 6144, 192 + uint(s, 104), 330000, 1, 4003)
    if phase == 4003:
        return launch(o, w, get(w, 1530080), get(w, 144), 0, 2, 4004)
    if phase == 4004:
        if get(w, 152) == 0 or get(w, 152) > 4096:
            return finish(o, w, 65)
        return copying(o, w, get(w, 144), 1, 0, get(w, 152), 4005)
    if phase == 4005:
        return finish(o, w, 0)
    return finish(o, w, 65)

def audit_start(s:readbuf, o:mutbuf, w:mutbuf, after:u64) -> u32:
    put(w, 1550000, 0)
    put(w, 1550016, after)
    return resume(s, o, w, 4500)

def source_audit(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 4500:
        if get(w, 1550000) == get(w, 80):
            return resume(s, o, w, get(w, 1550016))
        count = minimum(128, get(w, 80) - get(w, 1550000))
        at = capture_begin(s, w, MAGIC_AUDIT, count)
        i = 0
        while i < count:
            row = get(w, 131200 + (get(w, 1550000) + i) * 16)
            pn = uint(s, row)
            copyw(w, 530000, C_AUDIT_ALIAS, L_AUDIT_ALIAS)
            an = decimal(w, 530000 + L_AUDIT_ALIAS, i) - 530000
            if at + 56 + pn + an > 458752:
                return finish(o, w, 65)
            put(w, at, pn)
            put(w, at + 8, an)
            put(w, at + 16, 0)
            copy(s, w, at + 24, row + 8, 32)
            copy(s, w, at + 56, row + 40, pn)
            copyw(w, at + 56 + pn, 530000, an)
            at = at + 56 + pn + an
            i = i + 1
        put(w, 1550008, count)
        return capture_request(o, w, at - 393216, 4501)
    if phase == 4501:
        if get(w, 152) != 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 49152, 24, 0, 4502)
    if phase == 4502:
        if get(w, 49152) != MAGIC_AUDIT_OK or get(w, 49160) != get(w, 1550008) or get(w, 49168) > get(w, 1550008) * 67108864:
            return finish(o, w, 65)
        return call(o, w, 4503, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 4503:
        put(w, 1550000, get(w, 1550000) + get(w, 1550008))
        return resume(s, o, w, 4500)
    return finish(o, w, 65)

def cold_admission(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 4300:
        return capture_request(o, w, capture_kit(s, w, C_COLD_POLICY, L_COLD_POLICY, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_KIT), 4301)
    if phase == 4301:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 4302)
    if phase == 4302:
        put(w, 1531024, get(w, 144))
        put(w, 1531032, get(w, 152))
        return call(o, w, 4303, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 4303:
        return capture_request(o, w, capture_one(s, w, C_CONTRACT_PATH, L_CONTRACT_PATH, C_DATA_ALIAS, L_DATA_ALIAS, MAGIC_RAW), 4304)
    if phase == 4304:
        put(w, 1531000, get(w, 144))
        put(w, 1531008, get(w, 152))
        copy(s, w, 3145728, get(w, 88), uint(s, 112))
        return seal_buffer(o, w, 3145728, uint(s, 112), 4305)
    if phase == 4305:
        put(w, 1531016, get(w, 144))
        put(w, 6144, MAGIC_COLD)
        put(w, 6152, get(w, 3032))
        put(w, 6160, uint(s, 112))
        put(w, 6168, get(w, 1531008))
        copy(s, w, 6176, 224, 32)
        view(w, 0, uint(s, 80), 0, get(w, 3032))
        view(w, 1, get(w, 1531016), 0, uint(s, 112))
        view(w, 2, get(w, 1531000), 0, get(w, 1531008))
        return frame(o, w, 6144, 64, 330000, 3, 4306)
    if phase == 4306:
        return launch(o, w, get(w, 1531024), get(w, 144), 3, 0, 4307)
    if phase == 4307:
        if get(w, 152) != 48:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 49152, 48, 0, 4308)
    if phase == 4308:
        if get(w, 49152) != MAGIC_COLD_OK or get(w, 49192) != get(w, 80) or same_input(s, w, 224, 49160, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 4309, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 4309:
        return publish(o, w, get(w, 1531024), get(w, 1531032), C_COLD_NAME, L_COLD_NAME, 320, 4313)
    if phase == 4313:
        return call(o, w, 4310, 3, get(w, 1531024), 0, 0, 0, 0, 0, 0)
    if phase == 4310:
        return call(o, w, 4311, 3, get(w, 1531000), 0, 0, 0, 0, 0, 0)
    if phase == 4311:
        return call(o, w, 4312, 3, get(w, 1531016), 0, 0, 0, 0, 0, 0)
    if phase == 4312:
        return resume(s, o, w, 1014)
    return finish(o, w, 65)

def frontend(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 6000:
        return capture_request(o, w, capture_kit(s, w, C_FILTER_POLICY, L_FILTER_POLICY, C_ENTRY_PACKER, L_ENTRY_PACKER, MAGIC_KIT), 6001)
    if phase == 6001:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 6002)
    if phase == 6002:
        put(w, 1532000, get(w, 144))
        return call(o, w, 6003, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 6003:
        at = capture_begin(s, w, MAGIC_MULTI, 2)
        at = capture_relative(s, w, at, C_ENTRY_POLICY, L_ENTRY_POLICY, C_ENTRY_ALIAS, L_ENTRY_ALIAS)
        at = capture_relative(s, w, at, C_SHA_SOURCE, L_SHA_SOURCE, C_SHA_SOURCE, L_SHA_SOURCE)
        return capture_request(o, w, choose(at == 0, 0, at - 393216), 6004)
    if phase == 6004:
        return launch(o, w, get(w, 1532000), get(w, 144), 3, 0, 6005)
    if phase == 6005:
        if get(w, 152) < 216:
            return finish(o, w, 65)
        put(w, 992, get(w, 144))
        put(w, 1016, get(w, 152))
        put(w, 1000, 2)
        put(w, 176, C_ENTRY_NAME)
        put(w, 184, L_ENTRY_NAME)
        return reading(o, w, get(w, 144), 546816, 40, get(w, 152) - 40, 6006)
    if phase == 6006:
        if member_footer(w) == 0:
            return finish(o, w, 65)
        return reading(o, w, get(w, 992), 49152, 176, 0, 6007)
    if phase == 6007:
        if elf_header(w, get(w, 160)) == 0:
            return finish(o, w, 65)
        return extract_code(o, w, get(w, 992), get(w, 160), 6008)
    if phase == 6008:
        put(w, 1532008, get(w, 144))
        put(w, 1532016, get(w, 152))
        return call(o, w, 6009, 3, get(w, 992), 0, 0, 0, 0, 0, 0)
    if phase == 6009:
        return call(o, w, 6010, 3, get(w, 1532000), 0, 0, 0, 0, 0, 0)
    if phase == 6010:
        return capture_request(o, w, capture_kit(s, w, C_ENTRY_BINDER, L_ENTRY_BINDER, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_KIT), 6011)
    if phase == 6011:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 6012)
    if phase == 6012:
        put(w, 1532024, get(w, 144))
        if frontend_capabilities(w) == 0:
            return finish(o, w, 65)
        put(w, 1532032, 0)
        put(w, 1532200, MAGIC_ENTRY_BIND)
        return call(o, w, 6013, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 6013:
        index = get(w, 1532032)
        if index == 4:
            view(w, 0, get(w, 1532008), 0, get(w, 1532016))
            return frame(o, w, 1532200, 136, 330000, 1, 6015)
        row = 1532100 + index * 16
        return hash_view(o, w, get(w, row), 0, get(w, row + 8), 6014)
    if phase == 6014:
        copyw(w, 1532208 + get(w, 1532032) * 32, 4096, 32)
        put(w, 1532032, get(w, 1532032) + 1)
        return resume(s, o, w, 6013)
    if phase == 6015:
        return launch(o, w, get(w, 1532024), get(w, 144), 3, 0, 6016)
    if phase == 6016:
        if get(w, 152) != get(w, 1532016):
            return finish(o, w, 65)
        put(w, 1532040, get(w, 144))
        return publish(o, w, get(w, 144), get(w, 152), C_ENTRY_NAME, L_ENTRY_NAME, 320, 6017)
    if phase == 6017:
        return call(o, w, 6018, 3, get(w, 1532040), 0, 0, 0, 0, 0, 0)
    if phase == 6018:
        return call(o, w, 6019, 3, get(w, 1532024), 0, 0, 0, 0, 0, 0)
    if phase == 6019:
        return call(o, w, 6100, 3, get(w, 1532008), 0, 0, 0, 0, 0, 0)
    return finish(o, w, 65)

def frontend_capabilities(w:mutbuf) -> u64:
    owner = find_product(w, C_OWNER_NAME, L_OWNER_NAME)
    runner = find_product(w, C_RUNNER, L_RUNNER)
    capture = find_product(w, C_CAPTURE_NAME, L_CAPTURE_NAME)
    if owner == 0 or runner == 0 or capture == 0:
        return 0
    put(w, 1532100, get(w, owner))
    put(w, 1532108, get(w, owner + 8))
    put(w, 1532116, get(w, runner))
    put(w, 1532124, get(w, runner + 8))
    put(w, 1532132, get(w, 216))
    put(w, 1532140, get(w, 3008))
    put(w, 1532148, get(w, capture))
    put(w, 1532156, get(w, capture + 8))
    return 1

def worker_frontend(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 6100:
        return capture_request(o, w, capture_kit(s, w, C_FILTER_POLICY, L_FILTER_POLICY, C_WORKER_ENTRY_PACKER, L_WORKER_ENTRY_PACKER, MAGIC_KIT), 6101)
    if phase == 6101:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 6102)
    if phase == 6102:
        put(w, 1532000, get(w, 144))
        return call(o, w, 6103, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 6103:
        at = capture_begin(s, w, MAGIC_MULTI, 2)
        at = capture_relative(s, w, at, C_WORKER_ENTRY_POLICY, L_WORKER_ENTRY_POLICY, C_WORKER_ENTRY_ALIAS, L_WORKER_ENTRY_ALIAS)
        at = capture_relative(s, w, at, C_SHA_SOURCE, L_SHA_SOURCE, C_SHA_SOURCE, L_SHA_SOURCE)
        return capture_request(o, w, choose(at == 0, 0, at - 393216), 6104)
    if phase == 6104:
        return launch(o, w, get(w, 1532000), get(w, 144), 3, 0, 6105)
    if phase == 6105:
        if get(w, 152) < 216:
            return finish(o, w, 65)
        put(w, 992, get(w, 144))
        put(w, 1016, get(w, 152))
        put(w, 1000, 2)
        put(w, 176, C_WORKER_ENTRY_NAME)
        put(w, 184, L_WORKER_ENTRY_NAME)
        return reading(o, w, get(w, 144), 546816, 40, get(w, 152) - 40, 6106)
    if phase == 6106:
        if member_footer(w) == 0:
            return finish(o, w, 65)
        return reading(o, w, get(w, 992), 49152, 176, 0, 6107)
    if phase == 6107:
        if elf_header(w, get(w, 160)) == 0:
            return finish(o, w, 65)
        return extract_code(o, w, get(w, 992), get(w, 160), 6108)
    if phase == 6108:
        put(w, 1532008, get(w, 144))
        put(w, 1532016, get(w, 152))
        return call(o, w, 6109, 3, get(w, 992), 0, 0, 0, 0, 0, 0)
    if phase == 6109:
        return call(o, w, 6110, 3, get(w, 1532000), 0, 0, 0, 0, 0, 0)
    if phase == 6110:
        return capture_request(o, w, capture_kit(s, w, C_WORKER_ENTRY_BINDER, L_WORKER_ENTRY_BINDER, C_PACKER_ROLE, L_PACKER_ROLE, MAGIC_KIT), 6111)
    if phase == 6111:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 6112)
    if phase == 6112:
        put(w, 1532024, get(w, 144))
        if worker_frontend_capabilities(w) == 0:
            return finish(o, w, 65)
        put(w, 1532032, 0)
        put(w, 1532200, MAGIC_ENTRY_BIND)
        return call(o, w, 6113, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 6113:
        index = get(w, 1532032)
        if index == 4:
            view(w, 0, get(w, 1532008), 0, get(w, 1532016))
            return frame(o, w, 1532200, 136, 330000, 1, 6115)
        row = 1532100 + index * 16
        return hash_view(o, w, get(w, row), 0, get(w, row + 8), 6114)
    if phase == 6114:
        copyw(w, 1532208 + get(w, 1532032) * 32, 4096, 32)
        put(w, 1532032, get(w, 1532032) + 1)
        return resume(s, o, w, 6113)
    if phase == 6115:
        return launch(o, w, get(w, 1532024), get(w, 144), 3, 0, 6116)
    if phase == 6116:
        if get(w, 152) != get(w, 1532016):
            return finish(o, w, 65)
        put(w, 1532040, get(w, 144))
        return publish(o, w, get(w, 144), get(w, 152), C_WORKER_ENTRY_NAME, L_WORKER_ENTRY_NAME, 320, 6117)
    if phase == 6117:
        return call(o, w, 6118, 3, get(w, 1532040), 0, 0, 0, 0, 0, 0)
    if phase == 6118:
        return call(o, w, 6119, 3, get(w, 1532024), 0, 0, 0, 0, 0, 0)
    if phase == 6119:
        return call(o, w, 4000, 3, get(w, 1532008), 0, 0, 0, 0, 0, 0)
    return finish(o, w, 65)

def worker_frontend_capabilities(w:mutbuf) -> u64:
    owner = find_product(w, C_WORKER_OWNER_NAME, L_WORKER_OWNER_NAME)
    runner = find_product(w, C_RUNNER, L_RUNNER)
    capture = find_product(w, C_CAPTURE_NAME, L_CAPTURE_NAME)
    if owner == 0 or runner == 0 or capture == 0:
        return 0
    put(w, 1532100, get(w, owner))
    put(w, 1532108, get(w, owner + 8))
    put(w, 1532116, get(w, runner))
    put(w, 1532124, get(w, runner + 8))
    put(w, 1532132, get(w, 216))
    put(w, 1532140, get(w, 3008))
    put(w, 1532148, get(w, capture))
    put(w, 1532156, get(w, capture + 8))
    return 1

def admit_recipes(s:readbuf, w:mutbuf) -> u64:
    if get(w, 200704) != MAGIC_RECIPES or get(w, 200712) == 0 or get(w, 200712) > 256:
        return 0
    put(w, 104, get(w, 200712))
    if uint(s, 120) != 0 and uint(s, 120) != get(w, 104):
        return 0
    at = 200720
    i = 0
    while i < get(w, 104):
        at = recipe_entry(w, at, i)
        if at == 0:
            return 0
        i = i + 1
    if at != 200704 + get(w, 112):
        return 0
    if get(w, 270352) != L_DIRECTORY_NAME or same(w, get(w, 270344), C_DIRECTORY_NAME, L_DIRECTORY_NAME) == 0:
        return 0
    return 1

def recipe_entry(w:mutbuf, at:u64, index:u64) -> u64:
    if at >= 200704 + get(w, 112):
        return 0
    count = byte(w, at)
    if count < 2 or count > 10 or count & 1 != 0:
        return 0
    record = 270336 + index * 64
    put(w, record, at)
    put(w, record + 40, (count - 2) >> 1)
    at = at + 1
    i = 0
    while i < count:
        if at >= 200704 + get(w, 112):
            return 0
        n = byte(w, at)
        if n == 0 or n > 127 or n > 200704 + get(w, 112) - at - 1:
            return 0
        if i == 0:
            if valid_product(w, at + 1, n) == 0 or duplicate_product(w, at + 1, n, index) == 1:
                return 0
            put(w, record + 8, at + 1)
            put(w, record + 16, n)
        if i == 1:
            put(w, record + 24, at + 1)
            put(w, record + 32, n)
            put(w, record + 48, at + n + 1)
        at = at + 1 + n
        i = i + 1
    return at

def valid_product(w:mutbuf, at:u64, n:u64) -> u64:
    if n < 5 or byte(w, at) != 104 or byte(w, at + 1) != 105 or byte(w, at + 2) != 97 or byte(w, at + 3) != 45:
        return 0
    i = 0
    while i < n:
        if plain(byte(w, at + i)) == 0:
            return 0
        i = i + 1
    return 1

def duplicate_product(w:mutbuf, at:u64, n:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if get(w, 270352 + i * 64) == n and same(w, get(w, 270344 + i * 64), at, n) == 1:
            return 1
        i = i + 1
    return 0

def admit_reuse(w:mutbuf) -> u64:
    if get(w, 286720) != MAGIC_REUSE or get(w, 286728) != get(w, 104):
        return 0
    i = 0
    while i < get(w, 104):
        owner = get(w, 286736 + i * 8)
        if owner > i or get(w, 286736 + owner * 8) != owner:
            return 0
        record = 270336 + i * 64
        source = 270336 + owner * 64
        if get(w, record + 32) != get(w, source + 32) or same(w, get(w, record + 24), get(w, source + 24), get(w, record + 32)) == 0:
            return 0
        put(w, record + 56, owner)
        i = i + 1
    return 1

def member_loop(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1200:
        if get(w, 96) == get(w, 104):
            return resume(s, o, w, 1300)
        record = 270336 + get(w, 96) * 64
        put(w, 176, get(w, record + 8))
        put(w, 184, get(w, record + 16))
        put(w, 1000, get(w, record + 40))
        if get(w, record + 56) == get(w, 96):
            return capture_request(o, w, capture_kit(s, w, C_FILTER_POLICY, L_FILTER_POLICY, get(w, record + 24), get(w, record + 32), MAGIC_KIT), 1201)
        put(w, 136, get(w, 290816 + get(w, record + 56) * 8))
        if get(w, 136) < 3:
            return finish(o, w, 65)
        return member_loop(s, o, w, 1204, 0)
    if phase == 1201:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 1202)
    if phase == 1202:
        put(w, 136, get(w, 144))
        put(w, 290816 + get(w, 96) * 8, get(w, 144))
        return call(o, w, 1204, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 1204:
        if get(w, 1000) == 0:
            if get(w, 184) != L_PORT_NAME or same(w, get(w, 176), C_PORT_NAME, L_PORT_NAME) == 0:
                return finish(o, w, 65)
            put(w, 393216, MAGIC_PORT)
            return seal_buffer(o, w, 393216, 8, 1206)
        return capture_request(o, w, member_capture(s, w), 1206)
    if phase == 1206:
        return launch(o, w, get(w, 136), get(w, 144), 3, 0, 1207)
    if phase == 1207:
        if get(w, 152) < 176:
            return finish(o, w, 65)
        put(w, 992, get(w, 144))
        put(w, 1016, get(w, 152))
        if get(w, 1000) == 0:
            put(w, 160, get(w, 152))
            return reading(o, w, get(w, 144), 49152, 176, 0, 1210)
        return reading(o, w, get(w, 144), 546816, choose(get(w, 1000) == 1, 24, (get(w, 1000) + 3) * 8), get(w, 152) - choose(get(w, 1000) == 1, 24, (get(w, 1000) + 3) * 8), 1208)
    if phase == 1208:
        if member_footer(w) == 0:
            return finish(o, w, 65)
        return reading(o, w, get(w, 992), 49152, choose(is_artifact(w), 352, 176), 0, 1210)
    if phase == 1210:
        if elf_header(w, get(w, 160)) == 0:
            return finish(o, w, 65)
        if selfhost_view(w) != 0:
            return hash_view(o, w, get(w, 992), get(w, 1144), get(w, 1152), 1214)
        return extract_code(o, w, get(w, 992), get(w, 160), 1211)
    if phase == 1214:
        if same_input(s, w, 224, 4096, 32) == 0:
            return finish(o, w, 65)
        return extract_code(o, w, get(w, 992), get(w, 160), 1211)
    if phase == 1211:
        put(w, 321080, get(w, 144))
        put(w, 321088, get(w, 152))
        put(w, 321008, member_binding(w))
        if get(w, 321008) == 0:
            return publish(o, w, get(w, 144), get(w, 152), get(w, 176), get(w, 184), 320, 1212)
        row = 270336 + get(w, 96) * 64
        copyw(w, 530000, C_CORE_PREFIX, L_CORE_PREFIX)
        copyw(w, 530000 + L_CORE_PREFIX, get(w, row + 24), get(w, row + 32))
        return capture_request(o, w, capture_one(s, w, 530000, L_CORE_PREFIX + get(w, row + 32), C_DATA_ALIAS, L_DATA_ALIAS, MAGIC_RAW), 1215)
    if phase == 1212:
        retain_product(w)
        if get(w, 184) == L_CORE_NAME and same(w, get(w, 176), C_CORE_NAME, L_CORE_NAME) == 1:
            put(w, 1112, get(w, 992))
            put(w, 1120, get(w, 160))
            put(w, 1128, get(w, 546824))
            return member_loop(s, o, w, 1213, 0)
        return call(o, w, 1213, 3, get(w, 992), 0, 0, 0, 0, 0, 0)
    if phase == 1213:
        put(w, 96, get(w, 96) + 1)
        return member_loop(s, o, w, 1200, 0)
    if phase >= 1215:
        return binding_check(s, o, w, phase, r)
    return finish(o, w, 65)

def member_capture(s:readbuf, w:mutbuf) -> u64:
    record = 270336 + get(w, 96) * 64
    source = get(w, record + 48)
    at = capture_begin(s, w, choose(get(w, 1000) == 1, MAGIC_IMAGE, MAGIC_MULTI), get(w, 1000))
    i = 0
    while i < get(w, 1000):
        an = byte(w, source)
        alias = source + 1
        source = alias + an
        pn = byte(w, source)
        at = capture_relative(s, w, at, source + 1, pn, alias, an)
        if at == 0:
            return 0
        source = source + 1 + pn
        i = i + 1
    return at - 393216

def member_footer(w:mutbuf) -> u64:
    count = get(w, 1000)
    size = get(w, 546816)
    if size < 176 or size > get(w, 1016):
        return 0
    total = size
    i = 0
    while i < count:
        n = get(w, 546824 + i * 8)
        if n == 0 or n > 1048576:
            return 0
        total = total + n
        i = i + 1
    if count == 1:
        if get(w, 546832) != MAGIC_OBJECT or total + 24 != get(w, 1016):
            return 0
    else:
        if get(w, 546824 + count * 8) != count or get(w, 546832 + count * 8) != MAGIC_OBJECTS or total + (count + 3) * 8 != get(w, 1016):
            return 0
    put(w, 160, size)
    return 1

def elf_header(w:mutbuf, size:u64) -> u64:
    if get(w, 49152) != 282584257676671 or get(w, 49160) != 0:
        return 0
    if get(w, 49168) != 4299030530 or get(w, 49184) != 64 or get(w, 49192) != 0:
        return 0
    if get(w, 49200) != 15762873573703680 or get(w, 49208) != choose(is_artifact(w), 3, 2):
        return 0
    if get(w, 49216) != 21474836481 or get(w, 49224) != 0 or get(w, 49232) != 4194304 or get(w, 49240) != 4194304:
        return 0
    if get(w, 49248) != size or get(w, 49256) != size or get(w, 49264) != 4096:
        return 0
    if get(w, 49272) != 27455186257 or get(w, 49320) != 16:
        return 0
    i = 128
    while i < 168:
        if get(w, 49152 + i) != 0:
            return 0
        i = i + 8
    if is_artifact(w):
        return artifact_header(w, size)
    return choose(get(w, 49176) == 4194480, 1, 0)

def is_artifact(w:mutbuf) -> bool:
    return get(w, 184) == L_ARTIFACT_NAME and same(w, get(w, 176), C_ARTIFACT_NAME, L_ARTIFACT_NAME) == 1

def artifact_header(w:mutbuf, size:u64) -> u64:
    if size < 352 or get(w, 49176) != 4194656:
        return 0
    if get(w, 49328) != 17179869188 or get(w, 49336) != 232 or get(w, 49344) != 4194536 or get(w, 49352) != 4194536:
        return 0
    if get(w, 49360) != 120 or get(w, 49368) != 120 or get(w, 49376) != 4:
        return 0
    if get(w, 49384) != 412316860425 or getn(w, 49392, 4) != 1 or get(w, 49396) != 6217584620943264072 or getn(w, 49404, 4) != 0:
        return 0
    if get(w, 49408) != MAGIC_ARTIFACT_DESCRIPTOR or get(w, 49416) != 1 or get(w, 49424) != 4194656:
        return 0
    if get(w, 49432) <= 4194656 or get(w, 49432) >= 4194304 + size:
        return 0
    if get(w, 49440) != 16 or get(w, 49448) != 128 or get(w, 49456) != 96 or get(w, 49464) != 24:
        return 0
    if get(w, 49472) != 0 or get(w, 49480) != 0 or get(w, 49488) != 63 or get(w, 49496) != 0:
        return 0
    return 1

def extract_code(o:mutbuf, w:mutbuf, source:u64, count:u64, after:u64) -> u32:
    return extract_view(o, w, source, 0, count, after)

def extract_view(o:mutbuf, w:mutbuf, source:u64, offset:u64, count:u64, after:u64) -> u32:
    put(w, 1184, offset)
    put(w, 1072, source)
    put(w, 1080, count)
    put(w, 1088, after)
    return call(o, w, 1400, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)

def materialize(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1400:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1096, r)
        return copying(o, w, get(w, 1072), r, get(w, 1184), get(w, 1080), 1401)
    if phase == 1401:
        return call(o, w, 1402, 91, get(w, 1096), 320, 0, 0, 0, 0, 0)
    if phase == 1402:
        return call(o, w, 1403, 72, get(w, 1096), 1033, 15, 0, 0, 0, 0)
    if phase == 1403:
        put(w, 144, get(w, 1096))
        put(w, 152, get(w, 1080))
        return resume(s, o, w, get(w, 1088))
    return finish(o, w, 65)

def retain_product(w:mutbuf) -> u64:
    at = 294912 + get(w, 96) * 32
    put(w, at, get(w, 144))
    put(w, at + 8, get(w, 152))
    put(w, at + 16, get(w, 176))
    put(w, at + 24, get(w, 184))
    return 0

def selfhost_view(w:mutbuf) -> u64:
    source = get(w, 270384 + get(w, 96) * 64)
    offset = get(w, 160)
    i = 0
    while i < get(w, 1000):
        n = byte(w, source)
        if n == L_SELFHOST and same(w, source + 1, C_SELFHOST, n) == 1:
            put(w, 1144, offset)
            put(w, 1152, get(w, 546824 + i * 8))
            return 1
        source = source + n + 1
        source = source + byte(w, source) + 1
        offset = offset + get(w, 546824 + i * 8)
        i = i + 1
    return 0

def frame(o:mutbuf, w:mutbuf, header:u64, size:u64, parts:u64, count:u64, after:u64) -> u32:
    if count > 128 or size > 65536:
        return finish(o, w, 65)
    put(w, 3080, after)
    put(w, 3088, parts)
    put(w, 3096, count)
    put(w, 3104, 0)
    put(w, 3112, header)
    put(w, 3120, size)
    put(w, 3128, size)
    put(w, 3136, 0)
    return call(o, w, 1600, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)

def framed(o:mutbuf, w:mutbuf, header:u64, size:u64, parts:u64, count:u64, after:u64) -> u32:
    result = frame(o, w, header, size, parts, count, after)
    put(w, 3136, 1)
    return result

def frame_step(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1600:
        if r < 3:
            return finish(o, w, 74)
        put(w, 3072, r)
        return writing(o, w, r, get(w, 3112), get(w, 3120), 1601)
    if phase == 1601:
        return call(o, w, 1602, 8, get(w, 3072), get(w, 3120), 0, 0, 0, 0, 0)
    if phase == 1602 or phase == 1603:
        if phase == 1602 and r != get(w, 3120):
            return finish(o, w, 74)
        if phase == 1603:
            put(w, 3104, get(w, 3104) + 1)
        if get(w, 3104) == get(w, 3096):
            return call(o, w, 1604, 72, get(w, 3072), 1033, 15, 0, 0, 0, 0)
        row = get(w, 3088) + get(w, 3104) * 24
        if get(w, row) < 3 or get(w, row + 16) > 67108864 or get(w, 3128) > 67108864 - get(w, row + 16):
            return finish(o, w, 65)
        if get(w, 3136) != 0:
            if get(w, 3128) + get(w, row + 16) > 67108856:
                return finish(o, w, 65)
            put(w, 6144, get(w, row + 16))
            return writing_at(o, w, get(w, 3072), 6144, 8, get(w, 3128), 1605)
        put(w, 3128, get(w, 3128) + get(w, row + 16))
        return copying(o, w, get(w, row), get(w, 3072), get(w, row + 8), get(w, row + 16), 1603)
    if phase == 1605:
        put(w, 3128, get(w, 3128) + 8)
        return call(o, w, 1606, 8, get(w, 3072), get(w, 3128), 0, 0, 0, 0, 0)
    if phase == 1606:
        if r != get(w, 3128):
            return finish(o, w, 74)
        row = get(w, 3088) + get(w, 3104) * 24
        put(w, 3128, get(w, 3128) + get(w, row + 16))
        return copying(o, w, get(w, row), get(w, 3072), get(w, row + 8), get(w, row + 16), 1603)
    if phase == 1604:
        put(w, 144, get(w, 3072))
        put(w, 152, get(w, 3128))
        return resume(s, o, w, get(w, 3080))
    return finish(o, w, 65)

def view(w:mutbuf, index:u64, file:u64, offset:u64, size:u64) -> u64:
    put(w, 330000 + index * 24, file)
    put(w, 330008 + index * 24, offset)
    put(w, 330016 + index * 24, size)
    return 0

def compiler_manifest(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 2000:
        if get(w, 1112) < 3 or get(w, 1128) == 0:
            return finish(o, w, 65)
        return capture_request(o, w, capture_kit(s, w, C_MANIFEST_POLICY, L_MANIFEST_POLICY, C_CORE_PACKER, L_CORE_PACKER, MAGIC_KIT), 2001)
    if phase == 2001:
        return launch(o, w, get(w, 120), get(w, 144), 3, 0, 2002)
    if phase == 2002:
        put(w, 1176, get(w, 144))
        return call(o, w, 2003, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 2003:
        return call(o, w, 2004, 32, get(w, 320064), 0, 0, 0, 0, 0, 0)
    if phase == 2004:
        if r < 3:
            return finish(o, w, 74)
        return launch(o, w, get(w, 216), r, 4, 0, 2005)
    if phase == 2005:
        if get(w, 152) > 1048576:
            return finish(o, w, 65)
        put(w, 1160, get(w, 144))
        put(w, 1168, get(w, 152))
        if manifest_views(s, w) == 0:
            return finish(o, w, 65)
        return frame(o, w, 6144, 80, 330000, 9, 2006)
    if phase == 2006:
        return launch(o, w, get(w, 1176), get(w, 144), 3, 0, 2007)
    if phase == 2007:
        return publish(o, w, get(w, 144), get(w, 152), C_MANIFEST_NAME, L_MANIFEST_NAME, 256, 2008)
    if phase == 2008:
        put(w, 1560500, 0)
        return resume(s, o, w, 2010)
    if phase == 2010:
        index = get(w, 1560500)
        if index < get(w, 104):
            put(w, 1560500, index + 1)
            fd = get(w, 290816 + index * 8)
            put(w, 290816 + index * 8, 0)
            if fd >= 3:
                return call(o, w, 2010, 3, fd, 0, 0, 0, 0, 0, 0)
            return resume(s, o, w, 2010)
        return call(o, w, 2011, 3, get(w, 128), 0, 0, 0, 0, 0, 0)
    if phase == 2011:
        return call(o, w, 2012, 3, get(w, 1176), 0, 0, 0, 0, 0, 0)
    if phase == 2012:
        return call(o, w, 2013, 3, get(w, 1160), 0, 0, 0, 0, 0, 0)
    if phase == 2013:
        return call(o, w, 2014, 3, get(w, 1112), 0, 0, 0, 0, 0, 0)
    if phase == 2014:
        put(w, 1519984, 0)
        put(w, 1599904, 0)
        return resume(s, o, w, 5000)
    return finish(o, w, 65)

def final_frame(s:readbuf, w:mutbuf) -> u64:
    finalizer = find_product(w, C_FINALIZE_NAME, L_FINALIZE_NAME)
    packer = find_product(w, C_DIRECTORY_NAME, L_DIRECTORY_NAME)
    installer = find_product(w, C_INSTALLER_NAME, L_INSTALLER_NAME)
    artifact = find_product(w, C_ARTIFACT_NAME, L_ARTIFACT_NAME)
    if finalizer == 0 or packer == 0 or installer == 0 or artifact == 0:
        return 0
    put(w, 1530080, get(w, finalizer))
    put(w, 1530000, uint(s, 32))
    put(w, 1530008, uint(s, 40))
    put(w, 1530016, uint(s, 88))
    put(w, 1530024, uint(s, 96))
    put(w, 1530032, get(w, 232))
    put(w, 1530040, get(w, packer))
    put(w, 1530048, get(w, 216))
    put(w, 1530056, get(w, installer))
    put(w, 1530064, get(w, artifact))
    put(w, 6144, MAGIC_FINALIZE)
    put(w, 6152, 0)
    put(w, 6160, uint(s, 16))
    i = 0
    while i < 9:
        put(w, 6168 + i * 8, get(w, 1530000 + i * 8))
        i = i + 1
    put(w, 6240, uint(s, 104))
    put(w, 6248, get(w, 256))
    put(w, 6256, 64)
    put(w, 6264, 0)
    copy(s, w, 6272, 288, uint(s, 104))
    i = 0
    while i < 32:
        ch = byte(s, 128 + i)
        store(w, 6272 + uint(s, 104) + i * 2, hex_digit(ch >> 4))
        store(w, 6273 + uint(s, 104) + i * 2, hex_digit(ch & 15))
        i = i + 1
    return 1

def manifest_views(s:readbuf, w:mutbuf) -> u64:
    view(w, 0, uint(s, 80), 0, get(w, 3032))
    view(w, 1, uint(s, 72), 0, get(w, 3024))
    core = find_product(w, C_CORE_NAME, L_CORE_NAME)
    if core == 0:
        return 0
    view(w, 2, get(w, core), 0, get(w, core + 8))
    view(w, 3, get(w, 1112), get(w, 1120), get(w, 1128))
    view(w, 4, get(w, 1160), 0, get(w, 1168))
    view(w, 5, get(w, 320096), 0, get(w, 320104))
    view(w, 6, get(w, 320064), 0, get(w, 320072))
    view(w, 7, get(w, 320080), 0, get(w, 320088))
    view(w, 8, get(w, 320000), 0, get(w, 320008))
    put(w, 6144, MAGIC_COMPILER_MANIFEST)
    i = 0
    while i < 9:
        put(w, 6152 + i * 8, get(w, 330016 + i * 24))
        i = i + 1
    return 1

def find_product(w:mutbuf, name:u64, size:u64) -> u64:
    i = 0
    while i < get(w, 104):
        at = 294912 + i * 32
        if get(w, at + 24) == size and same(w, get(w, at + 16), name, size) == 1:
            return at
        i = i + 1
    return 0

def member_binding(w:mutbuf) -> u64:
    i = 0
    while i < N_BINDINGS:
        at = C_BINDINGS_TABLE + i * 64
        if get(w, at + 8) == get(w, 184) and same(w, get(w, at), get(w, 176), get(w, 184)) == 1:
            return at
        i = i + 1
    return 0

def binding_check(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1215:
        put(w, 321016, get(w, 144))
        put(w, 321024, get(w, 152))
        row = get(w, 321008)
        return capture_request(o, w, capture_one(s, w, get(w, row + 16), get(w, row + 24), C_DATA_ALIAS, L_DATA_ALIAS, MAGIC_RAW), 1216)
    if phase == 1216:
        put(w, 321032, get(w, 144))
        put(w, 321040, get(w, 152))
        row = get(w, 321008)
        return seal_buffer(o, w, get(w, row + 48), get(w, row + 56), 1217)
    if phase == 1217:
        put(w, 321048, get(w, 144))
        put(w, 321056, get(w, 152))
        row = get(w, 321008)
        if get(w, row + 40) == 2:
            return seal_buffer(o, w, C_ZERO_ENTRIES, get(w, row + 32) * 8, 1218)
        return binding_check(s, o, w, 1219, 0)
    if phase == 1218:
        put(w, 321064, get(w, 144))
        put(w, 321072, get(w, 152))
        return binding_check(s, o, w, 1219, 0)
    if phase == 1219:
        if binding_views(w) == 0:
            return finish(o, w, 65)
        return framed(o, w, 6144, 40, 330000, get(w, 6168), 1220)
    if phase == 1220:
        return launch(o, w, get(w, 321000), get(w, 144), 3, 0, 1221)
    if phase == 1221:
        if get(w, 152) != 32:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 49152, 32, 0, 1222)
    if phase == 1222:
        row = get(w, 321008)
        if get(w, 49152) != MAGIC_STAGE_OK or get(w, 49160) != get(w, row + 40) or get(w, 49168) != get(w, row + 32) or get(w, 49176) != get(w, 321088):
            return finish(o, w, 65)
        return call(o, w, 1223, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 1223:
        return call(o, w, 1224, 3, get(w, 321016), 0, 0, 0, 0, 0, 0)
    if phase == 1224:
        return call(o, w, 1225, 3, get(w, 321032), 0, 0, 0, 0, 0, 0)
    if phase == 1225:
        return call(o, w, 1226, 3, get(w, 321048), 0, 0, 0, 0, 0, 0)
    if phase == 1226:
        if get(w, get(w, 321008) + 40) == 2:
            return call(o, w, 1227, 3, get(w, 321064), 0, 0, 0, 0, 0, 0)
        return binding_check(s, o, w, 1227, 0)
    if phase == 1227:
        put(w, 144, get(w, 321080))
        put(w, 152, get(w, 321088))
        return publish(o, w, get(w, 144), get(w, 152), get(w, 176), get(w, 184), 320, 1212)
    return finish(o, w, 65)

def binding_views(w:mutbuf) -> u64:
    row = get(w, 321008)
    mode = get(w, row + 40)
    calls = get(w, row + 32)
    if calls == 0 or calls != get(w, 1000):
        return 0
    put(w, 6144, MAGIC_STAGE_CHECK)
    put(w, 6152, mode)
    put(w, 6160, calls)
    put(w, 6168, choose(mode == 2, 6, 4 + calls))
    put(w, 6176, 0)
    view(w, 0, get(w, 321080), 0, get(w, 321088))
    if mode == 2:
        view(w, 1, get(w, 992), get(w, 160), get(w, 546824))
        view(w, 2, get(w, 321016), 0, get(w, 321024))
        view(w, 3, get(w, 321032), 0, get(w, 321040))
        view(w, 4, get(w, 321064), 0, get(w, 321072))
        view(w, 5, get(w, 321048), 0, get(w, 321056))
    else:
        view(w, 1, get(w, 321016), 0, get(w, 321024))
        view(w, 2, get(w, 321032), 0, get(w, 321040))
        view(w, 3, get(w, 321048), 0, get(w, 321056))
        i = 0
        at = get(w, 160)
        while i < calls:
            view(w, 4 + i, get(w, 992), at, get(w, 546824 + i * 8))
            at = at + get(w, 546824 + i * 8)
            i = i + 1
    return 1

def resume(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u32:
    put(w, 0, phase)
    put(w, 8, 0)
    return 4

def sha(o:mutbuf, w:mutbuf, phase:u64, operation:u64, count:u64) -> u32:
    store(w, 65536, operation)
    put(w, 0, phase)
    put(o, 0, count)
    return 3

def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, mask:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, mask)
    return 1

def finish(o:mutbuf, w:mutbuf, code:u64) -> u32:
    return call(o, w, 99999, 60, code, 0, 0, 0, 0, 0, 0)

def minimum(a:u64, b:u64) -> u64:
    return choose(a < b, a, b)

def arg(w:mutbuf, at:u64, source:u64, count:u64) -> u64:
    put(w, at, count)
    copyw(w, at + 8, source, count)
    store(w, at + 8 + count, 0)
    return at + 9 + count

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    factor = 1
    while divide(value, factor) >= 10:
        factor = factor * 10
    while factor != 0:
        digit = divide(value, factor)
        store(w, at, 48 + digit)
        value = value - digit * factor
        factor = divide(factor, 10)
        at = at + 1
    return at

def divide(value:u64, divisor:u64) -> u64:
    bit = 1
    quotient = 0
    while divisor <= (value >> 1):
        divisor = divisor << 1
        bit = bit << 1
    while bit != 0:
        if value >= divisor:
            value = value - divisor
            quotient = quotient | bit
        divisor = divisor >> 1
        bit = bit >> 1
    return quotient

def same(w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def same_input(s:readbuf, w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if byte(s, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def copy(s:readbuf, w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def copyw(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def failed(value:u64) -> bool:
    return value >> 63 != 0

def uint(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return getn(w, at, 8)

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    value = 0
    while i < count:
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
DAG_POLICY = r'''def dag(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 5600:
        return dag_codec(s, o, w, phase, r)
    if phase >= 5200 and phase < 5300:
        return dag_kit(s, o, w, phase, r)
    if phase >= 5300 and phase < 5400:
        return dag_pick(s, o, w, phase, r)
    if phase >= 5400 and phase < 5500:
        return dag_run(s, o, w, phase, r)
    if phase >= 5500:
        return dag_check(s, o, w, phase, r)
    if phase == 5000:
        if get(w, 1519984) == N_DAGS:
            return resume(s, o, w, 6000)
        path = C_DAG_PATHS + get(w, 1519984) * 16
        return capture_request(o, w, capture_one(s, w, get(w, path), get(w, path + 8), C_DATA_ALIAS, L_DATA_ALIAS, MAGIC_RAW), 5001)
    if phase == 5001:
        if get(w, 152) < 24 or get(w, 152) > 1048576:
            return finish(o, w, 65)
        put(w, 1500000, get(w, 144))
        put(w, 1500008, get(w, 152))
        return reading(o, w, get(w, 144), 2097152, get(w, 152), 0, 5002)
    if phase == 5002:
        if get(w, 2097152) != MAGIC_DAG or get(w, 2097160) == 0 or get(w, 2097160) > 8192 or get(w, 2097168) > 512:
            return finish(o, w, 65)
        put(w, 1500016, get(w, 2097160))
        put(w, 1500024, get(w, 2097168))
        put(w, 1500032, 2097176)
        put(w, 1500040, 0)
        put(w, 1500104, get(w, 1599904))
        return call(o, w, 5003, 3, get(w, 1500000), 0, 0, 0, 0, 0, 0)
    if phase == 5003:
        if get(w, 1500040) == get(w, 1500016):
            if get(w, 1500032) != 2097152 + get(w, 1500008) or get(w, 1599904) - get(w, 1500104) != get(w, 1500024):
                return finish(o, w, 65)
            put(w, 1500120, 1)
            return resume(s, o, w, 5010)
        if dag_node(w) == 0:
            return finish(o, w, 65)
        return dag_execute(s, o, w)
    if phase == 5004:
        return dag_commit(o, w, 1)
    if phase == 5005:
        return dag_commit(o, w, 0)
    if phase == 5010:
        if get(w, 1500120) > 2048:
            put(w, 1519984, get(w, 1519984) + 1)
            return resume(s, o, w, 5000)
        row = 1048576 + get(w, 1500120) * 64
        put(w, 1500120, get(w, 1500120) + 1)
        fd = get(w, row)
        own = get(w, row + 56)
        put(w, row, 0)
        put(w, row + 56, 0)
        if own == 1:
            return call(o, w, 5010, 3, fd, 0, 0, 0, 0, 0, 0)
        return resume(s, o, w, 5010)
    return finish(o, w, 65)

def dag_node(w:mutbuf) -> u64:
    at = get(w, 1500032)
    end = 2097152 + get(w, 1500008)
    if at > end or end - at < 32:
        return 0
    op = get(w, at)
    id = get(w, at + 8)
    count = get(w, at + 16)
    size = get(w, at + 24)
    if op < 1 or op > 19 or count > 132 or size > 1048576 or 32 + count * 8 + size > end - at:
        return 0
    if op >= 7 and op <= 10:
        if id != 0:
            return 0
    else:
        if id == 0 or id > 2048 or get(w, 1048576 + id * 64) != 0:
            return 0
    put(w, 1500048, op)
    put(w, 1500056, id)
    put(w, 1500064, count)
    put(w, 1500072, at + 32 + count * 8)
    put(w, 1500080, size)
    put(w, 1500088, at + 32 + count * 8 + size)
    put(w, 1500096, at + 32)
    put(w, 1500136, 0)
    put(w, 1500144, 0)
    put(w, 1500152, 0)
    put(w, 1500160, 0)
    put(w, 1500168, 0)
    return 1

def dag_arg(w:mutbuf, index:u64) -> u64:
    if index >= get(w, 1500064):
        return 18446744073709551615
    return get(w, get(w, 1500096) + index * 8)

def dag_handle(w:mutbuf, id:u64) -> u64:
    if id == 0 or id > 2048:
        return 0
    at = 1048576 + id * 64
    return choose(get(w, at) >= 3, at, 0)

def dag_commit(o:mutbuf, w:mutbuf, own:u64) -> u32:
    id = get(w, 1500056)
    if id != 0:
        row = 1048576 + id * 64
        if get(w, 144) < 3 or get(w, 152) > 67108864:
            return finish(o, w, 65)
        put(w, row, get(w, 144))
        put(w, row + 8, get(w, 1500136))
        put(w, row + 16, get(w, 152))
        put(w, row + 24, get(w, 1500144))
        put(w, row + 32, get(w, 1500152))
        put(w, row + 40, get(w, 1500160))
        put(w, row + 48, get(w, 1500168))
        put(w, row + 56, own)
    put(w, 1500032, get(w, 1500088))
    put(w, 1500040, get(w, 1500040) + 1)
    put(w, 0, 5003)
    put(w, 8, 0)
    return 4

def dag_execute(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 1500048)
    if op == 1:
        if get(w, 1500064) != 1:
            return finish(o, w, 65)
        put(w, 1500144, 1)
        put(w, 1500152, get(w, 1500072))
        put(w, 1500160, 0)
        put(w, 1500168, dag_arg(w, 0))
        return capture_request(o, w, dag_capture(s, w), 5004)
    if op == 2 or op == 3:
        row = dag_handle(w, dag_arg(w, 0))
        if get(w, 1500064) != 1 or get(w, 1500080) != 0 or row == 0 or get(w, row + 24) != 1:
            return finish(o, w, 65)
        put(w, 1500144, op)
        put(w, 1500152, get(w, row + 32))
        put(w, 1500160, dag_arg(w, 0))
        put(w, 1500176, choose(op == 2, get(w, 216), get(w, 120)))
        put(w, 1500184, choose(op == 2, 1, 3))
        return extract_view(o, w, get(w, row), get(w, row + 8), get(w, row + 16), 5400)
    if op == 4:
        return dag_pick(s, o, w, 5300, 0)
    if op == 5 or op == 10:
        if dag_frame(w) == 0:
            return finish(o, w, 65)
        return framed(o, w, 6144, choose(op == 5, 48, 40), 330000, get(w, 1500120), 5410)
    if op == 6 or op == 14:
        return dag_run(s, o, w, 5420, 0)
    if op == 7 or op == 8 or op == 9 or op == 13:
        return dag_check(s, o, w, 5500, 0)
    if op == 11:
        if get(w, 1500064) != 0 or dag_import(s, w) == 0:
            return finish(o, w, 65)
        return dag_commit(o, w, 0)
    if op == 12:
        if get(w, 1500064) != 0:
            return finish(o, w, 65)
        return seal_buffer(o, w, get(w, 1500072), get(w, 1500080), 5004)
    if op == 16:
        count = get(w, 1500064)
        if count > 128 or get(w, 1500080) != 0:
            return finish(o, w, 65)
        i = 0
        while i < count:
            row = dag_handle(w, dag_arg(w, i))
            if row == 0:
                return finish(o, w, 65)
            view(w, i, get(w, row), get(w, row + 8), get(w, row + 16))
            i = i + 1
        return frame(o, w, 6144, 0, 330000, count, 5004)
    if op == 17:
        row = dag_handle(w, dag_arg(w, 0))
        if get(w, 1500064) != 1 or get(w, 1500080) != 0 or row == 0:
            return finish(o, w, 65)
        put(w, 6144, get(w, row + 16))
        return seal_buffer(o, w, 6144, 8, 5004)
    if op == 18:
        return dag_codec(s, o, w, 5600, 0)
    if op == 19:
        count = get(w, 1500064)
        if count == 0 or count > 128 or get(w, 1500080) != 0:
            return finish(o, w, 65)
        i = 0
        offset = count * 8
        while i < count:
            row = dag_handle(w, dag_arg(w, i))
            if row == 0 or get(w, row + 16) > 67108864 - offset:
                return finish(o, w, 65)
            put(w, 6144 + i * 8, offset)
            offset = offset + get(w, row + 16)
            view(w, i, get(w, row), get(w, row + 8), get(w, row + 16))
            i = i + 1
        return frame(o, w, 6144, count * 8, 330000, count, 5004)
    if op == 15:
        row = dag_handle(w, dag_arg(w, 0))
        offset = dag_arg(w, 1)
        size = dag_arg(w, 2)
        if get(w, 1500064) != 3 or get(w, 1500080) != 0 or row == 0 or offset > get(w, row + 16):
            return finish(o, w, 65)
        size = choose(size == 18446744073709551615, get(w, row + 16) - offset, size)
        if size > get(w, row + 16) - offset:
            return finish(o, w, 65)
        put(w, 144, get(w, row))
        put(w, 152, size)
        put(w, 1500136, get(w, row + 8) + offset)
        return dag_commit(o, w, 0)
    return finish(o, w, 65)

def dag_capture(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 1500072)
    end = at + get(w, 1500080)
    if end - at < 8 or get(w, at) == 0 or get(w, at) > 128:
        return 0
    count = get(w, at)
    wire = capture_begin(s, w, dag_arg(w, 0), count)
    at = at + 8
    i = 0
    while i < count:
        if at > end or end - at < 16:
            return 0
        an = get(w, at)
        pn = get(w, at + 8)
        if an == 0 or an > 127 or pn == 0 or pn > 4095 or an + pn > end - at - 16:
            return 0
        wire = capture_row(s, w, wire, at + 16 + an, pn, at + 16, an)
        if wire == 0:
            return 0
        at = at + 16 + an + pn
        i = i + 1
    return choose(at == end, wire - 393216, 0)

def dag_frame(w:mutbuf) -> u64:
    op = get(w, 1500048)
    skip = choose(op == 5, 4, 2)
    count = get(w, 1500064)
    if count < skip or count > skip + 128 or get(w, 1500080) != 0:
        return 0
    put(w, 6144, choose(op == 5, MAGIC_STAGE_FRAME, MAGIC_STAGE_CHECK))
    put(w, 6152, dag_arg(w, 0))
    put(w, 6160, dag_arg(w, 1))
    if op == 5:
        put(w, 6168, dag_arg(w, 2))
        put(w, 6176, dag_arg(w, 3))
        put(w, 6184, count - 4)
    else:
        put(w, 6168, count - 2)
        put(w, 6176, 0)
    i = skip
    while i < count:
        row = dag_handle(w, dag_arg(w, i))
        if row == 0:
            return 0
        view(w, i - skip, get(w, row), get(w, row + 8), get(w, row + 16))
        i = i + 1
    put(w, 1500120, count - skip)
    return 1

def dag_import(s:readbuf, w:mutbuf) -> u64:
    name = get(w, 1500072)
    size = get(w, 1500080)
    if size == L_COMPILER_NAME and same(w, name, C_COMPILER_NAME, size) == 1:
        put(w, 144, uint(s, 72))
        put(w, 152, get(w, 3024))
        return 1
    if size == L_SEED_NAME and same(w, name, C_SEED_NAME, size) == 1:
        put(w, 144, get(w, 216))
        put(w, 152, get(w, 3008))
        return 1
    row = find_product(w, name, size)
    if row != 0:
        put(w, 144, get(w, row))
        put(w, 152, get(w, row + 8))
        return 1
    i = 0
    while i < get(w, 1599904):
        row = 1600000 + i * 160
        if get(w, row + 16) == size and same(w, row + 32, name, size) == 1:
            put(w, 144, get(w, row))
            put(w, 152, get(w, row + 8))
            return 1
        i = i + 1
    return 0

def dag_run(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 5400:
        return launch(o, w, get(w, 1500176), get(w, 144), get(w, 1500184), 0, choose(get(w, 1500048) == 3, 5200, 5004))
    if phase == 5410:
        return launch(o, w, get(w, 321000), get(w, 144), 3, 0, choose(get(w, 1500048) == 10, 5411, 5004))
    if phase == 5411:
        if get(w, 152) != 32:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 49152, 32, 0, 5412)
    if phase == 5412:
        if get(w, 49152) != MAGIC_STAGE_OK or get(w, 49160) != dag_arg(w, 0) or get(w, 49168) != dag_arg(w, 1):
            return finish(o, w, 65)
        row = dag_handle(w, dag_arg(w, 2))
        if row == 0 or get(w, 49176) != get(w, row + 16):
            return finish(o, w, 65)
        return call(o, w, 5005, 3, get(w, 144), 0, 0, 0, 0, 0, 0)
    if phase == 5420:
        expected = choose(get(w, 1500048) == 6, 3, 2)
        row = dag_handle(w, dag_arg(w, 0))
        if get(w, 1500064) != expected or get(w, 1500080) != 0 or row == 0:
            return finish(o, w, 65)
        size = get(w, row + 16)
        if get(w, row + 24) == 3:
            size = get(w, row + 48)
        if size < 176:
            return finish(o, w, 65)
        return extract_view(o, w, get(w, row), get(w, row + 8), size, 5421)
    if phase == 5421:
        put(w, 1500176, get(w, 144))
        operation = dag_arg(w, 1)
        if get(w, 1500048) == 14:
            if operation < 1 or operation > 9:
                return finish(o, w, 65)
            put(w, 1500184, operation + 16)
            return seal_buffer(o, w, 6144, 0, 5422)
        row = dag_handle(w, dag_arg(w, 2))
        if operation > 4 or row == 0:
            return finish(o, w, 65)
        put(w, 1500184, operation)
        return extract_view(o, w, get(w, row), get(w, row + 8), get(w, row + 16), 5422)
    if phase == 5422:
        return launch(o, w, get(w, 1500176), get(w, 144), get(w, 1500184), 0, 5423)
    if phase == 5423:
        return call(o, w, 5004, 3, get(w, 1500176), 0, 0, 0, 0, 0, 0)
    return finish(o, w, 65)

def dag_kit(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 5200:
        if get(w, 152) < 240:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 1501000, 64, get(w, 152) - 64, 5201)
    if phase == 5201:
        size = get(w, 1501000)
        total = get(w, 1501008) + get(w, 1501016) + get(w, 1501024)
        if get(w, 1501056) != MAGIC_KIT_IMAGES or size != get(w, 152) - 64 or total > size or size - total < 176:
            return finish(o, w, 65)
        put(w, 1500168, size)
        put(w, 1500192, size - total)
        put(w, 1500200, 0)
        return resume(s, o, w, 5202)
    if phase == 5202:
        index = get(w, 1500200)
        if index == 3:
            return dag_commit(o, w, 1)
        size = get(w, 1501008 + index * 8)
        site = get(w, 1501032 + index * 8)
        if size == 0 or size > 1048576 or site <= 176 or site + 4 > get(w, 1500192):
            return finish(o, w, 65)
        j = 0
        while j < index:
            if site == get(w, 1501032 + j * 8):
                return finish(o, w, 65)
            j = j + 1
        return reading(o, w, get(w, 144), 1501072, 5, site - 1, 5203)
    if phase == 5203:
        index = get(w, 1500200)
        target = get(w, 1500192)
        j = 0
        while j < index:
            target = target + get(w, 1501008 + j * 8)
            j = j + 1
        delta = getn(w, 1501073, 4)
        if delta & 2147483648 != 0:
            delta = delta + 18446744069414584320
        if byte(w, 1501072) != 232 or get(w, 1501032 + index * 8) + 4 + delta != target:
            return finish(o, w, 65)
        put(w, 1500200, index + 1)
        return resume(s, o, w, 5202)
    return finish(o, w, 65)

def dag_pick(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 5300:
        row = dag_handle(w, dag_arg(w, 0))
        if get(w, 1500064) != 3 or get(w, 1500080) != 0 or row == 0 or dag_arg(w, 2) > 1 or get(w, row + 24) == 0:
            return finish(o, w, 65)
        if get(w, row + 24) == 4:
            if dag_arg(w, 1) > 1 or dag_arg(w, 2) != 0:
                return finish(o, w, 65)
            put(w, 144, get(w, row))
            put(w, 152, choose(dag_arg(w, 1) == 0, get(w, row + 32), get(w, row + 40)))
            put(w, 1500136, 24 + choose(dag_arg(w, 1) == 0, 0, get(w, row + 32)))
            return dag_commit(o, w, 0)
        if dag_pick_name(w, row) == 0:
            return finish(o, w, 65)
        if get(w, row + 24) == 1 and get(w, row + 48) == MAGIC_RAW:
            if dag_arg(w, 1) != 0 or dag_arg(w, 2) != 0:
                return finish(o, w, 65)
            put(w, 144, get(w, row))
            put(w, 152, get(w, row + 16))
            put(w, 1500136, get(w, row + 8))
            return dag_commit(o, w, 0)
        if get(w, row + 24) == 3 and dag_arg(w, 2) == 1:
            put(w, 1500216, row)
            return reading(o, w, get(w, row), 1501000, 64, get(w, row + 16) - 64, 5310)
        if get(w, row + 24) == 3:
            row = dag_handle(w, get(w, row + 40))
        if row == 0 or (get(w, row + 24) == 1 and dag_arg(w, 2) != 0):
            return finish(o, w, 65)
        put(w, 1500216, row)
        put(w, 1500224, 0)
        put(w, 1500232, 0)
        return reading(o, w, get(w, row), 1501104, 24, get(w, row + 8), 5301)
    if phase == 5301:
        row = get(w, 1500216)
        if get(w, row + 24) == 2:
            if get(w, 1501104) != MAGIC_PACKAGE or get(w, 1501112) != 2 * get(w, get(w, row + 32)) or get(w, 1501120) != 0:
                return finish(o, w, 65)
            put(w, 1500224, 24)
        else:
            if get(w, 1501112) != get(w, get(w, row + 32)):
                return finish(o, w, 65)
            put(w, 1500224, 16)
        put(w, 1500240, get(w, 1501112))
        return resume(s, o, w, 5302)
    if phase == 5302:
        row = get(w, 1500216)
        if get(w, 1500232) == get(w, 1500240):
            return finish(o, w, 65)
        if get(w, 1500224) > get(w, row + 16) or get(w, row + 16) - get(w, 1500224) < 24:
            return finish(o, w, 65)
        return reading(o, w, get(w, row), 1501104, 24, get(w, row + 8) + get(w, 1500224), 5303)
    if phase == 5303:
        row = get(w, 1500216)
        header = choose(get(w, row + 24) == 2, 24, 16)
        size = get(w, 1501104 + header - 8)
        name = get(w, 1501104)
        if name == 0 or name > 127 or size == 0 or size > 1048576 or header + name + size > get(w, row + 16) - get(w, 1500224):
            return finish(o, w, 65)
        if header == 24 and get(w, 1501112) != 256:
            return finish(o, w, 65)
        put(w, 1500248, header)
        put(w, 1500256, size)
        put(w, 1500264, name)
        return reading(o, w, get(w, row), 1501200, name, get(w, row + 8) + get(w, 1500224) + header, 5304)
    if phase == 5304:
        row = get(w, 1500216)
        if get(w, 1500264) == get(w, 1500208) and same(w, 1501200, 1501400, get(w, 1500264)) == 1:
            put(w, 144, get(w, row))
            put(w, 152, get(w, 1500256))
            put(w, 1500136, get(w, row + 8) + get(w, 1500224) + get(w, 1500248) + get(w, 1500264))
            return dag_commit(o, w, 0)
        put(w, 1500224, get(w, 1500224) + get(w, 1500248) + get(w, 1500264) + get(w, 1500256))
        put(w, 1500232, get(w, 1500232) + 1)
        return resume(s, o, w, 5302)
    if phase == 5310:
        row = get(w, 1500216)
        index = dag_arg(w, 1)
        if index > 2 or get(w, 1501056) != MAGIC_KIT_IMAGES or get(w, 1501000) != get(w, row + 48):
            return finish(o, w, 65)
        offset = get(w, 1501000) - get(w, 1501008) - get(w, 1501016) - get(w, 1501024)
        j = 0
        while j < index:
            offset = offset + get(w, 1501008 + j * 8)
            j = j + 1
        put(w, 144, get(w, row))
        put(w, 152, get(w, 1501008 + index * 8))
        put(w, 1500136, offset)
        return dag_commit(o, w, 0)
    return finish(o, w, 65)

def dag_pick_name(w:mutbuf, row:u64) -> u64:
    at = get(w, row + 32)
    ordinal = dag_arg(w, 1)
    if at < 2097152 or at >= 3145728 or ordinal >= get(w, at):
        return 0
    at = at + 8
    i = 0
    while i < ordinal:
        at = at + 16 + get(w, at) + get(w, at + 8)
        i = i + 1
    size = get(w, at)
    copyw(w, 1501400, at + 16, size)
    if get(w, row + 24) == 2 and dag_arg(w, 2) == 1:
        put(w, 1501400 + size, 1852400174)
        size = size + 4
    put(w, 1500208, size)
    return 1

def dag_check(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 5500:
        op = get(w, 1500048)
        row = dag_handle(w, dag_arg(w, 0))
        count = choose(op == 7 or op == 8, 2, 1)
        if row == 0 or get(w, 1500064) != count:
            return finish(o, w, 65)
        put(w, 1500272, row)
        if op == 8:
            second = dag_handle(w, dag_arg(w, 1))
            if second == 0 or get(w, second + 16) != get(w, row + 16) or get(w, 1500080) != 0:
                return finish(o, w, 65)
            put(w, 1500280, second)
            put(w, 1500288, 0)
            return resume(s, o, w, 5510)
        if op == 9 and get(w, 1500080) != 32:
            return finish(o, w, 65)
        if op == 13 and get(w, 1500080) != 0:
            return finish(o, w, 65)
        if op == 7 and dag_arg(w, 1) == 0:
            return resume(s, o, w, 5520)
        return hash_view(o, w, get(w, row), get(w, row + 8), get(w, row + 16), 5501)
    if phase == 5501:
        op = get(w, 1500048)
        if op == 13:
            return seal_buffer(o, w, 4096, 32, 5004)
        if op == 9:
            if same(w, 4096, get(w, 1500072), 32) == 0:
                return finish(o, w, 65)
            return dag_commit(o, w, 0)
        row = dag_handle(w, dag_arg(w, 1))
        if row == 0 or get(w, row + 16) != 32:
            return finish(o, w, 65)
        return reading(o, w, get(w, row), 1501600, 32, get(w, row + 8), 5502)
    if phase == 5502:
        if same(w, 4096, 1501600, 32) == 0:
            return finish(o, w, 65)
        return resume(s, o, w, 5520)
    if phase == 5510:
        row = get(w, 1500272)
        if get(w, 1500288) == get(w, row + 16):
            return dag_commit(o, w, 0)
        put(w, 1500296, minimum(65536, get(w, row + 16) - get(w, 1500288)))
        return reading(o, w, get(w, row), 700000, get(w, 1500296), get(w, row + 8) + get(w, 1500288), 5511)
    if phase == 5511:
        row = get(w, 1500280)
        return reading(o, w, get(w, row), 800000, get(w, 1500296), get(w, row + 8) + get(w, 1500288), 5512)
    if phase == 5512:
        if same(w, 700000, 800000, get(w, 1500296)) == 0:
            return finish(o, w, 65)
        put(w, 1500288, get(w, 1500288) + get(w, 1500296))
        return resume(s, o, w, 5510)
    if phase == 5520:
        row = get(w, 1500272)
        if dag_publication(w) == 0:
            return finish(o, w, 65)
        return extract_view(o, w, get(w, row), get(w, row + 8), get(w, row + 16), 5521)
    if phase == 5521:
        if get(w, 152) < 4:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 49152, 4, 0, 5522)
    if phase == 5522:
        row = 1600000 + get(w, 1599904) * 160
        put(w, row, get(w, 144))
        put(w, row + 8, get(w, 152))
        return publish(o, w, get(w, 144), get(w, 152), row + 32, get(w, row + 16), choose(getn(w, 49152, 4) == 1179403647, 320, 256), 5523)
    if phase == 5523:
        put(w, 1599904, get(w, 1599904) + 1)
        return dag_commit(o, w, 0)
    return finish(o, w, 65)

def dag_publication(w:mutbuf) -> u64:
    name = get(w, 1500072)
    size = get(w, 1500080)
    if size == 0 or size > 127 or get(w, 1599904) >= 512 or find_product(w, name, size) != 0:
        return 0
    if size == 1 and byte(w, name) == 46:
        return 0
    if size == 2 and byte(w, name) == 46 and byte(w, name + 1) == 46:
        return 0
    i = 0
    while i < size:
        if plain(byte(w, name + i)) == 0:
            return 0
        i = i + 1
    i = 0
    while i < get(w, 1599904):
        row = 1600000 + i * 160
        if get(w, row + 16) == size and same(w, row + 32, name, size) == 1:
            return 0
        i = i + 1
    row = 1600000 + get(w, 1599904) * 160
    put(w, row + 16, size)
    copyw(w, row + 32, name, size)
    return 1

def dag_codec(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 5660:
        return dag_codec_output(s, o, w, phase, r)
    if phase == 5600:
        if dag_codec_arguments(w) == 0:
            return finish(o, w, 65)
        row = dag_handle(w, dag_arg(w, 2))
        return extract_view(o, w, get(w, row), get(w, row + 8), get(w, row + 16), 5601)
    if phase == 5601:
        put(w, 1560016, get(w, 144))
        row = dag_handle(w, dag_arg(w, 3))
        return extract_view(o, w, get(w, row), get(w, row + 8), get(w, row + 48), 5602)
    if phase == 5602:
        put(w, 1560024, get(w, 144))
        if get(w, 1560000) == 0:
            return resume(s, o, w, 5620)
        return call(o, w, 5603, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 5603:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1560128, r)
        row = get(w, 1560008)
        put(w, 6144, get(w, row + 16))
        return writing(o, w, r, 6144, 8, 5604)
    if phase == 5604:
        return call(o, w, 5605, 8, get(w, 1560128), 8, 0, 0, 0, 0, 0)
    if phase == 5605:
        if r != 8:
            return finish(o, w, 74)
        row = get(w, 1560008)
        return copying(o, w, get(w, row), get(w, 1560128), get(w, row + 8), get(w, row + 16), 5606)
    if phase == 5606:
        put(w, 1560136, 8 + get(w, get(w, 1560008) + 16))
        return call(o, w, 5607, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 5607:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1560144, r)
        put(w, 1560152, 16)
        put(w, 6144, MAGIC_EXEC_ARCHIVE)
        put(w, 6152, get(w, get(w, 1560008) + 16))
        return writing(o, w, r, 6144, 16, 5620)
    if phase == 5620:
        row = get(w, 1560008)
        if get(w, 1560056) == get(w, row + 16):
            return resume(s, o, w, 5680)
        size = get(w, row + 16) - get(w, 1560056)
        put(w, 1560064, choose(get(w, 1560000) == 0, size, minimum(524288, size)))
        if get(w, 1560072) >= 3 and get(w, 1560080) == get(w, 1560064):
            return resume(s, o, w, 5630)
        if get(w, 1560072) >= 3:
            return call(o, w, 5621, 3, get(w, 1560072), 0, 0, 0, 0, 0, 0)
        return resume(s, o, w, 5621)
    if phase == 5621:
        put(w, 1560072, 0)
        put(w, 6144, MAGIC_CODEC)
        put(w, 6152, 2)
        put(w, 6160, get(w, 1560064))
        first = get(w, 1560032)
        second = get(w, 1560040)
        put(w, 6168, get(w, first + 16))
        put(w, 6176, get(w, second + 16))
        view(w, 0, get(w, first), get(w, first + 8), get(w, first + 16))
        view(w, 1, get(w, second), get(w, second + 8), get(w, second + 16))
        return frame(o, w, 6144, 40, 330000, 2, 5622)
    if phase == 5622:
        return launch(o, w, get(w, 1560024), get(w, 144), 3, 0, 5623)
    if phase == 5623:
        if get(w, 152) < 176:
            return finish(o, w, 65)
        put(w, 1560072, get(w, 144))
        put(w, 1560080, get(w, 1560064))
        return call(o, w, 5630, 91, get(w, 144), 320, 0, 0, 0, 0, 0)
    if phase == 5630:
        row = get(w, 1560008)
        return extract_view(o, w, get(w, row), get(w, row + 8) + get(w, 1560056), get(w, 1560064), 5631)
    if phase == 5631:
        return launch(o, w, get(w, 1560016), get(w, 144), 0, 0, 5632)
    if phase == 5632:
        if get(w, 152) == 0 or get(w, 152) > get(w, 1560048):
            return finish(o, w, 65)
        put(w, 1560088, get(w, 144))
        put(w, 1560096, get(w, 152))
        return extract_view(o, w, get(w, 144), 0, get(w, 152), 5633)
    if phase == 5633:
        return launch(o, w, get(w, 1560072), get(w, 144), 0, 0, 5634)
    if phase == 5634:
        if get(w, 152) != get(w, 1560064):
            return finish(o, w, 65)
        put(w, 1560104, get(w, 144))
        put(w, 1560112, 0)
        return resume(s, o, w, 5640)
    if phase == 5640:
        if get(w, 1560112) == get(w, 1560064):
            return call(o, w, 5660, 3, get(w, 1560104), 0, 0, 0, 0, 0, 0)
        size = minimum(65536, get(w, 1560064) - get(w, 1560112))
        put(w, 1560120, size)
        row = get(w, 1560008)
        return reading(o, w, get(w, row), 700000, size, get(w, row + 8) + get(w, 1560056) + get(w, 1560112), 5641)
    if phase == 5641:
        return reading(o, w, get(w, 1560104), 800000, get(w, 1560120), get(w, 1560112), 5642)
    if phase == 5642:
        if same(w, 700000, 800000, get(w, 1560120)) == 0:
            return finish(o, w, 65)
        put(w, 1560112, get(w, 1560112) + get(w, 1560120))
        return resume(s, o, w, 5640)
    return finish(o, w, 65)

def dag_codec_arguments(w:mutbuf) -> u64:
    if get(w, 1500064) != 7 or get(w, 1500080) != 0 or dag_arg(w, 0) > 1:
        return 0
    raw = dag_handle(w, dag_arg(w, 1))
    encoder = dag_handle(w, dag_arg(w, 2))
    builder = dag_handle(w, dag_arg(w, 3))
    source = dag_handle(w, dag_arg(w, 4))
    image = dag_handle(w, dag_arg(w, 5))
    if raw == 0 or encoder == 0 or builder == 0 or source == 0 or image == 0:
        return 0
    if get(w, raw + 16) == 0 or get(w, raw + 16) > 8388608 or get(w, encoder + 16) < 176 or get(w, builder + 24) != 3:
        return 0
    if get(w, source + 16) == 0 or get(w, source + 16) > 1048576 or get(w, image + 16) == 0 or get(w, image + 16) > 1048576:
        return 0
    if dag_arg(w, 6) == 0 or dag_arg(w, 6) > 1048576:
        return 0
    if dag_arg(w, 0) == 1 and (get(w, raw + 16) < 176 or dag_arg(w, 6) != 1048576):
        return 0
    put(w, 1560000, dag_arg(w, 0))
    put(w, 1560008, raw)
    put(w, 1560032, source)
    put(w, 1560040, image)
    put(w, 1560048, dag_arg(w, 6))
    put(w, 1560056, 0)
    put(w, 1560072, 0)
    put(w, 1560080, 0)
    put(w, 1560128, 0)
    put(w, 1560144, 0)
    return 1

def dag_codec_output(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 5660:
        if get(w, 1560000) == 0:
            put(w, 1560160, get(w, 1560088))
            put(w, 1560168, get(w, 1560096))
            put(w, 1560176, 0)
            return resume(s, o, w, 5690)
        size = get(w, 1560096)
        if get(w, 1560136) > 67108856 - size or get(w, 1560152) > 67108848 - size:
            return finish(o, w, 65)
        put(w, 6144, size)
        return writing_at(o, w, get(w, 1560128), 6144, 8, get(w, 1560136), 5661)
    if phase == 5661:
        return call(o, w, 5662, 8, get(w, 1560128), get(w, 1560136) + 8, 0, 0, 0, 0, 0)
    if phase == 5662:
        if r != get(w, 1560136) + 8:
            return finish(o, w, 74)
        return copying(o, w, get(w, 1560088), get(w, 1560128), 0, get(w, 1560096), 5663)
    if phase == 5663:
        put(w, 1560136, get(w, 1560136) + 8 + get(w, 1560096))
        put(w, 6144, get(w, 1560096))
        put(w, 6152, get(w, 1560064))
        return writing_at(o, w, get(w, 1560144), 6144, 16, get(w, 1560152), 5664)
    if phase == 5664:
        return call(o, w, 5665, 8, get(w, 1560144), get(w, 1560152) + 16, 0, 0, 0, 0, 0)
    if phase == 5665:
        if r != get(w, 1560152) + 16:
            return finish(o, w, 74)
        return copying(o, w, get(w, 1560088), get(w, 1560144), 0, get(w, 1560096), 5666)
    if phase == 5666:
        put(w, 1560152, get(w, 1560152) + 16 + get(w, 1560096))
        put(w, 1560056, get(w, 1560056) + get(w, 1560064))
        return call(o, w, 5620, 3, get(w, 1560088), 0, 0, 0, 0, 0, 0)
    if phase == 5680:
        put(w, 6144, MAGIC_CODEC_BUNDLE)
        put(w, 6152, get(w, 1560136))
        put(w, 6160, get(w, 1560152))
        view(w, 0, get(w, 1560128), 0, get(w, 1560136))
        view(w, 1, get(w, 1560144), 0, get(w, 1560152))
        return frame(o, w, 6144, 24, 330000, 2, 5681)
    if phase == 5681:
        put(w, 1560160, get(w, 144))
        put(w, 1560168, get(w, 152))
        put(w, 1500144, 4)
        put(w, 1500152, get(w, 1560136))
        put(w, 1500160, get(w, 1560152))
        return call(o, w, 5682, 3, get(w, 1560128), 0, 0, 0, 0, 0, 0)
    if phase == 5682:
        put(w, 1560176, 0)
        return call(o, w, 5690, 3, get(w, 1560144), 0, 0, 0, 0, 0, 0)
    if phase == 5690:
        index = get(w, 1560176)
        if index == 3:
            put(w, 144, get(w, 1560160))
            put(w, 152, get(w, 1560168))
            return dag_commit(o, w, 1)
        put(w, 1560176, index + 1)
        fd = get(w, 1560016)
        if index == 1:
            fd = get(w, 1560024)
        if index == 2:
            fd = get(w, 1560072)
        return call(o, w, 5690, 3, fd, 0, 0, 0, 0, 0, 0)
    return finish(o, w, 65)
'''

TEXT = {
    'EMPTY': b'', 'DOT': b'.', 'MEMFD': b'hia-release-owner', 'RUNNER': b'hia-subprocess',
    'CHILD': b'hia-release-child', 'ENV': b'PATH=', 'SOURCES': b'sources', 'PACK': b'pack',
    'BUILD': b'build', 'COMPILE': b'compile', 'PROC': b'/proc/self/fd/',
    'CORE_PREFIX': b'examples/hia_bootstrap/', 'POLICY_ROLE': b'source_build_policy.hepta',
    'PACKER_ROLE': b'source_build_packer.hepta', 'SELFHOST': b'selfhost.hepta',
    'COMPOSER_POLICY': b'source_release_kit.hepta', 'PLAN_POLICY': b'source_release_member_plan.hepta',
    'FILTER_POLICY': b'source_filter_member.hepta', 'STAGE_POLICY': b'source_release_stage_plan.hepta',
    'RECIPE_PATH': b'examples/hia_bootstrap/release_member_sources.tsv', 'DATA_ALIAS': b'data',
    'SEED_NAME': b'hia-source-build', 'DIRECTORY_NAME': b'hia-directory-package-build',
    'PORT_NAME': b'hia-worker-port', 'CORE_NAME': b'hia-core-json',
    'ARTIFACT_NAME': b'hia-artifact', 'COMPILER_NAME': b'selfhost.image.bin',
    'SCHEMA_FLAG': b'--schema', 'SCHEMA_NAME': b'hepta.hia.program.v1',
    'FINALIZE_NAME': b'hia-release-finalize', 'INSTALLER_NAME': b'hia-release',
    'COLD_POLICY': b'source_release_cold_admit.hepta', 'COLD_NAME': b'hia-release-cold-admit', 'AUDIT_ALIAS': b'source-',
    'OWNER_NAME': b'hia-release-owner', 'CAPTURE_NAME': b'hia-source-capture',
    'ENTRY_NAME': b'hia-release-build', 'ENTRY_ALIAS': b'hia-release-build.hepta',
    'ENTRY_POLICY': b'release_build_entry.hepta', 'ENTRY_PACKER': b'release_build_entry_packer.hepta',
    'ENTRY_BINDER': b'release_build_entry_bind.hepta', 'SHA_SOURCE': b'sha256_stream.hepta',
    'WORKER_OWNER_NAME': b'hia-worker-install-owner',
    'WORKER_ENTRY_NAME': b'hia-worker-install', 'WORKER_ENTRY_ALIAS': b'hia-worker-install.hepta',
    'WORKER_ENTRY_POLICY': b'worker_install_entry.hepta', 'WORKER_ENTRY_PACKER': b'worker_install_entry_packer.hepta',
    'WORKER_ENTRY_BINDER': b'worker_install_entry_bind.hepta',
    'CONTRACT_PATH': b'docs/HIA_SELFHOST_CORE_SUPPORT.json',
    'MANIFEST_POLICY': b'source_compiler_manifest.hepta', 'CORE_PACKER': b'core_json_cli_packer.hepta',
    'MANIFEST_NAME': b'compiler-manifest.json', 'ZERO_ENTRIES': bytes(128 * 8),
}
MAGICS = {
    'OWNER': b'HIAOWN01', 'PINS': b'HIASPI01', 'SUB': b'HIASUB01', 'SUBRECEIPT': b'HIASBR01',
    'PASS': b'HIAPFD01', 'CAPTURE': b'HIACAP02', 'NAMED': b'HIANAM01', 'KIT': b'HIAKIT01',
    'RAW': b'HIARAW01', 'IMAGE': b'HIAIMG01', 'MULTI': b'HIAMUL01', 'RECIPES': b'HIARLST1',
    'REUSE': b'HIARUSE1', 'PORT': b'HIAWPRT1', 'OBJECT': b'HIAOBJ01', 'OBJECTS': b'HIAOBJS1',
    'INVENTORY': b'HIAINV01', 'COMPILER_MANIFEST': b'HIACMF01',
    'STAGE_CHECK': b'HIASTC01', 'STAGE_OK': b'HIASTOK1',
    'ARTIFACT_DESCRIPTOR': b'HIADCTL1', 'DAG': b'HIASTD01', 'STAGE_FRAME': b'HIASTF01',
    'KIT_IMAGES': b'HIAKIMG1', 'PACKAGE': b'HIAREL01',
    'FINALIZE': b'HIAFIN01',
    'CODEC': b'HIACCO01', 'CODEC_BUNDLE': b'HIAECB01', 'EXEC_ARCHIVE': b'HIAECP01',
    'ENTRY_BIND': b'HIAENBD1',
    'AUDIT': b'HIAAUD01', 'AUDIT_OK': b'HIAAOK01', 'COLD': b'HIACLD01', 'COLD_OK': b'HIAADC01',
}
RESOURCES = (
    'examples/hia_bootstrap/selfhost.hepta', 'examples/hia_bootstrap/source_build_packer.hepta',
    'examples/hia_bootstrap/source_filter_member.hepta', 'examples/hia_bootstrap/source_build_policy.hepta',
    'examples/hia_bootstrap/core_json_cli_packer.hepta', 'examples/hia_bootstrap/core_json_frontend.hepta',
    'docs/HIA_SELFHOST_CORE_SUPPORT.json', 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json',
)


def dag_source():
    base = ast.parse(POLICY)
    available = {node.name: node for node in base.body if isinstance(node, ast.FunctionDef)}
    needed = set()
    todo = [DAG_POLICY]
    while todo:
        source = todo.pop()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in available and name not in needed:
                    needed.add(name)
                    todo.append(ast.get_source_segment(POLICY, available[name]))
    entry = '''def stage(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    return dag(s, o, w, get(w, 0), get(w, 8))
'''
    return entry + '\n' + DAG_POLICY + '\n' + '\n\n'.join(
        ast.get_source_segment(POLICY, node) for node in base.body
        if isinstance(node, ast.FunctionDef) and node.name in needed)


RELEASE_DAGS = ('safe', 'constructor', 'core', 'additional', 'controller')


def policy_source(*, stage=False):
    words, constants = {}, []
    cursor = 600000

    def data(key, raw):
        nonlocal cursor
        start = cursor
        words['C_' + key] = start
        words['L_' + key] = len(raw)
        for offset in range(0, len(raw) + 1, 8):
            chunk = (raw + b'\0')[offset:offset + 8].ljust(8, b'\0')
            constants.append(f'    put(w, {start + offset}, {int.from_bytes(chunk, "little")})')
        cursor = (cursor + len(raw) + 16) & ~7
        return start

    def word(at, value):
        constants.append(f'    put(w, {at}, {value})')

    for name, raw in TEXT.items():
        data(name, raw)
    resource_rows = []
    for index, resource in enumerate(RESOURCES):
        path, name = resource.encode(), Path(resource).name.encode()
        resource_rows.append((data(f'RESOURCE_PATH_{index}', path), len(path),
                              data(f'RESOURCE_NAME_{index}', name), len(name)))
    dag_rows = []
    for index, kind in enumerate(RELEASE_DAGS):
        path = ('examples/hia_bootstrap/release_stage_' + kind + '.hiastd').encode()
        dag_rows.append((data(f'DAG_PATH_{index}', path), len(path)))
    words['N_DAGS'] = len(RELEASE_DAGS)
    words['C_DAG_PATHS'] = cursor
    for row in dag_rows:
        for value in row:
            word(cursor, value)
            cursor += 8
    words['C_RESOURCE_TABLE'] = cursor
    for row in resource_rows:
        for value in row:
            word(cursor, value)
            cursor += 8
    bindings = {'hia-' + role: (info[2], 1, 2) for role, info in ROLES.items()}
    bindings['hia-reference-wire'] = (REFERENCE_CLI_ADAPTER, 1, 2)
    for name, _, _, adapter, calls in VARIANTS.values():
        bindings[name] = (adapter, len(calls), 3)
    rows = []
    for index, (name, (path, calls, mode)) in enumerate(sorted(bindings.items())):
        encoded, source = name.encode(), str(path).encode()
        instructions = (struct.pack('<Q', 1) + b'\xe8') * calls
        rows.append((data(f'BINDING_NAME_{index}', encoded), len(encoded),
                     data(f'BINDING_PATH_{index}', source), len(source), calls, mode,
                     data(f'BINDING_INSTRUCTIONS_{index}', instructions), len(instructions)))
    words['C_BINDINGS_TABLE'] = cursor
    words['N_BINDINGS'] = len(rows)
    for row in rows:
        for value in row:
            word(cursor, value)
            cursor += 8
    if cursor >= 700000:
        raise ValueError('release-owner constants overlap the exact-byte comparison scratch')
    words.update({'MAGIC_' + key: int.from_bytes(raw, 'little') for key, raw in MAGICS.items()})
    program = dag_source() if stage else POLICY
    for key, value in words.items():
        program = re.sub(r'\b' + key + r'\b', str(value), program)
    unresolved = re.findall(r'\b(?:C|L|N|MAGIC)_[A-Z_]+\b', program)
    if unresolved:
        raise ValueError('unresolved HIA owner constants: ' + repr(sorted(set(unresolved))))
    if not stage:
        program += '\n\ndef constants(w:mutbuf) -> u64:\n' + '\n'.join(constants) + '\n    return 0\n'
    return program


def template():
    with tempfile.TemporaryDirectory(prefix='hia-release-owner-author-') as tmp:
        obj, raw = Path(tmp) / 'adapter.o', Path(tmp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT / 'tools/hia_release_owner_syscalls.S'), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('release-owner capsule has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in ('policy_hole', 'stage_hole', 'sha_hole')}


def packer_source():
    prefix, holes = template()
    magic = int.from_bytes(b'HIAOWPK1', 'little')
    code = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or uint(s, 0, 8) != {magic}:
        return 4294967295
    policy = uint(s, 8, 8)
    stage = uint(s, 16, 8)
    sha = uint(s, 24, 8)
    if policy == 0 or stage == 0 or sha == 0 or policy > 1048576 or stage > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 32 + policy + stage + sha:
        return 4294967295
    size = {len(prefix)} + policy + stage + sha
    if size > 2097152 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        code += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    code += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix)) + (' + policy + stage' if name == 'sha_hole' else ' + policy' if name == 'stage_hole' else '')
        code += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    code += f'    copy_bytes(s, o, 32, {len(prefix)}, policy + stage + sha)\n    return size\n'
    return code + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in (('release_owner', policy_source()), ('release_dag', policy_source(stage=True)),
                         ('release_owner_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
