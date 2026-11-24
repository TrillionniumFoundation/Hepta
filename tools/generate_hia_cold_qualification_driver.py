"""Author the native, sealed-fd qualification plan executor.

No fixture/oracle is evaluated by this development author.  The checked-in
HIA executor performs the operations in an immutable source-bound plan.  It
retains every node and full process observation in a lossless binary journal.
"""
from pathlib import Path
import ast
import re
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import bulk_document as document
from tools.generate_hia_native_filter import LINK_SOURCE
from tools.generate_hia_release_owner import POLICY as RELEASE_HELPERS
from tools.generate_hia_cold_qualification_codec_lz import CODEC
from tools.hia_cold_byte_loops import accelerate
from tools.hia_cold_journal_backrefs import HELPERS as BACKREF_HELPERS

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    p = get(w, 0)
    r = get(w, 8)
    if p < 100:
        return admit_step(s, o, w, p, r)
    if p < 200:
        return running(s, o, w, p, r)
    if p < 250:
        return transfer(s, o, w, p, r)
    if p < 300:
        return hashing(s, o, w, p, r)
    if p >= 1600 and p < 1700:
        return frame_step(s, o, w, p, r)
    if p >= 1000 and p < 1100:
        return journal(s, o, w, p, r)
    if p >= 1100 and p < 1200:
        return archive_step(s, o, w, p, r)
    return dispatch(s, o, w, p, r)

def admit_step(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 0:
        constants(w)
        if request(s, w) == 0:
            return finish(o, w, 65)
        fill_range(w, 3342336, 524288, 0)
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if failed(r):
        return finish(o, w, 74)
    if p == 1:
        if uint(s, 8) != 0 and uint(s, 8) != r:
            return finish(o, w, 65)
        return call(o, w, 2, 157, 1, 15, 0, 0, 0, 0, 0)
    if p == 2:
        return call(o, w, 3, 39, 0, 0, 0, 0, 0, 0, 0)
    if p == 3:
        put(w, 16, r)
        return call(o, w, 4, 107, 0, 0, 0, 0, 0, 0, 0)
    if p == 4:
        put(w, 24, r)
        return call(o, w, 5, 5, uint(s, 24), 1200, 0, 0, 0, 0, 12)
    if p == 5:
        if getn(w, 1224, 4) & 61440 != 16384 or getn(w, 1224, 4) & 63 != 0 or getn(w, 1228, 4) != get(w, 24):
            return finish(o, w, 65)
        return call(o, w, 6, 5, uint(s, 56), 1200, 0, 0, 0, 0, 12)
    if p == 6:
        if getn(w, 1224, 4) & 61440 != 32768 or getn(w, 1224, 4) & 63 != 0 or getn(w, 1228, 4) != get(w, 24) or get(w, 1216) > 1 or get(w, 1248) != 0:
            return finish(o, w, 65)
        return call(o, w, 7, 5, uint(s, 48), 1200, 0, 0, 0, 0, 12)
    if p == 7:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) != uint(s, 72):
            return finish(o, w, 65)
        return call(o, w, 8, 72, uint(s, 48), 1034, 0, 0, 0, 0, 0)
    if p == 8:
        if r & 15 != 15:
            return finish(o, w, 65)
        return hash_view(o, w, uint(s, 48), 0, uint(s, 72), 9)
    if p == 9:
        if same_input(s, w, 88, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 1501000, 0)
        return import_inspect(s, o, w)
    if p == 10:
        at = 128 + get(w, 1501000) * 192
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) != uint(s, at + 8):
            return finish(o, w, 65)
        return call(o, w, 11, 72, uint(s, at), 1034, 0, 0, 0, 0, 0)
    if p == 11:
        if r & 15 != 15:
            return finish(o, w, 65)
        at = 128 + get(w, 1501000) * 192
        return hash_view(o, w, uint(s, at), 0, uint(s, at + 8), 12)
    if p == 12:
        at = 128 + get(w, 1501000) * 192
        if same_input(s, w, at + 32, 4096, 32) == 0:
            return finish(o, w, 65)
        put(w, 1501000, get(w, 1501000) + 1)
        return import_inspect(s, o, w)
    if p == 13:
        if get(w, 60000) != MAGIC_PLAN or get(w, 60008) != uint(s, 80) or get(w, 60016) != 0 or get(w, 60024) != 0:
            return finish(o, w, 65)
        put(w, 1500000, 32)
        put(w, 1500008, 0)
        return resume(s, o, w, 300)
    return finish(o, w, 65)

def request(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 320 or length(s) > 12416 or uint(s, 0) != MAGIC_REQUEST:
        return 0
    count = uint(s, 64)
    if count == 0 or count > 64 or length(s) != 128 + count * 192 or uint(s, 120) != 0:
        return 0
    if uint(s, 8) == 1 or uint(s, 8) > 2147483647 or uint(s, 16) == 0:
        return 0
    if uint(s, 72) < 32 or uint(s, 72) > 67108864 or uint(s, 80) == 0 or uint(s, 80) > 65536:
        return 0
    i = 0
    while i < 5:
        fd = uint(s, 24 + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < i:
            if fd == uint(s, 24 + j * 8):
                return 0
            j = j + 1
        i = i + 1
    fast = 0
    cold = 0
    i = 0
    while i < count:
        at = 128 + i * 192
        fd = uint(s, at)
        size = uint(s, at + 8)
        n = uint(s, at + 16)
        if fd < 3 or fd > 2147483647 or size > 67108864 or n == 0 or n > 127 or uint(s, at + 24) != 0:
            return 0
        if fd == uint(s, 24) or fd == uint(s, 48) or fd == uint(s, 56):
            return 0
        j = 0
        while j < 128:
            c = byte(s, at + 64 + j)
            if (j < n and (c < 33 or c > 126)) or (j >= n and c != 0):
                return 0
            j = j + 1
        j = 0
        while j < i:
            before = 128 + j * 192
            if fd == uint(s, before) or (uint(s, before + 16) == n and input_equal(s, at + 64, before + 64, n) == 1):
                return 0
            j = j + 1
        if fd == uint(s, 32):
            fast = fast + 1
        if fd == uint(s, 40):
            cold = cold + 1
        i = i + 1
    return choose(fast == 1 and cold == 1, 1, 0)

def import_inspect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1501000) == uint(s, 64):
        return reading(o, w, uint(s, 48), 60000, 32, 0, 13)
    at = 128 + get(w, 1501000) * 192
    return call(o, w, 10, 5, uint(s, at), 1200, 0, 0, 0, 0, 12)

def dispatch(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if p == 300:
        return call(o, w, 301, 228, 1, 1400, 0, 0, 0, 0, 12)
    if p == 301:
        if now(w) >= uint(s, 16):
            return finish(o, w, 124)
        if get(w, 1500008) == uint(s, 80):
            if get(w, 1500000) != uint(s, 72):
                return finish(o, w, 65)
            return call(o, w, 1050, 74, uint(s, 56), 0, 0, 0, 0, 0, 0)
        if get(w, 1500000) > uint(s, 72) or uint(s, 72) - get(w, 1500000) < 32:
            return finish(o, w, 65)
        return reading(o, w, uint(s, 48), 1500500, 32, get(w, 1500000), 302)
    if p == 302:
        if node(w) == 0:
            return finish(o, w, 65)
        n = get(w, 1500032) * 8 + get(w, 1500040)
        if n > uint(s, 72) - get(w, 1500000) - 32:
            return finish(o, w, 65)
        put(w, 1500048, get(w, 1500000) + 32 + n)
        if n == 0:
            return perform(s, o, w)
        return reading(o, w, uint(s, 48), 2097152, n, get(w, 1500000) + 32, 303)
    if p == 303:
        return perform(s, o, w)
    if p == 310:
        put(w, 1500064, 1)
        return journal_start(s, o, w)
    if p >= 320 and p <= 323:
        return shared(s, o, w, p, r)
    if p >= 340 and p <= 343:
        return compare_step(s, o, w, p, r)
    if p == 350:
        n = argument(w, 2)
        value = getn(w, 62000, n)
        if value & argument(w, 4) != argument(w, 3) & argument(w, 4):
            return finish(o, w, 1)
        return journal_start(s, o, w)
    if p == 360:
        return seal_buffer(o, w, 4096, 32, 310)
    if p >= 370 and p <= 373:
        return publish_file(s, o, w, p, r)
    if p == 392:
        return number_step(s, o, w, 392)
    if p == 391:
        return result_part(s, o, w, 391)
    if p == 380:
        put(w, 1500104, get(w, 1500104) + 1)
        return dropping(s, o, w)
    return finish(o, w, 65)

def node(w:mutbuf) -> u64:
    op = get(w, 1500500)
    id = get(w, 1500508)
    n = get(w, 1500516)
    size = get(w, 1500524)
    if op == 0 or op > 17 or n > 128 or size > 1048576:
        return 0
    if op == 6 or op == 7 or op == 11 or op == 12:
        if id != 0:
            return 0
    else:
        if id == 0 or id > 4096 or get(w, 1048576 + id * 32) != 0:
            return 0
    put(w, 1500016, op)
    put(w, 1500024, id)
    put(w, 1500032, n)
    put(w, 1500040, size)
    put(w, 1500056, 2097152 + n * 8)
    put(w, 1500064, 0)
    put(w, 1500072, 0)
    put(w, 1500080, 0)
    put(w, 144, 0)
    put(w, 152, 0)
    return 1

def argument(w:mutbuf, index:u64) -> u64:
    if index >= get(w, 1500032):
        return 18446744073709551615
    return get(w, 2097152 + index * 8)

def handle(w:mutbuf, id:u64) -> u64:
    if id == 0 or id > 4096:
        return 0
    at = 1048576 + id * 32
    return choose(get(w, at) >= 3, at, 0)

def perform(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 1500016)
    n = get(w, 1500032)
    size = get(w, 1500040)
    data = get(w, 1500056)
    if op == 1:
        if n != 0 or size == 0 or size > 127:
            return finish(o, w, 65)
        i = 0
        while i < uint(s, 64):
            at = 128 + i * 192
            if uint(s, at + 16) == size and same_input(s, w, at + 64, data, size) == 1:
                put(w, 144, uint(s, at))
                put(w, 152, uint(s, at + 8))
                return journal_start(s, o, w)
            i = i + 1
        return finish(o, w, 65)
    if op == 2:
        if n != 0:
            return finish(o, w, 65)
        return seal_buffer(o, w, data, size, 310)
    if op == 3:
        row = handle(w, argument(w, 0))
        offset = argument(w, 1)
        count = argument(w, 2)
        if n != 3 or size != 0 or row == 0 or offset > get(w, row + 8):
            return finish(o, w, 65)
        count = choose(count == 18446744073709551615, get(w, row + 8) - offset, count)
        if count > get(w, row + 8) - offset:
            return finish(o, w, 65)
        view(w, 0, get(w, row), offset, count)
        return frame(o, w, 6144, 0, 330000, 1, 310)
    if op == 4:
        if n == 0 or size != 0:
            return finish(o, w, 65)
        i = 0
        while i < n:
            row = handle(w, argument(w, i))
            if row == 0:
                return finish(o, w, 65)
            view(w, i, get(w, row), 0, get(w, row + 8))
            i = i + 1
        return frame(o, w, 6144, 0, 330000, n, 310)
    if op == 5:
        return run_start(s, o, w)
    if op == 6:
        return compare_step(s, o, w, 340, 0)
    if op == 7:
        row = handle(w, argument(w, 0))
        offset = argument(w, 1)
        count = argument(w, 2)
        if n != 5 or size != 0 or row == 0 or count == 0 or count > 8 or offset > get(w, row + 8) or count > get(w, row + 8) - offset:
            return finish(o, w, 65)
        return reading(o, w, get(w, row), 62000, count, offset, 350)
    if op == 8 or op == 16 or op == 17:
        return shared(s, o, w, 320, 0)
    if op == 9 or op == 10 or op == 13:
        row = handle(w, argument(w, 0))
        if n != 1 or size != 0 or row == 0:
            return finish(o, w, 65)
        if op == 13:
            return hash_view(o, w, get(w, row), 0, get(w, row + 8), 360)
        put(w, 62000, choose(op == 9, get(w, row), get(w, row + 8)))
        return seal_buffer(o, w, 62000, 8, 310)
    if op == 11:
        if n == 0 or size != 0:
            return finish(o, w, 65)
        put(w, 1500104, 0)
        return dropping(s, o, w)
    if op == 12:
        return publish_file(s, o, w, 370, 0)
    if op == 14:
        return result_part(s, o, w, 390)
    if op == 15:
        return number_step(s, o, w, 390)
    return finish(o, w, 65)

def number_step(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 390:
        row = handle(w, argument(w, 0))
        offset = argument(w, 1)
        width = argument(w, 2)
        if get(w, 1500032) != 6 or get(w, 1500040) != 0 or row == 0 or width == 0 or width > 8 or argument(w, 3) > 1 or offset > get(w, row + 8) or width > get(w, row + 8) - offset:
            return finish(o, w, 65)
        return reading(o, w, get(w, row), 62000, width, offset, 392)
    value = getn(w, 62000, argument(w, 2))
    amount = argument(w, 4)
    maximum = argument(w, 5)
    if argument(w, 3) == 0:
        if amount > maximum or value > maximum - amount:
            return finish(o, w, 65)
        value = value + amount
    else:
        if value < amount:
            return finish(o, w, 65)
        value = value - amount
        if value > maximum:
            return finish(o, w, 65)
    put(w, 62000, value)
    return seal_buffer(o, w, 62000, 8, 310)

def result_part(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u32:
    row = handle(w, argument(w, 0))
    part = argument(w, 1)
    if phase == 390:
        if get(w, 1500032) != 2 or get(w, 1500040) != 0 or row == 0 or get(w, row + 24) != 2 or get(w, row + 8) < 64 or part > 4:
            return finish(o, w, 65)
        return reading(o, w, get(w, row), 62000, 64, 0, 391)
    if get(w, 62000) != MAGIC_RESULT or get(w, 62056) != 0 or get(w, 62040) > 1:
        return finish(o, w, 65)
    out = get(w, 62008)
    err = get(w, 62016)
    receipt = get(w, 62024)
    shared = get(w, 62032)
    request = get(w, 62048)
    if out > 16777216 or err > 16777216 or receipt > 4194304 or shared > 1048576 or request > 65536 or get(w, row + 8) != 64 + out + err + receipt + shared + request:
        return finish(o, w, 65)
    offset = 64
    size = receipt
    if part == 1:
        offset = offset + receipt
        size = out
    if part == 2:
        offset = offset + receipt + out
        size = err
    if part == 3:
        offset = offset + receipt + out + err
        size = shared
    if part == 4:
        offset = offset + receipt + out + err + shared
        size = request
    view(w, 0, get(w, row), offset, size)
    return frame(o, w, 6144, 0, 330000, 1, 310)

def shared(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 320:
        row = handle(w, argument(w, 0))
        operation = get(w, 1500016)
        limit = choose(operation == 17, 1048712, choose(operation == 16, 1048584, 1048576))
        if get(w, 1500032) != 1 or get(w, 1500040) != 0 or row == 0 or get(w, row + 8) > limit:
            return finish(o, w, 65)
        if operation == 16 and get(w, row + 8) < 8:
            return finish(o, w, 65)
        if operation == 17 and get(w, row + 8) != 1048712:
            return finish(o, w, 65)
        put(w, 1500104, row)
        return call(o, w, 321, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if p == 321:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500112, r)
        return call(o, w, 322, 77, r, choose(get(w, get(w, 1500104) + 8) == 0, 1, get(w, get(w, 1500104) + 8)), 0, 0, 0, 0, 0)
    if p == 322:
        row = get(w, 1500104)
        return copying(o, w, get(w, row), get(w, 1500112), 0, get(w, row + 8), 323)
    if p == 323:
        put(w, 144, get(w, 1500112))
        put(w, 152, get(w, get(w, 1500104) + 8))
        put(w, 1500064, 1)
        put(w, 1500072, choose(get(w, 1500016) == 17, 4, choose(get(w, 1500016) == 16, 3, 1)))
        return call(o, w, 1000, 72, get(w, 144), 1033, 7, 0, 0, 0, 0)
    return finish(o, w, 65)

def compare_step(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 340:
        a = handle(w, argument(w, 0))
        b = handle(w, argument(w, 1))
        if get(w, 1500032) != 3 or get(w, 1500040) != 0 or a == 0 or b == 0 or argument(w, 2) > 1:
            return finish(o, w, 65)
        if get(w, a + 8) != get(w, b + 8):
            if argument(w, 2) == 1:
                return journal_start(s, o, w)
            return finish(o, w, 1)
        put(w, 1500104, 0)
        put(w, 1500112, 0)
        return compare_step(s, o, w, 341, 0)
    if p == 341:
        row = handle(w, argument(w, 0))
        if get(w, 1500104) == get(w, row + 8):
            if argument(w, 2) != get(w, 1500112):
                return finish(o, w, 1)
            return journal_start(s, o, w)
        count = minimum(65536, get(w, row + 8) - get(w, 1500104))
        put(w, 1500120, count)
        return reading(o, w, get(w, row), 700000, count, get(w, 1500104), 342)
    if p == 342:
        row = handle(w, argument(w, 1))
        return reading(o, w, get(w, row), 800000, get(w, 1500120), get(w, 1500104), 343)
    if p == 343:
        if same(w, 700000, 800000, get(w, 1500120)) == 0:
            put(w, 1500112, 1)
        put(w, 1500104, get(w, 1500104) + get(w, 1500120))
        return resume(s, o, w, 341)
    return finish(o, w, 65)

def dropping(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    while get(w, 1500104) < get(w, 1500032):
        row = handle(w, argument(w, get(w, 1500104)))
        if row == 0:
            return finish(o, w, 65)
        fd = get(w, row)
        own = get(w, row + 16)
        put(w, row, 0)
        if own == 1:
            return call(o, w, 380, 3, fd, 0, 0, 0, 0, 0, 0)
        put(w, 1500104, get(w, 1500104) + 1)
    return journal_start(s, o, w)

def publish_file(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p == 370:
        row = handle(w, argument(w, 0))
        size = get(w, 1500040)
        if get(w, 1500032) != 1 or size == 0 or size > 127 or row == 0:
            return finish(o, w, 65)
        i = 0
        while i < size:
            c = byte(w, get(w, 1500056) + i)
            if (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
                return finish(o, w, 65)
            i = i + 1
        if byte(w, get(w, 1500056)) == 46:
            return finish(o, w, 65)
        copyw(w, 62000, get(w, 1500056), size)
        store(w, 62000 + size, 0)
        put(w, 1500104, row)
        return call(o, w, 371, 257, uint(s, 24), 62000, 655553, 384, 0, 0, 12)
    if p == 371:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1500112, r)
        row = get(w, 1500104)
        return copying(o, w, get(w, row), r, 0, get(w, row + 8), 372)
    if p == 372:
        return call(o, w, 373, 74, get(w, 1500112), 0, 0, 0, 0, 0, 0)
    if p == 373:
        return call(o, w, 1000, 3, get(w, 1500112), 0, 0, 0, 0, 0, 0)
    return finish(o, w, 65)

def run_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    image = handle(w, argument(w, 0))
    source = handle(w, argument(w, 1))
    seconds = argument(w, 2)
    shared = argument(w, 3)
    mode = argument(w, 4)
    if get(w, 1500032) < 5 or get(w, 1500032) > 21 or image == 0 or source == 0 or get(w, image + 8) < 176 or mode > 1 or get(w, 1500040) < 8:
        return finish(o, w, 65)
    if seconds != 15 and seconds != 20 and seconds != 180:
        return finish(o, w, 65)
    if shared != 0:
        row = handle(w, shared)
        if row == 0 or get(w, row + 24) != 1 or get(w, row + 8) > 1048576:
            return finish(o, w, 65)
    put(w, 520, get(w, image))
    put(w, 528, get(w, source))
    put(w, 536, mode)
    put(w, 544, seconds)
    put(w, 552, 0)
    if get(w, image + 16) == 1:
        return call(o, w, 100, 91, get(w, image), 320, 0, 0, 0, 0, 0)
    return resume(s, o, w, 100)

def running(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if p >= 150:
        return run_child(s, o, w, p, r)
    if p == 112 and r == 18446744073709551612:
        return call(o, w, 112, 61, get(w, 592), 600, 0, 0, 0, 0, 12)
    if failed(r):
        return finish(o, w, 74)
    if p == 100:
        return call(o, w, 101, 8, get(w, 528), 0, 0, 0, 0, 0, 0)
    if p == 101:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 102, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if p == 102:
        if r < 3:
            return finish(o, w, 74)
        put(w, 560 + get(w, 552) * 8, r)
        return call(o, w, 103, 91, r, 384, 0, 0, 0, 0, 0)
    if p == 103:
        put(w, 552, get(w, 552) + 1)
        if get(w, 552) < 4:
            return call(o, w, 102, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
        return call(o, w, 104, 228, 1, 1400, 0, 0, 0, 0, 12)
    if p == 104:
        if now(w) >= uint(s, 16) or job_request(s, w) == 0:
            return finish(o, w, 65)
        return writing(o, w, get(w, 584), 458752, get(w, 608), 105)
    if p == 105:
        return call(o, w, 106, 72, get(w, 584), 1033, 15, 0, 0, 0, 0)
    if p == 106:
        put(w, 3904, C_CHILD)
        put(w, 3912, 18446744073709551615)
        put(w, 4056, 0)
        put(w, 0, 110)
        put(o, 0, 3904)
        put(o, 8, 2)
        put(o, 16, 4000)
        return 2
    if p == 110:
        return call(o, w, 111, 57, 0, 0, 0, 0, 0, 0, 0)
    if p == 111:
        if r == 0:
            return call(o, w, 150, 157, 1, 15, 0, 0, 0, 0, 0)
        put(w, 592, r)
        return call(o, w, 112, 61, r, 600, 0, 0, 0, 0, 12)
    if p == 112:
        if r != get(w, 592):
            return finish(o, w, 74)
        put(w, 1500400, getn(w, 600, 4))
        put(w, 552, 0)
        return call(o, w, 113, 5, get(w, 560), 1200, 0, 0, 0, 0, 12)
    if p == 113:
        size = get(w, 1248)
        index = get(w, 552)
        if getn(w, 1224, 4) & 61440 != 32768 or size > choose(index == 2, 4194304, 16777216):
            return finish(o, w, 74)
        put(w, 1500416 + index * 8, size)
        put(w, 552, index + 1)
        if index < 2:
            return call(o, w, 113, 5, get(w, 560 + (index + 1) * 8), 1200, 0, 0, 0, 0, 12)
        if size < choose(get(w, 536) == 0, 128, 256):
            put(w, 1500080, 74)
            return make_result(s, o, w)
        return reading(o, w, get(w, 576), 5376, choose(get(w, 536) == 0, 128, 256), 0, 114)
    if p == 114:
        if custody(w) == 0:
            put(w, 1500080, 74)
        return make_result(s, o, w)
    if p == 115:
        put(w, 1500304, get(w, 144))
        put(w, 1500312, get(w, 152))
        put(w, 552, 0)
        return call(o, w, 116, 3, get(w, 560), 0, 0, 0, 0, 0, 0)
    if p == 116:
        put(w, 552, get(w, 552) + 1)
        if get(w, 552) < 4:
            return call(o, w, 116, 3, get(w, 560 + get(w, 552) * 8), 0, 0, 0, 0, 0, 0)
        put(w, 144, get(w, 1500304))
        put(w, 152, get(w, 1500312))
        put(w, 1500064, 1)
        put(w, 1500072, 2)
        return journal_start(s, o, w)
    return finish(o, w, 65)

def job_request(s:readbuf, w:mutbuf) -> u64:
    at = 458752
    mode = get(w, 536)
    argc = get(w, get(w, 1500056))
    if argc == 0 or argc > 64:
        return 0
    passed = get(w, 1500032) - 5 + choose(argument(w, 3) == 0, 0, 1)
    if passed > 16:
        return 0
    if mode == 0:
        put(w, at, MAGIC_SUB)
        put(w, at + 8, get(w, 16))
        put(w, at + 16, minimum(uint(s, 16), now(w) + get(w, 544) * 1000000000))
        put(w, at + 24, get(w, 520))
        put(w, at + 32, get(w, 528))
        put(w, at + 40, get(w, 560))
        put(w, at + 48, get(w, 568))
        put(w, at + 56, uint(s, 24))
        put(w, at + 64, get(w, 576))
        put(w, at + 72, argc)
        put(w, at + 80, 4)
        put(w, at + 88, 16777216)
        put(w, at + 96, 16777216)
        put(w, at + 104, 3000000000)
        put(w, at + 112, 0)
        put(w, at + 120, 0)
    else:
        put(w, at, MAGIC_COLD)
        put(w, at + 8, get(w, 16))
        put(w, at + 16, now(w))
        put(w, at + 24, now(w) + get(w, 544) * 1000000000)
        put(w, at + 32, get(w, 544))
        put(w, at + 40, get(w, 520))
        put(w, at + 48, get(w, 528))
        put(w, at + 56, get(w, 560))
        put(w, at + 64, get(w, 568))
        put(w, at + 72, get(w, 576))
        put(w, at + 80, uint(s, 24))
        put(w, at + 88, argc)
        put(w, at + 96, 4)
        put(w, at + 104, passed)
        put(w, at + 112, 0)
        put(w, at + 120, 0)
    at = at + 128
    cursor = get(w, 1500056) + 8
    end = get(w, 1500056) + get(w, 1500040)
    i = 0
    while i < argc:
        if cursor > end or end - cursor < 8:
            return 0
        size = get(w, cursor)
        cursor = cursor + 8
        if size > 4095 or size > end - cursor or at - 458752 + size + 9 > 65000:
            return 0
        j = 0
        while j < size:
            if byte(w, cursor + j) == 0:
                return 0
            j = j + 1
        at = arg(w, at, cursor, size)
        cursor = cursor + size
        i = i + 1
    if cursor != end:
        return 0
    at = arg(w, at, C_ENV_PATH, L_ENV_PATH)
    at = arg(w, at, C_ENV_LANG, L_ENV_LANG)
    at = arg(w, at, C_ENV_LC, L_ENV_LC)
    at = arg(w, at, C_ENV_TZ, L_ENV_TZ)
    if mode == 0 and passed != 0:
        put(w, at, MAGIC_PASS)
        put(w, at + 8, passed)
        at = at + 16
    if argument(w, 3) != 0:
        put(w, at, get(w, handle(w, argument(w, 3))))
        at = at + 8
    i = 5
    while i < get(w, 1500032):
        row = handle(w, argument(w, i))
        if row == 0:
            return 0
        put(w, at, get(w, row))
        at = at + 8
        i = i + 1
    put(w, 608, at - 458752)
    return choose(at - 458752 <= 65536, 1, 0)

def run_child(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r) or p == 153:
        return finish(o, w, 127)
    if p == 150:
        return call(o, w, 151, 110, 0, 0, 0, 0, 0, 0, 0)
    if p == 151:
        if r != get(w, 16):
            return finish(o, w, 127)
        return call(o, w, 152, 33, get(w, 584), 0, 0, 0, 0, 0, 0)
    return call(o, w, 153, 322, choose(get(w, 536) == 0, uint(s, 32), uint(s, 40)), C_EMPTY, 4000, 4056, 4096, 0, 252)

def custody(w:mutbuf) -> u64:
    if get(w, 536) == 0:
        if get(w, 1500400) != 0 or get(w, 1500432) != 128 or get(w, 5376) != MAGIC_SUBRECEIPT:
            return 0
        if get(w, 5392) != 0 or get(w, 5416) != get(w, 1500416) or get(w, 5424) != get(w, 1500416) or get(w, 5432) != get(w, 1500424) or get(w, 5440) != get(w, 1500424):
            return 0
        if get(w, 5448) != 0 or get(w, 5456) != 0 or get(w, 5464) != 0 or get(w, 5472) != 1 or get(w, 5480) != 1 or get(w, 5496) != 1:
            return 0
        return 1
    if (get(w, 1500400) != 0 and get(w, 1500400) != 256) or get(w, 5376) != MAGIC_COLDRECEIPT:
        return 0
    if get(w, 5392) != get(w, 592) or get(w, 5400) != get(w, 16) or get(w, 5424) != get(w, 544):
        return 0
    if (get(w, 5384) == 0 and get(w, 1500400) != 0) or (get(w, 5384) == 1 and get(w, 1500400) != 256):
        return 0
    if get(w, 5384) > 1 or get(w, 5456) != 0 or get(w, 5464) != 1 or get(w, 5472) != 1 or get(w, 5480) != 1 or get(w, 5488) != 0 or get(w, 5496) != 0:
        return 0
    if get(w, 5512) != 0 or get(w, 5544) != 0 or get(w, 5552) != 1 or get(w, 5568) != 0 or get(w, 1500432) != 256 + get(w, 5520) * 48 + get(w, 5504) * 40:
        return 0
    return 1

def make_result(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 6144, MAGIC_RESULT)
    put(w, 6152, get(w, 1500416))
    put(w, 6160, get(w, 1500424))
    put(w, 6168, get(w, 1500432))
    size = 0
    shared = 0
    if argument(w, 3) != 0:
        row = handle(w, argument(w, 3))
        size = get(w, row + 8)
        shared = get(w, row)
    put(w, 6176, size)
    put(w, 6184, get(w, 536))
    put(w, 6192, get(w, 608))
    put(w, 6200, 0)
    view(w, 0, get(w, 576), 0, get(w, 1500432))
    view(w, 1, get(w, 560), 0, get(w, 1500416))
    view(w, 2, get(w, 568), 0, get(w, 1500424))
    if shared != 0:
        view(w, 3, shared, 0, size)
        view(w, 4, get(w, 584), 0, get(w, 608))
        return frame(o, w, 6144, 64, 330000, 5, 115)
    view(w, 3, get(w, 584), 0, get(w, 608))
    return frame(o, w, 6144, 64, 330000, 4, 115)

def journal_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return resume(s, o, w, 1000)

def journal(s:readbuf, o:mutbuf, w:mutbuf, p:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if p == 1000:
        put(w, 1500200, get(w, 144))
        put(w, 1500208, get(w, 152))
        put(w, 1500216, get(w, 1500064))
        put(w, 1500224, get(w, 1500072))
        put(w, 62000, MAGIC_JOURNAL)
        put(w, 62008, get(w, 1500008))
        put(w, 62016, get(w, 1500016))
        put(w, 62024, get(w, 1500024))
        put(w, 62032, get(w, 1500032))
        put(w, 62040, get(w, 1500040))
        put(w, 62048, get(w, 152))
        put(w, 62056, get(w, 1500080))
        return archive_memory(s, o, w, 62000, 64, 1001)
    if p == 1001:
        return archive_memory(s, o, w, 2097152, get(w, 1500032) * 8 + get(w, 1500040), 1002)
    if p == 1002:
        return archive_file(s, o, w, get(w, 1500200), get(w, 1500208), 1004)
    if p == 1004:
        if get(w, 1500080) != 0:
            return finish(o, w, get(w, 1500080))
        id = get(w, 1500024)
        if id != 0:
            row = 1048576 + id * 32
            put(w, row, get(w, 1500200))
            put(w, row + 8, get(w, 1500208))
            put(w, row + 16, get(w, 1500216))
            put(w, row + 24, get(w, 1500224))
        put(w, 1500000, get(w, 1500048))
        put(w, 1500008, get(w, 1500008) + 1)
        return resume(s, o, w, 300)
    if p == 1050:
        if get(w, 1500248) != 1:
            return finish(o, w, 74)
        copyw(w, 4160, 1008000, 1184)
        return sha(o, w, 1053, 2, 1)
    if p == 1053:
        if r != 32:
            return finish(o, w, 74)
        copyw(w, 1500320, 4096, 32)
        return hash_view(o, w, uint(s, 56), 0, get(w, 1500128), 1051)
    if p == 1051:
        if same(w, 1500320, 4096, 32) == 0:
            return finish(o, w, 74)
        put(w, 62000, MAGIC_SUCCESS)
        put(w, 62008, get(w, 1500008))
        put(w, 62016, uint(s, 72))
        put(w, 62024, get(w, 1500128))
        copyw(w, 62032, 4096, 32)
        put(w, 1500104, 0)
        return call(o, w, 1052, 1, 1, 62000, 64, 0, 0, 0, 12)
    if p == 1052:
        if r == 0 or r > 64 - get(w, 1500104):
            return finish(o, w, 74)
        put(w, 1500104, get(w, 1500104) + r)
        if get(w, 1500104) < 64:
            return call(o, w, 1052, 1, 1, 62000 + get(w, 1500104), 64 - get(w, 1500104), 0, 0, 0, 12)
        return finish(o, w, 0)
    return finish(o, w, 65)

def archive_memory(s:readbuf, o:mutbuf, w:mutbuf, buffer:u64, size:u64, after:u64) -> u32:
    if buffer > 4194304 or size > 4194304 - buffer:
        return finish(o, w, 65)
    put(w, 1500256, 0)
    put(w, 1500264, buffer)
    put(w, 1500272, size)
    put(w, 1500280, after)
    return resume(s, o, w, 1100)

def archive_file(s:readbuf, o:mutbuf, w:mutbuf, file:u64, size:u64, after:u64) -> u32:
    put(w, 1500256, file)
    put(w, 1500264, 0)
    put(w, 1500272, size)
    put(w, 1500280, after)
    return resume(s, o, w, 1100)

def archive_step(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 1100:
        remaining = get(w, 1500272)
        if remaining == 0:
            return resume(s, o, w, get(w, 1500280))
        count = minimum(16384, remaining)
        put(w, 1500288, count)
        if get(w, 1500256) == 0:
            copyw(w, 700000, get(w, 1500264), count)
            return resume(s, o, w, 1101)
        return reading(o, w, get(w, 1500256), 700000, count, get(w, 1500264), 1101)
    if phase == 1101:
        amount = pack_chunk(w, get(w, 1500288))
        if amount == 0 or unpack_chunk(w, amount) != get(w, 1500288) or chunk_equal(w, get(w, 1500288)) == 0:
            return finish(o, w, 74)
        put(w, 1500296, amount)
        put(w, 1501104, 0)
        if amount >= 64:
            put(w, 1501112, chunk_fingerprint(w, 800000, amount))
            put(w, 1501104, 1)
            return sha(o, w, 1120, 0, 1)
        return archive_ready(o, w)
    if phase == 1120:
        if r != 0:
            return finish(o, w, 74)
        copyw(w, 65537, 800000, get(w, 1500296))
        return sha(o, w, 1121, 1, get(w, 1500296) + 1)
    if phase == 1121:
        if r != 0:
            return finish(o, w, 74)
        return sha(o, w, 1122, 2, 1)
    if phase == 1122:
        if r != 32:
            return finish(o, w, 74)
        copyw(w, 1501160, 4096, 32)
        fingerprint = get(w, 1501112)
        slot = chunk_cache_slot(fingerprint)
        amount = get(w, 1500296)
        offset = get(w, slot + 8)
        if offset != 0 and get(w, slot) == fingerprint and get(w, slot + 16) == amount:
            if same(w, slot + 24, 1501160, 32) == 1:
                offset = offset - 1
                if offset < get(w, 1500128) and amount <= get(w, 1500128) - offset:
                    put(w, 1501120, offset)
                    return reading(o, w, uint(s, 56), 3866624, amount, offset, 1111)
        return archive_ready(o, w)
    if phase == 1111:
        amount = get(w, 1500296)
        if same(w, 800000, 3866624, amount) == 0:
            return finish(o, w, 74)
        copyw(w, 800000, 3866624, amount)
        if unpack_chunk(w, amount) != get(w, 1500288) or chunk_equal(w, get(w, 1500288)) == 0:
            return finish(o, w, 74)
        put(w, 800000, MAGIC_BACKREF)
        put(w, 800008, get(w, 1500288))
        put(w, 800016, 8)
        put(w, 800024, 3)
        put(w, 800032, get(w, 1501120))
        put(w, 1500296, 40)
        put(w, 1501104, 0)
        return archive_ready(o, w)
    if phase == 1110:
        if r != 0:
            return finish(o, w, 74)
        put(w, 1500248, 1)
        copyw(w, 1008000, 4160, 1184)
        return archive_hash(o, w)
    if phase == 1103:
        if r != 0:
            return finish(o, w, 74)
        copyw(w, 1008000, 4160, 1184)
        return writing_at(o, w, uint(s, 56), 800000, get(w, 1500296), get(w, 1500128), 1104)
    if phase == 1104:
        if get(w, 1501104) != 0:
            chunk_cache_store(w, get(w, 1501112), get(w, 1500128), get(w, 1500296))
            copyw(w, chunk_cache_slot(get(w, 1501112)) + 24, 1501160, 32)
        amount = get(w, 1500288)
        put(w, 1500240, get(w, 1500240) + amount)
        put(w, 1500128, get(w, 1500128) + get(w, 1500296))
        put(w, 1500264, get(w, 1500264) + amount)
        put(w, 1500272, get(w, 1500272) - amount)
        return resume(s, o, w, 1100)
    return finish(o, w, 65)

def archive_ready(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1500248) == 0:
        return sha(o, w, 1110, 0, 1)
    return archive_hash(o, w)

def archive_hash(o:mutbuf, w:mutbuf) -> u32:
    copyw(w, 4160, 1008000, 1184)
    copyw(w, 65537, 800000, get(w, 1500296))
    return sha(o, w, 1103, 1, get(w, 1500296) + 1)

def now(w:mutbuf) -> u64:
    return get(w, 1400) * 1000000000 + get(w, 1408)

def input_equal(s:readbuf, a:u64, b:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1
'''

HELPERS = ('writing','writing_at','reading','copying','transfer','seal_buffer',
           'hash_view','hashing','frame','frame_step','view','resume','sha','call',
           'finish','minimum','arg','same','same_input','copyw','failed','uint',
           'get','getn','put')


def policy_source():
    nodes = {n.name: ast.get_source_segment(RELEASE_HELPERS,n)
             for n in ast.parse(RELEASE_HELPERS).body if isinstance(n,ast.FunctionDef)}
    helpers = '\n\n'.join(nodes[name] for name in HELPERS)
    helpers = helpers.replace('put(w, 888, r)\n        return writing(o, w, r, get(w, 904), get(w, 912), 211)',
        'put(w, 888, r)\n        return call(o, w, 213, 91, r, 384, 0, 0, 0, 0, 0)\n    if phase == 213:\n        return writing(o, w, get(w, 888), get(w, 904), get(w, 912), 211)')
    helpers = helpers.replace('put(w, 3072, r)\n        return writing(o, w, r, get(w, 3112), get(w, 3120), 1601)',
        'put(w, 3072, r)\n        return call(o, w, 1607, 91, r, 384, 0, 0, 0, 0, 0)\n    if phase == 1607:\n        return writing(o, w, get(w, 3072), get(w, 3112), get(w, 3120), 1601)')
    helpers = helpers.replace('return getn(w, at, 8)', 'return word_load(w, at)')
    text = accelerate(SOURCE + '\n' + CODEC + '\n' + BACKREF_HELPERS + '\n' + helpers, bulk=True)
    words={};writes=[];cursor=600000
    for name,raw in {'MEMFD':b'hia-cold-plan','CHILD':b'hia-cold-child','EMPTY':b'',
                     'ENV_PATH':b'PATH=','ENV_LANG':b'LANG=C.UTF-8','ENV_LC':b'LC_ALL=C.UTF-8','ENV_TZ':b'TZ=UTC'}.items():
        words['C_'+name]=cursor;words['L_'+name]=len(raw)
        for i in range(0,len(raw)+1,8):
            writes.append(f'    put(w, {cursor+i}, {int.from_bytes((raw+b"\0")[i:i+8].ljust(8,b"\0"),"little")})')
        cursor=(cursor+len(raw)+16)&~7
    for name,raw in {'REQUEST':b'HIAQDR01','PLAN':b'HIAQPL01','RESULT':b'HIAQRR01','JOURNAL':b'HIAQJL01','SUCCESS':b'HIAQOK01',
                     'BACKREF':b'HIAQAZ03','SUB':b'HIASUB01','SUBRECEIPT':b'HIASBR01','PASS':b'HIAPFD01','COLD':b'HIACOW01','COLDRECEIPT':b'HIACOR01'}.items():
        words['MAGIC_'+name]=int.from_bytes(raw,'little')
    for key,value in words.items():text=re.sub(r'\b'+key+r'\b',str(value),text)
    unresolved=re.findall(r'\b(?:C|L|MAGIC)_[A-Z_]+\b',text)
    if unresolved:raise ValueError(unresolved)
    return text+'\ndef constants(w:mutbuf) -> u64:\n'+'\n'.join(writes)+'\n    return 0\n'


def template():
    adapter=ROOT/'tools/hia_cold_qualification_driver_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-cold-driver-author-') as tmp:
        obj,raw=Path(tmp)/'a.o',Path(tmp)/'a.bin'
        subprocess.run(['as','--64',str(adapter),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(addr,16) for addr,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if symbols['_start']!=0 or 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):raise ValueError('unresolved mechanical driver relocation')
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{name:176+symbols[name] for name in ('policy_hole','sha_hole')}


def packer_source():
    prefix,holes=template()
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0, 8) != {int.from_bytes(b'HIAQDP01','little')}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8];text+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    text+=f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {holes['policy_hole']}, {len(prefix)-holes['policy_hole']-4}, 4)
    write(o, {holes['sha_hole']}, {len(prefix)-holes['sha_hole']-4} + policy, 4)
    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)
    return size
'''
    return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name,text in (('cold_qualification_driver',policy_source()),('cold_qualification_driver_packer',packer_source())):
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        path.write_text(render_assembly(document(text,name)))
        print(path.name,path.stat().st_size)


if __name__=='__main__':main()
