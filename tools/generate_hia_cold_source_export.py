"""Author native source-only export and complete origin/export revalidation.

Capabilities are explicit directory FDs and a sealed manifest. Every pathname
is resolved beneath its directory without symbolic links. No source is executed.
"""
import ast
import re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document
from tools.generate_hia_release_owner import POLICY

ROOT=Path(__file__).resolve().parents[1]

SOURCE=r'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    r = get(w, 8)
    if phase >= 200 and phase < 250:
        return transfer(s, o, w, phase, r)
    if phase >= 250 and phase < 300:
        return hashing(s, o, w, phase, r)
    if phase >= 1000:
        return walk(s, o, w, phase, r)
    if phase < 30:
        return admit(s, o, w, phase, r)
    return files(s, o, w, phase, r)

def admit(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 0:
        if length(s) != 128 or word_load(s, 0) != REQUEST or word_load(s, 8) > 1 or word_load(s, 16) < 3 or word_load(s, 24) < 3 or word_load(s, 32) < 3 or word_load(s, 40) < 32 or word_load(s, 40) > 67108864 or word_load(s, 48) == 0 or word_load(s, 48) > 16384 or word_load(s, 56) != 0:
            return finish(o, w, 65)
        if word_load(s, 16) == word_load(s, 24) or word_load(s, 16) == word_load(s, 32) or word_load(s, 24) == word_load(s, 32):
            return finish(o, w, 65)
        i = 96
        while i < 128:
            if byte(s, i) != 0:
                return finish(o, w, 65)
            i = i + 1
        constants(w)
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if failed(r):
        return finish(o, w, 74)
    if phase == 1:
        put(w, 1600024, r)
        return call(o, w, 2, 5, word_load(s, 16), 1200, 0, 0, 0, 0, 12)
    if phase == 2:
        if getn(w, 1224, 4) & 61440 != 16384:
            return finish(o, w, 65)
        put(w, 1600048, get(w, 1200))
        put(w, 1600056, get(w, 1208))
        return call(o, w, 3, 5, word_load(s, 24), 1200, 0, 0, 0, 0, 12)
    if phase == 3:
        if private_dir(w) == 0 or (get(w, 1200) == get(w, 1600048) and get(w, 1208) == get(w, 1600056)):
            return finish(o, w, 65)
        return call(o, w, 4, 5, word_load(s, 32), 1200, 0, 0, 0, 0, 12)
    if phase == 4:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) != word_load(s, 40):
            return finish(o, w, 65)
        return call(o, w, 5, 72, word_load(s, 32), 1034, 0, 0, 0, 0, 0)
    if phase == 5:
        if r & 15 != 15:
            return finish(o, w, 65)
        return hash_view(o, w, word_load(s, 32), 0, word_load(s, 40), 6)
    if phase == 6:
        i = 0
        while i < 32:
            if byte(w, 4096 + i) != byte(s, 64 + i):
                return finish(o, w, 65)
            i = i + 1
        return reading(o, w, word_load(s, 32), 18000, 32, 0, 7)
    if phase == 7:
        if get(w, 18000) != MANIFEST or get(w, 18008) != word_load(s, 48) or get(w, 18016) != 1 or get(w, 18024) != 0:
            return finish(o, w, 65)
        if word_load(s, 8) == 1:
            return open_path(o, w, word_load(s, 24), 10000, 720896, 0, 11)
        return call(o, w, 8, 258, word_load(s, 24), 10000, 448, 0, 0, 0, 12)
    if phase == 8:
        return call(o, w, 9, 258, word_load(s, 24), 10016, 448, 0, 0, 0, 12)
    if phase == 9:
        return call(o, w, 10, 258, word_load(s, 24), 10032, 448, 0, 0, 0, 12)
    if phase == 10:
        return open_path(o, w, word_load(s, 24), 10000, 720896, 0, 11)
    if phase == 11:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600016, r)
        return call(o, w, 12, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 12:
        if private_dir(w) == 0:
            return finish(o, w, 65)
        return open_path(o, w, word_load(s, 24), 10016, 720896, 0, 13)
    if phase == 13 or phase == 17:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600064, r)
        return call(o, w, phase + 1, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 14 or phase == 18:
        if private_dir(w) == 0:
            return finish(o, w, 65)
        return call(o, w, phase + 1, 3, get(w, 1600064), 0, 0, 0, 0, 0, 0)
    if phase == 15:
        return open_path(o, w, word_load(s, 24), 10032, 720896, 0, 17)
    if phase == 19:
        put(w, 1600000, 32)
        put(w, 1600032, 1)
        return resume(s, o, w, 30)
    return finish(o, w, 65)

def files(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 41 and r == 18446744073709551599:
        return open_path(o, w, get(w, 1600160), 30000, 720896, 0, 42)
    if failed(r):
        return finish(o, w, 74)
    if phase == 30:
        if get(w, 1600008) == word_load(s, 48):
            if get(w, 1600000) != word_load(s, 40):
                return finish(o, w, 65)
            put(w, 600000, get(w, 1600016))
            put(w, 1600416, 1)
            return resume(s, o, w, 1000)
        offset = get(w, 1600000)
        if offset > word_load(s, 40) or word_load(s, 40) - offset < 48:
            return finish(o, w, 65)
        return reading(o, w, word_load(s, 32), 18000, 48, offset, 31)
    if phase == 31:
        path_size = get(w, 18000)
        size = get(w, 18008)
        if path_size == 0 or path_size > 4095 or size > 67108864 or path_size > word_load(s, 40) - get(w, 1600000) - 48:
            return finish(o, w, 65)
        put(w, 1600080, path_size)
        put(w, 1600088, size)
        copyw(w, 1600104, 18016, 32)
        return reading(o, w, word_load(s, 32), 20000, path_size, get(w, 1600000) + 48, 32)
    if phase == 32:
        size = get(w, 1600080)
        if path_valid(w, size) == 0:
            return finish(o, w, 65)
        store(w, 20000 + size, 0)
        put(w, 1600000, get(w, 1600000) + 48 + size)
        return open_path(o, w, word_load(s, 16), 20000, 657408, 0, 33)
    if phase == 33:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600144, r)
        return call(o, w, 34, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 34:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) != get(w, 1600088):
            return finish(o, w, 65)
        copyw(w, 1600200, 1200, 144)
        return hash_view(o, w, get(w, 1600144), 0, get(w, 1600088), 35)
    if phase == 35:
        if same(w, 4096, 1600104, 32) == 0:
            return finish(o, w, 65)
        if word_load(s, 8) == 1:
            return open_path(o, w, get(w, 1600016), 20000, 657408, 0, 36)
        put(w, 1600160, get(w, 1600016))
        put(w, 1600168, 0)
        return resume(s, o, w, 40)
    if phase == 36:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600152, r)
        return call(o, w, 37, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 37:
        if private_file(w) == 0 or get(w, 1248) != get(w, 1600088):
            return finish(o, w, 65)
        return hash_view(o, w, get(w, 1600152), 0, get(w, 1600088), 49)
    if phase == 40:
        begin = get(w, 1600168)
        pos = begin
        while pos < get(w, 1600080) and byte(w, 20000 + pos) != 47:
            pos = pos + 1
        copyw(w, 30000, 20000 + begin, pos - begin)
        store(w, 30000 + pos - begin, 0)
        put(w, 1600176, pos)
        if pos == get(w, 1600080):
            return open_path(o, w, get(w, 1600160), 30000, 657602, 384, 45)
        return call(o, w, 41, 258, get(w, 1600160), 30000, 448, 0, 0, 0, 12)
    if phase == 41:
        return open_path(o, w, get(w, 1600160), 30000, 720896, 0, 42)
    if phase == 42:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600184, r)
        return call(o, w, 43, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 43:
        if private_dir(w) == 0:
            return finish(o, w, 65)
        if get(w, 1600160) != get(w, 1600016):
            return call(o, w, 44, 3, get(w, 1600160), 0, 0, 0, 0, 0, 0)
        return resume(s, o, w, 44)
    if phase == 44:
        put(w, 1600160, get(w, 1600184))
        put(w, 1600168, get(w, 1600176) + 1)
        return resume(s, o, w, 40)
    if phase == 45:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600152, r)
        return copying(o, w, get(w, 1600144), r, 0, get(w, 1600088), 46)
    if phase == 46:
        return call(o, w, 47, 91, get(w, 1600152), 256, 0, 0, 0, 0, 0)
    if phase == 47:
        return call(o, w, 48, 74, get(w, 1600152), 0, 0, 0, 0, 0, 0)
    if phase == 48:
        return hash_view(o, w, get(w, 1600152), 0, get(w, 1600088), 49)
    if phase == 49:
        if same(w, 4096, 1600104, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 50, 5, get(w, 1600144), 1200, 0, 0, 0, 0, 12)
    if phase == 50:
        if origin_stable(w) == 0:
            return finish(o, w, 65)
        return call(o, w, 51, 3, get(w, 1600144), 0, 0, 0, 0, 0, 0)
    if phase == 51:
        return call(o, w, 52, 3, get(w, 1600152), 0, 0, 0, 0, 0, 0)
    if phase == 52:
        if word_load(s, 8) == 0 and get(w, 1600160) != get(w, 1600016):
            return call(o, w, 53, 3, get(w, 1600160), 0, 0, 0, 0, 0, 0)
        return resume(s, o, w, 53)
    if phase == 53:
        copyw(w, 25000, 20000, get(w, 1600080))
        put(w, 1600040, get(w, 1600080))
        put(w, 1600008, get(w, 1600008) + 1)
        return resume(s, o, w, 30)
    return finish(o, w, 65)
'''

EXTRA=r'''def open_path(o:mutbuf, w:mutbuf, directory:u64, path:u64, flags:u64, mode:u64, after:u64) -> u32:
    put(w, 1600, flags)
    put(w, 1608, mode)
    put(w, 1616, 14)
    return call(o, w, after, 437, directory, path, 1600, 24, 0, 0, 60)

def private_dir(w:mutbuf) -> u64:
    return choose(getn(w, 1224, 4) & 65535 == 16832 and getn(w, 1228, 4) == get(w, 1600024), 1, 0)

def private_file(w:mutbuf) -> u64:
    return choose(getn(w, 1224, 4) & 65535 == 33024 and getn(w, 1228, 4) == get(w, 1600024), 1, 0)

def origin_stable(w:mutbuf) -> u64:
    i = 0
    while i < 40:
        if get(w, 1200 + i) != get(w, 1600200 + i):
            return 0
        i = i + 8
    if get(w, 1248) != get(w, 1600248):
        return 0
    i = 88
    while i < 120:
        if get(w, 1200 + i) != get(w, 1600200 + i):
            return 0
        i = i + 8
    return 1

def path_valid(w:mutbuf, size:u64) -> u64:
    if byte(w, 20000) == 47 or byte(w, 20000 + size - 1) == 47:
        return 0
    previous = get(w, 1600040)
    if previous != 0:
        i = 0
        while i < previous and i < size and byte(w, 25000 + i) == byte(w, 20000 + i):
            i = i + 1
        if i == size or (i < previous and byte(w, 25000 + i) >= byte(w, 20000 + i)):
            return 0
    begin = 0
    pos = 0
    while pos <= size:
        if pos == size or byte(w, 20000 + pos) == 47:
            count = pos - begin
            if count == 0 or count > 255 or forbidden(w, 20000 + begin, count) == 1:
                return 0
            if pos < size:
                if previous <= pos or same(w, 20000, 25000, pos + 1) == 0:
                    put(w, 1600032, get(w, 1600032) + 1)
                begin = pos + 1
        else:
            if byte(w, 20000 + pos) < 32 or byte(w, 20000 + pos) == 127:
                return 0
        pos = pos + 1
    return choose(get(w, 1600032) <= 16384, 1, 0)

def forbidden(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 1 and byte(w, at) == 46:
        return 1
    if size == 2 and getn(w, at, 2) == 11822:
        return 1
    if size == 4 and getn(w, at, 4) == 1953064750:
        return 1
    if size == 11 and get(w, at) == 7526766689726123871 and getn(w, at + 8, 3) == 6250344:
        return 1
    return 0
'''

WALK=r'''def walk(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    depth = get(w, 1600400)
    if depth > 255:
        return finish(o, w, 65)
    row = 600000 + depth * 32
    buffer = 200000 + depth * 1024
    if phase == 1000:
        cursor = get(w, row + 8)
        count = get(w, row + 16)
        if cursor == count:
            return call(o, w, 1001, 217, get(w, row), buffer, 1024, 0, 0, 0, 12)
        if cursor > count or count - cursor < 20:
            return finish(o, w, 65)
        size = getn(w, buffer + cursor + 16, 2)
        if size < 20 or size > count - cursor:
            return finish(o, w, 65)
        pos = cursor + 19
        while pos < cursor + size and byte(w, buffer + pos) != 0:
            pos = pos + 1
        length = pos - cursor - 19
        if pos == cursor + size or length == 0 or length > 255:
            return finish(o, w, 65)
        copyw(w, 32000, buffer + cursor + 19, length)
        store(w, 32000 + length, 0)
        put(w, row + 8, cursor + size)
        if (length == 1 and byte(w, 32000) == 46) or (length == 2 and getn(w, 32000, 2) == 11822):
            return resume(s, o, w, 1000)
        if forbidden(w, 32000, length) == 1:
            return finish(o, w, 65)
        return open_path(o, w, get(w, row), 32000, 657408, 0, 1002)
    if phase == 1001:
        if r > 1024:
            return finish(o, w, 74)
        if r == 0:
            return call(o, w, 1005, 74, get(w, row), 0, 0, 0, 0, 0, 0)
        put(w, row + 8, 0)
        put(w, row + 16, r)
        return resume(s, o, w, 1000)
    if phase == 1002:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600456, r)
        return call(o, w, 1003, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 1003:
        kind = getn(w, 1224, 4) & 61440
        if kind == 32768:
            if private_file(w) == 0:
                return finish(o, w, 65)
            put(w, 1600408, get(w, 1600408) + 1)
            if get(w, 1600408) > word_load(s, 48):
                return finish(o, w, 65)
            return call(o, w, 1004, 3, get(w, 1600456), 0, 0, 0, 0, 0, 0)
        if kind != 16384 or private_dir(w) == 0 or depth == 255:
            return finish(o, w, 65)
        put(w, 1600416, get(w, 1600416) + 1)
        if get(w, 1600416) > get(w, 1600032):
            return finish(o, w, 65)
        put(w, 1600400, depth + 1)
        put(w, row + 32, get(w, 1600456))
        put(w, row + 40, 0)
        put(w, row + 48, 0)
        return resume(s, o, w, 1000)
    if phase == 1004:
        return resume(s, o, w, 1000)
    if phase == 1005:
        if depth == 0:
            if get(w, 1600408) != word_load(s, 48) or get(w, 1600416) != get(w, 1600032):
                return finish(o, w, 65)
            return call(o, w, 1007, 74, word_load(s, 24), 0, 0, 0, 0, 0, 0)
        return call(o, w, 1006, 3, get(w, row), 0, 0, 0, 0, 0, 0)
    if phase == 1006:
        put(w, 1600400, depth - 1)
        return resume(s, o, w, 1000)
    if phase == 1007:
        fill_range(w, 18000, 128, 0)
        put(w, 18000, RECEIPT)
        put(w, 18008, word_load(s, 8))
        put(w, 18016, word_load(s, 48))
        put(w, 18024, get(w, 1600416))
        i = 0
        while i < 32:
            store(w, 18032 + i, byte(s, 64 + i))
            i = i + 1
        put(w, 18064, 1)
        put(w, 18072, 1)
        put(w, 18080, 1)
        put(w, 18088, 1)
        put(w, 18096, 16384)
        put(w, 18104, 4095)
        put(w, 18112, 256)
        put(w, 18120, 67108864)
        put(w, 1600464, 0)
        return call(o, w, 1008, 1, 1, 18000, 128, 0, 0, 0, 12)
    if phase == 1008:
        if r == 0 or r > 128 - get(w, 1600464):
            return finish(o, w, 74)
        put(w, 1600464, get(w, 1600464) + r)
        if get(w, 1600464) < 128:
            return call(o, w, 1008, 1, 1, 18000 + get(w, 1600464), 128 - get(w, 1600464), 0, 0, 0, 12)
        return finish(o, w, 0)
    return finish(o, w, 65)
'''


def source():
    nodes={node.name:ast.get_source_segment(POLICY,node) for node in ast.parse(POLICY).body}
    helpers='\n\n'.join(nodes[name] for name in ('writing','writing_at','reading','copying','transfer',
        'hash_view','hashing','resume','sha','call','finish','minimum','same','copyw','failed','uint','get','getn','put'))
    helpers=helpers.replace('return getn(w, at, 8)','return word_load(w, at)')
    text=SOURCE+'\n'+EXTRA+'\n'+WALK+'\n'+helpers
    for name,raw in [('REQUEST',b'HIASXQ01'),('MANIFEST',b'HIASXM01'),('RECEIPT',b'HIASXR01')]:
        text=re.sub(r'\b'+name+r'\b',str(int.from_bytes(raw,'little')),text)
    for old,raw in [(1953064750,b'.git'),(7526766689726123871,b'__pycach'),(6250344,b'e__')]:
        text=re.sub(r'\b'+str(old)+r'\b',str(int.from_bytes(raw,'little')),text)
    text+='\n\ndef constants(w:mutbuf) -> u64:\n'
    for at,raw in [(10000,b'source'),(10016,b'home'),(10032,b'tmp')]:
        text+=f'    put(w, {at}, {int.from_bytes(raw+b"\0","little")})\n'
    return text+'    return 0\n'


if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/cold_source_export.hepta'
    path.write_text(render_assembly(document(source(),'cold_source_export')))
    print(path.name,path.stat().st_size)
