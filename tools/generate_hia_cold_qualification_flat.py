"""Author exact native-observer checks and the causal compiler source edit."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def check(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 192 or uint(s, 0, 8) != 3544409148055103816:
        return 4294967295
    mode = uint(s, 8, 8)
    sn = uint(s, 16, 8)
    cap = uint(s, 24, 8)
    work = uint(s, 32, 8)
    initial = uint(s, 48, 8)
    expected = uint(s, 56, 8)
    words = uint(s, 80, 8)
    size = uint(s, 96, 8)
    if mode > 4 or sn > 1048576 or cap > 1048576 or work > 1048576 or initial > 1048576 or expected > 16777216 or words > 64:
        return 4294967295
    if uint(s, 40, 8) != 0 or uint(s, 88, 8) != 0 or uint(s, 104, 8) != 0 or uint(s, 112, 8) != 0 or uint(s, 120, 8) != 0:
        return 4294967295
    payload = 128 + sn + initial + expected + words * 24
    if payload > length(s) or size != length(s) - payload or size < 64:
        return 4294967295
    if uint(s, payload, 8) != 3544409160981522760 or uint(s, payload + 56, 8) != 0:
        return 4294967295
    outn = uint(s, payload + 8, 8)
    errn = uint(s, payload + 16, 8)
    rn = uint(s, payload + 24, 8)
    shn = uint(s, payload + 32, 8)
    owner = uint(s, payload + 40, 8)
    requestn = uint(s, payload + 48, 8)
    if outn > 16777216 or errn > 16777216 or rn > 4194304 or shn > 1048576 or requestn > 65536 or owner > 1:
        return 4294967295
    if size != 64 + outn + errn + rn + shn + requestn:
        return 4294967295
    receipt = payload + 64
    status = 0
    if owner == 0:
        if rn != 128 or uint(s, receipt, 8) != 3544423351558687048:
            return 4294967295
        if uint(s, receipt + 16, 8) != 0 or uint(s, receipt + 40, 8) != outn or uint(s, receipt + 48, 8) != outn or uint(s, receipt + 56, 8) != errn or uint(s, receipt + 64, 8) != errn:
            return 4294967295
        if uint(s, receipt + 72, 8) != 0 or uint(s, receipt + 80, 8) != 0 or uint(s, receipt + 88, 8) != 0 or uint(s, receipt + 96, 8) != 1 or uint(s, receipt + 104, 8) != 1 or uint(s, receipt + 120, 8) != 1:
            return 4294967295
        status = uint(s, receipt + 8, 8)
    else:
        if rn < 256 or uint(s, receipt, 8) != 3544423407124826440 or uint(s, receipt + 8, 8) > 1:
            return 4294967295
        if uint(s, receipt + 80, 8) != 0 or uint(s, receipt + 88, 8) != 1 or uint(s, receipt + 96, 8) != 1 or uint(s, receipt + 104, 8) != 1 or uint(s, receipt + 112, 8) != 0 or uint(s, receipt + 120, 8) != 0 or uint(s, receipt + 136, 8) != 0 or uint(s, receipt + 168, 8) != 0 or uint(s, receipt + 176, 8) != 1 or uint(s, receipt + 192, 8) != 0:
            return 4294967295
        if rn != 256 + uint(s, receipt + 128, 8) * 40 + uint(s, receipt + 144, 8) * 48:
            return 4294967295
        status = uint(s, receipt + 72, 8)
    if status != uint(s, 72, 8):
        return 4294967295
    raw = receipt + rn
    if mode == 3:
        if sn != 0 or cap != 0 or work != 0 or initial != 0 or expected != 0 or words != 0 or errn != 0 or shn != 0:
            return 4294967295
        return produce(s, o, raw, outn)
    if mode == 4:
        if sn != 0 or cap != 0 or work != 0 or initial != 0 or words != 0 or shn != 0 or errn != 0 or outn != expected or equal(s, 128, raw, expected) == 0:
            return 4294967295
        return success(o)
    if mode == 2:
        if initial != cap or expected != cap or shn != cap or words != 0:
            return 4294967295
        if equal(s, 128 + sn + initial, raw + outn + errn, cap) == 0:
            return 4294967295
        return success(o)
    if status != 0 or errn != 0 or outn != 24 + sn + cap + work or uint(s, raw, 8) != 3626463568929892680:
        return 4294967295
    returned = uint(s, raw + 8, 8)
    if returned > 4294967295 or equal(s, 128, raw + 24, sn) == 0:
        return 4294967295
    output = raw + 24 + sn
    if shn != 0:
        if shn != cap or equal(s, output, raw + outn + errn, cap) == 0:
            return 4294967295
    at = 128 + sn + initial + expected
    i = 0
    while i < words:
        off = uint(s, at + i * 24, 8)
        width = uint(s, at + i * 24 + 8, 8)
        value = uint(s, at + i * 24 + 16, 8)
        if width == 0 or width > 8 or off > work or width > work - off or uint(s, output + cap + off, width) != value:
            return 4294967295
        i = i + 1
    if mode == 0:
        if initial != 0 or expected != 0 or returned == 0 or returned > cap:
            return 4294967295
        return produce(s, o, output, returned)
    if returned != uint(s, 64, 8) or initial != cap or expected != cap or equal(s, 128 + sn + initial, output, cap) == 0:
        return 4294967295
    return success(o)

def produce(s:readbuf, o:mutbuf, at:u64, size:u64) -> u32:
    if length(o) < size:
        return 4294967294
    i = 0
    while i + 8 <= size:
        word_store(o, i, word_load(s, at + i))
        i = i + 8
    while i < size:
        store(o, i, byte(s, at + i))
        i = i + 1
    return size

def success(o:mutbuf) -> u32:
    if length(o) < 8:
        return 4294967294
    put(o, 0, 3544409100861524296)
    return 8

def equal(s:readbuf, a:u64, b:u64, n:u64) -> u64:
    i = 0
    while i + 8 <= n:
        if word_load(s, a + i) != word_load(s, b + i):
            return 0
        i = i + 8
    while i < n:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def uint(s:readbuf, at:u64, n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def word_store(o:mutbuf, at:u64, value:u64) -> u64:
    return put(o, at, value)
'''

MUTATION = r'''def mutate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 27 or uint(s, 0, 8) != 3544409152386124104:
        return 4294967295
    name = uint(s, 8, 8)
    size = uint(s, 16, 8)
    if name == 0 or name > 128 or size > 1048576 or length(s) != 24 + name + size:
        return 4294967295
    source = 24 + name
    if length(o) < size:
        return 4294967294
    found = 0
    begin = 0
    at = source
    while at + 4 + name < length(s):
        if byte(s, at) == 10 and byte(s, at + 1) == 102 and byte(s, at + 2) == 110 and byte(s, at + 3) == 32 and equal(s, 24, at + 4, name) == 1 and byte(s, at + 4 + name) == 40:
            found = found + 1
            begin = at
        at = at + 1
    if found != 1:
        return 4294967295
    end = begin + 1
    while end + 5 <= length(s) and uint(s, end, 5) != 44701466122:
        end = end + 1
    if end + 5 > length(s):
        return 4294967295
    at = begin
    found = 0
    replacement = 0
    while at + 12 <= end:
        if uint(s, at, 8) == 4189022202992743035 and uint(s, at + 8, 4) == 2100577834:
            found = found + 1
            replacement = at + 9
        at = at + 1
    if found != 1:
        return 4294967295
    produce(s, o, source, size)
    store(o, replacement - source, 56)
    store(o, replacement - source + 1, 48)
    return size
'''


def main():
    # Byte tags are explicit wire constants, not source hash dispatch.
    source=SOURCE
    constants={3544409148055103816:b'HIAQFV01',3544409160981522760:b'HIAQRR01',
               3626463568929892680:b'HIAOBR02',3544409100861524296:b'HIAQOK01'}
    for value,raw in constants.items():source=source.replace(str(value),str(int.from_bytes(raw,'little')))
    mutation=MUTATION.replace('3544409152386124104',str(int.from_bytes(b'HIAQMU01','little')))
    mutation=mutation.replace('44701466122',str(int.from_bytes(b'\nend\n','little')))
    old=b'{"value":64}'
    mutation=mutation.replace('4189022202992743035',str(int.from_bytes(old[:8],'little'))).replace('2100577834',str(int.from_bytes(old[8:],'little')))
    common=source[source.index('\ndef produce('):]
    linked=source.replace(str(int.from_bytes(b'HIAQFV01','little')),str(int.from_bytes(b'HIAQLV01','little')))
    linked=linked.replace('if mode > 4 or ', 'if mode > 2 or ')
    linked=linked.replace(' or uint(s, 88, 8) != 0', ' or uint(s, 88, 8) != cap + 8')
    linked=linked.replace('payload = 128 + sn + initial + expected + words * 24', 'snapshot = 128 + sn + initial + expected + words * 24\n    payload = snapshot + cap + 8')
    linked=linked.replace(str(int.from_bytes(b'HIAOBR02','little')),str(int.from_bytes(b'HIAOBR03','little')))
    linked=linked.replace('if mode == 2:\n        if initial', 'if mode == 2:\n        at = 0\n        while at < cap + 8:\n            if byte(s, snapshot + at) != 0:\n                return 4294967295\n            at = at + 1\n        if initial')
    linked=linked.replace('output = raw + 24 + sn', 'output = raw + 24 + sn\n    if uint(s, snapshot, 8) != cap + 1 or equal(s, snapshot + 8, output, cap) == 0:\n        return 4294967295')
    for name,text in (('cold_qualification_flat',source),('cold_qualification_mutation',mutation+common),('cold_qualification_linked',linked)):
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        path.write_text(render_assembly(document(text,name)))
        print(path.name,path.stat().st_size)


if __name__=='__main__':main()
