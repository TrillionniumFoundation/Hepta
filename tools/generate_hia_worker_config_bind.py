"""Author the FD-owned native runtime configuration binder; Python is authoring only."""
from pathlib import Path
import ast,re,struct,subprocess,tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_controller_install import COMMON, POLICY as CONTROLLER, LINK_SOURCE
from tools.generate_hia_release_owner import POLICY as RELEASE
from tools.generate_hia_worker_config_json import source_program as json_source, document as config_document

ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    r = get(w, 8)
    if phase < 100:
        return admission(s, o, w, phase, r)
    if phase < 180:
        return execution(s, o, w, phase, r)
    if phase <= 183:
        return make_frame(s, o, w, phase, r)
    if phase < 250:
        return transfer(s, o, w, phase, r)
    if phase < 300:
        return hashing(s, o, w, phase, r)
    if phase < 400:
        return view_file(s, o, w, phase, r)
    if phase < 500:
        return normalize_file(s, o, w, phase, r)
    if phase < 600:
        return parse_file(s, o, w, phase, r)
    if phase < 700:
        return derive(s, o, w, phase, r)
    return binding(s, o, w, phase, r)

def valid_request(s:readbuf) -> u64:
    if length(s) != 192 or uint(s, 0) != MAGIC_REQUEST:
        return 0
    mode = uint(s, 8)
    if mode != 1 and mode != 2 and mode != 3:
        return 0
    if uint(s, 16) == 1 or uint(s, 16) > 2147483647 or uint(s, 24) == 0:
        return 0
    if mode == 2 and uint(s, 64) != 0:
        return 0
    if mode == 1 and uint(s, 64) != 0:
        fd = uint(s, 64)
        if fd < 3 or fd > 2147483647 or fd == uint(s, 32) or fd == uint(s, 40):
            return 0
    i = 72
    while i < 128:
        if uint(s, i) != 0:
            return 0
        i = i + 8
    count = choose(mode == 1, 2, choose(mode == 3, 5, 4))
    i = 0
    while i < count:
        fd = uint(s, 32 + i * 8)
        if fd < 3 or fd > 2147483647:
            return 0
        j = 0
        while j < i:
            if fd == uint(s, 32 + j * 8):
                return 0
            j = j + 1
        i = i + 1
    if mode == 1:
        if uint(s, 48) != 0 or uint(s, 56) != 0:
            return 0
        i = 160
        while i < 192:
            if byte(s, i) != 0:
                return 0
            i = i + 1
    return 1

def admission(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 0:
        constants(w)
        if valid_request(s) == 0:
            return finish(o, w, 65)
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        if r < 2 or (uint(s, 16) != 0 and r != uint(s, 16)):
            return finish(o, w, 65)
        put(w, 1600000, r)
        return call(o, w, 2, 157, 1, 9, 0, 0, 0, 0, 0)
    if failed(r):
        return finish(o, w, 74)
    if phase == 2:
        return call(o, w, 3, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if r != get(w, 1600000):
            return finish(o, w, 65)
        return call(o, w, 4, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 4:
        put(w, 16, r)
        return call(o, w, 5, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        put(w, 24, r)
        return clock_check(o, w, 12)
    if phase == 12:
        return sealed_view(o, w, uint(s, 32), 6)
    if phase == 90:
        now = get(w, 3000) * 1000000000 + get(w, 3008)
        if now >= uint(s, 24):
            return finish(o, w, 65)
        return resume(s, o, w, get(w, 1600500))
    if phase == 6:
        if get(w, 152) == 0:
            return finish(o, w, 65)
        put(w, 1600008, get(w, 152))
        put(w, 1600016, get(w, 160))
        return hash_view(o, w, uint(s, 32), 0, get(w, 152), 7)
    if phase == 7:
        if same_input(s, w, 128, 4096, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 8, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 8:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1600024, r)
        put(w, 1600032, 0)
        return call(o, w, 9, 91, r, 256, 0, 0, 0, 0, 0)
    if phase == 9:
        return pointer(o, w, 1600800, 196608, 10)
    if phase == 10:
        return pointer(o, w, 1600808, 10000, 11)
    if phase == 11:
        put(w, 10000, 1)
        put(w, 10008, 18446744073709551615)
        put(w, 10016, 0)
        put(w, 10024, 0)
        put(w, 10032, 0)
        return resume(s, o, w, 400)
    return finish(o, w, 65)

def clock_check(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, 1600500, next)
    return call(o, w, 90, 228, 1, 3000, 0, 0, 0, 0, 12)

def sealed_view(o:mutbuf, w:mutbuf, fd:u64, next:u64) -> u32:
    put(w, 1610000, fd)
    put(w, 1610008, next)
    return call(o, w, 300, 5, fd, 1200, 0, 0, 0, 0, 12)

def view_file(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 300:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1248) > 9223372036854775807:
            return finish(o, w, 65)
        put(w, 1610016, get(w, 1248))
        return call(o, w, 301, 72, get(w, 1610000), 1034, 0, 0, 0, 0, 0)
    if phase == 301:
        if r & 15 != 15:
            return finish(o, w, 65)
        if get(w, 1610016) == 0:
            put(w, 144, get(w, 1610000))
            put(w, 152, 0)
            put(w, 160, 0)
            return resume(s, o, w, get(w, 1610008))
        return call(o, w, 302, 9, 0, get(w, 1610016), 1, 2, get(w, 1610000), 0, 0)
    if phase == 302:
        if r == 0:
            return finish(o, w, 74)
        put(w, 144, get(w, 1610000))
        put(w, 152, get(w, 1610016))
        put(w, 160, r)
        return resume(s, o, w, get(w, 1610008))
    return finish(o, w, 65)

def borrowed_call(o:mutbuf, w:mutbuf, input:u64, input_size:u64, output:u64, output_size:u64, work:u64, work_size:u64, next:u64) -> u32:
    put(o, 0, input)
    put(o, 8, input_size)
    put(o, 16, output)
    put(o, 24, output_size)
    put(o, 32, work)
    put(o, 40, work_size)
    put(w, 0, next)
    return 5

def normalize_file(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 400:
        return borrowed_call(o, w, get(w, 1600016), get(w, 1600008), get(w, 1600800), 65536, get(w, 1600808), 64, 401)
    if phase == 401:
        if r != 0 or get(w, 10032) > 65536:
            return finish(o, w, 65)
        count = get(w, 10032)
        if count == 0:
            if get(w, 10024) == 0:
                return finish(o, w, 65)
            return resume(s, o, w, 402)
        return writing_at(o, w, get(w, 1600024), 196608, count, get(w, 1600032), 402)
    if phase == 402:
        put(w, 1600032, get(w, 1600032) + get(w, 10032))
        if get(w, 10024) == 0:
            return resume(s, o, w, 400)
        if get(w, 1600032) == 0:
            return finish(o, w, 65)
        return call(o, w, 403, 72, get(w, 1600024), 1033, 15, 0, 0, 0, 0)
    if phase == 403:
        return sealed_view(o, w, get(w, 1600024), 404)
    if phase == 404:
        if get(w, 152) != get(w, 1600032):
            return finish(o, w, 65)
        put(w, 1600040, get(w, 160))
        return parse_view(o, w, get(w, 160), get(w, 152), choose(uint(s, 8) == 3, 8, 2), 600)
    return finish(o, w, 65)

def parse_view(o:mutbuf, w:mutbuf, input:u64, size:u64, mode:u64, next:u64) -> u32:
    if size == 0:
        return finish(o, w, 65)
    put(w, 1620000, input)
    put(w, 1620008, size)
    put(w, 1620016, mode)
    put(w, 1620024, next)
    if size > 9223372036854774783:
        return finish(o, w, 74)
    put(w, 1620048, choose(size + 1024 > 131816, size + 1024, 131816))
    put(w, 1620072, 4096)
    put(w, 1620088, choose(mode == 5, 5, 7))
    return call(o, w, 500, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)

def parse_header(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, 7100, get(w, 1620088))
    put(w, 7108, 0)
    put(w, 7116, get(w, 1620080))
    put(w, 7124, get(w, 1620104))
    put(w, 7132, 0)
    put(w, 7140, 0)
    return writing(o, w, get(w, 1620056), 7100, 48, next)

def parse_invoke(o:mutbuf, w:mutbuf, next:u64) -> u32:
    return borrowed_call(o, w, get(w, 1620000), get(w, 1620008),
        get(w, 1620040), get(w, 1620048), get(w, 1620064), get(w, 1620072), next)

def parse_file(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 500:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1620032, r)
        return call(o, w, 501, 77, r, get(w, 1620048), 0, 0, 0, 0, 0)
    if phase == 501:
        return call(o, w, 502, 9, 0, get(w, 1620048), 3, 1, get(w, 1620032), 0, 0)
    if phase == 502:
        put(w, 1620040, r)
        return call(o, w, 503, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 503:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1620056, r)
        return call(o, w, 504, 77, r, get(w, 1620072), 0, 0, 0, 0, 0)
    if phase == 504:
        return call(o, w, 505, 9, 0, get(w, 1620072), 3, 1, get(w, 1620056), 0, 0)
    if phase == 505:
        put(w, 1620064, r)
        put(w, 1620080, 0)
        put(w, 1620104, 0)
        return parse_header(o, w, 506)
    if phase == 506:
        return parse_invoke(o, w, 507)
    if phase == 507:
        if r != 0:
            return finish(o, w, 65)
        if get(w, 1620088) == 5:
            return reading(o, w, get(w, 1620056), 7280, 8, 32, 518)
        return reading(o, w, get(w, 1620032), 7200, 32, 0, 508)
    if phase == 508:
        if get(w, 7200) != MAGIC_COUNT or get(w, 7208) > get(w, 1620008) or get(w, 7216) > get(w, 1620008):
            return finish(o, w, 65)
        put(w, 1620080, get(w, 7208))
        put(w, 1620104, get(w, 7216))
        return call(o, w, 509, 11, get(w, 1620040), get(w, 1620048), 0, 0, 0, 0, 0)
    if phase == 509:
        return call(o, w, 510, 11, get(w, 1620064), get(w, 1620072), 0, 0, 0, 0, 0)
    if phase == 510:
        depth = get(w, 1620104)
        keys = get(w, 1620080)
        if depth > 576460752303423483 or keys > 576460752303423486:
            return finish(o, w, 74)
        output_size = 128 + (depth + 1) * 32
        output_size = choose(output_size < 131816, 131816, output_size)
        output_size = choose(output_size < get(w, 1620008) + 1024, get(w, 1620008) + 1024, output_size)
        slots = 2
        while slots < (keys + 1) * 2:
            slots = slots * 2
        if slots > 1152921504606846975:
            return finish(o, w, 74)
        work_size = slots * 16
        work_size = choose(work_size < 4096, 4096, work_size)
        put(w, 1620048, output_size)
        put(w, 1620072, work_size)
        put(w, 1620088, get(w, 1620016))
        return call(o, w, 511, 77, get(w, 1620032), output_size, 0, 0, 0, 0, 0)
    if phase == 511:
        return call(o, w, 512, 77, get(w, 1620056), get(w, 1620072), 0, 0, 0, 0, 0)
    if phase == 512:
        return call(o, w, 513, 9, 0, get(w, 1620048), 3, 1, get(w, 1620032), 0, 0)
    if phase == 513:
        put(w, 1620040, r)
        return call(o, w, 514, 9, 0, get(w, 1620072), 3, 1, get(w, 1620056), 0, 0)
    if phase == 514:
        put(w, 1620064, r)
        return parse_header(o, w, 515)
    if phase == 515:
        return parse_invoke(o, w, 516)
    if phase == 516:
        if r != 0:
            return finish(o, w, 65)
        return reading(o, w, get(w, 1620056), 7280, 8, 32, 518)
    if phase == 518:
        size = get(w, 7280)
        if size == 0 or size > get(w, 1620048):
            return finish(o, w, 65)
        put(w, 1620096, size)
        return call(o, w, 519, 11, get(w, 1620040), get(w, 1620048), 0, 0, 0, 0, 0)
    if phase == 519:
        return call(o, w, 520, 11, get(w, 1620064), get(w, 1620072), 0, 0, 0, 0, 0)
    if phase == 520:
        return call(o, w, 521, 72, get(w, 1620032), 1033, 15, 0, 0, 0, 0)
    if phase == 521:
        return call(o, w, 522, 3, get(w, 1620056), 0, 0, 0, 0, 0, 0)
    if phase == 522:
        put(w, 144, get(w, 1620032))
        put(w, 152, get(w, 1620096))
        return resume(s, o, w, get(w, 1620024))
    return finish(o, w, 65)

def derive(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 668 and r == 18446744073709551612:
        return call(o, w, 668, 1, 1, get(w, 1600400), get(w, 1600408), 0, 0, 0, 12)
    if failed(r):
        return finish(o, w, 74)
    if phase == 600:
        if get(w, 152) < 520:
            return finish(o, w, 65)
        put(w, 1600300, get(w, 144))
        put(w, 1600308, get(w, 152))
        return reading(o, w, get(w, 144), 1800000, 512, 0, 601)
    if phase == 601:
        if get(w, 1800000) != MAGIC_META or get(w, 1800008) != 2 or get(w, 1800016) > 32:
            return finish(o, w, 65)
        if get(w, 1800024) < 8 or 512 + get(w, 1800024) != get(w, 1600308):
            return finish(o, w, 65)
        return sealed_view(o, w, uint(s, 40), 603)
    if phase == 603:
        if get(w, 152) < 8:
            return finish(o, w, 65)
        return parse_view(o, w, get(w, 160), get(w, 152), 5, 604)
    if phase == 604:
        if get(w, 152) < 8:
            return finish(o, w, 65)
        put(w, 1600316, get(w, 144))
        put(w, 1600324, get(w, 152))
        return reading(o, w, get(w, 144), 2000000, 8, 0, 605)
    if phase == 605:
        if get(w, 2000000) > 32:
            return finish(o, w, 65)
        if get(w, 2000000) == 0:
            return resume(s, o, w, 606)
        if get(w, 1600324) != get(w, 1800024):
            return finish(o, w, 65)
        put(w, 1600332, 0)
        return resume(s, o, w, 610)
    if phase == 610:
        cursor = get(w, 1600332)
        if cursor == get(w, 1800024):
            return resume(s, o, w, 606)
        count = minimum(65536, get(w, 1800024) - cursor)
        put(w, 1600340, count)
        return reading(o, w, get(w, 1600300), 196608, count, 512 + cursor, 611)
    if phase == 611:
        return reading(o, w, get(w, 1600316), 262144, get(w, 1600340), get(w, 1600332), 612)
    if phase == 612:
        if same(w, 196608, 262144, get(w, 1600340)) == 0:
            return finish(o, w, 65)
        put(w, 1600332, get(w, 1600332) + get(w, 1600340))
        return resume(s, o, w, 610)
    if phase == 606:
        return call(o, w, 607, 3, get(w, 1600316), 0, 0, 0, 0, 0, 0)
    if phase == 607:
        return clock_check(o, w, 640)
    if phase == 640:
        if uint(s, 8) != 1:
            if get(w, 1800064) != 0:
                return finish(o, w, 65)
            return resume(s, o, w, 700)
        if uint(s, 64) != 0:
            return call(o, w, 660, 5, uint(s, 64), 1200, 0, 0, 0, 0, 12)
        return copying(o, w, get(w, 1600300), 1, 512, get(w, 1800024), 650)
    if phase == 650:
        return finish(o, w, 0)

    if phase == 660:
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1216) != 0 or get(w, 1248) != 0 or getn(w, 1228, 4) != get(w, 24):
            return finish(o, w, 65)
        return call(o, w, 661, 72, uint(s, 64), 3, 0, 0, 0, 0, 0)
    if phase == 661:
        if r & 3 != 2 or r & 1024 != 0:
            return finish(o, w, 65)
        return call(o, w, 662, 72, uint(s, 64), 1034, 0, 0, 0, 0, 0)
    if phase == 662:
        if r != 0:
            return finish(o, w, 65)
        return call(o, w, 663, 91, uint(s, 64), 384, 0, 0, 0, 0, 0)
    if phase == 663:
        return call(o, w, 664, 8, uint(s, 64), 0, 0, 0, 0, 0, 0)
    if phase == 664:
        return copying(o, w, get(w, 1600300), uint(s, 64), 512, get(w, 1800024), 665)
    if phase == 665:
        return call(o, w, 666, 72, uint(s, 64), 1033, 15, 0, 0, 0, 0)
    if phase == 666:
        return hash_view(o, w, uint(s, 64), 0, get(w, 1800024), 667)
    if phase == 667:
        put(w, 196608, MAGIC_ROOTS)
        put(w, 196616, 1)
        put(w, 196624, get(w, 1800024))
        copyw(w, 196632, 4096, 32)
        put(w, 196664, 0)
        put(w, 1600400, 196608)
        put(w, 1600408, 64)
        return call(o, w, 668, 1, 1, 196608, 64, 0, 0, 0, 12)
    if phase == 668:
        count = get(w, 1600408)
        if r == 0 or r > count:
            return finish(o, w, 74)
        put(w, 1600400, get(w, 1600400) + r)
        put(w, 1600408, count - r)
        if r != count:
            return call(o, w, 668, 1, 1, get(w, 1600400), count - r, 0, 0, 0, 12)
        return finish(o, w, 0)
    return finish(o, w, 65)


def binding(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase >= 1900:
        return cleanup(s, o, w, phase, r)
    if phase >= 1200:
        return native_jobs(s, o, w, phase, r)
    if phase >= 1100:
        return publication(s, o, w, phase, r)
    if phase >= 1000:
        return artifact_scope(s, o, w, phase, r)
    if phase >= 900:
        return capture_installed(s, o, w, phase, r)
    if failed(r):
        return finish(o, w, 74)
    if phase == 700:
        put(w, 1540000, uint(s, 48))
        return call(o, w, 701, 5, uint(s, 48), 1200, 0, 0, 0, 0, 12)
    if phase == 701:
        if getn(w, 1224, 4) & 61440 != 16384 or getn(w, 1228, 4) != get(w, 24) or getn(w, 1224, 4) & 63 != 0:
            return finish(o, w, 65)
        copyw(w, 1540500, 1200, 144)
        copyw(w, 2190000, C_PROC, 14)
        end = decimal(w, 2190014, uint(s, 48))
        store(w, end, 0)
        return call(o, w, 702, 267, 18446744073709551516, 2190000, 2200000, 4096, 0, 0, 60)
    if phase == 702:
        if r == 0 or r >= 4096 or byte(w, 2200000) != 47:
            return finish(o, w, 65)
        if r >= 10 and same(w, 2200000 + r - 10, C_DELETED, 10) == 1:
            return finish(o, w, 65)
        if r + 18 >= 4096:
            return finish(o, w, 65)
        put(w, 1540008, r)
        store(w, 2200000 + r, 0)
        copyw(w, 2205000, 2200000, r)
        copyw(w, 2205000 + r, C_ENTRY_SUFFIX, 18)
        copyw(w, 2210000, 2200000, r)
        copyw(w, 2210000 + r, C_PROFILE_SUFFIX, 13)
        put(w, 1540016, r + 17)
        put(w, 1540024, r + 12)
        return capture_start(o, w, uint(s, 48), 0, C_PROFILE, 0, 710)
    if phase == 710:
        return capture_start(o, w, uint(s, 48), 1, C_ENTRY, 1, 711)
    if phase == 711:
        return capture_start(o, w, uint(s, 48), 2, C_DESCRIPTOR, 0, 712)
    if phase == 712:
        return capture_start(o, w, uint(s, 48), 3, C_CAPSULE, 0, 713)
    if phase == 713:
        return sealed_view(o, w, uint(s, 56), 714)
    if phase == 714:
        if get(w, 152) == 0:
            return finish(o, w, 65)
        return hash_view(o, w, uint(s, 56), 0, get(w, 152), 715)
    if phase == 715:
        if same_input(s, w, 160, 4096, 32) == 0:
            return finish(o, w, 65)
        copyw(w, 2220000, C_ANCHOR_ENV, 30)
        end = decimal(w, 2220030, get(w, 1541192))
        store(w, end, 0)
        put(w, 1540040, end - 2220000)
        hex_bytes(w, 2221000, 1542000, 32)
        store(w, 2221064, 0)
        exec_args(w, 2205000, get(w, 1540016))
        exec_add_arg(w, C_B, 2)
        exec_add_arg(w, C_E, 2)
        exec_add_arg(w, C_S, 2)
        exec_add_arg(w, C_M, 2)
        exec_add_arg(w, C_MODULE, 22)
        exec_add_arg(w, C_QUERY, 23)
        exec_add_arg(w, C_HELPERS, 25)
        exec_add_arg(w, 2210000, get(w, 1540024))
        exec_add_arg(w, C_EXPECT, 32)
        exec_add_arg(w, 2221000, 64)
        exec_pass(w, get(w, 1541192))
        put(w, 1510152, 15000000000)
        return bytes_frame(o, w, 196608, 0, 716)
    if phase == 716:
        return start_exec(o, w, get(w, 1541200), get(w, 1530024), uint(s, 48), 0, 0, 0, 718)
    if phase == 718:
        if get(w, 168) != 0 or get(w, 152) == 0:
            return finish(o, w, 65)
        put(w, 1540032, get(w, 144))
        return sealed_view(o, w, get(w, 144), 719)
    if phase == 719:
        return parse_view(o, w, get(w, 160), get(w, 152), 3, 720)
    if phase == 720:
        if get(w, 152) != 144:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 1543000, 144, 0, 721)
    if phase == 721:
        if get(w, 1543000) != MAGIC_PINS or get(w, 1543008) != 4 or same(w, 1543112, 1542000, 32) == 0:
            return finish(o, w, 65)
        return sealed_view(o, w, get(w, 1541392), 722)
    if phase == 722:
        return parse_view(o, w, get(w, 160), get(w, 152), 4, 723)
    if phase == 723:
        if get(w, 152) != 40:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 1543200, 40, 0, 724)
    if phase == 724:
        if get(w, 1543200) != MAGIC_DESC or same(w, 1543208, 1542096, 32) == 0:
            return finish(o, w, 65)
        if get(w, 1541592) < 56:
            return finish(o, w, 65)
        return reading(o, w, get(w, 1541584), 1544000, 56, 0, 1000)
    if phase == 740:
        if prepare_values(w) == 0:
            return finish(o, w, 65)
        if uint(s, 8) == 3:
            return resume(s, o, w, 1200)
        return open_output(s, o, w)
    return finish(o, w, 65)

def open_output(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 3088, 655554)
    put(w, 3096, 384)
    put(w, 3104, 14)
    return call(o, w, 1100, 437, uint(s, 48), C_TEMP, 3088, 24, 0, 0, 60)

def capture_record(index:u64) -> u64:
    if index < 4:
        return 1541000 + index * 192
    return 2700000 + (index - 4) * 192

def capture_digest(index:u64) -> u64:
    if index < 4:
        return 1542000 + index * 32
    return 2702000 + (index - 4) * 32

def capture_start(o:mutbuf, w:mutbuf, dir:u64, index:u64, path:u64, executable:u64, next:u64) -> u32:
    put(w, 1550000, index)
    put(w, 1550008, path)
    put(w, 1550016, executable)
    put(w, 1550024, next)
    put(w, 3088, 657408)
    put(w, 3096, 0)
    put(w, 3104, 14)
    return call(o, w, 900, 437, dir, path, 3088, 24, 0, 0, 60)

def capture_installed(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    record = capture_record(get(w, 1550000))
    if phase == 900:
        if r < 3:
            return finish(o, w, 74)
        put(w, record, r)
        put(w, record + 24, get(w, 1550008))
        return call(o, w, 901, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 901:
        owner = getn(w, 1228, 4)
        if getn(w, 1224, 4) & 61440 != 32768 or get(w, 1216) != 1 or getn(w, 1224, 4) & 18 != 0:
            return finish(o, w, 65)
        if owner != 0 and owner != get(w, 24):
            return finish(o, w, 65)
        size = get(w, 1248)
        if size == 0 or size > 9223372036854775807:
            return finish(o, w, 65)
        if get(w, 1550000) >= 4:
            if size > job_role_limit(get(w, 1550000) - 4):
                return finish(o, w, 65)
            if get(w, 1550000) > 4 and (size < 64 or getn(w, 1224, 4) & 73 == 0):
                return finish(o, w, 65)
        put(w, record + 16, size)
        copyw(w, record + 32, 1200, 144)
        return call(o, w, 902, 319, C_MEMFD, 2, 0, 0, 0, 0, 3)
    if phase == 902:
        if r < 3:
            return finish(o, w, 74)
        put(w, record + 8, r)
        return call(o, w, 903, 91, r, choose(get(w, 1550016) == 1, 320, 256), 0, 0, 0, 0, 0)
    if phase == 903:
        return copying(o, w, get(w, record), get(w, record + 8), 0, get(w, record + 16), 904)
    if phase == 904:
        return call(o, w, 905, 5, get(w, record), 1200, 0, 0, 0, 0, 12)
    if phase == 905:
        if same(w, record + 32, 1200, 72) == 0 or same(w, record + 120, 1288, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 906, 72, get(w, record + 8), 1033, 15, 0, 0, 0, 0)
    if phase == 906:
        return hash_view(o, w, get(w, record + 8), 0, get(w, record + 16), 907)
    if phase == 907:
        copyw(w, capture_digest(get(w, 1550000)), 4096, 32)
        return resume(s, o, w, get(w, 1550024))
    return finish(o, w, 65)

def artifact_scope(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 1000:
        total = get(w, 1541592)
        count = get(w, 1544016)
        if get(w, 1544008) != 1 or count > divide(total - 56, 48):
            return finish(o, w, 65)
        at = 56 + count * 48
        index = 0
        while index < 3:
            size = get(w, 1544024 + index * 8)
            if size > total - at:
                return finish(o, w, 65)
            at = at + size
            index = index + 1
        if get(w, 1544048) != total - at or total - at < 88:
            return finish(o, w, 65)
        put(w, 1560000, at)
        return reading(o, w, get(w, 1541584), 1545000, 88, at, 1001)
    if phase == 1001:
        total = get(w, 1541592)
        at = get(w, 1560000)
        size = get(w, 1545072)
        count = get(w, 1545080)
        if get(w, 1545000) != MAGIC_ARTIFACT or count != get(w, 1800016) or count > 32 or size > total - at - 88:
            return finish(o, w, 65)
        at = at + 88 + size
        tail = total - at
        if tail > 131296 or tail + 8 != get(w, 1800024):
            return finish(o, w, 65)
        put(w, 1560008, at)
        put(w, 1560016, tail)
        put(w, 2000000, count)
        if tail == 0:
            return resume(s, o, w, 1002)
        return reading(o, w, get(w, 1541584), 2000008, tail, at, 1002)
    if phase == 1002:
        index = 0
        at = 2000008
        end = 2000008 + get(w, 1560016)
        while index < get(w, 2000000):
            if at > end or end - at < 8:
                return finish(o, w, 65)
            size = get(w, at)
            if size > 4095 or size > end - at - 8:
                return finish(o, w, 65)
            at = at + 8 + size
            index = index + 1
        if at != end:
            return finish(o, w, 65)
        return reading(o, w, get(w, 1600300), 1800512, get(w, 1800024), 512, 1003)
    if phase == 1003:
        if same(w, 1800512, 2000000, get(w, 1800024)) == 0:
            return finish(o, w, 65)
        return clock_check(o, w, 740)
    return finish(o, w, 65)

def prepare_values(w:mutbuf) -> u64:
    i = 0
    while i < 4:
        at = 2230000 + i * 32768
        store(w, at, 34)
        hex_bytes(w, at + 1, 1543016 + i * 32, 32)
        store(w, at + 65, 34)
        put(w, 1570100 + i * 8, 66)
        i = i + 1
    size = quote_path(w, 2205000, get(w, 1540016), 2361072)
    if size == 0:
        return 0
    put(w, 1570132, size)
    size = quote_path(w, 2210000, get(w, 1540024), 2393840)
    if size == 0:
        return 0
    put(w, 1570140, size)
    at = 2500000
    fields = get(w, 1800048)
    i = 0
    while i < 6:
        if get(w, 1800056) & (1 << i) == 0:
            if fields != 0:
                store(w, at, 44)
                at = at + 1
            size = field_name_size(i)
            copyw(w, at, field_name(i), size)
            at = at + size
            copyw(w, at, 2230000 + i * 32768, get(w, 1570100 + i * 8))
            at = at + get(w, 1570100 + i * 8)
            fields = fields + 1
        i = i + 1
    put(w, 1570080, at - 2500000)
    return 1

def quote_path(w:mutbuf, source:u64, size:u64, target:u64) -> u64:
    if valid_utf8(w, source, size) == 0:
        return 0
    at = target
    store(w, at, 34)
    at = at + 1
    i = 0
    while i < size:
        ch = byte(w, source + i)
        if ch == 0:
            return 0
        if ch == 34 or ch == 92:
            store(w, at, 92)
            store(w, at + 1, ch)
            at = at + 2
        else:
            if ch < 32:
                store(w, at, 92)
                store(w, at + 1, 117)
                store(w, at + 2, 48)
                store(w, at + 3, 48)
                store(w, at + 4, hex_digit(ch >> 4))
                store(w, at + 5, hex_digit(ch & 15))
                at = at + 6
            else:
                store(w, at, ch)
                at = at + 1
        i = i + 1
    store(w, at, 34)
    return at + 1 - target

def valid_utf8(w:mutbuf, start:u64, size:u64) -> u64:
    at = start
    end = start + size
    while at < end:
        ch = byte(w, at)
        at = at + 1
        if ch >= 128:
            count = 0
            minimum = 0
            cp = 0
            if ch >= 194 and ch <= 223:
                count = 1
                minimum = 128
                cp = ch & 31
            if ch >= 224 and ch <= 239:
                count = 2
                minimum = 2048
                cp = ch & 15
            if ch >= 240 and ch <= 244:
                count = 3
                minimum = 65536
                cp = ch & 7
            if count == 0 or count > end - at:
                return 0
            i = 0
            while i < count:
                ch = byte(w, at)
                if ch < 128 or ch > 191:
                    return 0
                cp = cp * 64 + (ch & 63)
                at = at + 1
                i = i + 1
            if cp < minimum or cp > 1114111 or (cp >= 55296 and cp <= 57343):
                return 0
    return 1

def exec_request(s:readbuf, w:mutbuf) -> u64:
    at = 458752
    put(w, at, MAGIC_SUB)
    put(w, at + 8, get(w, 16))
    put(w, at + 16, get(w, 1510080))
    put(w, at + 24, get(w, 1510008))
    put(w, at + 32, get(w, 1510016))
    put(w, at + 40, get(w, 1510112))
    put(w, at + 48, get(w, 1510120))
    put(w, at + 56, get(w, 1510024))
    put(w, at + 64, get(w, 1510128))
    put(w, at + 72, get(w, 1510048))
    put(w, at + 80, 2)
    put(w, at + 88, 67108864)
    put(w, at + 96, 65536)
    put(w, at + 104, 100000000)
    put(w, at + 112, 2147483648)
    put(w, at + 120, 0)
    copyw(w, at + 128, 1700000, get(w, 1510056))
    at = arg(w, at + 128 + get(w, 1510056), C_ENV, 5)
    at = arg(w, at, 2220000, get(w, 1540040))
    put(w, at, MAGIC_PASS)
    put(w, at + 8, get(w, 1510064))
    copyw(w, at + 16, 1510400, get(w, 1510064) * 8)
    return at + 16 + get(w, 1510064) * 8 - 458752

def next_edit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if uint(s, 8) == 3:
        return jobs_next_edit(s, o, w)
    selected = 6
    first = 18446744073709551615
    i = 0
    while i < 6:
        start = get(w, 1800128 + i * 24)
        if get(w, 1570024) & (1 << i) == 0 and start < first:
            selected = i
            first = start
        i = i + 1
    cursor = get(w, 1570016)
    if selected == 6:
        end = get(w, 1800040) - 1
        if end < cursor or end >= get(w, 1600032):
            return finish(o, w, 65)
        put(w, 1570040, end)
        return copying(o, w, get(w, 1600024), get(w, 1570000), cursor, end - cursor, 1110)
    end = get(w, 1800136 + selected * 24)
    if first < cursor or end < first or end > get(w, 1600032):
        return finish(o, w, 65)
    put(w, 1570032, selected)
    put(w, 1570040, first)
    put(w, 1570048, end)
    return copying(o, w, get(w, 1600024), get(w, 1570000), cursor, first - cursor, 1104)

def publication(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1180 and r == 18446744073709551612:
        return call(o, w, 1180, 1, 1, get(w, 1570200), get(w, 1570208), 0, 0, 0, 12)
    if failed(r):
        return finish(o, w, 74)
    if phase == 1100:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1570000, r)
        put(w, 1570056, 1)
        return call(o, w, 1101, 91, r, 384, 0, 0, 0, 0, 0)
    if phase == 1101:
        put(w, 1570008, 0)
        put(w, 1570016, 0)
        put(w, 1570024, 0)
        return next_edit(s, o, w)
    if phase == 1104:
        size = get(w, 1570040) - get(w, 1570016)
        put(w, 1570008, get(w, 1570008) + size)
        index = get(w, 1570032)
        return writing_at(o, w, get(w, 1570000), edit_value(index), get(w, 1570100 + index * 8), get(w, 1570008), 1105)
    if phase == 1105:
        index = get(w, 1570032)
        put(w, 1570008, get(w, 1570008) + get(w, 1570100 + index * 8))
        put(w, 1570016, get(w, 1570048))
        put(w, 1570024, get(w, 1570024) | (1 << index))
        return call(o, w, 1106, 8, get(w, 1570000), get(w, 1570008), 0, 0, 0, 0, 0)
    if phase == 1106:
        return next_edit(s, o, w)
    if phase == 1110:
        put(w, 1570008, get(w, 1570008) + get(w, 1570040) - get(w, 1570016))
        if uint(s, 8) == 3:
            return call(o, w, 1114, 75, get(w, 1570000), 0, 0, 0, 0, 0, 0)
        return writing_at(o, w, get(w, 1570000), 2500000, get(w, 1570080), get(w, 1570008), 1111)
    if phase == 1111:
        put(w, 1570008, get(w, 1570008) + get(w, 1570080))
        return call(o, w, 1112, 8, get(w, 1570000), get(w, 1570008), 0, 0, 0, 0, 0)
    if phase == 1112:
        return copying(o, w, get(w, 1600024), get(w, 1570000), get(w, 1570040), get(w, 1600032) - get(w, 1570040), 1113)
    if phase == 1113:
        put(w, 1570008, get(w, 1570008) + get(w, 1600032) - get(w, 1570040))
        return call(o, w, 1114, 75, get(w, 1570000), 0, 0, 0, 0, 0, 0)
    if phase == 1114:
        return hash_view(o, w, get(w, 1570000), 0, get(w, 1570008), 1115)
    if phase == 1115:
        copyw(w, 1570300, 4096, 32)
        put(w, 1570096, 0)
        return resume(s, o, w, 1120)
    if phase == 1120:
        index = get(w, 1570096)
        if index == choose(uint(s, 8) == 3, 10, 4):
            return clock_check(o, w, 1130)
        record = capture_record(index)
        put(w, 3088, 657408)
        put(w, 3096, 0)
        put(w, 3104, 14)
        return call(o, w, 1121, 437, uint(s, 48), get(w, record + 24), 3088, 24, 0, 0, 60)
    if phase == 1121:
        if r < 3:
            return finish(o, w, 74)
        put(w, 1570340, r)
        return call(o, w, 1122, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 1122:
        record = capture_record(get(w, 1570096))
        if same(w, record + 32, 1200, 72) == 0 or same(w, record + 120, 1288, 32) == 0:
            return finish(o, w, 65)
        return call(o, w, 1123, 3, get(w, 1570340), 0, 0, 0, 0, 0, 0)
    if phase == 1123:
        put(w, 1570096, get(w, 1570096) + 1)
        return resume(s, o, w, 1120)
    if phase == 1130:
        return call(o, w, 1131, 265, uint(s, 48), C_TEMP, uint(s, 48), C_OUTPUT, 0, 0, 204)
    if phase == 1131:
        put(w, 1570064, 1)
        return call(o, w, 1132, 263, uint(s, 48), C_TEMP, 0, 0, 0, 0, 12)
    if phase == 1132:
        put(w, 1570056, 0)
        return call(o, w, 1133, 74, uint(s, 48), 0, 0, 0, 0, 0, 0)
    if phase == 1133:
        put(w, 196608, MAGIC_OUTPUT)
        put(w, 196616, 1)
        put(w, 196624, get(w, 1570008))
        copyw(w, 196632, 1570300, 32)
        copyw(w, 196664, 1542000, 32)
        put(w, 196696, 0)
        put(w, 1570200, 196608)
        put(w, 1570208, 96)
        return call(o, w, 1180, 1, 1, 196608, 96, 0, 0, 0, 12)
    if phase == 1180:
        count = get(w, 1570208)
        if r == 0 or r > count:
            return finish(o, w, 74)
        put(w, 1570200, get(w, 1570200) + r)
        put(w, 1570208, count - r)
        if r != count:
            return call(o, w, 1180, 1, 1, get(w, 1570200), count - r, 0, 0, 0, 12)
        return finish(o, w, 0)
    return finish(o, w, 65)

def native_jobs(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if failed(r):
        return finish(o, w, 74)
    if phase == 1200:
        return sealed_view(o, w, uint(s, 64), 1201)
    if phase == 1201:
        if get(w, 152) != 96:
            return finish(o, w, 65)
        return reading(o, w, uint(s, 64), 2630000, 96, 0, 1202)
    if phase == 1202:
        if get(w, 2630000) != MAGIC_CONTROLLER or get(w, 2630008) != 26 or get(w, 2630016) != 20 or get(w, 2630088) != 0:
            return finish(o, w, 65)
        if jobs_paths(w) == 0:
            return finish(o, w, 65)
        return capture_start(o, w, uint(s, 48), 4, 2600000, 0, 1203)
    if phase == 1203:
        if same(w, capture_digest(4), 2630056, 32) == 0:
            return finish(o, w, 65)
        row = capture_record(4)
        return sealed_view(o, w, get(w, row + 8), 1204)
    if phase == 1204:
        return parse_view(o, w, get(w, 160), get(w, 152), 6, 1205)
    if phase == 1205:
        if get(w, 152) != 624:
            return finish(o, w, 65)
        return reading(o, w, get(w, 144), 2630200, 624, 0, 1206)
    if phase == 1206:
        if get(w, 2630200) != MAGIC_JOBS or get(w, 2630208) != 19:
            return finish(o, w, 65)
        put(w, 2631000, 0)
        return resume(s, o, w, 1210)
    if phase == 1210:
        index = get(w, 2631000)
        if index == 5:
            if jobs_values(w) == 0:
                return finish(o, w, 65)
            return clock_check(o, w, 1290)
        return capture_start(o, w, uint(s, 48), index + 5, 2600000 + (index + 1) * 4096, 1, 1211)
    if phase == 1211:
        index = get(w, 2631000)
        if same(w, capture_digest(index + 5), 2630216 + index * 32, 32) == 0:
            return finish(o, w, 65)
        row = capture_record(index + 5)
        return reading(o, w, get(w, row + 8), 2631200, 20, 0, 1212)
    if phase == 1212:
        if getn(w, 2631200, 7) != MAGIC_ELF or getn(w, 2631216, 4) != 4063234:
            return finish(o, w, 65)
        put(w, 2631000, get(w, 2631000) + 1)
        return resume(s, o, w, 1210)
    if phase == 1290:
        return open_output(s, o, w)
    return finish(o, w, 65)

def jobs_paths(w:mutbuf) -> u64:
    index = 0
    while index < 6:
        at = 2600000 + index * 4096
        size = job_role_size(index)
        if get(w, 1540008) + 77 + size >= 4096:
            return 0
        copyw(w, at, C_CONTROLLER, 11)
        hex_bytes(w, at + 11, 2630024, 32)
        store(w, at + 75, 47)
        copyw(w, at + 76, job_role_name(index), size)
        store(w, at + 76 + size, 0)
        index = index + 1
    return 1

def jobs_values(w:mutbuf) -> u64:
    at = 2800000
    start = get(w, 1800344)
    end = get(w, 1800352)
    if start == 18446744073709551615:
        start = get(w, 1800328) - 1
        end = start
        if get(w, 1800336) != 0:
            store(w, at, 44)
            at = at + 1
        copyw(w, at, C_JOBS_KEY, 15)
        at = at + 15
    else:
        store(w, at, 123)
        at = at + 1
    put(w, 1800296, start)
    put(w, 1800304, end)
    put(w, 1800312, 7)
    index = 0
    while index < 5:
        if index != 0:
            store(w, at, 44)
            at = at + 1
        size = job_field_size(index)
        copyw(w, at, job_field_name(index), size)
        at = at + size
        root_size = get(w, 1540008)
        path_size = 76 + job_role_size(index + 1)
        copyw(w, 2640000, 2200000, root_size)
        store(w, 2640000 + root_size, 47)
        copyw(w, 2640001 + root_size, 2600000 + (index + 1) * 4096, path_size)
        quoted = quote_path(w, 2640000, root_size + 1 + path_size, 2750000)
        if quoted == 0 or quoted > 32768:
            return 0
        copyw(w, at, 2750000, quoted)
        at = at + quoted
        copyw(w, at, C_JOBS_SHA, 11)
        at = at + 11
        hex_bytes(w, at, 2630216 + index * 32, 32)
        at = at + 64
        store(w, at, 34)
        store(w, at + 1, 125)
        at = at + 2
        index = index + 1
    store(w, at, 125)
    at = at + 1
    if at > 3000000:
        return 0
    put(w, 1570156, at - 2800000)
    put(w, 1800272, get(w, 1800040) - 1)
    put(w, 1800280, get(w, 1800040) - 1)
    put(w, 1800288, 6)
    put(w, 1570148, get(w, 1570080))
    return 1

def edit_value(index:u64) -> u64:
    if index == 6:
        return 2500000
    if index == 7:
        return 2800000
    return 2230000 + index * 32768

def jobs_next_edit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    selected = 8
    first = 18446744073709551615
    i = 0
    while i < 8:
        start = get(w, 1800128 + i * 24)
        if get(w, 1570024) & (1 << i) == 0 and start < first:
            selected = i
            first = start
        i = i + 1
    cursor = get(w, 1570016)
    if selected == 8:
        if cursor > get(w, 1600032):
            return finish(o, w, 65)
        put(w, 1570040, get(w, 1600032))
        return copying(o, w, get(w, 1600024), get(w, 1570000), cursor, get(w, 1600032) - cursor, 1110)
    end = get(w, 1800136 + selected * 24)
    if first < cursor or end < first or end > get(w, 1600032):
        return finish(o, w, 65)
    put(w, 1570032, selected)
    put(w, 1570040, first)
    put(w, 1570048, end)
    return copying(o, w, get(w, 1600024), get(w, 1570000), cursor, first - cursor, 1104)

def finish(o:mutbuf, w:mutbuf, code:u64) -> u32:
    if code != 0 and (get(w, 1570056) != 0 or get(w, 1570064) != 0):
        put(w, 1570072, code)
        if get(w, 1570064) != 0:
            return call(o, w, 1900, 263, get(w, 1540000), C_OUTPUT, 0, 0, 0, 0, 12)
        return call(o, w, 1901, 263, get(w, 1540000), C_TEMP, 0, 0, 0, 0, 12)
    return call(o, w, 1999, 60, code, 0, 0, 0, 0, 0, 0)

def cleanup(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 1900:
        put(w, 1570064, 0)
        if get(w, 1570056) != 0:
            return call(o, w, 1901, 263, get(w, 1540000), C_TEMP, 0, 0, 0, 0, 12)
    if phase == 1901:
        put(w, 1570056, 0)
    return call(o, w, 1999, 60, get(w, 1570072), 0, 0, 0, 0, 0, 0)
'''

def constant_source():
    data={'C_MEMFD':b'hia-worker-config-bind\0','C_EMPTY':b'\0',
          'C_RUNNER':b'hia-subprocess\0','C_CHILD':b'hia-config-child\0','C_ENV':b'PATH=\0',
          'C_PROFILE':b'worker.json\0','C_ENTRY':b'hia-agent-worker\0',
          'C_DESCRIPTOR':b'evaluate-full-worker.json\0','C_CAPSULE':b'evaluate-full-worker-capsule.bin\0',
          'C_OUTPUT':b'runtime-config.json\0','C_TEMP':b'.hia-runtime-config.tmp\0',
          'C_PROC':b'/proc/self/fd/','C_DELETED':b' (deleted)',
          'C_ENTRY_SUFFIX':b'/hia-agent-worker\0','C_PROFILE_SUFFIX':b'/worker.json\0',
          'C_ANCHOR_ENV':b'HEPTA_RUNTIME_WORKER_ENTRY_FD=',
          'C_B':b'-B\0','C_E':b'-E\0','C_S':b'-s\0','C_M':b'-m\0',
          'C_MODULE':b'hepta.hia_agent_worker\0','C_QUERY':b'--installation-manifest\0',
          'C_HELPERS':b'--native-helpers-manifest\0','C_EXPECT':b'--expected-native-helpers-sha256\0',
          'C_CONTROLLER':b'controller/','C_JOBS_KEY':b'"native_jobs":{','C_JOBS_SHA':b',"sha256":"'}
    roles=('hia-controller.json','hia-job-entry','hia-job-submit','hia-job-observation','hia-job-cancel','hia-job-launch')
    job_fields=('entry','submit','observation','cancel','launcher')
    for i,name in enumerate(roles):data['C_JR'+str(i)]=name.encode()
    for i,name in enumerate(job_fields):data['C_JF'+str(i)]=('"'+name+'":{"executable":').encode()
    fields=('worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256','python_executable','native_helpers_manifest')
    for i,key in enumerate(fields):data['C_F'+str(i)]=('\"'+key+'\":').encode()
    words={};lines=[];at=600000
    for name,raw in data.items():
        words[name]=at
        for i in range(0,len(raw),8):
            part=raw[i:i+8];lines.append(f'    write(w, {at+i}, {int.from_bytes(part,"little")}, {len(part)})')
        at=(at+len(raw)+7)&~7
    words.update({k:int.from_bytes(v,'little') for k,v in {
      'MAGIC_REQUEST':b'HIAWCB01','MAGIC_META':b'HIAWCM01','MAGIC_COUNT':b'HIAWCQ01',
      'MAGIC_OUTPUT':b'HIAWCO01','MAGIC_ROOTS':b'HIAWCR01','MAGIC_PINS':b'HIAWCP01','MAGIC_DESC':b'HIAWCD01',
      'MAGIC_SUB':b'HIASUB01','MAGIC_PASS':b'HIAPFD01','MAGIC_SUBRECEIPT':b'HIASBR01',
      'MAGIC_CONTROLLER':b'HIACTO01','MAGIC_JOBS':b'HIAWCJ01','MAGIC_ELF':b'\x7fELF\x02\x01\x01'}.items()})
    from tools.generate_hia_readonly_worker_capsule import ARTIFACT_CONFIG
    words['MAGIC_ARTIFACT']=int.from_bytes(ARTIFACT_CONFIG,'little')
    init='def constants(w:mutbuf) -> u64:\n'+'\n'.join(lines)+'\n    return 0\n'
    for name,values in [('field_name',[words['C_F'+str(i)] for i in range(6)]),('field_name_size',[len(data['C_F'+str(i)]) for i in range(6)]),
                        ('job_role_name',[words['C_JR'+str(i)] for i in range(6)]),
                        ('job_role_size',[len(data['C_JR'+str(i)]) for i in range(6)]),
                        ('job_role_limit',[16384,2097152,4194304,2097152,1048576,1048576]),
                        ('job_field_name',[words['C_JF'+str(i)] for i in range(5)]),
                        ('job_field_size',[len(data['C_JF'+str(i)]) for i in range(5)])]:
        init+='\ndef '+name+'(index:u64) -> u64:\n'
        for i,value in enumerate(values):init+='    if index == '+str(i)+':\n        return '+str(value)+'\n'
        init+='    return 0\n'
    return words,init

def policy_source():
    words,init=constant_source()
    write_node=next(n for n in ast.parse(LINK_SOURCE).body if isinstance(n,ast.FunctionDef) and n.name=='write')
    own=POLICY+'\n'+init+'\n'+ast.get_source_segment(LINK_SOURCE,write_node)+'\n'
    available={}
    common=COMMON.replace('1600000','1700000').replace('minimum(uint(s, 16),','minimum(uint(s, 24),')
    common=common.replace('uint(s, 48), get(w, 1510008)','uint(s, 56), get(w, 1510008)')
    for raw in (RELEASE,CONTROLLER,common):
        for n in ast.parse(raw).body:
            if isinstance(n,ast.FunctionDef):available[n.name]=ast.get_source_segment(raw,n)
    own_names={n.name for n in ast.parse(own).body if isinstance(n,ast.FunctionDef)}
    needed=set();pending=[own]
    while pending:
        for node in ast.walk(ast.parse(pending.pop())):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                name=node.func.id
                if name in available and name not in own_names and name not in needed:
                    needed.add(name);pending.append(available[name])
    code=own+'\n'+'\n\n'.join(available[n] for n in available if n in needed)
    for name,value in words.items():code=re.sub(r'\b'+name+r'\b',str(value),code)
    assert not re.findall(r'\b(?:C|MAGIC)_[A-Z_0-9]+\b',code)
    return code

def template():
    with tempfile.TemporaryDirectory(prefix='hia-config-author-') as tmp:
        obj=Path(tmp)/'abi.o';raw=Path(tmp)/'abi.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_worker_config_bind_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(at,16) for at,_,name in (row.split() for row in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
        code=raw.read_bytes()
    head=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
          +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
          +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return head+code,{n:176+symbols[n] for n in ('policy_hole','stage_hole','sha_hole')}

def packer_source():
    prefix,holes=template()
    magic=int.from_bytes(b'HIAWCBK1','little')
    code=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or uint(s, 0, 8) != {magic}:
        return 4294967295
    policy = uint(s, 8, 8)
    parser = uint(s, 16, 8)
    sha = uint(s, 24, 8)
    if policy == 0 or parser == 0 or sha == 0 or policy > 1048576 or parser > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 32 + policy + parser + sha:
        return 4294967295
    size = {len(prefix)} + policy + parser + sha
    if size > 2097152 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        part=prefix[at:at+8];code+=f'    write(o, {at}, {int.from_bytes(part,"little")}, {len(part)})\n'
    code+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name,at in holes.items():
        target=str(len(prefix))+(' + policy + parser' if name=='sha_hole' else ' + policy' if name=='stage_hole' else '')
        code+=f'    write(o, {at}, {target} - {at+4}, 4)\n'
    code+=f'    copy_bytes(s, o, 32, {len(prefix)}, policy + parser + sha)\n    return size\n'
    return code+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def main():
    for name,code in (('worker_config_bind',policy_source()),('worker_config_json',json_source()),
                      ('worker_config_bind_packer',packer_source())):
        doc=config_document(code,name) if name == 'worker_config_json' else document(code,name)
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        path.write_text(render_assembly(doc))
        print(name,path.stat().st_size,'blocks',sum(len(f['blocks']) for f in doc['functions']),
              'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
