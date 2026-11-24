"""Author native release CLI policy, its mechanical packer and immutable pin binder."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,json,struct,subprocess,tempfile
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
POLICY_SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 67108864 or length(o) != 67108864 or length(w) != 8388608:
        return 0
    phase = get(w, 0)
    r = get(w, 8)
    if phase == 0:
        entry_constants(w)
        constants(w)
        result = arguments(s, w)
        if result == 2:
            return call(o, w, 900, 1, 1, 2097152 + 48000, 118, 0, 0, 0, 12)
        if result == 0:
            return finish(o, w, 64)
        return call(o, w, 700, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 700:
        if failed(r):
            return finish(o, w, 74)
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 2097152, r)
        return call(o, w, 2, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        if r < 2 or r > 2147483647:
            return finish(o, w, 65)
        put(w, 2097152 + 8, r)
        return call(o, w, 3, 157, 1, 15, 0, 0, 0, 0, 0)
    if phase == 3:
        if failed(r):
            return finish(o, w, 74)
        return call(o, w, 4, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 4:
        if r != get(w, 2097152 + 8):
            return finish(o, w, 65)
        return call(o, w, 5, 95, 63, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        put(w, 6448, 1)
        return call(o, w, 6, 13, 13, 6448, 0, 8, 0, 0, 12)
    if phase == 6:
        if failed(r):
            return finish(o, w, 74)
        return call(o, w, 7, 228, 1, 2097152 + 12288, 0, 0, 0, 0, 12)
    if phase == 7:
        if failed(r) or get(w, 2097152 + 12296) >= 1000000000:
            return finish(o, w, 74)
        deadline = get(w, 2097152 + 12288) * 1000000000 + get(w, 2097152 + 12296) + get(w, 2097152 + 224) * 1000000000
        if deadline >> 63 != 0:
            return finish(o, w, 65)
        put(w, 2097152 + 16, deadline)
        return call(o, w, 8, 267, 18446744073709551516, 2097152 + 45056, 2097152 + 32768, 4095, 0, 0, 60)
    if phase == 8:
        if failed(r) or r == 0 or r >= 4095:
            return finish(o, w, 65)
        if r >= 7 and getn(w, 2097152 + 32768, 7) == 16435939734023471:
            if byte(w, 2097152 + 53248) != 47 or dirname(w, 2097152 + 53248, get(w, 2097152 + 264), 2097152 + 32768) == 0:
                return finish(o, w, 65)
        else:
            if dirname(w, 2097152 + 32768, r, 2097152 + 32768) == 0:
                return finish(o, w, 65)
        return open_directory(o, w, 9, 18446744073709551516, 2097152 + 32768)
    if phase == 9:
        if failed(r) or r < 3:
            return finish(o, w, 65)
        put(w, 2097152 + 64, r)
        return call(o, w, 10, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 10:
        if failed(r) or getn(w, 1224, 4) & 61440 != 16384 or getn(w, 1224, 4) & 18 != 0:
            return finish(o, w, 65)
        if getn(w, 1228, 4) != get(w, 2097152) and getn(w, 1228, 4) != 0:
            return finish(o, w, 65)
        return open_directory(o, w, 11, 18446744073709551516, 2097152 + 20480)
    if phase == 11:
        if failed(r) or r < 3:
            return finish(o, w, 65)
        put(w, 2097152 + 24, r)
        return open_directory(o, w, 12, 18446744073709551516, 2097152 + 36864)
    if phase == 12:
        if failed(r) or r < 3:
            return finish(o, w, 65)
        put(w, 2097152 + 48, r)
        return call(o, w, 13, 262, r, 2097152 + 40960, 1200, 256, 0, 0, 60)
    if phase == 13:
        if r != 18446744073709551614:
            return finish(o, w, 65)
        put(w, 2097152 + 176, 0)
        return open_input(o, w)
    if phase >= 20 and phase <= 33:
        return input_phase(s, o, w, phase, r)
    if phase == 35:
        if r == 18446744073709551612:
            return read_cold(o, w)
        if failed(r) or r == 0 or r > get(w, 2097152 + 208) - get(w, 2097152 + 160):
            return finish(o, w, 74)
        put(w, 2097152 + 160, get(w, 2097152 + 160) + r)
        if get(w, 2097152 + 160) != get(w, 2097152 + 208):
            return read_cold(o, w)
        if inventory(s, o, w) == 0:
            return finish(o, w, 65)
        put(w, 2097152 + 232, 0)
        return call(o, w, 40, 318, 2097152 + 12416, 16, 0, 0, 0, 0, 3)
    if phase == 40:
        if r == 18446744073709551612:
            return call(o, w, 40, 318, 2097152 + 12416, 16, 0, 0, 0, 0, 3)
        if r != 16:
            return finish(o, w, 74)
        i = 0
        while i < 16:
            value = byte(w, 2097152 + 12416 + i)
            store(w, 2097152 + 41483 + i * 2, hex_digit(value >> 4))
            store(w, 2097152 + 41484 + i * 2, hex_digit(value & 15))
            i = i + 1
        store(w, 2097152 + 41515, 0)
        return call(o, w, 41, 258, get(w, 2097152 + 48), 2097152 + 41472, 448, 0, 0, 0, 12)
    if phase == 41:
        if r == 18446744073709551599 and get(w, 2097152 + 232) < 8:
            put(w, 2097152 + 232, get(w, 2097152 + 232) + 1)
            return call(o, w, 40, 318, 2097152 + 12416, 16, 0, 0, 0, 0, 3)
        if failed(r):
            return finish(o, w, 74)
        return open_directory(o, w, 42, get(w, 2097152 + 48), 2097152 + 41472)
    if phase == 42:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 72, r)
        return call(o, w, 43, 258, r, 2097152 + 45696, 448, 0, 0, 0, 12)
    if phase == 43:
        if failed(r):
            return finish(o, w, 74)
        return open_directory(o, w, 44, get(w, 2097152 + 72), 2097152 + 45696)
    if phase == 44:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 32, r)
        return call(o, w, 45, 258, get(w, 2097152 + 72), 2097152 + 45760, 448, 0, 0, 0, 12)
    if phase == 45:
        if failed(r):
            return finish(o, w, 74)
        return open_directory(o, w, 46, get(w, 2097152 + 72), 2097152 + 45760)
    if phase == 46:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 40, r)
        return call(o, w, 47, 258, get(w, 2097152 + 48), 2097152 + 40960, 448, 0, 0, 0, 12)
    if phase == 47:
        if failed(r):
            return finish(o, w, 65)
        return open_directory(o, w, 48, get(w, 2097152 + 48), 2097152 + 40960)
    if phase == 48:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 56, r)
        if request(o, w) == 0:
            return finish(o, w, 65)
        return call(o, w, 50, 319, 2097152 + 45824, 3, 0, 0, 0, 0, 3)
    if phase == 50:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 128, r)
        put(w, 2097152 + 160, 0)
        return call(o, w, 51, 91, r, 256, 0, 0, 0, 0, 0)
    if phase == 51:
        if failed(r):
            return finish(o, w, 74)
        return write_request(o, w)
    if phase == 52:
        if r == 18446744073709551612:
            return write_request(o, w)
        if failed(r) or r == 0 or r > get(w, 2097152 + 192) - get(w, 2097152 + 160):
            return finish(o, w, 74)
        put(w, 2097152 + 160, get(w, 2097152 + 160) + r)
        if get(w, 2097152 + 160) != get(w, 2097152 + 192):
            return write_request(o, w)
        return call(o, w, 53, 72, get(w, 2097152 + 128), 1033, 15, 0, 0, 0, 0)
    if phase == 53:
        if failed(r):
            return finish(o, w, 74)
        return call(o, w, 54, 8, get(w, 2097152 + 128), 0, 0, 0, 0, 0, 0)
    if phase == 54:
        if r != 0:
            return finish(o, w, 74)
        return call(o, w, 55, 33, get(w, 2097152 + 128), 0, 0, 0, 0, 0, 0)
    if phase == 55:
        if r != 0:
            return finish(o, w, 74)
        put(w, 2097152 + 176, 0)
        return inherit(o, w)
    if phase == 56:
        if failed(r):
            return finish(o, w, 74)
        put(w, 2097152 + 176, get(w, 2097152 + 176) + 1)
        if get(w, 2097152 + 176) < 10:
            return inherit(o, w)
        put(w, 2097152 + 49152, 2097152 + 45120)
        put(w, 2097152 + 49160, 18446744073709551615)
        put(w, 2097152 + 49168, 18446744073709551615)
        put(o, 0, 2097152 + 49152)
        put(o, 8, 3)
        put(o, 16, 2097152 + 49216)
        put(w, 0, 58)
        return 2
    if phase == 58:
        if r != 0:
            return finish(o, w, 74)
        return call(o, w, 999, 322, get(w, 2097152 + 80), 2097152 + 45952, 2097152 + 49216, 2097152 + 49232, 4096, 0, 252)
    if phase == 900:
        return finish(o, w, choose(failed(r), 74, 0))
    return finish(o, w, 74)

def input_phase(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, r:u64) -> u32:
    if phase == 20:
        if failed(r) or r < 3:
            return finish(o, w, 65)
        put(w, 2097152 + 136, r)
        return call(o, w, 21, 5, r, 1200, 0, 0, 0, 0, 12)
    if phase == 21:
        if failed(r) or getn(w, 1224, 4) & 61440 != 32768:
            return finish(o, w, 65)
        size = get(w, 1248)
        if size == 0 or size > 67108864:
            return finish(o, w, 65)
        if get(w, 2097152 + 176) < 4 and getn(w, 1224, 4) & 18 != 0:
            return finish(o, w, 65)
        copyw(w, 2097152 + 10000, 1200, 144)
        put(w, 2097152 + 152, size)
        put(w, 2097152 + 160, 0)
        return call(o, w, 22, 319, 2097152 + 45888, 3, 0, 0, 0, 0, 3)
    if phase == 22:
        if failed(r) or r < 3:
            return finish(o, w, 74)
        put(w, 2097152 + 144, r)
        return call(o, w, 23, 91, r, choose(get(w, 2097152 + 176) < 4, 320, 256), 0, 0, 0, 0, 0)
    if phase == 23:
        if failed(r):
            return finish(o, w, 74)
        return sha(o, w, 24, 0, 1)
    if phase == 24 or phase == 28:
        if r != 0:
            return finish(o, w, 74)
        return read_input(o, w)
    if phase == 25:
        if r == 18446744073709551612:
            return read_input(o, w)
        if failed(r) or r > 65536:
            return finish(o, w, 74)
        if r == 0:
            if get(w, 2097152 + 160) != get(w, 2097152 + 152):
                return finish(o, w, 65)
            return call(o, w, 29, 5, get(w, 2097152 + 136), 1200, 0, 0, 0, 0, 12)
        if get(w, 2097152 + 160) + r > get(w, 2097152 + 152):
            return finish(o, w, 65)
        put(w, 2097152 + 160, get(w, 2097152 + 160) + r)
        put(w, 2097152 + 240, r)
        put(w, 2097152 + 248, 0)
        return write_input(o, w)
    if phase == 26:
        if r == 18446744073709551612:
            return write_input(o, w)
        if failed(r) or r == 0 or r > get(w, 2097152 + 240) - get(w, 2097152 + 248):
            return finish(o, w, 74)
        put(w, 2097152 + 248, get(w, 2097152 + 248) + r)
        if get(w, 2097152 + 248) != get(w, 2097152 + 240):
            return write_input(o, w)
        return sha(o, w, 28, 1, get(w, 2097152 + 240) + 1)
    if phase == 29:
        if failed(r) or same_stat(w, 1200, 2097152 + 10000) == 0:
            return finish(o, w, 65)
        return sha(o, w, 30, 2, 1)
    if phase == 30:
        if r != 32:
            return finish(o, w, 74)
        index = get(w, 2097152 + 176)
        if index < 4 and same_bytes(w, 4096, 2097152 + 512 + index * 32, 32) == 0:
            return finish(o, w, 65)
        copyw(w, 2097152 + 768 + index * 32, 4096, 32)
        return call(o, w, 31, 72, get(w, 2097152 + 144), 1033, 15, 0, 0, 0, 0)
    if phase == 31:
        if failed(r):
            return finish(o, w, 74)
        return call(o, w, 32, 72, get(w, 2097152 + 144), 1034, 0, 0, 0, 0, 0)
    if phase == 32:
        if failed(r) or r & 15 != 15:
            return finish(o, w, 74)
        index = get(w, 2097152 + 176)
        put(w, 2097152 + 80 + index * 8, get(w, 2097152 + 144))
        if index == 5:
            put(w, 2097152 + 208, get(w, 2097152 + 152))
        return call(o, w, 33, 3, get(w, 2097152 + 136), 0, 0, 0, 0, 0, 0)
    if phase == 33:
        if failed(r):
            return finish(o, w, 74)
        put(w, 2097152 + 176, get(w, 2097152 + 176) + 1)
        if get(w, 2097152 + 176) < 6:
            return open_input(o, w)
        put(w, 2097152 + 160, 0)
        return read_cold(o, w)
    return finish(o, w, 74)

def open_directory(o:mutbuf, w:mutbuf, phase:u64, directory:u64, path:u64) -> u32:
    put(w, 2097152 + 8192, 720896)
    put(w, 2097152 + 8200, 0)
    put(w, 2097152 + 8208, 6)
    return call(o, w, phase, 437, directory, path, 2097152 + 8192, 24, 0, 0, 60)

def open_input(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 2097152 + 176)
    directory = get(w, 2097152 + 64)
    path = 2097152 + 45120 + index * 64
    if index == 4:
        directory = 18446744073709551516
        path = 2097152 + 24576
    elif index == 5:
        directory = 18446744073709551516
        path = 2097152 + 28672
    put(w, 2097152 + 8192, 657408)
    put(w, 2097152 + 8200, 0)
    put(w, 2097152 + 8208, 6)
    return call(o, w, 20, 437, directory, path, 2097152 + 8192, 24, 0, 0, 60)

def read_input(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 25, 17, get(w, 2097152 + 136), 65537, 65536, get(w, 2097152 + 160), 0, 0, 12)

def write_input(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 26, 1, get(w, 2097152 + 144), 65537 + get(w, 2097152 + 248), get(w, 2097152 + 240) - get(w, 2097152 + 248), 0, 0, 0, 12)

def read_cold(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 35, 17, get(w, 2097152 + 120), get(w, 2097152 + 160), get(w, 2097152 + 208) - get(w, 2097152 + 160), get(w, 2097152 + 160), 0, 0, 4)

def write_request(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 52, 1, get(w, 2097152 + 128), 33554432 + get(w, 2097152 + 160), get(w, 2097152 + 192) - get(w, 2097152 + 160), 0, 0, 0, 8)

def inherit(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 2097152 + 176)
    descriptor = get(o, 33554432 + 24 + index * 8)
    return call(o, w, 56, 72, descriptor, 2, 0, 0, 0, 0, 0)

def arguments(s:readbuf, w:mutbuf) -> u64:
    if uint(s, 0, 8) != 3544411325348268360:
        return 0
    count = uint(s, 8, 8)
    if count < 1 or count > 16:
        return 0
    at = 144
    first = uint(s, at, 8)
    if first == 0 or first > 4095:
        return 0
    copy(s, w, 2097152 + 53248, at + 8, first)
    store(w, 2097152 + 53248 + first, 0)
    put(w, 2097152 + 264, first)
    at = at + 9 + first
    if count == 2:
        size = uint(s, at, 8)
        if argument_equal(s, w, at + 8, size, 2097152 + 46400, 6) != 0:
            return 2
    if count < 7 or (count & 1) == 0:
        return 0
    mask = 0
    index = 1
    while index < count:
        if at + 8 > 65536:
            return 0
        size = uint(s, at, 8)
        if size > 8192 or at + 9 + size > 65536:
            return 0
        bit = 0
        target = 0
        if argument_equal(s, w, at + 8, size, 2097152 + 46080, 8) != 0:
            bit = 1
            target = 2097152 + 16384
        elif argument_equal(s, w, at + 8, size, 2097152 + 46144, 10) != 0:
            bit = 2
            target = 2097152 + 24576
        elif argument_equal(s, w, at + 8, size, 2097152 + 46208, 13) != 0:
            bit = 4
            target = 2097152 + 28672
        elif argument_equal(s, w, at + 8, size, 2097152 + 46272, 8) != 0:
            bit = 8
            target = 2097152 + 20480
        elif argument_equal(s, w, at + 8, size, 2097152 + 46336, 17) != 0:
            bit = 16
        if bit == 0 or mask & bit != 0:
            return 0
        mask = mask | bit
        at = at + 9 + size
        if at + 8 > 65536:
            return 0
        size = uint(s, at, 8)
        if size == 0 or size > 4095 or at + 9 + size > 65536:
            return 0
        if bit == 16:
            if size > 6:
                return 0
            number = 0
            i = 0
            while i < size:
                ch = byte(s, at + 8 + i)
                if ch < 48 or ch > 57:
                    return 0
                number = number * 10 + ch - 48
                i = i + 1
            if number == 0 or number > 604800:
                return 0
            put(w, 2097152 + 224, number)
        else:
            copy(s, w, target, at + 8, size)
            store(w, target + size, 0)
        at = at + 9 + size
        index = index + 2
    if mask & 7 != 7 or split_output(w) == 0:
        return 0
    i = 0
    while i < 4:
        nonzero = 0
        j = 0
        while j < 32:
            nonzero = nonzero | byte(s, 16 + i * 32 + j)
            j = j + 1
        if nonzero == 0:
            return 0
        i = i + 1
    copy(s, w, 2097152 + 512, 16, 128)
    return 1

def argument_equal(s:readbuf, w:mutbuf, at:u64, count:u64, text:u64, size:u64) -> u64:
    if count != size:
        return 0
    i = 0
    while i < size:
        if byte(s, at + i) != byte(w, text + i):
            return 0
        i = i + 1
    return 1

def dirname(w:mutbuf, at:u64, count:u64, target:u64) -> u64:
    last = 0
    found = 0
    i = 0
    while i < count:
        if byte(w, at + i) == 47:
            last = i
            found = 1
        i = i + 1
    if found == 0:
        store(w, target, 46)
        store(w, target + 1, 0)
        return 1
    if last == 0:
        store(w, target, 47)
        store(w, target + 1, 0)
        return 1
    copyw(w, target, at, last)
    store(w, target + last, 0)
    return last

def split_output(w:mutbuf) -> u64:
    at = 2097152 + 16384
    size = 0
    name = 0
    while size < 4096 and byte(w, at + size) != 0:
        if byte(w, at + size) == 47:
            name = size + 1
        size = size + 1
    count = size - name
    if size == 4096 or count == 0 or count > 255:
        return 0
    if count == 1 and byte(w, at + name) == 46:
        return 0
    if count == 2 and byte(w, at + name) == 46 and byte(w, at + name + 1) == 46:
        return 0
    i = 0
    while i < count:
        ch = byte(w, at + name + i)
        if ch == 0 or ch > 127 or ch == 47:
            return 0
        store(w, 2097152 + 40960 + i, ch)
        i = i + 1
    store(w, 2097152 + 40960 + count, 0)
    put(w, 2097152 + 216, count)
    return choose(dirname(w, at, size, 2097152 + 36864) != 0, 1, 0)

def inventory(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 128, 1)
    root = json_parse(s, o, w, 0, get(w, 2097152 + 208))
    node = field(s, o, w, root, 6)
    if node == 0 or kind(o, node) != 3:
        return 0
    at = 16777232
    previous = 0
    count = 0
    while True:
        cursor = node + 1
        best = 0
        while cursor < following(o, node):
            take = 1
            if previous != 0 and string_compare(s, token_start(o, cursor), token_start(o, previous)) != 2:
                take = 0
            if take != 0:
                if best == 0 or string_compare(s, token_start(o, cursor), token_start(o, best)) != 2:
                    best = cursor
            cursor = following(o, cursor + 1)
        if best == 0:
            if count == 0:
                return 0
            put(o, 16777216, 3544413516083579208)
            put(o, 16777224, count)
            put(w, 2097152 + 200, at - 16777216)
            return 1
        if count >= 4096 or at + 4135 > 17825216:
            return 0
        path_size = decode_path(s, o, best, at + 40)
        if path_size == 0 or decode_pin(s, o, best + 1, at + 8) == 0:
            return 0
        put(o, at, path_size)
        at = at + 40 + path_size
        count = count + 1
        previous = best
    return 0

def decode_path(s:readbuf, o:mutbuf, node:u64, target:u64) -> u64:
    if kind(o, node) != 2:
        return 0
    source = token_start(o, node) + 1
    count = 0
    done = 0
    while done == 0:
        unit = decoded(s, source)
        source = unit >> 32
        cp = unit & 4294967295
        if cp == 1114112:
            done = 1
        else:
            if cp == 1114113 or count >= 4095 or cp > 127 or cp == 0:
                return 0
            store(o, target + count, cp)
            count = count + 1
    if count == 0:
        return 0
    start = 0
    i = 0
    while i <= count:
        ch = 47
        if i < count:
            ch = byte(o, target + i)
        if ch == 47:
            length = i - start
            if length == 0:
                return 0
            if length == 1 and byte(o, target + start) == 46:
                return 0
            if length == 2 and byte(o, target + start) == 46 and byte(o, target + start + 1) == 46:
                return 0
            start = i + 1
        else:
            if (ch < 48 or ch > 57) and (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 46 and ch != 45 and ch != 95:
                return 0
        i = i + 1
    return count

def decode_pin(s:readbuf, o:mutbuf, node:u64, target:u64) -> u64:
    if kind(o, node) != 2:
        return 0
    source = token_start(o, node) + 1
    i = 0
    value = 0
    while i < 64:
        unit = decoded(s, source)
        source = unit >> 32
        cp = unit & 4294967295
        digit = hexval(cp)
        if digit > 15:
            return 0
        if i & 1 == 0:
            value = digit * 16
        else:
            store(o, target + (i >> 1), value + digit)
        i = i + 1
    unit = decoded(s, source)
    return choose((unit & 4294967295) == 1114112, 1, 0)

def request(o:mutbuf, w:mutbuf) -> u64:
    at = 33554432
    namesize = get(w, 2097152 + 216)
    inventorysize = get(w, 2097152 + 200)
    size = 288 + namesize + inventorysize
    if size > 1048576:
        return 0
    put(o, at, 3544419043639380296)
    put(o, at + 8, get(w, 2097152 + 8))
    put(o, at + 16, get(w, 2097152 + 16))
    put(o, at + 24, get(w, 2097152 + 24))
    put(o, at + 32, get(w, 2097152 + 32))
    put(o, at + 40, get(w, 2097152 + 40))
    put(o, at + 48, get(w, 2097152 + 88))
    put(o, at + 56, get(w, 2097152 + 96))
    put(o, at + 64, get(w, 2097152 + 104))
    put(o, at + 72, get(w, 2097152 + 112))
    put(o, at + 80, get(w, 2097152 + 120))
    put(o, at + 88, get(w, 2097152 + 48))
    put(o, at + 96, get(w, 2097152 + 56))
    put(o, at + 104, namesize)
    put(o, at + 112, inventorysize)
    put(o, at + 120, 0)
    copy_between(w, o, at + 128, 2097152 + 800, 160)
    copy_between(w, o, at + 288, 2097152 + 40960, namesize)
    copyw(o, at + 288 + namesize, 16777216, inventorysize)
    put(w, 2097152 + 192, size)
    return 1

def copy_between(source:mutbuf, target:mutbuf, to:u64, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(target, to + i, byte(source, at + i))
        i = i + 1
    return 0

def same_bytes(w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def same_stat(w:mutbuf, a:u64, b:u64) -> u64:
    if same_bytes(w, a, b, 40) == 0:
        return 0
    if same_bytes(w, a + 48, b + 48, 8) == 0:
        return 0
    return same_bytes(w, a + 88, b + 88, 32)
def json_parse(s: readbuf, o: mutbuf, w: mutbuf, start: u64, limit: u64) -> u64:
    root = get(w, 128)
    put(w, 256, start)
    put(w, 264, 0)
    put(w, 272, 1)
    put(w, 280, 0)
    while get(w, 280) == 0:
        put(w, 256, whitespace(s, get(w, 256), limit))
        result = 0
        if get(w, 272) == 1:
            result = json_value(s, o, w, limit)
        else:
            result = json_separator(s, o, w, limit)
        if result == 0:
            return 0
    if whitespace(s, get(w, 256), limit) != limit:
        return 0
    return root

def json_value(s: readbuf, o: mutbuf, w: mutbuf, limit: u64) -> u64:
    at = get(w, 256)
    if at >= limit:
        return 0
    ch = byte(s, at)
    if ch == 123 or ch == 91:
        if get(w, 264) >= 1024:
            return 0
        node = new_node(o, w, choose(ch == 123, 3, 4), at)
        if node == 0:
            return 0
        slot = 65536 + get(w, 264) * 24
        put(w, slot, node)
        put(w, slot + 8, choose(ch == 123, 3, 4))
        put(w, slot + 16, 0)
        put(w, 264, get(w, 264) + 1)
        put(w, 256, at + 1)
        put(w, 272, 0)
        return 1
    k = 0
    end = 0
    if ch == 34:
        k = 2
        end = string_end(s, at, limit)
    elif ch == 116 and limit - at >= 4 and (uint(s, at, 4) == 1702195828):
        k = 6
        end = at + 4
    elif ch == 102 and limit - at >= 5 and (uint(s, at, 5) == 435728179558):
        k = 7
        end = at + 5
    elif ch == 110 and limit - at >= 4 and (uint(s, at, 4) == 1819047278):
        k = 8
        end = at + 4
    elif ch == 78 and limit - at >= 3 and (uint(s, at, 3) == 5136718):
        k = 9
        end = at + 3
    elif ch == 73 and limit - at >= 8 and (uint(s, at, 8) == 8751735898823355977):
        k = 9
        end = at + 8
    elif ch == 45 and limit - at >= 9 and (uint(s, at + 1, 8) == 8751735898823355977):
        k = 9
        end = at + 9
    else:
        k = 5
        end = number_end(s, at, limit)
    if end == 0:
        return 0
    node = new_node(o, w, k, at)
    if node == 0:
        return 0
    put(o, 1048576 + node * 32 + 16, end)
    put(o, 1048576 + node * 32 + 24, get(w, 128))
    put(w, 256, end)
    value_done(w)
    return 1

def json_separator(s: readbuf, o: mutbuf, w: mutbuf, limit: u64) -> u64:
    if get(w, 264) == 0 or get(w, 256) >= limit:
        return 0
    slot = 65536 + (get(w, 264) - 1) * 24
    k = get(w, slot + 8)
    state = get(w, slot + 16)
    ch = byte(s, get(w, 256))
    if state == 0 or state == 1:
        if state == 0 and (k == 3 and ch == 125 or (k == 4 and ch == 93)):
            return close_container(o, w, slot)
        if k == 4:
            put(w, slot + 16, 4)
            put(w, 272, 1)
            return 1
        if ch != 34:
            return 0
        end = string_end(s, get(w, 256), limit)
        if end == 0:
            return 0
        node = new_node(o, w, 2, get(w, 256))
        if node == 0:
            return 0
        put(o, 1048576 + node * 32 + 16, end)
        put(o, 1048576 + node * 32 + 24, get(w, 128))
        end = whitespace(s, end, limit)
        if end >= limit or byte(s, end) != 58:
            return 0
        put(w, 256, end + 1)
        put(w, slot + 16, 4)
        put(w, 272, 1)
        return 1
    if state != 5:
        return 0
    if ch == 44:
        put(w, 256, get(w, 256) + 1)
        put(w, slot + 16, 1)
        return 1
    if k == 3 and ch == 125 or (k == 4 and ch == 93):
        return close_container(o, w, slot)
    return 0

def close_container(o: mutbuf, w: mutbuf, slot: u64) -> u64:
    node = get(w, slot)
    put(o, 1048576 + node * 32 + 16, get(w, 256) + 1)
    put(o, 1048576 + node * 32 + 24, get(w, 128))
    put(w, 256, get(w, 256) + 1)
    put(w, 264, get(w, 264) - 1)
    value_done(w)
    return 1

def value_done(w: mutbuf) -> u64:
    put(w, 272, 0)
    if get(w, 264) == 0:
        put(w, 280, 1)
    else:
        put(w, 65536 + (get(w, 264) - 1) * 24 + 16, 5)
    return 0

def new_node(o: mutbuf, w: mutbuf, k: u64, at: u64) -> u64:
    node = get(w, 128)
    if node >= 262144:
        return 0
    put(o, 1048576 + node * 32, k)
    put(o, 1048576 + node * 32 + 8, at)
    put(w, 128, node + 1)
    return node

def number_end(s: readbuf, at: u64, limit: u64) -> u64:
    if byte(s, at) == 45:
        at = at + 1
    if at >= limit or byte(s, at) < 48 or byte(s, at) > 57:
        return 0
    if byte(s, at) == 48:
        at = at + 1
    else:
        while at < limit and byte(s, at) >= 48 and (byte(s, at) <= 57):
            at = at + 1
    if at < limit and byte(s, at) == 46:
        at = at + 1
        start = at
        while at < limit and byte(s, at) >= 48 and (byte(s, at) <= 57):
            at = at + 1
        if at == start:
            return 0
    if at < limit and (byte(s, at) == 69 or byte(s, at) == 101):
        at = at + 1
        if at < limit and (byte(s, at) == 43 or byte(s, at) == 45):
            at = at + 1
        start = at
        while at < limit and byte(s, at) >= 48 and (byte(s, at) <= 57):
            at = at + 1
        if at == start:
            return 0
    return at

def string_end(s: readbuf, at: u64, limit: u64) -> u64:
    at = at + 1
    while at < limit:
        unit = decoded(s, at)
        cp = unit & 4294967295
        at = unit >> 32
        if cp == 1114113 or at > limit:
            return 0
        if cp == 1114112:
            return at
    return 0

def whitespace(s: readbuf, at: u64, limit: u64) -> u64:
    more = 1
    while at < limit and more != 0:
        ch = byte(s, at)
        if ch == 32 or ch == 9 or ch == 10 or (ch == 13):
            at = at + 1
        else:
            more = 0
    return at

def field(s: readbuf, o: mutbuf, w: mutbuf, root: u64, name: u64) -> u64:
    if root == 0 or kind(o, root) != 3:
        return 0
    cursor = root + 1
    found = 0
    while cursor < following(o, root):
        if text_equal(s, o, w, cursor, 1000000 + name * 256, constant_length(name)) != 0:
            found = cursor + 1
        cursor = following(o, cursor + 1)
    return found

def text_equal(s: readbuf, o: mutbuf, w: mutbuf, node: u64, at: u64, n: u64) -> u64:
    if node == 0 or kind(o, node) != 2:
        return 0
    source = token_start(o, node) + 1
    i = 0
    while source < token_end(o, node):
        unit = decoded(s, source)
        cp = unit & 4294967295
        source = unit >> 32
        if cp == 1114112:
            return choose(i == n, 1, 0)
        if cp == 1114113 or i >= n or cp != byte(w, at + i):
            return 0
        i = i + 1
    return 0

def string_compare(s: readbuf, a: u64, b: u64) -> u64:
    a = a + 1
    b = b + 1
    while True:
        x = decoded(s, a)
        y = decoded(s, b)
        a = x >> 32
        b = y >> 32
        x = x & 4294967295
        y = y & 4294967295
        if x == 1114112 and y == 1114112:
            return 0
        if x == 1114112:
            return 1
        if y == 1114112:
            return 2
        if x < y:
            return 1
        if x > y:
            return 2
    return 0

def kind(o: mutbuf, node: u64) -> u64:
    return get(o, 1048576 + node * 32)

def token_start(o: mutbuf, node: u64) -> u64:
    return get(o, 1048576 + node * 32 + 8)

def token_end(o: mutbuf, node: u64) -> u64:
    return get(o, 1048576 + node * 32 + 16)

def following(o: mutbuf, node: u64) -> u64:
    return get(o, 1048576 + node * 32 + 24)

def hex_digit(n: u64) -> u64:
    return choose(n < 10, 48 + n, 87 + n)

def uint(s: readbuf, at: u64, n: u64) -> u64:
    i = 0
    value = 0
    while i < n:
        value = value | byte(s, at + i) << i * 8
        i = i + 1
    return value

def get(w: mutbuf, at: u64) -> u64:
    return word_load(w, at)

def put(w: mutbuf, at: u64, value: u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value >> i * 8 & 255)
        i = i + 1
    return 0

def constants(w: mutbuf) -> u64:
    put(w, 1001536, 7881129350718123891)
    put(w, 1001544, 32777976645512801)
    return 0

def constant_length(i: u64) -> u64:
    return choose(i == 6, 15, 0)

def hex4(s: readbuf, index: u64) -> u64:
    if index + 4 > length(s):
        return 4294967295
    count = 0
    value = 0
    while count < 4:
        ch = byte(s, index + count)
        digit = 16
        if ch >= 48 and ch <= 57:
            digit = ch - 48
        if ch >= 65 and ch <= 70:
            digit = ch - 55
        if ch >= 97 and ch <= 102:
            digit = ch - 87
        if digit == 16:
            return 4294967295
        value = value * 16 + digit
        count = count + 1
    return value

def decoded(s: readbuf, index: u64) -> u64:
    size = length(s)
    if index >= size:
        return 8 << 32 | 1114113
    ch = byte(s, index)
    index = index + 1
    if ch == 34:
        return index << 32 | 1114112
    if ch < 32:
        return 2 << 32 | 1114113
    if ch == 92:
        if index >= size:
            return 3 << 32 | 1114113
        esc = byte(s, index)
        index = index + 1
        if esc == 34 or esc == 92 or esc == 47:
            return index << 32 | esc
        if esc == 98:
            return index << 32 | 8
        if esc == 102:
            return index << 32 | 12
        if esc == 110:
            return index << 32 | 10
        if esc == 114:
            return index << 32 | 13
        if esc == 116:
            return index << 32 | 9
        if esc != 117 or index + 4 > size:
            return 4 << 32 | 1114113
        cursor = index
        characters = 0
        while cursor < size and characters < 4:
            unit = byte(s, cursor)
            if unit < 128 or unit >= 192:
                characters = characters + 1
            cursor = cursor + 1
        if characters < 4:
            return 4 << 32 | 1114113
        cp = hex4(s, index)
        if cp == 4294967295:
            return 5 << 32 | 1114113
        index = index + 4
        if cp >= 55296 and cp <= 56319:
            if index + 6 > size:
                return 6 << 32 | 1114113
            if byte(s, index) != 92 or byte(s, index + 1) != 117:
                return 6 << 32 | 1114113
            low = hex4(s, index + 2)
            if low < 56320 or low > 57343:
                return 6 << 32 | 1114113
            cp = 65536 + (cp - 55296) * 1024 + low - 56320
            index = index + 6
        elif cp >= 56320 and cp <= 57343:
            return 7 << 32 | 1114113
        return index << 32 | cp
    if ch < 128:
        return index << 32 | ch
    needed = 0
    minimum = 0
    cp = 0
    if ch >= 194 and ch <= 223:
        needed = 1
        minimum = 128
        cp = ch & 31
    if ch >= 224 and ch <= 239:
        needed = 2
        minimum = 2048
        cp = ch & 15
    if ch >= 240 and ch <= 244:
        needed = 3
        minimum = 65536
        cp = ch & 7
    if needed == 0 or index + needed > size:
        return 20 << 32 | 1114113
    count = 0
    while count < needed:
        ch = byte(s, index)
        if ch < 128 or ch > 191:
            return 20 << 32 | 1114113
        cp = cp * 64 + (ch & 63)
        index = index + 1
        count = count + 1
    if cp < minimum or cp > 1114111:
        return 20 << 32 | 1114113
    if cp >= 55296 and cp <= 57343:
        return 20 << 32 | 1114113
    return index << 32 | cp

def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pointers:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, pointers)
    return 1

def finish(o:mutbuf, w:mutbuf, code:u64) -> u32:
    return call(o, w, 999, 60, code, 0, 0, 0, 0, 0, 0)

def failed(value:u64) -> bool:
    return value >> 63 != 0

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, count:u64) -> u32:
    put(w, 0, phase)
    store(w, 65536, command)
    put(o, 0, count)
    return 3

def copyw(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    index = 0
    value = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def hexval(ch:u64) -> u64:
    if ch >= 48 and ch <= 57:
        return ch - 48
    if ch >= 97 and ch <= 102:
        return ch - 87
    return 16

def copy(s:readbuf, w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def entry_constants(w:mutbuf) -> u64:
    put(w, 2097376, 3600)
    store(w, 2117632, 46)
    store(w, 2117633, 0)
    put(w, 2138624, 7599087893304928302)
    store(w, 2138632, 108)
    store(w, 2138633, 100)
    store(w, 2138634, 45)
    store(w, 2138635, 0)
    put(w, 2142208, 7310238724270485551)
    store(w, 2142216, 108)
    store(w, 2142217, 102)
    store(w, 2142218, 47)
    store(w, 2142219, 101)
    store(w, 2142220, 120)
    store(w, 2142221, 101)
    store(w, 2142222, 0)
    put(w, 2142272, 7308327836377508200)
    put(w, 2142280, 7308910564655592289)
    store(w, 2142288, 114)
    store(w, 2142289, 0)
    put(w, 2142336, 8098164217508620648)
    store(w, 2142344, 114)
    store(w, 2142345, 111)
    store(w, 2142346, 99)
    store(w, 2142347, 101)
    store(w, 2142348, 115)
    store(w, 2142349, 115)
    store(w, 2142350, 0)
    put(w, 2142400, 8247620833072212328)
    put(w, 2142408, 7236274654156776803)
    store(w, 2142416, 0)
    put(w, 2142464, 8247620833072212328)
    put(w, 2142472, 8463513163314062691)
    store(w, 2142480, 114)
    store(w, 2142481, 101)
    store(w, 2142482, 0)
    store(w, 2142848, 115)
    store(w, 2142849, 116)
    store(w, 2142850, 97)
    store(w, 2142851, 103)
    store(w, 2142852, 101)
    store(w, 2142853, 0)
    store(w, 2142912, 119)
    store(w, 2142913, 111)
    store(w, 2142914, 114)
    store(w, 2142915, 107)
    store(w, 2142916, 0)
    put(w, 2142976, 7308910564655327592)
    put(w, 2142984, 8315181416903224690)
    store(w, 2142992, 116)
    store(w, 2142993, 0)
    put(w, 2143040, 7811904093179439464)
    put(w, 2143048, 32780223047609700)
    store(w, 2143104, 0)
    put(w, 2143232, 8391737126163524909)
    store(w, 2143240, 0)
    put(w, 2143296, 7811898643973352749)
    store(w, 2143304, 101)
    store(w, 2143305, 114)
    store(w, 2143306, 0)
    put(w, 2143360, 8227342511163780397)
    store(w, 2143368, 101)
    store(w, 2143369, 112)
    store(w, 2143370, 111)
    store(w, 2143371, 114)
    store(w, 2143372, 116)
    store(w, 2143373, 0)
    put(w, 2143424, 7305808869231635757)
    store(w, 2143432, 0)
    put(w, 2143488, 8462093745447513389)
    put(w, 2143496, 7236844123925458292)
    store(w, 2143504, 115)
    store(w, 2143505, 0)
    store(w, 2143552, 45)
    store(w, 2143553, 45)
    store(w, 2143554, 104)
    store(w, 2143555, 101)
    store(w, 2143556, 108)
    store(w, 2143557, 112)
    store(w, 2143558, 0)
    put(w, 2145152, 7503061186399794005)
    put(w, 2145160, 7018134777289859433)
    put(w, 2145168, 7236274654156776819)
    put(w, 2145176, 8462391747554389280)
    put(w, 2145184, 3251678457671721076)
    put(w, 2145192, 7308332226908742445)
    put(w, 2145200, 3251678457671721074)
    put(w, 2145208, 7309955054514955053)
    put(w, 2145216, 6071221872994971504)
    put(w, 2145224, 8462108862724120648)
    put(w, 2145232, 6075161636495516530)
    put(w, 2145240, 7883960360072061021)
    put(w, 2145248, 7162257421467217765)
    put(w, 2145256, 4847371972774227567)
    store(w, 2145264, 79)
    store(w, 2145265, 78)
    store(w, 2145266, 68)
    store(w, 2145267, 83)
    store(w, 2145268, 93)
    store(w, 2145269, 10)
    store(w, 2145270, 0)
    return 0
'''
MINI_SOURCE = r'''def copy(s:readbuf, w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0
def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
def uint(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value
'''

def document(source, module):
    nodes = ast.parse(source).body

    class Fold(ast.NodeTransformer):

        def visit_BinOp(self, node):
            node = self.generic_visit(node)
            if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant) and isinstance(node.left.value, int) and isinstance(node.right.value, int):
                if isinstance(node.op, ast.Add):
                    return ast.Constant(value=node.left.value + node.right.value)
                if isinstance(node.op, ast.Sub):
                    return ast.Constant(value=node.left.value - node.right.value)
            return node
    nodes = [ast.fix_missing_locations(Fold().visit(n)) for n in nodes]
    names = {n.name: f'f{i}' for i, n in enumerate(nodes)}
    assert len(names) == len(nodes)
    sigs = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for n in nodes:
        b = LinkerBuilder(n, names, sigs, total)
        b.statements(n.body)
        functions.append({'name': names[n.name], 'params': [b.param(a) for a in b.params], 'returns': [b.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9', 'module': module, 'functions': functions})

def _render(directory):
    outputs = {}

    def authored(module, source):
        doc = document(source, module)
        text = render_assembly(doc)
        outputs[module] = text
        return {'module': module, 'source_bytes': len(text.encode()), 'functions': len(doc['functions']), 'blocks': sum((len(f['blocks']) for f in doc['functions'])), 'instructions': sum((len(b['ops']) for f in doc['functions'] for b in f['blocks'])), 'max_parameters': max((len(b['params']) for f in doc['functions'] for b in f['blocks']))}
    records = [authored('release_build_entry', POLICY_SOURCE)]
    D = directory
    obj = D / 'entry.o'
    blob = D / 'entry.bin'
    subprocess.run(['as', '--64', str(ROOT / 'tools/hia_release_build_entry_syscalls.S'), '-o', str(obj)], check=True, capture_output=True)
    subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(blob)], check=True, capture_output=True)
    symbols = {name: int(address, 16) for address, _, name in (l.split() for l in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
    assert symbols['_start'] == 0 and 'R_X86_64' not in subprocess.check_output(['objdump', '-r', str(obj)], text=True)
    adapter = blob.read_bytes()
    header = b'\x7fELF\x02\x01\x01' + bytes(9) + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 4194480, 64, 0, 0, 64, 56, 2, 0, 0, 0) + struct.pack('<IIQQQQQQ', 1, 5, 0, 4194304, 4194304, 0, 0, 4096) + struct.pack('<IIQQQQQQ', 1685382481, 6, 0, 0, 0, 0, 0, 16)
    prefix = header + adapter
    holes = {n: 176 + symbols[n] for n in ('policy_hole', 'sha_hole')}
    pins = 176 + symbols['entry_pins']
    metadata = 176 + symbols['entry_metadata']
    mini = MINI_SOURCE
    packer = f"def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s) < 26 or uint(s, 0) != {int.from_bytes(b'HIAENPK1', 'little')}:\n        return 4294967295\n    policy = uint(s, 8)\n    sha = uint(s, 16)\n    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 24 + policy + sha:\n        return 4294967295\n    size = {len(prefix)} + policy + sha\n    if size > 4194304 or length(o) < size:\n        return 4294967294\n"
    for at in range(0, len(prefix), 8):
        part = prefix[at:at + 8]
        if len(part) == 8:
            packer += f"    put(o, {at}, {int.from_bytes(part, 'little')})\n"
        else:
            for i, ch in enumerate(part):
                packer += f'    store(o, {at + i}, {ch})\n'
    packer += '    put(o, 96, size)\n    put(o, 104, size)\n'
    packer += f'    put(o, {metadata + 8}, policy)\n    put(o, {metadata + 16}, sha)\n'
    for name, at in holes.items():
        target = f'{len(prefix)}' + (' + policy' if name == 'sha_hole' else '')
        packer += f'    displacement = {target} - {at + 4}\n'
        for i in range(4):
            packer += f'    store(o, {at + i}, (displacement >> {i * 8}) & 255)\n'
    packer += f'    copy(s, o, {len(prefix)}, 24, policy + sha)\n    return size\n' + mini
    records.append(authored('release_build_entry_packer', packer))
    binder = f"def bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(w) < 256:\n        return 17\n    phase = uintw(w, 0)\n    mode = uintw(w, 16)\n    if phase == 0 and mode == 0:\n        if length(s) != 21 or uint(s, 0) != 1 or uint(s, 8) != 5 or partial(s, 16, 5) != {int.from_bytes(b'build', 'little')}:\n            return 16\n        put(w, 16, 1)\n        return 0\n    if phase == 2 and mode == 3:\n        return 3\n    if phase != 1 or mode != 1 or length(s) < {136 + len(prefix) + 2} or uint(s, 0) != {int.from_bytes(b'HIAENBD1', 'little')}:\n        return 16\n    size = length(s) - 136\n    if size > 4194304 or size > length(o):\n        return 17\n    policy = uint(s, {136 + metadata + 8})\n    sha = uint(s, {136 + metadata + 16})\n    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or size != {len(prefix)} + policy + sha:\n        return 16\n    if uint(s, 232) != size or uint(s, 240) != size:\n        return 16\n    if partial(s, {136 + holes['policy_hole']}, 4) != {len(prefix) - holes['policy_hole'] - 4} or partial(s, {136 + holes['sha_hole']}, 4) != {len(prefix) - holes['sha_hole'] - 4} + policy:\n        return 16\n"
    skip = set(range(96, 112)) | set(range(metadata + 8, metadata + 24))
    for at in holes.values():
        skip.update(range(at, at + 4))
    checks = []
    at = 0
    while at < len(prefix):
        if at in skip:
            at += 1
            continue
        end = at + 1
        while end < len(prefix) and end not in skip and (end - at < 8):
            end += 1
        raw = prefix[at:end]
        expression = f'uint(s, {136 + at})' if len(raw) == 8 else f'partial(s, {136 + at}, {len(raw)})'
        checks.append(f"    if {expression} != {int.from_bytes(raw, 'little')}:\n        return 0\n")
        at = end
    prefix_helpers = ''
    for number, start in enumerate(range(0, len(checks), 40)):
        prefix_helpers += f'\ndef prefix_{number}(s:readbuf) -> u64:\n' + ''.join(checks[start:start + 40]) + '    return 1\n'
        binder += f'    if prefix_{number}(s) == 0:\n        return 16\n'
    binder += '    i = 0\n    while i < 4:\n        nonzero = 0\n        j = 0\n        while j < 32:\n            nonzero = nonzero | byte(s, 8 + i * 32 + j)\n            j = j + 1\n        if nonzero == 0:\n            return 16\n        i = i + 1\n    copy(s, o, 0, 136, size)\n'
    binder += f'    copy(s, o, {pins}, 8, 128)\n    put(w, 88, size)\n    put(w, 16, 3)\n    return 0\ndef uintw(w:mutbuf, at:u64) -> u64:\n    return word_load(w, at)\ndef partial(s:readbuf, at:u64, count:u64) -> u64:\n    i = 0\n    value = 0\n    while i < count:\n        value = value | (byte(s, at + i) << (i * 8))\n        i = i + 1\n    return value\n' + mini
    binder += prefix_helpers
    records.append(authored('release_build_entry_bind', binder))
    return (outputs, {'prefix_bytes': len(prefix), 'pins': pins, 'metadata': metadata, 'holes': holes, 'adapter_sha256': sha256(adapter).hexdigest(), 'records': records})

def render():
 with tempfile.TemporaryDirectory(prefix='hia-release-entry-author-') as directory:
  return _render(Path(directory))

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--check',action='store_true')
 args=parser.parse_args()
 outputs,metadata=render()
 for module,text in outputs.items():
  path=ROOT/'examples/hia_bootstrap'/(module+'.hepta')
  if args.check:
   if path.read_text()!=text:raise SystemExit('native release entry source differs: '+module)
  else:path.write_text(text)
 print(json.dumps(metadata,sort_keys=True))

if __name__=='__main__':
 main()
