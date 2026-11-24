"""Author the HIA subprocess owner and its mechanical Linux syscall adapter."""
from __future__ import annotations

import ast
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_native_filter import bind_adapter, document as packer_document, elf_header
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/subprocess.hepta'
PACKER_PATH = 'examples/hia_bootstrap/subprocess_packer.hepta'
ADAPTER_PATH = 'tools/hia_subprocess_syscalls.S'
PACKER_MAGIC = int.from_bytes(b'HIASUPK1', 'little')

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 131072:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if admit(s, w) == 0:
            return 0
        return call(o, w, 1, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        if result != uint(s, 8):
            return 0
        return call(o, w, 2, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        put(w, 392, result)
        put(w, 400, 0)
        return inspect_file(s, o, w)
    if phase >= 3 and phase <= 6:
        return file_observation(s, o, w, phase, result)
    if phase >= 7 and phase <= 17:
        return prepare_owner(s, o, w, phase, result)
    if phase == 170:
        if result < 2 or result > 2147483647:
            return 0
        put(w, 456, result)
        return call(o, w, 18, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 18:
        if failed(result):
            return 0
        if result == 0:
            return call(o, w, 100, 157, 1, 9, 0, 0, 0, 0, 0)
        put(w, 40, result)
        put(w, 416, 0)
        return call(o, w, 19, 3, get(w, 80), 0, 0, 0, 0, 0, 0)
    if phase == 19:
        if failed(result):
            return fail_run(s, o, w)
        index = get(w, 416) + 1
        put(w, 416, index)
        if index < 3:
            return call(o, w, 19, 3, get(w, 80 + 16 * index), 0, 0, 0, 0, 0, 0)
        return call(o, w, 20, 434, get(w, 40), 0, 0, 0, 0, 0, 0)
    if phase == 20:
        if failed(result):
            return fail_run(s, o, w)
        put(w, 48, result)
        poll_row(w, 0, result)
        poll_row(w, 1, get(w, 56))
        poll_row(w, 2, get(w, 64))
        poll_row(w, 3, get(w, 72))
        poll_row(w, 4, get(w, 88))
        poll_row(w, 5, get(w, 104))
        return poll(o, w)
    if phase == 21:
        return ready(s, o, w, result)
    if phase >= 22 and phase <= 27:
        return stopping(s, o, w, phase, result)
    if phase >= 28 and phase <= 32:
        return capture(s, o, w, phase, result)
    if phase >= 40 and phase <= 45:
        return finish_owner(s, o, w, phase, result)
    if phase == 60:
        if failed(result):
            return 0
        kind = getn(w, 536, 4) & 61440
        if kind != 32768 and kind != 16384:
            return 0
        index = 0
        while index < 7:
            if index != 4 and (index != 6 or uint(s, 120) != 0):
                if get(w, 512) == get(w, 1704 + 16 * index) and get(w, 520) == get(w, 1712 + 16 * index):
                    return 0
            index = index + 1
        put(w, 488, get(w, 488) + 1)
        return inspect_passed(s, o, w)
    if phase == 401:
        return call(o, w, 41, 61, get(w, 40), 336, 0, 0, 0, 0, 12)
    if phase == 430:
        if failed(result):
            return call(o, w, 999, 60, 74, 0, 0, 0, 0, 0, 0)
        encode_receipt(w)
        put(w, 368, 0)
        return call(o, w, 44, 18, uint(s, 64), 4096, 128, 0, 0, 0, 12)
    if phase >= 100 and phase <= 116:
        return child(s, o, w, phase, result)
    if phase >= 230 and phase <= 232:
        if phase == 230:
            return call(o, w, 231, 3, get(w, 88), 0, 0, 0, 0, 0, 0)
        if phase == 231:
            return call(o, w, 232, 3, get(w, 104), 0, 0, 0, 0, 0, 0)
        return end_group(o, w)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    size = length(s)
    if size < 138 or size > 65536 or uint(s, 0) != 3544405840977021256:
        return 0
    parent = uint(s, 8)
    argc = uint(s, 72)
    envc = uint(s, 80)
    if parent < 2 or parent > 2147483647 or uint(s, 16) == 0:
        return 0
    if argc == 0 or argc > 64 or envc > 64:
        return 0
    if uint(s, 88) > 536870912 or uint(s, 96) > 16777216:
        return 0
    if uint(s, 104) < 1000000 or uint(s, 104) > 5000000000:
        return 0
    memory = uint(s, 112)
    if memory != 0 and (memory < 67108864 or memory > 17179869184):
        return 0
    index = 0
    while index < 7:
        fd = selected_fd(s, index)
        if index != 6 or fd != 0:
            if fd < 3 or fd > 2147483647:
                return 0
            previous = 0
            while previous < index:
                if fd == selected_fd(s, previous):
                    return 0
                previous = previous + 1
        index = index + 1
    at = 128
    index = 0
    while index < argc + envc:
        if at + 8 >= size:
            return 0
        count = uint(s, at)
        at = at + 8
        if count > 8192 or count >= size - at or byte(s, at + count) != 0:
            return 0
        if index == 0 and count == 0:
            return 0
        text = 0
        equal = 0
        while text < count:
            ch = byte(s, at + text)
            if ch == 0:
                return 0
            if index >= argc and equal == 0:
                if ch == 61:
                    if text == 0:
                        return 0
                    equal = text
                elif (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 95:
                    if text == 0 or ch < 48 or ch > 57:
                        return 0
            text = text + 1
        if index < argc:
            put(w, 2048 + index * 8, at)
        else:
            if equal == 0:
                return 0
            prior = 0
            while prior < index - argc:
                other = get(w, 2688 + prior * 8)
                if same_name(s, at, other, equal) != 0:
                    return 0
                prior = prior + 1
            put(w, 2688 + (index - argc) * 8, at)
        at = at + count + 1
        index = index + 1
    put(w, 504, at - 1)
    if at != size:
        if size - at < 16 or uint(s, at) != 3544407975525435720:
            return 0
        count = uint(s, at + 8)
        if count > 16 or size - at != 16 + count * 8:
            return 0
        put(w, 480, count)
        index = 0
        while index < count:
            fd = uint(s, at + 16 + index * 8)
            if fd < 3 or fd > 2147483647:
                return 0
            previous = 0
            while previous < 7:
                if previous != 4 and fd == selected_fd(s, previous):
                    return 0
                previous = previous + 1
            previous = 0
            while previous < index:
                if fd == get(w, 9504 + previous * 8):
                    return 0
                previous = previous + 1
            put(w, 9504 + index * 8, fd)
            index = index + 1
    put(w, 2048 + argc * 8, 18446744073709551615)
    put(w, 2688 + envc * 8, 18446744073709551615)
    return 1

def same_name(s:readbuf, left:u64, right:u64, count:u64) -> u64:
    index = 0
    while index <= count:
        if right + index >= length(s) or byte(s, left + index) != byte(s, right + index):
            return 0
        index = index + 1
    return 1

def selected_fd(s:readbuf, index:u64) -> u64:
    if index == 6:
        return uint(s, 120)
    return uint(s, 24 + index * 8)

def inspect_file(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 400)
    if index == 7 or (index == 6 and uint(s, 120) == 0):
        return inspect_passed(s, o, w)
    return call(o, w, 3, 5, selected_fd(s, index), 512, 0, 0, 0, 0, 12)

def inspect_passed(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 488)
    if index == get(w, 480):
        put(w, 416, 0)
        return call(o, w, 7, 293, 768, 524288, 0, 0, 0, 0, 3)
    return call(o, w, 60, 5, get(w, 9504 + index * 8), 512, 0, 0, 0, 0, 12)

def next_file(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 400, get(w, 400) + 1)
    return inspect_file(s, o, w)

def file_observation(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return 0
    index = get(w, 400)
    if phase == 4:
        if result & 15 != 15:
            return 0
        return next_file(s, o, w)
    if phase == 5:
        if result & 3 == 0 or result & 1024 != 0:
            return 0
        return next_file(s, o, w)
    if phase == 6:
        return next_file(s, o, w)
    mode = getn(w, 536, 4)
    device = get(w, 512)
    inode = get(w, 520)
    previous = 0
    while previous < index:
        if device == get(w, 1704 + 16 * previous) and inode == get(w, 1712 + 16 * previous):
            return 0
        previous = previous + 1
    put(w, 1704 + 16 * index, device)
    put(w, 1712 + 16 * index, inode)
    if index == 4:
        if mode & 61440 != 16384:
            return 0
        return next_file(s, o, w)
    if mode & 61440 != 32768:
        return 0
    if index < 2:
        limit = choose(index == 0, 67108864, 536870912)
        if get(w, 560) > limit or (index == 0 and get(w, 560) == 0):
            return 0
        return call(o, w, 4, 72, selected_fd(s, index), 1034, 0, 0, 0, 0, 0)
    if get(w, 528) > 1 or getn(w, 540, 4) != get(w, 392) or mode & 63 != 0:
        return 0
    if index == 6:
        if get(w, 528) != 1:
            return 0
        return call(o, w, 6, 73, uint(s, 120), 6, 0, 0, 0, 0, 0)
    if get(w, 560) != 0:
        return 0
    return call(o, w, 5, 72, selected_fd(s, index), 3, 0, 0, 0, 0, 0)

def prepare_owner(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return 0
    if phase == 7:
        index = get(w, 416)
        put(w, 72 + 16 * index, getn(w, 768, 4))
        put(w, 80 + 16 * index, getn(w, 772, 4))
        return call(o, w, 8, 72, getn(w, 768, 4), 4, 2048, 0, 0, 0, 0)
    if phase == 8:
        index = get(w, 416) + 1
        put(w, 416, index)
        if index < 3:
            return call(o, w, 7, 293, 768, 524288, 0, 0, 0, 0, 3)
        put(w, 784, 16386)
        return call(o, w, 9, 14, 0, 784, 792, 8, 0, 0, 60)
    if phase == 9:
        return call(o, w, 10, 157, 1, 15, 0, 0, 0, 0, 0)
    if phase == 10:
        return call(o, w, 11, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 11:
        if result != uint(s, 8):
            return 0
        return call(o, w, 12, 289, 18446744073709551615, 784, 8, 526336, 0, 0, 12)
    if phase == 12:
        put(w, 64, result)
        return call(o, w, 13, 283, 1, 526336, 0, 0, 0, 0, 0)
    if phase == 13:
        put(w, 56, result)
        return call(o, w, 14, 228, 1, 128, 0, 0, 0, 0, 12)
    if phase == 14:
        now = get(w, 128) * 1000000000 + get(w, 136)
        put(w, 24, now)
        if now >= uint(s, 16):
            put(w, 32, 1)
            put(w, 304, 1)
            put(w, 312, 1)
            return call(o, w, 42, 74, uint(s, 40), 0, 0, 0, 0, 0, 0)
        timer_value(w, uint(s, 16))
        return call(o, w, 15, 286, get(w, 56), 1, 1536, 0, 0, 0, 48)
    if phase == 15:
        return relocate(o, w, 16, 2048, uint(s, 72) + 1, 8192)
    if phase == 16:
        return relocate(o, w, 17, 2688, uint(s, 80) + 1, 8832)
    return call(o, w, 170, 39, 0, 0, 0, 0, 0, 0, 0)

def poll_row(w:mutbuf, index:u64, fd:u64) -> u64:
    put(w, 1024 + 8 * index, fd | 4294967296)
    return 0

def poll(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 21, 7, 1024, 6, 18446744073709551615, 0, 0, 0, 3)

def ready(s:readbuf, o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result == 18446744073709551612:
        return poll(o, w)
    if result == 0 or failed(result):
        return fail_run(s, o, w)
    index = 0
    while index < 6:
        if getn(w, 1030 + 8 * index, 2) & 32 != 0:
            return fail_run(s, o, w)
        index = index + 1
    if getn(w, 1030, 2) & 1 != 0:
        put(w, 320, 1)
        put(w, 1024, 4294967295)
    if getn(w, 1046, 2) != 0:
        return call(o, w, 22, 0, get(w, 64), 18432, 128, 0, 0, 0, 12)
    if getn(w, 1038, 2) != 0:
        return call(o, w, 23, 0, get(w, 56), 1632, 8, 0, 0, 0, 12)
    if get(w, 320) != 0 and get(w, 304) != 0 and get(w, 312) != 0 and get(w, 424) != 0:
        return end_group(o, w)
    if getn(w, 1054, 2) != 0 and get(w, 304) == 0:
        return call(o, w, 28, 0, get(w, 72), 32768, 65536, 0, 0, 0, 12)
    if getn(w, 1062, 2) != 0 and get(w, 312) == 0:
        return call(o, w, 29, 0, get(w, 88), 32768, 65536, 0, 0, 0, 12)
    if getn(w, 1070, 2) != 0 and get(w, 424) == 0:
        return call(o, w, 32, 0, get(w, 104), 32768, 8, 0, 0, 0, 12)
    return poll(o, w)

def stopping(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 22:
        if get(w, 328) != 0:
            return poll(o, w)
        return begin_stop(s, o, w, 2)
    if phase == 23:
        if get(w, 328) == 0:
            return begin_stop(s, o, w, 1)
        if get(w, 328) == 1:
            put(w, 328, 2)
            put(w, 464, 9)
            return call(o, w, 25, 62, 0 - get(w, 40), 9, 0, 0, 0, 0, 0)
        put(w, 440, 1)
        return call(o, w, 230, 3, get(w, 72), 0, 0, 0, 0, 0, 0)
    if phase == 25:
        return call(o, w, 26, 424, get(w, 48), get(w, 464), 0, 0, 0, 0, 0)
    if phase == 26:
        return call(o, w, 24, 228, 1, 128, 0, 0, 0, 0, 12)
    if phase == 24:
        if failed(result):
            return fail_run(s, o, w)
        delay = uint(s, 104)
        if get(w, 328) == 2:
            delay = 1000000000
        timer_value(w, get(w, 128) * 1000000000 + get(w, 136) + delay)
        return call(o, w, 27, 286, get(w, 56), 1, 1536, 0, 0, 0, 48)
    if failed(result):
        return fail_run(s, o, w)
    return poll(o, w)

def begin_stop(s:readbuf, o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 328) != 0:
        return poll(o, w)
    put(w, 32, reason)
    put(w, 328, 1)
    put(w, 464, 15)
    return call(o, w, 25, 62, 0 - get(w, 40), 15, 0, 0, 0, 0, 0)

def capture(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 32:
        if result == 0:
            put(w, 424, 1)
            put(w, 1064, 4294967295)
        elif result == 8:
            put(w, 432, get(w, 32768))
        elif result != 18446744073709551605 and result != 18446744073709551612:
            return fail_run(s, o, w)
        if get(w, 320) != 0 and get(w, 304) != 0 and get(w, 312) != 0 and get(w, 424) != 0:
            return end_group(o, w)
        return poll(o, w)
    index = choose(phase == 29 or phase == 31, 1, 0)
    seen = 256 + index * 24
    stored = seen + 8
    error = seen + 16
    if phase == 30 or phase == 31:
        if result == 18446744073709551612:
            return write_chunk(s, o, w, index)
        if failed(result) or result == 0 or result > get(w, 360):
            put(w, error, choose(failed(result), 0 - result, 5))
            return begin_stop(s, o, w, 4)
        put(w, stored, get(w, stored) + result)
        put(w, 360, get(w, 360) - result)
        put(w, 368, get(w, 368) + result)
        if get(w, 360) != 0:
            return write_chunk(s, o, w, index)
        return poll(o, w)
    if result == 18446744073709551605 or result == 18446744073709551612:
        return poll(o, w)
    if failed(result):
        put(w, error, 0 - result)
        put(w, 304 + index * 8, 1)
        put(w, 1048 + index * 8, 4294967295)
        return begin_stop(s, o, w, 4)
    if result == 0:
        put(w, 304 + index * 8, 1)
        put(w, 1048 + index * 8, 4294967295)
        if get(w, 320) != 0 and get(w, 304) != 0 and get(w, 312) != 0 and get(w, 424) != 0:
            return end_group(o, w)
        return poll(o, w)
    if result > 65536 or get(w, seen) > 18446744073709486079:
        return fail_run(s, o, w)
    put(w, seen, get(w, seen) + result)
    cap = uint(s, 88 + index * 8)
    remain = cap - get(w, stored)
    count = choose(result < remain, result, remain)
    if get(w, error) != 0 or count == 0:
        return poll(o, w)
    put(w, 360, count)
    put(w, 368, 0)
    return write_chunk(s, o, w, index)

def write_chunk(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u32:
    return call(o, w, 30 + index, 18, uint(s, 40 + index * 8), 32768 + get(w, 368), get(w, 360), get(w, 264 + index * 24), 0, 0, 12)

def fail_run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 32, 4)
    put(w, 440, 1)
    return end_group(o, w)

def end_group(o:mutbuf, w:mutbuf) -> u32:
    # Keep the original child unreaped until its entire process group is stopped.
    return call(o, w, 40, 62, 0 - get(w, 40), 9, 0, 0, 0, 0, 0)

def finish_owner(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 40:
        return call(o, w, 401, 62, get(w, 40), 9, 0, 0, 0, 0, 0)
    if phase == 41:
        if result == 18446744073709551612:
            return call(o, w, 41, 61, get(w, 40), 336, 0, 0, 0, 0, 12)
        if result != get(w, 40):
            return call(o, w, 999, 60, 74, 0, 0, 0, 0, 0, 0)
        put(w, 448, 1)
        return call(o, w, 42, 74, uint(s, 40), 0, 0, 0, 0, 0, 0)
    if phase == 42:
        if failed(result):
            put(w, 272, 0 - result)
        else:
            put(w, 344, 1)
        return call(o, w, 43, 74, uint(s, 48), 0, 0, 0, 0, 0, 0)
    if phase == 43:
        if failed(result):
            put(w, 296, 0 - result)
        else:
            put(w, 344, get(w, 344) | 2)
        return call(o, w, 430, 228, 1, 128, 0, 0, 0, 0, 12)
    if phase == 44:
        if result == 18446744073709551612:
            return call(o, w, 44, 18, uint(s, 64), 4096 + get(w, 368), 128 - get(w, 368), get(w, 368), 0, 0, 12)
        if failed(result) or result == 0 or result > 128 - get(w, 368):
            return call(o, w, 999, 60, 74, 0, 0, 0, 0, 0, 0)
        put(w, 368, get(w, 368) + result)
        if get(w, 368) < 128:
            return call(o, w, 44, 18, uint(s, 64), 4096 + get(w, 368), 128 - get(w, 368), get(w, 368), 0, 0, 12)
        return call(o, w, 45, 74, uint(s, 64), 0, 0, 0, 0, 0, 0)
    return call(o, w, 999, 60, choose(failed(result), 74, 0), 0, 0, 0, 0, 0, 0)

def encode_receipt(w:mutbuf) -> u64:
    raw = get(w, 336)
    signal = raw & 127
    code = choose(signal == 0, raw >> 8, 0 - signal)
    if get(w, 40) == 0:
        code = 18446744073709551360
    put(w, 4096, 3544423351558687048)
    put(w, 4104, code)
    put(w, 4112, get(w, 32))
    put(w, 4120, raw)
    put(w, 4128, get(w, 40))
    put(w, 4136, get(w, 256))
    put(w, 4144, get(w, 264))
    put(w, 4152, get(w, 280))
    put(w, 4160, get(w, 288))
    put(w, 4168, get(w, 272))
    put(w, 4176, get(w, 296))
    put(w, 4184, get(w, 432))
    complete = get(w, 304) != 0 and get(w, 312) != 0 and get(w, 272) == 0 and get(w, 296) == 0 and get(w, 440) == 0
    complete = complete and get(w, 256) == get(w, 264) and get(w, 280) == get(w, 288)
    put(w, 4192, choose(complete, 1, 0))
    put(w, 4200, choose(get(w, 344) == 3, 1, 0))
    put(w, 4208, get(w, 128) * 1000000000 + get(w, 136) - get(w, 24))
    put(w, 4216, get(w, 448))
    return 0

def child(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 113 or (failed(result) and phase != 114):
        put(w, 432, choose(failed(result), 0 - result, 5))
        return call(o, w, 114, 1, get(w, 112), 432, 8, 0, 0, 0, 12)
    if phase == 114:
        return call(o, w, 999, 60, 127, 0, 0, 0, 0, 0, 0)
    if phase == 100:
        return call(o, w, 101, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 101:
        if result != get(w, 456):
            put(w, 432, 3)
            return call(o, w, 114, 1, get(w, 112), 432, 8, 0, 0, 0, 12)
        return call(o, w, 102, 14, 2, 800, 0, 8, 0, 0, 12)
    if phase == 102:
        return call(o, w, 103, 112, 0, 0, 0, 0, 0, 0, 0)
    if phase == 103:
        return call(o, w, 104, 13, 13, 1600, 0, 8, 0, 0, 12)
    if phase == 104:
        return call(o, w, 105, 13, 25, 1600, 0, 8, 0, 0, 12)
    if phase == 105:
        return call(o, w, 106, 33, uint(s, 32), 0, 0, 0, 0, 0, 0)
    if phase == 106:
        return call(o, w, 115, 8, 0, 0, 0, 0, 0, 0, 0)
    if phase == 115:
        return call(o, w, 107, 33, get(w, 80), 1, 0, 0, 0, 0, 0)
    if phase == 107:
        return call(o, w, 108, 33, get(w, 96), 2, 0, 0, 0, 0, 0)
    if phase == 108:
        return call(o, w, 109, 81, uint(s, 56), 0, 0, 0, 0, 0, 0)
    if phase == 109:
        return call(o, w, 110, 160, 4, 1664, 0, 0, 0, 0, 12)
    if phase == 110 and uint(s, 112) != 0:
        put(w, 1664, uint(s, 112))
        put(w, 1672, uint(s, 112))
        return call(o, w, 111, 160, 9, 1664, 0, 0, 0, 0, 12)
    if phase == 110 or phase == 111:
        return call(o, w, 112, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 112:
        put(w, 488, 0)
        return inherit_next(s, o, w)
    if phase == 116:
        put(w, 488, get(w, 488) + 1)
        return inherit_next(s, o, w)
    return 0

def inherit_next(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 488)
    if index < get(w, 480):
        return call(o, w, 116, 72, get(w, 9504 + index * 8), 2, 0, 0, 0, 0, 0)
    return call(o, w, 113, 322, uint(s, 24), get(w, 504), 8192, 8832, 4096, 0, 244)

def timer_value(w:mutbuf, value:u64) -> u64:
    put(w, 1536, 0)
    put(w, 1544, 0)
    put(w, 1552, value // 1000000000)
    put(w, 1560, value % 1000000000)
    return 0

def relocate(o:mutbuf, w:mutbuf, phase:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

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

def failed(result:u64) -> bool:
    return result >> 63 != 0

def uint(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return getn(w, at, 8)

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    index = 0
    value = 0
    while index < count:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def document():
    nodes = ast.parse(SOURCE).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'subprocess', 'functions': functions})


def main():
    source = (ROOT / ADAPTER_PATH).read_bytes()
    with TemporaryDirectory(prefix='hia-subprocess-adapter-') as directory:
        adapter, holes, _ = adapter_layout(Path(directory), ADAPTER_PATH, source, {'policy': 'subprocess_policy_call_hole'})
    header = elf_header()
    hole = holes['policy']
    packer = packer_document(magic=PACKER_MAGIC, module='subprocess_packer',
                             image_template=(header + adapter, (len(header) + hole,)))
    for path, item in ((SOURCE_PATH, document()), (PACKER_PATH, bind_adapter(packer, source, adapter, (hole,)))):
        (ROOT / path).write_text(render_assembly(item))


if __name__ == '__main__':
    main()
