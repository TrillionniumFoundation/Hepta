"""Author native paged immutable-prefix cursors for the complete row owner.

Development component. It is not selected by an ordinary worker, and no
hosted row iterator is a production fallback.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES, catalog
from tools.generate_hia_agent_namespace_compare import COMPARE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIANVW01','little')
RECORD_MAGIC=int.from_bytes(b'HIANLR01','little')

VIEWS=r'''
def namespace_views(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 12288:
        return 4294967293
    if get(w, 8) == 4 or get(w, 8) == 5:
        return emit(o, w, 4294967293)
    if length(o) < 256:
        return poison(w, 1)
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            poison(w, 2)
            return emit(o, w, 4294967293)
        return emit(o, w, 0)
    if valid_state(w) == 0 or frame(s, w) == 0:
        poison(w, 3)
        return emit(o, w, 4294967293)
    command = read64(s, 8)
    if command == 4:
        put(w, 32, read64(s, 32))
        clear_result(w)
        put(w, 8, 5)
        return emit(o, w, 0)
    if command == 2:
        put(w, 32, read64(s, 32))
        clear_result(w)
        if get(w, 632) == 1:
            return emit(o, w, 3)
        put(w, 312, 0)
        put(w, 256, 0)
        put(w, 264, get(w, 120))
        put(w, 8, 2)
        put(w, 656, 0)
        return scan(o, w, 0)
    status = read64(s, 56)
    if status == 2:
        poison(w, 4)
        return emit(o, w, 4294967293)
    if status == 1:
        if read64(s, 104) == 4:
            return read_more(o, w)
        return io_error(o, w, 266, read64(s, 104))
    count = read64(s, 80)
    if count == 0:
        return io_error(o, w, 522, 0)
    copy_input(w, s, get(w, 600) + get(w, 592), 160, count)
    put(w, 592, get(w, 592) + count)
    put(w, 48, 0)
    if get(w, 592) < get(w, 584):
        return read_more(o, w)
    return continue_read(o, w)

def poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 8) != 4:
        put(w, 192, reason)
    put(w, 8, 4)
    return 4294967293

def io_error(o:mutbuf, w:mutbuf, code:u64, detail:u64) -> u64:
    clear_result(w)
    put(w, 184, code)
    put(w, 640, detail)
    put(w, 8, 6)
    put(w, 48, 0)
    put(w, 56, 0)
    put(w, 656, 1)
    return emit(o, w, 2)

def clear_result(w:mutbuf) -> u64:
    fill_range(w, 200, 40, 0)
    return 0

def zeros(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def initialize(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 160 or read64(s, 0) != VIEW_MAGIC or read64(s, 8) != 1 or read64(s, 32) != 1:
        return 0
    if (read64(s, 16) == 0 and read64(s, 24) == 0) or zeros(s, 40, 64) == 0 or zeros(s, 136, 160) == 0:
        return 0
    if read64(s, 64) == 0 or read64(s, 72) == 0 or read64(s, 80) == 0:
        return 0
    table = read64(s, 88)
    order = read64(s, 96)
    if table < 1 or table > 10 or order < 1 or order > 2 or (order == 2 and table != 8):
        return 0
    if read64(s, 120) == 0 or read64(s, 112) > 9223372036854775807 or read64(s, 128) > 9223372036854775807:
        return 0
    if (read64(s, 104) == 0 and read64(s, 112) != 0) or read64(s, 104) == read64(s, 120):
        return 0
    at = 0
    while at < 12288:
        if byte(w, at) != 0:
            return 0
        at = at + 1
    put(w, 0, VIEW_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, 1)
    put(w, 64, read64(s, 64))
    put(w, 72, read64(s, 72))
    put(w, 80, read64(s, 80))
    put(w, 88, table)
    put(w, 96, order)
    put(w, 112, read64(s, 104))
    put(w, 120, read64(s, 112))
    put(w, 128, read64(s, 120))
    put(w, 136, read64(s, 128))
    put(w, 656, 1)
    return 1

def expected_buffer(phase:u64) -> u64:
    if phase == 10 or phase == 11 or phase == 20 or phase == 21 or phase == 30:
        return 1024
    if phase == 31:
        return 1032
    if phase == 32:
        return 1040
    if phase == 33:
        return 1056
    if phase == 34:
        return 1072
    if phase == 35:
        return 1088
    if phase == 36:
        return 2048
    if phase == 37:
        return 6144
    return 0

def expected_count(w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase == 10 or phase == 20 or phase == 32 or phase == 34:
        return 16
    if phase == 11 or phase == 21:
        return 64
    if phase == 30 or phase == 31 or phase == 33 or phase == 35:
        return 8
    if phase == 36 or phase == 37:
        return get(w, 624)
    return 0

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != VIEW_MAGIC or get(w, 8) < 1 or (get(w, 8) > 2 and get(w, 8) != 6):
        return 0
    if get(w, 16) == 0 and get(w, 24) == 0:
        return 0
    if get(w, 32) == 0 or get(w, 64) == 0 or get(w, 72) == 0 or get(w, 80) == 0 or get(w, 128) == 0:
        return 0
    if get(w, 88) < 1 or get(w, 88) > 10 or get(w, 96) < 1 or get(w, 96) > 2 or (get(w, 96) == 2 and get(w, 88) != 8):
        return 0
    if get(w, 144) > 1 or get(w, 312) > 1 or get(w, 632) > 1 or get(w, 192) != 0:
        return 0
    if get(w, 112) == get(w, 128) or (get(w, 112) == 0 and get(w, 120) != 0):
        return 0
    if get(w, 120) > 9223372036854775807 or get(w, 136) > 9223372036854775807:
        return 0
    if get(w, 8) == 1:
        return choose(get(w, 48) == 0 and get(w, 56) == 0 and get(w, 184) == 0 and get(w, 656) == 1, 1, 0)
    if get(w, 8) == 6:
        return choose(get(w, 48) == 0 and get(w, 56) == 0 and get(w, 184) != 0 and get(w, 656) == 1, 1, 0)
    if get(w, 48) != 1 or get(w, 40) == 0 or get(w, 584) == 0 or get(w, 584) > 4096 or get(w, 592) >= get(w, 584) or get(w, 656) != 0:
        return 0
    if get(w, 600) != expected_buffer(get(w, 56)) or get(w, 584) != expected_count(w) or get(w, 600) == 0:
        return 0
    if get(w, 256) > 2 or get(w, 368) > 2:
        return 0
    return expected_read(w)

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 160 or read64(s, 0) != VIEW_MAGIC or read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        return 0
    command = read64(s, 8)
    if command == 2 or command == 4:
        if length(s) != 160 or get(w, 8) == 2 or (get(w, 8) == 6 and command != 4):
            return 0
        if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return 0
        return zeros(s, 40, 160)
    if command != 3 or get(w, 8) != 2 or read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40) or read64(s, 48) != 1:
        return 0
    if read64(s, 64) != get(w, 568) or read64(s, 72) != get(w, 576) + get(w, 592) or read64(s, 88) != get(w, 72) or read64(s, 96) != get(w, 80):
        return 0
    if zeros(s, 112, 160) == 0 or read64(s, 80) != length(s) - 160:
        return 0
    status = read64(s, 56)
    if status == 0:
        return choose(read64(s, 80) <= get(w, 584) - get(w, 592) and read64(s, 104) == 0, 1, 0)
    if status == 1:
        return choose(read64(s, 80) == 0 and read64(s, 104) > 0 and read64(s, 104) <= 4095, 1, 0)
    return choose(status == 2 and read64(s, 80) == 0 and read64(s, 104) == 0, 1, 0)

def range_valid(w:mutbuf, fd:u64, at:u64, size:u64) -> u64:
    end = 0
    if fd != 0 and fd == get(w, 112):
        end = get(w, 120)
    elif fd == get(w, 128):
        end = get(w, 136)
    else:
        return 0
    return choose(at <= end and size <= end - at, 1, 0)

def expected_read(w:mutbuf) -> u64:
    phase = get(w, 56)
    fd = 0
    at = 0
    if phase == 10 or phase == 11 or phase == 20 or phase == 21:
        slot = choose(phase < 20, 256, 368)
        if get(w, slot) > 1:
            return 0
        fd = stream_fd(w, get(w, slot))
        at = get(w, slot + 8)
        if phase == 10 or phase == 20:
            if at < 80:
                return 0
            at = at - 16
        elif get(w, 648) < 80 or range_valid(w, fd, at, get(w, 648)) == 0:
            return 0
    else:
        if get(w, 96) != 2 or get(w, 432) < 1 or get(w, 432) > 2 or get(w, 440) > 1:
            return 0
        if get(w, 448) != get(w, 272) or get(w, 456) != get(w, 280) or get(w, 464) != get(w, 288):
            return 0
        right = choose(get(w, 432) == 1, 160, 320)
        if get(w, 472) != get(w, right) or get(w, 480) != get(w, right + 8) or get(w, 488) != get(w, right + 16):
            return 0
        if get(w, 464) < 136 or get(w, 488) < 136:
            return 0
        if range_valid(w, get(w, 448), get(w, 456), get(w, 464)) == 0 or range_valid(w, get(w, 472), get(w, 480), get(w, 488)) == 0:
            return 0
        if phase == 30:
            fd = get(w, 448)
            at = get(w, 456) + 64
        elif phase == 31:
            fd = get(w, 472)
            at = get(w, 480) + 64
        elif phase == 32 or phase == 33 or phase == 36:
            fd = get(w, 448)
            at = get(w, 496)
            if phase != 32:
                at = at + 16
            if phase == 36:
                if get(w, 560) > get(w, 520) or get(w, 624) > get(w, 520) - get(w, 560):
                    return 0
                at = at + get(w, 560)
        elif phase == 34 or phase == 35 or phase == 37:
            fd = get(w, 472)
            at = get(w, 504)
            if phase != 34:
                at = at + 16
            if phase == 37:
                if get(w, 560) > get(w, 536) or get(w, 624) > get(w, 536) - get(w, 560):
                    return 0
                at = at + get(w, 560)
        else:
            return 0
    if get(w, 568) != fd or get(w, 576) != at:
        return 0
    return range_valid(w, fd, at, get(w, 584))

def read_more(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 40) == 18446744073709551615:
        poison(w, 5)
        return emit(o, w, 4294967293)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, 1)
    return emit(o, w, 1)

def read_range(o:mutbuf, w:mutbuf, phase:u64, fd:u64, at:u64, size:u64) -> u64:
    if size == 0 or size > 4096 or expected_buffer(phase) == 0 or range_valid(w, fd, at, size) == 0:
        return io_error(o, w, 11, 1)
    put(w, 56, phase)
    put(w, 568, fd)
    put(w, 576, at)
    put(w, 584, size)
    put(w, 592, 0)
    put(w, 600, expected_buffer(phase))
    fill_range(w, get(w, 600), size, 0)
    return read_more(o, w)

def stream_fd(w:mutbuf, stream:u64) -> u64:
    return choose(stream == 0, get(w, 112), get(w, 128))

def scan(o:mutbuf, w:mutbuf, nested:u64) -> u64:
    stream_slot = choose(nested == 0, 256, 368)
    pos_slot = stream_slot + 8
    while get(w, stream_slot) < 2:
        pos = get(w, pos_slot)
        if pos == 0:
            put(w, stream_slot, get(w, stream_slot) + 1)
            if get(w, stream_slot) == 1:
                put(w, pos_slot, get(w, 136))
        else:
            if pos < 80:
                return io_error(o, w, 11, 2)
            return read_range(o, w, choose(nested == 0, 10, 20), stream_fd(w, get(w, stream_slot)), pos - 16, 16)
    if nested != 0:
        return io_error(o, w, 11, 3)
    if get(w, 312) == 0:
        put(w, 632, 1)
        put(w, 8, 1)
        put(w, 56, 0)
        put(w, 656, 1)
        return emit(o, w, 3)
    put(w, 144, 1)
    put(w, 152, get(w, 344))
    put(w, 160, get(w, 320))
    put(w, 168, get(w, 328))
    put(w, 176, get(w, 336))
    if get(w, 352) == 2:
        put(w, 312, 0)
        put(w, 256, 0)
        put(w, 264, get(w, 120))
        return scan(o, w, 0)
    put(w, 200, get(w, 344))
    put(w, 208, get(w, 320))
    put(w, 216, get(w, 328))
    put(w, 224, get(w, 336))
    put(w, 232, get(w, 352))
    put(w, 8, 1)
    put(w, 56, 0)
    put(w, 656, 1)
    return emit(o, w, 0)

def footer(o:mutbuf, w:mutbuf, nested:u64) -> u64:
    stream_slot = choose(nested == 0, 256, 368)
    pos_slot = stream_slot + 8
    span = get(w, 1024)
    if get(w, 1032) != RECORD_MAGIC_VALUE or span < 80 or span > get(w, pos_slot):
        return io_error(o, w, 11, 4)
    put(w, pos_slot, get(w, pos_slot) - span)
    put(w, 648, span)
    return read_range(o, w, choose(nested == 0, 11, 21), stream_fd(w, get(w, stream_slot)), get(w, pos_slot), 64)

def header(o:mutbuf, w:mutbuf, nested:u64) -> u64:
    kind = get(w, 1040)
    table = get(w, 1048)
    rowid = get(w, 1056)
    size = get(w, 1064)
    span = get(w, 648)
    if get(w, 1024) != RECORD_MAGIC_VALUE or get(w, 1032) != 1 or get(w, 1080) != 0 or get(w, 1072) != span:
        return io_error(o, w, 11, 5)
    if kind < 1 or kind > 3 or table < 1 or table > 10 or size != span - 80:
        return io_error(o, w, 11, 5)
    if (kind == 2 and size != 0) or (kind == 1 and size < 8 + row_width(table) * 16):
        return io_error(o, w, 11, 5)
    if kind == 3 and (table != 5 or rowid != 0 or size < 24):
        return io_error(o, w, 11, 5)
    if table != get(w, 88) or kind == 3:
        return scan(o, w, nested)
    if nested != 0:
        if rowid != get(w, 384):
            return scan(o, w, 1)
        if kind == 2:
            return scan(o, w, 0)
        put(w, 272, stream_fd(w, get(w, 368)))
        put(w, 280, get(w, 376))
        put(w, 288, span)
        put(w, 296, rowid)
        put(w, 304, kind)
        return eligible(o, w)
    put(w, 272, stream_fd(w, get(w, 256)))
    put(w, 280, get(w, 264))
    put(w, 288, span)
    put(w, 296, rowid)
    put(w, 304, kind)
    if get(w, 96) == 2:
        put(w, 384, rowid)
        put(w, 368, 0)
        put(w, 376, get(w, 120))
        return scan(o, w, 1)
    if get(w, 144) == 1 and compare_signed(rowid, get(w, 152)) != 2:
        return scan(o, w, 0)
    if get(w, 312) == 0 or compare_signed(rowid, get(w, 344)) == 0:
        remember_candidate(w)
    return scan(o, w, 0)

def remember_candidate(w:mutbuf) -> u64:
    put(w, 312, 1)
    put(w, 320, get(w, 272))
    put(w, 328, get(w, 280))
    put(w, 336, get(w, 288))
    put(w, 344, get(w, 296))
    put(w, 352, get(w, 304))
    return 0

def eligible(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 144) == 1:
        if get(w, 296) == get(w, 152):
            return scan(o, w, 0)
        return start_compare(o, w, 1)
    return better_candidate(o, w)

def better_candidate(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 312) == 0:
        remember_candidate(w)
        return scan(o, w, 0)
    if get(w, 296) == get(w, 344):
        return scan(o, w, 0)
    return start_compare(o, w, 2)

def start_compare(o:mutbuf, w:mutbuf, purpose:u64) -> u64:
    put(w, 432, purpose)
    put(w, 440, 0)
    put(w, 448, get(w, 272))
    put(w, 456, get(w, 280))
    put(w, 464, get(w, 288))
    right = choose(purpose == 1, 160, 320)
    put(w, 472, get(w, right))
    put(w, 480, get(w, right + 8))
    put(w, 488, get(w, right + 16))
    put(w, 496, get(w, 456) + 72)
    put(w, 504, get(w, 480) + 72)
    return read_range(o, w, 30, get(w, 448), get(w, 456) + 64, 8)

def read_cell(o:mutbuf, w:mutbuf, right:u64) -> u64:
    base = choose(right == 0, 448, 472)
    position = get(w, choose(right == 0, 496, 504))
    end = get(w, base + 8) + get(w, base + 16) - 16
    if position > end or end - position < 16:
        return io_error(o, w, 11, 6)
    return read_range(o, w, choose(right == 0, 32, 34), get(w, base), position, 16)

def cell_header(o:mutbuf, w:mutbuf, right:u64) -> u64:
    source = choose(right == 0, 1040, 1072)
    base = choose(right == 0, 448, 472)
    position = get(w, choose(right == 0, 496, 504))
    end = get(w, base + 8) + get(w, base + 16) - 16
    kind = get(w, source)
    size = get(w, source + 8)
    if position > end or end - position < 16 or size > end - position - 16 or kind > 4:
        return io_error(o, w, 11, 7)
    if (kind == 0 and size != 0) or ((kind == 1 or kind == 2) and size != 8):
        return io_error(o, w, 11, 7)
    put(w, choose(right == 0, 512, 528), kind)
    put(w, choose(right == 0, 520, 536), size)
    put(w, choose(right == 0, 544, 552), 0)
    if kind == 1 or kind == 2:
        return read_range(o, w, choose(right == 0, 33, 35), get(w, base), position + 16, 8)
    if right == 0:
        return read_cell(o, w, 1)
    return compare_current_cells(o, w)

def effective_kind(kind:u64, bits:u64) -> u64:
    if kind == 2 and ((bits >> 52) & 2047) == 2047 and (bits & 4503599627370495) != 0:
        return 0
    return kind

def compare_current_cells(o:mutbuf, w:mutbuf) -> u64:
    left = effective_kind(get(w, 512), get(w, 544))
    right = effective_kind(get(w, 528), get(w, 552))
    if left == 0 or right == 0:
        return compared(o, w, choose(left == right, 1, choose(left == 0, 0, 2)))
    if left <= 2 and right <= 2:
        a = get(w, 544)
        b = get(w, 552)
        result = 0
        if left == 1 and right == 1:
            result = compare_signed(a, b)
        elif left == 2 and right == 2:
            result = compare_real(a, b)
        elif left == 1:
            result = compare_integer_real(a, b)
        else:
            result = reverse(compare_integer_real(b, a))
        return compared(o, w, result)
    if left != right:
        return compared(o, w, choose(left < right, 0, 2))
    put(w, 560, 0)
    return compare_window(o, w)

def compare_window(o:mutbuf, w:mutbuf) -> u64:
    left_size = get(w, 520)
    right_size = get(w, 536)
    position = get(w, 560)
    size = choose(left_size < right_size, left_size, right_size)
    if position == size:
        return compared(o, w, compare_unsigned(left_size, right_size))
    if position > size:
        poison(w, 6)
        return emit(o, w, 4294967293)
    size = size - position
    if size > 4096:
        size = 4096
    put(w, 624, size)
    return read_range(o, w, 36, get(w, 448), get(w, 496) + 16 + position, size)

def compare_window_bytes(o:mutbuf, w:mutbuf) -> u64:
    at = 0
    while at < get(w, 624):
        left = byte(w, 2048 + at)
        right = byte(w, 6144 + at)
        if left != right:
            return compared(o, w, choose(left < right, 0, 2))
        at = at + 1
    put(w, 560, get(w, 560) + get(w, 624))
    return compare_window(o, w)

def compared(o:mutbuf, w:mutbuf, result:u64) -> u64:
    if result == 1:
        if get(w, 440) == 0:
            put(w, 440, 1)
            put(w, 496, get(w, 496) + 16 + get(w, 520))
            put(w, 504, get(w, 504) + 16 + get(w, 536))
            return read_cell(o, w, 0)
        result = compare_signed(get(w, 296), choose(get(w, 432) == 1, get(w, 152), get(w, 344)))
    if get(w, 432) == 1:
        if result == 2:
            return better_candidate(o, w)
    elif result == 0:
        remember_candidate(w)
    return scan(o, w, 0)

def continue_read(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase == 10 or phase == 20:
        return footer(o, w, choose(phase == 10, 0, 1))
    if phase == 11 or phase == 21:
        return header(o, w, choose(phase == 11, 0, 1))
    if phase == 30:
        if get(w, 1024) != 3:
            return io_error(o, w, 11, 8)
        return read_range(o, w, 31, get(w, 472), get(w, 480) + 64, 8)
    if phase == 31:
        if get(w, 1032) != 3:
            return io_error(o, w, 11, 8)
        return read_cell(o, w, 0)
    if phase == 32 or phase == 34:
        return cell_header(o, w, choose(phase == 32, 0, 1))
    if phase == 33:
        put(w, 544, get(w, 1056))
        return read_cell(o, w, 1)
    if phase == 35:
        put(w, 552, get(w, 1088))
        return compare_current_cells(o, w)
    if phase == 36:
        return read_range(o, w, 37, get(w, 472), get(w, 504) + 16 + get(w, 560), get(w, 624))
    if phase == 37:
        return compare_window_bytes(o, w)
    poison(w, 7)
    return emit(o, w, 4294967293)

def emit(o:mutbuf, w:mutbuf, status:u64) -> u64:
    if length(o) < 256:
        return 4294967293
    fill_range(o, 0, length(o), 0)
    put(o, 0, VIEW_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 56))
    if status == 1:
        put(o, 56, 1)
        put(o, 64, get(w, 568))
        put(o, 72, get(w, 576) + get(w, 592))
        put(o, 80, get(w, 584) - get(w, 592))
    put(o, 88, get(w, 72))
    put(o, 96, get(w, 80))
    put(o, 104, get(w, 88))
    put(o, 112, get(w, 96))
    put(o, 120, get(w, 208))
    put(o, 128, get(w, 216))
    put(o, 136, get(w, 224))
    put(o, 144, get(w, 200))
    put(o, 152, get(w, 232))
    put(o, 160, get(w, 184))
    put(o, 168, get(w, 192))
    put(o, 176, get(w, 640))
    put(o, 184, get(w, 64))
    put(o, 192, get(w, 8))
    put(o, 200, get(w, 632))
    put(o, 208, 1)
    return status
'''


def source_program():
    result = VIEWS.replace('RECORD_MAGIC_VALUE', str(RECORD_MAGIC)).replace('VIEW_MAGIC', str(MAGIC))
    pure = {'compare_unsigned', 'compare_signed', 'compare_real',
            'compare_integer_real', 'compare_absolute_integer_real', 'reverse'}
    selected = {node.name: ast.get_source_segment(COMPARE, node)
                for node in ast.parse(COMPARE).body if node.name in pure}
    if set(selected) != pure:
        raise ValueError('complete frozen scalar comparison functions are required')
    result += '\n\n' + '\n\n'.join(selected.values()) + '\n'
    result += VALUES[VALUES.index('\ndef read64('):]
    result += '\ndef row_width(table:u64) -> u64:\n'
    for table in catalog()['tables']:
        result += '    if table == %d:\n        return %d\n' % (table['id'], len(table['columns']))
    return result + '    return 0\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace views HIA symbol')
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_namespace_views', 'functions': functions})


def main():
    path = ROOT/'examples/hia_bootstrap/agent_namespace_views.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
