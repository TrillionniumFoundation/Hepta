"""Author the HIA owner of remote job observations and its Linux ABI.

The checked-in HIA programs are the product sources. This development authoring
module is not executed by the observation image or its source-only native build.
"""
from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_job_supervisor import document
from tools.generate_hia_native_filter import LINK_SOURCE
from tools.generate_hia_job_observation_status import extend, STATUS_FIELDS, STATUS_TEXT
from tools.generate_hia_job_metadata import NORMALIZE, metadata_json_source

ROOT = Path(__file__).resolve().parents[1]
STATE_BYTES = 224 << 20
REQUEST_MAGIC = int.from_bytes(b'HIAJOBQ1', 'little')
PACKER_MAGIC = int.from_bytes(b'HIAJOK01', 'little')
META = 1 << 20
OUTPUT = 5 << 20
ARENA = 16 << 20
ARENA_BYTES = 160 << 20
SCRATCH = 184 << 20
SCRATCH_BYTES = 32 << 20
RAW_JSON = 176 << 20
NONE = (1 << 64) - 1

POLICY = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if admit(s, w) == 0:
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 16, result)
        store(w, 8192, 47)
        store(w, 8193, 0)
        return call(o, w, 2, 257, NEG100, 8192, 2818048, 0, 0, 0, 12)
    if phase == 2:
        if failed(result):
            return 0
        put(w, 24, result)
        put(w, 32, 0)
        put(w, 40, 0)
        return next_directory(s, o, w)
    if phase == 3:
        if failed(result):
            return 0
        put(w, 24, result)
        return call(o, w, 4, 5, result, 4096, 0, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or getn(w, 4120, 4) & 61440 != 16384:
            return 0
        if get(w, 40) + 3 >= get(w, 48):
            if getn(w, 4124, 4) != get(w, 16) or getn(w, 4120, 4) & 4095 != 448:
                return 0
        put(w, 40, get(w, 40) + 1)
        return next_directory(s, o, w)
    if phase >= 10 and phase <= 19:
        return metadata(s, o, w, phase, result)
    if phase >= 30 and phase <= 39:
        return log_observation(s, o, w, phase, result)
    if phase == 90:
        if result == NEG4:
            return write_reply(o, w)
        if failed(result) or result == 0 or result > get(w, 176) - get(w, 184):
            return 0
        put(w, 184, get(w, 184) + result)
        if get(w, 184) < get(w, 176):
            return write_reply(o, w)
        return call(o, w, 99, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 80 or length(s) > 65536 or uint(s, 0) != REQUEST_MAGIC:
        return 0
    if uint(s, 8) != 0 or uint(s, 72) != 0:
        return 0
    path_size = uint(s, 40)
    job_size = uint(s, 48)
    unit_size = uint(s, 56)
    if path_size < 6 or path_size > 4096 or job_size == 0 or job_size > 128 or unit_size == 0 or unit_size > 512 or uint(s, 64) != 64:
        return 0
    if length(s) != 80 + path_size + job_size + unit_size + 64 or byte(s, 80) != 47:
        return 0
    at = 80
    while at < length(s):
        if byte(s, at) == 0:
            return 0
        at = at + 1
    at = 80 + path_size + job_size + unit_size
    while at < length(s):
        c = byte(s, at)
        if (c < 48 or c > 57) and (c < 97 or c > 102):
            return 0
        at = at + 1
    put(w, 56, 80 + path_size)
    put(w, 64, 80 + path_size + job_size)
    put(w, 72, 80 + path_size + job_size + unit_size)
    # Count nonempty components and bind the penultimate component to jobs.
    count = 0
    at = 0
    previous = 0
    last = 0
    previous_size = 0
    last_size = 0
    while at < path_size:
        if byte(s, 80 + at) == 47:
            at = at + 1
        else:
            start = at
            while at < path_size and byte(s, 80 + at) != 47:
                at = at + 1
            size = at - start
            if (size == 1 and byte(s, 80 + start) == 46) or (size == 2 and byte(s, 80 + start) == 46 and byte(s, 81 + start) == 46):
                return 0
            previous = last
            previous_size = last_size
            last = start
            last_size = size
            count = count + 1
    if count < 3 or previous_size != 4:
        return 0
    if byte(s, 80 + previous) != 106 or byte(s, 81 + previous) != 111 or byte(s, 82 + previous) != 98 or byte(s, 83 + previous) != 115:
        return 0
    put(w, 48, count)
    limit = uint(s, 32)
    if limit < 1:
        limit = 1
    if limit > 16384:
        limit = 16384
    put(w, 80, limit)
    return 1

def next_directory(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 32)
    size = uint(s, 40)
    while at < size and byte(s, 80 + at) == 47:
        at = at + 1
    if at == size:
        put(w, 88, 0)
        return open_metadata(o, w)
    start = at
    while at < size and byte(s, 80 + at) != 47:
        store(w, 8192 + at - start, byte(s, 80 + at))
        at = at + 1
    store(w, 8192 + at - start, 0)
    put(w, 32, at)
    flags = choose(get(w, 40) + 3 >= get(w, 48), 720896, 2818048)
    return call(o, w, 3, 257, get(w, 24), 8192, flags, 0, 0, 0, 12)

def open_metadata(o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 88)
    at = 8192
    if which == 0:
        at = text_request_name(w, at)
    elif which == 1:
        at = text_launch_name(w, at)
    else:
        at = text_exit_name(w, at)
    store(w, at, 0)
    return call(o, w, 10, 257, get(w, 24), 8192, 657408, 0, 0, 0, 12)

def metadata(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 10:
        if result == NEG2 and get(w, 88) != 0:
            return next_metadata(s, o, w)
        if failed(result):
            return 0
        put(w, 96, result)
        return call(o, w, 11, 5, result, 4096, 0, 0, 0, 0, 12)
    if phase == 11:
        if failed(result) or safe_file(w, 4096) == 0 or get(w, 4144) > 4194304:
            return 0
        put(w, 104, 0)
        return read_metadata(o, w)
    if phase == 12:
        if result == NEG4:
            return read_metadata(o, w)
        if failed(result) or result > 4194305 - get(w, 104):
            return 0
        if result != 0:
            put(w, 104, get(w, 104) + result)
            if get(w, 104) > 4194304:
                return 0
            return read_metadata(o, w)
        return call(o, w, 13, 5, get(w, 96), 4352, 0, 0, 0, 0, 12)
    if phase == 13:
        if failed(result) or same_stamp(w, 4096, 4352) == 0:
            return 0
        return call(o, w, 14, 262, get(w, 24), 8192, 4608, 256, 0, 0, 60)
    if phase == 14:
        if failed(result) or same_stamp(w, 4096, 4608) == 0:
            return 0
        return call(o, w, 15, 3, get(w, 96), 0, 0, 0, 0, 0, 0)
    if phase == 15:
        if failed(result):
            return 0
        normalized = normalize_json(w, META, get(w, 104))
        if normalized == NONE:
            return metadata_failure(s, o, w, True)
        put(w, 232, normalized)
        put(w, SCRATCH + 48, 2097152)
        put(w, SCRATCH + 56, 699047)
        return decode(o, w, 16, RAW_JSON, normalized)
    if phase == 16:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            return 0
        if get(w, 88) == 0 and request_bound(s, w) == 0:
            return 0
        return next_metadata(s, o, w)
    return 0

def read_metadata(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 12, 0, get(w, 96), META + get(w, 104), 4194305 - get(w, 104), 0, 0, 0, 12)

def next_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 88) + 1
    put(w, 88, which)
    if which < 3:
        return open_metadata(o, w)
    at = text_reply_open(w, OUTPUT)
    at = quoted_input(s, w, at, get(w, 56), uint(s, 48))
    at = text_stdout(w, at)
    put(w, 176, at)
    put(w, 112, 0)
    return open_log(s, o, w)

def request_bound(s:readbuf, w:mutbuf) -> u64:
    if equal_input_field(s, w, lookup(w, 1), get(w, 56), uint(s, 48)) == 0:
        return 0
    if equal_input_field(s, w, lookup(w, 2), 80, uint(s, 40)) == 0:
        return 0
    if equal_input_field(s, w, lookup(w, 3), get(w, 64), uint(s, 56)) == 0:
        return 0
    digest = lookup(w, 4)
    if digest == NONE:
        digest = lookup(w, 5)
    return equal_input_field(s, w, digest, get(w, 72), 64)

def lookup(w:mutbuf, field:u64) -> u64:
    child = get(w, ARENA + 88)
    found = NONE
    while child != NONE:
        record = ARENA + 64 + child * 72
        if key_id(w, ARENA + get(w, record + 40), get(w, record + 48)) == field:
            found = record
        child = get(w, record + 16)
    return found

def equal_input_field(s:readbuf, w:mutbuf, record:u64, at:u64, size:u64) -> u64:
    if record == NONE or get(w, record) != 4 or get(w, record + 32) != size:
        return 0
    source = ARENA + get(w, record + 24)
    index = 0
    while index < size:
        if byte(w, source + index) != byte(s, at + index):
            return 0
        index = index + 1
    return 1

def open_log(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 112) == 0:
        end = text_stdout_name(w, 8192)
        offset = uint(s, 16)
    else:
        end = text_stderr_name(w, 8192)
        offset = uint(s, 24)
    store(w, end, 0)
    put(w, 120, offset)
    put(w, 128, 0)
    put(w, 136, 0)
    put(w, 144, 0)
    return call(o, w, 30, 257, get(w, 24), 8192, 657408, 0, 0, 0, 12)

def log_observation(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 30:
        if result == NEG2:
            if get(w, 120) != 0:
                return 0
            return finish_log(s, o, w)
        if failed(result):
            return 0
        put(w, 96, result)
        return call(o, w, 31, 5, result, 4096, 0, 0, 0, 0, 12)
    if phase == 31:
        if failed(result) or safe_file(w, 4096) == 0:
            return 0
        size = get(w, 4144)
        if size >> 63 != 0 or get(w, 120) > size:
            return 0
        put(w, 128, size)
        count = size - get(w, 120)
        if count > get(w, 80):
            count = get(w, 80)
        put(w, 136, count)
        return read_log(o, w)
    if phase == 32:
        if result == NEG4:
            return read_log(o, w)
        if failed(result) or result > get(w, 136) - get(w, 144):
            return 0
        put(w, 144, get(w, 144) + result)
        if result != 0 and get(w, 144) < get(w, 136):
            return read_log(o, w)
        return call(o, w, 33, 262, get(w, 24), 8192, 4608, 256, 0, 0, 60)
    if phase == 33:
        if failed(result) or get(w, 4608) != get(w, 4096) or get(w, 4616) != get(w, 4104):
            return 0
        return call(o, w, 34, 5, get(w, 96), 4352, 0, 0, 0, 0, 12)
    if phase == 34:
        if failed(result) or get(w, 4368) != 1 or get(w, 4400) < get(w, 128):
            return 0
        return call(o, w, 35, 3, get(w, 96), 0, 0, 0, 0, 0, 0)
    if phase == 35:
        if failed(result):
            return 0
        return finish_log(s, o, w)
    return 0

def read_log(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 32, 17, get(w, 96), META + get(w, 144), get(w, 136) - get(w, 144), get(w, 120) + get(w, 144), 0, 0, 12)

def finish_log(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = text_offset(w, get(w, 176))
    at = decimal(w, at, get(w, 120))
    at = text_next_offset(w, at)
    at = decimal(w, at, get(w, 120) + get(w, 144))
    at = text_size(w, at)
    at = decimal(w, at, get(w, 128))
    at = text_eof(w, at)
    if get(w, 120) + get(w, 144) >= get(w, 128):
        at = text_true(w, at)
    else:
        at = text_false(w, at)
    at = text_text(w, at)
    at = quoted(w, at, META, get(w, 144))
    at = text_hex(w, at)
    index = 0
    while index < get(w, 144):
        point = byte(w, META + index)
        store(w, at, hex_digit(point >> 4))
        store(w, at + 1, hex_digit(point & 15))
        at = at + 2
        index = index + 1
    at = text_log_end(w, at)
    if get(w, 112) == 0:
        at = text_stderr(w, at)
        put(w, 176, at)
        put(w, 112, 1)
        return open_log(s, o, w)
    at = text_reply_end(w, at)
    put(w, 176, at)
    put(w, 184, OUTPUT)
    return write_reply(o, w)

def write_reply(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 90, 1, 1, get(w, 184), get(w, 176) - get(w, 184), 0, 0, 0, 12)

def safe_file(w:mutbuf, at:u64) -> u64:
    mode = getn(w, at + 24, 4)
    return choose(mode & 61440 == 32768 and mode & 18 == 0 and get(w, at + 16) == 1 and getn(w, at + 28, 4) == get(w, 16), 1, 0)

def same_stamp(w:mutbuf, left:u64, right:u64) -> u64:
    at = 0
    while at < 32:
        if get(w, left + at) != get(w, right + at):
            return 0
        at = at + 8
    if get(w, left + 48) != get(w, right + 48):
        return 0
    at = 88
    while at < 120:
        if get(w, left + at) != get(w, right + at):
            return 0
        at = at + 8
    return 1

def quoted_input(s:readbuf, w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, 16384 + index, byte(s, source + index))
        index = index + 1
    return quoted(w, at, 16384, size)

def quoted(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    return quote_value(w, at, source, size, False)

def quoted_metadata(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    return quote_value(w, at, source, size, True)

def quote_value(w:mutbuf, at:u64, source:u64, size:u64, metadata:bool) -> u64:
    store(w, at, 34)
    at = at + 1
    index = 0
    while index < size:
        point = byte(w, source + index)
        consumed = 1
        if point >= 128:
            needed = 0
            cp = 65533
            low = 128
            high = 191
            if point >= 194 and point <= 223:
                needed = 2
                cp = point & 31
            elif point >= 224 and point <= 239:
                needed = 3
                cp = point & 15
                if point == 224:
                    low = 160
                elif point == 237 and metadata == False:
                    high = 159
            elif point >= 240 and point <= 244:
                needed = 4
                cp = point & 7
                if point == 240:
                    low = 144
                elif point == 244:
                    high = 143
            valid = needed != 0
            while valid and consumed < needed:
                if index + consumed >= size:
                    valid = False
                else:
                    next = byte(w, source + index + consumed)
                    if next < low or next > high:
                        valid = False
                    else:
                        cp = (cp << 6) | (next & 63)
                        consumed = consumed + 1
                        low = 128
                        high = 191
            point = choose(valid, cp, 65533)
        if point == 34 or point == 92:
            store(w, at, 92)
            store(w, at + 1, point)
            at = at + 2
        elif point >= 32 and point < 127:
            store(w, at, point)
            at = at + 1
        elif point < 65536:
            at = escaped_scalar(w, at, point)
        else:
            point = point - 65536
            at = escaped_scalar(w, at, 55296 | (point >> 10))
            at = escaped_scalar(w, at, 56320 | (point & 1023))
        index = index + consumed
    store(w, at, 34)
    return at + 1

def escaped_scalar(w:mutbuf, at:u64, point:u64) -> u64:
    store(w, at, 92)
    store(w, at + 1, 117)
    store(w, at + 2, hex_digit((point >> 12) & 15))
    store(w, at + 3, hex_digit((point >> 8) & 15))
    store(w, at + 4, hex_digit((point >> 4) & 15))
    store(w, at + 5, hex_digit(point & 15))
    return at + 6

def hex_digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        store(w, at, 48)
        return at + 1
    count = 0
    while value != 0:
        store(w, 20480 + count, 48 + value % 10)
        count = count + 1
        value = value // 10
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 20480 + count))
        at = at + 1
    return at

def decode(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4

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

def failed(value:u64) -> bool:
    return value >> 63 != 0

def uint(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return getn(w, at, 8)

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    index = 0
    value = 0
    while index < count:
        value = value | (byte(w, at + index) << (8 * index))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0

def copy_bytes(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    return copy_state(w, source, target, size)
'''

TEXT = {
    'request_name': 'request.json', 'launch_name': 'launch.json',
    'exit_name': 'exit.json', 'stdout_name': 'stdout.log',
    'stderr_name': 'stderr.log', 'reply_open': '{"job_id":',
    'stdout': ',"stdout":', 'stderr': ',"stderr":',
    'offset': '{"offset":', 'next_offset': ',"next_offset":',
    'size': ',"size":', 'eof': ',"eof":', 'true': 'true', 'false': 'false',
    'text': ',"text":', 'hex': ',"bytes_hex":"', 'log_end': '"}',
    'reply_end': '}\n',
}
FIELDS = ('job_id', 'job_dir', 'unit', 'request_digest', 'request_fingerprint')
TEXT.update(STATUS_TEXT)
FIELDS += STATUS_FIELDS


def policy_source():
    source = extend(POLICY) + NORMALIZE
    values = dict(STATE_BYTES=STATE_BYTES, REQUEST_MAGIC=REQUEST_MAGIC,
                  META=META, OUTPUT=OUTPUT, ARENA_BYTES=ARENA_BYTES, ARENA=ARENA,
                  SCRATCH_BYTES=SCRATCH_BYTES, SCRATCH=SCRATCH, NONE=NONE,
                  RAW_JSON=RAW_JSON,
                  NEG100=(1 << 64) - 100, NEG4=(1 << 64) - 4, NEG2=(1 << 64) - 2)
    for name in sorted(values, key=len, reverse=True):
        source = source.replace(name, str(values[name]))
    # Fixed text is grouped into small HIA dispatch functions, retaining the
    # existing native compiler's function and block budgets without expansion.
    literals = list(TEXT.items())
    for index, (name, _) in enumerate(literals):
        source = source.replace(f'text_{name}(w, ', f'text_bank_{index // 16}(w, {index % 16}, ')
    for first in range(0, len(literals), 16):
        source += f'\ndef text_bank_{first // 16}(w:mutbuf, kind:u64, at:u64) -> u64:\n'
        for index, (_, value) in enumerate(literals[first:first + 16]):
            raw = value.encode()
            source += f'    if kind == {index}:\n'
            full = len(raw) // 8 * 8
            for i in range(0, full, 8):
                source += f'        put(w, at + {i}, {int.from_bytes(raw[i:i + 8], "little")})\n'
            for i in range(full, len(raw)):
                source += f'        store(w, at + {i}, {raw[i]})\n'
            source += f'        return at + {len(raw)}\n'
        source += '    return at\n'
    source += '\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    by_size = {}
    for i, name in enumerate(FIELDS, 1):
        raw = name.encode()
        by_size.setdefault(len(raw), []).append((i, raw))
    for size, fields in by_size.items():
        source += f'    if size == {size}:\n'
        for i, raw in fields:
            condition = ' and '.join(
                f'getn(w, at + {j}, {len(raw[j:j + 8])}) == {int.from_bytes(raw[j:j + 8], "little")}'
                for j in range(0, len(raw), 8))
            source += f'        if {condition}:\n            return {i}\n'
    source += '    return 0\n'
    return source


def observation_json_source():
    return metadata_json_source()


def template():
    adapter = ROOT / 'tools/hia_job_observation_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-job-observation-author-') as tmp:
        obj, raw = Path(tmp) / 'adapter.o', Path(tmp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(adapter), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('observation adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in
                           ('job_observation_policy_hole', 'job_observation_json_hole')}


def packer_source():
    prefix, holes = template()
    code = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    decoder = uint(s, 16, 8)
    if policy == 0 or decoder == 0 or policy > 1048576 or decoder > 1048576:
        return 4294967295
    if length(s) != 24 + policy + decoder:
        return 4294967295
    size = {len(prefix)} + policy + decoder
    if size > 2097152 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        code += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    code += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix)) + (' + policy' if name.endswith('json_hole') else '')
        code += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    code += f'    copy_bytes(s, o, 24, {len(prefix)}, policy + decoder)\n    return size\n'
    return code + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for module, source in (
        ('job_observation', policy_source()),
        ('job_observation_json', observation_json_source()),
        ('job_observation_packer', packer_source()),
    ):
        path = ROOT / 'examples/hia_bootstrap' / (module + '.hepta')
        path.write_text(render_assembly(document(source, module)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
