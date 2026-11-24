"""Author the HIA owner of the bound native job launch boundary.

The checked-in HIA sources implement policy. This authoring module and the
assembler are development tools; neither is executed by the resulting image.
"""
from __future__ import annotations

import ast
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_job_supervisor import document
from tools.generate_hia_job_observation import POLICY as OBSERVATION_POLICY
from tools.generate_hia_job_metadata import NORMALIZE, metadata_json_source, MAXIMUM_METADATA_DEPTH
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT = Path(__file__).resolve().parents[1]
STATE_BYTES = 224 << 20
PACKER_MAGIC = int.from_bytes(b'HIAJLNK1', 'little')
FIELDS = (
    'device', 'inode', 'job_id', 'launch_nonce', 'request_fingerprint',
    'hia_terminal_publisher', 'encoder', 'writer', 'supervisor',
    'engine_scratch_protocol', 'timeout_seconds', 'nice',
    'allowed_cwd_prefixes', 'cwd', 'default_cwd', 'executable',
    'stdin_path', 'env', 'args',
    'hia_terminal_supervisor', 'hia_owner_publication', 'hia_workdir_authority',
    'hia_loop_authority', 'hia_group_authority', 'hia_child_publication',
    'hia_original_child_wait', 'hia_native_output_capture', 'hia_workload_spawn',
    'hia_supervisor_identity', 'hia_owner_lock_admission',
    'hia_owner_record_encoding', 'hia_owner_file_lock',
    'hia_owner_marker_observation', 'hia_owner_custody', 'hia_native_job_owner',
)
TEXT = {
    'request_name': 'request.json', 'encoder_name': 'hia-terminal-encoder',
    'writer_name': 'hia-terminal-writer', 'supervisor_name': 'hia-terminal-supervisor',
    'stdin_name': 'stdin.bin', 'stdout_name': 'stdout.log',
    'stderr_name': 'stderr.log', 'receipt_name': 'native-exit.bin',
    'capture_memfd': 'hia-bound-launch-capture', 'request_memfd': 'hia-job-owner-request',
    'supervisor_argv': 'hia-job-supervisor',
    'env_job': 'HEPTA_RUNTIME_JOB_ID=', 'env_entry': 'HEPTA_RUNTIME_WORKER_ENTRY_FD=',
}

POLICY = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if arguments(s, w) == 0:
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 16, result)
        return decode(o, w, 2, META, get(w, 344))
    if phase == 2:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or bind_values(w) == 0:
            return 0
        store(w, PATH_PART, 47)
        store(w, PATH_PART + 1, 0)
        return call(o, w, 3, 257, NEG100, PATH_PART, 2818048, 0, 0, 0, 12)
    if phase == 3:
        if failed(result):
            return 0
        put(w, 24, result)
        put(w, 32, 0)
        put(w, 40, 0)
        return next_directory(o, w)
    if phase == 4:
        if failed(result):
            return 0
        put(w, 24, result)
        return call(o, w, 5, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 5:
        if failed(result) or getn(w, STAT + 24, 4) & 61440 != 16384:
            return 0
        if get(w, 40) + 3 >= get(w, 48):
            if getn(w, STAT + 28, 4) != get(w, 16) or getn(w, STAT + 24, 4) & 4095 != 448:
                return 0
        put(w, 40, get(w, 40) + 1)
        return next_directory(o, w)
    if phase == 6:
        if failed(result):
            return 0
        put(w, 96, 0)
        return capture_start(o, w)
    if phase >= 200 and phase <= 224:
        return capture(s, o, w, phase, result)
    if phase == 30:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or request_values(w) == 0:
            return 0
        return call(o, w, 31, 95, 63, 0, 0, 0, 0, 0, 0)
    if phase == 31:
        put(w, 96, 1)
        return capture_start(o, w)
    if phase >= 40 and phase <= 49:
        return cwd_phase(s, o, w, phase, result)
    if phase == 50:
        if failed(result):
            return 0
        put(w, 96, 4)
        return capture_start(o, w)
    if phase == 51:
        if failed(result):
            return 0
        put(w, 176, result)
        return call(o, w, 52, 91, result, 256, 0, 0, 0, 0, 0)
    if phase == 52:
        if failed(result):
            return 0
        return call(o, w, 53, 72, get(w, 176), 1033, 15, 0, 0, 0, 0)
    if phase == 53:
        if failed(result):
            return 0
        return prepare_environment(s, o, w)
    if phase == 54:
        if failed(result):
            return 0
        nice = 20 - result + get(w, 360)
        if nice > 19:
            nice = 19
        return call(o, w, 55, 141, 0, 0, nice, 0, 0, 0, 0)
    if phase == 55:
        if failed(result):
            return 0
        return open_destinations(o, w)
    if phase == 60:
        if failed(result):
            return 0
        put(w, 184 + get(w, 368) * 8, result)
        put(w, 368, get(w, 368) + 1)
        return open_destinations(o, w)
    if phase == 61:
        if failed(result):
            return 0
        return call(o, w, 62, 228, 1, CLOCK, 0, 0, 0, 0, 12)
    if phase == 62:
        if failed(result) or build_frame(w) == 0:
            return 0
        end = text_request_memfd(w, PATH_PART)
        store(w, end, 0)
        return call(o, w, 63, 319, PATH_PART, 3, 0, 0, 0, 0, 3)
    if phase == 63:
        if failed(result):
            return 0
        put(w, 376, result)
        put(w, 384, 0)
        return call(o, w, 64, 91, result, 256, 0, 0, 0, 0, 0)
    if phase == 64:
        if failed(result):
            return 0
        return write_frame(o, w)
    if phase == 65:
        if result == NEG4:
            return write_frame(o, w)
        if failed(result) or result == 0 or result > get(w, 392) - get(w, 384):
            return 0
        put(w, 384, get(w, 384) + result)
        if get(w, 384) < get(w, 392):
            return write_frame(o, w)
        return call(o, w, 66, 72, get(w, 376), 1033, 15, 0, 0, 0, 0)
    if phase == 66:
        if failed(result):
            return 0
        return call(o, w, 67, 8, get(w, 376), 0, 0, 0, 0, 0, 0)
    if phase == 67:
        if result != 0:
            return 0
        put(w, 400, 0)
        return inherit(o, w)
    if phase == 68:
        if failed(result):
            return 0
        put(w, 400, get(w, 400) + 1)
        return inherit(o, w)
    if phase == 69:
        if result != 0:
            return 0
        end = text_supervisor_argv(w, PATH_PART)
        store(w, end, 0)
        store(w, PATH_PART + 128, 0)
        put(w, POINTERS, PATH_PART)
        put(w, POINTERS + 8, NONE)
        put(w, POINTERS + 16, NONE)
        put(o, 0, POINTERS)
        put(o, 8, 3)
        put(o, 16, POINTERS + 64)
        put(w, 0, 70)
        return 2
    if phase == 70:
        if result != 0:
            return 0
        return call(o, w, 71, 322, get(w, 128), PATH_PART + 128, POINTERS + 64, POINTERS + 80, 4096, 0, 252)
    return 0

def arguments(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 32 or uint(s, 0) != ARG_MAGIC or uint(s, 24) != length(s):
        return 0
    argc = uint(s, 8)
    envc = uint(s, 16)
    if (argc != 3 and argc != 4) or envc > 128:
        return 0
    index = 0
    at = 32
    while index < argc + envc:
        if at + 8 > length(s):
            return 0
        size = uint(s, at)
        if size > 8192 or at + 9 + size > length(s) or byte(s, at + 8 + size) != 0:
            return 0
        i = 0
        while i < size:
            if byte(s, at + 8 + i) == 0:
                return 0
            i = i + 1
        if index < argc:
            put(w, ARGS + index * 16, at + 8)
            put(w, ARGS + index * 16 + 8, size)
        if index == argc:
            put(w, 336, at)
        at = at + size + 9
        index = index + 1
    if at != length(s):
        return 0
    path = get(w, ARGS + 16)
    size = get(w, ARGS + 24)
    if size < 6 or size > 4096 or byte(s, path) != 47:
        return 0
    copy_input(s, w, PATH, path, size)
    store(w, PATH + size, 0)
    put(w, 320, size)
    count = 0
    at = 0
    previous = 0
    last = 0
    previous_size = 0
    last_size = 0
    while at < size:
        if byte(w, PATH + at) == 47:
            at = at + 1
        else:
            start = at
            while at < size and byte(w, PATH + at) != 47:
                at = at + 1
            n = at - start
            if (n == 1 and byte(w, PATH + start) == 46) or (n == 2 and byte(w, PATH + start) == 46 and byte(w, PATH + start + 1) == 46):
                return 0
            previous = last
            previous_size = last_size
            last = start
            last_size = n
            count = count + 1
    if count < 3 or previous_size != 4 or getn(w, PATH + previous, 4) != JOBS_WORD:
        return 0
    put(w, 48, count)
    put(w, 224, 0)
    if argc == 4:
        at = get(w, ARGS + 48)
        size = get(w, ARGS + 56)
        if size == 7 and uint(s, at) & 72057594037927935 == SYSTEMD_WORD:
            put(w, 224, 1)
        elif size != 8 or uint(s, at) != DETACHED_WORD:
            return 0
    size = get(w, ARGS + 40)
    copy_input(s, w, META, get(w, ARGS + 32), size)
    put(w, 344, size)
    return 1

def bind_values(w:mutbuf) -> u64:
    root = ARENA + 64
    device = number(w, lookup(w, root, FIELD_device))
    inode = number(w, lookup(w, root, FIELD_inode))
    if device == NONE or inode == NONE:
        return 0
    put(w, 208, device)
    put(w, 216, inode)
    size = string_copy(w, lookup(w, root, FIELD_job_id), BIND_JOB, 128, 0)
    if size == NONE or size == 0:
        return 0
    put(w, 328, size)
    if string_copy(w, lookup(w, root, FIELD_launch_nonce), BIND_NONCE, 32, 0) != 32 or hex_bytes(w, BIND_NONCE, 32) == 0:
        return 0
    if string_copy(w, lookup(w, root, FIELD_request_fingerprint), BIND_DIGEST, 64, 0) != 64 or hex_bytes(w, BIND_DIGEST, 64) == 0:
        return 0
    if flags(w, root) == 0:
        return 0
    return publisher(w, lookup(w, root, FIELD_hia_terminal_publisher), 0)

def next_directory(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 32)
    size = get(w, 320)
    while at < size and byte(w, PATH + at) == 47:
        at = at + 1
    if at == size:
        if get(w, STAT) != get(w, 208) or get(w, STAT + 8) != get(w, 216):
            return 0
        return call(o, w, 6, 81, get(w, 24), 0, 0, 0, 0, 0, 0)
    start = at
    while at < size and byte(w, PATH + at) != 47:
        store(w, PATH_PART + at - start, byte(w, PATH + at))
        at = at + 1
    store(w, PATH_PART + at - start, 0)
    put(w, 32, at)
    mode = choose(get(w, 40) + 3 >= get(w, 48), 720896, 2818048)
    return call(o, w, 4, 257, get(w, 24), PATH_PART, mode, 0, 0, 0, 12)

def request_values(w:mutbuf) -> u64:
    root = ARENA + 64
    if equal_field(w, lookup(w, root, FIELD_job_id), BIND_JOB, get(w, 328)) == 0:
        return 0
    if equal_field(w, lookup(w, root, FIELD_launch_nonce), BIND_NONCE, 32) == 0:
        return 0
    if equal_field(w, lookup(w, root, FIELD_request_fingerprint), BIND_DIGEST, 64) == 0:
        return 0
    if flags(w, root) == 0 or publisher(w, lookup(w, root, FIELD_hia_terminal_publisher), 1) == 0:
        return 0
    if truth(w, lookup(w, root, FIELD_engine_scratch_protocol)) != 0:
        return 0
    n = lookup(w, root, FIELD_timeout_seconds)
    timeout = 0
    if n != NONE and get(w, n) != 0:
        timeout = number(w, n)
        if timeout == NONE or timeout > 18446744073:
            return 0
    put(w, 232, timeout)
    n = lookup(w, root, FIELD_nice)
    nice = 0
    if n != NONE and get(w, n) != 0:
        nice = number(w, n)
        if nice == NONE or nice > 255:
            return 0
    put(w, 360, nice)
    roots = lookup(w, root, FIELD_allowed_cwd_prefixes)
    child = NONE
    if roots != NONE:
        if get(w, roots) != 5:
            return 0
        child = get(w, roots + 24)
    put(w, 352, child)
    while child != NONE:
        record = ARENA + 64 + child * 72
        if get(w, record) != 4 or get(w, record + 32) == 0 or byte(w, ARENA + get(w, record + 24)) != 47:
            return 0
        child = get(w, record + 16)
    cwd = lookup(w, root, FIELD_cwd)
    if get(w, 352) != NONE and truth(w, cwd) == 0:
        return 0
    if truth(w, cwd) == 0:
        cwd = lookup(w, root, FIELD_default_cwd)
    if truth(w, cwd) == 0:
        store(w, CWD_PATH, 46)
        store(w, CWD_PATH + 1, 0)
    elif string_copy(w, cwd, CWD_PATH, 8192, 1) == NONE:
        return 0
    if string_copy(w, lookup(w, root, FIELD_executable), EXE_PATH, 8192, 1) == NONE:
        return 0
    return 1

def publisher(w:mutbuf, record:u64, compare:u64) -> u64:
    if record == NONE or get(w, record) != 6:
        return 0
    child = get(w, record + 24)
    while child != NONE:
        item = ARENA + 64 + child * 72
        key = key_id(w, ARENA + get(w, item + 40), get(w, item + 48))
        if key != FIELD_encoder and key != FIELD_writer and key != FIELD_supervisor:
            return 0
        child = get(w, item + 16)
    index = 0
    while index < 3:
        field = FIELD_encoder + index
        item = lookup(w, record, field)
        if compare == 0:
            if string_copy(w, item, BIND_PINS + index * 64, 64, 0) != 64 or hex_bytes(w, BIND_PINS + index * 64, 64) == 0:
                return 0
        elif equal_field(w, item, BIND_PINS + index * 64, 64) == 0:
            return 0
        index = index + 1
    return 1

def capture_start(o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 96)
    directory = get(w, 24)
    name = PATH_PART
    if which == 0:
        end = text_request_name(w, name)
    elif which == 1:
        end = text_encoder_name(w, name)
    elif which == 2:
        end = text_writer_name(w, name)
    elif which == 3:
        end = text_supervisor_name(w, name)
    elif which == 4:
        directory = NEG100
        name = EXE_PATH
        end = name + cstring_size(w, name, 8192)
    else:
        end = text_stdin_name(w, name)
    store(w, end, 0)
    put(w, 1024, directory)
    put(w, 1032, name)
    put(w, 1040, 0)
    return call(o, w, 200, 257, directory, name, 657408, 0, 0, 0, 12)

def capture(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    which = get(w, 96)
    if phase == 200:
        if failed(result):
            return 0
        put(w, 1048, result)
        return call(o, w, 201, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 201:
        mode = getn(w, STAT + 24, 4)
        if failed(result) or mode & 61440 != 32768 or mode & 18 != 0:
            return 0
        size = get(w, STAT + 48)
        maximum = 4194304
        minimum = 0
        if which >= 1 and which <= 3:
            maximum = 1048576
            minimum = 64
            if mode & 4095 != 384:
                return 0
        elif which == 4:
            maximum = 67108864
            minimum = 64
        elif which == 5:
            maximum = 536870912
        if size < minimum or size > maximum:
            return 0
        if which != 4 and (get(w, STAT + 16) != 1 or getn(w, STAT + 28, 4) != get(w, 16)):
            return 0
        put(w, 1056, size)
        if which == 0:
            return capture_read(o, w)
        end = text_capture_memfd(w, PATH_PART + 128)
        store(w, end, 0)
        return call(o, w, 202, 319, PATH_PART + 128, 3, 0, 0, 0, 0, 3)
    if phase == 202:
        if failed(result):
            return 0
        put(w, 1064, result)
        return call(o, w, 203, 91, result, choose(which == 5, 256, 320), 0, 0, 0, 0, 0)
    if phase == 203:
        if failed(result):
            return 0
        if which <= 3:
            return sha(o, w, 204, 0, 1)
        return capture_read(o, w)
    if phase == 204 or phase == 207:
        if result != 0:
            return 0
        return capture_read(o, w)
    if phase == 205:
        if result == NEG4:
            return capture_read(o, w)
        if failed(result) or result > 65536:
            return 0
        if result == 0:
            if get(w, 1040) != get(w, 1056):
                return 0
            return call(o, w, 208, 5, get(w, 1048), STAT + 256, 0, 0, 0, 0, 12)
        if result > get(w, 1056) - get(w, 1040):
            return 0
        if which == 4 and get(w, 1040) == 0:
            if result < 7 or getn(w, 65537, 7) != ELF_WORD:
                return 0
        if which == 0:
            copy_bytes(w, META + get(w, 1040), 65537, result)
            put(w, 1040, get(w, 1040) + result)
            return capture_read(o, w)
        put(w, 1072, result)
        put(w, 1080, 0)
        put(w, 1040, get(w, 1040) + result)
        return capture_write(o, w)
    if phase == 206:
        if result == NEG4:
            return capture_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1072) - get(w, 1080):
            return 0
        put(w, 1080, get(w, 1080) + result)
        if get(w, 1080) != get(w, 1072):
            return capture_write(o, w)
        if which <= 3:
            return sha(o, w, 207, 1, get(w, 1072) + 1)
        return capture_read(o, w)
    if phase == 208:
        if failed(result) or same_stamp(w, STAT, STAT + 256) == 0:
            return 0
        return call(o, w, 209, 262, get(w, 1024), get(w, 1032), STAT + 512, 256, 0, 0, 60)
    if phase == 209:
        if failed(result) or same_stamp(w, STAT, STAT + 512) == 0:
            return 0
        if which == 0:
            put(w, 344, get(w, 1040))
            return call(o, w, 214, 3, get(w, 1048), 0, 0, 0, 0, 0, 0)
        if which <= 3:
            return sha(o, w, 210, 2, 1)
        return call(o, w, 211, 72, get(w, 1064), 1033, 15, 0, 0, 0, 0)
    if phase == 210:
        if result != 32:
            return 0
        index = 0
        while index < 32:
            point = byte(w, 4096 + index)
            expected = BIND_PINS + (which - 1) * 64 + index * 2
            if byte(w, expected) != hex_digit(point >> 4) or byte(w, expected + 1) != hex_digit(point & 15):
                return 0
            index = index + 1
        return call(o, w, 211, 72, get(w, 1064), 1033, 15, 0, 0, 0, 0)
    if phase == 211:
        if failed(result):
            return 0
        return call(o, w, 212, 72, get(w, 1064), 1034, 0, 0, 0, 0, 0)
    if phase == 212:
        if failed(result) or result & 15 != 15:
            return 0
        return call(o, w, 213, 8, get(w, 1064), 0, 0, 0, 0, 0, 0)
    if phase == 213:
        if result != 0:
            return 0
        if which == 1:
            put(w, 136, get(w, 1064))
        elif which == 2:
            put(w, 144, get(w, 1064))
        elif which == 3:
            put(w, 128, get(w, 1064))
        elif which == 4:
            put(w, 160, get(w, 1064))
            put(w, 168, get(w, 1048))
            return capture_finished(s, o, w)
        else:
            put(w, 176, get(w, 1064))
        return call(o, w, 214, 3, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 214:
        if failed(result):
            return 0
        return capture_finished(s, o, w)
    return 0

def capture_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 205, 17, get(w, 1048), 65537, 65536, get(w, 1040), 0, 0, 12)

def capture_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 206, 1, get(w, 1064), 65537 + get(w, 1080), get(w, 1072) - get(w, 1080), 0, 0, 0, 12)

def capture_finished(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 96)
    if which == 0:
        return decode(o, w, 30, META, get(w, 344))
    if which < 3:
        put(w, 96, which + 1)
        return capture_start(o, w)
    if which == 3:
        return call(o, w, 40, 257, NEG100, CWD_PATH, 2686976, 0, 0, 0, 12)
    if which == 4:
        if truth(w, lookup(w, ARENA + 64, FIELD_stdin_path)) != 0:
            put(w, 96, 5)
            return capture_start(o, w)
        end = text_capture_memfd(w, PATH_PART)
        store(w, end, 0)
        return call(o, w, 51, 319, PATH_PART, 3, 0, 0, 0, 0, 3)
    return prepare_environment(s, o, w)

def cwd_phase(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 40:
        if failed(result):
            return 0
        put(w, 152, result)
        return call(o, w, 41, 81, result, 0, 0, 0, 0, 0, 0)
    if phase == 41:
        if failed(result):
            return 0
        return call(o, w, 42, 79, CWD_ACTUAL, 8193, 0, 0, 0, 0, 3)
    if phase == 42:
        if failed(result) or result < 2 or result > 8193:
            return 0
        put(w, 408, result - 1)
        if get(w, 352) == NONE:
            return call(o, w, 50, 81, get(w, 24), 0, 0, 0, 0, 0, 0)
        put(w, 416, 0)
        return cwd_root(o, w)
    if phase == 47:
        if failed(result):
            return 0
        return cwd_root(o, w)
    if phase == 43:
        if result == NEG4:
            return call(o, w, 43, 267, NEG100, ROOT_ACTUAL, CWD_PATH, 8193, 0, 0, 60)
        # realpath(strict=False) retains a component when readlink cannot
        # resolve it, including nonexistent tails. Dot-dot is still resolved
        # after following earlier links, rather than lexically before them.
        if failed(result):
            return realpath_step(o, w)
        if result == 0 or result > 8192:
            return 0
        depth = get(w, 488)
        index = 0
        while index < depth:
            frame = REALSTACK + index * 32768
            if get(w, frame + 8) == get(w, 472) and same_bytes(w, frame + 64, ROOT_ACTUAL, get(w, 472)) != 0:
                return realpath_step(o, w)
            index = index + 1
        if depth == 256:
            return 0
        frame = REALSTACK + depth * 32768
        remaining = get(w, 464) - get(w, 456)
        put(w, frame, remaining)
        put(w, frame + 8, get(w, 472))
        copy_bytes(w, frame + 64, ROOT_ACTUAL, get(w, 472))
        copy_bytes(w, frame + 8320, ROOT_PATH + get(w, 456), remaining)
        put(w, 488, depth + 1)
        size = get(w, 480)
        if byte(w, CWD_PATH) == 47:
            size = 1
        put(w, 472, size)
        store(w, ROOT_ACTUAL + size, 0)
        copy_bytes(w, ROOT_PATH, CWD_PATH, result)
        put(w, 464, result)
        put(w, 456, 0)
        return realpath_step(o, w)
    return 0

def cwd_root(o:mutbuf, w:mutbuf) -> u32:
    record = ARENA + 64 + get(w, 352) * 72
    size = string_copy(w, record, ROOT_PATH, 8192, 1)
    if size == NONE:
        return 0
    put(w, 456, 0)
    put(w, 464, size)
    put(w, 472, 1)
    put(w, 488, 0)
    store(w, ROOT_ACTUAL, 47)
    store(w, ROOT_ACTUAL + 1, 0)
    return realpath_step(o, w)

def realpath_step(o:mutbuf, w:mutbuf) -> u32:
    going = True
    while going:
        at = get(w, 456)
        size = get(w, 464)
        while at < size and byte(w, ROOT_PATH + at) == 47:
            at = at + 1
        if at == size:
            depth = get(w, 488)
            if depth == 0:
                count = get(w, 472)
                if count <= get(w, 408) and same_bytes(w, CWD_ACTUAL, ROOT_ACTUAL, count) != 0:
                    if count == 1 or count == get(w, 408) or byte(w, CWD_ACTUAL + count) == 47:
                        put(w, 416, 1)
                return next_root(o, w)
            depth = depth - 1
            frame = REALSTACK + depth * 32768
            size = get(w, frame)
            copy_bytes(w, ROOT_PATH, frame + 8320, size)
            put(w, 488, depth)
            put(w, 464, size)
            put(w, 456, 0)
        else:
            start = at
            while at < size and byte(w, ROOT_PATH + at) != 47:
                at = at + 1
            count = at - start
            put(w, 456, at)
            if count == 1 and byte(w, ROOT_PATH + start) == 46:
                put(w, 456, at)
            elif count == 2 and getn(w, ROOT_PATH + start, 2) == 11822:
                end = get(w, 472)
                while end > 1 and byte(w, ROOT_ACTUAL + end - 1) != 47:
                    end = end - 1
                if end > 1:
                    end = end - 1
                put(w, 472, end)
                store(w, ROOT_ACTUAL + end, 0)
            else:
                end = get(w, 472)
                put(w, 480, end)
                if end > 1:
                    store(w, ROOT_ACTUAL + end, 47)
                    end = end + 1
                if end + count > 8192:
                    return 0
                copy_bytes(w, ROOT_ACTUAL + end, ROOT_PATH + start, count)
                end = end + count
                store(w, ROOT_ACTUAL + end, 0)
                put(w, 472, end)
                return call(o, w, 43, 267, NEG100, ROOT_ACTUAL, CWD_PATH, 8193, 0, 0, 60)
    return 0

def next_root(o:mutbuf, w:mutbuf) -> u32:
    record = ARENA + 64 + get(w, 352) * 72
    child = get(w, record + 16)
    put(w, 352, child)
    if child != NONE:
        return call(o, w, 47, 39, 0, 0, 0, 0, 0, 0, 0)
    if get(w, 416) == 0:
        return 0
    return call(o, w, 50, 81, get(w, 24), 0, 0, 0, 0, 0, 0)

def prepare_environment(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, 240, 0)
    put(w, 432, ENV_BYTES)
    at = get(w, 336)
    index = 0
    while index < uint(s, 16):
        size = uint(s, at)
        copy_input(s, w, ENV_TEMP, at + 8, size)
        store(w, ENV_TEMP + size, 0)
        if env_insert(w, ENV_TEMP, size, NONE) == 0:
            return 0
        at = at + size + 9
        index = index + 1
    put(w, 440, 1)
    env = lookup(w, ARENA + 64, FIELD_env)
    if env != NONE:
        if get(w, env) != 6:
            return 0
        child = get(w, env + 24)
        while child != NONE:
            record = ARENA + 64 + child * 72
            keysize = fs_copy(w, ENV_TEMP, ARENA + get(w, record + 40), get(w, record + 48), 8192)
            if keysize == NONE:
                return 0
            store(w, ENV_TEMP + keysize, 61)
            size = string_copy(w, record, ENV_TEMP + keysize + 1, 8192 - keysize - 1, 1)
            if size == NONE or env_insert(w, ENV_TEMP, keysize + 1 + size, keysize) == 0:
                return 0
            child = get(w, record + 16)
    end = text_env_job(w, ENV_TEMP)
    copy_bytes(w, end, BIND_JOB, get(w, 328))
    if env_insert(w, ENV_TEMP, end - ENV_TEMP + get(w, 328), end - ENV_TEMP - 1) == 0:
        return 0
    end = text_env_entry(w, ENV_TEMP)
    keysize = end - ENV_TEMP - 1
    end = decimal(w, end, get(w, 168))
    if env_insert(w, ENV_TEMP, end - ENV_TEMP, keysize) == 0 or get(w, 240) > 64:
        return 0
    # Exact key order, independent of insertion order and value prefixes.
    index = 1
    while index < get(w, 240):
        cursor = index
        while cursor > 0 and env_less(w, cursor, cursor - 1) != 0:
            word = 0
            while word < 3:
                left = ENV_TABLE + cursor * 24 + word * 8
                right = left - 24
                value = get(w, left)
                put(w, left, get(w, right))
                put(w, right, value)
                word = word + 1
            cursor = cursor - 1
        index = index + 1
    if build_frame(w) == 0:
        return 0
    if get(w, 224) == 0 and get(w, 360) != 0:
        return call(o, w, 54, 140, 0, 0, 0, 0, 0, 0, 0)
    return open_destinations(o, w)

def env_insert(w:mutbuf, source:u64, size:u64, key:u64) -> u64:
    if key == NONE:
        key = 0
        while key < size and byte(w, source + key) != 61:
            key = key + 1
        if key == size:
            return 1
    if key >= size or size > 8192:
        return 0
    special = env_key(w, source, key)
    if special == 1:
        return 1
    if special == 2 and get(w, 440) == 0:
        if size - key - 1 != 0 and size - key - 1 != 32:
            return 0
        put(w, 448, size - key - 1)
        copy_bytes(w, INVOCATION, source + key + 1, size - key - 1)
        put(w, 440, 1)
    count = get(w, 240)
    index = 0
    found = 0
    while index < count and found == 0:
        item = ENV_TABLE + index * 24
        if get(w, item + 16) == key and same_bytes(w, get(w, item), source, key) != 0:
            found = 1
        else:
            index = index + 1
    if index == count:
        if count == 128:
            return 0
        put(w, 240, count + 1)
    end = get(w, 432)
    if end + size + 1 > ENV_END:
        return 0
    copy_bytes(w, end, source, size)
    store(w, end + size, 0)
    item = ENV_TABLE + index * 24
    put(w, item, end)
    put(w, item + 8, size)
    put(w, item + 16, key)
    put(w, 432, end + size + 1)
    return 1

def env_less(w:mutbuf, left:u64, right:u64) -> u64:
    a = ENV_TABLE + left * 24
    b = ENV_TABLE + right * 24
    asize = get(w, a + 16)
    bsize = get(w, b + 16)
    ai = 0
    bi = 0
    while ai < asize and bi < bsize:
        av = filesystem_scalar(w, get(w, a), asize, ai)
        bv = filesystem_scalar(w, get(w, b), bsize, bi)
        ai = av >> 32
        bi = bv >> 32
        av = av & 4294967295
        bv = bv & 4294967295
        if av != bv:
            return choose(av < bv, 1, 0)
    return choose(ai == asize and bi < bsize, 1, 0)

def filesystem_scalar(w:mutbuf, source:u64, size:u64, index:u64) -> u64:
    point = byte(w, source + index)
    if point < 128:
        return ((index + 1) << 32) | point
    cp = point
    needed = 0
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
        elif point == 237:
            high = 159
    elif point >= 240 and point <= 244:
        needed = 4
        cp = point & 7
        if point == 240:
            low = 144
        elif point == 244:
            high = 143
    if needed == 0 or index + needed > size:
        return ((index + 1) << 32) | (56320 + point)
    consumed = 1
    while consumed < needed:
        next = byte(w, source + index + consumed)
        if next < low or next > high:
            return ((index + 1) << 32) | (56320 + point)
        cp = (cp << 6) | (next & 63)
        consumed = consumed + 1
        low = 128
        high = 191
    return ((index + consumed) << 32) | cp

def open_destinations(o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 368)
    if which == 3:
        return call(o, w, 61, 74, get(w, 24), 0, 0, 0, 0, 0, 0)
    if which == 0:
        end = text_stdout_name(w, PATH_PART)
    elif which == 1:
        end = text_stderr_name(w, PATH_PART)
    else:
        end = text_receipt_name(w, PATH_PART)
    store(w, end, 0)
    return call(o, w, 60, 257, get(w, 24), PATH_PART, 655554, 384, 0, 0, 12)

def build_frame(w:mutbuf) -> u64:
    timeout = get(w, 232)
    deadline = 9223372036854775807
    if timeout != 0:
        now = get(w, CLOCK) * 1000000000 + get(w, CLOCK + 8)
        delta = timeout * 1000000000
        if delta > NONE - now:
            return 0
        deadline = now + delta
    put(w, FRAME, JOB_MAGIC)
    put(w, FRAME + 8, 0)
    put(w, FRAME + 16, deadline)
    put(w, FRAME + 24, get(w, 160))
    put(w, FRAME + 32, get(w, 176))
    put(w, FRAME + 40, get(w, 184))
    put(w, FRAME + 48, get(w, 192))
    put(w, FRAME + 56, get(w, 152))
    put(w, FRAME + 64, get(w, 200))
    put(w, FRAME + 80, get(w, 240))
    put(w, FRAME + 88, 67108864)
    put(w, FRAME + 96, 16777216)
    put(w, FRAME + 104, 2000000000)
    put(w, FRAME + 112, 0)
    put(w, FRAME + 120, 0)
    put(w, FRAME + 128, get(w, 24))
    put(w, FRAME + 136, get(w, 328))
    copy_bytes(w, FRAME + 144, BIND_NONCE, 32)
    put(w, FRAME + 176, get(w, 448))
    copy_bytes(w, FRAME + 184, INVOCATION, get(w, 448))
    copy_bytes(w, FRAME + 216, BIND_JOB, get(w, 328))
    at = FRAME + 216 + get(w, 328)
    size = cstring_size(w, EXE_PATH, 8192)
    at = frame_string(w, at, EXE_PATH, size)
    if at == NONE:
        return 0
    argc = 1
    args = lookup(w, ARENA + 64, FIELD_args)
    if args != NONE:
        if get(w, args) != 5:
            return 0
        child = get(w, args + 24)
        while child != NONE:
            if argc == 64:
                return 0
            record = ARENA + 64 + child * 72
            size = string_copy(w, record, ENV_TEMP, 8192, 1)
            if size == NONE:
                return 0
            at = frame_string(w, at, ENV_TEMP, size)
            if at == NONE:
                return 0
            argc = argc + 1
            child = get(w, record + 16)
    put(w, FRAME + 72, argc)
    index = 0
    while index < get(w, 240):
        record = ENV_TABLE + index * 24
        at = frame_string(w, at, get(w, record), get(w, record + 8))
        if at == NONE:
            return 0
        index = index + 1
    if at + 24 > FRAME + 65536:
        return 0
    put(w, at, PFD_MAGIC)
    put(w, at + 8, 1)
    put(w, at + 16, get(w, 168))
    put(w, 392, at + 24 - FRAME)
    return 1

def frame_string(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    if size > 8192 or at + size + 9 > FRAME + 65536:
        return NONE
    put(w, at, size)
    copy_bytes(w, at + 8, source, size)
    store(w, at + 8 + size, 0)
    return at + size + 9

def write_frame(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 65, 1, get(w, 376), FRAME + get(w, 384), get(w, 392) - get(w, 384), 0, 0, 0, 12)

def inherit(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 400)
    if index == 8:
        return call(o, w, 69, 33, get(w, 376), 0, 0, 0, 0, 0, 0)
    fd = get(w, 160)
    if index == 1:
        fd = get(w, 176)
    elif index == 2:
        fd = get(w, 184)
    elif index == 3:
        fd = get(w, 192)
    elif index == 4:
        fd = get(w, 152)
    elif index == 5:
        fd = get(w, 200)
    elif index == 6:
        fd = get(w, 24)
    elif index == 7:
        fd = get(w, 168)
    return call(o, w, 68, 72, fd, 2, 0, 0, 0, 0, 0)

def lookup(w:mutbuf, parent:u64, field:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    child = get(w, parent + 24)
    found = NONE
    while child != NONE:
        record = ARENA + 64 + child * 72
        if key_id(w, ARENA + get(w, record + 40), get(w, record + 48)) == field:
            found = record
        child = get(w, record + 16)
    return found

def number(w:mutbuf, record:u64) -> u64:
    if record == NONE or get(w, record) != 3:
        return NONE
    at = RAW_JSON + get(w, record + 24)
    size = get(w, record + 32)
    if size == 0 or size > 20:
        return NONE
    value = 0
    index = 0
    while index < size:
        point = byte(w, at + index)
        if point < 48 or point > 57 or value > 1844674407370955161:
            return NONE
        if value == 1844674407370955161 and point > 53:
            return NONE
        value = value * 10 + point - 48
        index = index + 1
    return value

def truth(w:mutbuf, record:u64) -> u64:
    if record == NONE:
        return 0
    kind = get(w, record)
    if kind == 0 or kind == 1:
        return 0
    if kind == 2:
        return 1
    if kind == 3:
        return choose(number(w, record) == 0, 0, 1)
    return choose(get(w, record + 32) == 0, 0, 1)

def equal_field(w:mutbuf, record:u64, expected:u64, size:u64) -> u64:
    if record == NONE or get(w, record) != 4 or get(w, record + 32) != size:
        return 0
    return same_bytes(w, ARENA + get(w, record + 24), expected, size)

def string_copy(w:mutbuf, record:u64, target:u64, maximum:u64, filesystem:u64) -> u64:
    if record == NONE or get(w, record) != 4:
        return NONE
    source = ARENA + get(w, record + 24)
    size = get(w, record + 32)
    if filesystem != 0:
        return fs_copy(w, target, source, size, maximum)
    if size > maximum:
        return NONE
    copy_bytes(w, target, source, size)
    store(w, target + size, 0)
    return size

def fs_copy(w:mutbuf, target:u64, source:u64, size:u64, maximum:u64) -> u64:
    index = 0
    written = 0
    while index < size:
        point = byte(w, source + index)
        if point == 0 or written == maximum:
            return NONE
        if point == 237 and index + 2 < size and byte(w, source + index + 1) >= 160:
            second = byte(w, source + index + 1)
            third = byte(w, source + index + 2)
            if second < 178 or second > 179 or third < 128 or third > 191:
                return NONE
            point = ((second & 3) << 6) | (third & 63)
            index = index + 2
        store(w, target + written, point)
        written = written + 1
        index = index + 1
    store(w, target + written, 0)
    return written

def cstring_size(w:mutbuf, at:u64, maximum:u64) -> u64:
    size = 0
    while size <= maximum:
        if byte(w, at + size) == 0:
            return size
        size = size + 1
    return NONE

def hex_bytes(w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        point = byte(w, at + index)
        if (point < 48 or point > 57) and (point < 97 or point > 102):
            return 0
        index = index + 1
    return 1

def same_bytes(w:mutbuf, left:u64, right:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1

def copy_bytes(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 0

def copy_input(s:readbuf, w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return 0

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, size:u64) -> u32:
    put(w, 0, phase)
    store(w, 65536, command)
    put(o, 0, size)
    return 3
'''


def policy_source():
    source = POLICY + '\n' + NORMALIZE
    needed = {'same_stamp', 'failed', 'uint', 'get', 'getn', 'put', 'decimal',
              'hex_digit', 'call'}
    for node in ast.parse(OBSERVATION_POLICY).body:
        if node.name in needed:
            source += '\n' + ast.get_source_segment(OBSERVATION_POLICY, node) + '\n'
    source += '''
def decode(o:mutbuf, w:mutbuf, phase:u64, source:u64, size:u64) -> u32:
    size = normalize_json(w, source, size)
    if size == NONE:
        return 0
    put(w, SCRATCH + 48, 2097152)
    put(w, SCRATCH + 56, MAXIMUM_METADATA_DEPTH)
    put(w, 0, phase)
    put(o, 0, RAW_JSON)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4
'''
    source += '\ndef flags(w:mutbuf, root:u64) -> u64:\n'
    for field in FIELDS[FIELDS.index('hia_terminal_supervisor'):]:
        source += f'    field = lookup(w, root, FIELD_{field})\n'
        source += '    if field == NONE or get(w, field) != 2:\n        return 0\n'
    source += '    return 1\n'
    source += '\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    for i, field in enumerate(FIELDS, 1):
        value = field.encode()
        source += f'    if size == {len(value)}:\n'
        condition = ' and '.join(f"getn(w, at + {j}, {len(value[j:j+8])}) == {int.from_bytes(value[j:j+8], 'little')}" for j in range(0, len(value), 8))
        source += f'        if {condition}:\n            return {i}\n'
    source += '    return 0\n'
    source += '\ndef env_key(w:mutbuf, at:u64, size:u64) -> u64:\n'
    for i, key in enumerate(('HEPTA_RUNTIME_ENGINE_SCRATCH', 'INVOCATION_ID'), 1):
        value = key.encode()
        source += f'    if size == {len(value)}:\n'
        condition = ' and '.join(f"getn(w, at + {j}, {len(value[j:j+8])}) == {int.from_bytes(value[j:j+8], 'little')}" for j in range(0, len(value), 8))
        source += f'        if {condition}:\n            return {i}\n'
    source += '    return 0\n'
    for name, value in TEXT.items():
        value = value.encode()
        source += f'\ndef text_{name}(w:mutbuf, at:u64) -> u64:\n'
        for i, byte in enumerate(value):
            source += f'    store(w, at + {i}, {byte})\n'
        source += f'    return at + {len(value)}\n'
    values = dict(
        STATE_BYTES=STATE_BYTES, MAXIMUM_METADATA_DEPTH=MAXIMUM_METADATA_DEPTH, META=2 << 20, ARENA=16 << 20, ARENA_BYTES=160 << 20,
        SCRATCH=184 << 20, SCRATCH_BYTES=32 << 20, FRAME=6 << 20, RAW_JSON=8 << 20,
        NONE=(1 << 64) - 1, NEG100=(1 << 64) - 100, NEG4=(1 << 64) - 4,
        NEG2=(1 << 64) - 2, NEG20=(1 << 64) - 20,
        ARG_MAGIC=int.from_bytes(b'HIAARG02', 'little'),
        JOB_MAGIC=int.from_bytes(b'HIAJOB01', 'little'),
        PFD_MAGIC=int.from_bytes(b'HIAPFD01', 'little'),
        SYSTEMD_WORD=int.from_bytes(b'systemd', 'little'),
        DETACHED_WORD=int.from_bytes(b'detached', 'little'),
        JOBS_WORD=int.from_bytes(b'jobs', 'little'),
        ELF_WORD=int.from_bytes(b'\x7fELF\x02\x01\x01', 'little'),
        ARGS=2048, STAT=8192, BIND_JOB=16384, BIND_NONCE=16544,
        BIND_DIGEST=16640, BIND_PINS=16800, INVOCATION=17152,
        PATH=32768, PATH_PART=40960, CWD_PATH=49152, EXE_PATH=139264,
        CWD_ACTUAL=155648, ROOT_PATH=172032, ROOT_ACTUAL=188416,
        ENV_TABLE=204800, ENV_TEMP=212992, ENV_BYTES=262144,
        ENV_END=2 << 20, CLOCK=1632, POINTERS=2304, REALSTACK=216 << 20,
    )
    values.update({'FIELD_' + name: index for index, name in enumerate(FIELDS, 1)})
    for name in sorted(values, key=len, reverse=True):
        source = re.sub(r'\b' + re.escape(name) + r'\b', str(values[name]), source)
    return source



def template():
    adapter = ROOT / 'tools/hia_job_launch_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-job-launch-author-') as tmp:
        obj, raw = Path(tmp) / 'adapter.o', Path(tmp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(adapter), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('launch adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in
                           ('job_launch_policy_hole', 'job_launch_json_hole', 'job_launch_sha_hole')}


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    decoder = uint(s, 16, 8)
    sha = uint(s, 24, 8)
    if policy == 0 or decoder == 0 or sha == 0 or policy > 2097152 or decoder > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 32 + policy + decoder + sha:
        return 4294967295
    size = {len(prefix)} + policy + decoder + sha
    if size > 4194304 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        source += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix))
        if name.endswith('json_hole') or name.endswith('sha_hole'):
            target += ' + policy'
        if name.endswith('sha_hole'):
            target += ' + decoder'
        source += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 32, {len(prefix)}, policy + decoder + sha)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for module, source in (
        ('job_launch', policy_source()),
        ('job_launch_json', metadata_json_source()),
        ('job_launch_packer', packer_source()),
    ):
        path = ROOT / 'examples/hia_bootstrap' / (module + '.hepta')
        path.write_text(render_assembly(document(source, module)))
        print(path.name, path.stat().st_size, flush=True)


if __name__ == '__main__':
    main()
