"""Author the HIA owner of remote native job submission.

Only checked-in HIA sources and the mechanical syscall adapter form the product.
This generator is a development tool.
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
from tools.generate_hia_job_launch import FIELDS as LAUNCH_FIELDS, policy_source as launch_policy_source
from tools.generate_hia_job_observation import POLICY as OBSERVATION_POLICY
from tools.generate_hia_job_metadata import metadata_json_source, MAXIMUM_METADATA_DEPTH
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT = Path(__file__).resolve().parents[1]
STATE_BYTES = 224 << 20
PACKER_MAGIC = int.from_bytes(b'HIAJSBK1', 'little')
FIELDS = LAUNCH_FIELDS + (
    'job_dir', 'unit', 'request_digest', 'allow_detached_fallback',
    'cpu_quota_percent', 'memory_max_bytes', 'execution_mode',
    'allow_job_network', 'platform', 'hia_job_launcher_sha256', 'backend',
    'hia_job_entry_path',
)
IMAGE_NAMES = ('hia-terminal-encoder', 'hia-terminal-writer',
               'hia-terminal-supervisor', 'hia-native-launch')
TOMBSTONES = ('stdin.bin', 'runner.py', 'owner-intent.json', 'started.json',
              'child.json', 'launch.json', 'exit.json', 'exit.witness.json',
              'exit.witness.json.tmp', 'stdout.log', 'stderr.log', 'native-exit.bin',
              *IMAGE_NAMES)
TEXT = {
    'input_memfd': 'hia-job-submission-input',
    'launch_lock': 'launch.lock', 'request_name': 'request.json',
    'launch_name': 'launch.json', 'launch_tmp': 'launch.json.tmp',
    'exit_name': 'exit.json', 'stdin_name': 'stdin.bin',
    'replay_open': '{"ok":true,"reused_remote":true,',
    'ok_open': '{"ok":true,', 'completed': '"backend":"completed"',
    'default_cwd': '"default_cwd":', 'launch_nonce': ',"launch_nonce":',
    'protocol': ',"terminal_publication_protocol":1',
    'stdin_path': ',"stdin_path":',
    'dev_null': '/dev/null', 'launcher_argv': 'hia-job-launch',
    'detached': 'detached',
    'binding_device': '{"device":', 'binding_inode': ',"inode":',
    'binding_job': ',"job_id":', 'binding_fingerprint': ',"request_fingerprint":',
    'binding_publisher': ',"hia_terminal_publisher":{',
    'binding_encoder': '"encoder":', 'binding_writer': ',"writer":',
    'binding_supervisor': ',"supervisor":',
    'binding_flags': ''.join(',"' + field + '":true' for field in LAUNCH_FIELDS[LAUNCH_FIELDS.index('hia_terminal_supervisor'):]),
    'xdg': 'XDG_RUNTIME_DIR=/run/user/',
    'dbus': 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/', 'bus': '/bus',
    'launch_detached': '{"backend":"detached","unit":',
    'launcher_pid': ',"launcher_pid":',
    'systemd_error_text': 'systemd user units unavailable on this platform',
    'systemd_error': ',"systemd_error":',
    'launch_systemd': '{"backend":"systemd","unit":',
    'launch_failed': '{"backend":"launch_failed","unit":',
    'launcher_null': ',"launcher_pid":null',
    'error_memfd': 'hia-systemd-launch-stderr',
    'default_path': '/bin:/usr/bin', 'systemd_run': 'systemd-run',
    'description': 'Description=Hepta Runtime job ',
    'double_dash': '--', 'proc': '/proc/', 'fd': '/fd/', 'systemd': 'systemd',
    'property': '--property', 'cpu_quota': 'CPUQuota=', 'memory_max': 'MemoryMax=', 'nice': 'Nice=',
    'launch_base64': '--launch-base64',
}

POLICY = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if length(s) < 32 or uint(s, 0) != ARG_MAGIC or uint(s, 8) != 1 or uint(s, 24) != length(s):
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 16, result)
        return call(o, w, 2, 102, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        put(w, 584, result)
        return call(o, w, 3, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3:
        put(w, 616, result)
        put(w, 64, 0)
        return read_header(o, w)
    if phase == 4:
        if result == NEG4:
            return read_header(o, w)
        if failed(result) or result == 0 or result > 64 - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < 64:
            return read_header(o, w)
        if get(w, HEADER) != SUBMIT_MAGIC or get(w, HEADER + 56) != 0:
            return 0
        if get(w, HEADER + 8) == 0 or get(w, HEADER + 8) > 4194304:
            return 0
        if get(w, HEADER + 16) != NONE and get(w, HEADER + 16) > 536870912:
            return 0
        index = 0
        while index < 4:
            if get(w, HEADER + 24 + index * 8) > 1048576:
                return 0
            index = index + 1
        put(w, 64, 0)
        return read_request(o, w)
    if phase == 5:
        if result == NEG4:
            return read_request(o, w)
        if failed(result) or result == 0 or result > get(w, HEADER + 8) - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < get(w, HEADER + 8):
            return read_request(o, w)
        return submit_decode(o, w, 6, get(w, 64))
    if phase == 6:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or incoming(w) == 0:
            return 0
        put(w, 96, 0)
        return input_image(o, w)
    if phase >= 10 and phase <= 19:
        return capture_input(s, o, w, phase, result)
    if phase == 20:
        if result == NEG4:
            return call(o, w, 20, 0, 0, 65537, 1, 0, 0, 0, 12)
        if result != 0:
            return 0
        return call(o, w, 21, 79, OLD_CWD, 8193, 0, 0, 0, 0, 3)
    if phase == 21:
        if failed(result) or result < 2 or result > 8193:
            return 0
        put(w, 600, result - 1)
        return call(o, w, 22, 95, 63, 0, 0, 0, 0, 0, 0)
    if phase == 22:
        store(w, PATH_PART, 47)
        store(w, PATH_PART + 1, 0)
        return call(o, w, 50, 257, NEG100, PATH_PART, 2818048, 0, 0, 0, 12)
    if phase >= 50 and phase <= 69:
        return directory(s, o, w, phase, result)
    if phase >= 80 and phase <= 89:
        return private_read(s, o, w, phase, result)
    if phase == 100:
        if result != NEG2:
            return 0
        put(w, 640, get(w, 640) + 1)
        return check_tombstone(o, w)
    if phase == 101:
        if result == NEG4:
            return random_nonce(o, w)
        if failed(result) or result == 0 or result > 16 - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < 16:
            return random_nonce(o, w)
        index = 0
        while index < 16:
            point = byte(w, 12000 + index)
            store(w, BIND_NONCE + index * 2, hex_digit(point >> 4))
            store(w, BIND_NONCE + index * 2 + 1, hex_digit(point & 15))
            index = index + 1
        if request_output(w) == 0:
            return 0
        put(w, 96, 0)
        return stage_file(o, w)
    if phase >= 110 and phase <= 119:
        return stage(s, o, w, phase, result)
    if (phase >= 130 and phase <= 169) or phase >= 200:
        return 5
    if phase == 190:
        if result == NEG4:
            return write_reply(o, w)
        if failed(result) or result == 0 or result > get(w, 664) - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < get(w, 664):
            return write_reply(o, w)
        return call(o, w, 199, 60, get(w, 792), 0, 0, 0, 0, 0, 0)
    return 0

def read_header(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 4, 0, 0, HEADER + get(w, 64), 64 - get(w, 64), 0, 0, 0, 12)

def read_request(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 5, 0, 0, META + get(w, 64), get(w, HEADER + 8) - get(w, 64), 0, 0, 0, 12)

def submit_decode(o:mutbuf, w:mutbuf, phase:u64, size:u64) -> u32:
    size = normalize_json(w, META, size)
    if size == NONE:
        return 0
    put(w, 560, size)
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

def incoming(w:mutbuf) -> u64:
    root = ARENA + 64
    size = string_copy(w, lookup(w, root, FIELD_job_dir), PATH, 4096, 1)
    if size == NONE or size < 6 or byte(w, PATH) != 47:
        return 0
    put(w, 320, size)
    if path_shape(w) == 0:
        return 0
    size = string_copy(w, lookup(w, root, FIELD_job_id), BIND_JOB, 128, 0)
    if size == NONE or size == 0:
        return 0
    put(w, 328, size)
    size = string_copy(w, lookup(w, root, FIELD_unit), UNIT, 512, 0)
    if size == NONE or size == 0:
        return 0
    put(w, 608, size)
    if string_copy(w, lookup(w, root, FIELD_request_fingerprint), BIND_DIGEST, 64, 0) != 64:
        return 0
    record = lookup(w, root, FIELD_request_digest)
    if record == NONE:
        record = lookup(w, root, FIELD_request_fingerprint)
    if string_copy(w, record, REQUEST_DIGEST, 64, 0) != 64:
        return 0
    return roots_copy(w, ROOT_CACHE, 0)

def roots_copy(w:mutbuf, destination:u64, compare:u64) -> u64:
    record = lookup(w, ARENA + 64, FIELD_allowed_cwd_prefixes)
    child = NONE
    if record != NONE:
        if get(w, record) != 5:
            return 0
        child = get(w, record + 24)
    at = 8
    count = 0
    while child != NONE:
        item = ARENA + 64 + child * 72
        if get(w, item) != 4:
            return 0
        size = get(w, item + 32)
        if at + size + 8 > 8388608:
            return 0
        if compare == 0:
            word = 0
            while word < 4:
                store(w, destination + at + word, (size >> (word * 8)) & 255)
                word = word + 1
            copy_bytes(w, destination + at + 4, ARENA + get(w, item + 24), size)
        else:
            if getn(w, destination + at, 4) != size or same_bytes(w, destination + at + 4, ARENA + get(w, item + 24), size) == 0:
                return 0
        count = count + 1
        at = at + size + 4
        child = get(w, item + 16)
    if compare == 0:
        put(w, destination, count)
    elif get(w, destination) != count:
        return 0
    return 1

def path_shape(w:mutbuf) -> u64:
    size = get(w, 320)
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
            if (n == 1 and byte(w, PATH + start) == 46) or (n == 2 and getn(w, PATH + start, 2) == 11822):
                return 0
            previous = last
            previous_size = last_size
            last = start
            last_size = n
            count = count + 1
    if count < 3 or previous_size != 4 or getn(w, PATH + previous, 4) != JOBS_WORD:
        return 0
    put(w, 48, count)
    return 1

def input_image(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 96)
    if index == 5 or (index == 4 and get(w, HEADER + 16) == NONE):
        return call(o, w, 20, 0, 0, 65537, 1, 0, 0, 0, 12)
    size = get(w, HEADER + 24 + index * 8)
    if index == 4:
        size = get(w, HEADER + 16)
    put(w, 1056, size)
    put(w, 1040, 0)
    end = text_input_memfd(w, PATH_PART)
    store(w, end, 0)
    return call(o, w, 10, 319, PATH_PART, 3, 0, 0, 0, 0, 3)

def capture_input(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    index = get(w, 96)
    if phase == 10:
        if failed(result):
            return 0
        put(w, 512 + index * 8, result)
        return call(o, w, 11, 91, result, choose(index == 4, 256, 320), 0, 0, 0, 0, 0)
    if phase == 11:
        if failed(result):
            return 0
        if index < 4:
            return sha(o, w, 12, 0, 1)
        return input_read(o, w)
    if phase == 12 or phase == 15:
        if result != 0:
            return 0
        return input_read(o, w)
    if phase == 13:
        if result == NEG4:
            return input_read(o, w)
        if failed(result) or result == 0 or result > get(w, 1056) - get(w, 1040) or result > 65536:
            return 0
        put(w, 1040, get(w, 1040) + result)
        put(w, 1072, result)
        put(w, 1080, 0)
        return input_write(o, w)
    if phase == 14:
        if result == NEG4:
            return input_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1072) - get(w, 1080):
            return 0
        put(w, 1080, get(w, 1080) + result)
        if get(w, 1080) < get(w, 1072):
            return input_write(o, w)
        if index < 4:
            return sha(o, w, 15, 1, get(w, 1072) + 1)
        return input_read(o, w)
    if phase == 16:
        if result != 32:
            return 0
        copy_bytes(w, IMAGE_HASHES + index * 32, 4096, 32)
        return call(o, w, 17, 72, get(w, 512 + index * 8), 1033, 15, 0, 0, 0, 0)
    if phase == 17:
        if failed(result):
            return 0
        return call(o, w, 18, 72, get(w, 512 + index * 8), 1034, 0, 0, 0, 0, 0)
    if phase == 18:
        if failed(result) or result & 15 != 15:
            return 0
        put(w, 96, index + 1)
        return input_image(o, w)
    return 0

def input_read(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1040) == get(w, 1056):
        if get(w, 96) < 4:
            return sha(o, w, 16, 2, 1)
        return call(o, w, 17, 72, get(w, 544), 1033, 15, 0, 0, 0, 0)
    size = get(w, 1056) - get(w, 1040)
    if size > 65536:
        size = 65536
    return call(o, w, 13, 0, 0, 65537, size, 0, 0, 0, 12)

def input_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 14, 1, get(w, 512 + get(w, 96) * 8), 65537 + get(w, 1080), get(w, 1072) - get(w, 1080), 0, 0, 0, 12)

def directory(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 50:
        if failed(result):
            return 0
        put(w, 24, result)
        put(w, 32, 0)
        put(w, 40, 0)
        return directory_next(o, w)
    if phase == 51 or phase == 57:
        if phase == 51 and result == NEG2 and get(w, 40) + 3 >= get(w, 48):
            store(w, PATH_PART + 512, 46)
            store(w, PATH_PART + 513, 0)
            return call(o, w, 52, 257, get(w, 24), PATH_PART + 512, 720896, 0, 0, 0, 12)
        if failed(result):
            return 0
        put(w, 24, result)
        return call(o, w, 58, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 52:
        if failed(result):
            return 0
        put(w, 568, result)
        return call(o, w, 53, 5, get(w, 24), STAT, 0, 0, 0, 0, 12)
    if phase == 53:
        if failed(result):
            return 0
        return call(o, w, 54, 5, get(w, 568), STAT + 256, 0, 0, 0, 0, 12)
    if phase == 54:
        if failed(result) or get(w, STAT) != get(w, STAT + 256) or get(w, STAT + 8) != get(w, STAT + 264):
            return 0
        return call(o, w, 55, 258, get(w, 568), PATH_PART, 448, 0, 0, 0, 12)
    if phase == 55:
        if result == NEG17:
            return call(o, w, 57, 257, get(w, 568), PATH_PART, 720896, 0, 0, 0, 12)
        if failed(result):
            return 0
        return call(o, w, 56, 74, get(w, 568), 0, 0, 0, 0, 0, 0)
    if phase == 56:
        if failed(result):
            return 0
        return call(o, w, 57, 257, get(w, 568), PATH_PART, 720896, 0, 0, 0, 12)
    if phase == 58:
        if failed(result) or getn(w, STAT + 24, 4) & 61440 != 16384:
            return 0
        if get(w, 40) + 3 >= get(w, 48):
            if getn(w, STAT + 28, 4) != get(w, 16) or getn(w, STAT + 24, 4) & 4095 != 448:
                return 0
        put(w, 40, get(w, 40) + 1)
        return directory_next(o, w)
    if phase == 59:
        if failed(result):
            return 0
        end = text_launch_lock(w, PATH_PART)
        store(w, end, 0)
        return call(o, w, 60, 257, get(w, 24), PATH_PART, 655426, 384, 0, 0, 12)
    if phase == 60:
        if failed(result):
            return 0
        put(w, 576, result)
        return call(o, w, 61, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 61:
        if failed(result) or getn(w, STAT + 24, 4) != 33152 or getn(w, STAT + 28, 4) != get(w, 16) or get(w, STAT + 16) != 1:
            return 0
        return call(o, w, 62, 73, get(w, 576), 2, 0, 0, 0, 0, 0)
    if phase == 62:
        if result == NEG4:
            return call(o, w, 62, 73, get(w, 576), 2, 0, 0, 0, 0, 0)
        if failed(result):
            return 0
        put(w, 592, 0)
        return read_private(o, w)
    return 0

def directory_next(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 32)
    size = get(w, 320)
    while at < size and byte(w, PATH + at) == 47:
        at = at + 1
    if at == size:
        put(w, 208, get(w, STAT))
        put(w, 216, get(w, STAT + 8))
        return call(o, w, 59, 81, get(w, 24), 0, 0, 0, 0, 0, 0)
    start = at
    while at < size and byte(w, PATH + at) != 47:
        store(w, PATH_PART + at - start, byte(w, PATH + at))
        at = at + 1
    store(w, PATH_PART + at - start, 0)
    put(w, 32, at)
    mode = choose(get(w, 40) + 3 >= get(w, 48), 720896, 2818048)
    return call(o, w, 51, 257, get(w, 24), PATH_PART, mode, 0, 0, 0, 12)

def read_private(o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 592)
    if which == 0:
        end = text_request_name(w, PATH_PART)
    elif which == 1:
        end = text_launch_name(w, PATH_PART)
    else:
        end = text_exit_name(w, PATH_PART)
    store(w, end, 0)
    return call(o, w, 80, 257, get(w, 24), PATH_PART, 657408, 0, 0, 0, 12)

def private_read(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 80:
        if result == NEG2:
            if get(w, 592) == 0:
                return fresh(o, w)
            return replay_next(o, w, 0)
        if failed(result):
            return 0
        put(w, 1048, result)
        return call(o, w, 81, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 81:
        if failed(result) or safe_file(w, STAT) == 0 or get(w, STAT + 48) > 4194304:
            return 0
        put(w, 64, 0)
        return private_read_bytes(o, w)
    if phase == 82:
        if result == NEG4:
            return private_read_bytes(o, w)
        if failed(result) or result > 4194305 - get(w, 64):
            return 0
        if result != 0:
            put(w, 64, get(w, 64) + result)
            if get(w, 64) > 4194304:
                return 0
            return private_read_bytes(o, w)
        return call(o, w, 83, 5, get(w, 1048), STAT + 256, 0, 0, 0, 0, 12)
    if phase == 83:
        if failed(result) or same_stamp(w, STAT, STAT + 256) == 0:
            return 0
        return call(o, w, 84, 262, get(w, 24), PATH_PART, STAT + 512, 256, 0, 0, 60)
    if phase == 84:
        if failed(result) or same_stamp(w, STAT, STAT + 512) == 0:
            return 0
        return call(o, w, 85, 3, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 85:
        if failed(result):
            return 0
        return submit_decode(o, w, 86, get(w, 64))
    if phase == 86:
        if result >= 4294967292 or get(w, ARENA + 64) != 6:
            return 0
        if get(w, 592) == 0:
            if existing_bound(w) == 0:
                return 0
            put(w, 592, 1)
            return read_private(o, w)
        return replay_next(o, w, 1)
    return 0

def private_read_bytes(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 82, 0, get(w, 1048), META + get(w, 64), 4194305 - get(w, 64), 0, 0, 0, 12)

def existing_bound(w:mutbuf) -> u64:
    root = ARENA + 64
    if equal_field(w, lookup(w, root, FIELD_job_id), BIND_JOB, get(w, 328)) == 0:
        return 0
    if equal_field(w, lookup(w, root, FIELD_unit), UNIT, get(w, 608)) == 0:
        return 0
    if equal_field(w, lookup(w, root, FIELD_request_fingerprint), BIND_DIGEST, 64) == 0:
        return 0
    path = lookup(w, root, FIELD_job_dir)
    size = string_copy(w, path, PATH_PART + 1024, 4096, 1)
    if size != get(w, 320) or same_bytes(w, PATH_PART + 1024, PATH, size) == 0:
        return 0
    digest = lookup(w, root, FIELD_request_digest)
    if digest == NONE:
        digest = lookup(w, root, FIELD_request_fingerprint)
    if equal_field(w, digest, REQUEST_DIGEST, 64) == 0:
        return 0
    return roots_copy(w, ROOT_CACHE, 1)

def replay_next(o:mutbuf, w:mutbuf, present:u64) -> u32:
    if get(w, 592) == 1:
        size = 0
        if present != 0 and get(w, ARENA + 96) != 0:
            backend = lookup(w, ARENA + 64, FIELD_backend)
            if backend != NONE and get(w, backend) == 4:
                if string_equals(w, ARENA + get(w, backend + 24), get(w, backend + 32), 1) != 0:
                    return 0
            size = get(w, ARENA + 128) - 2
            copy_bytes(w, ROOT_CACHE, RAW_JSON + get(w, ARENA + 120) + 1, size)
        put(w, 624, size)
        put(w, 592, 2)
        return read_private(o, w)
    if get(w, 624) == 0 and (present == 0 or get(w, ARENA + 96) == 0):
        return 0
    at = text_replay_open(w, OUTPUT)
    if get(w, 624) != 0:
        at = ascii_json(w, at, ROOT_CACHE, get(w, 624))
    else:
        at = text_completed(w, at)
    store(w, at, 125)
    store(w, at + 1, 10)
    put(w, 664, at + 2 - OUTPUT)
    put(w, 64, 0)
    return write_reply(o, w)

def fresh(o:mutbuf, w:mutbuf) -> u32:
    root = ARENA + 64
    if flags(w, root) == 0 or publisher(w, lookup(w, root, FIELD_hia_terminal_publisher), 0) == 0:
        return 0
    if string_copy(w, lookup(w, root, FIELD_hia_job_launcher_sha256), BIND_PINS + 192, 64, 0) != 64 or hex_bytes(w, BIND_PINS + 192, 64) == 0:
        return 0
    index = 0
    while index < 4:
        if get(w, HEADER + 24 + index * 8) < 64:
            return 0
        byte_index = 0
        while byte_index < 32:
            point = byte(w, IMAGE_HASHES + index * 32 + byte_index)
            pin = BIND_PINS + index * 64 + byte_index * 2
            if byte(w, pin) != hex_digit(point >> 4) or byte(w, pin + 1) != hex_digit(point & 15):
                return 0
            byte_index = byte_index + 1
        index = index + 1
    put(w, 640, 0)
    return check_tombstone(o, w)

def check_tombstone(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 640)
    if index == TOMBSTONE_COUNT:
        put(w, 64, 0)
        return random_nonce(o, w)
    end = tombstone_name(w, PATH_PART, index)
    store(w, end, 0)
    return call(o, w, 100, 262, get(w, 24), PATH_PART, STAT, 256, 0, 0, 60)

def random_nonce(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 101, 318, 12000 + get(w, 64), 16 - get(w, 64), 0, 0, 0, 0, 3)

def request_output(w:mutbuf) -> u64:
    root = ARENA + 64
    start = RAW_JSON + get(w, root + 56)
    size = get(w, root + 64)
    if size < 2:
        return 0
    store(w, OUTPUT, 123)
    at = ascii_json(w, OUTPUT + 1, start + 1, size - 2)
    if get(w, root + 32) != 0:
        store(w, at, 44)
        at = at + 1
    at = text_default_cwd(w, at)
    at = quoted_text(w, at, OLD_CWD, get(w, 600), 1)
    at = text_launch_nonce(w, at)
    at = quoted_text(w, at, BIND_NONCE, 32, 0)
    at = text_protocol(w, at)
    if get(w, HEADER + 16) != NONE:
        at = text_stdin_path(w, at)
        copy_bytes(w, PATH_PART + 1024, PATH, get(w, 320))
        end = PATH_PART + 1024 + get(w, 320)
        if byte(w, end - 1) != 47:
            store(w, end, 47)
            end = end + 1
        end = text_stdin_name(w, end)
        at = quoted_text(w, at, PATH_PART + 1024, end - PATH_PART - 1024, 1)
    store(w, at, 125)
    put(w, 648, at + 1 - OUTPUT)
    return 1

def stage_file(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 96)
    if index == 4 and get(w, HEADER + 16) == NONE:
        index = 5
        put(w, 96, index)
    if index == 6:
        return prepare_launch(o, w)
    if index < 4:
        end = image_name(w, PATH_PART, index)
        size = get(w, HEADER + 24 + index * 8)
    elif index == 4:
        end = text_stdin_name(w, PATH_PART)
        size = get(w, HEADER + 16)
    else:
        end = text_request_name(w, PATH_PART)
        size = get(w, 648)
    store(w, end, 0)
    put(w, 1056, size)
    put(w, 1040, 0)
    return call(o, w, 110, 257, get(w, 24), PATH_PART, 655553, 384, 0, 0, 12)

def stage(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 110:
        if failed(result):
            return 0
        put(w, 1048, result)
        return stage_read(o, w)
    if phase == 111:
        if result == NEG4:
            return stage_read(o, w)
        if failed(result) or result == 0 or result > 65536 or result > get(w, 1056) - get(w, 1040):
            return 0
        put(w, 1072, result)
        put(w, 1080, 0)
        return stage_write(o, w)
    if phase == 112:
        if result == NEG4:
            return stage_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1072) - get(w, 1080):
            return 0
        put(w, 1080, get(w, 1080) + result)
        if get(w, 1080) < get(w, 1072):
            return stage_write(o, w)
        put(w, 1040, get(w, 1040) + get(w, 1072))
        return stage_read(o, w)
    if phase == 113:
        if failed(result):
            return 0
        return call(o, w, 114, 74, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 114:
        if failed(result):
            return 0
        return call(o, w, 115, 3, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 115:
        if failed(result):
            return 0
        return call(o, w, 116, 74, get(w, 24), 0, 0, 0, 0, 0, 0)
    if phase == 116:
        if failed(result):
            return 0
        put(w, 96, get(w, 96) + 1)
        return stage_file(o, w)
    return 0

def stage_read(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1040) == get(w, 1056):
        return call(o, w, 113, 91, get(w, 1048), 384, 0, 0, 0, 0, 0)
    size = get(w, 1056) - get(w, 1040)
    if size > 65536:
        size = 65536
    if get(w, 96) == 5:
        put(w, 1072, size)
        put(w, 1080, 0)
        return stage_write(o, w)
    return call(o, w, 111, 17, get(w, 512 + get(w, 96) * 8), 65537, size, get(w, 1040), 0, 0, 12)

def stage_write(o:mutbuf, w:mutbuf) -> u32:
    source = 65537 + get(w, 1080)
    if get(w, 96) == 5:
        source = OUTPUT + get(w, 1040) + get(w, 1080)
    return call(o, w, 112, 1, get(w, 1048), source, get(w, 1072) - get(w, 1080), 0, 0, 0, 12)

def prepare_launch(o:mutbuf, w:mutbuf) -> u32:
    put(w, 0, 200)
    return 5

def binding_output(w:mutbuf) -> u64:
    at = text_binding_device(w, BINDING)
    at = decimal(w, at, get(w, 208))
    at = text_binding_inode(w, at)
    at = decimal(w, at, get(w, 216))
    at = text_binding_job(w, at)
    at = quoted_text(w, at, BIND_JOB, get(w, 328), 0)
    at = text_launch_nonce(w, at)
    at = quoted_text(w, at, BIND_NONCE, 32, 0)
    at = text_binding_fingerprint(w, at)
    at = quoted_text(w, at, BIND_DIGEST, 64, 0)
    at = text_binding_publisher(w, at)
    at = text_binding_encoder(w, at)
    at = quoted_text(w, at, BIND_PINS, 64, 0)
    at = text_binding_writer(w, at)
    at = quoted_text(w, at, BIND_PINS + 64, 64, 0)
    at = text_binding_supervisor(w, at)
    at = quoted_text(w, at, BIND_PINS + 128, 64, 0)
    store(w, at, 125)
    at = text_binding_flags(w, at + 1)
    store(w, at, 125)
    store(w, at + 1, 0)
    put(w, 632, at + 1 - BINDING)
    return choose(get(w, 632) <= 8192, 1, 0)

def submit_environment(s:readbuf, w:mutbuf) -> u64:
    count = uint(s, 16)
    if count > 128:
        return 0
    at = 32 + uint(s, 32) + 9
    put(w, 240, 0)
    put(w, 432, ENV_BYTES)
    index = 0
    while index < count:
        size = uint(s, at)
        if size > 8192 or at + 9 + size > length(s):
            return 0
        copy_input(s, w, ENV_TEMP, at + 8, size)
        if submit_env_insert(w, ENV_TEMP, size, 0) == 0:
            return 0
        at = at + size + 9
        index = index + 1
    if at != length(s):
        return 0
    end = text_xdg(w, ENV_TEMP)
    end = decimal(w, end, get(w, 584))
    if submit_env_insert(w, ENV_TEMP, end - ENV_TEMP, 1) == 0:
        return 0
    end = text_dbus(w, ENV_TEMP)
    end = decimal(w, end, get(w, 584))
    end = text_bus(w, end)
    return submit_env_insert(w, ENV_TEMP, end - ENV_TEMP, 1)

def submit_env_insert(w:mutbuf, source:u64, size:u64, default:u64) -> u64:
    key = 0
    while key < size and byte(w, source + key) != 61:
        key = key + 1
    if key == size:
        return 1
    count = get(w, 240)
    index = 0
    found = 0
    while index < count and found == 0:
        item = ENV_TABLE + index * 24
        if get(w, item + 16) == key and same_bytes(w, get(w, item), source, key) != 0:
            found = 1
        else:
            index = index + 1
    if found != 0 and default != 0:
        return 1
    if index == count:
        if count == 130:
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

def launch_output(o:mutbuf, w:mutbuf) -> u32:
    backend = get(w, 688)
    if backend == 1:
        at = text_launch_systemd(w, OUTPUT)
    elif backend == 2:
        at = text_launch_failed(w, OUTPUT)
    else:
        at = text_launch_detached(w, OUTPUT)
    at = quoted_text(w, at, UNIT, get(w, 608), 0)
    if backend == 1:
        at = text_launcher_null(w, at)
    else:
        if backend == 0:
            at = text_launcher_pid(w, at)
            at = decimal(w, at, get(w, 656))
        at = text_systemd_error(w, at)
        at = quoted_text(w, at, STDERR_BYTES + get(w, 712), get(w, 704), 0)
    store(w, at, 125)
    store(w, at + 1, 10)
    put(w, 664, at + 2 - OUTPUT)
    put(w, 64, 0)
    end = text_launch_tmp(w, PATH_PART)
    store(w, end, 0)
    return call(o, w, 160, 257, get(w, 24), PATH_PART, 655553, 384, 0, 0, 12)

def publish(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 160:
        if failed(result):
            return 0
        put(w, 1048, result)
        return publish_write(o, w)
    if phase == 161:
        if result == NEG4:
            return publish_write(o, w)
        if failed(result) or result == 0 or result > get(w, 664) - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < get(w, 664):
            return publish_write(o, w)
        return call(o, w, 162, 74, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 162:
        if failed(result):
            return 0
        return call(o, w, 163, 3, get(w, 1048), 0, 0, 0, 0, 0, 0)
    if phase == 163:
        if failed(result):
            return 0
        end = text_launch_name(w, PATH_PART + 128)
        store(w, end, 0)
        return call(o, w, 164, 264, get(w, 24), PATH_PART, get(w, 24), PATH_PART + 128, 0, 0, 204)
    if phase == 164:
        if failed(result):
            return 0
        return call(o, w, 165, 74, get(w, 24), 0, 0, 0, 0, 0, 0)
    if phase == 165:
        if failed(result):
            return 0
        if get(w, 688) == 2:
            size = get(w, 704)
            copy_bytes(w, OUTPUT, STDERR_BYTES + get(w, 712), size)
            store(w, OUTPUT + size, 10)
            put(w, 664, size + 1)
            put(w, 792, get(w, 696))
            put(w, 800, 2)
            put(w, 64, 0)
            return write_reply(o, w)
        # Prepend ok without changing the durable launch object.
        size = get(w, 664)
        copy_bytes(w, ROOT_CACHE, OUTPUT, size)
        at = text_ok_open(w, OUTPUT)
        copy_bytes(w, at, ROOT_CACHE + 1, size - 1)
        put(w, 664, at - OUTPUT + size - 1)
        put(w, 64, 0)
        return write_reply(o, w)
    return 0

def publish_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 161, 1, get(w, 1048), OUTPUT + get(w, 64), get(w, 664) - get(w, 64), 0, 0, 0, 12)

def write_reply(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 190, 1, choose(get(w, 800) == 2, 2, 1), OUTPUT + get(w, 64), get(w, 664) - get(w, 64), 0, 0, 0, 12)

def quoted_text(w:mutbuf, at:u64, source:u64, size:u64, filesystem:u64) -> u64:
    store(w, at, 34)
    at = at + 1
    index = 0
    while index < size:
        if filesystem != 0:
            unit = filesystem_scalar(w, source, size, index)
        else:
            unit = metadata_scalar(w, source, index)
        index = unit >> 32
        point = unit & 4294967295
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
    store(w, at, 34)
    return at + 1

def ascii_json(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        point = byte(w, source + index)
        if point < 128:
            store(w, at, point)
            at = at + 1
            index = index + 1
        else:
            unit = metadata_scalar(w, source, index)
            index = unit >> 32
            point = unit & 4294967295
            if point < 65536:
                at = escaped_scalar(w, at, point)
            else:
                point = point - 65536
                at = escaped_scalar(w, at, 55296 | (point >> 10))
                at = escaped_scalar(w, at, 56320 | (point & 1023))
    return at

def metadata_scalar(w:mutbuf, source:u64, index:u64) -> u64:
    point = byte(w, source + index)
    index = index + 1
    if point < 128:
        return (index << 32) | point
    needed = 1
    cp = point & 31
    if point >= 240:
        needed = 3
        cp = point & 7
    elif point >= 224:
        needed = 2
        cp = point & 15
    count = 0
    while count < needed:
        cp = (cp << 6) | (byte(w, source + index) & 63)
        index = index + 1
        count = count + 1
    return (index << 32) | cp
'''
LAUNCH_POLICY = r'''
def launch_advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 200:
        if binding_output(w) == 0 or submit_environment(s, w) == 0:
            return 0
        end = text_dev_null(w, PATH_PART)
        store(w, end, 0)
        return call(o, w, 201, 257, NEG100, PATH_PART, 524290, 0, 0, 0, 12)
    if phase == 201:
        if failed(result):
            return 0
        put(w, 672, result)
        platform = lookup(w, ARENA + 64, FIELD_platform)
        if platform != NONE:
            if get(w, platform) != 4 or string_equals(w, ARENA + get(w, platform + 24), get(w, platform + 32), 2) == 0:
                return systemd_unavailable(o, w)
        if path_environment(w) == 0:
            return systemd_unavailable(o, w)
        put(w, 736, 0)
        return systemd_candidate(o, w)
    if phase == 202:
        if failed(result) or getn(w, STAT + 24, 4) & 61440 != 32768:
            return systemd_candidate(o, w)
        return call(o, w, 203, 439, NEG100, SYSTEMD_PATH, 1, 0, 0, 0, 12)
    if phase == 203:
        if failed(result):
            return systemd_candidate(o, w)
        put(w, 688, 1)
        if systemd_command(w) == 0:
            return 0
        put(w, 808, 0)
        return systemd_image_chunk(o, w)
    if phase == 204:
        if result == NEG4:
            return systemd_image_read(o, w)
        if failed(result) or result == 0 or result > get(w, 824) - get(w, 816):
            return 0
        put(w, 816, get(w, 816) + result)
        if get(w, 816) < get(w, 824):
            return systemd_image_read(o, w)
        if image_argument(w) == 0:
            return 0
        put(w, 808, get(w, 808) + get(w, 824))
        return systemd_image_chunk(o, w)
    if phase == 210:
        if result != 0:
            return 0
        index = 0
        while index < get(w, 240):
            put(w, ENV_POINTERS + index * 8, get(w, ENV_TABLE + index * 24))
            index = index + 1
        put(w, ENV_POINTERS + index * 8, NONE)
        put(o, 0, ENV_POINTERS)
        put(o, 8, index + 1)
        put(o, 16, ENV_POINTERS + 2048)
        put(w, 0, 211)
        return 2
    if phase == 211:
        if result != 0:
            return 0
        return call(o, w, 212, 293, ERROR_PIPE, 524288, 0, 0, 0, 0, 3)
    if phase == 212:
        if failed(result):
            return 0
        if get(w, 688) == 0:
            return call(o, w, 214, 57, 0, 0, 0, 0, 0, 0, 0)
        end = text_error_memfd(w, PATH_PART)
        store(w, end, 0)
        return call(o, w, 213, 319, PATH_PART, 1, 0, 0, 0, 0, 3)
    if phase == 213:
        if failed(result):
            return 0
        put(w, 760, result)
        return call(o, w, 214, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 214:
        if failed(result):
            return 0
        if result == 0:
            if get(w, 688) == 0:
                return call(o, w, 215, 112, 0, 0, 0, 0, 0, 0, 0)
            put(w, 64, 0)
            return spawn_stdio(o, w)
        put(w, 656, result)
        return call(o, w, 220, 3, getn(w, ERROR_PIPE + 4, 4), 0, 0, 0, 0, 0, 0)
    if phase == 215:
        if failed(result):
            return child_error(o, w, result)
        put(w, 64, 0)
        return spawn_stdio(o, w)
    if phase == 216:
        if failed(result):
            return child_error(o, w, result)
        put(w, 64, get(w, 64) + 1)
        return spawn_stdio(o, w)
    if phase == 217:
        if failed(result):
            return child_error(o, w, result)
        if get(w, 688) == 0:
            store(w, PATH_PART, 0)
            return call(o, w, 218, 322, get(w, 536), PATH_PART, POINTERS + 1024, ENV_POINTERS + 2048, 4096, 0, 252)
        return call(o, w, 218, 59, SYSTEMD_PATH, POINTERS + 1024, ENV_POINTERS + 2048, 0, 0, 0, 63)
    if phase == 218:
        return child_error(o, w, result)
    if phase == 219:
        if result == NEG4:
            return call(o, w, 219, 1, getn(w, ERROR_PIPE + 4, 4), ERROR_RECORD, 8, 0, 0, 0, 12)
        return call(o, w, 199, 60, 127, 0, 0, 0, 0, 0, 0)
    if phase == 220:
        if failed(result):
            return 0
        put(w, 64, 0)
        return read_child_error(o, w)
    if phase == 221:
        if result == NEG4:
            return read_child_error(o, w)
        if failed(result) or result > 8 - get(w, 64):
            return 0
        if result != 0:
            put(w, 64, get(w, 64) + result)
            if get(w, 64) < 8:
                return read_child_error(o, w)
        put(w, 784, choose(get(w, 64) == 0, 0, 1))
        return call(o, w, 222, 3, getn(w, ERROR_PIPE, 4), 0, 0, 0, 0, 0, 0)
    if phase == 222:
        if failed(result):
            return 0
        if get(w, 784) != 0 or get(w, 688) != 0:
            return wait_systemd(o, w)
        return launch_output(o, w)
    if phase == 223:
        if result == NEG4:
            return wait_systemd(o, w)
        if failed(result) or result != get(w, 656) or get(w, 784) != 0:
            return 0
        status = getn(w, WAIT_STATUS, 4)
        code = (status >> 8) & 255
        if status & 127 != 0:
            code = (256 - (status & 127)) & 255
        put(w, 696, code)
        if code == 0:
            return launch_output(o, w)
        return call(o, w, 224, 5, get(w, 760), STAT, 0, 0, 0, 0, 12)
    if phase == 224:
        if failed(result) or get(w, STAT + 48) > 4194304:
            return 0
        put(w, 64, 0)
        put(w, 704, get(w, STAT + 48))
        return read_systemd_error(o, w)
    if phase == 225:
        if result == NEG4:
            return read_systemd_error(o, w)
        if failed(result) or result == 0 or result > get(w, 704) - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        return read_systemd_error(o, w)
    if phase >= 160 and phase <= 169:
        return publish(s, o, w, phase, result)
    return 0

def path_environment(w:mutbuf) -> u64:
    index = 0
    while index < get(w, 240):
        item = ENV_TABLE + index * 24
        if get(w, item + 16) == 4 and getn(w, get(w, item), 4) == PATH_WORD:
            put(w, 720, get(w, item) + 5)
            put(w, 728, get(w, item + 8) - 5)
            return choose(get(w, 728) != 0, 1, 0)
        index = index + 1
    end = text_default_path(w, PATH_SEARCH)
    put(w, 720, PATH_SEARCH)
    put(w, 728, end - PATH_SEARCH)
    return 1

def systemd_candidate(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 736)
    if at > get(w, 728):
        return systemd_unavailable(o, w)
    start = at
    while at < get(w, 728) and byte(w, get(w, 720) + at) != 58:
        at = at + 1
    put(w, 736, at + 1)
    count = at - start
    copy_bytes(w, SYSTEMD_PATH, get(w, 720) + start, count)
    end = SYSTEMD_PATH + count
    if count != 0:
        store(w, end, 47)
        end = end + 1
    end = text_systemd_run(w, end)
    store(w, end, 0)
    return call(o, w, 202, 262, NEG100, SYSTEMD_PATH, STAT, 0, 0, 0, 60)

def systemd_unavailable(o:mutbuf, w:mutbuf) -> u32:
    end = text_systemd_error_text(w, STDERR_BYTES)
    put(w, 704, end - STDERR_BYTES)
    put(w, 712, 0)
    put(w, 696, 127)
    return fallback(o, w)

def fallback(o:mutbuf, w:mutbuf) -> u32:
    root = ARENA + 64
    if truth(w, lookup(w, root, FIELD_allow_detached_fallback)) == 0:
        put(w, 688, 2)
        return launch_output(o, w)
    if truth(w, lookup(w, root, FIELD_cpu_quota_percent)) != 0 or truth(w, lookup(w, root, FIELD_memory_max_bytes)) != 0:
        return 0
    put(w, 688, 0)
    put(w, 744, 0)
    put(w, 752, 0)
    end = text_launcher_argv(w, CMD_BYTES)
    command_commit(w, end)
    if command_copy(w, PATH, get(w, 320), 0) == 0 or command_copy(w, BINDING, get(w, 632), 0) == 0:
        return 0
    at = CMD_BYTES + get(w, 752)
    command_commit(w, text_detached(w, at))
    return relocate_command(o, w)

def command_commit(w:mutbuf, end:u64) -> u64:
    count = get(w, 744)
    start = CMD_BYTES + get(w, 752)
    if count >= 120 or end < start or end >= CMD_BYTES + 2097152:
        return 0
    store(w, end, 0)
    put(w, POINTERS + count * 8, start)
    put(w, 744, count + 1)
    put(w, 752, end + 1 - CMD_BYTES)
    return 1

def command_copy(w:mutbuf, source:u64, size:u64, filesystem:u64) -> u64:
    at = CMD_BYTES + get(w, 752)
    if filesystem != 0:
        size = fs_copy(w, at, source, size, 8192)
        if size == NONE:
            return 0
    else:
        copy_bytes(w, at, source, size)
    if cstring_size(w, at, size) < size:
        return 0
    return command_commit(w, at + size)

def systemd_command(w:mutbuf) -> u64:
    put(w, 744, 0)
    put(w, 752, 0)
    systemd_fixed_arguments(w)
    if command_copy(w, UNIT, get(w, 608), 1) == 0:
        return 0
    systemd_fixed_properties(w)
    at = CMD_BYTES + get(w, 752)
    at = text_description(w, at)
    size = fs_copy(w, at, BIND_JOB, get(w, 328), 8192)
    if size == NONE:
        return 0
    at = at + size
    store(w, at, 32)
    copy_bytes(w, at + 1, BIND_NONCE, 32)
    command_commit(w, at + 33)
    root = ARENA + 64
    if numeric_property(w, lookup(w, root, FIELD_cpu_quota_percent), 1) == 0 or numeric_property(w, lookup(w, root, FIELD_memory_max_bytes), 2) == 0 or numeric_property(w, lookup(w, root, FIELD_nice), 3) == 0:
        return 0
    mode = lookup(w, root, FIELD_execution_mode)
    operator = 0
    if mode != NONE and get(w, mode) == 4:
        operator = string_equals(w, ARENA + get(w, mode + 24), get(w, mode + 32), 3)
    if operator == 0:
        systemd_isolation_arguments(w)
    if truth(w, lookup(w, root, FIELD_allow_job_network)) == 0:
        systemd_network_arguments(w)
    at = CMD_BYTES + get(w, 752)
    command_commit(w, text_double_dash(w, at))
    size = string_copy(w, lookup(w, root, FIELD_hia_job_entry_path), ENTRY_PATH, 8192, 1)
    if size == NONE or size < 2 or byte(w, ENTRY_PATH) != 47:
        return 0
    if command_copy(w, ENTRY_PATH, size, 0) == 0:
        return 0
    at = CMD_BYTES + get(w, 752)
    command_commit(w, text_launch_base64(w, at))
    if command_copy(w, BIND_PINS + 192, 64, 0) == 0:
        return 0
    if command_copy(w, PATH, get(w, 320), 0) == 0 or command_copy(w, BINDING, get(w, 632), 0) == 0:
        return 0
    return 1

def systemd_image_chunk(o:mutbuf, w:mutbuf) -> u32:
    remaining = get(w, HEADER + 48) - get(w, 808)
    if remaining == 0:
        return relocate_command(o, w)
    if remaining > 49152:
        remaining = 49152
    put(w, 816, 0)
    put(w, 824, remaining)
    return systemd_image_read(o, w)

def systemd_image_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 204, 17, get(w, 536), 65537 + get(w, 816), get(w, 824) - get(w, 816), get(w, 808) + get(w, 816), 0, 0, 12)

def image_argument(w:mutbuf) -> u64:
    size = get(w, 824)
    at = CMD_BYTES + get(w, 752)
    index = 0
    while index < size:
        a = byte(w, 65537 + index)
        b = 0
        c = 0
        if index + 1 < size:
            b = byte(w, 65538 + index)
        if index + 2 < size:
            c = byte(w, 65539 + index)
        store(w, at, base64_digit(a >> 2))
        store(w, at + 1, base64_digit(((a & 3) << 4) | (b >> 4)))
        store(w, at + 2, choose(index + 1 < size, base64_digit(((b & 15) << 2) | (c >> 6)), 61))
        store(w, at + 3, choose(index + 2 < size, base64_digit(c & 63), 61))
        index = index + 3
        at = at + 4
    return command_commit(w, at)

def base64_digit(value:u64) -> u64:
    if value < 26:
        return 65 + value
    if value < 52:
        return 97 + value - 26
    if value < 62:
        return 48 + value - 52
    return choose(value == 62, 43, 47)

def numeric_property(w:mutbuf, record:u64, kind:u64) -> u64:
    if truth(w, record) == 0:
        return 1
    if get(w, record) != 3:
        return 0
    size = get(w, record + 32)
    source = RAW_JSON + get(w, record + 24)
    if size == 0 or size > 20:
        return 0
    index = 0
    if kind == 3 and byte(w, source) == 45:
        index = 1
    if index == size:
        return 0
    while index < size:
        if byte(w, source + index) < 48 or byte(w, source + index) > 57:
            return 0
        index = index + 1
    at = CMD_BYTES + get(w, 752)
    command_commit(w, text_property(w, at))
    at = CMD_BYTES + get(w, 752)
    if kind == 1:
        at = text_cpu_quota(w, at)
    elif kind == 2:
        at = text_memory_max(w, at)
    else:
        at = text_nice(w, at)
    copy_bytes(w, at, source, size)
    at = at + size
    if kind == 1:
        store(w, at, 37)
        at = at + 1
    return command_commit(w, at)

def relocate_command(o:mutbuf, w:mutbuf) -> u32:
    count = get(w, 744)
    put(w, POINTERS + count * 8, NONE)
    put(o, 0, POINTERS)
    put(o, 8, count + 1)
    put(o, 16, POINTERS + 1024)
    put(w, 0, 210)
    return 2

def spawn_stdio(o:mutbuf, w:mutbuf) -> u32:
    target = get(w, 64)
    if target == 3:
        return call(o, w, 217, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    source = get(w, 672)
    if get(w, 688) != 0 and target == 2:
        source = get(w, 760)
    return call(o, w, 216, 33, source, target, 0, 0, 0, 0, 0)

def child_error(o:mutbuf, w:mutbuf, error:u64) -> u32:
    put(w, ERROR_RECORD, error)
    return call(o, w, 219, 1, getn(w, ERROR_PIPE + 4, 4), ERROR_RECORD, 8, 0, 0, 0, 12)

def read_child_error(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 221, 0, getn(w, ERROR_PIPE, 4), ERROR_RECORD + get(w, 64), 8 - get(w, 64), 0, 0, 0, 12)

def wait_systemd(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 223, 61, get(w, 656), WAIT_STATUS, 0, 0, 0, 0, 12)

def read_systemd_error(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 64) == get(w, 704):
        if trim_error(w) == 0:
            return 0
        return fallback(o, w)
    size = get(w, 704) - get(w, 64)
    if size > 65536:
        size = 65536
    return call(o, w, 225, 17, get(w, 760), STDERR_BYTES + get(w, 64), size, get(w, 64), 0, 0, 12)

def trim_error(w:mutbuf) -> u64:
    source_index = 0
    written = 0
    while source_index < get(w, 704):
        point = byte(w, STDERR_BYTES + source_index)
        source_index = source_index + 1
        if point == 13:
            point = 10
            if source_index < get(w, 704) and byte(w, STDERR_BYTES + source_index) == 10:
                source_index = source_index + 1
        store(w, STDERR_BYTES + written, point)
        written = written + 1
    put(w, 704, written)
    index = 0
    first = NONE
    last = 0
    size = get(w, 704)
    while index < size:
        before = index
        unit = utf8_scalar(w, STDERR_BYTES, size, index)
        if unit == NONE:
            return 0
        index = unit >> 32
        point = unit & 4294967295
        space = (point >= 9 and point <= 13) or (point >= 28 and point <= 32) or point == 133 or point == 160 or point == 5760 or (point >= 8192 and point <= 8202) or point == 8232 or point == 8233 or point == 8239 or point == 8287 or point == 12288
        if choose(space, 0, 1) != 0:
            if first == NONE:
                first = before
            last = index
    if first == NONE:
        first = 0
    put(w, 712, first)
    put(w, 704, last - first)
    return 1

def utf8_scalar(w:mutbuf, source:u64, size:u64, index:u64) -> u64:
    point = byte(w, source + index)
    index = index + 1
    if point < 128:
        return (index << 32) | point
    if point < 194 or point > 244:
        return NONE
    remaining = 1
    cp = point & 31
    minimum = 128
    if point >= 240:
        remaining = 3
        cp = point & 7
        minimum = 65536
    elif point >= 224:
        remaining = 2
        cp = point & 15
        minimum = 2048
    if index + remaining > size:
        return NONE
    while remaining != 0:
        point = byte(w, source + index)
        if point < 128 or point > 191:
            return NONE
        cp = (cp << 6) | (point & 63)
        index = index + 1
        remaining = remaining - 1
    if cp < minimum or cp > 1114111 or (cp >= 55296 and cp <= 57343):
        return NONE
    return (index << 32) | cp
'''


def literal_function(name, text):
    value = text.encode()
    source = f'\ndef {name}(w:mutbuf, at:u64) -> u64:\n'
    for i in range(0, len(value), 8):
        chunk = value[i:i + 8]
        if len(chunk) == 8:
            source += f'    put(w, at + {i}, {int.from_bytes(chunk, "little")})\n'
        else:
            for j, byte in enumerate(chunk):
                source += f'    store(w, at + {i + j}, {byte})\n'
    return source + f'    return at + {len(value)}\n'


def policy_source():
    source = POLICY + '\n' + LAUNCH_POLICY
    common = launch_policy_source()
    needed = {'normalize_json', 'encoding_word', 'put_utf8', 'same_stamp',
              'failed', 'uint', 'get', 'getn', 'put', 'decimal', 'hex_digit',
              'call', 'lookup', 'number', 'truth', 'equal_field', 'string_copy',
              'fs_copy', 'cstring_size', 'hex_bytes', 'same_bytes', 'copy_bytes',
              'copy_input', 'sha', 'filesystem_scalar', 'flags', 'publisher'}
    for node in ast.parse(common).body:
        if node.name in needed:
            source += '\n' + ast.get_source_segment(common, node) + '\n'
    for node in ast.parse(OBSERVATION_POLICY).body:
        if node.name in {'safe_file', 'escaped_scalar'}:
            source += '\n' + ast.get_source_segment(OBSERVATION_POLICY, node) + '\n'
    source += '\ndef key_id(w:mutbuf, at:u64, size:u64) -> u64:\n'
    lengths = sorted(set(map(len, FIELDS)))
    for length in lengths:
        source += f'    if size == {length}:\n'
        for index, field in enumerate(FIELDS, 1):
            value = field.encode()
            if len(value) != length:
                continue
            condition = ' and '.join(f"getn(w, at + {j}, {len(value[j:j+8])}) == {int.from_bytes(value[j:j+8], 'little')}" for j in range(0, len(value), 8))
            source += f'        if {condition}:\n            return {index}\n'
    source += '    return 0\n'
    for name, value in TEXT.items():
        source += literal_function('text_' + name, value)
    for function, values in (('image_name', IMAGE_NAMES), ('tombstone_name', TOMBSTONES)):
        source += f'\ndef {function}(w:mutbuf, at:u64, index:u64) -> u64:\n'
        for i in range(len(values)):
            source += f'    if index == {i}:\n        return {function}_{i}(w, at)\n'
        source += '    return at\n'
        for i, name in enumerate(values):
            source += literal_function(function + '_' + str(i), name)
    source += '\ndef string_equals(w:mutbuf, at:u64, size:u64, kind:u64) -> u64:\n'
    for i, name in enumerate(('launch_failed','linux','operator'), 1):
        value = name.encode()
        condition = ' and '.join(f"getn(w, at + {j}, {len(value[j:j+8])}) == {int.from_bytes(value[j:j+8], 'little')}" for j in range(0, len(value), 8))
        source += f'    if kind == {i} and size == {len(value)}:\n        return choose({condition}, 1, 0)\n'
    source += '    return 0\n'
    for function, arguments in {
        'systemd_fixed_arguments': ('systemd-run','--user','--quiet','--collect','--unit'),
        'systemd_fixed_properties': ('--property','KillMode=control-group','--property','TimeoutStopSec=10s','--property'),
        'systemd_isolation_arguments': ('--property','NoNewPrivileges=yes','--property','RestrictSUIDSGID=yes'),
        'systemd_network_arguments': ('--property','PrivateNetwork=yes','--property','RestrictAddressFamilies=AF_UNIX AF_NETLINK'),
    }.items():
        source += f'\ndef {function}(w:mutbuf) -> u64:\n'
        for value in arguments:
            source += '    at = CMD_BYTES + get(w, 752)\n'
            raw = value.encode()
            for i in range(0, len(raw), 8):
                chunk = raw[i:i + 8]
                if len(chunk) == 8:
                    source += f'    put(w, at + {i}, {int.from_bytes(chunk, "little")})\n'
                else:
                    for j, point in enumerate(chunk):
                        source += f'    store(w, at + {i + j}, {point})\n'
            source += f'    command_commit(w, at + {len(raw)})\n'
        source += '    return 1\n'
    values = dict(
        STATE_BYTES=STATE_BYTES, MAXIMUM_METADATA_DEPTH=MAXIMUM_METADATA_DEPTH,
        META=2 << 20, RAW_JSON=8 << 20, ARENA=16 << 20, ARENA_BYTES=160 << 20,
        SCRATCH=184 << 20, SCRATCH_BYTES=32 << 20,
        OUTPUT=184 << 20, ROOT_CACHE=216 << 20,
        BINDING=2 << 20, CMD_BYTES=6 << 20,
        STDERR_BYTES=176 << 20, SYSTEMD_PATH=139264, PATH_SEARCH=155648,
        ENTRY_PATH=172032,
        ERROR_PIPE=9216, WAIT_STATUS=9232, ERROR_RECORD=9240,
        PATH_WORD=int.from_bytes(b'PATH','little'),
        NONE=(1 << 64) - 1, NEG100=(1 << 64) - 100,
        NEG2=(1 << 64) - 2, NEG4=(1 << 64) - 4, NEG17=(1 << 64) - 17,
        ARG_MAGIC=int.from_bytes(b'HIAARG02', 'little'),
        SUBMIT_MAGIC=int.from_bytes(b'HIAJSB01', 'little'),
        JOBS_WORD=int.from_bytes(b'jobs', 'little'),
        HEADER=10240, IMAGE_HASHES=12288, STAT=8192,
        BIND_JOB=16384, BIND_NONCE=16544, BIND_DIGEST=16640,
        BIND_PINS=16800, UNIT=17408, REQUEST_DIGEST=17920,
        PATH=32768, PATH_PART=40960, OLD_CWD=49152,
        POINTERS=2304, ENV_POINTERS=24576,
        ENV_TABLE=204800, ENV_TEMP=212992, ENV_BYTES=262144,
        ENV_END=2 << 20, TOMBSTONE_COUNT=len(TOMBSTONES),
    )
    values.update({'FIELD_' + name: index for index, name in enumerate(FIELDS, 1)})
    for name in sorted(values, key=len, reverse=True):
        source = re.sub(r'\b' + re.escape(name) + r'\b', str(values[name]), source)
    return source


def reachable(source, entry):
    functions = {node.name:node for node in ast.parse(source).body}
    found = set()
    def visit(name):
        if name in found or name not in functions:
            return
        found.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                visit(node.func.id)
    visit(entry)
    names = [entry] + [name for name in functions if name != entry and name in found]
    return '\n\n'.join(ast.get_source_segment(source,functions[name]) for name in names)+'\n'


def template():
    adapter = ROOT / 'tools/hia_job_submit_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-job-submit-author-') as tmp:
        obj, raw = Path(tmp) / 'adapter.o', Path(tmp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(adapter), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('submit adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in
                           ('job_submit_policy_hole', 'job_submit_launch_hole', 'job_submit_json_hole', 'job_submit_sha_hole')}


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 44 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    launch = uint(s, 16, 8)
    decoder = uint(s, 24, 8)
    sha = uint(s, 32, 8)
    if policy == 0 or launch == 0 or decoder == 0 or sha == 0 or policy > 2097152 or launch > 2097152 or decoder > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 40 + policy + launch + decoder + sha:
        return 4294967295
    size = {len(prefix)} + policy + launch + decoder + sha
    if size > 4194304 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        source += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix))
        if not name.endswith('policy_hole'):
            target += ' + policy'
        if name.endswith('json_hole') or name.endswith('sha_hole'):
            target += ' + launch'
        if name.endswith('sha_hole'):
            target += ' + decoder'
        source += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 40, {len(prefix)}, policy + launch + decoder + sha)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]



def main():
    for module, source in (
        ('job_submit', reachable(policy_source(),'advance')),
        ('job_submit_launch', reachable(policy_source(),'launch_advance')),
        ('job_submit_json', metadata_json_source()),
        ('job_submit_packer', packer_source()),
    ):
        path = ROOT / 'examples/hia_bootstrap' / (module + '.hepta')
        path.write_text(render_assembly(document(source, module)))
        print(path.name, path.stat().st_size, flush=True)


if __name__ == '__main__':
    main()
