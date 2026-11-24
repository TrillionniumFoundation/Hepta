"""Author root-owned Jobctl registry preparation and durable launch barriers.

This continuation begins after exact Request/policy admission and the existing
registry flock.  Retained records remain ownership evidence, never free slots.
No submitted executable image is interpreted or executed by this root owner.
"""
from __future__ import annotations
from tools.generate_hia_system_jobctl_diagnostics import HELPERS as DIAGNOSTICS
from tools.generate_hia_system_jobctl_typed_errors import HELPERS as TYPED_ERRORS
import argparse, ast, re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document, request_source
from tools import generate_hia_system_jobctl_control as control
from tools import generate_hia_system_jobctl_record as record

ROOT=Path(__file__).resolve().parents[1]
CONSTANTS={**control.CONSTANTS,**record.CONSTANTS,
 'DIGEST':43008,'NONCE':43104,'TIMESTAMP':43200,'PROTOCOL':43300,'PENDING':43400,
 'BOOT':102<<20,'SHA_STATE':106<<20,'SHA_OUT':33024,
 'SPEC_OUT':122<<20,'SPEC_SIZE':41432,'START_REUSED':41440,
 'ATOMIC_NEXT':41600,'ATOMIC_DATA':41608,'ATOMIC_SIZE':41616,'ATOMIC_USED':41624,
 'ATOMIC_FD':41632,'ATOMIC_PARENT_FD':41640,'PID':41648,
 'ATOMIC_FAILURE_NEXT':41688,'ATOMIC_ERROR':41696,
 'START_PID':41704,'START_STATUS':41712,'START_POLLS':41720,'START_STOP':41736,
 'SIGNAL_HANDLER':41744,'SIGNAL_RESTORER':41752,'START_WAIT':41760,
 'START_SLEEP':41840,'START_REMAINING':41856,'START_SIGNAL':41800,
 'REPLY_SIZE':41784,'REPLY_USED':41792,'REPLY_SOURCE':41872,
 'START_REPLY':104<<20,'START_REPLY_SIZE':41920,
 'BARRIER_ROOT_FD':41656,'BARRIER_PARENT_FD':41664,
 'COMMAND':124<<20,'COMMAND_END':126<<20,'ARGV':126<<20,'COMMAND_COUNT':41672,'COMMAND_CURSOR':41680}
COMMAND_VALUES=['/usr/bin/systemd-run', '--quiet', '--collect', '--unit', '--pty', '--wait', '--property', 'Description=Hepta Runtime ', 'DynamicUser=yes', 'Slice=hepta-runtime-jobs.slice', 'SupplementaryGroups=hepta-workspace', 'StateDirectory=hepta-job-', 'StateDirectoryMode=0700', 'LoadCredential=spec:', 'BindPaths=', 'WorkingDirectory=/workspace', 'InaccessiblePaths=-/var/lib/hepta-runtime -/etc/hepta-runtime -/run/user -/run/dbus -/run/systemd/private -/run/docker.sock -/run/libvirt', 'ProtectHome=yes', 'ProtectSystem=strict', 'PrivateTmp=yes', 'PrivateDevices=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'RestrictSUIDSGID=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictRealtime=yes', 'LockPersonality=yes', 'ProtectProc=invisible', 'KillMode=control-group', 'TimeoutStopSec=3s', 'TasksMax=infinity', 'UMask=0007', 'MemorySwapMax=0', 'CPUQuota=', 'MemoryMax=', 'Nice=', 'RuntimeMaxSec=', ':/workspace', 'PrivateNetwork=yes', 'RestrictAddressFamilies=AF_UNIX AF_NETLINK', '--', '/usr/local/libexec/hepta-runtime-jobctl', 'supervise', 'supervise-pty']
TEXT={'identity_error':'job identity mismatch','different_request':'job ID already bound to a different request',
 'invalid_utf8':'stream did not contain valid UTF-8','bad_nonce':'kernel launch nonce is not 128-bit lowercase hexadecimal',
 'launch_failure':'systemd launch failed: ',
 'barrier_root_open':'open job registry before dispatch: ',
 'barrier_parent_open':'open job registry parent before dispatch: ',
 'barrier_root_sync':'sync job registry before dispatch: ',
 'barrier_parent_sync':'sync job registry parent before dispatch: ',
 'write_zero':'failed to write whole buffer',**control.TEXT,
 'spec_tmp':'/spec.tmp-','record_tmp':'/record.tmp-',
 'pending':'pending','captured':'captured_v1','pty_protocol':'pty_v1',
 'launched':'launched','launch_failed':'launch_failed',
 'start_reply':'{"backend":"systemd_system","invocation_id":',
 'start_reply_unit':',"ok":true,"unit":',
 'start_reply_end':',"workspace":"/workspace"}',
 'pty_reply':'{"pty_exit_code":','null':'null',
 'spec_request':'{"request":','spec_nonce':',"nonce":','spec_boot':',"boot_id":',
 'spec_workspace':',"workspace":','spec_protocol':',"terminal_protocol":'}

POLICY=r'''
def start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 1400 and phase < 1420:
        return atomic_write(s, o, w, phase, result)
    if phase >= 320 and phase < 330:
        return namespace_barrier(o, w, phase, result)
    if phase == 300:
        put(w, START_REUSED, 0)
        return hash_request(o, w, 301, 0, 1)
    if phase == 301:
        if result != 0:
            return 0
        return hash_request(o, w, 302, 1, get(w, REQUEST_SIZE) + 1)
    if phase == 302:
        if result != 0:
            return 0
        return hash_request(o, w, 303, 2, 1)
    if phase == 303:
        if result != 32:
            return 0
        index = 0
        while index < 32:
            value = byte(w, SHA_OUT + index)
            store(w, DIGEST + index * 2, hexadecimal(value >> 4))
            store(w, DIGEST + index * 2 + 1, hexadecimal(value & 15))
            index = index + 1
        record_path(w)
        return call(o, w, 304, 262, NEG100, PATH, STAT, 0, 0, 0, 60)
    if phase == 304:
        if result == 0:
            return begin_file(o, w, 305, PATH, FILE_RAW, 1048576)
        return call(o, w, 307, 258, NEG100, REGISTRY, 511, 0, 0, 0, 12)
    if phase == 305:
        return record_call(o, w, 306, 0, FILE_RAW, get(w, 288))
    if phase == 306:
        if result != 1:
            return typed_error(o, w, 258, FILE_RAW, get(w, 288), 317)
        if retained_identity(w) == 0:
            return diagnostic(w, DIAG_TEXT, text_identity_error(w, DIAG_TEXT) - DIAG_TEXT)
        if equal(w, get(w, RECORD_FIELDS + 32), get(w, RECORD_FIELDS + 40), DIGEST, 64) == 0:
            return diagnostic(w, DIAG_TEXT, text_different_request(w, DIAG_TEXT) - DIAG_TEXT)
        put(w, START_REUSED, 1)
        put(w, 0, 200)
        return 8
    if phase == 307:
        if result != 0 and result != NEG17:
            return diagnostic_errno(w, result)
        return call(o, w, 308, 262, NEG100, REGISTRY, STAT, 0, 0, 0, 60)
    if phase == 308:
        if result != 0:
            return diagnostic_errno(w, result)
        if getn(w, STAT + 24, 4) & 61440 != 16384:
            return diagnostic_errno(w, NEG17)
        return call(o, w, 309, 90, REGISTRY, 448, 0, 0, 0, 0, 3)
    if phase == 309:
        if result != 0:
            return diagnostic_errno(w, result)
        terminated(w, text_uuid(w, PATH))
        return begin_file(o, w, 310, PATH, FILE_RAW, 1048576)
    if phase == 310:
        if kernel_text(w, FILE_RAW, get(w, 288)) == 0:
            return diagnostic(w, DIAG_TEXT, text_invalid_utf8(w, DIAG_TEXT) - DIAG_TEXT)
        size = get(w, SCAN_SIZE)
        source = get(w, SCAN_NEXT)
        index = 0
        used = 0
        while index < size:
            point = byte(w, source + index)
            if point != 45:
                if used == 32 or ((point < 48 or point > 57) and (point < 97 or point > 102)):
                    return diagnostic(w, DIAG_TEXT, text_bad_nonce(w, DIAG_TEXT) - DIAG_TEXT)
                store(w, NONCE + used, point)
                used = used + 1
            index = index + 1
        if used != 32:
            return diagnostic(w, DIAG_TEXT, text_bad_nonce(w, DIAG_TEXT) - DIAG_TEXT)
        terminated(w, text_boot(w, PATH))
        return begin_file(o, w, 311, PATH, FILE_RAW, 1048576)
    if phase == 311:
        if kernel_text(w, FILE_RAW, get(w, 288)) == 0:
            return diagnostic(w, DIAG_TEXT, text_invalid_utf8(w, DIAG_TEXT) - DIAG_TEXT)
        copy(w, BOOT, get(w, SCAN_NEXT), get(w, SCAN_SIZE))
        field(w, 3, BOOT, get(w, SCAN_SIZE))
        return call(o, w, 312, 228, 0, STAT, 0, 0, 0, 0, 12)
    if phase == 312:
        if result != 0:
            put(w, STAT, 0)
            put(w, STAT + 8, 0)
        milliseconds(w)
        field(w, 0, JOB_ID, get(w, 48))
        field(w, 1, UNIT, get(w, 56))
        field(w, 2, DIGEST, 64)
        field(w, 4, NONCE, 32)
        field(w, 5, NONE, 0)
        field(w, 6, PENDING, text_pending(w, PENDING) - PENDING)
        protocol = 1
        size = text_captured(w, PROTOCOL) - PROTOCOL
        if get(w, 40) == 2:
            protocol = 2
            size = text_pty_protocol(w, PROTOCOL) - PROTOCOL
        field(w, 8, PROTOCOL, size)
        put(w, RECORD_PROTOCOL, protocol)
        return record_call(o, w, 313, 1, FILE_RAW, 0)
    if phase == 313:
        if result != 1 or prepare_spec(w) == 0:
            return 0
        return call(o, w, 314, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 314:
        if failed(result):
            return diagnostic_errno(w, result)
        put(w, PID, result)
        return begin_atomic(o, w, 315, 0, SPEC_OUT, get(w, SPEC_SIZE))
    if phase == 315:
        return begin_atomic(o, w, 316, 1, RECORD_OUT, get(w, RECORD_SIZE))
    if phase == 317:
        return typed_failure(w, DIAG_TEXT, text_unknown_job(w, DIAG_TEXT) - DIAG_TEXT)
    if phase == 316:
        put(w, BARRIER_ROOT_FD, NONE)
        put(w, BARRIER_PARENT_FD, NONE)
        terminated(w, text_root(w, PATH))
        return call(o, w, 320, 257, NEG100, PATH, 524288, 0, 0, 0, 12)
    if phase >= 700 and phase < 800:
        return launched(s, o, w, phase, result)
    return 0

def launched(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 700:
        if build_command(w) == 0:
            return 0
        if get(w, 40) == 2:
            put(w, 0, 701)
            return 15
        return launch_process(w)
    if phase == 701:
        return call(o, w, 702, 158, 4097, 0, 0, 0, 0, 0, 12)
    if phase == 702:
        if result != 0:
            return 0
        put(w, START_SIGNAL, get(w, SIGNAL_HANDLER))
        put(w, START_SIGNAL + 8, 335544320)
        put(w, START_SIGNAL + 16, get(w, SIGNAL_RESTORER))
        put(w, START_SIGNAL + 24, 0)
        return call(o, w, 703, 13, 15, START_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 703:
        return call(o, w, 704, 13, 2, START_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 704:
        return call(o, w, 705, 13, 1, START_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 705:
        return launch_process(w)
    if phase == 730:
        if get(w, 51368) != 0:
            return diagnostic_errno(w, 0 - get(w, 51368))
        if get(w, 51232) != 0:
            put(w, 41928, 0 - get(w, 51232))
            put(w, 0, 745)
            return 8
        put(w, START_PID, get(w, 51216))
        put(w, START_STATUS, get(w, 51224))
        if get(w, 40) == 2:
            put(w, START_POLLS, 0)
            return observation(w, 733, 1)
        return call(o, w, 731, 3, get(w, 52000), 0, 0, 0, 0, 0, 0)
    if phase == 731:
        put(w, 52000, NONE)
        if get(w, START_STATUS) != 0:
            field(w, 6, PENDING, text_launch_failed(w, PENDING) - PENDING)
            return record_call(o, w, 740, 1, FILE_RAW, 0)
        return call(o, w, 732, 3, get(w, 52008), 0, 0, 0, 0, 0, 0)
    if phase == 732:
        put(w, 52008, NONE)
        return mark_launched(w)
    if phase == 733:
        put(w, 52800, 0)
        if get(w, 52824) != 0:
            return mark_launched(w)
        put(w, START_SLEEP, 0)
        put(w, START_SLEEP + 8, 10000000)
        return call(o, w, 734, 35, START_SLEEP, START_REMAINING, 0, 0, 0, 0, 15)
    if phase == 734:
        if result == NEG4:
            copy(w, START_SLEEP, START_REMAINING, 16)
            return call(o, w, 734, 35, START_SLEEP, START_REMAINING, 0, 0, 0, 0, 15)
        if result != 0:
            return 0
        put(w, START_POLLS, get(w, START_POLLS) + 1)
        if get(w, START_POLLS) < 100:
            return observation(w, 733, 1)
        return mark_launched(w)
    if phase == 735:
        put(w, 52800, 0)
        return record_call(o, w, 736, 1, FILE_RAW, 0)
    if phase == 736:
        if result != 1:
            return 0
        return begin_atomic(o, w, 737, 1, RECORD_OUT, get(w, RECORD_SIZE))
    if phase == 737:
        put(w, 68500, 738)
        put(w, 0, 2080)
        return 8
    if phase == 738:
        put(w, 368, NONE)
        if save_start_reply(w) == 0:
            return 0
        if get(w, 40) == 2:
            return wait_pty(o, w)
        return start_reply(o, w)
    if phase == 740:
        if result != 1:
            return 0
        put(w, ATOMIC_FAILURE_NEXT, 742)
        return begin_atomic(o, w, 741, 1, RECORD_OUT, get(w, RECORD_SIZE))
    if phase == 741:
        fd = get(w, 52008)
        put(w, 52008, NONE)
        return diagnostic_stderr(w, fd, get(w, 51248), DIAG_TEXT, text_launch_failure(w, DIAG_TEXT) - DIAG_TEXT)
    if phase == 742:
        return call(o, w, 744, 3, get(w, 52008), 0, 0, 0, 0, 0, 0)
    if phase == 744:
        put(w, 52008, NONE)
        if get(w, 68008) == 1:
            return diagnostic(w, DIAG_TEXT, text_write_zero(w, DIAG_TEXT) - DIAG_TEXT)
        return diagnostic_errno(w, get(w, 68000))
    if phase == 745:
        fd = get(w, 52000)
        put(w, 52000, NONE)
        if fd != NONE:
            return call(o, w, 746, 3, fd, 0, 0, 0, 0, 0, 0)
        put(w, 0, 746)
        return 8
    if phase == 746:
        fd = get(w, 52008)
        put(w, 52008, NONE)
        if fd != NONE:
            return call(o, w, 747, 3, fd, 0, 0, 0, 0, 0, 0)
        put(w, 0, 747)
        return 8
    if phase == 747:
        return diagnostic_errno(w, get(w, 41928))
    if phase == 750:
        if result == get(w, START_PID):
            return pty_reply(o, w, getn(w, START_WAIT, 4))
        if result != 0:
            return diagnostic_errno(w, result)
        if get(w, START_STOP) != 0:
            put(w, 40, 5)
            return observation(w, 754, 3)
        put(w, START_SLEEP, 0)
        put(w, START_SLEEP + 8, 25000000)
        return call(o, w, 751, 35, START_SLEEP, START_REMAINING, 0, 0, 0, 0, 15)
    if phase == 751:
        if result == NEG4:
            copy(w, START_SLEEP, START_REMAINING, 16)
            return call(o, w, 751, 35, START_SLEEP, START_REMAINING, 0, 0, 0, 0, 15)
        if result != 0:
            return 0
        return wait_pty(o, w)
    if phase == 754:
        put(w, 52800, 0)
        put(w, 40, 2)
        return call(o, w, 755, 62, get(w, START_PID), 9, 0, 0, 0, 0, 0)
    if phase == 755:
        return call(o, w, 756, 61, get(w, START_PID), START_WAIT, 0, 0, 0, 0, 12)
    if phase == 756:
        if result == NEG4:
            return call(o, w, 756, 61, get(w, START_PID), START_WAIT, 0, 0, 0, 0, 12)
        return start_reply(o, w)
    if phase == 780:
        if result == NEG4:
            return reply_bytes(o, w)
        if result == 0 or failed(result) or result > get(w, REPLY_SIZE) - get(w, REPLY_USED):
            return 0
        put(w, REPLY_USED, get(w, REPLY_USED) + result)
        if get(w, REPLY_USED) < get(w, REPLY_SIZE):
            return reply_bytes(o, w)
        return call(o, w, 781, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0

def launch_process(w:mutbuf) -> u32:
    put(w, 51200, choose(get(w, 40) == 2, 1, 0))
    put(w, 51208, 730)
    put(w, 51360, 730)
    put(w, 0, 1500)
    return 11

def observation(w:mutbuf, next:u64, operation:u64) -> u32:
    put(w, 52800, operation)
    put(w, 52808, next)
    put(w, 0, 200)
    return 6

def mark_launched(w:mutbuf) -> u32:
    field(w, 6, PENDING, text_launched(w, PENDING) - PENDING)
    return observation(w, 735, 2)

def wait_pty(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 750, 61, get(w, START_PID), START_WAIT, 1, 0, 0, 0, 12)

def save_start_reply(w:mutbuf) -> u64:
    at = text_start_reply(w, RECORD_OUT)
    source = get(w, RECORD_FIELDS + 80)
    if source == NONE:
        at = text_null(w, at)
    else:
        at = quote(w, at, source, get(w, RECORD_FIELDS + 88))
    if at == NONE:
        return 0
    at = text_start_reply_unit(w, at)
    at = quote(w, at, UNIT, get(w, 56))
    if at == NONE:
        return 0
    at = text_start_reply_end(w, at)
    store(w, at, 10)
    size = at + 1 - RECORD_OUT
    if size > 2097152:
        return 0
    copy(w, START_REPLY, RECORD_OUT, size)
    put(w, START_REPLY_SIZE, size)
    return 1

def start_reply(o:mutbuf, w:mutbuf) -> u32:
    put(w, REPLY_SOURCE, START_REPLY)
    put(w, REPLY_SIZE, get(w, START_REPLY_SIZE))
    put(w, REPLY_USED, 0)
    return reply_bytes(o, w)

def pty_reply(o:mutbuf, w:mutbuf, status:u64) -> u32:
    at = text_pty_reply(w, RECORD_OUT)
    if status & 127 == 0:
        at = decimal(w, at, (status >> 8) & 255)
    else:
        at = text_null(w, at)
    store(w, at, 125)
    return emit_reply(o, w, at + 1)

def emit_reply(o:mutbuf, w:mutbuf, at:u64) -> u32:
    put(w, REPLY_SOURCE, RECORD_OUT)
    store(w, at, 10)
    put(w, REPLY_SIZE, at + 1 - RECORD_OUT)
    put(w, REPLY_USED, 0)
    return reply_bytes(o, w)

def reply_bytes(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 780, 1, 1, get(w, REPLY_SOURCE) + get(w, REPLY_USED), get(w, REPLY_SIZE) - get(w, REPLY_USED), 0, 0, 0, 12)

def build_command(w:mutbuf) -> u64:
    put(w, COMMAND_COUNT, 0)
    put(w, COMMAND_CURSOR, COMMAND)
    if constant_argument(w, 0) == 0 or constant_argument(w, 1) == 0 or constant_argument(w, 2) == 0 or constant_argument(w, 3) == 0:
        return 0
    if raw_argument(w, UNIT, get(w, 56)) == 0:
        return 0
    if get(w, 40) == 2:
        if constant_argument(w, 4) == 0 or constant_argument(w, 5) == 0:
            return 0
    property = 0
    while property < 32:
        if constant_argument(w, 6) == 0:
            return 0
        at = get(w, COMMAND_CURSOR)
        stop = command_text(w, 7 + property, at)
        if property == 0:
            copy(w, stop, JOB_ID, get(w, 48))
            stop = stop + get(w, 48)
            store(w, stop, 32)
            copy(w, stop + 1, NONCE, 32)
            stop = stop + 33
        elif property == 4:
            copy(w, stop, JOB_ID, get(w, 48))
            stop = stop + get(w, 48)
        elif property == 6:
            copy(w, stop, REGISTRY, get(w, 64))
            stop = text_spec(w, stop + get(w, 64))
        elif property == 7:
            copy(w, stop, get(w, 2096), get(w, 2104))
            stop = stop + get(w, 2104)
            stop = command_text(w, 39, stop)
        elif property == 28:
            value = get(w, 2080)
            if present(w, 9) == 1:
                value = get(w, VALUES + 72)
            stop = decimal(w, stop, value)
            store(w, stop, 37)
            stop = stop + 1
        elif property == 29:
            value = get(w, 2088)
            if present(w, 10) == 1:
                value = get(w, VALUES + 80)
            stop = decimal(w, stop, value)
        elif property == 30:
            value = 10
            if present(w, 8) == 1:
                value = get(w, VALUES + 64)
            stop = decimal(w, stop, value)
        elif property == 31:
            stop = decimal(w, stop, get(w, OVERRIDE_TIMEOUT) + 10)
            store(w, stop, 115)
            stop = stop + 1
        if argument(w, stop) == 0:
            return 0
        property = property + 1
    if get(w, 2064) == 0:
        if constant_argument(w, 6) == 0 or constant_argument(w, 40) == 0 or constant_argument(w, 6) == 0 or constant_argument(w, 41) == 0:
            return 0
    if constant_argument(w, 42) == 0 or constant_argument(w, 43) == 0:
        return 0
    if constant_argument(w, choose(get(w, 40) == 2, 45, 44)) == 0:
        return 0
    return raw_argument(w, JOB_ID, get(w, 48))

def constant_argument(w:mutbuf, value:u64) -> u64:
    return argument(w, command_text(w, value, get(w, COMMAND_CURSOR)))

def raw_argument(w:mutbuf, source:u64, size:u64) -> u64:
    at = get(w, COMMAND_CURSOR)
    if size >= COMMAND_END - at:
        return 0
    copy(w, at, source, size)
    return argument(w, at + size)

def argument(w:mutbuf, stop:u64) -> u64:
    at = get(w, COMMAND_CURSOR)
    count = get(w, COMMAND_COUNT)
    if stop < at or stop >= COMMAND_END or count >= 128:
        return 0
    put(w, ARGV + count * 16, at)
    put(w, ARGV + count * 16 + 8, stop - at)
    store(w, stop, 0)
    put(w, COMMAND_CURSOR, stop + 1)
    put(w, COMMAND_COUNT, count + 1)
    return 1

def namespace_barrier(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 320:
        if result == NEG4:
            return call(o, w, 320, 257, NEG100, PATH, 524288, 0, 0, 0, 12)
        if failed(result):
            return barrier_failure(o, w, 1, result)
        put(w, BARRIER_ROOT_FD, result)
        terminated(w, text_varlib(w, PATH))
        return call(o, w, 321, 257, NEG100, PATH, 524288, 0, 0, 0, 12)
    if phase == 321:
        if result == NEG4:
            return call(o, w, 321, 257, NEG100, PATH, 524288, 0, 0, 0, 12)
        if failed(result):
            return barrier_failure(o, w, 2, result)
        put(w, BARRIER_PARENT_FD, result)
        return call(o, w, 322, 74, get(w, BARRIER_ROOT_FD), 0, 0, 0, 0, 0, 0)
    if phase == 322:
        if result == NEG4:
            return call(o, w, 322, 74, get(w, BARRIER_ROOT_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return barrier_failure(o, w, 3, result)
        return call(o, w, 323, 74, get(w, BARRIER_PARENT_FD), 0, 0, 0, 0, 0, 0)
    if phase == 323:
        if result == NEG4:
            return call(o, w, 323, 74, get(w, BARRIER_PARENT_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return barrier_failure(o, w, 4, result)
        return call(o, w, 324, 3, get(w, BARRIER_ROOT_FD), 0, 0, 0, 0, 0, 0)
    if phase == 324:
        put(w, BARRIER_ROOT_FD, NONE)
        return call(o, w, 325, 3, get(w, BARRIER_PARENT_FD), 0, 0, 0, 0, 0, 0)
    if phase == 325:
        put(w, BARRIER_PARENT_FD, NONE)
        put(w, 0, 700)
        return 8
    if phase == 326:
        fd = get(w, BARRIER_ROOT_FD)
        put(w, BARRIER_ROOT_FD, NONE)
        if fd != NONE:
            return call(o, w, 327, 3, fd, 0, 0, 0, 0, 0, 0)
        put(w, 0, 327)
        return 8
    if phase == 327:
        fd = get(w, BARRIER_PARENT_FD)
        put(w, BARRIER_PARENT_FD, NONE)
        if fd != NONE:
            return call(o, w, 328, 3, fd, 0, 0, 0, 0, 0, 0)
        put(w, 0, 328)
        return 8
    if phase == 328:
        kind = get(w, 68128)
        end = text_barrier_root_open(w, DIAG_TEXT)
        if kind == 2:
            end = text_barrier_parent_open(w, DIAG_TEXT)
        elif kind == 3:
            end = text_barrier_root_sync(w, DIAG_TEXT)
        elif kind == 4:
            end = text_barrier_parent_sync(w, DIAG_TEXT)
        return diagnostic_context_errno(w, DIAG_TEXT, end - DIAG_TEXT, get(w, 68120))
    return 0

def barrier_failure(o:mutbuf, w:mutbuf, kind:u64, result:u64) -> u32:
    put(w, 68120, result)
    put(w, 68128, kind)
    put(w, 0, 326)
    return 8

def record_path(w:mutbuf) -> u64:
    copy(w, PATH, REGISTRY, get(w, 64))
    return terminated(w, text_record(w, PATH + get(w, 64)))

def retained_identity(w:mutbuf) -> u64:
    if equal(w, get(w, RECORD_FIELDS), get(w, RECORD_FIELDS + 8), JOB_ID, get(w, 48)) == 0:
        return 0
    return equal(w, get(w, RECORD_FIELDS + 16), get(w, RECORD_FIELDS + 24), UNIT, get(w, 56))

def field(w:mutbuf, index:u64, source:u64, size:u64) -> u64:
    put(w, RECORD_FIELDS + index * 16, source)
    put(w, RECORD_FIELDS + index * 16 + 8, size)
    return 0

def hash_request(o:mutbuf, w:mutbuf, next:u64, command:u64, size:u64) -> u32:
    store(w, REQUEST_OUT - 1, command)
    put(w, 0, next)
    put(o, 0, REQUEST_OUT - 1)
    put(o, 8, size)
    put(o, 16, SHA_OUT)
    put(o, 24, SHA_STATE)
    return 10

def record_call(o:mutbuf, w:mutbuf, next:u64, mode:u64, source:u64, size:u64) -> u32:
    put(w, RECORD_MODE, mode)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    return 9

def prepare_spec(w:mutbuf) -> u64:
    at = text_spec_request(w, SPEC_OUT)
    size = get(w, REQUEST_SIZE)
    if size > 2097152:
        return 0
    copy(w, at, REQUEST_OUT, size)
    at = text_spec_nonce(w, at + size)
    at = quote(w, at, NONCE, 32)
    if at == NONE:
        return 0
    at = text_spec_boot(w, at)
    at = quote(w, at, get(w, RECORD_FIELDS + 48), get(w, RECORD_FIELDS + 56))
    if at == NONE:
        return 0
    at = text_spec_workspace(w, at)
    at = quote(w, at, get(w, 2096), get(w, 2104))
    if at == NONE:
        return 0
    at = text_spec_protocol(w, at)
    at = quote(w, at, PROTOCOL, get(w, RECORD_FIELDS + 136))
    if at == NONE or at >= QUOTE_END - 2:
        return 0
    store(w, at, 125)
    put(w, SPEC_SIZE, at + 1 - SPEC_OUT)
    return 1

def begin_atomic(o:mutbuf, w:mutbuf, next:u64, record_file:u64, source:u64, size:u64) -> u32:
    put(w, ATOMIC_NEXT, next)
    put(w, ATOMIC_DATA, source)
    put(w, ATOMIC_SIZE, size + 1)
    put(w, ATOMIC_USED, 0)
    put(w, ATOMIC_FD, NONE)
    put(w, ATOMIC_PARENT_FD, NONE)
    put(w, ATOMIC_ERROR, 0)
    put(w, 68000, 0)
    put(w, 68008, 0)
    store(w, source + size, 10)
    copy(w, PATH, REGISTRY, get(w, 64))
    copy(w, TEMP_PATH, REGISTRY, get(w, 64))
    if record_file == 1:
        terminated(w, text_record(w, PATH + get(w, 64)))
        at = text_record_tmp(w, TEMP_PATH + get(w, 64))
    else:
        terminated(w, text_spec(w, PATH + get(w, 64)))
        at = text_spec_tmp(w, TEMP_PATH + get(w, 64))
    terminated(w, decimal(w, at, get(w, PID)))
    return call(o, w, 1400, 257, NEG100, TEMP_PATH, 524481, 384, 0, 0, 12)

def atomic_write(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1400:
        if result == NEG4:
            return call(o, w, 1400, 257, NEG100, TEMP_PATH, 524481, 384, 0, 0, 12)
        if failed(result):
            put(w, 68000, result)
            return atomic_failure(w)
        put(w, ATOMIC_FD, result)
        return atomic_bytes(o, w)
    if phase == 1401:
        if result == NEG4:
            return atomic_bytes(o, w)
        if result == 0 or failed(result) or result > get(w, ATOMIC_SIZE) - get(w, ATOMIC_USED):
            return atomic_cleanup(o, w)
        put(w, ATOMIC_USED, get(w, ATOMIC_USED) + result)
        if get(w, ATOMIC_USED) < get(w, ATOMIC_SIZE):
            return atomic_bytes(o, w)
        return call(o, w, 1402, 74, get(w, ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 1402:
        if result == NEG4:
            return call(o, w, 1402, 74, get(w, ATOMIC_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return atomic_cleanup(o, w)
        return call(o, w, 1403, 264, NEG100, TEMP_PATH, NEG100, PATH, 0, 0, 204)
    if phase == 1403:
        if result != 0:
            return atomic_cleanup(o, w)
        return call(o, w, 1404, 257, NEG100, REGISTRY, 524288, 0, 0, 0, 12)
    if phase == 1404:
        if result == NEG4:
            return call(o, w, 1404, 257, NEG100, REGISTRY, 524288, 0, 0, 0, 12)
        if failed(result):
            return atomic_cleanup(o, w)
        put(w, ATOMIC_PARENT_FD, result)
        return call(o, w, 1405, 74, result, 0, 0, 0, 0, 0, 0)
    if phase == 1405:
        if result == NEG4:
            return call(o, w, 1405, 74, get(w, ATOMIC_PARENT_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return atomic_cleanup(o, w)
        return call(o, w, 1406, 3, get(w, ATOMIC_PARENT_FD), 0, 0, 0, 0, 0, 0)
    if phase == 1406:
        put(w, ATOMIC_PARENT_FD, NONE)
        return call(o, w, 1407, 3, get(w, ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 1407:
        put(w, ATOMIC_FD, NONE)
        put(w, ATOMIC_FAILURE_NEXT, 0)
        put(w, 0, get(w, ATOMIC_NEXT))
        return 8
    if phase == 1410:
        if get(w, ATOMIC_PARENT_FD) != NONE:
            return call(o, w, 1412, 3, get(w, ATOMIC_PARENT_FD), 0, 0, 0, 0, 0, 0)
        return call(o, w, 1411, 3, get(w, ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 1412:
        put(w, ATOMIC_PARENT_FD, NONE)
        return call(o, w, 1411, 3, get(w, ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 1411:
        put(w, ATOMIC_FD, NONE)
        return atomic_failure(w)
    return 0

def atomic_failure(w:mutbuf) -> u32:
    put(w, ATOMIC_ERROR, 1)
    next = get(w, ATOMIC_FAILURE_NEXT)
    put(w, ATOMIC_FAILURE_NEXT, 0)
    if next == 0:
        if get(w, 68008) == 1:
            return diagnostic(w, FILE_RAW, text_write_zero(w, FILE_RAW) - FILE_RAW)
        return diagnostic_errno(w, get(w, 68000))
    put(w, 0, next)
    return 8

def atomic_bytes(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1401, 1, get(w, ATOMIC_FD), get(w, ATOMIC_DATA) + get(w, ATOMIC_USED), get(w, ATOMIC_SIZE) - get(w, ATOMIC_USED), 0, 0, 0, 12)

def atomic_cleanup(o:mutbuf, w:mutbuf) -> u32:
    put(w, 68000, get(w, 8))
    zero = get(w, 0) == 1401 and get(w, 8) == 0
    put(w, 68008, choose(zero, 1, 0))
    return call(o, w, 1410, 263, NEG100, TEMP_PATH, 0, 0, 0, 0, 12)

def equal(w:mutbuf, left:u64, left_size:u64, right:u64, right_size:u64) -> u64:
    if left_size != right_size or left > length(w) or left_size > length(w) - left:
        return 0
    index = 0
    while index < left_size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1

def milliseconds(w:mutbuf) -> u64:
    seconds = get(w, STAT)
    nanos = get(w, STAT + 8)
    low = 0
    high = 0
    if seconds >> 63 == 0:
        upper = (seconds >> 32) * 1000
        bottom = (seconds & 4294967295) * 1000 + nanos // 1000000
        low = (upper << 32) + bottom
        high = (upper >> 32) + choose(low < bottom, 1, 0)
    at = decimal128(w, TIMESTAMP, low, high)
    field(w, 7, TIMESTAMP, at - TIMESTAMP)
    return 0

def decimal128(w:mutbuf, at:u64, low:u64, high:u64) -> u64:
    count = 0
    while high != 0 or low >= 10:
        a = high >> 32
        b = high & 4294967295
        c = low >> 32
        d = low & 4294967295
        q1 = a // 10
        value = ((a % 10) << 32) | b
        q2 = value // 10
        value = ((value % 10) << 32) | c
        q3 = value // 10
        value = ((value % 10) << 32) | d
        q4 = value // 10
        store(w, 3000 + count, 48 + value % 10)
        count = count + 1
        high = (q1 << 32) | q2
        low = (q3 << 32) | q4
    store(w, at, 48 + low)
    at = at + 1
    while count != 0:
        count = count - 1
        store(w, at, byte(w, 3000 + count))
        at = at + 1
    return at

def kernel_text(w:mutbuf, source:u64, size:u64) -> u64:
    index = 0
    first = NONE
    stop = 0
    while index < size:
        start = index
        point = byte(w, source + index)
        index = index + 1
        width = 0
        minimum = 0
        if point >= 194 and point <= 223:
            point = point & 31
            width = 1
            minimum = 128
        elif point >= 224 and point <= 239:
            point = point & 15
            width = 2
            minimum = 2048
        elif point >= 240 and point <= 244:
            point = point & 7
            width = 3
            minimum = 65536
        elif point >= 128:
            return 0
        if width > size - index:
            return 0
        while width != 0:
            next = byte(w, source + index)
            if next < 128 or next > 191:
                return 0
            point = (point << 6) | (next & 63)
            width = width - 1
            index = index + 1
        if point < minimum or point > 1114111 or (point >= 55296 and point <= 57343):
            return 0
        whitespace = (point >= 9 and point <= 13) or point == 32 or point == 133 or point == 160 or point == 5760 or (point >= 8192 and point <= 8202) or point == 8232 or point == 8233 or point == 8239 or point == 8287 or point == 12288
        if whitespace == False:
            if first == NONE:
                first = start
            stop = index
    if first == NONE:
        first = 0
    put(w, SCAN_NEXT, source + first)
    put(w, SCAN_SIZE, stop - first)
    return 1
'''

def source_program():
    source=POLICY+"\n"+DIAGNOSTICS+"\n"+TYPED_ERRORS
    available={}
    for body in [request_source(),control.source_program(),record.source_program()]:
        available.update({n.name:ast.get_source_segment(body,n) for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)})
    for name in ['call','begin_file','copy','terminated','decimal','get','getn','put','putn','failed','quote','hexadecimal','present','node']:
        if name not in available:
            raise ValueError(name)
        source+='\n'+available[name]+'\n'
    for name,value in TEXT.items():
        raw=value.encode();source+=f'\ndef text_{name}(w:mutbuf, at:u64) -> u64:\n'
        for i in range(0,len(raw),8):
            chunk=raw[i:i+8];source+=f'    putn(w, at + {i}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
        source+=f'    return at + {len(raw)}\n'
    source+=record.texts('command_text',COMMAND_VALUES)
    for key in sorted(CONSTANTS,key=len,reverse=True):
        source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source

def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    doc=document(source_program(),'system_jobctl_start');path=ROOT/'examples/hia_bootstrap/system_jobctl_start.hepta';text=render_assembly(doc)
    if args.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks']) for f in doc['functions']),'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
