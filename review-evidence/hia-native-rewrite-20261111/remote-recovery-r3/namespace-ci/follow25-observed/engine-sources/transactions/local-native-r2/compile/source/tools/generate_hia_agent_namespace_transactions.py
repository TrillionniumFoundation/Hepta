"""Complete namespace transaction sequencing, newly reconstructed revision 3.

All 31 retained row operations share this owner. Physical/value/log peers are
separate native composition work; this module never installs a hosted fallback.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_store import VALUES, catalog
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIANTX03', 'little')

TRANSACTIONS = r'''
def namespace_transactions(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        return 4294967293
    if get(w, 8) == 3:
        return emit(o, w, 4294967293)
    if length(o) < 256:
        return poison(w, 1)
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            poison(w, 2)
            return emit(o, w, 4294967293)
        return issue(o, w, 11, 1, get(w, 288), 0, 0, 0, 0, 0)
    if valid_state(w) == 0 or frame(s, w) == 0:
        poison(w, 3)
        return emit(o, w, 4294967293)
    if read64(s, 8) == 7:
        if acknowledge(s, w) == 0:
            poison(w, 4)
            return emit(o, w, 4294967293)
        if get(w, 248) == 2:
            poison(w, 5)
            return emit(o, w, 4294967293)
        if get(w, 248) == 1:
            return peer_error(o, w)
        return drive(o, w)
    return command(s, o, w)

def initialize(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 160 or read64(s, 0) != TX_MAGIC or read64(s, 8) != 1:
        return 0
    if (read64(s, 16) == 0 and read64(s, 24) == 0) or read64(s, 32) != 1 or read64(s, 64) == 0:
        return 0
    at = 40
    while at < 160:
        if at != 64 and read64(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < 512:
        if byte(w, at) != 0:
            return 0
        at = at + 1
    put(w, 0, TX_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, 1)
    put(w, 64, 1)
    put(w, 288, read64(s, 64))
    return 1

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != TX_MAGIC or get(w, 8) < 1 or get(w, 8) > 2:
        return 0
    if (get(w, 16) == 0 and get(w, 24) == 0) or get(w, 32) == 0:
        return 0
    if get(w, 48) > 13 or get(w, 128) > 3 or get(w, 184) > 3 or get(w, 208) > 1:
        return 0
    if get(w, 224) != 0 and get(w, 224) != 2:
        return 0
    if get(w, 8) == 2 and (get(w, 88) != 0 or get(w, 96) != 0 or get(w, 104) != 0 or get(w, 112) != 0 or get(w, 128) != 0):
        return 0
    if get(w, 48) == 0 and get(w, 56) != 0:
        return 0
    if get(w, 48) != 0 and get(w, 56) == 0:
        return 0
    if get(w, 48) != 0 and pending_state(w) == 0:
        return 0
    if get(w, 48) == 0:
        if get(w, 8) == 1 and get(w, 88) == 0:
            return 0
        if get(w, 128) > 1:
            return 0
        if get(w, 128) == 0:
            if get(w, 96) != 0 or get(w, 104) != 0 or get(w, 112) != 0 or get(w, 120) != 0 or get(w, 200) != 0 or get(w, 208) != 0:
                return 0
        elif live_transaction(w) == 0 or get(w, 200) != 0:
            return 0
    if get(w, 304) != 0 or get(w, 312) != 0:
        return 0
    at = 448
    while at < 512:
        if get(w, at) != 0:
            return 0
        at = at + 8
    return 1

def live_transaction(w:mutbuf) -> u64:
    if get(w, 128) != 1 and get(w, 128) != 2:
        return 0
    if get(w, 96) == 0 or get(w, 104) == 0 or get(w, 112) == 0 or get(w, 120) == 0:
        return 0
    return 1

def pending_state(w:mutbuf) -> u64:
    phase = get(w, 56)
    action = get(w, 48)
    if phase_action(phase) != action:
        return 0
    if phase == 11:
        return choose(get(w, 64) == 1 and get(w, 32) == 1 and get(w, 88) == 0 and get(w, 128) == 0 and get(w, 288) != 0, 1, 0)
    if get(w, 88) == 0 or get(w, 8) != 1:
        return 0
    if phase == 21:
        return choose((get(w, 128) == 1 or get(w, 128) == 2) and get(w, 96) == 0 and get(w, 104) == 0 and get(w, 112) == 0 and get(w, 120) == 0, 1, 0)
    if phase == 31:
        if get(w, 104) != 0 or get(w, 112) != 0 or get(w, 120) != 0:
            return 0
        if get(w, 128) == 3:
            return choose(get(w, 96) == 0 and get(w, 64) == 3 and operation_write(get(w, 72)) == 0, 1, 0)
        return choose((get(w, 128) == 1 or get(w, 128) == 2) and get(w, 96) != 0, 1, 0)
    if phase == 41:
        return choose((get(w, 128) == 1 or get(w, 128) == 2) and get(w, 96) != 0 and get(w, 104) != 0 and get(w, 192) != 0 and get(w, 112) == 0 and get(w, 120) == 0, 1, 0)
    if phase == 51:
        if get(w, 64) != 3 or get(w, 72) < 1 or get(w, 72) > 31 or get(w, 80) == 0 or get(w, 216) != get(w, 32):
            return 0
        if get(w, 128) == 3:
            return choose(operation_write(get(w, 72)) == 0 and get(w, 104) != 0 and get(w, 96) == 0 and get(w, 112) == 0 and get(w, 120) == 0, 1, 0)
        return live_transaction(w)
    if phase == 61 or phase == 71 or phase == 81 or phase == 91:
        if live_transaction(w) == 0 or get(w, 208) != 1:
            return 0
        if get(w, 64) != 4 and (get(w, 64) != 3 or get(w, 128) != 2):
            return 0
        if phase == 61:
            return choose(get(w, 200) == 0 and get(w, 184) == 0, 1, 0)
        if get(w, 200) == 0:
            return 0
        return choose(get(w, 184) == choose(phase == 91, 2, 1), 1, 0)
    return pending_retirement(w)

def pending_retirement(w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase == 101:
        return choose(live_transaction(w) == 1 and get(w, 184) < 2, 1, 0)
    if phase == 111:
        if get(w, 384) == 2:
            return choose(get(w, 128) == 3 and get(w, 240) == 2 and get(w, 104) != 0 and get(w, 96) == 0 and get(w, 112) == 0 and get(w, 200) == 0, 1, 0)
        return choose(get(w, 384) == 3 and get(w, 240) == 3 and get(w, 184) != 2, 1, 0)
    if phase == 121:
        return choose(get(w, 128) == 0 and get(w, 96) != 0 and get(w, 104) == 0 and get(w, 112) == 0 and get(w, 120) == 0 and get(w, 200) == 0 and get(w, 208) == 0, 1, 0)
    if phase == 131:
        return choose(get(w, 64) == 6 and get(w, 128) == 0 and get(w, 96) == 0 and get(w, 104) == 0 and get(w, 112) == 0, 1, 0)
    if phase == 141:
        return choose(get(w, 384) == 1 and get(w, 64) == 4 and get(w, 128) == 1 and live_transaction(w) == 1 and get(w, 200) != 0 and get(w, 184) == 1 and get(w, 224) == 2 and (get(w, 160) & 255) == 5, 1, 0)
    return 0

def phase_action(phase:u64) -> u64:
    if phase == 11:
        return 1
    if phase == 21:
        return 2
    if phase == 31:
        return 3
    if phase == 41:
        return 4
    if phase == 51:
        return 5
    if phase == 61:
        return 6
    if phase == 71:
        return 7
    if phase == 81:
        return 8
    if phase == 91:
        return 9
    if phase == 101:
        return 13
    if phase == 111 or phase == 141:
        return 10
    if phase == 121:
        return 11
    if phase == 131:
        return 12
    return 0

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 160 or read64(s, 0) != TX_MAGIC:
        return 0
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        return 0
    at = 128
    while at < 160:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def acknowledge(s:readbuf, w:mutbuf) -> u64:
    if get(w, 48) == 0 or read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40) or read64(s, 48) != get(w, 48):
        return 0
    if read64(s, 56) > 2:
        return 0
    put(w, 248, read64(s, 56))
    at = 0
    while at < 64:
        put(w, 320 + at, read64(s, 64 + at))
        at = at + 8
    put(w, 296, get(w, 48))
    put(w, 48, 0)
    return 1

def command(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    cmd = read64(s, 8)
    if get(w, 48) != 0 or get(w, 56) != 0 or get(w, 32) == 18446744073709551615:
        return invalid(o, w, 6)
    if cmd < 2 or cmd > 6 or read64(s, 32) != get(w, 32) + 1:
        return invalid(o, w, 6)
    if read64(s, 40) != 0 or read64(s, 48) != 0 or read64(s, 56) != 0:
        return invalid(o, w, 6)
    at = choose(cmd == 3, 80, 64)
    while at < 128:
        if read64(s, at) != 0:
            return invalid(o, w, 6)
        at = at + 8
    if cmd == 3:
        if read64(s, 64) < 1 or read64(s, 64) > 31 or read64(s, 72) == 0:
            return invalid(o, w, 6)
    put(w, 32, read64(s, 32))
    put(w, 64, cmd)
    put(w, 72, choose(cmd == 3, read64(s, 64), 0))
    put(w, 80, choose(cmd == 3, read64(s, 72), 0))
    put(w, 136, 0)
    put(w, 144, 0)
    put(w, 152, 0)
    put(w, 160, 0)
    put(w, 168, 0)
    put(w, 184, 0)
    put(w, 216, get(w, 32))
    put(w, 224, 0)
    put(w, 240, 0)
    put(w, 248, 0)
    put(w, 256, 0)
    put(w, 264, 0)
    put(w, 272, get(w, 128))
    put(w, 280, choose(cmd == 6, 1, 0))
    if get(w, 8) == 2:
        if cmd != 6:
            error(w, 0, 4)
        return finish(o, w)
    if cmd == 2:
        if get(w, 128) != 0:
            error(w, 1, 1)
            return finish(o, w)
        put(w, 128, 1)
        return lock(o, w)
    if cmd == 3:
        if get(w, 128) == 1:
            return rows(o, w)
        if get(w, 128) != 0:
            return invalid(o, w, 7)
        if operation_write(get(w, 72)) == 0:
            put(w, 128, 3)
            return snapshot(o, w)
        put(w, 128, 2)
        return lock(o, w)
    if cmd == 4 or cmd == 5:
        if get(w, 128) == 0:
            error(w, 1, choose(cmd == 4, 2, 3))
            return finish(o, w)
        if get(w, 128) != 1:
            return invalid(o, w, 7)
        if cmd == 4 and get(w, 208) != 0:
            return commit(o, w)
        return cleanup(o, w)
    if get(w, 128) == 1:
        return cleanup(o, w)
    if get(w, 128) != 0:
        return invalid(o, w, 7)
    return issue(o, w, 131, 12, get(w, 88), 0, 0, 0, 0, 0)

def lock(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 88) == 0 or get(w, 96) != 0 or get(w, 104) != 0 or get(w, 112) != 0:
        return invalid(o, w, 8)
    return issue(o, w, 21, 2, get(w, 88), 10000000000, 0, 0, 0, 0)

def snapshot(o:mutbuf, w:mutbuf) -> u64:
    return issue(o, w, 31, 3, get(w, 88), get(w, 96), get(w, 32), 0, 0, 0)

def rows(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 104) == 0 or get(w, 72) < 1 or get(w, 72) > 31:
        return invalid(o, w, 9)
    view = choose(get(w, 112) != 0, get(w, 112), get(w, 104))
    return issue(o, w, 51, 5, get(w, 72), get(w, 80), view, get(w, 216), get(w, 104), get(w, 112))

def commit(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 96) == 0 or get(w, 104) == 0 or get(w, 112) == 0 or get(w, 120) == 0 or get(w, 200) != 0:
        return invalid(o, w, 10)
    return issue(o, w, 61, 6, get(w, 112), get(w, 104), get(w, 96), get(w, 120), 0, 0)

def drive(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase < 60:
        return acquired(o, w)
    if phase < 100:
        return committing(o, w)
    return retiring(o, w)

def acquired(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase == 11:
        if handle(w) == 0:
            return invalid(o, w, 11)
        put(w, 88, get(w, 320))
        put(w, 288, 0)
        return finish(o, w)
    if phase == 21:
        if handle(w) == 0:
            return invalid(o, w, 11)
        put(w, 96, get(w, 320))
        return snapshot(o, w)
    if phase == 31:
        if get(w, 320) == 0 or get(w, 328) == 0 or zeros(w, 2) == 0:
            return invalid(o, w, 11)
        put(w, 104, get(w, 320))
        put(w, 192, get(w, 328))
        if get(w, 128) == 3:
            return rows(o, w)
        return issue(o, w, 41, 4, get(w, 104), get(w, 96), get(w, 32), 0, 0, 0)
    if phase == 41:
        if handle(w) == 0:
            return invalid(o, w, 11)
        put(w, 112, get(w, 320))
        put(w, 120, get(w, 32))
        if get(w, 64) == 2:
            return finish(o, w)
        return rows(o, w)
    if phase == 51:
        if get(w, 320) == 0 or zeros(w, 3) == 0 or get(w, 328) > get(w, 336):
            return invalid(o, w, 11)
        if operation_write(get(w, 72)) == 0 and get(w, 328) != 0:
            return invalid(o, w, 11)
        put(w, 136, get(w, 320))
        put(w, 144, get(w, 328))
        put(w, 152, get(w, 336))
        if get(w, 328) != 0:
            put(w, 208, 1)
        if get(w, 128) == 1:
            return finish(o, w)
        if get(w, 128) == 3:
            return retire_read(o, w)
        if get(w, 128) != 2:
            return invalid(o, w, 7)
        if get(w, 208) == 0:
            return cleanup(o, w)
        return commit(o, w)
    return invalid(o, w, 12)

def committing(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, 56)
    if phase == 61:
        if handle(w) == 0:
            return invalid(o, w, 11)
        put(w, 200, get(w, 320))
        put(w, 184, 1)
        return issue(o, w, 71, 7, get(w, 200), 0, 0, 0, 0, 0)
    if phase == 71:
        if zeros(w, 0) == 0:
            return invalid(o, w, 11)
        return issue(o, w, 81, 8, get(w, 200), get(w, 104), get(w, 96), 0, 0, 0)
    if phase == 81:
        if handle(w) == 0:
            return invalid(o, w, 11)
        put(w, 192, get(w, 320))
        put(w, 184, 2)
        return issue(o, w, 91, 9, get(w, 192), get(w, 88), 0, 0, 0, 0)
    if phase == 91:
        if zeros(w, 0) == 0:
            return invalid(o, w, 11)
        put(w, 184, 3)
        return retire_transaction(o, w)
    return invalid(o, w, 12)

def cleanup(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 112) != 0 and get(w, 184) != 3:
        return issue(o, w, 101, 13, get(w, 112), get(w, 104), get(w, 96), get(w, 120), 0, 0)
    return retire_transaction(o, w)

def retire_transaction(o:mutbuf, w:mutbuf) -> u64:
    put(w, 240, 3)
    return issue(o, w, 111, 10, 3, get(w, 104), get(w, 112), get(w, 200), get(w, 136), get(w, 120))

def retire_read(o:mutbuf, w:mutbuf) -> u64:
    put(w, 240, 2)
    return issue(o, w, 111, 10, 2, get(w, 104), 0, 0, get(w, 136), get(w, 32))

def retiring(o:mutbuf, w:mutbuf) -> u64:
    if zeros(w, 0) == 0:
        return invalid(o, w, 11)
    phase = get(w, 56)
    if phase == 101:
        return retire_transaction(o, w)
    if phase == 111:
        put(w, 104, 0)
        put(w, 112, 0)
        put(w, 120, 0)
        put(w, 192, 0)
        put(w, 200, 0)
        put(w, 208, 0)
        put(w, 128, 0)
        if get(w, 96) != 0:
            return issue(o, w, 121, 11, get(w, 96), 0, 0, 0, 0, 0)
        return after_unlock(o, w)
    if phase == 121:
        put(w, 96, 0)
        return after_unlock(o, w)
    if phase == 131:
        put(w, 88, 0)
        put(w, 8, 2)
        return finish(o, w)
    if phase == 141:
        put(w, 200, 0)
        put(w, 184, 0)
        return finish(o, w)
    return invalid(o, w, 12)

def after_unlock(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 280) != 0:
        return issue(o, w, 131, 12, get(w, 88), 0, 0, 0, 0, 0)
    return finish(o, w)

def peer_error(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, 56)
    code = get(w, 320)
    if code == 0 or code > 4294967295 or (code & 255) == 0 or (code & 255) == 100 or (code & 255) == 101:
        return invalid(o, w, 13)
    if zeros(w, choose(phase == 51, 3, 2)) == 0:
        return invalid(o, w, 13)
    error(w, code, get(w, 328))
    if phase == 11:
        put(w, 288, 0)
        put(w, 8, 2)
        return finish(o, w)
    if phase == 21:
        put(w, 128, 0)
        return finish(o, w)
    if phase == 31 or phase == 41:
        return cleanup(o, w)
    if phase == 51:
        put(w, 136, get(w, 336))
        if get(w, 136) == 0:
            return invalid(o, w, 13)
        if get(w, 128) == 3:
            return retire_read(o, w)
        if get(w, 128) == 1 and abort_transaction(get(w, 72), code) == 0:
            return finish(o, w)
        return cleanup(o, w)
    if phase == 61 or phase == 71 or phase == 81:
        put(w, 136, 0)
        put(w, 144, 0)
        put(w, 152, 0)
        if (code & 255) == 5 and get(w, 64) == 4 and get(w, 128) == 1:
            if get(w, 200) == 0:
                return finish(o, w)
            return issue(o, w, 141, 10, 1, get(w, 104), get(w, 112), get(w, 200), 0, get(w, 120))
        return cleanup(o, w)
    return invalid(o, w, 14)

def abort_transaction(operation:u64, code:u64) -> u64:
    primary = code & 255
    if primary == 7 or primary == 10 or primary == 13:
        return 1
    if primary == 9 and operation_write(operation) != 0:
        return 1
    return 0

def error(w:mutbuf, code:u64, detail:u64) -> u64:
    if get(w, 224) == 0:
        put(w, 160, code)
        put(w, 168, detail)
        put(w, 224, 2)
        put(w, 264, get(w, 56))
    return 0

def finish(o:mutbuf, w:mutbuf) -> u64:
    put(w, 48, 0)
    put(w, 56, 0)
    at = 384
    while at < 448:
        put(w, at, 0)
        at = at + 8
    return emit(o, w, get(w, 224))

def zeros(w:mutbuf, start:u64) -> u64:
    at = start
    while at < 8:
        if get(w, 320 + at * 8) != 0:
            return 0
        at = at + 1
    return 1

def handle(w:mutbuf) -> u64:
    if get(w, 320) == 0 or zeros(w, 1) == 0:
        return 0
    return get(w, 320)

def issue(o:mutbuf, w:mutbuf, phase:u64, action:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u64:
    if get(w, 40) == 18446744073709551615 or get(w, 48) != 0:
        return invalid(o, w, 15)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, action)
    put(w, 56, phase)
    put(w, 248, 0)
    put(w, 384, a)
    put(w, 392, b)
    put(w, 400, c)
    put(w, 408, d)
    put(w, 416, e)
    put(w, 424, f)
    put(w, 432, 0)
    put(w, 440, 0)
    return emit(o, w, 1)

def poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 8) != 3:
        put(w, 8, 3)
        put(w, 176, reason)
    return 4294967293

def invalid(o:mutbuf, w:mutbuf, reason:u64) -> u64:
    poison(w, reason)
    return emit(o, w, 4294967293)

def emit(o:mutbuf, w:mutbuf, status:u64) -> u64:
    if length(o) < 256:
        return 4294967293
    at = 0
    while at < 256:
        put(o, at, 0)
        at = at + 8
    put(o, 0, TX_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 64))
    put(o, 56, get(w, 72))
    put(o, 64, get(w, 48))
    at = 0
    while at < 48:
        put(o, 72 + at, get(w, 384 + at))
        at = at + 8
    put(o, 120, get(w, 136))
    put(o, 128, get(w, 144))
    put(o, 136, get(w, 152))
    put(o, 144, get(w, 160))
    put(o, 152, get(w, 168))
    put(o, 160, get(w, 128))
    put(o, 168, get(w, 120))
    put(o, 176, get(w, 104))
    put(o, 184, get(w, 112))
    put(o, 192, get(w, 8))
    put(o, 200, get(w, 184))
    put(o, 208, get(w, 176))
    put(o, 216, get(w, 56))
    put(o, 224, get(w, 88))
    put(o, 232, get(w, 96))
    put(o, 240, get(w, 200))
    return status
'''


def source_program():
    rows = catalog()['relational_operations']
    result = TRANSACTIONS.replace('TX_MAGIC', str(MAGIC))
    result += VALUES[VALUES.index('\ndef read64('):]
    result += '\ndef operation_write(operation:u64) -> u64:\n'
    writes = [row['id'] for row in rows if row['kind'] != 'SELECT']
    mask = sum(1 << value for value in writes)
    result += f'    if operation < 1 or operation > 31:\n        return 0\n    return ({mask} >> operation) & 1\n'
    return result


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace transaction HIA symbol')
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'agent_namespace_transactions', 'functions': functions})


def main():
    path = ROOT / 'examples/hia_bootstrap/agent_namespace_transactions.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
