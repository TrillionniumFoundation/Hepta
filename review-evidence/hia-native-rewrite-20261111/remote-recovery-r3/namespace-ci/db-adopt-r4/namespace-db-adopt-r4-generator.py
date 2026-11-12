"""NEW HIA main-database inode owner, completed-FSTAT adoption revision r4.

This is the full Linux non-timeout POSIX unixLock/posixUnlock/CheckReserved/
unixClose state machine for one actually issued database inode context.
It is distinct from the existing eight WAL-byte lock registry and DMS128 owner.
A future fixed coordinator must own the shared FS session and real reply leases.
Command9 consumes the first matching deferred descriptor, exactly as the
post-stat inode-local portion of findReusableFd. The private coordinator still
owns global inode lookup, real stat and locks. This new revision is reconstructed
from the published r2; no identity or counts are inherited from inaccessible drafts.
A consumed descriptor whose earlier unlock failed leaves a non-owning accounting
witness, preserving the original inode counters until the inode is released.
New private command10 adopts one complete, already completed actual FS FSTAT
receipt issued by the fixed global-inode parent. It does not issue a second stat.
All original commands1..9 remain supported; command10 is not an external authority.
The full 912-byte adoption packet is retained through GROW and compared on retry.
This is new authoring source with zero AST/generation/VM/B3/native execution.
No ordinary Store, SQLite migration or physical global-inode closure is claimed.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANDB01","little")
BAD=int.from_bytes(b"HIADBB01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
DBLOCKS=r'''

def db_node(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1536:
        if length(w) >= 8:
            put(w, 0, DB_BAD)
        return 4294967293
    if get(w, 0) == DB_BAD:
        return db_emit(o, w, 4294967293, 0, 0, 0)
    if length(o) < 256:
        return db_reject(o, w, 1)
    if length(s) < 256 or read64(s, 0) != DB_MAGIC or read64(s, 128) != length(s) - 256:
        return db_reject(o, w, 2)
    at = 136
    while at < 256:
        if read64(s, at) != 0:
            return db_reject(o, w, 3)
        at = at + 8
    command = read64(s, 8)
    if get(w, 0) == 0:
        at = 0
        while at < 1536:
            if get(w, at) != 0:
                return db_reject(o, w, 4)
            at = at + 8
        if command != 1 or length(s) != 256 or (read64(s, 16) | read64(s, 24)) == 0:
            return db_reject(o, w, 5)
        if (read64(s, 80) | read64(s, 88)) == 0:
            return db_reject(o, w, 5)
        at = 32
        while at < 80:
            if read64(s, at) != 0:
                return db_reject(o, w, 5)
            at = at + 8
        if (read64(s, 112) | read64(s, 120)) != 0:
            return db_reject(o, w, 5)
        put(w, 0, DB_MAGIC)
        put(w, 8, 1)
        put(w, 16, read64(s, 16))
        put(w, 24, read64(s, 24))
        put(w, 48, 1)
        put(w, 128, read64(s, 80))
        put(w, 136, read64(s, 88))
        put(w, 144, read64(s, 96))
        put(w, 152, read64(s, 104))
        return db_emit(o, w, 0, 0, 0, 0)
    if db_steady(w) == 0:
        return db_reject(o, w, 6)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
        return db_reject(o, w, 7)
    phase = get(w, 8)
    if phase == 4:
        return db_reject(o, w, 8)
    if phase == 2:
        if command != 7 and command != 8:
            return db_reject(o, w, 9)
        if db_ack_shape(s, w) == 0:
            return db_reject(o, w, 10)
        if command == 8:
            if length(s) != 256:
                return db_reject(o, w, 10)
            return db_reject(o, w, 11)
        return db_peer(s, o, w)
    if phase == 6:
        if command != 10 or length(s) != 912:
            return db_reject(o, w, 38)
        at = 0
        while at < 912:
            if read64(s, at) != get(w, 512 + at):
                return db_reject(o, w, 38)
            at = at + 8
        if db_adopt_valid(s, w) == 0:
            return db_reject(o, w, 39)
        return db_adopt_prepare(s, o, w)
    if phase == 3:
        if length(s) != 256:
            return db_reject(o, w, 12)
        at = 0
        while at < 256:
            if read64(s, at) != get(w, 512 + at):
                return db_reject(o, w, 12)
            at = at + 8
        return db_register_prepare(o, w)
    if (command < 2 or command > 6) and command != 9 and command != 10:
        return db_reject(o, w, 13)
    if command == 10:
        if length(s) != 912:
            return db_reject(o, w, 13)
    elif length(s) != 256:
        return db_reject(o, w, 13)
    if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
        return db_reject(o, w, 14)
    if read64(s, 120) == 0 or (read64(s, 40) | read64(s, 56)) != 0:
        return db_reject(o, w, 15)
    at = 80
    while at < 120:
        if read64(s, at) != 0:
            return db_reject(o, w, 15)
        at = at + 8
    row = 0
    if command == 2 or command == 10:
        if read64(s, 48) != 0 or read64(s, 64) == 0 or read64(s, 72) > 3:
            return db_reject(o, w, 16)
        if get(w, 48) == 18446744073709551615:
            return db_reject(o, w, 16)
        if db_token_exists(w, read64(s, 64)) != 0:
            return db_reject(o, w, 16)
        if command == 10 and db_adopt_valid(s, w) == 0:
            return db_reject(o, w, 39)
    elif command == 9:
        if read64(s, 48) != 0 or read64(s, 64) > 4294967295 or read64(s, 72) != 0:
            return db_reject(o, w, 37)
    else:
        row = db_find(w, read64(s, 48))
        if row == 0 or get(w, row + 16) != 1 or read64(s, 72) != 0:
            return db_reject(o, w, 17)
        target = read64(s, 64)
        if command == 3:
            if target != 1 and target != 2 and target != 4:
                return db_reject(o, w, 18)
            old = get(w, row + 24)
            if old < target:
                if old == 0 and target != 1:
                    return db_reject(o, w, 18)
                if target == 2 and old != 1:
                    return db_reject(o, w, 18)
        elif command == 4:
            if target > 1:
                return db_reject(o, w, 18)
        elif target != 0:
            return db_reject(o, w, 18)
        if command == 5 and get(w, row + 24) > 1:
            return db_reject(o, w, 18)
    if command == 10:
        copy_input(w, s, 512, 0, 912)
    else:
        copy_input(w, s, 512, 0, 256)
    put(w, 32, read64(s, 32))
    put(w, 40, 0)
    put(w, 160, read64(s, 120))
    put(w, 168, command)
    put(w, 176, read64(s, 48))
    put(w, 184, row)
    put(w, 240, 0)
    put(w, 248, 0)
    put(w, 256, 0)
    put(w, 280, read64(s, 64))
    put(w, 288, read64(s, 72))
    if command == 2:
        return db_register_prepare(o, w)
    if command == 10:
        put(w, 200, read64(s, 64))
        return db_adopt_prepare(s, o, w)
    if command == 9:
        return db_take_unused(o, w)
    if command == 3:
        put(w, 232, 10)
    elif command == 4:
        put(w, 232, 20)
    elif command == 5:
        put(w, 232, 50)
    else:
        put(w, 280, 0)
        put(w, 232, 20)
    return db_drive(o, w)

def db_zero(w:mutbuf, at:u64, count:u64) -> u64:
    end = at + count
    while at < end:
        put(w, at, 0)
        at = at + 8
    return 0

def db_slot(w:mutbuf, row:u64) -> u64:
    if row < 1536 or row >= 1536 + get(w, 56) * 128 or ((row - 1536) & 127) != 0:
        return 0
    return 1

def db_find(w:mutbuf, handle:u64) -> u64:
    if handle == 0:
        return 0
    at = 1536
    end = 1536 + get(w, 56) * 128
    while at < end:
        if get(w, at + 16) != 0 and get(w, at) == handle:
            return at
        at = at + 128
    return 0

def db_token_exists(w:mutbuf, token:u64) -> u64:
    at = 1536
    end = 1536 + get(w, 56) * 128
    while at < end:
        if get(w, at + 16) != 0 and get(w, at + 8) == token:
            return 1
        at = at + 128
    return 0

def db_steady(w:mutbuf) -> u64:
    if get(w, 0) != DB_MAGIC:
        return 0
    if (get(w, 8) < 1 or get(w, 8) > 4) and get(w, 8) != 6:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or (get(w, 128) | get(w, 136)) == 0:
        return 0
    if get(w, 48) == 0 or get(w, 56) > 144115188075855859:
        return 0
    if 1536 + get(w, 56) * 128 > length(w):
        return 0
    if get(w, 88) > 4 or get(w, 96) > 1 or get(w, 120) > 1:
        return 0
    if get(w, 64) > get(w, 56) or get(w, 72) > get(w, 56) or get(w, 80) > get(w, 56) + 1:
        return 0
    expected_locks = get(w, 72) + get(w, 96)
    if get(w, 8) == 2 and get(w, 232) == 24:
        expected_locks = expected_locks + 1
    if get(w, 80) != expected_locks:
        return 0
    at = 384
    while at < 512:
        if get(w, at) != 0:
            return 0
        at = at + 8
    at = 768
    if get(w, 8) == 6:
        at = 1424
    while at < 1536:
        if get(w, at) != 0:
            return 0
        at = at + 8
    count = 0
    deferred = 0
    locked = 0
    maximum = 0
    at = 1536
    end = 1536 + get(w, 56) * 128
    while at < end:
        state = get(w, at + 16)
        if state > 3:
            return 0
        if state == 0:
            p = at
            while p < at + 128:
                if get(w, p) != 0:
                    return 0
                p = p + 8
        else:
            if get(w, at) == 0 or get(w, at) >= get(w, 48):
                return 0
            if state == 3:
                if get(w, at + 8) != 0 or get(w, at + 24) == 0 or get(w, at + 56) != 0:
                    return 0
                if get(w, at + 64) == 0 or get(w, at + 64) > get(w, 264):
                    return 0
            elif get(w, at + 8) == 0:
                return 0
            if get(w, at + 24) > 4 or get(w, at + 32) > 1 or get(w, at + 40) > 1:
                return 0
            if get(w, at + 48) > 4095 or get(w, at + 72) > 4294967295:
                return 0
            if get(w, at + 80) > 4294967295:
                return 0
            if state == 1:
                if get(w, at + 56) != 0 or get(w, at + 64) != 0:
                    return 0
                count = count + 1
            elif state == 2:
                deferred = deferred + 1
                if get(w, at + 64) == 0 or get(w, at + 64) > get(w, 264):
                    return 0
                following = get(w, at + 56)
                if following != 0:
                    if db_slot(w, following) == 0 or get(w, following + 16) != 2:
                        return 0
                    if get(w, following + 64) >= get(w, at + 64):
                        return 0
            if get(w, at + 24) != 0:
                locked = locked + 1
                if get(w, at + 24) > maximum:
                    maximum = get(w, at + 24)
            p = at + 88
            while p < at + 128:
                if get(w, p) != 0:
                    return 0
                p = p + 8
            other = 1536
            while other < at:
                if get(w, other + 16) != 0:
                    if get(w, other) == get(w, at):
                        return 0
                    if get(w, at + 8) != 0 and get(w, other + 8) == get(w, at + 8):
                        return 0
                other = other + 128
        at = at + 128
    if count != get(w, 64):
        return 0
    if get(w, 272) != 0:
        if db_slot(w, get(w, 272)) == 0 or get(w, get(w, 272) + 16) != 2:
            return 0
    cursor = get(w, 272)
    walked = 0
    while cursor != 0:
        if walked >= deferred or db_slot(w, cursor) == 0 or get(w, cursor + 16) != 2:
            return 0
        cursor = get(w, cursor + 56)
        walked = walked + 1
    if walked != deferred:
        return 0
    phase = get(w, 8)
    if phase == 1 or phase == 4:
        if locked != get(w, 72) or maximum != get(w, 88):
            return 0
        at = 160
        while at < 264:
            if get(w, at) != 0:
                return 0
            at = at + 8
        at = 280
        while at < 384:
            if get(w, at) != 0:
                return 0
            at = at + 8
        at = 512
        while at < 768:
            if get(w, at) != 0:
                return 0
            at = at + 8
        if phase == 4 and (get(w, 64) | get(w, 72) | get(w, 80) | get(w, 272)) != 0:
            return 0
    else:
        if get(w, 32) == 0 or get(w, 160) == 0 or get(w, 512) != DB_MAGIC:
            return 0
        if get(w, 528) != get(w, 16) or get(w, 536) != get(w, 24) or get(w, 544) != get(w, 32):
            return 0
        if get(w, 632) != get(w, 160) or get(w, 520) != get(w, 168) or get(w, 560) != get(w, 176):
            return 0
        if phase == 3:
            if get(w, 168) != 2 or get(w, 192) != 0 or get(w, 296) < 1536:
                return 0
        elif phase == 6:
            if get(w, 168) != 10 or get(w, 192) != 0:
                return 0
            if get(w, 56) > 144115188075855843 or get(w, 640) != 656:
                return 0
            if get(w, 40) != 0 or get(w, 296) != 1536 + (get(w, 56) + 16) * 128:
                return 0
            if get(w, 200) == 0 or get(w, 200) != get(w, 576):
                return 0
            if locked != get(w, 72) or maximum != get(w, 88):
                return 0
        elif db_pending_valid(w) == 0:
            return 0
    return 1

def db_pending_valid(w:mutbuf) -> u64:
    op = get(w, 192)
    stage = get(w, 232)
    if get(w, 40) == 0 or get(w, 200) == 0 or get(w, 296) != 0:
        return 0
    if op == 15:
        if stage != 2 or get(w, 168) != 2 or get(w, 200) != get(w, 576):
            return 0
        if db_slot(w, get(w, 184)) == 0 or get(w, get(w, 184) + 16) != 0:
            return 0
        if (get(w, 208) | get(w, 216) | get(w, 224)) != 0:
            return 0
    elif op == 8:
        if stage != 32 and stage != 41:
            return 0
        if stage == 32 and get(w, 168) != 6:
            return 0
        if stage == 41:
            if get(w, 168) != 4 and get(w, 168) != 6:
                return 0
            if get(w, 352) != 27 and get(w, 352) != 33:
                return 0
            if get(w, 352) == 33 and (get(w, 168) != 6 or get(w, 64) != 0):
                return 0
        if db_token_exists(w, get(w, 200)) != 0:
            return 0
        if (get(w, 208) | get(w, 216) | get(w, 224)) != 0:
            return 0
    elif op == 17 or op == 23:
        row = get(w, 184)
        if db_slot(w, row) == 0 or get(w, row + 16) != 1:
            return 0
        if get(w, row) != get(w, 176) or get(w, row + 8) != get(w, 200):
            return 0
        if op == 23:
            if stage != 51 or get(w, 168) != 5 or get(w, 208) != 1 or get(w, 216) != 1073741825 or get(w, 224) != 1:
                return 0
        elif stage == 11:
            if get(w, 168) != 3 or get(w, 208) != 0 or get(w, 216) != 1073741824 or get(w, 224) != 1:
                return 0
        elif stage == 12 or stage == 21:
            if get(w, 280) != 1:
                return 0
            if stage == 12 and get(w, 168) != 3:
                return 0
            if stage == 21 and get(w, 168) != 4:
                return 0
            if get(w, 208) != 0 or get(w, 216) != 1073741826 or get(w, 224) != 510:
                return 0
        elif stage == 13:
            if get(w, 168) != 3 or get(w, 208) != 2 or get(w, 216) != 1073741824 or get(w, 224) != 1:
                return 0
        elif stage == 15:
            if get(w, 168) != 3 or get(w, 280) != 4 or get(w, 208) != 1 or get(w, 216) != 1073741824 or get(w, 224) != 1:
                return 0
        elif stage == 17:
            if get(w, 168) != 3 or get(w, 208) != 1:
                return 0
            if get(w, 280) == 2:
                if get(w, 216) != 1073741825 or get(w, 224) != 1:
                    return 0
            elif get(w, 280) != 4 or get(w, 216) != 1073741826 or get(w, 224) != 510:
                return 0
        elif stage == 22:
            if get(w, 168) != 4 and get(w, 168) != 6:
                return 0
            if get(w, 208) != 2 or get(w, 216) != 1073741824 or get(w, 224) != 2:
                return 0
        elif stage == 24:
            if (get(w, 168) != 4 and get(w, 168) != 6) or get(w, 280) != 0:
                return 0
            if get(w, 208) != 2 or (get(w, 216) | get(w, 224)) != 0:
                return 0
        elif stage == 90:
            if get(w, row + 32) != 0 or get(w, row + 40) != 1 or get(w, 96) != 0:
                return 0
            if get(w, 208) != 1 or get(w, 216) != 1073741826 or get(w, 224) != 510:
                return 0
            continuation = get(w, 336)
            if continuation != 11 and continuation != 12 and continuation != 13 and continuation != 15 and continuation != 17 and continuation != 21 and continuation != 22 and continuation != 24:
                return 0
        else:
            return 0
    else:
        return 0
    return 1

def db_register_prepare(o:mutbuf, w:mutbuf) -> u32:
    row = 1536
    end = 1536 + get(w, 56) * 128
    while row < end and get(w, row + 16) != 0:
        row = row + 128
    if row == end:
        cap = get(w, 56)
        if cap > 144115188075855843:
            return db_reject(o, w, 19)
        required = 1536 + (cap + 16) * 128
        if length(w) < required:
            put(w, 8, 3)
            put(w, 296, required)
            return db_emit(o, w, 2, 0, 0, 0)
        db_zero(w, end, 2048)
        put(w, 56, cap + 16)
    put(w, 184, row)
    put(w, 296, 0)
    return db_issue(o, w, 15, get(w, 576), 0, 0, 0, 2)

def db_issue(o:mutbuf, w:mutbuf, op:u64, token:u64, kind:u64, start:u64, count:u64, stage:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or token == 0:
        return db_reject(o, w, 20)
    put(w, 40, get(w, 40) + 1)
    put(w, 192, op)
    put(w, 200, token)
    put(w, 208, kind)
    put(w, 216, start)
    put(w, 224, count)
    put(w, 232, stage)
    put(w, 8, 2)
    return db_emit(o, w, 1, 0, 0, 0)

def db_system_lock(o:mutbuf, w:mutbuf, kind:u64, start:u64, count:u64, stage:u64) -> u32:
    row = get(w, 184)
    if get(w, row + 32) == 0 and get(w, row + 40) == 1:
        if get(w, 96) == 0:
            put(w, 336, stage)
            return db_issue(o, w, 17, get(w, row + 8), 1, 1073741826, 510, 90)
        put(w, 320, 0)
        put(w, 232, stage)
        return 3
    return db_issue(o, w, 17, get(w, row + 8), kind, start, count, stage)

def db_errno(error:u64) -> u64:
    if error == 13 or error == 11 or error == 110 or error == 16 or error == 4 or error == 37:
        return 5
    if error == 1:
        return 3
    return 3850

def db_lock_error(o:mutbuf, w:mutbuf, error:u64) -> u32:
    code = db_errno(error)
    if code != 5:
        put(w, get(w, 184) + 48, error)
    return db_finish(o, w, code, error, get(w, 176))

def db_lock_step(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 184)
    stage = get(w, 232)
    target = get(w, 280)
    error = get(w, 320)
    if stage == 10:
        old = get(w, row + 24)
        group = get(w, 88)
        if old >= target:
            return db_finish(o, w, 0, 0, get(w, row))
        if old != group and (group >= 3 or target > 1):
            return db_finish(o, w, 5, 0, get(w, row))
        if target == 1 and (group == 1 or group == 2):
            put(w, row + 24, 1)
            put(w, 72, get(w, 72) + 1)
            put(w, 80, get(w, 80) + 1)
            return db_finish(o, w, 0, 0, get(w, row))
        if target == 1:
            return db_system_lock(o, w, 0, 1073741824, 1, 11)
        if target == 4 and old == 2:
            return db_system_lock(o, w, 1, 1073741824, 1, 15)
        put(w, 232, 16)
        return 3
    if stage == 11:
        if error != 0:
            return db_lock_error(o, w, error)
        return db_system_lock(o, w, 0, 1073741826, 510, 12)
    if stage == 12:
        if error != 0:
            put(w, 240, db_errno(error))
            put(w, 248, error)
        return db_system_lock(o, w, 2, 1073741824, 1, 13)
    if stage == 13:
        code = get(w, 240)
        saved_error = get(w, 248)
        if code == 0 and error != 0:
            code = 2058
            saved_error = error
        if code != 0:
            if code != 5:
                put(w, row + 48, saved_error)
            return db_finish(o, w, code, saved_error, get(w, row))
        put(w, row + 24, 1)
        put(w, 72, 1)
        put(w, 80, get(w, 80) + 1)
        put(w, 88, 1)
        return db_finish(o, w, 0, 0, get(w, row))
    if stage == 15:
        if error != 0:
            return db_lock_error(o, w, error)
        put(w, row + 24, 3)
        put(w, 88, 3)
        put(w, 232, 16)
        return 3
    if stage == 16:
        if target == 4 and get(w, 72) > 1:
            return db_finish(o, w, 5, 0, get(w, row))
        if target == 2:
            return db_system_lock(o, w, 1, 1073741825, 1, 17)
        return db_system_lock(o, w, 1, 1073741826, 510, 17)
    if stage == 17:
        if error != 0:
            return db_lock_error(o, w, error)
        put(w, row + 24, target)
        put(w, 88, target)
        return db_finish(o, w, 0, 0, get(w, row))
    return db_reject(o, w, 22)

def db_unlock_end(o:mutbuf, w:mutbuf, code:u64, error:u64) -> u32:
    if get(w, 168) == 6:
        put(w, 240, 0)
        put(w, 248, 0)
        put(w, 232, 30)
        return 3
    return db_finish(o, w, code, error, get(w, 176))

def db_unlock_step(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 184)
    stage = get(w, 232)
    target = get(w, 280)
    error = get(w, 320)
    if stage == 20:
        if get(w, row + 24) <= target:
            return db_unlock_end(o, w, 0, 0)
        if get(w, 72) == 0:
            return db_reject(o, w, 23)
        if get(w, row + 24) > 1:
            if get(w, 88) != get(w, row + 24):
                return db_reject(o, w, 23)
            if target == 1:
                return db_system_lock(o, w, 0, 1073741826, 510, 21)
            return db_system_lock(o, w, 2, 1073741824, 2, 22)
        put(w, 232, 23)
        return 3
    if stage == 21:
        if error != 0:
            put(w, row + 48, error)
            return db_unlock_end(o, w, 2314, error)
        return db_system_lock(o, w, 2, 1073741824, 2, 22)
    if stage == 22:
        if error != 0:
            put(w, row + 48, error)
            return db_unlock_end(o, w, 2058, error)
        put(w, 88, 1)
        put(w, 232, 23)
        return 3
    if stage == 23:
        if target == 1:
            put(w, row + 24, 1)
            return db_unlock_end(o, w, 0, 0)
        if get(w, 72) == 0:
            return db_reject(o, w, 24)
        put(w, 72, get(w, 72) - 1)
        if get(w, 72) == 0:
            return db_system_lock(o, w, 2, 0, 0, 24)
        put(w, 232, 25)
        return 3
    if stage == 24:
        put(w, 88, 0)
        if error != 0:
            put(w, row + 48, error)
            put(w, row + 24, 0)
            put(w, 240, 2058)
            put(w, 248, error)
        put(w, 232, 25)
        return 3
    if stage == 25:
        if get(w, 80) == 0:
            return db_reject(o, w, 25)
        put(w, 80, get(w, 80) - 1)
        if get(w, 80) == 0:
            put(w, 352, 27)
            put(w, 232, 40)
        else:
            put(w, 232, 27)
        return 3
    if stage == 27:
        code = get(w, 240)
        error = get(w, 248)
        if code == 0:
            put(w, row + 24, target)
        return db_unlock_end(o, w, code, error)
    return db_reject(o, w, 26)

def db_close_step(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 184)
    stage = get(w, 232)
    if stage == 30:
        if get(w, 64) == 0 or get(w, row + 16) != 1:
            return db_reject(o, w, 27)
        token = get(w, row + 8)
        put(w, 64, get(w, 64) - 1)
        if get(w, 80) != 0:
            if get(w, 264) == 18446744073709551615:
                return db_reject(o, w, 28)
            put(w, 264, get(w, 264) + 1)
            put(w, row + 16, 2)
            put(w, row + 56, get(w, 272))
            put(w, row + 64, get(w, 264))
            put(w, 272, row)
            if get(w, 64) == 0:
                put(w, 352, 33)
                put(w, 232, 40)
                return 3
            return db_finish(o, w, 0, 0, get(w, 176))
        db_zero(w, row, 128)
        return db_issue(o, w, 8, token, 0, 0, 0, 32)
    if stage == 32:
        error = get(w, 320)
        if error != 0 and get(w, 256) == 0:
            put(w, 256, error)
        if get(w, 64) == 0:
            put(w, 232, 33)
            return 3
        return db_finish(o, w, 0, 0, get(w, 176))
    if stage == 33:
        if get(w, 272) != 0 or get(w, 64) != 0:
            return db_reject(o, w, 29)
        retired = 1536
        retired_end = 1536 + get(w, 56) * 128
        while retired < retired_end:
            if get(w, retired + 16) == 3:
                db_zero(w, retired, 128)
            retired = retired + 128
        put(w, 72, 0)
        put(w, 80, 0)
        put(w, 88, 0)
        put(w, 96, 0)
        put(w, 8, 4)
        return db_finish(o, w, 0, 0, get(w, 176))
    return db_reject(o, w, 30)

def db_drain_step(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 232) == 41:
        error = get(w, 320)
        if error != 0 and get(w, 256) == 0:
            put(w, 256, error)
        put(w, 232, 40)
    row = get(w, 272)
    if row == 0:
        following = get(w, 352)
        if following != 27 and following != 33:
            return db_reject(o, w, 31)
        put(w, 352, 0)
        put(w, 232, following)
        return 3
    if db_slot(w, row) == 0 or get(w, row + 16) != 2:
        return db_reject(o, w, 32)
    token = get(w, row + 8)
    put(w, 272, get(w, row + 56))
    db_zero(w, row, 128)
    return db_issue(o, w, 8, token, 0, 0, 0, 41)

def db_reserved_step(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 232) == 50:
        if get(w, 88) > 1:
            return db_finish(o, w, 0, 0, 1)
        if get(w, 96) != 0:
            return db_finish(o, w, 0, 0, 0)
        return db_issue(o, w, 23, get(w, get(w, 184) + 8), 1, 1073741825, 1, 51)
    if get(w, 232) == 51:
        error = get(w, 320)
        if error != 0:
            put(w, get(w, 184) + 48, error)
            return db_finish(o, w, 3594, error, 0)
        if get(w, 344) != 2:
            return db_finish(o, w, 0, 0, 1)
        return db_finish(o, w, 0, 0, 0)
    return db_reject(o, w, 33)

def db_status_u64(code:u32) -> u64:
    # The loop phi is u64, like its sentinel literal. Keep every step's
    # existing u32 result and widen only at this internal scalar boundary.
    return code

def db_drive(o:mutbuf, w:mutbuf) -> u32:
    result = 3
    while result == 3:
        stage = get(w, 232)
        if stage == 90:
            error = get(w, 320)
            if error == 0:
                put(w, 96, 1)
                put(w, 80, get(w, 80) + 1)
            put(w, 232, get(w, 336))
            put(w, 336, 0)
        elif stage >= 10 and stage < 20:
            result = db_status_u64(db_lock_step(o, w))
        elif stage >= 20 and stage < 30:
            result = db_status_u64(db_unlock_step(o, w))
        elif stage >= 30 and stage < 40:
            result = db_status_u64(db_close_step(o, w))
        elif stage == 40 or stage == 41:
            result = db_status_u64(db_drain_step(o, w))
        elif stage == 50 or stage == 51:
            result = db_status_u64(db_reserved_step(o, w))
        else:
            result = db_status_u64(db_reject(o, w, 34))
    return result

def db_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 32) != get(w, 32) or read64(s, 40) != get(w, 40):
        return 0
    if read64(s, 48) != get(w, 176) or read64(s, 56) != get(w, 192) or read64(s, 120) != get(w, 160):
        return 0
    at = 64
    while at < 120:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def db_peer_valid(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 768:
        return 0
    if read64(s, 256) != FS_MAGIC or read64(s, 264) != 2:
        return 0
    if read64(s, 272) != get(w, 128) or read64(s, 280) != get(w, 136):
        return 0
    call = read64(s, 288)
    if call <= get(w, 144) or read64(s, 296) != 0:
        return 0
    if read64(s, 304) != get(w, 192) or read64(s, 312) != 0 or read64(s, 320) != get(w, 200):
        return 0
    if read64(s, 328) != get(w, 208) or read64(s, 336) != get(w, 216) or read64(s, 344) != get(w, 224):
        return 0
    if read64(s, 352) != 0 or read64(s, 360) != get(w, 40):
        return 0
    at = 368
    while at < 512:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if read64(s, 512) != FS_MAGIC or read64(s, 520) != 0:
        return 0
    if read64(s, 528) != get(w, 128) or read64(s, 536) != get(w, 136) or read64(s, 544) != call:
        return 0
    if read64(s, 552) <= get(w, 152) or read64(s, 560) != get(w, 192):
        return 0
    if read64(s, 568) > 4095 or read64(s, 624) != get(w, 40):
        return 0
    if read64(s, 632) != 1 or read64(s, 688) != 3 or read64(s, 696) != 0:
        return 0
    if (read64(s, 648) | read64(s, 656) | read64(s, 664)) != 0 or read64(s, 680) == 0:
        return 0
    at = 712
    while at < 768:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    n = read64(s, 640)
    if n > length(s) - 768:
        return 0
    op = get(w, 192)
    error = read64(s, 568)
    if op == 15 and error == 0:
        if n != 144 or length(s) < 912:
            return 0
        if read64(s, 576) != read64(s, 768) or read64(s, 584) != read64(s, 776):
            return 0
        if read64(s, 592) != (read64(s, 792) & 4294967295):
            return 0
        if read64(s, 600) != (read64(s, 792) >> 32):
            return 0
        if read64(s, 608) != (read64(s, 800) & 4294967295):
            return 0
        if read64(s, 616) != read64(s, 816) or read64(s, 704) != read64(s, 784):
            return 0
    elif op == 23 and error == 0:
        if n != 32 or length(s) < 800 or read64(s, 704) != 0:
            return 0
        if read64(s, 576) != (read64(s, 768) & 65535) or read64(s, 576) > 2:
            return 0
        if read64(s, 584) != ((read64(s, 768) >> 16) & 65535):
            return 0
        if read64(s, 592) != read64(s, 776) or read64(s, 600) != read64(s, 784):
            return 0
        if read64(s, 608) != (read64(s, 792) & 4294967295) or read64(s, 616) != 0:
            return 0
    else:
        if n != 0 or read64(s, 704) != 0:
            return 0
        at = 576
        while at < 624:
            if read64(s, at) != 0:
                return 0
            at = at + 8
    return 1

def db_peer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if db_peer_valid(s, w) == 0:
        return db_reject(o, w, 35)
    put(w, 144, read64(s, 288))
    put(w, 152, read64(s, 552))
    put(w, 320, read64(s, 568))
    put(w, 344, 0)
    op = get(w, 192)
    put(w, 192, 0)
    put(w, 8, 1)
    if op == 15:
        if read64(s, 568) != 0:
            return db_finish(o, w, 10, read64(s, 568), 0)
        dev = read64(s, 576)
        ino = read64(s, 584)
        if get(w, 120) != 0:
            if dev != get(w, 104) or ino != get(w, 112):
                return db_reject(o, w, 36)
        else:
            put(w, 104, dev)
            put(w, 112, ino)
            put(w, 120, 1)
        row = get(w, 184)
        handle = get(w, 48)
        put(w, row, handle)
        put(w, row + 8, get(w, 200))
        put(w, row + 16, 1)
        put(w, row + 32, get(w, 288) & 1)
        put(w, row + 40, (get(w, 288) >> 1) & 1)
        put(w, row + 72, read64(s, 592))
        put(w, row + 80, read64(s, 600))
        put(w, 48, handle + 1)
        put(w, 64, get(w, 64) + 1)
        return db_finish(o, w, 0, 0, handle)
    if op == 23 and read64(s, 568) == 0:
        put(w, 344, read64(s, 576))
    return db_drive(o, w)

def db_finish(o:mutbuf, w:mutbuf, code:u64, error:u64, result:u64) -> u32:
    if get(w, 8) != 4:
        put(w, 8, 1)
    db_emit(o, w, 0, code, error, result)
    saved_source_bytes = 256
    if get(w, 168) == 10:
        saved_source_bytes = 912
    db_zero(w, 160, 104)
    db_zero(w, 280, 104)
    db_zero(w, 512, saved_source_bytes)
    return 0

def db_reject(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != DB_BAD:
        put(w, 376, reason)
    put(w, 0, DB_BAD)
    put(w, 8, 5)
    return db_emit(o, w, 4294967293, 0, 0, 0)

def db_emit(o:mutbuf, w:mutbuf, status:u64, code:u64, error:u64, result:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    db_zero(o, 0, 256)
    put(o, 0, DB_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 176))
    put(o, 56, get(w, 192))
    put(o, 64, code)
    put(o, 72, error)
    put(o, 80, result)
    put(o, 88, get(w, 160))
    put(o, 96, get(w, 64))
    put(o, 104, get(w, 72))
    put(o, 112, get(w, 80))
    put(o, 120, get(w, 88))
    put(o, 128, get(w, 200))
    put(o, 136, get(w, 208))
    put(o, 144, get(w, 216))
    put(o, 152, get(w, 224))
    put(o, 160, get(w, 256))
    put(o, 168, get(w, 296))
    put(o, 176, 1)
    put(o, 184, get(w, 376))
    put(o, 192, get(w, 8))
    put(o, 200, get(w, 96))
    put(o, 208, get(w, 232))
    put(o, 216, get(w, 104))
    put(o, 224, get(w, 112))
    return status

def db_take_unused(o:mutbuf, w:mutbuf) -> u32:
    # The global inode-list and original stat selection have already occurred
    # in the same fixed coordinator context. This function does no syscall.
    wanted = get(w, 280) & 3
    previous = 0
    row = get(w, 272)
    while row != 0:
        flags = 2 - get(w, row + 32)
        if flags == wanted:
            following = get(w, row + 56)
            if previous == 0:
                put(w, 272, following)
            else:
                put(w, previous + 56, following)
            token = get(w, row + 8)
            if get(w, row + 24) == 0:
                db_zero(w, row, 128)
            else:
                # Original posixUnlock may have failed before decrementing
                # nShared/nLock. Reuse changes only pUnused, not those counters.
                # Keep a token-free witness; it cannot authorize any descriptor.
                put(w, row + 8, 0)
                put(w, row + 16, 3)
                put(w, row + 56, 0)
            return db_finish(o, w, 0, 0, token)
        previous = row
        row = get(w, row + 56)
    return db_finish(o, w, 0, 0, 0)

def db_adopt_valid(s:readbuf, w:mutbuf) -> u64:
    # This is the same actual FS result admitted by a fixed native parent.
    # Frame correlation is not external authentication or a new syscall.
    if length(s) != 912 or read64(s, 128) != 656:
        return 0
    if read64(s, 256) != FS_MAGIC or read64(s, 264) != 2:
        return 0
    if read64(s, 272) != get(w, 128) or read64(s, 280) != get(w, 136):
        return 0
    call = read64(s, 288)
    if call <= get(w, 144) or read64(s, 296) != 0:
        return 0
    if read64(s, 304) != 15 or read64(s, 312) != 0:
        return 0
    if read64(s, 320) != read64(s, 64) or read64(s, 320) == 0:
        return 0
    if (read64(s, 328) | read64(s, 336) | read64(s, 344) | read64(s, 352)) != 0:
        return 0
    action = read64(s, 360)
    if action == 0:
        return 0
    at = 368
    while at < 512:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if read64(s, 512) != FS_MAGIC or read64(s, 520) != 0:
        return 0
    if read64(s, 528) != get(w, 128) or read64(s, 536) != get(w, 136):
        return 0
    if read64(s, 544) != call or read64(s, 552) <= get(w, 152):
        return 0
    if read64(s, 560) != 15 or read64(s, 568) != 0:
        return 0
    if read64(s, 624) != action or read64(s, 632) != 1 or read64(s, 640) != 144:
        return 0
    if (read64(s, 648) | read64(s, 656) | read64(s, 664)) != 0:
        return 0
    if read64(s, 680) == 0 or read64(s, 688) != 3 or read64(s, 696) != 0:
        return 0
    at = 712
    while at < 768:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if read64(s, 576) != read64(s, 768) or read64(s, 584) != read64(s, 776):
        return 0
    if read64(s, 592) != (read64(s, 792) & 4294967295):
        return 0
    if read64(s, 600) != (read64(s, 792) >> 32):
        return 0
    if read64(s, 608) != (read64(s, 800) & 4294967295):
        return 0
    if read64(s, 616) != read64(s, 816) or read64(s, 704) != read64(s, 784):
        return 0
    if get(w, 120) != 0:
        if read64(s, 576) != get(w, 104) or read64(s, 584) != get(w, 112):
            return 0
    return 1

def db_adopt_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    row = 1536
    end = 1536 + get(w, 56) * 128
    while row < end and get(w, row + 16) != 0:
        row = row + 128
    if row == end:
        cap = get(w, 56)
        if cap > 144115188075855843:
            return db_reject(o, w, 19)
        required = 1536 + (cap + 16) * 128
        if length(w) < required:
            put(w, 8, 6)
            put(w, 296, required)
            return db_emit(o, w, 2, 0, 0, 0)
        db_zero(w, end, 2048)
        put(w, 56, cap + 16)
    put(w, 184, row)
    put(w, 296, 0)
    put(w, 144, read64(s, 288))
    put(w, 152, read64(s, 552))
    if get(w, 120) == 0:
        put(w, 104, read64(s, 576))
        put(w, 112, read64(s, 584))
        put(w, 120, 1)
    handle = get(w, 48)
    put(w, row, handle)
    put(w, row + 8, read64(s, 64))
    put(w, row + 16, 1)
    put(w, row + 32, read64(s, 72) & 1)
    put(w, row + 40, (read64(s, 72) >> 1) & 1)
    put(w, row + 72, read64(s, 592))
    put(w, row + 80, read64(s, 600))
    put(w, 48, handle + 1)
    put(w, 64, get(w, 64) + 1)
    return db_finish(o, w, 0, 0, handle)


'''
def source_program():
    source=DBLOCKS
    for name,value in (("DB_MAGIC",MAGIC),("DB_BAD",BAD),("FS_MAGIC",FS_MAGIC)):
        source=source.replace(name,str(value))
    return source+VALUES[VALUES.index("\ndef read64("):]
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate DB-node function")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=ObjectBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns],"effects":["read","write","trap"],"entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_db_node_adopt_r4","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_db_node_adopt_r4.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
