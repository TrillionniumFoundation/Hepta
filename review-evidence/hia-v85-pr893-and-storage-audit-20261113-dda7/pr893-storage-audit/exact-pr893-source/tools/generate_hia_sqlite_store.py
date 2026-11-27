"""Author the closed HIA SQLite store protocol and its transaction decisions.

This is development-time authoring. The emitted HIA owns statement bytes,
bindings, transaction boundaries and release decisions. The assembly transport
never maps a business action to SQL. No ordinary Core effect inventory changes.
"""
from __future__ import annotations
import ast
from copy import deepcopy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_agent_journal import ENTRY as JOURNAL_ENTRY

REQUEST_MAGIC = int.from_bytes(b"HIASQRQ1", "little")
EVENT_MAGIC = int.from_bytes(b"HIASQEV1", "little")
EFFECT_MAGIC = int.from_bytes(b"HIASQFX1", "little")
STATE_MAGIC = int.from_bytes(b"HIASQST1", "little")
JOURNAL_MAGIC = int.from_bytes(b"HIAJRN02", "little")
FILE_MAGIC = int.from_bytes(b"HIASAF01", "little")
# SQLite supplies a storage engine. Every application statement is HIA data.
STATEMENTS = {
    1: "BEGIN IMMEDIATE",
    2: "COMMIT",
    3: "ROLLBACK",
    4: "SELECT id,slot,generation,artifact,active FROM leases WHERE id=?",
    5: "UPDATE leases SET active=0 WHERE id=?",
    6: "PRAGMA journal_mode=WAL",
    7: "PRAGMA synchronous=FULL",
    8: "PRAGMA journal_mode",
    9: "SELECT name FROM sqlite_master LIMIT 1",
    10: "CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,uri TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,metadata TEXT NOT NULL,content_key TEXT UNIQUE NOT NULL)",
    11: "CREATE TABLE IF NOT EXISTS profiles (id TEXT NOT NULL,sha256 TEXT NOT NULL,artifact TEXT NOT NULL,PRIMARY KEY(id,sha256))",
    12: "CREATE TABLE IF NOT EXISTS contexts (id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,artifact TEXT NOT NULL,created_ns TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0)",
    13: "CREATE TABLE IF NOT EXISTS requests (key TEXT PRIMARY KEY,digest TEXT NOT NULL,tool TEXT NOT NULL,state TEXT NOT NULL,response TEXT,started_ns TEXT NOT NULL)",
    14: "CREATE TABLE IF NOT EXISTS costs (sequence INTEGER PRIMARY KEY AUTOINCREMENT,context_id TEXT,tool TEXT NOT NULL,request_id TEXT NOT NULL,wall_ns TEXT NOT NULL,status TEXT NOT NULL,details TEXT NOT NULL)",
    15: "CREATE TABLE IF NOT EXISTS cursors (id TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,sha256 TEXT NOT NULL,offset INTEGER NOT NULL)",
    16: "CREATE TABLE IF NOT EXISTS slots (name TEXT PRIMARY KEY,context_id TEXT NOT NULL,generation TEXT NOT NULL,epoch TEXT NOT NULL,abi_sha256 TEXT NOT NULL)",
    17: "CREATE TABLE IF NOT EXISTS versions (slot TEXT NOT NULL,generation TEXT NOT NULL,artifact TEXT NOT NULL,PRIMARY KEY(slot,generation))",
    18: "CREATE TABLE IF NOT EXISTS leases (id TEXT PRIMARY KEY,slot TEXT NOT NULL,generation TEXT NOT NULL,artifact TEXT NOT NULL,active INTEGER NOT NULL)",
    19: "CREATE TABLE IF NOT EXISTS execution_budgets (context_id TEXT PRIMARY KEY,used_native_ns TEXT NOT NULL,owner TEXT)",
}
# Effects: 0 response, 1 open, 2 close, 3 busy_timeout, 4 prepare, 5 bind,
# 6 step, 7 column snapshot, 8 finalize, 9 get_autocommit,
# 10 the fixed HIA canonical-JSON component, 11 lstat, 12 orderly exit.
# SQLite pointers never occur in these words: role/index/generation are tokens.
SOURCE = r'''
def store_driver(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 2048 or length(o) < 256 or length(s) < 128:
        return 4294967293
    if valid_packet(s) == 0:
        return 4294967295
    magic = read_word(s, 0)
    if magic == REQUEST_MAGIC:
        if valid_request(s) == 0:
            return 4294967295
        return request(s, o, w)
    if magic != EVENT_MAGIC or get(w, 0) != STATE_MAGIC:
        return 4294967295
    if read_word(s, 8) != get(w, 16) or read_word(s, 16) != get(w, 8):
        return 4294967295
    if event_resources(s, w) == 0:
        return 4294967295
    if get(w, 24) == 100:
        return sql_event(s, o, w)
    return event(s, o, w)

def request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    operation = read_word(s, 8)
    if get(w, 0) == 0:
        if operation != 0 or read_word(s, 104) != 1:
            return 4294967295
        size = read_word(s, 128)
        start = 136
        if size == 0 or size > length(w) - 1024:
            return 4294967293
        fill_range(w, 0, 1024, 0)
        put(w, 0, STATE_MAGIC)
        put(w, 264, 1)
        if byte(s, start) != 47:
            return response(o, w, 4, 0, 0)
        i = 0
        parent = 0
        while i < size:
            if byte(s, start + i) == 0:
                return response(o, w, 4, 0, 0)
            if byte(s, start + i) == 47:
                parent = i
            i = i + 1
        if parent == 0:
            parent = 1
        put(w, 352, parent)
        put(w, 128, size)
        copy_source(s, w, start, 1024, size)
        put(w, 136, 1024 + size)
        put(w, 24, 70)
        return path_effect(o, w, 11, 0, 3)
    if get(w, 0) != STATE_MAGIC or get(w, 24) != 0:
        return 4294967295
    if operation == 2:
        return close_owned(o, w)
    if operation != 1 and operation != 3 and operation != 4 and operation != 5 and operation != 6:
        return response(o, w, 1, 0, 0)
    if get(w, 264) != 0 or get(w, 328) != 1:
        return response(o, w, 6, 0, 0)
    base = get(w, 136)
    if length(s) > length(w) - base:
        return 4294967293
    copy_source(s, w, 0, base, length(s))
    put(w, 144, length(s))
    put(w, 152, base + length(s))
    put(w, 160, base + length(s))
    fill_range(w, 512, 120, 0)
    put(w, 104, 0)
    put(w, 240, 0)
    put(w, 312, 0)
    put(w, 120, 0)
    put(w, 344, 0)
    put(w, 24, 60)
    return path_effect(o, w, 11, 0, 0)

def close_owned(o:mutbuf, w:mutbuf) -> u32:
    # Only an explicit valid close request reaches this cleanup path.
    # Malformed component/events still publish no new SQL authority.
    if get(w, 432) != 0:
        put(w, 24, 54)
        return fd_effect(o, w, 24, 65, 0, 0, 0)
    if get(w, 56) != 0:
        put(w, 24, 52)
        return effect(o, w, 8, 3, 0, 0, 0)
    if get(w, 120) == 1:
        return sql_start(o, w, 3, 1, 53)
    # State 2 is the original uncertain-COMMIT fence. Do not issue a
    # compensating SQL statement or label its outcome committed/rolled back.
    if get(w, 72) != 0:
        put(w, 24, 50)
        return effect(o, w, 2, 2, 0, 0, 0)
    if get(w, 64) != 0:
        put(w, 24, 51)
        return effect(o, w, 2, 1, 0, 0, 0)
    return effect(o, w, 12, 0, 0, 0, 0)

def event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 24)
    rc = read_word(s, 24)
    if phase == 54:
        put(w, 432, 0)
        if read_word(s, 128) != 0:
            return 4294967295
        return close_owned(o, w)
    if phase == 70:
        if rc != 0 or private_directory(s) == 0:
            return response(o, w, 4, 0, 0)
        put(w, 24, 1)
        return path_effect(o, w, 11, 0, 0)
    if phase == 1:
        if rc != 0 or private_file(s) == 0:
            return response(o, w, 4, 0, 0)
        put(w, 216, read_word(s, 80))
        put(w, 224, read_word(s, 88))
        put(w, 232, read_word(s, 56))
        put(w, 24, 2)
        return path_effect(o, w, 1, 1, 2)
    if phase == 2 or phase == 8:
        if rc != 0 or read_word(s, 48) == 0:
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        role = 1
        if phase == 8:
            role = 2
        put(w, 56 + role * 8, read_word(s, 48))
        put(w, 24, phase + 1)
        return effect(o, w, 3, role, 10000, 0, 0)
    if phase == 3:
        if rc != 0:
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        put(w, 248, 0)
        return sql_start(o, w, 6, 1, 4)
    if phase == 5 or phase == 6 or phase == 7 or phase == 12 or phase == 13 or phase == 14 or phase == 60 or phase == 61 or phase == 62:
        if rc != 0 or private_file(s) == 0:
            return response(o, w, 4, 0, 0)
        if phase == 5 or phase == 12 or phase == 60:
            if read_word(s, 80) != get(w, 216) or read_word(s, 88) != get(w, 224):
                return response(o, w, 4, 0, 0)
        if phase == 5:
            put(w, 24, 6)
            return path_effect(o, w, 11, 0, 1)
        if phase == 6:
            put(w, 272, read_word(s, 80))
            put(w, 280, read_word(s, 88))
            put(w, 24, 7)
            return path_effect(o, w, 11, 0, 2)
        if phase == 7:
            put(w, 288, read_word(s, 80))
            put(w, 296, read_word(s, 88))
            put(w, 24, 8)
            return path_effect(o, w, 1, 2, 2)
        if phase == 12 or phase == 60:
            put(w, 24, phase + 1)
            return path_effect(o, w, 11, 0, 1)
        if phase == 13 or phase == 61:
            if read_word(s, 80) != get(w, 272) or read_word(s, 88) != get(w, 280):
                put(w, 264, 1)
                return response(o, w, 4, 0, 0)
            put(w, 24, phase + 1)
            return path_effect(o, w, 11, 0, 2)
        if read_word(s, 80) != get(w, 288) or read_word(s, 88) != get(w, 296):
            put(w, 264, 1)
            return response(o, w, 4, 0, 0)
        if phase == 62:
            put(w, 24, 63)
            return effect(o, w, 9, 1, 0, 0, 0)
        put(w, 328, 1)
        put(w, 264, 0)
        return response(o, w, 0, 0, 0)
    if phase == 63 or phase == 64:
        if rc != 0 or read_word(s, 64) != 1:
            put(w, 264, 1)
            return response(o, w, 6, 0, 0)
        if phase == 63:
            put(w, 24, 64)
            return effect(o, w, 9, 2, 0, 0, 0)
        if get(w, get(w, 136) + 8) == 3 or get(w, get(w, 136) + 8) == 4 or get(w, get(w, 136) + 8) == 5 or get(w, get(w, 136) + 8) == 6:
            put(w, 24, 200)
            return buffer_effect(o, w, 13, 0, 1, 0, get(w, 136), get(w, 144))
        return sql_start(o, w, 1, 1, 21)
    if phase == 9:
        if rc != 0:
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        return sql_start(o, w, 8, 2, 10)
    if phase == 23:
        if rc != 0:
            return fail_body(o, w, 3)
        size = read_word(s, 128)
        at = get(w, 160)
        if size > length(w) - at:
            return 4294967293
        copy_source(s, w, 136, at, size)
        put(w, 200, at)
        put(w, 208, size)
        put(w, 160, at + size)
        base = get(w, 136)
        index = get(w, 192)
        start = field_start(w, base, index)
        size = field_size(w, base, index)
        if size == 0 or size - 1 > 8388608 or byte(w, start) != 7:
            return fail_body(o, w, 2)
        put(w, 24, 24)
        return buffer_effect(o, w, 10, 0, 262144, 128, start + 1, size - 1)
    if phase == 24:
        if rc != 0:
            return fail_body(o, w, 2)
        size = read_word(s, 128)
        if size != get(w, 208):
            return fail_body(o, w, 2)
        i = 0
        while i < size:
            if byte(s, 136 + i) != byte(w, get(w, 200) + i):
                return fail_body(o, w, 2)
            i = i + 1
        return sql_start(o, w, 5, 1, 25)
    if phase == 27:
        if rc != 0 or read_word(s, 64) != 1:
            put(w, 264, 1)
            return response(o, w, 6, 0, 0)
        put(w, 120, 0)
        put(w, 24, 0)
        return response(o, w, 0, get(w, 568), get(w, 576))
    if phase == 52:
        # sqlite3_finalize destroys the owned statement even on an error.
        put(w, 56, 0)
        if rc != 0:
            put(w, 264, 1)
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        return close_owned(o, w)
    if phase == 50:
        if rc != 0:
            put(w, 264, 1)
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        put(w, 72, 0)
        put(w, 24, 51)
        return effect(o, w, 2, 1, 0, 0, 0)
    if phase == 51:
        if rc != 0:
            put(w, 312, rc)
            return response(o, w, 5, 0, 0)
        put(w, 64, 0)
        return effect(o, w, 12, 0, 0, 0, 0)
    return 4294967295

def advance(o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 256)
    put(w, 24, phase)
    if phase == 4:
        index = get(w, 248)
        put(w, 248, index + 1)
        if index == 0:
            return sql_start(o, w, 7, 1, 4)
        if index <= 10:
            return sql_start(o, w, 9 + index, 1, 4)
        if index == 11:
            return sql_start(o, w, 9, 1, 4)
        put(w, 24, 5)
        return path_effect(o, w, 11, 0, 0)
    if phase == 10:
        if get(w, 304) != 1:
            return response(o, w, 4, 0, 0)
        return sql_start(o, w, 7, 2, 11)
    if phase == 11:
        return sql_start(o, w, 9, 2, 13)
    if phase == 13:
        put(w, 24, 12)
        return path_effect(o, w, 11, 0, 0)
    if phase == 21:
        put(w, 120, 1)
        if lease_fields(w) == 0:
            return fail_body(o, w, 1)
        return sql_start(o, w, 4, 1, 22)
    if phase == 22:
        if get(w, 88) == 0:
            return fail_body(o, w, 2)
        if get(w, 608) != 1 or get(w, 624) != 8:
            return fail_body(o, w, 2)
        if get(w, get(w, 616)) != 1:
            return fail_body(o, w, 2)
        if row_text_matches(w, 1, get(w, 176)) == 0 or row_text_matches(w, 2, get(w, 184)) == 0:
            return fail_body(o, w, 2)
        kind = get(w, 584)
        if kind != 3 and kind != 4:
            return fail_body(o, w, 3)
        if get(w, 600) > 8388608:
            return fail_body(o, w, 3)
        put(w, 24, 23)
        return buffer_effect(o, w, 10, 0, 262144, 128, get(w, 592), get(w, 600))
    if phase == 25:
        put(w, 120, 2)
        return sql_start(o, w, 2, 1, 26)
    if phase == 26:
        put(w, 24, 27)
        return effect(o, w, 9, 1, 0, 0, 0)
    if phase == 53:
        put(w, 120, 0)
        return close_owned(o, w)
    if phase == 40:
        put(w, 120, 0)
        put(w, 24, 0)
        return response(o, w, get(w, 104), 0, 0)
    return 4294967295

def sql_start(o:mutbuf, w:mutbuf, statement:u64, role:u64, continuation:u64) -> u32:
    put(w, 24, 100)
    put(w, 32, statement)
    put(w, 40, 0)
    put(w, 80, role)
    put(w, 88, 0)
    put(w, 96, 0)
    put(w, 256, continuation)
    put(w, 240, 0)
    if statement == 8:
        put(w, 304, 0)
    size = sql_size(statement)
    count = widen(effect(o, w, 4, role, 0, 0, size))
    if count >= 4294967292:
        return count
    sql_bytes(o, statement)
    return count

def sql_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    stage = get(w, 40)
    rc = read_word(s, 24)
    statement = get(w, 32)
    if stage == 0:
        if rc != 0 or read_word(s, 48) == 0:
            return fail_sql(o, w, rc)
        put(w, 56, read_word(s, 48))
        put(w, 320, read_word(s, 48))
        if statement == 4 or statement == 5:
            put(w, 40, 1)
            return bind_lease_id(o, w, statement)
        put(w, 40, 2)
        return effect(o, w, 6, 3, 0, 0, 0)
    if stage == 1:
        if rc != 0:
            put(w, 240, rc)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        put(w, 40, 2)
        return effect(o, w, 6, 3, 0, 0, 0)
    if stage == 2:
        if rc == 100:
            if statement == 4 or statement == 8:
                put(w, 88, 1)
                put(w, 96, 0)
                put(w, 40, 3)
                return effect(o, w, 7, 3, 0, 0, 0)
            return effect(o, w, 6, 3, 0, 0, 0)
        if rc != 101:
            put(w, 240, rc)
        put(w, 40, 4)
        return effect(o, w, 8, 3, 0, 0, 0)
    if stage == 3:
        if rc != 0 or read_word(s, 104) != 1:
            put(w, 240, 21)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        if statement == 8:
            if read_word(s, 64) == 3 and read_word(s, 128) == 3:
                if (byte(s, 136) | 32) == 119 and (byte(s, 137) | 32) == 97 and (byte(s, 138) | 32) == 108:
                    put(w, 304, 1)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        column = get(w, 96)
        if read_word(s, 72) != 5 or column >= 5:
            return 4294967295
        size = read_word(s, 128)
        at = get(w, 160)
        if size > length(w) - at:
            return 4294967293
        put(w, 512 + column * 24, read_word(s, 64))
        put(w, 520 + column * 24, at)
        put(w, 528 + column * 24, size)
        copy_source(s, w, 136, at, size)
        put(w, 160, at + size)
        column = column + 1
        put(w, 96, column)
        if column < 5:
            return effect(o, w, 7, 3, column, 0, 0)
        put(w, 40, 4)
        return effect(o, w, 8, 3, 0, 0, 0)
    if stage == 4:
        put(w, 56, 0)
        if get(w, 344) != 0:
            error = get(w, 344)
            put(w, 344, 0)
            return fail_body(o, w, error)
        if get(w, 240) != 0:
            return fail_sql(o, w, get(w, 240))
        if rc != 0:
            return fail_sql(o, w, rc)
        return advance(o, w)
    return 4294967295

def fail_body(o:mutbuf, w:mutbuf, code:u64) -> u32:
    put(w, 104, code)
    return sql_start(o, w, 3, 1, 40)

def fail_sql(o:mutbuf, w:mutbuf, rc:u64) -> u32:
    put(w, 312, rc)
    if get(w, 32) == 3 or get(w, 120) == 2:
        put(w, 264, 1)
        put(w, 24, 0)
        return response(o, w, 5, 0, 0)
    if get(w, 120) == 1:
        return fail_body(o, w, 5)
    put(w, 24, 0)
    return response(o, w, 5, 0, 0)

def bind_lease_id(o:mutbuf, w:mutbuf, statement:u64) -> u32:
    if statement == 5:
        if get(w, 512) != 3:
            put(w, 240, 21)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        return buffer_effect(o, w, 5, 3, 1, 5, get(w, 520), get(w, 528))
    base = get(w, 136)
    index = get(w, 168)
    at = field_start(w, base, index)
    size = field_size(w, base, index)
    if size == 0:
        return 4294967295
    kind = byte(w, at)
    if kind == 3:
        result = signed_integer(w, at + 1, size - 1)
        if result != 1:
            put(w, 344, choose(result == 2, 7, 6))
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        return buffer_effect(o, w, 5, 3, 1, 3, 336, 8)
    if kind > 6 or (kind <= 2 and size != 1) or (kind == 4 and size != 9):
        put(w, 344, choose(kind == 9, 9, 8))
        put(w, 40, 4)
        return effect(o, w, 8, 3, 0, 0, 0)
    return buffer_effect(o, w, 5, 3, 1, kind, at + 1, size - 1)


def fd_effect(o:mutbuf, w:mutbuf, op:u64, role:u64, a:u64, b:u64, size:u64) -> u32:
    count = widen(effect(o, w, op, role, a, b, size))
    if count >= 4294967292:
        return count
    if role >= 64 and role <= 66:
        put(o, 40, role - 64)
        put(o, 48, get(w, 400 + (role - 64) * 8))
        put(o, 56, 0)
    return count

def fd_buffer_effect(o:mutbuf, w:mutbuf, op:u64, role:u64, a:u64, b:u64, at:u64, size:u64) -> u32:
    if at > length(w) or size > length(w) - at:
        return 4294967295
    count = widen(fd_effect(o, w, op, role, a, b, size))
    if count >= 4294967292:
        return count
    copy_private(w, o, at, 136, size)
    return count

def valid_request(s:readbuf) -> u64:
    if read_word(s, 16) != 0 or read_word(s, 24) != 0:
        return 0
    if read_word(s, 32) != 0 or read_word(s, 40) != 0 or read_word(s, 48) != 0 or read_word(s, 56) != 0:
        return 0
    if read_word(s, 72) != 0 or read_word(s, 80) != 0 or read_word(s, 88) != 0:
        return 0
    op = read_word(s, 8)
    if op == 0:
        return choose(read_word(s, 64) == 0 and read_word(s, 104) == 1, 1, 0)
    if op == 2:
        return choose(read_word(s, 64) == 0 and read_word(s, 104) == 0, 1, 0)
    return choose(op == 1 or ((op == 3 or op == 4 or op == 5 or op == 6) and read_word(s, 64) == 0 and read_word(s, 104) == 5), 1, 0)

def signed_integer(w:mutbuf, at:u64, size:u64) -> u64:
    if size < 2:
        return 0
    negative = byte(w, at)
    if negative > 1:
        return 0
    if size > 9:
        return 2
    index = 1
    value = 0
    while index < size:
        value = value | (byte(w, at + index) << ((index - 1) * 8))
        index = index + 1
    if negative == 0 and value > 9223372036854775807:
        return 2
    if negative != 0 and value > 9223372036854775808:
        return 2
    if negative != 0 and value != 0:
        value = 18446744073709551615 - value + 1
    put(w, 336, value)
    return 1

def event_resources(s:readbuf, w:mutbuf) -> u64:
    if read_word(s, 8) == 24:
        return choose(get(w, 24) == 54 and read_word(s, 104) == 1 and read_word(s, 32) == 65 and read_word(s, 40) == 1 and read_word(s, 48) != 0 and read_word(s, 48) == get(w, 408) and read_word(s, 56) == 0 and get(w, 432) == 1, 1, 0)
    if read_word(s, 104) != 1:
        return 0
    op = read_word(s, 8)
    phase = get(w, 24)
    role = read_word(s, 32)
    slot = read_word(s, 40)
    generation = read_word(s, 48)
    if op == 10 or op == 11:
        if op == 10 and phase != 23 and phase != 24:
            return 0
        if op == 11 and phase != 70 and phase != 1 and phase != 5 and phase != 6 and phase != 7 and phase != 12 and phase != 13 and phase != 14 and phase != 60 and phase != 61 and phase != 62:
            return 0
        return choose(role == 0 and slot == 0 and generation == 0, 1, 0)
    if op == 1:
        if phase != 2 and phase != 8:
            return 0
        expected = choose(phase == 2, 1, 2)
        if role != expected or slot != expected - 1:
            return 0
        if read_word(s, 24) == 0:
            return choose(generation == 1 and get(w, 56 + expected * 8) == 0, 1, 0)
        return choose(generation == 0, 1, 0)
    if op == 4:
        if phase != 100:
            return 0
        if read_word(s, 24) != 0:
            return choose(role == get(w, 80) and slot == role - 1 and generation == get(w, 56 + role * 8), 1, 0)
        if get(w, 320) == 18446744073709551615:
            return 0
        return choose(role == 3 and slot == 2 and generation == get(w, 320) + 1 and read_word(s, 56) == get(w, 80), 1, 0)
    if op == 2 or op == 3 or op == 9:
        expected = 0
        if op == 2 and phase == 50:
            expected = 2
        if op == 2 and phase == 51:
            expected = 1
        if op == 3 and phase == 3:
            expected = 1
        if op == 3 and phase == 9:
            expected = 2
        if op == 9 and (phase == 63 or phase == 27):
            expected = 1
        if op == 9 and phase == 64:
            expected = 2
        if expected == 0 or role != expected or slot != expected - 1 or generation == 0:
            return 0
        return choose(generation == get(w, 56 + expected * 8), 1, 0)
    if op >= 5 and op <= 8:
        if (phase != 100 and (op != 8 or phase != 52)) or generation == 0:
            return 0
        return choose(role == 3 and slot == 2 and generation == get(w, 56) and read_word(s, 56) == get(w, 80), 1, 0)
    return 0

def lease_fields(w:mutbuf) -> u64:
    base = get(w, 136)
    if get(w, base + 64) != 6 or get(w, base + 104) != 8:
        return 0
    put(w, 168, 18446744073709551615)
    put(w, 176, 18446744073709551615)
    put(w, 184, 18446744073709551615)
    put(w, 192, 18446744073709551615)
    index = 0
    while index < 8:
        at = field_start(w, base, index)
        size = field_size(w, base, index)
        key = key_kind(w, at, size)
        if key == 0 or get(w, 160 + key * 8) != 18446744073709551615:
            return 0
        put(w, 160 + key * 8, index + 1)
        index = index + 2
    return 1

def key_kind(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0 or byte(w, at) != 5:
        return 0
    if size == 3 and byte(w, at + 1) == 105 and byte(w, at + 2) == 100:
        return 1
    if size == 5 and get_four(w, at + 1) == 1953459315:
        return 2
    if size == 11 and get(w, at + 1) == 7598805583366743399 and byte(w, at + 9) == 111 and byte(w, at + 10) == 110:
        return 3
    if size == 9 and get(w, at + 1) == 8386093273910571617:
        return 4
    return 0

def row_text_matches(w:mutbuf, column:u64, index:u64) -> u64:
    if get(w, 512 + column * 24) != 3:
        return 0
    base = get(w, 136)
    at = field_start(w, base, index)
    size = field_size(w, base, index)
    if size == 0 or byte(w, at) != 5 or size - 1 != get(w, 528 + column * 24):
        return 0
    row = get(w, 520 + column * 24)
    i = 0
    while i < size - 1:
        if byte(w, row + i) != byte(w, at + 1 + i):
            return 0
        i = i + 1
    return 1

def private_directory(s:readbuf) -> u64:
    mode = read_word(s, 64)
    if (mode & 61440) != 16384 or (mode & 18) != 0:
        return 0
    return choose(read_word(s, 72) == read_word(s, 56), 1, 0)

def private_file(s:readbuf) -> u64:
    mode = read_word(s, 64)
    if (mode & 61440) != 32768 or (mode & 18) != 0:
        return 0
    return choose(read_word(s, 72) == read_word(s, 56), 1, 0)

def response(o:mutbuf, w:mutbuf, status:u64, at:u64, size:u64) -> u32:
    if get(w, 328) == 0:
        put(w, 264, 1)
    put(w, 24, 0)
    count = widen(effect(o, w, 0, 0, status, choose(status == 5, get(w, 312), 0), size))
    if count >= 4294967292:
        return count
    if size != 0:
        copy_private(w, o, at, 136, size)
    return count

def path_effect(o:mutbuf, w:mutbuf, op:u64, role:u64, suffix:u64) -> u32:
    size = get(w, 128)
    extra = 0
    if op == 11 and suffix == 3:
        size = get(w, 352)
    if op == 11 and (suffix == 1 or suffix == 2):
        extra = 4
    count = widen(effect(o, w, op, role, choose(op == 1, suffix, 0), 0, size + extra))
    if count >= 4294967292:
        return count
    copy_private(w, o, 1024, 136, size)
    if extra != 0:
        store(o, 136 + size, 45)
        if suffix == 1:
            store(o, 137 + size, 119)
            store(o, 138 + size, 97)
            store(o, 139 + size, 108)
        else:
            store(o, 137 + size, 115)
            store(o, 138 + size, 104)
            store(o, 139 + size, 109)
    return count

def buffer_effect(o:mutbuf, w:mutbuf, op:u64, role:u64, a:u64, b:u64, at:u64, size:u64) -> u32:
    if at > length(w) or size > length(w) - at:
        return 4294967295
    count = widen(effect(o, w, op, role, a, b, size))
    if count >= 4294967292:
        return count
    copy_private(w, o, at, 136, size)
    return count

def effect(o:mutbuf, w:mutbuf, op:u64, role:u64, a:u64, b:u64, size:u64) -> u32:
    if size > length(o) - 136:
        return 4294967293
    if get(w, 8) == 18446744073709551615:
        return 4294967295
    fill_range(o, 0, 136, 0)
    put(w, 8, get(w, 8) + 1)
    put(w, 16, op)
    put(o, 0, EFFECT_MAGIC)
    put(o, 8, op)
    put(o, 16, get(w, 8))
    put(o, 32, role)
    if role == 1 or role == 2:
        put(o, 40, role - 1)
        put(o, 48, get(w, 56 + role * 8))
    if role == 3:
        put(o, 40, 2)
        put(o, 48, get(w, 56))
        put(o, 56, get(w, 80))
    put(o, 64, a)
    put(o, 72, b)
    put(o, 96, size)
    put(o, 104, 1)
    put(o, 128, size)
    return 136 + size

def valid_packet(s:readbuf) -> u64:
    if read_word(s, 112) != 0 or read_word(s, 120) != 0:
        return 0
    count = read_word(s, 104)
    remaining = length(s) - 128
    if count > (remaining >> 3):
        return 0
    at = 128 + count * 8
    remaining = length(s) - at
    if read_word(s, 96) != remaining:
        return 0
    i = 0
    while i < count:
        size = read_word(s, 128 + i * 8)
        if size > remaining:
            return 0
        remaining = remaining - size
        i = i + 1
    return choose(remaining == 0, 1, 0)

def field_size(w:mutbuf, base:u64, index:u64) -> u64:
    return get(w, base + 128 + index * 8)

def field_start(w:mutbuf, base:u64, index:u64) -> u64:
    at = base + 128 + get(w, base + 104) * 8
    i = 0
    while i < index:
        at = at + get(w, base + 128 + i * 8)
        i = i + 1
    return at

def copy_source(s:readbuf, w:mutbuf, source:u64, destination:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, destination + i, byte(s, source + i))
        i = i + 1
    return 0

def copy_private(w:mutbuf, o:mutbuf, source:u64, destination:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, destination + i, byte(w, source + i))
        i = i + 1
    return 0

def widen(value:u32) -> u64:
    return value

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def get_four(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 4:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


# Separate flat modules retain the existing compiler limits independently.
# Only the trusted native store driver enters this transaction continuation.
# Until the full retained-Core/context/receipt continuation is complete, the
# Python adapter deliberately exposes no ordinary .call/.rollback entrypoint.
AGENT_SOURCE = r'''
def agent_transaction(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(o) < 256 or length(w) < 2048:
        return 4294967293
    if valid_packet(s) == 0 or get(w, 0) != STATE_MAGIC:
        return 4294967295
    phase = get(w, 24)
    if phase == 200:
        if read_word(s, 0) != REQUEST_MAGIC or (read_word(s, 8) != 3 and read_word(s, 8) != 4 and read_word(s, 8) != 5 and read_word(s, 8) != 6):
            return 4294967295
        if read_word(s, 104) != 5 or read_word(s, 64) != 0:
            return 4294967295
        end = get(w, 136) + get(w, 144)
        if end > length(w) or length(w) - end < 4104:
            return 4294967293
        state = (end + 7) & 18446744073709551608
        fill_range(w, state, 4096, 0)
        put(w, 368, state)
        put(w, 160, state + 4096)
        base = get(w, 136)
        if read_word(s, 8) == 5 or read_word(s, 8) == 6:
            return agent_artifact_begin(s, o, w)
        if field_size(w, base, 4) != 16:
            return 4294967295
        at = field_start(w, base, 4)
        aset(w, 24, get(w, at))
        aset(w, 32, get(w, at + 8))
        if aget(w, 32) > 1:
            return 4294967295
        return agent_journal(o, w, 9, field_start(w, base, 1), field_size(w, base, 1), 210)
    if read_word(s, 0) != EVENT_MAGIC or read_word(s, 8) != get(w, 16) or read_word(s, 16) != get(w, 8):
        return 4294967295
    if agent_event_resources(s, w) == 0:
        return 4294967295
    if phase == 250:
        return agent_sql_event(s, o, w)
    return agent_event(s, o, w)

def aget(w:mutbuf, index:u64) -> u64:
    return get(w, get(w, 368) + index)

def aset(w:mutbuf, index:u64, value:u64) -> u64:
    return put(w, get(w, 368) + index, value)

def agent_event_resources(s:readbuf, w:mutbuf) -> u64:
    if read_word(s, 104) != 1:
        return 0
    if read_word(s, 8) >= 17:
        return agent_fd_resources(s, w)
    op = read_word(s, 8)
    phase = get(w, 24)
    role = read_word(s, 32)
    slot = read_word(s, 40)
    generation = read_word(s, 48)
    if op == 14:
        if phase != 210 and phase != 211 and phase != 218 and phase != 222 and phase != 226 and phase != 228 and phase != 229 and phase != 302:
            return 0
        return choose(role == 0 and slot == 0 and generation == 0, 1, 0)
    if op == 15:
        if phase != 214 and phase != 215 and phase != 303:
            return 0
        return choose(role == 0 and slot == 0 and generation == 0, 1, 0)
    if op == 16:
        return choose(phase == 300 and role == 0 and slot == 0 and generation == 0, 1, 0)
    if op == 4:
        if phase != 250:
            return 0
        if read_word(s, 24) != 0:
            return choose(role == 1 and slot == 0 and generation != 0 and generation == get(w, 64), 1, 0)
        if get(w, 320) == 18446744073709551615:
            return 0
        return choose(role == 3 and slot == 2 and generation == get(w, 320) + 1 and read_word(s, 56) == 1, 1, 0)
    if op >= 5 and op <= 8:
        return choose(phase == 250 and role == 3 and slot == 2 and generation != 0 and generation == get(w, 56) and read_word(s, 56) == 1, 1, 0)
    if op == 9:
        return choose((phase == 224 or phase == 227) and role == 1 and slot == 0 and generation != 0 and generation == get(w, 64), 1, 0)
    return 0

def agent_journal(o:mutbuf, w:mutbuf, stage:u64, at:u64, size:u64, continuation:u64) -> u32:
    if at > length(w) or size > length(w) - at or (stage != 10 and size > 8388608):
        return 4294967295
    base = get(w, 136)
    foreign = choose(stage == 0, field_size(w, base, 2), 0)
    if foreign > 262144:
        return 4294967295
    state = get(w, 368) + 1024
    put(w, state + 336, foreign)
    put(w, state + 344, aget(w, 32))
    total = 512 + foreign + size
    count = widen(effect(o, w, 14, 0, stage, aget(w, 24), total))
    if count >= 4294967292:
        return count
    copy_private(w, o, state, 136, 512)
    if foreign != 0:
        copy_private(w, o, field_start(w, base, 2), 648, foreign)
    copy_private(w, o, at, 648 + foreign, size)
    put(w, 24, continuation)
    return count

def agent_journal_accept(s:readbuf, w:mutbuf, expected:u64) -> u64:
    size = read_word(s, 128)
    if read_word(s, 24) >= 4294967264 or size < 512:
        return 0
    if read_word(s, 136) != JOURNAL_MAGIC or read_word(s, 184) != read_word(s, 24):
        return 0
    state_phase = read_word(s, 144)
    if state_phase > 11 or state_phase == 9:
        return 0
    if read_word(s, 152) > 12 or read_word(s, 160) > 1 or read_word(s, 168) > 1 or read_word(s, 176) > 1:
        return 0
    if read_word(s, 400) > 2 or read_word(s, 424) > 3:
        return 0
    first = read_word(s, 408)
    second = read_word(s, 416)
    if first > 8388608 or second > 8388608 or size - 512 != first + second:
        return 0
    code = read_word(s, 24)
    status = read_word(s, 400)
    flags = read_word(s, 424)
    if code == 10:
        if (flags != 1 and flags != 3) or first == 0 or second == 0 or status == 0:
            return 0
    elif code == 9:
        if flags != 2 or first == 0 or second != 0 or status != 1:
            return 0
    elif status != 0 or first != 0 or second != 0 or flags != 0:
        return 0
    if expected != 18446744073709551615 and read_word(s, 24) != expected:
        return 0
    state = get(w, 368) + 1024
    if get(w, state + 192) != 0:
        i = 64
        while i < 258:
            if byte(s, 136 + i) != byte(w, state + i):
                return 0
            i = i + 1
    copy_source(s, w, 136, state, 512)
    return 1

def agent_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 24)
    if phase >= 401 and phase <= 411:
        return agent_file_event(s, o, w)
    if phase >= 420 and phase <= 424:
        return agent_metadata_event(s, o, w)
    if phase == 300:
        return agent_policy_event(s, o, w)
    if phase == 302:
        return agent_terminal_event(s, o, w)
    if phase == 303:
        return agent_terminal_clock(s, o, w)
    if phase == 210:
        if agent_journal_accept(s, w, 12) == 0:
            return agent_fence(o, w, 14)
        fill_range(w, get(w, 368) + 1024, 512, 0)
        base = get(w, 136)
        return agent_journal(o, w, 0, field_start(w, base, 0), field_size(w, base, 0), 211)
    if phase == 211:
        if agent_journal_accept(s, w, 18446744073709551615) == 0:
            return agent_fence(o, w, 14)
        action = read_word(s, 24)
        if action == 11:
            return response(o, w, 14, get(w, 368) + 1080, 8)
        if action != 2 and (action != 1 or agent_full_enabled(w) == 0):
            return response(o, w, 13, 0, 0)
        aset(w, 40, action)
        put(w, 24, 214)
        return effect(o, w, 15, 0, 0, 0, 0)
    if phase == 214 or phase == 215:
        if read_word(s, 24) != 0 or read_word(s, 128) != 16:
            return agent_fence(o, w, 14)
        seconds = read_word(s, 136)
        nanos = read_word(s, 144)
        if nanos >= 1000000000:
            return agent_fence(o, w, 14)
        if phase == 214:
            agent_timestamp(w, seconds, nanos, get(w, 368) + 512)
            put(w, 24, 215)
            return effect(o, w, 15, 0, 1, 0, 0)
        aset(w, 56, seconds)
        aset(w, 592, nanos)
        if aget(w, 40) == 1:
            return agent_policy_start(o, w)
        return agent_sql(o, w, 1, 216)
    if phase == 218:
        if agent_journal_accept(s, w, 18446744073709551615) == 0:
            return agent_fence(o, w, 14)
        action = read_word(s, 24)
        if action == 11:
            aset(w, 0, 14)
            return agent_sql(o, w, 3, 241)
        if action == 3:
            if get(w, get(w, 368) + 1040) != 11:
                aset(w, 0, 13)
                return agent_sql(o, w, 3, 241)
            return agent_sql(o, w, 21, 221)
        if action == 4:
            kind = aget(w, 224)
            if kind != 3 and kind != 4:
                aset(w, 0, 14)
                return agent_sql(o, w, 3, 241)
            aset(w, 64, aget(w, 232))
            aset(w, 72, aget(w, 240))
            if kind == 4 and aget(w, 32) == 0:
                return agent_journal(o, w, 10, aget(w, 64), aget(w, 72), 229)
            return agent_journal(o, w, 3, aget(w, 64), aget(w, 72), 226)
        return agent_fence(o, w, 14)
    if phase == 229:
        if agent_journal_accept(s, w, 13) == 0:
            return agent_fence(o, w, 14)
        return agent_journal(o, w, 3, aget(w, 64), aget(w, 72), 226)
    if phase == 222:
        if agent_journal_accept(s, w, 1) == 0:
            return agent_fence(o, w, 14)
        put(w, 120, 2)
        return agent_sql(o, w, 2, 223)
    if phase == 224:
        if read_word(s, 24) != 0 or read_word(s, 64) != 1:
            return agent_fence(o, w, 6)
        put(w, 120, 0)
        if agent_full_enabled(w) != 0:
            return agent_policy_start(o, w)
        # Operation 3 remains the retained private-prefix test interface.
        return response(o, w, 13, 0, 0)
    if phase == 226:
        if agent_journal_accept(s, w, 5) == 0:
            return agent_fence(o, w, 14)
        put(w, 120, 2)
        return agent_sql(o, w, 2, 225)
    if phase == 227:
        if read_word(s, 24) != 0 or read_word(s, 64) != 1:
            return agent_fence(o, w, 6)
        put(w, 120, 0)
        return agent_journal(o, w, 8, 0, 0, 228)
    if phase == 228:
        if agent_journal_accept(s, w, 0) == 0:
            return agent_fence(o, w, 14)
        return response(o, w, 0, aget(w, 64), aget(w, 72))
    return 4294967295

def agent_fence(o:mutbuf, w:mutbuf, status:u64) -> u32:
    put(w, 264, 1)
    return response(o, w, status, 0, 0)

def agent_div10(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def agent_decimal(w:mutbuf, value:u64, at:u64) -> u64:
    size = 0
    while value != 0 or size == 0:
        quotient = agent_div10(value)
        store(w, at + size, 48 + (value - quotient * 10))
        value = quotient
        size = size + 1
    i = 0
    while i < (size >> 1):
        saved = byte(w, at + i)
        store(w, at + i, byte(w, at + size - 1 - i))
        store(w, at + size - 1 - i, saved)
        i = i + 1
    aset(w, 568, size)
    return size

def agent_sql(o:mutbuf, w:mutbuf, statement:u64, continuation:u64) -> u32:
    put(w, 24, 250)
    put(w, 32, statement)
    put(w, 40, 0)
    put(w, 80, 1)
    put(w, 240, 0)
    aset(w, 80, continuation)
    aset(w, 88, 0)
    aset(w, 96, 0)
    aset(w, 104, 0)
    size = sql_size(statement)
    count = widen(effect(o, w, 4, 1, 0, 0, size))
    if count >= 4294967292:
        return count
    sql_bytes(o, statement)
    return count

def agent_bind(o:mutbuf, w:mutbuf, position:u64) -> u32:
    statement = get(w, 32)
    state = get(w, 368) + 1024
    if statement == 24:
        base = get(w, 136)
        return buffer_effect(o, w, 5, 3, 1, 5, field_start(w, base, 0), field_size(w, base, 0))
    if statement == 22 or statement == 23:
        return agent_terminal_bind(o, w, position)
    if statement == 20:
        return buffer_effect(o, w, 5, 3, 1, 5, state + 128, 64)
    if statement != 21:
        return 4294967295
    if position == 1:
        return buffer_effect(o, w, 5, 3, 1, 5, state + 128, 64)
    if position == 2:
        return buffer_effect(o, w, 5, 3, 2, 5, state + 64, 64)
    if position == 3:
        if get(w, state + 16) != 11:
            return 4294967295
        put(w, get(w, 368) + 544, 7812741990598142312)
        store(w, get(w, 368) + 552, 98)
        store(w, get(w, 368) + 553, 97)
        store(w, get(w, 368) + 554, 99)
        store(w, get(w, 368) + 555, 107)
        return buffer_effect(o, w, 5, 3, 3, 5, get(w, 368) + 544, 12)
    if position == 4:
        put(w, get(w, 368) + 560, 29113321704551794)
        return buffer_effect(o, w, 5, 3, 4, 5, get(w, 368) + 560, 7)
    if position == 5:
        return effect(o, w, 5, 3, 5, 0, 0)
    if position == 6:
        return buffer_effect(o, w, 5, 3, 6, 5, get(w, 368) + 512, aget(w, 568))
    return 4294967295

def agent_sql_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    stage = get(w, 40)
    rc = read_word(s, 24)
    statement = get(w, 32)
    if stage == 0:
        if rc != 0 or read_word(s, 48) == 0:
            return agent_sql_failure(o, w, rc)
        put(w, 56, read_word(s, 48))
        put(w, 320, read_word(s, 48))
        if statement == 20 or statement == 21 or statement == 22 or statement == 23 or statement == 24:
            aset(w, 88, 1)
            put(w, 40, 1)
            return agent_bind(o, w, 1)
        put(w, 40, 2)
        return effect(o, w, 6, 3, 0, 0, 0)
    if stage == 1:
        if rc != 0:
            put(w, 240, rc)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        position = aget(w, 88) + 1
        if ((statement == 21 or statement == 22) and position <= 6) or (statement == 23 and position <= 2):
            aset(w, 88, position)
            return agent_bind(o, w, position)
        put(w, 40, 2)
        return effect(o, w, 6, 3, 0, 0, 0)
    if stage == 2:
        if (statement == 20 or statement == 24) and aget(w, 96) == 1 and aget(w, 104) == 6:
            if rc != 100 and rc != 101:
                put(w, 240, rc)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        if rc == 100:
            if statement == 20 or statement == 24:
                aset(w, 96, 1)
                aset(w, 104, 0)
                put(w, 40, 3)
                return effect(o, w, 7, 3, 0, 0, 0)
            return effect(o, w, 6, 3, 0, 0, 0)
        if rc != 101:
            put(w, 240, rc)
        put(w, 40, 4)
        return effect(o, w, 8, 3, 0, 0, 0)
    if stage == 3:
        if rc != 0 or read_word(s, 72) != 6:
            put(w, 240, 21)
            put(w, 40, 4)
            return effect(o, w, 8, 3, 0, 0, 0)
        column = aget(w, 104)
        if column >= 6:
            return 4294967295
        size = read_word(s, 128)
        at = get(w, 160)
        if at > length(w) or size > length(w) - at:
            return 4294967293
        aset(w, 128 + column * 24, read_word(s, 64))
        aset(w, 136 + column * 24, at)
        aset(w, 144 + column * 24, size)
        copy_source(s, w, 136, at, size)
        put(w, 160, at + size)
        if read_word(s, 64) == 3:
            code = agent_column_utf8(w, at, size)
            if code != 0:
                if code != 4294967271 or aget(w, 640) >= aget(w, 648) or aget(w, 648) > size or aget(w, 656) < 1 or aget(w, 656) > 3:
                    return agent_fence(o, w, 6)
                return agent_text_error(o, w)
        return agent_column_finished(o, w)
    if stage == 4:
        put(w, 56, 0)
        if get(w, 240) != 0:
            return agent_sql_failure(o, w, get(w, 240))
        if rc != 0:
            return agent_sql_failure(o, w, rc)
        if aget(w, 624) == 2 and statement == 24:
            return response(o, w, 18, aget(w, 608), aget(w, 616))
        if aget(w, 624) != 0 and statement != 3:
            return agent_sql(o, w, 3, 242)
        return agent_advance(o, w)
    return 4294967295

def agent_advance(o:mutbuf, w:mutbuf) -> u32:
    phase = aget(w, 80)
    if phase == 400:
        return agent_artifact_row(o, w)
    if phase == 304:
        if aget(w, 736) == 3:
            return agent_sql(o, w, 23, 305)
        return response(o, w, 0, aget(w, 696), aget(w, 704))
    if phase == 305:
        return response(o, w, 0, aget(w, 696), aget(w, 704))
    if phase == 216:
        put(w, 120, 1)
        return agent_sql(o, w, 20, 217)
    if phase == 217:
        if aget(w, 96) != 0:
            state_extent = agent_observed_extent(w, 3)
            if state_extent > 8388608:
                return agent_budget_error(o, w, 1)
            digest_extent = agent_observed_extent(w, 1)
            if digest_extent > 8388608:
                return agent_budget_error(o, w, 1)
            if 20 + state_extent + digest_extent > 8388608:
                return agent_budget_error(o, w, 2)
        start = get(w, 160)
        aset(w, 112, start)
        aset(w, 120, 0)
        if aget(w, 96) == 0:
            agent_text(w, 'null')
        else:
            agent_text(w, '{"digest":')
            agent_observed_text(w, 1)
            agent_text(w, ',"state":')
            agent_observed_text(w, 3)
            agent_text(w, '}')
        if aget(w, 120) != 0:
            return agent_fence(o, w, 14)
        size = aget(w, 112) - start
        put(w, 160, start + size)
        return agent_journal(o, w, 1, start, size, 218)
    if phase == 221:
        return agent_journal(o, w, 2, 0, 0, 222)
    if phase == 223:
        put(w, 24, 224)
        return effect(o, w, 9, 1, 0, 0, 0)
    if phase == 225:
        put(w, 24, 227)
        return effect(o, w, 9, 1, 0, 0, 0)
    if phase == 241:
        put(w, 120, 0)
        return response(o, w, aget(w, 0), get(w, 368) + 1080, 8)
    if phase == 240:
        put(w, 120, 0)
        return response(o, w, 5, 0, 0)
    if phase == 242:
        put(w, 120, 0)
        return response(o, w, 15, aget(w, 608), aget(w, 616))
    return 4294967295

def agent_sql_failure(o:mutbuf, w:mutbuf, rc:u64) -> u32:
    put(w, 312, rc)
    if get(w, 32) == 3 or get(w, 120) == 2:
        return agent_fence(o, w, 5)
    if get(w, 120) == 1:
        return agent_sql(o, w, 3, 240)
    return response(o, w, 5, 0, 0)

def agent_emit_byte(w:mutbuf, value:u64) -> u64:
    at = aget(w, 112)
    if at >= length(w) or (aget(w, 632) != 0 and at >= aget(w, 632)):
        aset(w, 120, 1)
        return 0
    store(w, at, value)
    aset(w, 112, at + 1)
    return 0

def agent_emit_word(w:mutbuf, value:u64, size:u64) -> u64:
    i = 0
    while i < size:
        agent_emit_byte(w, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def agent_string(w:mutbuf, at:u64, size:u64) -> u64:
    if at > length(w) or size > length(w) - at:
        aset(w, 120, 1)
        return 0
    agent_emit_byte(w, 34)
    i = 0
    while i < size:
        value = byte(w, at + i)
        if value == 34 or value == 92:
            agent_emit_byte(w, 92)
            agent_emit_byte(w, value)
        elif value < 32:
            agent_emit_byte(w, 92)
            if value == 8:
                agent_emit_byte(w, 98)
            elif value == 9:
                agent_emit_byte(w, 116)
            elif value == 10:
                agent_emit_byte(w, 110)
            elif value == 12:
                agent_emit_byte(w, 102)
            elif value == 13:
                agent_emit_byte(w, 114)
            else:
                agent_emit_word(w, 3158133, 3)
                agent_emit_byte(w, 48 + (value >> 4))
                low = value & 15
                agent_emit_byte(w, choose(low < 10, 48 + low, 87 + low))
        else:
            agent_emit_byte(w, value)
        i = i + 1
    agent_emit_byte(w, 34)
    return 0

def agent_observed_text(w:mutbuf, column:u64) -> u64:
    kind = aget(w, 128 + column * 24)
    if kind == 3:
        return agent_string(w, aget(w, 136 + column * 24), aget(w, 144 + column * 24))
    agent_text(w, '{"sqlite_storage_class":"')
    if kind == 1:
        agent_text(w, 'int')
    elif kind == 2:
        agent_text(w, 'float')
    elif kind == 4:
        agent_text(w, 'bytes')
    elif kind == 5:
        agent_text(w, 'NoneType')
    else:
        aset(w, 120, 1)
    agent_text(w, '"}')
    return 0

def agent_timestamp(w:mutbuf, seconds:u64, nanos:u64, at:u64) -> u64:
    negative = seconds > 9223372036854775807
    if negative:
        seconds = 18446744073709551615 - seconds + 1
        if nanos != 0:
            seconds = seconds - 1
            nanos = 1000000000 - nanos
        store(w, at, 45)
    start = at + choose(negative, 1, 0)
    if seconds == 0:
        size = agent_decimal(w, nanos, start)
    else:
        size = agent_decimal(w, seconds, start)
        i = 9
        while i != 0:
            i = i - 1
            quotient = agent_div10(nanos)
            store(w, start + size + i, 48 + (nanos - quotient * 10))
            nanos = quotient
        size = size + 9
    size = size + choose(negative, 1, 0)
    aset(w, 568, size)
    return size

def agent_column_finished(o:mutbuf, w:mutbuf) -> u32:
    column = aget(w, 104) + 1
    aset(w, 104, column)
    put(w, 24, 250)
    if column < 6:
        put(w, 40, 3)
        return effect(o, w, 7, 3, column, 0, 0)
    put(w, 40, 2)
    return effect(o, w, 6, 3, 0, 0, 0)

def agent_observed_extent(w:mutbuf, column:u64) -> u64:
    kind = aget(w, 128 + column * 24)
    if kind == 3:
        return agent_string_extent(w, aget(w, 136 + column * 24), aget(w, 144 + column * 24))
    if kind == 1:
        return 30
    if kind == 5:
        return 35
    return 32

def agent_string_extent(w:mutbuf, at:u64, size:u64) -> u64:
    total = 2
    i = 0
    while i < size and total <= 8388608:
        value = byte(w, at + i)
        if value == 34 or value == 92 or value == 8 or value == 9 or value == 10 or value == 12 or value == 13:
            total = total + 2
        elif value < 32:
            total = total + 6
        else:
            total = total + 1
        i = i + 1
    return total

def agent_budget_error(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    start = get(w, 368) + 1792
    aset(w, 112, start)
    aset(w, 120, 0)
    aset(w, 632, get(w, 368) + 2386)
    if reason == 1:
        agent_text(w, 'E_HIA_EDIT: JSON string exceeds byte budget before encoding')
    else:
        agent_text(w, 'E_HIA_EDIT: JSON encoding exceeds byte budget')
    size = aget(w, 112) - start
    aset(w, 632, 0)
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    return agent_error_json(o, w, start, size)

def agent_text_error(o:mutbuf, w:mutbuf) -> u32:
    state = get(w, 368)
    raw = state + 1536
    aset(w, 112, raw)
    aset(w, 120, 0)
    aset(w, 632, raw + 198)
    agent_text(w, "Could not decode to UTF-8 column '")
    column = aget(w, 104)
    if get(w, 32) == 24:
        if column == 0:
            agent_text(w, 'id')
        elif column == 1:
            agent_text(w, 'sha256')
        elif column == 2:
            agent_text(w, 'uri')
        elif column == 3:
            agent_text(w, 'kind')
        elif column == 4:
            agent_text(w, 'metadata')
        elif column == 5:
            agent_text(w, 'content_key')
        else:
            return agent_fence(o, w, 6)
    else:
        if column == 0:
            agent_text(w, 'key')
        elif column == 1:
            agent_text(w, 'digest')
        elif column == 2:
            agent_text(w, 'tool')
        elif column == 3:
            agent_text(w, 'state')
        elif column == 4:
            agent_text(w, 'response')
        elif column == 5:
            agent_text(w, 'started_ns')
        else:
            return agent_fence(o, w, 6)
    agent_text(w, "' with text '")
    at = aget(w, 136 + column * 24)
    size = aget(w, 144 + column * 24)
    i = 0
    copying = True
    while copying and i < size and aget(w, 112) < raw + 198:
        value = byte(w, at + i)
        if value == 0:
            copying = False
        else:
            agent_emit_byte(w, value)
        i = i + 1
    agent_text(w, "'")
    size = aget(w, 112) - raw
    at = state + 1792
    i = 0
    extent = 0
    while i < size:
        value = byte(w, raw + i)
        if value < 128:
            store(w, at + extent, value)
            extent = extent + 1
        else:
            store(w, at + extent, 239)
            store(w, at + extent + 1, 191)
            store(w, at + extent + 2, 189)
            extent = extent + 3
        i = i + 1
    aset(w, 632, 0)
    aset(w, 120, 0)
    return agent_error_json(o, w, at, extent)

def agent_error_json(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u32:
    if get(w, 120) != 1 and get(w, 32) != 24:
        return agent_fence(o, w, 6)
    start = get(w, 368) + 2560
    aset(w, 112, start)
    aset(w, 120, 0)
    aset(w, 632, get(w, 368) + 4096)
    agent_text(w, '{"code":"E_HIA_REJECTED","details_artifact":null,"message":')
    agent_string(w, at, size)
    agent_text(w, ',"phase":"admission","retry_action":"correct_input"}')
    extent = aget(w, 112) - start
    aset(w, 632, 0)
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    aset(w, 608, start)
    aset(w, 616, extent)
    aset(w, 624, choose(get(w, 32) == 24, 2, 1))
    if get(w, 56) != 0:
        put(w, 24, 250)
        put(w, 40, 4)
        return effect(o, w, 8, 3, 0, 0, 0)
    return agent_sql(o, w, 3, 242)

def agent_full_enabled(w:mutbuf) -> u64:
    return choose(get(w, get(w, 136) + 8) == 4, 1, 0)

def agent_policy_start(o:mutbuf, w:mutbuf) -> u32:
    base = get(w, 136)
    put(w, 24, 300)
    return buffer_effect(o, w, 16, 0, 0, 0, field_start(w, base, 0), field_size(w, base, 0))

def agent_policy_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = read_word(s, 128)
    if read_word(s, 24) != size or size < 64 or size > 8388608:
        return agent_fence(o, w, 6)
    if read_word(s, 136) != POLICY_MAGIC or read_word(s, 160) != size - 64:
        return agent_fence(o, w, 6)
    index = 168
    while index < 200:
        if byte(s, index) != 0:
            return agent_fence(o, w, 6)
        index = index + 1
    status = read_word(s, 144)
    fields = read_word(s, 152)
    at = get(w, 160)
    if at > length(w) or size > length(w) - at:
        return 4294967293
    copy_source(s, w, 136, at, size)
    put(w, 160, at + size)
    if status == 1:
        if fields != 0 or size == 64:
            return agent_fence(o, w, 6)
        return agent_complete_error(o, w, at + 64, size - 64)
    if status != 0 or fields != 9 or size < 136:
        return agent_fence(o, w, 6)
    index = 0
    remaining = size - 136
    while index < 9:
        extent = get(w, at + 64 + index * 8)
        if extent > remaining:
            return agent_fence(o, w, 6)
        remaining = remaining - extent
        index = index + 1
    if remaining != 0:
        return agent_fence(o, w, 6)
    aset(w, 680, at)
    aset(w, 688, size)
    # The following owned continuation consumes actual installation, context,
    # retained artifact and Core observations. It must not become public until
    # its remaining explicit dependency request has an admitted implementation.
    return agent_business_start(o, w)

def agent_policy_field(w:mutbuf, index:u64) -> u64:
    at = aget(w, 680) + 136
    current = 0
    while current < index:
        at = at + get(w, aget(w, 680) + 64 + current * 8)
        current = current + 1
    return at

def agent_complete_error(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u32:
    if at > length(w) or size > length(w) - at or size > 8388608:
        return agent_fence(o, w, 6)
    start = get(w, 160)
    aset(w, 112, start)
    aset(w, 120, 0)
    agent_text(w, '{"contract_version":"hepta.hia.agent-native.v1","error":')
    index = 0
    while index < size:
        agent_emit_byte(w, byte(w, at + index))
        index = index + 1
    agent_text(w, ',"request_id":')
    agent_string(w, get(w, 368) + 1216, 66)
    agent_text(w, ',"status":"rejected"}')
    extent = aget(w, 112) - start
    if aget(w, 120) != 0 or extent > 8388608:
        return agent_fence(o, w, 6)
    put(w, 160, start + extent)
    aset(w, 696, start)
    aset(w, 704, extent)
    return agent_journal(o, w, 8, start, extent, 302)

def agent_terminal_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if agent_journal_accept(s, w, 10) == 0:
        return agent_fence(o, w, 6)
    first = read_word(s, 408)
    second = read_word(s, 416)
    flags = read_word(s, 424)
    at = get(w, 160)
    if at > length(w) or first > length(w) - at or second > length(w) - at - first:
        return 4294967293
    copy_source(s, w, 648, at, first + second)
    put(w, 160, at + first + second)
    aset(w, 696, at)
    aset(w, 704, first)
    aset(w, 712, at + first)
    aset(w, 720, second)
    aset(w, 728, read_word(s, 400))
    aset(w, 736, flags)
    put(w, 24, 303)
    return effect(o, w, 15, 0, 1, 0, 0)

def agent_terminal_clock(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 24) != 0 or read_word(s, 128) != 16:
        return agent_fence(o, w, 6)
    seconds = read_word(s, 136)
    nanos = read_word(s, 144)
    original_seconds = aget(w, 56)
    original_nanos = aget(w, 592)
    if nanos >= 1000000000 or seconds < original_seconds:
        return agent_fence(o, w, 6)
    seconds = seconds - original_seconds
    if nanos < original_nanos:
        if seconds == 0:
            return agent_fence(o, w, 6)
        seconds = seconds - 1
        nanos = nanos + 1000000000 - original_nanos
    else:
        nanos = nanos - original_nanos
    at = get(w, 368) + 800
    if seconds == 0:
        size = agent_decimal(w, nanos, at)
    else:
        size = agent_decimal(w, seconds, at)
        index = 9
        while index != 0:
            index = index - 1
            quotient = agent_div10(nanos)
            store(w, at + size + index, 48 + nanos - quotient * 10)
            nanos = quotient
        size = size + 9
    aset(w, 744, size)
    return agent_sql(o, w, 22, 304)

def agent_terminal_bind(o:mutbuf, w:mutbuf, position:u64) -> u32:
    statement = get(w, 32)
    state = get(w, 368)
    if statement == 23:
        if position == 1:
            return buffer_effect(o, w, 5, 3, 1, 5, aget(w, 696), aget(w, 704))
        if position == 2:
            return buffer_effect(o, w, 5, 3, 2, 5, state + 1152, 64)
        return 4294967295
    if statement != 22:
        return 4294967295
    if position == 1:
        if aget(w, 752) == 0:
            return effect(o, w, 5, 3, 1, 0, 0)
        return buffer_effect(o, w, 5, 3, 1, 5, aget(w, 752), aget(w, 760))
    if position == 2:
        put(w, state + 544, 7812741990598142312)
        store(w, state + 552, 98)
        store(w, state + 553, 97)
        store(w, state + 554, 99)
        store(w, state + 555, 107)
        return buffer_effect(o, w, 5, 3, 2, 5, state + 544, 12)
    if position == 3:
        return buffer_effect(o, w, 5, 3, 3, 5, state + 1216, 66)
    if position == 4:
        return buffer_effect(o, w, 5, 3, 4, 5, state + 800, aget(w, 744))
    if position == 5:
        if aget(w, 728) == 2:
            put(w, state + 840, 7234316346692625778)
            return buffer_effect(o, w, 5, 3, 5, 5, state + 840, 8)
        if aget(w, 728) == 1:
            put(w, state + 840, 7310579611546251107)
            store(w, state + 848, 100)
            return buffer_effect(o, w, 5, 3, 5, 5, state + 840, 9)
        return 4294967295
    if position == 6:
        return buffer_effect(o, w, 5, 3, 6, 5, aget(w, 712), aget(w, 720))
    return 4294967295

def agent_business_start(o:mutbuf, w:mutbuf) -> u32:
    # Kept as an explicit unfinished dependency boundary while the new owner
    # is assembled. No ordinary service method consumes this internal status.
    return response(o, w, 16, aget(w, 680), aget(w, 688))


def agent_artifact_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 104) != 5 or read_word(s, 64) != 0:
        return 4294967295
    base = get(w, 136)
    size = choose(read_word(s, 8) == 6, 16, 8)
    if field_size(w, base, 4) != size:
        return 4294967295
    if get(w, field_start(w, base, 4)) > 1:
        return 4294967295
    if read_word(s, 8) == 6:
        limit = get(w, field_start(w, base, 4) + 8)
        if limit != 0 and limit < 640:
            return 4294967295
        aset(w, 880, 1)
        aset(w, 888, limit)
    index = 0
    while index < 4:
        if agent_column_utf8(w, field_start(w, base, index), field_size(w, base, index)) != 0:
            return 4294967295
        index = index + 1
    return agent_sql(o, w, 24, 400)

def agent_bytes_equal(w:mutbuf, left:u64, left_size:u64, right:u64, right_size:u64) -> u64:
    if left_size != right_size:
        return 0
    index = 0
    while index < left_size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1

def agent_artifact_row(o:mutbuf, w:mutbuf) -> u32:
    base = get(w, 136)
    if aget(w, 96) != 1:
        return agent_artifact_fail(o, w, 1)
    index = 0
    while index < 3:
        if aget(w, 128 + index * 24) != 3:
            return agent_artifact_fail(o, w, 1)
        if agent_bytes_equal(w, aget(w, 136 + index * 24), aget(w, 144 + index * 24),
                             field_start(w, base, index), field_size(w, base, index)) == 0:
            return agent_artifact_fail(o, w, 1)
        index = index + 1
    if get(w, field_start(w, base, 4)) == 1:
        if aget(w, 200) != 3 or agent_bytes_equal(w, aget(w, 208), aget(w, 216),
                                                field_start(w, base, 3), field_size(w, base, 3)) == 0:
            return agent_artifact_fail(o, w, 2)
    start = get(w, 160)
    aset(w, 800, start)
    aset(w, 112, start)
    aset(w, 120, 0)
    name = aget(w, 160)
    size = aget(w, 168)
    if size == 0 or byte(w, name) != 47:
        index = 0
        while index < get(w, 352):
            agent_emit_byte(w, byte(w, 1024 + index))
            index = index + 1
        agent_text(w, '/artifacts/')
    index = 0
    while index < size:
        if byte(w, name + index) == 0:
            return agent_artifact_fail(o, w, 7)
        agent_emit_byte(w, byte(w, name + index))
        index = index + 1
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    aset(w, 808, aget(w, 112) - start)
    put(w, 160, aget(w, 112))
    put(w, 24, 401)
    return fd_buffer_effect(o, w, 17, 65, 657408, 0, start, aget(w, 808))

def agent_fd_resources(s:readbuf, w:mutbuf) -> u64:
    phase = get(w, 24)
    op = read_word(s, 8)
    role = read_word(s, 32)
    slot = read_word(s, 40)
    generation = read_word(s, 48)
    if op >= 30 and op <= 32:
        return choose(phase == op + 391 and role == 0 and slot == 0 and generation == 0 and read_word(s, 56) == 0, 1, 0)
    if op == 26:
        return choose((phase == 403 or phase == 410 or phase == 420 or phase == 424) and role == 0 and slot == 0 and generation == 0, 1, 0)
    if op == 28:
        return choose((phase == 404 or phase == 406 or phase == 409) and role == 0 and slot == 0 and generation == 0, 1, 0)
    if role != 65 or slot != 1 or read_word(s, 56) != 0:
        return 0
    if op == 17:
        if phase != 401 or get(w, 432) != 0:
            return 0
        if read_word(s, 24) != 0:
            return choose(generation == get(w, 408), 1, 0)
        return choose(get(w, 408) != 18446744073709551615 and generation != 0 and generation == get(w, 408) + 1, 1, 0)
    if generation == 0 or generation != get(w, 408) or get(w, 432) != 1:
        return 0
    if op == 18:
        return choose(phase == 402 or phase == 407, 1, 0)
    if op == 19:
        return choose(phase == 405, 1, 0)
    if op == 24:
        return choose(phase == 408 or phase == 411, 1, 0)
    return 0

def agent_file_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 24)
    rc = read_word(s, 24)
    size = read_word(s, 128)
    if phase == 401:
        if rc != 0:
            return agent_artifact_fail(o, w, 6)
        if size != 0:
            return agent_fence(o, w, 6)
        put(w, 408, read_word(s, 48))
        put(w, 432, 1)
        put(w, 24, 402)
        return fd_effect(o, w, 18, 65, 0, 0, 0)
    if phase == 402:
        if rc != 0:
            return agent_artifact_fail(o, w, 6)
        if size != 144:
            return agent_fence(o, w, 6)
        # Original os.fdopen rejects directories before stable_read's file gate.
        if (read_word(s, 160) & 61440) == 16384:
            return agent_artifact_fail(o, w, 6)
        if (read_word(s, 160) & 61440) != 32768 or read_word(s, 184) > 67108864:
            return agent_artifact_fail(o, w, 3)
        copy_source(s, w, 136, get(w, 368) + 2560, 144)
        aset(w, 816, get(w, 160))
        aset(w, 824, 0)
        aset(w, 832, read_word(s, 184))
        if get(w, 160) > 18446744073642442750:
            return agent_fence(o, w, 6)
        aset(w, 856, get(w, 160) + 67108865)
        put(w, 24, 403)
        return effect(o, w, 26, 0, aget(w, 856), 0, 0)
    if phase == 403:
        if rc != 0 or size != 0 or read_word(s, 64) < aget(w, 856) or length(w) < aget(w, 856):
            return agent_fence(o, w, 6)
        fill_range(w, get(w, 368) + 2816, 1184, 0)
        return agent_sha(o, w, 0, 0, 0, 404)
    if phase == 404 or phase == 406:
        if agent_sha_accept(s, w, 0) == 0:
            return agent_fence(o, w, 6)
        if aget(w, 824) == 67108865:
            put(w, 24, 407)
            return fd_effect(o, w, 18, 65, 0, 0, 0)
        put(w, 24, 405)
        remaining = 67108865 - aget(w, 824)
        return fd_effect(o, w, 19, 65, choose(remaining < 65536, remaining, 65536), 0, 0)
    if phase == 405:
        if rc != 0:
            return agent_artifact_fail(o, w, 6)
        remaining = 67108865 - aget(w, 824)
        if size > 65536 or size > remaining:
            return agent_fence(o, w, 6)
        if size == 0:
            put(w, 24, 407)
            return fd_effect(o, w, 18, 65, 0, 0, 0)
        at = aget(w, 816) + aget(w, 824)
        copy_source(s, w, 136, at, size)
        aset(w, 824, aget(w, 824) + size)
        return agent_sha(o, w, 1, at, size, 406)
    if phase == 407:
        if rc != 0:
            return agent_artifact_fail(o, w, 6)
        if size != 144:
            return agent_fence(o, w, 6)
        if agent_file_identity(s, w) == 0:
            return agent_artifact_fail(o, w, 4)
        put(w, 24, 408)
        return fd_effect(o, w, 24, 65, 0, 0, 0)
    if phase == 408:
        put(w, 432, 0)
        if size != 0:
            return agent_fence(o, w, 6)
        if rc != 0:
            return agent_artifact_fail(o, w, 6)
        return agent_sha(o, w, 2, 0, 0, 409)
    if phase == 409:
        if agent_sha_accept(s, w, 32) == 0:
            return agent_fence(o, w, 6)
        if agent_file_digest(w, get(w, 368) + 2688) == 0:
            return agent_artifact_fail(o, w, 5)
        if aget(w, 880) != 0:
            return agent_metadata_start(o, w)
        return agent_artifact_ready(o, w)
    if phase == 410:
        if rc != 0 or size != 0 or read_word(s, 72) < aget(w, 864) or length(o) < aget(w, 864):
            return agent_fence(o, w, 6)
        return agent_artifact_publish(o, w)
    if phase == 411:
        put(w, 432, 0)
        if size != 0:
            return agent_fence(o, w, 6)
        if rc != 0:
            aset(w, 840, 6)
        return agent_artifact_error(o, w)
    return 4294967295

def agent_file_identity(s:readbuf, w:mutbuf) -> u64:
    if aget(w, 824) != aget(w, 832):
        return 0
    before = get(w, 368) + 2560
    if read_word(s, 136) != get(w, before) or read_word(s, 144) != get(w, before + 8):
        return 0
    if read_word(s, 184) != get(w, before + 48):
        return 0
    # Python compares st_mtime_ns and st_ctime_ns, not access time or mode.
    if read_word(s, 224) != get(w, before + 88) or read_word(s, 232) != get(w, before + 96):
        return 0
    if read_word(s, 240) != get(w, before + 104) or read_word(s, 248) != get(w, before + 112):
        return 0
    return 1

def agent_sha(o:mutbuf, w:mutbuf, command:u64, at:u64, size:u64, continuation:u64) -> u32:
    if size > 65536 or at > length(w) or size > length(w) - at:
        return 4294967295
    extent = widen(effect(o, w, 28, 0, command, 0, 1185 + size))
    if extent >= 4294967292:
        return extent
    copy_private(w, o, get(w, 368) + 2816, 136, 1184)
    store(o, 1320, command)
    copy_private(w, o, at, 1321, size)
    put(w, 24, continuation)
    return extent

def agent_sha_accept(s:readbuf, w:mutbuf, expected:u64) -> u64:
    if read_word(s, 24) != expected or read_word(s, 128) != 1184 + expected:
        return 0
    copy_source(s, w, 136, get(w, 368) + 2816, 1184)
    if expected == 32:
        copy_source(s, w, 1320, get(w, 368) + 2688, 32)
    return 1

def agent_file_digest(w:mutbuf, digest:u64) -> u64:
    if aget(w, 168) != 64:
        return 0
    at = aget(w, 160)
    index = 0
    while index < 32:
        value = byte(w, digest + index)
        high = value >> 4
        low = value & 15
        if byte(w, at + index * 2) != choose(high < 10, 48 + high, 87 + high):
            return 0
        if byte(w, at + index * 2 + 1) != choose(low < 10, 48 + low, 87 + low):
            return 0
        index = index + 1
    return 1

def agent_artifact_ready(o:mutbuf, w:mutbuf) -> u32:
    # Raw metadata remains a separate, ordered real dependency. This receipt
    # never says that metadata/whole Core has passed merely because SHA did.
    payload = 96 + aget(w, 824)
    index = 0
    while index < 4:
        extent = aget(w, 144 + index * 24)
        if extent > 18446744073709551615 - payload:
            return agent_fence(o, w, 6)
        payload = payload + extent
        index = index + 1
    if payload > 18446744073709551479 or aget(w, 240) > 18446744073709551479 - payload:
        return agent_fence(o, w, 6)
    payload = payload + aget(w, 240)
    aset(w, 864, payload + 136)
    put(w, 24, 410)
    return effect(o, w, 26, 0, 0, payload + 136, 0)

def agent_artifact_publish(o:mutbuf, w:mutbuf) -> u32:
    payload = aget(w, 864) - 136
    count = widen(effect(o, w, 0, 0, 17, 0, payload))
    if count >= 4294967292:
        return count
    put(o, 136, FILE_MAGIC)
    put(o, 144, 1)
    put(o, 152, aget(w, 824))
    put(o, 160, aget(w, 240))
    put(o, 168, aget(w, 224))
    index = 0
    while index < 4:
        put(o, 176 + index * 8, aget(w, 144 + index * 24))
        index = index + 1
    put(o, 208, aget(w, 200))
    put(o, 216, 0)
    put(o, 224, 0)
    at = 232
    copy_private(w, o, aget(w, 816), at, aget(w, 824))
    at = at + aget(w, 824)
    copy_private(w, o, aget(w, 232), at, aget(w, 240))
    at = at + aget(w, 240)
    index = 0
    while index < 4:
        extent = aget(w, 144 + index * 24)
        copy_private(w, o, aget(w, 136 + index * 24), at, extent)
        at = at + extent
        index = index + 1
    put(w, 24, 0)
    return count

def agent_artifact_fail(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    aset(w, 840, reason)
    if get(w, 432) != 0:
        put(w, 24, 411)
        return fd_effect(o, w, 24, 65, 0, 0, 0)
    return agent_artifact_error(o, w)

def agent_artifact_error(o:mutbuf, w:mutbuf) -> u32:
    start = get(w, 160)
    aset(w, 112, start)
    aset(w, 120, 0)
    reason = aget(w, 840)
    if reason == 1:
        agent_text(w, '{"code":"E_HIA_ARTIFACT_IDENTITY","message":"artifact reference was not issued in this runtime namespace"}')
    elif reason == 2:
        return agent_artifact_authority(o, w)
    elif reason == 3:
        agent_text(w, '{"code":"E_HIA_ARTIFACT_FILE","message":"artifact is not a bounded ordinary file"}')
    elif reason == 4:
        agent_text(w, '{"code":"E_HIA_ARTIFACT_CHANGED","message":"artifact changed while it was read"}')
    elif reason == 5:
        agent_text(w, '{"code":"E_HIA_ARTIFACT_CORRUPT","message":"artifact bytes no longer match their recorded digest"}')
    elif reason == 6:
        agent_text(w, '{"code":"E_HIA_ARTIFACT_FILE","message":"cannot read authorized ordinary artifact"}')
    elif reason == 7:
        agent_text(w, '{"code":"E_HIA_REJECTED","message":"embedded null byte"}')
    else:
        return agent_fence(o, w, 6)
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    return response(o, w, 18, start, aget(w, 112) - start)

def agent_artifact_authority(o:mutbuf, w:mutbuf) -> u32:
    message = get(w, 160)
    aset(w, 112, message)
    aset(w, 120, 0)
    agent_text(w, 'input bytes cannot impersonate a retained ')
    base = get(w, 136)
    index = 0
    at = field_start(w, base, 3)
    size = field_size(w, base, 3)
    while index < size:
        agent_emit_byte(w, byte(w, at + index))
        index = index + 1
    extent = aget(w, 112) - message
    start = aget(w, 112)
    agent_text(w, '{"code":"E_HIA_ARTIFACT_AUTHORITY","message":')
    agent_string(w, message, extent)
    agent_text(w, '}')
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    return response(o, w, 18, start, aget(w, 112) - start)

def agent_metadata_start(o:mutbuf, w:mutbuf) -> u32:
    kind = aget(w, 224)
    if kind != 3 and kind != 4:
        return agent_metadata_error(o, w, 1)
    size = aget(w, 240)
    if agent_column_utf8(w, aget(w, 232), size) != 0:
        return agent_metadata_error(o, w, 2)
    if size > 8388608:
        return agent_metadata_error(o, w, 3)
    bound = ((size + 1) >> 1) + 1
    if bound > 262144:
        bound = 262144
    end = aget(w, 816) + aget(w, 824)
    if end < aget(w, 816) or end > 18446744073709551608:
        return agent_fence(o, w, 6)
    transform = (end + 7) & 18446744073709551608
    if transform > 18446744073709551608 - size:
        return agent_fence(o, w, 6)
    arena = (transform + size + 7) & 18446744073709551608
    capacity = 64 + bound * 56 + size
    if arena > 18446744073709551608 - capacity:
        return agent_fence(o, w, 6)
    end = (arena + capacity + 7) & 18446744073709551608
    if end > 18446744073709551615 - bound * 8:
        return agent_fence(o, w, 6)
    aset(w, 896, transform)
    aset(w, 912, arena)
    aset(w, 952, end + bound * 8)
    put(w, 24, 420)
    return effect(o, w, 26, 0, aget(w, 952), size + 136, 0)

def agent_number_end(w:mutbuf, at:u64, size:u64, index:u64) -> u64:
    start = index
    aset(w, 976, 0)
    if byte(w, at + index) == 45:
        index = index + 1
    if index >= size or byte(w, at + index) < 48 or byte(w, at + index) > 57:
        return start
    if byte(w, at + index) == 48:
        index = index + 1
    else:
        while index < size and byte(w, at + index) >= 48 and byte(w, at + index) <= 57:
            index = index + 1
    if index + 1 < size and byte(w, at + index) == 46 and byte(w, at + index + 1) >= 48 and byte(w, at + index + 1) <= 57:
        aset(w, 976, 1)
        index = index + 2
        while index < size and byte(w, at + index) >= 48 and byte(w, at + index) <= 57:
            index = index + 1
    if index < size and (byte(w, at + index) == 69 or byte(w, at + index) == 101):
        cursor = index + 1
        if cursor < size and (byte(w, at + cursor) == 43 or byte(w, at + cursor) == 45):
            cursor = cursor + 1
        if cursor < size and byte(w, at + cursor) >= 48 and byte(w, at + cursor) <= 57:
            aset(w, 976, 1)
            index = cursor + 1
            while index < size and byte(w, at + index) >= 48 and byte(w, at + index) <= 57:
                index = index + 1
    return index

def agent_metadata_transform(w:mutbuf) -> u64:
    at = aget(w, 232)
    size = aget(w, 240)
    target = aget(w, 896)
    index = 0
    used = 0
    while index < size:
        begin = index
        value = byte(w, at + index)
        if value == 34:
            index = index + 1
            going = True
            while going and index < size:
                value = byte(w, at + index)
                if value == 92:
                    index = index + 2
                elif value == 34:
                    index = index + 1
                    going = False
                else:
                    index = index + 1
            if index > size:
                index = size
        elif value == 45 or (value >= 48 and value <= 57):
            index = agent_number_end(w, at, size, index)
            if index == begin:
                index = index + 1
            elif aget(w, 976) != 0:
                store(w, target + used, 48)
                used = used + 1
                begin = index
        else:
            index = index + 1
        while begin < index:
            store(w, target + used, byte(w, at + begin))
            used = used + 1
            begin = begin + 1
    aset(w, 904, used)
    return used

def agent_metadata_event(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 24)
    code = read_word(s, 24)
    size = read_word(s, 128)
    if phase == 420:
        if code != 0 or size != 0 or length(w) < aget(w, 952) or read_word(s, 64) < aget(w, 952) or length(o) < aget(w, 240) + 136:
            return agent_fence(o, w, 6)
        agent_metadata_transform(w)
        put(w, 24, 421)
        return buffer_effect(o, w, 30, 0, 262144, 128, aget(w, 896), aget(w, 904))
    if phase == 421:
        if size != 16:
            return agent_fence(o, w, 6)
        reason = read_word(s, 136)
        if code == 1:
            if reason < 1 or reason > 20:
                return agent_fence(o, w, 6)
            aset(w, 968, reason)
            return agent_metadata_error(o, w, 6)
        if reason != 0:
            return agent_fence(o, w, 6)
        if code == 2:
            return agent_metadata_error(o, w, 4)
        if code == 4:
            return agent_metadata_error(o, w, 5)
        if code != 0:
            return agent_fence(o, w, 6)
        put(w, 24, 422)
        return buffer_effect(o, w, 31, 0, 262144, 128, aget(w, 896), aget(w, 904))
    if phase == 422:
        if code != size or size < 64 or size > aget(w, 952) - aget(w, 912):
            return agent_fence(o, w, 6)
        if read_word(s, 136) != 3549210620639398216 or read_word(s, 184) != 1 or read_word(s, 192) != 0:
            return agent_fence(o, w, 6)
        nodes = read_word(s, 144)
        if nodes < 1 or nodes > 262144 or read_word(s, 152) != 64 + nodes * 56:
            return agent_fence(o, w, 6)
        if read_word(s, 160) != size or read_word(s, 168) != size or read_word(s, 176) != aget(w, 904) or size < 64 + nodes * 56:
            return agent_fence(o, w, 6)
        if size > 64 + nodes * 56 + aget(w, 904):
            return agent_fence(o, w, 6)
        bits = (aget(w, 912) + size + 7) & 18446744073709551608
        if bits > length(w) or nodes * 8 > length(w) - bits:
            return agent_fence(o, w, 6)
        copy_source(s, w, 136, aget(w, 912), size)
        fill_range(w, bits, nodes * 8, 0)
        aset(w, 920, size)
        aset(w, 928, nodes)
        aset(w, 936, bits)
        aset(w, 944, 0)
        aset(w, 992, 0)
        aset(w, 1000, 0)
        put(w, aget(w, 912) + 40, aget(w, 240))
        return agent_metadata_numbers(o, w)
    if phase == 423:
        if code == 4294967292:
            if size != 0:
                return agent_fence(o, w, 6)
            return agent_metadata_error(o, w, 8)
        if code != 8 or size != 8:
            return agent_fence(o, w, 6)
        bits = read_word(s, 136)
        if ((bits >> 52) & 2047) == 2047:
            return agent_fence(o, w, 6)
        put(w, aget(w, 936) + aget(w, 944) * 8, bits)
        if aget(w, 1008) != aget(w, 1016):
            return agent_metadata_bad_tail(o, w)
        aset(w, 944, aget(w, 944) + 1)
        return agent_metadata_numbers(o, w)
    if phase == 424:
        if code != 0 or size != 0 or read_word(s, 72) < aget(w, 864) or length(o) < aget(w, 864):
            return agent_fence(o, w, 6)
        return agent_metadata_publish(o, w)
    return 4294967295

def agent_metadata_numbers(o:mutbuf, w:mutbuf) -> u32:
    index = aget(w, 944)
    while index < aget(w, 928):
        record = aget(w, 912) + 64 + index * 56
        kind = get(w, record)
        if kind > 6:
            return agent_fence(o, w, 6)
        if kind <= 3:
            start = get(w, record + 24)
            size = get(w, record + 32)
            if size == 0 or start > aget(w, 904) or size > aget(w, 904) - start:
                return agent_fence(o, w, 6)
            raw_start = agent_metadata_boundary(w, start)
            raw_end = agent_metadata_boundary(w, start + size)
            if raw_start >= raw_end or raw_end > aget(w, 240):
                return agent_fence(o, w, 6)
            end = raw_end
            if kind == 3:
                end = agent_number_end(w, aget(w, 232), aget(w, 240), raw_start)
                if end == raw_start:
                    aset(w, 968, 1)
                    aset(w, 640, raw_start)
                    return agent_metadata_error(o, w, 9)
                if end > raw_end:
                    return agent_fence(o, w, 6)
                kind = choose(aget(w, 976) != 0, 7, 3)
                put(w, record, kind)
            put(w, record + 24, raw_start)
            put(w, record + 32, end - raw_start)
            if kind == 3 or kind == 7:
                aset(w, 944, index)
                aset(w, 1008, end)
                aset(w, 1016, raw_end)
                if kind == 7:
                    put(w, 24, 423)
                    return buffer_effect(o, w, 32, 0, 0, 0, aget(w, 232) + raw_start, end - raw_start)
                digits = end - raw_start
                if byte(w, aget(w, 232) + raw_start) == 45:
                    digits = digits - 1
                if aget(w, 888) != 0 and digits > aget(w, 888):
                    aset(w, 984, digits)
                    return agent_metadata_error(o, w, 7)
                if end != raw_end:
                    return agent_metadata_bad_tail(o, w)
        index = index + 1
    aset(w, 944, index)
    return agent_metadata_ready(o, w)


def agent_metadata_boundary(w:mutbuf, target:u64) -> u64:
    # Private monotone mapper: only complete kind 0..3 atom boundaries from
    # the actual transformed decoder. Never called for string/pool/container
    # offsets or arbitrary positions inside a quoted token.
    at = aget(w, 232)
    size = aget(w, 240)
    raw = aget(w, 992)
    checked = aget(w, 1000)
    if target < checked or target > aget(w, 904):
        return 18446744073709551615
    while checked < target:
        if raw >= size:
            return 18446744073709551615
        begin = raw
        value = byte(w, at + raw)
        replaced = False
        if value == 34:
            raw = raw + 1
            going = True
            while going and raw < size:
                value = byte(w, at + raw)
                if value == 92:
                    raw = raw + 2
                elif value == 34:
                    raw = raw + 1
                    going = False
                else:
                    raw = raw + 1
            if raw > size:
                raw = size
        elif value == 45 or (value >= 48 and value <= 57):
            raw = agent_number_end(w, at, size, raw)
            if raw == begin:
                raw = raw + 1
            elif aget(w, 976) != 0:
                replaced = True
        else:
            raw = raw + 1
        amount = choose(replaced, 1, raw - begin)
        if amount > target - checked:
            if replaced:
                return 18446744073709551615
            raw = begin + target - checked
            checked = target
        else:
            checked = checked + amount
    aset(w, 992, raw)
    aset(w, 1000, checked)
    return raw

def agent_metadata_bad_tail(o:mutbuf, w:mutbuf) -> u32:
    record = aget(w, 912) + 64 + aget(w, 944) * 56
    parent = get(w, record + 8)
    aset(w, 968, choose(parent == 18446744073709551615, 3, 2))
    aset(w, 640, aget(w, 1008))
    return agent_metadata_error(o, w, 9)

def agent_metadata_json_location(w:mutbuf) -> u64:
    at = aget(w, 232)
    position = aget(w, 640)
    index = 0
    characters = 0
    line = 1
    column = 1
    while index < position:
        value = byte(w, at + index)
        if (value & 192) != 128:
            characters = characters + 1
            if value == 10:
                line = line + 1
                column = 1
            else:
                column = column + 1
        index = index + 1
    agent_text(w, ': line ')
    agent_metadata_decimal(w, line)
    agent_text(w, ' column ')
    agent_metadata_decimal(w, column)
    agent_text(w, ' (char ')
    agent_metadata_decimal(w, characters)
    agent_text(w, ')')
    return 0

def agent_metadata_ready(o:mutbuf, w:mutbuf) -> u32:
    payload = 128 + aget(w, 824) + aget(w, 240) + aget(w, 920) + aget(w, 928) * 8
    index = 0
    while index < 4:
        size = aget(w, 144 + index * 24)
        if size > 18446744073709551479 - payload:
            return agent_fence(o, w, 6)
        payload = payload + size
        index = index + 1
    aset(w, 864, payload + 136)
    put(w, 24, 424)
    return effect(o, w, 26, 0, 0, payload + 136, 0)

def agent_metadata_publish(o:mutbuf, w:mutbuf) -> u32:
    count = widen(effect(o, w, 0, 0, 19, 0, aget(w, 864) - 136))
    if count >= 4294967292:
        return count
    put(o, 136, 3616467747162114376)
    put(o, 144, 2)
    put(o, 152, aget(w, 824))
    put(o, 160, aget(w, 240))
    put(o, 168, aget(w, 224))
    index = 0
    while index < 4:
        put(o, 176 + index * 8, aget(w, 144 + index * 24))
        index = index + 1
    put(o, 208, aget(w, 200))
    put(o, 216, 1)
    put(o, 224, aget(w, 920))
    put(o, 232, aget(w, 928))
    put(o, 240, aget(w, 928) * 8)
    put(o, 248, aget(w, 888))
    put(o, 256, 0)
    at = 264
    copy_private(w, o, aget(w, 816), at, aget(w, 824))
    at = at + aget(w, 824)
    copy_private(w, o, aget(w, 232), at, aget(w, 240))
    at = at + aget(w, 240)
    index = 0
    while index < 4:
        size = aget(w, 144 + index * 24)
        copy_private(w, o, aget(w, 136 + index * 24), at, size)
        at = at + size
        index = index + 1
    copy_private(w, o, aget(w, 912), at, aget(w, 920))
    at = at + aget(w, 920)
    copy_private(w, o, aget(w, 936), at, aget(w, 928) * 8)
    put(w, 24, 0)
    return count

def agent_metadata_decimal(w:mutbuf, value:u64) -> u64:
    at = get(w, 368) + 2496
    size = agent_decimal(w, value, at)
    index = 0
    while index < size:
        agent_emit_byte(w, byte(w, at + index))
        index = index + 1
    return 0

def agent_metadata_error(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    start = get(w, 368) + 1536
    aset(w, 112, start)
    aset(w, 120, 0)
    aset(w, 632, start + 900)
    if reason == 1:
        agent_text(w, 'JSON data must be UTF-8 bytes or text')
    elif reason == 2:
        agent_text(w, "'utf-8' codec can't decode ")
        if aget(w, 648) == aget(w, 640) + 1:
            agent_text(w, 'byte 0x')
            value = byte(w, aget(w, 232) + aget(w, 640))
            digit = value >> 4
            agent_emit_byte(w, choose(digit < 10, 48 + digit, 87 + digit))
            digit = value & 15
            agent_emit_byte(w, choose(digit < 10, 48 + digit, 87 + digit))
            agent_text(w, ' in position ')
            agent_metadata_decimal(w, aget(w, 640))
        else:
            agent_text(w, 'bytes in position ')
            agent_metadata_decimal(w, aget(w, 640))
            agent_text(w, '-')
            agent_metadata_decimal(w, aget(w, 648) - 1)
        agent_text(w, ': ')
        if aget(w, 656) == 1:
            agent_text(w, 'invalid start byte')
        elif aget(w, 656) == 2:
            agent_text(w, 'invalid continuation byte')
        elif aget(w, 656) == 3:
            agent_text(w, 'unexpected end of data')
        else:
            return agent_fence(o, w, 6)
    elif reason == 3:
        agent_text(w, 'JSON data exceeds 8 MiB')
    elif reason == 4:
        agent_text(w, 'HIA JSON exceeds node/depth budget before decoding')
    elif reason == 5:
        agent_text(w, 'HIA JSON preflight: duplicate decoded object key')
    elif reason == 6:
        agent_text(w, 'HIA JSON preflight: ')
        agent_metadata_syntax(w, aget(w, 968))
    elif reason == 7:
        agent_text(w, 'Exceeds the limit (')
        agent_metadata_decimal(w, aget(w, 888))
        agent_text(w, ' digits) for integer string conversion: value has ')
        agent_metadata_decimal(w, aget(w, 984))
        agent_text(w, ' digits; use sys.set_int_max_str_digits() to increase the limit')
    elif reason == 8:
        agent_text(w, 'nonfinite JSON number')
    elif reason == 9:
        if aget(w, 968) == 1:
            agent_text(w, 'Expecting value')
        elif aget(w, 968) == 2:
            agent_text(w, "Expecting ',' delimiter")
        elif aget(w, 968) == 3:
            agent_text(w, 'Extra data')
        else:
            return agent_fence(o, w, 6)
        agent_metadata_json_location(w)
    else:
        return agent_fence(o, w, 6)
    size = aget(w, 112) - start
    target = get(w, 368) + 2560
    aset(w, 112, target)
    aset(w, 632, get(w, 368) + 4096)
    if reason == 1 or reason == 3 or reason == 8:
        agent_text(w, '{"code":"E_HIA_JSON","message":')
    else:
        agent_text(w, '{"code":"E_HIA_REJECTED","message":')
    agent_string(w, start, size)
    agent_text(w, '}')
    aset(w, 632, 0)
    if aget(w, 120) != 0:
        return agent_fence(o, w, 6)
    return response(o, w, 18, target, aget(w, 112) - target)

def agent_metadata_syntax(w:mutbuf, reason:u64) -> u64:
    if reason == 1:
        agent_text(w, "expected JSON string")
    elif reason == 2:
        agent_text(w, "unescaped control or isolated Unicode surrogate")
    elif reason == 3:
        agent_text(w, "unterminated JSON escape")
    elif reason == 4:
        agent_text(w, "invalid JSON escape")
    elif reason == 5:
        agent_text(w, "invalid Unicode escape")
    elif reason == 6:
        agent_text(w, "unpaired high Unicode surrogate")
    elif reason == 7:
        agent_text(w, "unpaired low Unicode surrogate")
    elif reason == 8:
        agent_text(w, "unterminated JSON string")
    elif reason == 9:
        agent_text(w, "missing JSON value")
    elif reason == 10:
        agent_text(w, "expected JSON integer or literal")
    elif reason == 11:
        agent_text(w, "unexpected value completion")
    elif reason == 12:
        agent_text(w, "extra JSON data")
    elif reason == 13:
        agent_text(w, "incomplete JSON value")
    elif reason == 14:
        agent_text(w, "expected array separator/end")
    elif reason == 15:
        agent_text(w, "invalid array preflight state")
    elif reason == 16:
        agent_text(w, "expected object field name")
    elif reason == 17:
        agent_text(w, "expected object colon")
    elif reason == 18:
        agent_text(w, "expected object separator/end")
    elif reason == 19:
        agent_text(w, "invalid object preflight state")
    elif reason == 20:
        agent_text(w, "invalid JSON syntax or Unicode")
    return 0

'''
AGENT_STATEMENTS = {
    1: STATEMENTS[1], 2: STATEMENTS[2], 3: STATEMENTS[3],
    20: "SELECT * FROM requests WHERE key=?",
    21: "INSERT INTO requests VALUES (?,?,?,?,?,?)",
    22: "INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)",
    23: "UPDATE requests SET state='completed',response=? WHERE key=?",
    24: "SELECT * FROM artifacts WHERE id=?",
}
AGENT_COMMON = (
    'response', 'buffer_effect', 'effect', 'valid_packet', 'field_size',
    'field_start', 'copy_source', 'copy_private', 'widen', 'read_word', 'get', 'put',
    'fd_effect', 'fd_buffer_effect',
)


def column_utf8_source():
    """Reuse the actual journal codec without its cached-response session.

    Only the source span, diagnostic destinations and function names change.
    LOOKUP retains its real phase; the original journal stage-10 phase-5
    admission and cached-BLOB path are not altered.
    """
    original = {node.name: node for node in ast.parse(JOURNAL_ENTRY).body
                if isinstance(node, ast.FunctionDef)}
    signatures = {
        'utf8_failure': (('o','mutbuf'),('start','u64'),('end','u64'),('reason','u64')),
        'utf8_codec': (('s','readbuf'),('o','mutbuf')),
    }
    functions = []
    class ColumnSpan(ast.NodeTransformer):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name == 'length' and len(node.args) == 1 and ast.dump(node.args[0]) == ast.dump(ast.Name('s', ast.Load())):
                    return ast.Name('size', ast.Load())
                if name == 'byte' and ast.dump(node.args[0]) == ast.dump(ast.Name('s', ast.Load())):
                    return ast.Call(func=ast.Name('byte', ast.Load()), args=[
                        ast.Name('w', ast.Load()), ast.BinOp(ast.Name('at', ast.Load()),
                        ast.Add(), self.visit(node.args[1]))], keywords=[])
                if name == 'put' and ast.dump(node.args[0]) == ast.dump(ast.Name('o', ast.Load())):
                    if (len(node.args) != 3 or not isinstance(node.args[1], ast.Constant)
                            or node.args[1].value not in (16777216,16777224,16777232)):
                        raise ValueError('journal UTF-8 diagnostic layout changed')
                    return ast.Call(func=ast.Name('aset', ast.Load()), args=[
                        ast.Name('w', ast.Load()), ast.Constant(640 + node.args[1].value - 16777216),
                        self.visit(node.args[2])], keywords=[])
                if name == 'utf8_failure':
                    if len(node.args) != 4 or ast.dump(node.args[0]) != ast.dump(ast.Name('o', ast.Load())):
                        raise ValueError('journal UTF-8 failure call changed')
                    return ast.Call(func=ast.Name('agent_column_utf8_failure', ast.Load()),
                        args=[ast.Name('w', ast.Load())]+[self.visit(arg) for arg in node.args[1:]], keywords=[])
            return self.generic_visit(node)
    for name in ('utf8_failure','utf8_codec'):
        node = original[name]
        actual = tuple((arg.arg, arg.annotation.id) for arg in node.args.args)
        if actual != signatures[name] or node.returns.id != 'u64':
            raise ValueError('journal UTF-8 helper signature changed')
        node = deepcopy(node)
        node.body = [ColumnSpan().visit(statement) for statement in node.body]
        if name == 'utf8_codec':
            node.name = 'agent_column_utf8'
            node.args.args = [ast.arg(arg='w',annotation=ast.Name('mutbuf',ast.Load())),
                             ast.arg(arg='at',annotation=ast.Name('u64',ast.Load())),
                             ast.arg(arg='size',annotation=ast.Name('u64',ast.Load()))]
        else:
            node.name = 'agent_column_utf8_failure'
            node.args.args[0] = ast.arg(arg='w',annotation=ast.Name('mutbuf',ast.Load()))
        if any(isinstance(part,ast.Name) and part.id in ('s','o') for part in ast.walk(node)):
            raise ValueError('journal UTF-8 source/diagnostic alias was not relocated')
        functions.append(node)
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])))


POLICY_SOURCE = r'''
def rollback_policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    bound = ((length(s) + 1) >> 1) + 1
    if bound > 262144:
        bound = 262144
    if length(s) > 8388608 or length(o) < 4194304 or length(w) < 64 + bound * 56 + length(s) + 32768:
        return 4294967293
    private = length(w) - 32768
    policy_put(w, private, 0)
    policy_put(w, private + 8, 0)
    policy_put(w, private + 16, 0)
    policy_put(w, private + 24, 0)
    policy_put(o, 48, 262144)
    policy_put(o, 56, 128)
    code = policy_widen(decode_json(s, w, o))
    if code >= 4294967292:
        return code
    if policy_kind(w, 0) != 6:
        return 4294967295
    arguments = policy_field(w, 0, 2)
    tool = policy_field(w, 0, 1)
    if arguments == 18446744073709551615 or policy_kind(w, tool) != 4:
        return 4294967295
    if policy_match(w, policy_get(w, 64 + tool * 56 + 24), policy_get(w, 64 + tool * 56 + 32), 19) == 0:
        return 4294967295
    if policy_schema_0(w, arguments) != 0:
        return policy_publish_error(o, w, 1)
    catalog = policy_field(w, arguments, 3)
    if policy_match(w, policy_get(w, 64 + catalog * 56 + 24), policy_get(w, 64 + catalog * 56 + 32), 20) == 0:
        policy_message_literal(w, 'tool catalog digest differs from installed catalog')
        return policy_publish_error(o, w, 2)
    return policy_publish_fields(o, w, arguments)

def policy_widen(value:u32) -> u64:
    return value

def policy_get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def policy_put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value >> (index * 8))
        index = index + 1
    return value

def policy_kind(w:mutbuf, node:u64) -> u64:
    if node == 18446744073709551615:
        return 18446744073709551615
    return policy_get(w, 64 + node * 56)

def policy_field(w:mutbuf, node:u64, name:u64) -> u64:
    if policy_kind(w, node) != 6:
        return 18446744073709551615
    child = policy_get(w, 64 + node * 56 + 24)
    while child != 18446744073709551615:
        record = 64 + child * 56
        if policy_match(w, policy_get(w, record + 40), policy_get(w, record + 48), name) != 0:
            return child
        child = policy_get(w, record + 16)
    return 18446744073709551615

def policy_message_byte(w:mutbuf, value:u64) -> u64:
    private = length(w) - 32768
    size = policy_get(w, private)
    characters = policy_get(w, private + 8)
    if (value & 192) != 128:
        if characters == 4096:
            policy_put(w, private + 24, 1)
            return 0
        characters = characters + 1
        policy_put(w, private + 8, characters)
    if policy_get(w, private + 24) != 0:
        return 0
    if size >= 16384:
        policy_put(w, private + 16, 1)
        return 0
    store(w, private + 256 + size, value)
    policy_put(w, private, size + 1)
    return 0

def policy_message_word(w:mutbuf, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        policy_message_byte(w, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def policy_message_span(w:mutbuf, at:u64, size:u64) -> u64:
    if at > length(w) or size > length(w) - at:
        return 1
    index = 0
    while index < size and policy_get(w, length(w) - 32768 + 24) == 0:
        policy_message_byte(w, byte(w, at + index))
        index = index + 1
    return 0

def policy_string_length(w:mutbuf, at:u64, size:u64) -> u64:
    count = 0
    index = 0
    while index < size:
        if (byte(w, at + index) & 192) != 128:
            count = count + 1
        index = index + 1
    return count

def policy_pattern(w:mutbuf, at:u64, extent:u64, pattern:u64) -> u64:
    # Python re.search uses $ rather than fullmatch: one final LF may follow
    # the exact ASCII matched body. Later u64 admission remains separate.
    size = extent
    if size != 0 and byte(w, at + size - 1) == 10:
        size = size - 1
    if pattern == 1:
        if size != 64:
            return 0
        index = 0
        while index < size:
            ch = byte(w, at + index)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                return 0
            index = index + 1
        return 1
    if pattern == 2:
        if size == 0 or size > 192:
            return 0
        index = 0
        while index < size:
            ch = byte(w, at + index)
            alpha = (ch >= 48 and ch <= 57) or (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122)
            if alpha == False:
                if index == 0:
                    return 0
                if ch != 95 and ch != 46 and ch != 58 and ch != 47 and ch != 45:
                    return 0
            index = index + 1
        return 1
    if pattern == 3:
        if size == 0 or size > 20:
            return 0
        if byte(w, at) == 48:
            return choose(size == 1, 1, 0)
        if byte(w, at) < 49 or byte(w, at) > 57:
            return 0
        index = 1
        while index < size:
            if byte(w, at + index) < 48 or byte(w, at + index) > 57:
                return 0
            index = index + 1
        return 1
    return 0

def policy_output_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    private = length(w) - 32768
    at = policy_get(w, private + 32)
    if at >= length(o):
        policy_put(w, private + 16, 1)
        return 0
    store(o, at, value)
    policy_put(w, private + 32, at + 1)
    return 0

def policy_output_word(o:mutbuf, w:mutbuf, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        policy_output_byte(o, w, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def policy_json_string(o:mutbuf, w:mutbuf, at:u64, size:u64) -> u64:
    policy_output_byte(o, w, 34)
    index = 0
    while index < size:
        value = byte(w, at + index)
        if value == 34 or value == 92:
            policy_output_byte(o, w, 92)
            policy_output_byte(o, w, value)
        elif value < 32:
            policy_output_byte(o, w, 92)
            if value == 8:
                policy_output_byte(o, w, 98)
            elif value == 9:
                policy_output_byte(o, w, 116)
            elif value == 10:
                policy_output_byte(o, w, 110)
            elif value == 12:
                policy_output_byte(o, w, 102)
            elif value == 13:
                policy_output_byte(o, w, 114)
            else:
                policy_output_word(o, w, 3158133, 3)
                policy_output_byte(o, w, 48 + (value >> 4))
                low = value & 15
                policy_output_byte(o, w, choose(low < 10, 48 + low, 87 + low))
        else:
            policy_output_byte(o, w, value)
        index = index + 1
    policy_output_byte(o, w, 34)
    return 0

def policy_publish_header(o:mutbuf, w:mutbuf, status:u64, fields:u64) -> u32:
    if policy_get(w, length(w) - 32768 + 16) != 0:
        return 4294967293
    size = policy_get(w, length(w) - 32768 + 32)
    if size < 64 or size > length(o) or size > 8388608:
        return 4294967293
    index = 0
    while index < 64:
        store(o, index, 0)
        index = index + 1
    policy_put(o, 0, POLICY_MAGIC)
    policy_put(o, 8, status)
    policy_put(o, 16, fields)
    policy_put(o, 24, size - 64)
    return size

def policy_publish_error(o:mutbuf, w:mutbuf, code:u64) -> u32:
    private = length(w) - 32768
    policy_put(w, private + 32, 64)
    if code == 1:
        policy_text(o, w, '{"code":"E_HIA_SCHEMA","details_artifact":null,"message":')
    elif code == 2:
        policy_text(o, w, '{"code":"E_HIA_CATALOG_STALE","details_artifact":null,"message":')
    else:
        return 4294967295
    policy_json_string(o, w, private + 256, policy_get(w, private))
    policy_text(o, w, ',"phase":"admission","retry_action":"correct_input"}')
    return policy_publish_header(o, w, 1, 0)

def policy_publish_fields(o:mutbuf, w:mutbuf, arguments:u64) -> u32:
    private = length(w) - 32768
    policy_put(w, private + 32, 136)
    index = 0
    while index < 9:
        node = policy_result_node(w, arguments, index)
        if policy_kind(w, node) != 4:
            return 4294967295
        record = 64 + node * 56
        at = policy_get(w, record + 24)
        size = policy_get(w, record + 32)
        policy_put(o, 64 + index * 8, size)
        cursor = 0
        while cursor < size:
            policy_output_byte(o, w, byte(w, at + cursor))
            cursor = cursor + 1
        index = index + 1
    return policy_publish_header(o, w, 0, 9)

def policy_result_node(w:mutbuf, arguments:u64, index:u64) -> u64:
    if index == 0:
        return policy_field(w, arguments, 3)
    if index == 1:
        return policy_field(w, policy_field(w, arguments, 4), 10)
    if index == 2:
        return policy_field(w, policy_field(w, arguments, 4), 11)
    if index == 3:
        return policy_field(w, policy_field(w, arguments, 5), 13)
    if index == 4:
        return policy_field(w, policy_field(w, arguments, 5), 12)
    if index == 5:
        return policy_field(w, arguments, 8)
    if index == 6:
        return policy_field(w, arguments, 6)
    if index == 7:
        return policy_field(w, arguments, 7)
    if index == 8:
        return policy_field(w, arguments, 9)
    return 18446744073709551615
'''

POLICY_MAGIC = int.from_bytes(b"HIASQPL1", "little")
POLICY_KEYS = {
    "tool": 1, "arguments": 2, "catalog_sha256": 3, "context": 4,
    "expected_current": 5, "reason": 6, "request_key": 7,
    "retained_generation": 8, "target_slot": 9, "id": 10,
    "sha256": 11, "epoch": 12, "generation": 13,
}
POLICY_PATTERNS = {
    r"^[0-9a-f]{64}$": 1,
    r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$": 2,
    r"^(0|[1-9][0-9]{0,19})$": 3,
}

def rollback_schema_program():
    """Compile the actual fixed catalog schema; no runtime Python validator."""
    import json
    catalog = json.loads((ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes())
    candidates = [tool for tool in catalog['tools'] if tool['name'] == 'hia_rollback']
    if len(candidates) != 1:
        raise ValueError('rollback catalog owner is not unique')
    schema = candidates[0]['inputSchema']
    functions = []
    def emit_schema(value, label):
        number = len(functions)
        functions.append(None)
        typ = value.get('type')
        allowed = {'type','$schema','description'}
        allowed |= ({'properties','required','additionalProperties'} if typ == 'object'
                    else {'pattern','minLength','maxLength'})
        if set(value) - allowed or typ not in ('object','string'):
            raise ValueError('rollback schema requires an unimplemented rule')
        lines = [f'def policy_schema_{number}(w:mutbuf, node:u64) -> u64:',
                 f'    if policy_kind(w, node) != {6 if typ=="object" else 4}:',
                 f'        policy_message_literal(w, {repr(label+": expected "+typ)})',
                 '        return 1']
        if typ == 'object':
            properties = value['properties']
            if value.get('additionalProperties') is not False:
                raise ValueError('rollback object must preserve its exact closed shape')
            if any(name not in POLICY_KEYS for name in properties):
                raise ValueError('rollback property has no exact native key identifier')
            required = sorted(value.get('required', []))
            if not set(required) <= set(properties):
                raise ValueError('required rollback key lacks its declared schema')
            lines += ['    missing = False']
            for name in required:
                lines += [f'    if policy_field(w, node, {POLICY_KEYS[name]}) == 18446744073709551615:',
                          '        if missing:',
                          "            policy_message_literal(w, ', ')",
                          '        else:',
                          f'            policy_message_literal(w, {repr(label+": missing fields ")})',
                          f'        policy_message_literal(w, {repr(name)})',
                          '        missing = True']
            lines += ['    if missing:', '        return 1',
                      '    child = policy_get(w, 64 + node * 56 + 24)',
                      '    while child != 18446744073709551615:',
                      '        record = 64 + child * 56',
                      '        at = policy_get(w, record + 40)',
                      '        size = policy_get(w, record + 48)']
            for i, (name, child_schema) in enumerate(properties.items()):
                child_function = emit_schema(child_schema, label+'.'+name)
                lines += [f'        {"if" if i==0 else "elif"} policy_match(w, at, size, {POLICY_KEYS[name]}) != 0:',
                          f'            if policy_schema_{child_function}(w, child) != 0:',
                          '                return 1']
            lines += ['        else:',
                      f'            policy_message_literal(w, {repr(label+": unknown field ")})',
                      '            policy_message_span(w, at, size)',
                      '            return 1',
                      '        child = policy_get(w, record + 16)']
        else:
            lines += ['    at = policy_get(w, 64 + node * 56 + 24)',
                      '    size = policy_get(w, 64 + node * 56 + 32)']
            if 'minLength' in value or 'maxLength' in value:
                minimum,maximum = value.get('minLength',0),value.get('maxLength',(1<<63))
                if type(minimum) is not int or type(maximum) is not int:
                    raise ValueError('non-integer declared character bound')
                lines += ['    characters = policy_string_length(w, at, size)',
                          f'    if characters < {minimum} or characters > {maximum}:',
                          f'        policy_message_literal(w, {repr(label+": string length is outside limits")})',
                          '        return 1']
            if 'pattern' in value:
                if value['pattern'] not in POLICY_PATTERNS:
                    raise ValueError('rollback pattern has no exact native implementation')
                lines += [f'    if policy_pattern(w, at, size, {POLICY_PATTERNS[value["pattern"]]}) == 0:',
                          f'        policy_message_literal(w, {repr(label+": string does not match the declared pattern")})',
                          '        return 1']
        lines += ['    return 0']
        functions[number] = '\n'.join(lines)
        return number
    if emit_schema(schema, 'arguments') != 0:
        raise AssertionError('rollback schema root changed')
    return '\n\n'.join(functions)

def rollback_match_program():
    from hashlib import sha256
    values = dict(POLICY_KEYS)
    values['hia_rollback'] = 19
    values[sha256((ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()).hexdigest()] = 20
    lines = ['def policy_match(w:mutbuf, at:u64, size:u64, name:u64) -> u64:']
    helpers = []
    for text,number in sorted(values.items(), key=lambda item:item[1]):
        raw = text.encode('utf-8')
        helper = 'policy_match_' + str(number)
        lines += [f'    if name == {number}:',
                  f'        return {helper}(w, at, size)']
        body = [f'def {helper}(w:mutbuf, at:u64, size:u64) -> u64:',
                f'    if size != {len(raw)}:',
                '        return 0']
        for i,value in enumerate(raw):
            body += [f'    if byte(w, at + {i}) != {value}:',
                     '        return 0']
        body += ['    return 1']
        helpers.append('\n'.join(body))
    return '\n\n'.join(['\n'.join(lines + ['    return 0']), *helpers])


def rollback_policy_program():
    from tools.generate_hia_worker_request import data_source
    class Literals(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id in ('policy_message_literal','policy_text')):
                message = call.func.id == 'policy_message_literal'
                arguments = call.args[:-1]
                literal = call.args[-1]
                if not isinstance(literal, ast.Constant) or type(literal.value) is not str:
                    raise ValueError('policy literals must be fixed authoring bytes')
                raw = literal.value.encode('utf-8')
                name = 'policy_message_word' if message else 'policy_output_word'
                return [ast.Expr(ast.Call(ast.Name(name,ast.Load()),
                            [*deepcopy(arguments),ast.Constant(int.from_bytes(raw[i:i+8],'little')),
                             ast.Constant(len(raw[i:i+8]))],[]))
                        for i in range(0,len(raw),8)]
            return self.generic_visit(node)
    source = '\n'.join((POLICY_SOURCE.replace('POLICY_MAGIC', str(POLICY_MAGIC)),
                       rollback_schema_program(), rollback_match_program(), data_source()))
    tree = Literals().visit(ast.parse(source))
    ast.fix_missing_locations(tree)
    names = [node.name for node in tree.body]
    if len(set(names)) != len(names) or names[0] != 'rollback_policy':
        raise ValueError('native rollback policy function identity differs')
    return ast.unparse(tree)

def source_program(target='driver'):
    if target == 'policy':
        return rollback_policy_program()
    if target == 'driver':
        source, statements = SOURCE, STATEMENTS
    elif target == 'agent':
        library = {node.name: node for node in ast.parse(SOURCE).body
                   if isinstance(node, ast.FunctionDef)}
        source = AGENT_SOURCE + '\n' + column_utf8_source() + '\n' + '\n'.join(ast.unparse(library[name]) for name in AGENT_COMMON)
        statements = AGENT_STATEMENTS
        class Text(ast.NodeTransformer):
            def visit_Expr(self, node):
                call = node.value
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'agent_text':
                    workspace, literal = call.args
                    if not isinstance(literal, ast.Constant) or type(literal.value) is not str:
                        raise ValueError('only exact authoring text literals may be expanded')
                    raw = literal.value.encode('utf-8')
                    return [ast.Expr(value=ast.Call(func=ast.Name(id='agent_emit_word',ctx=ast.Load()),
                        args=[workspace,ast.Constant(int.from_bytes(raw[i:i+8],'little')),
                              ast.Constant(len(raw[i:i+8]))],keywords=[]))
                        for i in range(0,len(raw),8)]
                return self.generic_visit(node)
        source = ast.unparse(ast.fix_missing_locations(Text().visit(ast.parse(source))))
    else:
        raise ValueError('unknown closed native store component')
    for name in ('REQUEST_MAGIC', 'EVENT_MAGIC', 'EFFECT_MAGIC', 'STATE_MAGIC', 'JOURNAL_MAGIC', 'POLICY_MAGIC', 'FILE_MAGIC'):
        source = source.replace(name, str(globals()[name]))
    source = source.replace('1953459315', str(int.from_bytes(b'slot', 'little')))
    source = source.replace('7598805583366743399', str(int.from_bytes(b'generati', 'little')))
    source = source.replace('8386093273910571617', str(int.from_bytes(b'artifact', 'little')))
    source += '\ndef sql_size(index:u64) -> u64:\n'
    for index, text in statements.items():
        source += f'    if index == {index}:\n        return {len(text.encode())}\n'
    source += '    return 0\n\ndef sql_bytes(o:mutbuf, index:u64) -> u64:\n'
    for index, text in statements.items():
        source += f'    if index == {index}:\n'
        raw = text.encode()
        for start in range(0, len(raw), 8):
            chunk = raw[start:start + 8]
            if len(chunk) == 8:
                source += f'        put(o, {136 + start}, {int.from_bytes(chunk, "little")})\n'
            else:
                for j, byte in enumerate(chunk):
                    source += f'        store(o, {136 + start + j}, {byte})\n'
        source += '        return 0\n'
    source += '    return 1\n'
    return source


def document(target='driver'):
    nodes = ast.parse(source_program(target)).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    module = {'driver':'sqlite_store','agent':'sqlite_agent_transaction','policy':'sqlite_rollback_policy'}[target]
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module, 'functions': functions})


def main():
    for component, name in (('driver','sqlite_store.hepta'),('agent','sqlite_agent_transaction.hepta'),('policy','sqlite_rollback_policy.hepta')):
        target = ROOT / 'examples/hia_bootstrap' / name
        target.write_text(render_assembly(document(component)), encoding='utf-8')
        target.chmod(0o644)
        print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
