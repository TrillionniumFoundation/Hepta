"""Selected SQLite 3.46.1 filename/create-mode/URI policy in HIA.

NEW source, not executed. One serial private issuer supplies the immutable
SQLite filename allocation and a logical pointer within it. Bounded parsing
preserves databaseName, first URI-key match and sqlite3GetBoolean semantics.
Only the exact getFileMode branch emits a raw FS8 STAT_CSTR request. Full
unixOpen, real syscall joining, ordinary Store and SQL31 remain OPEN.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANCM01","little")
BAD=int.from_bytes(b"HIACMB01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
POLICY=r'''

def create_mode_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        if length(w) >= 8:
            put(w, 0, CREATE_BAD)
        return 4294967293
    if get(w, 0) == CREATE_BAD:
        return cm_emit(o, w, 4294967293, 0)
    if length(s) < 256 or length(o) < 256:
        return cm_refuse(o, w, 1)
    if read64(s, 0) != CREATE_MAGIC or read64(s, 128) != length(s) - 256:
        return cm_refuse(o, w, 2)
    if get(w, 0) == 0:
        return cm_begin(s, o, w)
    if cm_steady(w) == 0:
        return cm_refuse(o, w, 3)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24) or read64(s, 32) != get(w, 32):
        return cm_refuse(o, w, 4)
    if read64(s, 120) != get(w, 248) or read64(s, 136) != get(w, 168):
        return cm_refuse(o, w, 4)
    if get(w, 8) == 1:
        at = 0
        while at < 256:
            if read64(s, at) != get(w, 512 + at):
                return cm_refuse(o, w, 5)
            at = at + 8
        return cm_publish(s, o, w)
    if get(w, 8) != 2 or read64(s, 40) != get(w, 40) or read64(s, 48) != get(w, 48):
        return cm_refuse(o, w, 6)
    if read64(s, 8) != 2 or cm_ack_shape(s, w) == 0:
        return cm_refuse(o, w, 7)
    error = read64(s, 312)
    if error == 0:
        put(w, 64, read64(s, 336) & 511)
        put(w, 72, read64(s, 344))
        put(w, 80, read64(s, 352))
    else:
        put(w, 56, 1802)
        put(w, 88, error)
    put(w, 8, 3)
    return cm_emit(o, w, 0, 0)

def cm_zero(w:mutbuf, start:u64, count:u64) -> u64:
    stop = start + count
    while start < stop:
        put(w, start, 0)
        start = start + 8
    return 0

def cm_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = 0
    while at < 1024:
        if get(w, at) != 0:
            return cm_refuse(o, w, 8)
        at = at + 8
    if read64(s, 8) != 1 or (read64(s, 16) | read64(s, 24)) == 0 or read64(s, 32) == 0:
        return cm_refuse(o, w, 9)
    if read64(s, 40) != 0 or read64(s, 56) != 0 or read64(s, 120) == 0 or read64(s, 136) == 0:
        return cm_refuse(o, w, 9)
    op = read64(s, 48)
    n = read64(s, 80)
    keyn = read64(s, 88)
    if op < 1 or op > 3 or read64(s, 64) > 4294967295 or read64(s, 96) > 4294967295 or read64(s, 104) > 4095:
        return cm_refuse(o, w, 10)
    if n > length(s) - 256 or keyn != length(s) - 256 - n or read64(s, 112) != 0:
        return cm_refuse(o, w, 11)
    present = read64(s, 176)
    keypresent = read64(s, 184)
    if present > 1 or keypresent > 1:
        return cm_refuse(o, w, 12)
    if present == 0:
        if n != 0 or read64(s, 72) != 0:
            return cm_refuse(o, w, 12)
    elif read64(s, 72) >= n:
        return cm_refuse(o, w, 12)
    if keypresent == 0 and keyn != 0:
        return cm_refuse(o, w, 13)
    if op == 1:
        if present != 1 or keypresent != 0 or keyn != 0 or read64(s, 96) != 0 or (read64(s, 144) | read64(s, 152)) == 0:
            return cm_refuse(o, w, 14)
    else:
        if read64(s, 64) != 0 or (read64(s, 144) | read64(s, 152) | read64(s, 160) | read64(s, 168)) != 0:
            return cm_refuse(o, w, 14)
        if op == 2 and read64(s, 96) != 0:
            return cm_refuse(o, w, 14)
    at = 192
    while at < 256:
        if read64(s, at) != 0:
            return cm_refuse(o, w, 15)
        at = at + 8
    at = 0
    while at < keyn:
        if byte(s, 256 + n + at) == 0:
            return cm_refuse(o, w, 16)
        at = at + 1
    put(w, 0, CREATE_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, read64(s, 32))
    put(w, 48, op)
    put(w, 88, read64(s, 104))
    put(w, 144, 1024)
    put(w, 152, 256)
    put(w, 168, read64(s, 136))
    put(w, 176, read64(s, 144))
    put(w, 184, read64(s, 152))
    put(w, 192, read64(s, 160))
    put(w, 200, read64(s, 168))
    put(w, 208, read64(s, 64))
    put(w, 216, n)
    put(w, 224, read64(s, 72))
    put(w, 232, keyn)
    put(w, 240, read64(s, 96))
    put(w, 248, read64(s, 120))
    copy_input(w, s, 512, 0, 256)
    if op == 1:
        if cm_select_mode(s, w) == 0:
            return cm_refuse(o, w, 17)
    else:
        found = cm_find_parameter(s, w, 0)
        if found == 2:
            return cm_refuse(o, w, 18)
        if op == 2:
            if found == 1:
                value_n = get(w, 120)
                if value_n > 18446744073709551358:
                    return cm_refuse(o, w, 19)
                put(w, 152, 257 + value_n)
        else:
            value = choose(get(w, 240) != 0, 1, 0)
            if found == 1:
                value = cm_boolean(s, get(w, 112), get(w, 120), value)
            put(w, 96, value)
    return cm_publish(s, o, w)

def cm_cstrlen(s:readbuf, start:u64, n:u64) -> u64:
    if start >= n:
        return 18446744073709551615
    pos = start
    while pos < n:
        if byte(s, 256 + pos) == 0:
            return pos - start
        pos = pos + 1
    return 18446744073709551615

def cm_database(s:readbuf, pos:u64, n:u64) -> u64:
    if pos >= n:
        return 18446744073709551615
    while pos >= 4:
        if byte(s, 256 + pos - 1) == 0 and byte(s, 256 + pos - 2) == 0 and byte(s, 256 + pos - 3) == 0 and byte(s, 256 + pos - 4) == 0:
            return pos
        pos = pos - 1
    return 18446744073709551615

def cm_key_equal(s:readbuf, w:mutbuf, pos:u64, count:u64, modekey:u64) -> u64:
    if modekey != 0:
        if count != 6:
            return 0
        literal = 112628628483949
        i = 0
        while i < 6:
            if byte(s, 256 + pos + i) != ((literal >> (i * 8)) & 255):
                return 0
            i = i + 1
        return 1
    if count != get(w, 232):
        return 0
    i = 0
    while i < count:
        if byte(s, 256 + pos + i) != byte(s, 256 + get(w, 216) + i):
            return 0
        i = i + 1
    return 1

def cm_find_parameter(s:readbuf, w:mutbuf, modekey:u64) -> u64:
    if get(w, 688) == 0 or (modekey == 0 and get(w, 696) == 0):
        return 0
    n = get(w, 216)
    pos = cm_database(s, get(w, 224), n)
    if pos == 18446744073709551615:
        return 2
    count = cm_cstrlen(s, pos, n)
    if count == 18446744073709551615:
        return 2
    pos = pos + (count & 1073741823) + 1
    while pos < n:
        if byte(s, 256 + pos) == 0:
            return 0
        count = cm_cstrlen(s, pos, n)
        if count == 18446744073709551615:
            return 2
        equal = cm_key_equal(s, w, pos, count, modekey)
        pos = pos + (count & 1073741823) + 1
        value_n = cm_cstrlen(s, pos, n)
        if value_n == 18446744073709551615:
            return 2
        if equal == 1:
            put(w, 104, 1)
            put(w, 112, pos)
            put(w, 120, value_n)
            return 1
        pos = pos + (value_n & 1073741823) + 1
    return 2

def cm_select_mode(s:readbuf, w:mutbuf) -> u64:
    n = get(w, 216)
    base = get(w, 224)
    flags = get(w, 208)
    selected = 0
    start = 0
    amount = 0
    if (flags & 526336) != 0:
        count = cm_cstrlen(s, base, n)
        if count == 18446744073709551615:
            return 0
        count = count & 1073741823
        if count > 1:
            i = count - 1
            while i > 0:
                ch = byte(s, 256 + base + i)
                if ch == 46:
                    i = 0
                elif ch == 45:
                    selected = 1
                    start = base
                    amount = i
                    i = 0
                else:
                    i = i - 1
    elif (flags & 8) != 0:
        put(w, 64, 384)
    elif (flags & 64) != 0:
        found = cm_find_parameter(s, w, 1)
        if found == 2:
            return 0
        if found == 1:
            selected = 1
            start = get(w, 112)
            amount = get(w, 120)
    if selected == 1:
        if amount > 18446744073709551102:
            return 0
        put(w, 128, start)
        put(w, 136, amount)
        put(w, 152, 513 + amount)
        put(w, 280, 1)
    return 1

def cm_digit(ch:u64) -> u64:
    return choose(ch >= 48 and ch <= 57, 1, 0)

def cm_hex(ch:u64) -> u64:
    if ch >= 48 and ch <= 57:
        return ch - 48
    if ch >= 65 and ch <= 70:
        return ch - 55
    if ch >= 97 and ch <= 102:
        return ch - 87
    return 16

def cm_numeric_prefix(s:readbuf, pos:u64, n:u64) -> u64:
    if n >= 3:
        second = byte(s, 257 + pos)
        if byte(s, 256 + pos) == 48 and (second == 120 or second == 88) and cm_hex(byte(s, 258 + pos)) < 16:
            i = 2
            while i < n and byte(s, 256 + pos + i) == 48:
                i = i + 1
            value = 0
            digits = 0
            while i < n and digits < 8 and cm_hex(byte(s, 256 + pos + i)) < 16:
                value = value * 16 + cm_hex(byte(s, 256 + pos + i))
                i = i + 1
                digits = digits + 1
            if value >= 2147483648:
                return 0
            if i < n and cm_hex(byte(s, 256 + pos + i)) < 16:
                return 0
            return value
    i = 0
    while i < n and byte(s, 256 + pos + i) == 48:
        i = i + 1
    value = 0
    digits = 0
    while i < n and digits < 11 and cm_digit(byte(s, 256 + pos + i)) == 1:
        value = value * 10 + byte(s, 256 + pos + i) - 48
        i = i + 1
        digits = digits + 1
    if digits > 10 or value > 2147483647:
        return 0
    return value

def cm_word(s:readbuf, pos:u64, n:u64, literal:u64) -> u64:
    i = 0
    while i < n:
        ch = byte(s, 256 + pos + i)
        if ch >= 65 and ch <= 90:
            ch = ch + 32
        if ch != ((literal >> (i * 8)) & 255):
            return 0
        i = i + 1
    return 1

def cm_boolean(s:readbuf, pos:u64, n:u64, default:u64) -> u64:
    if n != 0 and cm_digit(byte(s, 256 + pos)) == 1:
        return choose((cm_numeric_prefix(s, pos, n) & 255) != 0, 1, 0)
    n = n & 1073741823
    if n == 2:
        if cm_word(s, pos, 2, 28271) == 1:
            return 1
        if cm_word(s, pos, 2, 28526) == 1:
            return 0
    elif n == 3:
        if cm_word(s, pos, 3, 7562617) == 1:
            return 1
        if cm_word(s, pos, 3, 6710895) == 1:
            return 0
    elif n == 4:
        if cm_word(s, pos, 4, 1702195828) == 1:
            return 1
    elif n == 5:
        if cm_word(s, pos, 5, 435728179558) == 1:
            return 0
    return default

def cm_publish(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < get(w, 152):
        return cm_emit(o, w, 2, 0)
    if get(w, 280) == 1:
        if get(w, 192) == 18446744073709551615 or get(w, 200) == 18446744073709551615:
            return cm_refuse(o, w, 20)
        put(w, 192, get(w, 192) + 1)
        put(w, 200, get(w, 200) + 1)
        put(w, 40, 1)
        put(w, 8, 2)
        cm_zero(w, 768, 256)
        put(w, 768, FILESYSTEM_MAGIC)
        put(w, 776, 2)
        put(w, 784, get(w, 176))
        put(w, 792, get(w, 184))
        put(w, 800, get(w, 192))
        put(w, 816, 29)
        put(w, 864, get(w, 136))
        put(w, 872, get(w, 40))
        cm_emit(o, w, 1, 256 + get(w, 136))
        copy_workspace(o, w, 256, 768, 256)
        copy_input(o, s, 512, 256 + get(w, 128), get(w, 136))
        return 1
    put(w, 8, 3)
    payload = 0
    if get(w, 48) == 2 and get(w, 104) == 1:
        payload = get(w, 120) + 1
    cm_emit(o, w, 0, payload)
    if payload != 0:
        copy_input(o, s, 256, 256 + get(w, 112), payload)
    return 0

def cm_steady(w:mutbuf) -> u64:
    if get(w, 0) != CREATE_MAGIC or get(w, 8) < 1 or get(w, 8) > 3:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 32) == 0 or get(w, 168) == 0 or get(w, 248) == 0:
        return 0
    if get(w, 48) < 1 or get(w, 48) > 3 or get(w, 88) > 4095 or get(w, 104) > 1 or get(w, 280) > 1 or get(w, 160) != 0:
        return 0
    if get(w, 144) != 1024 or get(w, 208) > 4294967295 or get(w, 240) > 4294967295:
        return 0
    if get(w, 104) == 1:
        if get(w, 112) >= get(w, 216) or get(w, 120) >= get(w, 216) - get(w, 112):
            return 0
    elif (get(w, 112) | get(w, 120)) != 0:
        return 0
    need = 256
    if get(w, 280) == 1:
        if get(w, 48) != 1 or (get(w, 176) | get(w, 184)) == 0:
            return 0
        if get(w, 128) > get(w, 216) or get(w, 136) > get(w, 216) - get(w, 128) or get(w, 136) > 18446744073709551102:
            return 0
        need = 513 + get(w, 136)
    elif (get(w, 128) | get(w, 136)) != 0:
        return 0
    elif get(w, 48) == 2 and get(w, 104) == 1:
        if get(w, 120) > 18446744073709551358:
            return 0
        need = 257 + get(w, 120)
    if get(w, 152) != need:
        return 0
    if get(w, 8) == 1:
        if get(w, 40) != 0 or get(w, 56) != 0:
            return 0
    elif get(w, 8) == 2:
        if get(w, 40) != 1 or get(w, 280) != 1 or get(w, 192) == 0 or get(w, 200) == 0:
            return 0
    return 1

def cm_ack_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 56) != 0:
        return 0
    at = 64
    while at < 120:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    at = 144
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    n = read64(s, 128)
    if n != 256 and n != 400:
        return 0
    if read64(s, 256) != FILESYSTEM_MAGIC or read64(s, 264) != 0:
        return 0
    if read64(s, 272) != get(w, 176) or read64(s, 280) != get(w, 184) or read64(s, 288) != get(w, 192) or read64(s, 296) != get(w, 200):
        return 0
    if read64(s, 304) != 29 or read64(s, 312) > 4095 or read64(s, 368) != get(w, 40) or read64(s, 376) != 1 or read64(s, 384) != n - 256:
        return 0
    if (read64(s, 392) | read64(s, 400) | read64(s, 408) | read64(s, 440)) != 0 or read64(s, 432) != 3:
        return 0
    at = 456
    while at < 512:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if read64(s, 312) != 0:
        if n != 256 or read64(s, 448) != 0:
            return 0
        at = 320
        while at < 368:
            if read64(s, at) != 0:
                return 0
            at = at + 8
        return 1
    if n != 400:
        return 0
    if read64(s, 320) != read64(s, 512) or read64(s, 328) != read64(s, 520) or read64(s, 448) != read64(s, 528):
        return 0
    if read64(s, 336) != (read64(s, 536) & 4294967295) or read64(s, 344) != (read64(s, 536) >> 32):
        return 0
    if read64(s, 352) != (read64(s, 544) & 4294967295) or read64(s, 360) != read64(s, 560):
        return 0
    return 1

def cm_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != CREATE_BAD:
        put(w, 160, reason)
    put(w, 0, CREATE_BAD)
    return cm_emit(o, w, 4294967293, 0)

def cm_emit(o:mutbuf, w:mutbuf, status:u64, payload:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    cm_zero(o, 0, 256)
    put(o, 0, CREATE_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 56))
    put(o, 64, get(w, 64))
    put(o, 72, get(w, 72))
    put(o, 80, get(w, 80))
    put(o, 88, get(w, 88))
    put(o, 96, get(w, 96))
    put(o, 104, get(w, 104))
    put(o, 112, get(w, 112))
    put(o, 120, get(w, 120))
    put(o, 128, payload)
    put(o, 136, get(w, 144))
    put(o, 144, get(w, 152))
    put(o, 152, get(w, 160))
    put(o, 160, get(w, 8))
    put(o, 168, get(w, 248))
    put(o, 176, get(w, 168))
    put(o, 184, get(w, 192))
    put(o, 192, get(w, 200))
    put(o, 200, get(w, 176))
    put(o, 208, get(w, 184))
    put(o, 216, get(w, 208))
    put(o, 224, get(w, 224))
    put(o, 232, get(w, 216))
    put(o, 240, 1)
    return status
'''
def source_program():
    return (POLICY.replace("CREATE_BAD",str(BAD)).replace("CREATE_MAGIC",str(MAGIC))
        .replace("FILESYSTEM_MAGIC",str(FS_MAGIC))+VALUES[VALUES.index("\ndef read64("):])
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate create-mode symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_create_mode_r1","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_create_mode_r1.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
