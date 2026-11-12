"""Complete Linux SQLite robust_open continuation, NEW source-only revision.

The HIA owner decides every EINTR retry, low-descriptor unlink/close/warning,
raw /dev/null refill, and nonzero-mode FSTAT/FCHMOD. Fixed FS6 performs only
raw syscalls and issues logical descriptor tokens. Inputs/replies are private
immutable leases from one serial native coordinator, not external authority.
Full unixOpen/URI/tempname/ordinary Store remain distinct unfinished work.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b"HIANRO01","little")
BAD=int.from_bytes(b"HIAROB01","little")
FS_MAGIC=int.from_bytes(b"HIANFR03","little")
ROBUST=r'''

def robust_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        if length(w) >= 8:
            put(w, 0, ROBUST_BAD)
        return 4294967293
    if get(w, 0) == ROBUST_BAD:
        return ro_emit(o, w, 4294967293, 0)
    if length(o) < 256 or length(s) < 256:
        return ro_refuse(o, w, 1)
    if read64(s, 0) != ROBUST_MAGIC or read64(s, 128) != length(s) - 256:
        return ro_refuse(o, w, 2)
    if get(w, 0) == 0:
        return ro_begin(s, o, w)
    if ro_steady(w) == 0:
        return ro_refuse(o, w, 3)
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24) or read64(s, 32) != get(w, 32) or read64(s, 136) != get(w, 248):
        return ro_refuse(o, w, 4)
    phase = get(w, 8)
    if phase == 1:
        at = 0
        while at < 256:
            if read64(s, at) != get(w, 256 + at):
                return ro_refuse(o, w, 5)
            at = at + 8
        return ro_prepare(s, o, w)
    if phase != 2 and phase != 3:
        return ro_refuse(o, w, 6)
    if read64(s, 40) != get(w, 40):
        return ro_refuse(o, w, 7)
    command = read64(s, 8)
    if command == 4:
        return ro_refuse(o, w, 8)
    if length(o) < get(w, 160):
        return ro_emit(o, w, 2, 0)
    if phase == 2:
        if command != 2 or ro_reply_shape(s, w) == 0:
            return ro_refuse(o, w, 9)
        return ro_fs_reply(s, o, w)
    if command != 3 or ro_warning_shape(s, w) == 0:
        return ro_refuse(o, w, 10)
    put(w, 112, read64(s, 64))
    return ro_issue(o, w, 25, 0, 0, get(w, 104), 0, 2, 23)

def ro_zero(w:mutbuf, start:u64, amount:u64) -> u64:
    end = start + amount
    while start < end:
        put(w, start, 0)
        start = start + 8
    return 0

def ro_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = 0
    while at < 1024:
        if get(w, at) != 0:
            return ro_refuse(o, w, 11)
        at = at + 8
    if read64(s, 8) != 1 or (read64(s, 16) | read64(s, 24)) == 0 or read64(s, 32) == 0 or read64(s, 136) == 0:
        return ro_refuse(o, w, 12)
    if (read64(s, 40) | read64(s, 48) | read64(s, 56) | read64(s, 88)) != 0:
        return ro_refuse(o, w, 12)
    if read64(s, 64) > 4294967295 or read64(s, 72) > 4294967295 or read64(s, 80) > 4095:
        return ro_refuse(o, w, 13)
    if (read64(s, 96) | read64(s, 104)) == 0:
        return ro_refuse(o, w, 13)
    at = 144
    while at < 256:
        if read64(s, at) != 0:
            return ro_refuse(o, w, 14)
        at = at + 8
    n = read64(s, 128)
    if n > 18446744073709550584:
        return ro_refuse(o, w, 15)
    at = 0
    while at < n:
        if byte(s, 256 + at) == 0:
            return ro_refuse(o, w, 16)
        at = at + 1
    put(w, 0, ROBUST_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, read64(s, 32))
    put(w, 64, read64(s, 96))
    put(w, 72, read64(s, 104))
    put(w, 80, read64(s, 112))
    put(w, 88, read64(s, 120))
    put(w, 96, read64(s, 64))
    put(w, 104, read64(s, 72))
    put(w, 112, read64(s, 80))
    put(w, 120, n)
    put(w, 136, 18446744073709551615)
    put(w, 152, 1024 + ((n + 7) & 18446744073709551608))
    need = n
    if need < 9:
        need = 9
    put(w, 160, 513 + need)
    put(w, 248, read64(s, 136))
    copy_input(w, s, 256, 0, 256)
    return ro_prepare(s, o, w)

def ro_steady(w:mutbuf) -> u64:
    if get(w, 0) != ROBUST_MAGIC or get(w, 8) < 1 or get(w, 8) > 4:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or (get(w, 64) | get(w, 72)) == 0 or get(w, 32) == 0 or get(w, 248) == 0:
        return 0
    if get(w, 96) > 4294967295 or get(w, 104) > 4294967295 or get(w, 112) > 4095:
        return 0
    n = get(w, 120)
    if n > 18446744073709550584 or get(w, 152) != 1024 + ((n + 7) & 18446744073709551608):
        return 0
    need = n
    if need < 9:
        need = 9
    if get(w, 160) != 513 + need or get(w, 168) != 0:
        return 0
    if get(w, 8) != 1 and get(w, 152) > length(w):
        return 0
    if get(w, 8) == 1:
        if (get(w, 40) | get(w, 48) | get(w, 56) | get(w, 128) | get(w, 144) | get(w, 184) | get(w, 192)) != 0:
            return 0
    elif get(w, 8) == 2:
        if get(w, 40) == 0 or get(w, 80) == 0 or get(w, 88) == 0 or ro_stage_op(get(w, 56)) != get(w, 48):
            return 0
        if get(w, 48) != 25 and get(w, 128) == 0:
            return 0
    elif get(w, 8) == 3:
        if get(w, 48) != 28 or get(w, 56) != 22 or get(w, 128) != 0 or get(w, 144) > 2 or get(w, 184) == 0:
            return 0
    return 1

def ro_stage_op(stage:u64) -> u64:
    if stage == 10 or stage == 23:
        return 25
    if stage == 20:
        return 9
    if stage == 21:
        return 8
    if stage == 30:
        return 15
    if stage == 31:
        return 21
    return 0

def ro_prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < get(w, 152) or length(o) < get(w, 160):
        return ro_emit(o, w, 2, 0)
    copy_input(w, s, 1024, 256, get(w, 120))
    return ro_open(o, w)

def ro_open(o:mutbuf, w:mutbuf) -> u32:
    mode = get(w, 104)
    if mode == 0:
        mode = 420
    return ro_issue(o, w, 25, 0, get(w, 96) | 524288, mode, 0, 1, 10)

def ro_issue(o:mutbuf, w:mutbuf, op:u64, a:u64, b:u64, c:u64, d:u64, path:u64, stage:u64) -> u32:
    if get(w, 40) == 18446744073709551615 or get(w, 80) == 18446744073709551615 or get(w, 88) == 18446744073709551615:
        return ro_refuse(o, w, 17)
    if ro_stage_op(stage) != op or path > 2:
        return ro_refuse(o, w, 18)
    put(w, 40, get(w, 40) + 1)
    put(w, 80, get(w, 80) + 1)
    put(w, 88, get(w, 88) + 1)
    put(w, 48, op)
    put(w, 56, stage)
    put(w, 8, 2)
    put(w, 200, path)
    put(w, 208, a)
    put(w, 216, b)
    put(w, 224, c)
    put(w, 232, d)
    ro_zero(w, 512, 256)
    n = 0
    if path == 1:
        n = get(w, 120)
    elif path == 2:
        n = 9
    put(w, 512, FILESYSTEM_MAGIC)
    put(w, 520, 2)
    put(w, 528, get(w, 64))
    put(w, 536, get(w, 72))
    put(w, 544, get(w, 80))
    put(w, 560, op)
    put(w, 576, a)
    put(w, 584, b)
    put(w, 592, c)
    put(w, 600, d)
    put(w, 608, n)
    put(w, 616, get(w, 40))
    ro_emit(o, w, 1, 256 + n)
    copy_workspace(o, w, 256, 512, 256)
    if path == 1:
        copy_workspace(o, w, 512, 1024, n)
    elif path == 2:
        put(o, 512, 7815273711403623471)
        store(o, 520, 108)
    return 1

def ro_reply_shape(s:readbuf, w:mutbuf) -> u64:
    if read64(s, 48) != get(w, 48) or read64(s, 56) != 0:
        return 0
    at = 64
    while at < 128:
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
    if read64(s, 272) != get(w, 64) or read64(s, 280) != get(w, 72) or read64(s, 288) != get(w, 80) or read64(s, 296) != get(w, 88):
        return 0
    if read64(s, 304) != get(w, 48) or read64(s, 312) > 4095:
        return 0
    if read64(s, 368) != get(w, 40) or read64(s, 376) != 1 or read64(s, 384) != n - 256:
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
    op = get(w, 48)
    if op == 25:
        if n != 256 or read64(s, 320) == 0 or read64(s, 328) > 2147483647 or read64(s, 416) == 0 or read64(s, 424) <= read64(s, 320):
            return 0
        if (read64(s, 336) | read64(s, 344) | read64(s, 352) | read64(s, 360) | read64(s, 448)) != 0:
            return 0
        return 1
    if op == 15:
        if n != 400:
            return 0
        if read64(s, 320) != read64(s, 512) or read64(s, 328) != read64(s, 520):
            return 0
        if read64(s, 336) != (read64(s, 536) & 4294967295) or read64(s, 344) != (read64(s, 536) >> 32):
            return 0
        if read64(s, 352) != (read64(s, 544) & 4294967295) or read64(s, 360) != read64(s, 560) or read64(s, 448) != read64(s, 528):
            return 0
        return 1
    if n != 256 or read64(s, 448) != 0:
        return 0
    at = 320
    while at < 368:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def ro_fs_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    error = read64(s, 312)
    if error != 0:
        put(w, 112, error)
    stage = get(w, 56)
    if stage == 10:
        if error == 4:
            return ro_open(o, w)
        if error != 0:
            put(w, 128, 0)
            put(w, 136, 18446744073709551615)
            return ro_done(o, w)
        put(w, 128, read64(s, 320))
        put(w, 136, read64(s, 328))
        if read64(s, 328) < 3:
            put(w, 144, read64(s, 328))
            if (get(w, 96) & 192) == 192:
                return ro_issue(o, w, 9, 0, 0, 0, 0, 1, 20)
            return ro_issue(o, w, 8, get(w, 128), 0, 0, 0, 0, 21)
        if get(w, 104) != 0:
            return ro_issue(o, w, 15, get(w, 128), 0, 0, 0, 0, 30)
        return ro_done(o, w)
    if stage == 20:
        return ro_issue(o, w, 8, get(w, 128), 0, 0, 0, 0, 21)
    if stage == 21:
        put(w, 128, 0)
        put(w, 136, 18446744073709551615)
        return ro_warning(o, w)
    if stage == 23:
        if error != 0:
            return ro_done(o, w)
        if get(w, 192) == 18446744073709551615:
            return ro_refuse(o, w, 19)
        put(w, 192, get(w, 192) + 1)
        return ro_open(o, w)
    if stage == 30:
        if error == 0 and read64(s, 360) == 0 and (read64(s, 336) & 511) != get(w, 104):
            return ro_issue(o, w, 21, get(w, 128), get(w, 104), 0, 0, 0, 31)
        return ro_done(o, w)
    if stage == 31:
        return ro_done(o, w)
    return ro_refuse(o, w, 20)

def ro_warning(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 40) == 18446744073709551615 or get(w, 184) == 18446744073709551615:
        return ro_refuse(o, w, 21)
    put(w, 40, get(w, 40) + 1)
    put(w, 184, get(w, 184) + 1)
    put(w, 8, 3)
    put(w, 48, 28)
    put(w, 56, 22)
    n = get(w, 120)
    ro_emit(o, w, 3, n + 39)
    put(o, 256, 2338603604650300513)
    put(o, 264, 2334385695208992628)
    store(o, 272, 34)
    copy_workspace(o, w, 273, 1024, n)
    at = 273 + n
    put(o, at, 7812730950842982434)
    put(o, at + 8, 8100115651830383993)
    put(o, at + 16, 2338603637978313586)
    store(o, at + 21, get(w, 144) + 48)
    store(o, at + 22, 0)
    return 3

def ro_warning_shape(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 256 or read64(s, 48) != 28 or read64(s, 56) != 0 or read64(s, 64) > 4095:
        return 0
    at = 72
    while at < 128:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    at = 144
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    return 1

def ro_done(o:mutbuf, w:mutbuf) -> u32:
    put(w, 8, 4)
    put(w, 48, 0)
    put(w, 56, 0)
    ro_zero(w, 200, 40)
    return ro_emit(o, w, 0, 0)

def ro_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != ROBUST_BAD:
        put(w, 168, reason)
    put(w, 0, ROBUST_BAD)
    return ro_emit(o, w, 4294967293, 0)

def ro_emit(o:mutbuf, w:mutbuf, status:u64, payload:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    ro_zero(o, 0, 256)
    put(o, 0, ROBUST_MAGIC)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 56))
    put(o, 64, get(w, 128))
    put(o, 72, get(w, 136))
    put(o, 80, get(w, 112))
    put(o, 88, get(w, 8))
    put(o, 96, get(w, 184))
    put(o, 104, get(w, 192))
    put(o, 112, get(w, 80))
    put(o, 120, get(w, 88))
    put(o, 128, payload)
    put(o, 136, get(w, 152))
    put(o, 144, get(w, 160))
    put(o, 152, get(w, 168))
    put(o, 160, 1)
    put(o, 168, get(w, 64))
    put(o, 176, get(w, 72))
    put(o, 184, get(w, 248))
    return status
'''
def source_program():
    return (ROBUST.replace("ROBUST_BAD",str(BAD)).replace("ROBUST_MAGIC",str(MAGIC))
        .replace("FILESYSTEM_MAGIC",str(FS_MAGIC)) + VALUES[VALUES.index("\ndef read64("):])
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate robust-open symbol")
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"agent_namespace_robust_open_r1","functions":functions})
if __name__=="__main__":
    path=ROOT/"examples/hia_bootstrap/agent_namespace_robust_open_r1.hiaasm"
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
