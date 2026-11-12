"""New selected SQLite 3.46.1 process PRNG policy, not an installed Store.

The complete original random.c transition is HIA-owned. Initialization, static
mutex and VFS entropy are typed pending effects until a real fixed issuer is
joined. The private header is correlation, not external authentication.
"""
from __future__ import annotations
import ast
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
MAGIC=int.from_bytes(b"HIANPR01","little")
BAD=int.from_bytes(b"HIANPB01","little")
EVENT=int.from_bytes(b"HIANPE01","little")
POLICY=r'''
def prng_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 4096 or length(o) < 256:
        if length(w) >= 8:
            put(w, 0, PR_BAD)
        return 4294967293
    if get(w, 0) == PR_BAD:
        return pr_emit(o, w, 4294967293)
    if length(s) < 256 or read64(s, 0) != PR_MAGIC:
        return pr_refuse(o, w, 1)
    if get(w, 0) == 0 or get(w, 8) == 4:
        return pr_begin(s, o, w)
    if pr_steady(w) == 0:
        return pr_refuse(o, w, 2)
    if get(w, 8) == 1:
        if pr_same_begin(s, w, 1) == 0:
            return pr_refuse(o, w, 3)
        return pr_prepare(o, w)
    if get(w, 8) == 3:
        if pr_same_begin(s, w, 3) == 0:
            return pr_refuse(o, w, 4)
        if length(o) < get(w, 64):
            return pr_refuse(o, w, 5)
        return pr_generate_step(o, w)
    if get(w, 8) != 2 or pr_reply_shape(s, w) == 0:
        return pr_refuse(o, w, 6)
    if length(o) < get(w, 64):
        return pr_refuse(o, w, 5)
    return pr_reply(s, o, w)

def pr_u32(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 4:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def pr_put32(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 4:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def pr_zero(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, at + i, 0)
        i = i + 1
    return 0

def pr_state_shape(w:mutbuf, at:u64) -> u64:
    if byte(w, at + 128) > 64:
        return 0
    if (byte(w, at + 129) | byte(w, at + 130) | byte(w, at + 131)) != 0:
        return 0
    if pr_u32(w, at) != 0:
        if pr_u32(w, at) != 1634760805 or pr_u32(w, at + 4) != 857760878:
            return 0
        if pr_u32(w, at + 8) != 2036477234 or pr_u32(w, at + 12) != 1797285236:
            return 0
    return 1

def pr_steady(w:mutbuf) -> u64:
    if get(w, 0) != PR_MAGIC or get(w, 8) < 1 or get(w, 8) > 4:
        return 0
    if (get(w, 16) | get(w, 24)) == 0 or get(w, 32) == 0 or get(w, 56) > 1:
        return 0
    if get(w, 88) > 1 or get(w, 96) > 4294967295 or get(w, 104) < 1 or get(w, 104) > 3:
        return 0
    n = 0
    if get(w, 104) == 1 and get(w, 88) != 0 and get(w, 96) < 2147483648:
        n = get(w, 96)
    if get(w, 80) != n or get(w, 72) > n or get(w, 64) != 256 + n:
        return 0
    if pr_state_shape(w, 512) == 0 or pr_state_shape(w, 768) == 0:
        return 0
    if get(w, 8) == 2:
        if get(w, 40) == 0 or get(w, 48) < 1 or get(w, 48) > 5:
            return 0
        if get(w, 1792) != PR_EVENT or get(w, 1800) != 1 or get(w, 1832) != get(w, 40):
            return 0
    elif get(w, 48) != 0:
        return 0
    if get(w, 8) == 3 and (get(w, 56) != 1 or get(w, 80) == 0 or get(w, 72) >= get(w, 80)):
        return 0
    return 1

def pr_begin_shape(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 256 or read64(s, 8) != 1 or (read64(s, 16) | read64(s, 24)) == 0 or read64(s, 32) == 0:
        return 0
    api = read64(s, 40)
    if api < 1 or api > 3 or read64(s, 48) > 4294967295 or read64(s, 56) > 1:
        return 0
    if api != 1 and (read64(s, 48) | read64(s, 56)) != 0:
        return 0
    at = 64
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    if get(w, 0) != 0:
        if pr_steady(w) == 0 or get(w, 8) != 4 or get(w, 56) != 0:
            return 0
        if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24):
            return 0
        if get(w, 32) == 18446744073709551615 or read64(s, 32) != get(w, 32) + 1:
            return 0
    return 1

def pr_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if pr_begin_shape(s, w) == 0:
        return pr_refuse(o, w, 7)
    if get(w, 0) == 0:
        at = 0
        while at < 4096:
            if get(w, at) != 0:
                return pr_refuse(o, w, 8)
            at = at + 8
    pr_zero(w, 0, 256)
    put(w, 0, PR_MAGIC)
    put(w, 8, 1)
    put(w, 16, read64(s, 16))
    put(w, 24, read64(s, 24))
    put(w, 32, read64(s, 32))
    put(w, 88, read64(s, 56))
    put(w, 96, read64(s, 48))
    put(w, 104, read64(s, 40))
    n = 0
    if read64(s, 40) == 1 and read64(s, 56) != 0 and read64(s, 48) < 2147483648:
        n = read64(s, 48)
    put(w, 80, n)
    put(w, 64, 256 + n)
    copy_input(w, s, 1536, 0, 256)
    return pr_prepare(o, w)

def pr_same_begin(s:readbuf, w:mutbuf, command:u64) -> u64:
    if length(s) != 256 or read64(s, 8) != command:
        return 0
    at = 0
    while at < 256:
        if at != 8 and read64(s, at) != get(w, 1536 + at):
            return 0
        at = at + 8
    return 1

def pr_prepare(o:mutbuf, w:mutbuf) -> u32:
    if length(o) < get(w, 64):
        return pr_emit(o, w, 2)
    if get(w, 104) == 2:
        move_workspace(w, 768, 512, 132)
        return pr_done(o, w)
    if get(w, 104) == 3:
        move_workspace(w, 512, 768, 132)
        return pr_done(o, w)
    return pr_issue(o, w, 1)

def pr_issue(o:mutbuf, w:mutbuf, op:u64) -> u32:
    if op < 1 or op > 5 or get(w, 40) == 18446744073709551615:
        return pr_refuse(o, w, 9)
    put(w, 40, get(w, 40) + 1)
    put(w, 48, op)
    put(w, 8, 2)
    pr_emit(o, w, 1)
    copy_workspace(w, o, 1792, 0, 256)
    return 1

def pr_reply_shape(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 512 or read64(s, 8) != 2:
        return 0
    if read64(s, 16) != get(w, 16) or read64(s, 24) != get(w, 24) or read64(s, 32) != get(w, 32):
        return 0
    if read64(s, 40) != get(w, 40) or read64(s, 48) != get(w, 48):
        return 0
    if read64(s, 56) > 4294967295 or read64(s, 64) != length(s) - 512:
        return 0
    if read64(s, 72) == 0 or read64(s, 80) == 0 or read64(s, 88) == 0:
        return 0
    at = 96
    while at < 256:
        if read64(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < 256:
        if read64(s, 256 + at) != get(w, 1792 + at):
            return 0
        at = at + 8
    op = get(w, 48)
    if op == 4:
        return choose(length(s) == 556, 1, 0)
    if length(s) != 512:
        return 0
    if op == 1:
        return 1
    if op == 3:
        return choose(read64(s, 56) <= 1, 1, 0)
    return choose(read64(s, 56) == 0, 1, 0)

def pr_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    op = get(w, 48)
    value = read64(s, 56)
    put(w, 48, 0)
    put(w, 128, read64(s, 72))
    put(w, 136, read64(s, 80))
    put(w, 144, read64(s, 88))
    if op == 1:
        put(w, 112, value)
        if value != 0:
            return pr_done(o, w)
        return pr_issue(o, w, 2)
    if op == 2:
        put(w, 56, 1)
        if get(w, 80) == 0:
            pr_put32(w, 512, 0)
            return pr_issue(o, w, 5)
        if pr_u32(w, 512) == 0:
            return pr_issue(o, w, 3)
        return pr_generate_step(o, w)
    if op == 3:
        pr_put32(w, 512, 1634760805)
        pr_put32(w, 516, 857760878)
        pr_put32(w, 520, 2036477234)
        pr_put32(w, 524, 1797285236)
        if value != 0:
            return pr_issue(o, w, 4)
        pr_zero(w, 528, 44)
        return pr_seed_done(o, w)
    if op == 4:
        copy_input(w, s, 528, 512, 44)
        put(w, 120, value)
        return pr_seed_done(o, w)
    if op == 5:
        put(w, 56, 0)
        return pr_done(o, w)
    return pr_refuse(o, w, 10)

def pr_seed_done(o:mutbuf, w:mutbuf) -> u32:
    pr_put32(w, 572, pr_u32(w, 560))
    pr_put32(w, 560, 0)
    store(w, 640, 0)
    return pr_generate_step(o, w)

def pr_rot(value:u64, amount:u64) -> u64:
    return ((value << amount) | (value >> (32 - amount))) & 4294967295

def pr_quarter(w:mutbuf, ai:u64, bi:u64, ci:u64, di:u64) -> u64:
    a = pr_u32(w, 1024 + ai * 4)
    b = pr_u32(w, 1024 + bi * 4)
    c = pr_u32(w, 1024 + ci * 4)
    d = pr_u32(w, 1024 + di * 4)
    a = (a + b) & 4294967295
    d = pr_rot(d ^ a, 16)
    c = (c + d) & 4294967295
    b = pr_rot(b ^ c, 12)
    a = (a + b) & 4294967295
    d = pr_rot(d ^ a, 8)
    c = (c + d) & 4294967295
    b = pr_rot(b ^ c, 7)
    pr_put32(w, 1024 + ai * 4, a)
    pr_put32(w, 1024 + bi * 4, b)
    pr_put32(w, 1024 + ci * 4, c)
    pr_put32(w, 1024 + di * 4, d)
    return 0

def pr_block(w:mutbuf) -> u64:
    move_workspace(w, 1024, 512, 64)
    i = 0
    while i < 10:
        pr_quarter(w, 0, 4, 8, 12)
        pr_quarter(w, 1, 5, 9, 13)
        pr_quarter(w, 2, 6, 10, 14)
        pr_quarter(w, 3, 7, 11, 15)
        pr_quarter(w, 0, 5, 10, 15)
        pr_quarter(w, 1, 6, 11, 12)
        pr_quarter(w, 2, 7, 8, 13)
        pr_quarter(w, 3, 4, 9, 14)
        i = i + 1
    i = 0
    while i < 16:
        pr_put32(w, 576 + i * 4, (pr_u32(w, 1024 + i * 4) + pr_u32(w, 512 + i * 4)) & 4294967295)
        i = i + 1
    return 0

def pr_generate_step(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 56) != 1 or get(w, 80) == 0 or get(w, 72) >= get(w, 80):
        return pr_refuse(o, w, 11)
    left = get(w, 80) - get(w, 72)
    n = byte(w, 640)
    if left <= n:
        copy_workspace(o, w, 256 + get(w, 72), 576 + n - left, left)
        store(w, 640, n - left)
        put(w, 72, get(w, 80))
        return pr_issue(o, w, 5)
    if n != 0:
        copy_workspace(o, w, 256 + get(w, 72), 576, n)
        put(w, 72, get(w, 72) + n)
    pr_put32(w, 560, (pr_u32(w, 560) + 1) & 4294967295)
    pr_block(w)
    store(w, 640, 64)
    put(w, 8, 3)
    return pr_emit(o, w, 3)

def pr_done(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 56) != 0:
        return pr_refuse(o, w, 12)
    put(w, 8, 4)
    put(w, 48, 0)
    return pr_emit(o, w, 0)

def pr_refuse(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    if get(w, 0) != PR_BAD:
        put(w, 152, reason)
    put(w, 0, PR_BAD)
    put(w, 8, 5)
    return pr_emit(o, w, 4294967293)

def pr_emit(o:mutbuf, w:mutbuf, status:u64) -> u32:
    if length(o) < 256:
        return 4294967293
    pr_zero(o, 0, 256)
    put(o, 0, PR_EVENT)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 32))
    put(o, 40, get(w, 40))
    put(o, 48, get(w, 48))
    put(o, 56, get(w, 8))
    put(o, 64, get(w, 80))
    put(o, 72, get(w, 72))
    put(o, 80, get(w, 56))
    put(o, 88, get(w, 64))
    put(o, 96, get(w, 152))
    put(o, 104, get(w, 112))
    put(o, 112, get(w, 120))
    copy_workspace(o, w, 120, 512, 132)
    return status
'''
def source_program():
    return (POLICY.replace("PR_MAGIC",str(MAGIC)).replace("PR_BAD",str(BAD))
        .replace("PR_EVENT",str(EVENT))+VALUES[VALUES.index("\ndef read64("):])
def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if len(names)!=len(nodes):raise ValueError("duplicate process PRNG symbol")
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"agent_namespace_sqlite3461_prng_r1","functions":functions})
