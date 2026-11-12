"""Author HIA artifact byte/identity/path policy and a fixed syscall adapter.

The optional standalone application does not replace default Agent persistence.
It uses the existing exact-bytes, no-replace-link, point-in-time contract.
"""
from __future__ import annotations

import hashlib
import ast
import struct, subprocess, tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ROOT=Path(__file__).resolve().parents[1]
POLICY_SOURCE='''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 4096:
        return 16
    phase = get(w, 0)
    if phase == 0:
        if length(s) < 32 or length(o) < 1048576:
            return 16
        a = uint(s, 0, 8)
        b = uint(s, 8, 8)
        c = uint(s, 16, 8)
        d = uint(s, 24, 8)
        if a > 131071 or b > 131071 or c > 131071 or d > 131071:
            return 16
        if a + b + c + d + 32 != length(s) or d == 0:
            return 16
        op = 0
        if a == 7 and uint(s, 32, 7) == 29400294205060464:
            op = 1
        if a == 6 and uint(s, 32, 6) == 133480762729846:
            op = 2
        if a == 8 and uint(s, 32, 8) == 8602282538829113719:
            op = 3
        if a == 9 and uint(s, 32, 8) == 8462313613564015731 and uint(s, 40, 1) == 116:
            op = 4
        if a == 9 and uint(s, 32, 8) == 7306858834166772851 and uint(s, 40, 1) == 116:
            op = 5
        if a == 10 and uint(s, 32, 8) == 7018909932991771763 and uint(s, 40, 2) == 26739:
            op = 6
        if op == 0:
            return 16
        put(w, 8, op)
        if op == 6:
            return op
        x = normalize(s, o, 0)
        if op == 4 or op == 5:
            if x == 0:
                return 16
            start = 32 + a + b
            if op == 4:
                if c != 1 or byte(s, start) != 45:
                    return 16
            if op == 5:
                if c != 64:
                    return 16
                i = 0
                while i < 64:
                    v = byte(s, start + i)
                    if v < 48 or v > 102:
                        return 16
                    if v > 57 and v < 97:
                        return 16
                    store(w, 2256 + i, v)
                    store(w, 2416 + i, v)
                    i = i + 1
                store(w, 2320, 0)
            return op
        y = normalize(s, o, 1)
        if x == 0 or y == 0:
            return 16
        put(w, 56, 262160)
        if op != 3 and x == y:
            i = 0
            same = 1
            while i < x:
                if byte(o, i) != byte(o, 262160 + i):
                    same = 0
                i = i + 1
            if same == 1:
                return 16
        return op
    if phase == 10:
        mode = get(w, 2072) & 4294967295
        uid = get(w, 2076) & 4294967295
        if mode & 61440 != 16384 or mode & 18 != 0 or uid != get(w, 120):
            return 10
        return 0
    if phase == 11:
        if regular(w, 272) == 0:
            return 10
        size = get(w, 320)
        if size > 67108864:
            return 17
        if get(w, 112) == 1:
            put(w, 16, size)
        return 0
    if phase == 12:
        write(w, 2336, 12777924611700526, 7)
        store(w, 2206, (byte(w, 2206) & 15) | 64)
        store(w, 2208, (byte(w, 2208) & 63) | 128)
        i = 0
        while i < 16:
            value = byte(w, 2200 + i)
            store(w, 2343 + i * 2, hex(value >> 4))
            store(w, 2344 + i * 2, hex(value & 15))
            i = i + 1
        store(w, 2375, 0)
        return 0
    if phase == 13:
        if length(o) < 32:
            return 16
        i = 0
        while i < 32:
            value = byte(o, i)
            store(w, 2560 + i, value)
            store(w, 2256 + i * 2, hex(value >> 4))
            store(w, 2257 + i * 2, hex(value & 15))
            i = i + 1
        store(w, 2320, 0)
        return 0
    if phase == 14:
        i = 0
        while i < 64:
            if byte(w, 2256 + i) != byte(w, 2416 + i):
                return 11
            i = i + 1
        return 0
    if phase == 15:
        if length(o) < 32:
            return 16
        i = 0
        while i < 32:
            store(o, i, byte(w, 2560 + i))
            i = i + 1
        return 0
    if phase == 16:
        if get(w, 16) > 67108864:
            return 17
        return 0
    if phase == 17:
        copy(w, 128, 848, 144)
        return 0
    if phase == 18:
        copy(w, 128, 2640, 144)
        return 0
    if phase == 19:
        copy(w, 2640, 128, 144)
        return 0
    if phase == 20:
        offset = get(w, 40)
        count = get(w, 24)
        total = get(w, 16)
        if total > 67108864:
            return 17
        if offset > total or count > total - offset:
            return 11
        return 0
    if phase == 1:
        if regular(w, 272) == 0:
            return 10
        if get(w, 32) == 2 and equal(w, 272, 848, 1) == 0:
            return 10
        return 0
    if phase == 2:
        if equal(w, 272, 416, 1) == 0:
            return 12
        return 0
    if phase == 3:
        count = get(w, 24)
        offset = get(w, 40)
        total = get(w, 16)
        if offset > total or count > total - offset or count > length(s) or count > length(o):
            return 11
        i = 0
        while i < count:
            if byte(s, i) != byte(o, i):
                return 11
            i = i + 1
        return 0
    if phase == 4:
        if get(w, 40) != get(w, 16) or equal(w, 272, 560, 1) == 0:
            return 11
        return 0
    if phase == 5:
        if equal(w, 272, 704, 1) == 0:
            return 12
        round = get(w, 32)
        if round > 2:
            return 16
        if round == 0:
            copy(w, 272, 128, 144)
            copy(w, 272, 848, 144)
        if round == 1:
            if equal(w, 128, 272, 0) == 0:
                return 12
            copy(w, 272, 848, 144)
        return 0
    if phase == 6:
        if regular(w, 128) == 0 or regular(w, 272) == 0:
            return 10
        if get(w, 128) != get(w, 272) or get(w, 136) != get(w, 280):
            return 10
        return 0
    if phase == 7:
        if length(o) < 160:
            return 16
        i = 0
        while i < 32:
            store(w, 1600 + i, byte(o, i))
            i = i + 1
        write(o, 0, 3906083645759365755, 8)
        write(o, 8, 2243106, 3)
        i = 0
        while i < 32:
            v = byte(w, 1600 + i)
            store(o, 11 + i * 2, hex(v >> 4))
            store(o, 12 + i * 2, hex(v & 15))
            i = i + 1
        write(o, 75, 8315180351695760418, 8)
        write(o, 83, 14882, 2)
        value = get(w, 16)
        count = 0
        while value > 0:
            quotient = divide10(value)
            store(w, 1700 + count, 48 + value - quotient * 10)
            value = quotient
            count = count + 1
        if count == 0:
            store(w, 1700, 48)
            count = 1
        i = 0
        while i < count:
            store(o, 85 + i, byte(w, 1700 + count - 1 - i))
            i = i + 1
        store(o, 85 + count, 125)
        store(o, 86 + count, 10)
        return 87 + count
    if phase == 8:
        if length(o) < 32:
            return 16
        write(o, 0, 8242828067189760635, 8)
        write(o, 8, 249685768033, 5)
        if get(w, 48) == 1:
            write(o, 13, 11533689385588, 6)
            return 19
        write(o, 13, 2952624448758118, 7)
        return 20
    return 16

def normalize(s:readbuf, o:mutbuf, which:u64) -> u64:
    cmd = uint(s, 0, 8)
    stage = uint(s, 8, 8)
    dest = uint(s, 16, 8)
    cwd = uint(s, 24, 8)
    start = 32 + cmd
    size = stage
    output = 0
    if which == 1:
        start = start + stage
        size = dest
        output = 262160
    cwdstart = 32 + cmd + stage + dest
    n = 0
    if size == 0 or byte(s, start) != 47:
        i = 0
        while i < cwd:
            v = byte(s, cwdstart + i)
            if v == 0:
                return 0
            store(o, 524320 + n, v)
            n = n + 1
            i = i + 1
        if n == 0 or byte(o, 524320 + n - 1) != 47:
            store(o, 524320 + n, 47)
            n = n + 1
    i = 0
    while i < size:
        v = byte(s, start + i)
        if v == 0:
            return 0
        store(o, 524320 + n, v)
        n = n + 1
        i = i + 1
    if n == 0 or byte(o, 524320) != 47:
        return 0
    store(o, output, 47)
    count = 1
    if n > 1 and byte(o, 524321) == 47:
        if n == 2 or byte(o, 524322) != 47:
            store(o, output + 1, 47)
            count = 2
    i = 0
    while i < n:
        while i < n and byte(o, 524320 + i) == 47:
            i = i + 1
        first = i
        while i < n and byte(o, 524320 + i) != 47:
            i = i + 1
        span = i - first
        if span > 0:
            keep = 1
            if span == 1 and byte(o, 524320 + first) == 46:
                keep = 0
            if keep == 1:
                if byte(o, output + count - 1) != 47:
                    store(o, output + count, 47)
                    count = count + 1
                j = 0
                while j < span:
                    store(o, output + count, byte(o, 524320 + first + j))
                    count = count + 1
                    j = j + 1
    if count > 262159:
        return 0
    store(o, output + count, 0)
    return count

def regular(w:mutbuf, at:u64) -> u64:
    mode = get(w, at + 24) & 4294967295
    if mode & 61440 != 32768:
        return 0
    return 1

def equal(w:mutbuf, a:u64, b:u64, ctime:u64) -> u64:
    if get(w, a) != get(w, b) or get(w, a + 8) != get(w, b + 8):
        return 0
    if get(w, a + 24) & 4294967295 != get(w, b + 24) & 4294967295:
        return 0
    if get(w, a + 48) != get(w, b + 48):
        return 0
    if get(w, a + 88) != get(w, b + 88) or get(w, a + 96) != get(w, b + 96):
        return 0
    if ctime == 1:
        if get(w, a + 104) != get(w, b + 104) or get(w, a + 112) != get(w, b + 112):
            return 0
    return 1

def copy(w:mutbuf, a:u64, b:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, b + i, byte(w, a + i))
        i = i + 1
    return 0

def divide10(value:u64) -> u64:
    result = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        result = result << 1
        if remainder >= 10:
            remainder = remainder - 10
            result = result | 1
    return result

def hex(v:u64) -> u64:
    if v < 10:
        return 48 + v
    return 87 + v

def get(s:mutbuf, p:u64) -> u64:
    v = 0
    i = 0
    while i < 8:
        v = v | (byte(s, p + i) << (8 * i))
        i = i + 1
    return v

def uint(s:readbuf, p:u64, n:u64) -> u64:
    v = 0
    i = 0
    while i < n:
        v = v | (byte(s, p + i) << (8 * i))
        i = i + 1
    return v

def put(o:mutbuf, p:u64, v:u64) -> u64:
    return write(o, p, v, 8)

def write(o:mutbuf, p:u64, v:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, p + i, (v >> (8 * i)) & 255)
        i = i + 1
    return 0
'''


def document(source=POLICY_SOURCE, module='artifact_publication_policy'):
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);fns=[]
    for n in nodes:
        b=Builder(n,names,sigs,total);b.statements(n.body)
        fns.append({'name':names[n.name],'params':[b.param(p) for p in b.params],
                    'returns':[b.returns], 'effects':['read','write','trap'],
                    'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':fns})


MAGIC=int.from_bytes(b'HIAPUB01','little')

# Fixed Linux/SysV transport. HIA owns the policy and ELF packer below.
# Keep the .S source and assembled_template() as the independent authoring oracle.
# No assembler, linker, payload code, or native image is executed by template().
TRANSPORT_SOURCE_SHA256 = '0042cf07a91f7a61ca2dd440ec838e0aaafc9d986d584acaa2c0c7dfbb80ddbf'
TRANSPORT_SHA256 = '0ed6eee39d74ec3cdef7edcf84e8def5ccb562a8e02d823efd9cc9e55ecd78bf'
TRANSPORT_BYTES = 3978
TRANSPORT = bytes.fromhex(
    '4989e749833f040f856f0f000031ffbe00401a00ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05'
    '483d01f0ffff0f83390f00004889c548c785d017180001000000bf0d000000488db5d017180031d241ba08000000b80d'
    '0000000f054885c00f88070f000041bc20000000bb01000000498b74df08e8cc0e00004883f8ff0f84e10e0000488944'
    'ddf84889c14a8d7c25004901c4f3a4ffc383fb0475d34a8d7c2500be00000200b84f0000000f054885c00f88b50e0000'
    '48ffc8488945184901c448c78500101800000000004889ef4c89e6488d9520000800b9000010004c8d850010180041b9'
    '001000004883ec00e80000000083f8060f87680e000085c00f84600e000083f8030f84740d000083f8050f8463020000'
    '31ffbe00000100ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff0f83260e000049'
    '89c44531edbb000001004939dd75314c89e74889de4889da48d1e20f82fd0d000041ba01000000b8190000000f05483d'
    '01f0ffff0f83eb0d00004989c448d1e331c031ff4b8d342c4889da4c29ea48898560101800488b85601018000f054883'
    'f8fc74f14885c00f88b80d000074354901c54883bd0810180004728e4c89ad1010180048c785001018001000000031ff'
    '31f6e8f20b000085c00f8551070000e966ffffff4c89ad101018004883bd08101800040f83b40000004d85ed0f845c0d'
    '00004c89ad1010180048c7852010180000000000488dbd20000800e8a209000085c00f85f60b00004883bd0810180002'
    '745c488dbd20000800488db530000c00b85600000048898560101800488b85601018000f054883f8fc74f14885c00f88'
    '0501000048c785301018000100000048c7852010180001000000488dbd20000800e83c09000085c00f85900b000048c7'
    '852010180002000000488dbd30000c00e81d09000085c00f85710b0000c6850030190000be01000000e8320b000085c0'
    '0f859900000031db4c39eb74474c89e94829d94881f9000001007605b90000010048898d58101800498d341c488dbd01'
    '301900f3a4c6850030190001488bb5581018004801f348ffc6e8e20a000085c0754debb4c6850030190002be01000000'
    'e8cb0a000083f82075354883bd08101800040f83b300000048c785001018000700000031ff31f6e87d0a000083f85772'
    '0e89c2488db500201800e9ae0b0000b810000000e9b50a0000b80e000000e9ab0a000031ffbe01000004ba0300000041'
    'ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff0f83c30b00004989c44531ede8ca03000085c00f'
    '857b05000048c785701018000100000048c7852010180000000000488dbdd0181800e86105000085c00f85510500004c'
    '8bad10101800e9c2feffff48c785001018000d00000031ff31f6e8ca09000085c00f85290500004883bd08101800050f'
    '843b0300004883bd08101800060f84e6020000e84f03000085c00f850005000049c7c6ffffffff31db488dbc1d981818'
    '00be100000004829de31d2b83e01000048898560101800488b85601018000f054883f8fc74f14885c00f8e8f03000048'
    '01c34883fb1072c148c785001018000c00000031ff31f6e83d09000085c00f856f0300004c89ff488db520191800bac1'
    '000a0041ba00010000b80101000048898560101800488b85601018000f054883f8fc74f14885c00f88310300004989c6'
    '48c785f0131800010000004c89f7488db580101800b80500000048898560101800488b85601018000f054883f8fc74f1'
    '4885c00f88f502000031db4c39eb74364c89f7498d341c4c89ea4829dab80100000048898560101800488b8560101800'
    '0f054883f8fc74f14885c00f8ebd0200004801c3ebc54c89f7b84a00000048898560101800488b85601018000f054883'
    'f8fc74f14885c00f88910200004c89f7488db580101800b80500000048898560101800488b85601018000f054883f8fc'
    '74f14885c00f88630200004c89f7b8030000000f0549c7c6ffffffff4885c00f884902000048c7850010180011000000'
    '31ff31f6e80008000048c7852010180002000000488dbd20191800e85803000085c00f851b02000048c7850010180012'
    '00000031ff31f6e8cd0700004c89ff488db5201918004c89fa4c8d95d01818004531c0b8090100004889856010180048'
    '8b85601018000f054883f8fc74f14883f8ef74544885c00f88c101000048c785f81318000100000048c7852010180001'
    '000000488dbd20191800e8d902000085c00f859c01000048c7852010180002000000488dbdd0181800e8ba02000085c0'
    '0f857d010000eb4148c7852010180000000000488dbdd0181800e8990200004889852014180048c78500101800130000'
    '0031ff31f6e80f070000488b852014180085c00f853a0100004c89ffb84a00000048898560101800488b85601018000f'
    '054883f8fc74f14885c0791048c785f813180000000000e902010000e88901000085c00f852702000048c78500101800'
    '0f00000031ff31f6e8ac06000085c00f850b02000048c785001018000700000031ff31f6e89006000083f8570f82ee01'
    '000089c2488db500201800e9bd07000048c785001018000e00000031ff31f6e86506000085c00f85c40100004c89e64c'
    '89eae99607000053488dbd20000800be00000b0031d2b80200000048898560101800488b85601018000f054883f8fc74'
    'f14885c078514989c74c89ff488db500181800b80500000048898560101800488b85601018000f054883f8fc74f14885'
    'c07824b86b0000000f054889857810180048c785001018000a00000031ff31f6e8d40500005bc3b80f0000005bc3b80f'
    '000000488985001418004983feff74114c89f7b8030000000f0549c7c6ffffffff4883bdf813180001754e4c89ff488d'
    'b5d0181800488d951011180041ba00010000b8060100000f054885c0782b48c785001018000600000031ff31f6e86705'
    '000085c075134c89ff488db5d018180031d2b8070100000f05e80c000000488b8500141800e9a6000000534883bdf013'
    '1800010f858c0000004c89ff488db520191800488d951011180041ba00010000b80601000048898560101800488b8560'
    '1018000f054883f8fc74f14883f8fe74544885c0785348c785001018000600000031ff31f6e8df04000085c075374c89'
    'ff488db52019180031d2b80701000048898560101800488b85601018000f054883f8fc74f14885c0780f48c785f01318'
    '000000000031c05bc3b80f0000005bc34889c7e939060000534889fb49c7c6ffffffff48c78528101800000000004889'
    'de4c89ff488d951011180041ba00010000b80601000048898560101800488b85601018000f054883f8fc74f14885c00f'
    '881102000048c785001018000100000031ff31f6e83004000085c00f85fa01000048c785001018000b00000031ff31f6'
    'e81404000085c00f85de0100004c89ff4889deba00080a004531d2b80101000048898560101800488b85601018000f05'
    '4883f8fc74f14885c00f88a70100004989c64c89f7488db5a0111800b80500000048898560101800488b85601018000f'
    '054883f8fc74f14885c00f887601000048c785001018000200000031ff31f6e89503000085c00f855f01000031c04c89'
    'f7488db500201800ba0000010048898560101800488b85601018000f054883f8fc74f14885c00f882a0100000f848300'
    '0000488985181018004883bd70101800017439488b8528101800498d3c044c89ee4829c648c7850010180003000000e8'
    '2503000085c00f85ef000000488b851810180048018528101800eb8048c785001018001400000031ff31f6e8f9020000'
    '85c00f85c3000000488b8528101800498d3c04488db500201800488b8d18101800f3a4ebb74c89f7488db530121800b8'
    '0500000048898560101800488b85601018000f054883f8fc74f14885c0787748c785001018000400000031ff31f6e896'
    '02000085c075644c89f7b8030000000f0549c7c6ffffffff4885c078494c89ff4889de488d95c012180041ba00010000'
    'b80601000048898560101800488b85601018000f054883f8fc74f14885c0781648c785001018000500000031ff31f6e8'
    '35020000eb05b80f000000488985401018004983feff740a4c89f7b8030000000f0549c7c6ffffffff488b8540101800'
    '5bc3534889fb49c7c6ffffffff48c7852810180000000000488db510111800b80600000048898560101800488b856010'
    '18000f054883f8fc74f14885c00f88a101000048c785001018000100000031ff31f6e8b201000085c00f858a01000048'
    '89dfbe00080a0031d2b80200000048898560101800488b85601018000f054883f8fc74f14885c00f88570100004989c6'
    '4c89f7488db5a0111800b80500000048898560101800488b85601018000f054883f8fc74f14885c00f882601000048c7'
    '85001018000200000031ff31f6e83701000085c00f850f01000031c04c89f7488db500201800ba000001004889856010'
    '1800488b85601018000f054883f8fc74f14885c00f88da000000744048898518101800488b8528101800498d3c044c89'
    'ee4829c648c7850010180003000000e8d500000085c00f85ad000000488b851810180048018528101800eb8e4c89f748'
    '8db530121800b80500000048898560101800488b85601018000f054883f8fc74f14885c0786e48c78500101800040000'
    '0031ff31f6e87f00000085c0755b4c89f7b8030000000f0549c7c6ffffffff4885c078404889df488db5c0121800b806'
    '00000048898560101800488b85601018000f054883f8fc74f14885c0781648c785001018000500000031ff31f6e82700'
    '0000eb05b80f000000488985401018004983feff740a4c89f7b8030000000f05488b85401018005bc3488d9500201800'
    'b9000001004c8d850010180041b9001000004883ec08e8000000004883c408c3488dbd00301900488d9500201800b900'
    '0001004c8d850020190041b9001000004883ec08e8000000004883c408c3488985501018004883bd3010180001754048'
    '8dbd30000c00488db510111800b8060000000f054885c0782648c785001018000600000031ff31f6e86cffffff85c075'
    '0e488dbd30000c00b8570000000f05488bbd50101800e9f600000048c7853010180000000000488dbd20000800488db5'
    '80101800b8060000000f054885c07850488dbd30000c00488db510111800b8060000000f054885c0783648c785001018'
    '000600000031ff31f6e8fbfeffff85c0751e488dbd30000c00b8570000000f054885c0780b48c7853010180001000000'
    '48c785001018000800000031ff31f6e8c5feffff89c2488db5002018004885d27448b801000000bf0100000048898560'
    '101800488b85601018000f054883f8fc74f14885c07e2e4801c64829c2ebce31c0803c0600741248ffc0483d00000200'
    '72ef48c7c0ffffffffc331ffeb13bf10000000eb0cbf0f000000eb05bf40000000b83c0000000f050f0b'
)
TRANSPORT_HOLES = {'policy_initial_hole': 249, 'policy_hole': 3575, 'sha_hole': 3621}


def template():
    source = ROOT / "tools/hia_artifact_publication_syscalls.S"
    if hashlib.sha256(source.read_bytes()).hexdigest() != TRANSPORT_SOURCE_SHA256:
        raise ValueError("fixed artifact_publication syscall source changed; refresh and independently verify the transport")
    if len(TRANSPORT) != TRANSPORT_BYTES or hashlib.sha256(TRANSPORT).hexdigest() != TRANSPORT_SHA256:
        raise ValueError("fixed artifact_publication transport bytes changed")
    expected_holes = {'policy_initial_hole': 249, 'policy_hole': 3575, 'sha_hole': 3621}
    if TRANSPORT_HOLES != expected_holes:
        raise ValueError("fixed artifact_publication transport holes changed")
    for offset in TRANSPORT_HOLES.values():
        if TRANSPORT[offset - 1:offset + 4] != b"\xe8\0\0\0\0":
            raise ValueError("fixed artifact_publication rel32 call hole changed")
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + TRANSPORT, {name: 176 + offset for name, offset in TRANSPORT_HOLES.items()}


def assembled_template():
    # Authoring-time assembler handles fixed Linux transport only. No payload,
    # identity/byte check, hash or receipt formatter is translated by it.
    with tempfile.TemporaryDirectory(prefix='hia-publication-template-') as folder:
        obj=Path(folder)/'adapter.o'; raw=Path(folder)/'adapter.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_artifact_publication_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={}
        for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines():
            address,kind,name=line.split(); symbols[name]=int(address,16)
        relocations=subprocess.check_output(['objdump','-r',str(obj)],text=True)
        if 'R_X86_64' in relocations: raise ValueError('unresolved template relocation')
        code=raw.read_bytes()
    head=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(head)==176
    holes={key:176+symbols[key] for key in ('policy_initial_hole','policy_hole','sha_hole')}
    return head+code,holes


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix,holes=template()
    text=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8];text+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    text+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for key,offset in holes.items():
        target=str(len(prefix))+(' + policy' if key=='sha_hole' else '')
        text+=f'    write(o, {offset}, {target} - {offset+4}, 4)\n'
    text+=f'''    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)
    return size
'''
    return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name,source in [('artifact_publication_policy',POLICY_SOURCE),('artifact_publication_packer',packer_source())]:
        path=ROOT/('examples/hia_bootstrap/'+name+'.hiaasm')
        path.write_text(render_assembly(document(source,name)));print(path.name,path.stat().st_size)

if __name__=='__main__':main()
