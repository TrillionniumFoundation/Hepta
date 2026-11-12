"""Author HIA artifact byte/identity/path policy and a fixed syscall adapter.

The optional standalone application does not replace default Agent persistence.
It uses the existing exact-bytes, no-replace-link, point-in-time contract.
"""
from __future__ import annotations
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

def template():
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
        path=ROOT/('examples/hia_bootstrap/'+name+'.hepta')
        path.write_text(render_assembly(document(source,name)));print(path.name,path.stat().st_size)

if __name__=='__main__':main()
