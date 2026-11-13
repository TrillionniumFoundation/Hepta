"""Author HIA-owned multi-image scheduling and its native ELF packer.

The fixed assembly template transports effects. It does not decide the unit
number, continuation status, frame size, mode, arity or internal handoff.
The external peer still owns objects: this is not a native object runtime.
"""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT=Path(__file__).resolve().parents[1]
META_MAGIC=int.from_bytes(b'HIACTN01','little')
PACK_MAGIC=int.from_bytes(b'HIACTPK1','little')
RPC_MAGIC=int.from_bytes(b'HIAIPC01','little')
LOW_MAGIC=int.from_bytes(b'HIALOW01','little')
POOL_MAGIC=int.from_bytes(b'HIALIT01','little')
LIMIT=64<<20
IMAGE_LIMIT=1<<20
PW_BYTES=65536
LAYOUT=dict(PACKET=4096,HEADER=8192,PW=12288,UNIT_WORK=12288+PW_BYTES)
LAYOUT['OUT']=LAYOUT['UNIT_WORK']+IMAGE_LIMIT
LAYOUT['MAPSIZE']=LAYOUT['OUT']+IMAGE_LIMIT

HELPERS='''
def uint(s:readbuf, at:u64, n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
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

def write(o:mutbuf, at:u64, value:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def put(w:mutbuf, at:u64, value:u64) -> u64:
    return write(w, at, value, 8)

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0
'''

POLICY='''def schedule(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 65536 or length(o) < 64:
        return 17
    phase = get(w, 0)
    if phase == 0:
        if get(w, 16) != 1 or length(s) < 112:
            return bad(w)
        if uint(s, 0, 8) != META_MAGIC or uint(s, 56, 8) != 0:
            return bad(w)
        units = uint(s, 8, 8)
        work = uint(s, 16, 8)
        output = uint(s, 24, 8)
        pool = uint(s, 32, 8)
        literals = uint(s, 40, 8)
        modes = uint(s, 48, 8)
        if units == 0 or units > 128 or modes == 0 or modes > 1024:
            return bad(w)
        if work < 1024 or work > 1048576 or output < 128 or output > 1048576:
            return bad(w)
        if pool < 64 or pool > 1048576 or literals < 3 or literals > (pool - 16) >> 4:
            return bad(w)
        if length(s) != 64 + (units + 1) * 16 + modes * 16:
            return bad(w)
        put(w, 24, units)
        put(w, 32, work)
        put(w, 40, output)
        put(w, 48, pool)
        put(w, 56, literals)
        put(w, 120, modes)
        i = 0
        end = 0
        while i < units + 1:
            offset = uint(s, 64 + i * 16, 8)
            size = uint(s, 72 + i * 16, 8)
            if size == 0 or size > 1048576 or offset < end or offset > 67108864 or size > 67108864 - offset:
                return bad(w)
            put(w, 4096 + i * 16, offset)
            put(w, 4104 + i * 16, size)
            end = offset + size
            i = i + 1
        at = 64 + (units + 1) * 16
        i = 0
        while i < modes:
            number = uint(s, at + i * 16, 8)
            arity = uint(s, at + i * 16 + 8, 8)
            if number != i + 1 or arity > 4:
                return bad(w)
            put(w, 8192 + i * 16, number)
            put(w, 8200 + i * 16, arity)
            i = i + 1
        put(w, 136, get(w, 4096))
        put(w, 144, 0)
        put(w, 152, pool)
        put(w, 160, 0)
        put(w, 168, 0)
        put(w, 0, 1)
        return 1
    if phase == 1:
        if get(w, 8) != get(w, 48) or length(s) != get(w, 48):
            return bad(w)
        if uint(s, 0, 8) != POOL_MAGIC or uint(s, 8, 8) != get(w, 56):
            return bad(w)
        put(w, 0, 2)
        return event(o, w, 3, get(w, 48))
    if phase == 2 or phase == 5:
        if length(s) != 0:
            return bad(w)
        put(w, 0, 3)
        return 2
    if phase == 3:
        if length(s) != 128 or uint(s, 0, 8) != LOW_MAGIC:
            return bad(w)
        if get(w, 104) == 0:
            mode = uint(s, 24, 8)
            if mode == 0 or mode > get(w, 120):
                return bad(w)
            if uint(s, 32, 8) != get(w, 8200 + (mode - 1) * 16):
                return bad(w)
            put(w, 104, 1)
        put(w, 168, 0)
        return select_unit(w)
    if phase == 4:
        if length(s) != get(w, 40) or uint(s, 0, 8) != LOW_MAGIC:
            return bad(w)
        status = get(w, 8)
        if status == 0:
            if uint(s, 16, 8) != 0:
                return bad(w)
            put(w, 0, 6)
            return event(o, w, 0, 128)
        if status == 1:
            opcode = uint(s, 16, 8)
            count = uint(s, 24, 8)
            vector = uint(s, 32, 8)
            results = uint(s, 40, 8)
            if opcode == 0 or opcode > 18 or count > 8 or results > 3:
                return bad(w)
            if vector > (get(w, 40) - 128) >> 3:
                return bad(w)
            put(w, 0, 5)
            return event(o, w, 1, 128 + vector * 8)
        if status == 2:
            unit = uint(s, 24, 8)
            if uint(s, 16, 8) != 19 or unit >= get(w, 24):
                return bad(w)
            if get(w, 80) == 18446744073709551615:
                return bad(w)
            put(w, 80, get(w, 80) + 1)
            put(w, 64, unit)
            i = 0
            while i < 128:
                store(w, 2048 + i, 0)
                i = i + 1
            put(w, 2048, LOW_MAGIC)
            put(w, 2056, 2)
            put(w, 2064, uint(s, 8, 8))
            put(w, 2072, unit)
            put(w, 168, 1)
            return select_unit(w)
        return bad(w)
    if phase == 6:
        if length(s) != 0:
            return bad(w)
        put(w, 0, 7)
        return 0
    return bad(w)

def select_unit(w:mutbuf) -> u32:
    unit = get(w, 64)
    calls = get(w, 72)
    if unit >= get(w, 24) or calls == 18446744073709551615:
        return bad(w)
    put(w, 72, calls + 1)
    put(w, 136, get(w, 4096 + (unit + 1) * 16))
    put(w, 144, 128)
    put(w, 152, get(w, 40))
    put(w, 160, get(w, 32))
    put(w, 0, 4)
    return 1

def event(o:mutbuf, w:mutbuf, status:u64, size:u64) -> u32:
    write(o, 0, RPC_MAGIC, 8)
    write(o, 8, status, 8)
    write(o, 16, size, 8)
    write(o, 24, get(w, 72), 8)
    write(o, 32, get(w, 80), 8)
    write(o, 40, get(w, 64), 8)
    write(o, 48, 0, 8)
    write(o, 56, 0, 8)
    put(w, 176, size)
    return 3

def bad(w:mutbuf) -> u32:
    put(w, 0, 255)
    return 16
'''


def template(*, in_process=False):
    if in_process:
        return inprocess_template()
    source=(ROOT/'tools/hia_continuation_syscalls.S').read_text()
    constants={**LAYOUT,'PW_BYTES':PW_BYTES}
    source='\n'.join(f'.equ {key},{value}' for key,value in constants.items())+'\n'+source
    with tempfile.TemporaryDirectory(prefix='hia-continuation-template-') as directory:
        folder=Path(directory);asm=folder/'adapter.S';obj=folder/'adapter.o';raw=folder/'adapter.bin'
        asm.write_text(source)
        subprocess.run(['as','--64',str(asm),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(address,16) for address,_,name in
            (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
            raise ValueError('unresolved continuation transport relocation')
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)
        +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+code,{name:176+symbols[name] for name in
        ('policy_hole','metadata_hole','metadata_size_hole')}



def inprocess_template():
    source=(ROOT/'tools/hia_continuation_inprocess.S').read_text()
    with tempfile.TemporaryDirectory(prefix='hia-continuation-inprocess-') as directory:
        folder=Path(directory);asm=folder/'adapter.S';obj=folder/'adapter.o';raw=folder/'adapter.bin'
        asm.write_text(source)
        subprocess.run(['as','--64',str(asm),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(address,16) for address,_,name in
            (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
            raise ValueError('unresolved in-process transport relocation')
        code=raw.read_bytes()
    header=bytearray(176);header[:8]=b'HIAINP01';struct.pack_into('<2Q',header,8,1,176)
    return bytes(header)+code,{name:176+symbols[name] for name in
        ('policy_hole','metadata_hole','metadata_size_hole')}


def policy_source():
    source=POLICY+HELPERS
    for name,value in dict(META_MAGIC=META_MAGIC,POOL_MAGIC=POOL_MAGIC,
                            LOW_MAGIC=LOW_MAGIC,RPC_MAGIC=RPC_MAGIC).items():
        source=source.replace(name,str(value))
    return source


def packer_source(*, in_process=False):
    prefix,holes=template(in_process=in_process)
    source=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 99 or length(s) > {LIMIT} or uint(s, 0, 8) != {PACK_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    units = uint(s, 16, 8)
    work = uint(s, 24, 8)
    output = uint(s, 32, 8)
    pool = uint(s, 40, 8)
    literals = uint(s, 48, 8)
    modes = uint(s, 56, 8)
    pool_image = uint(s, 64, 8)
    if policy == 0 or policy > 1048576 or pool_image == 0 or pool_image > 1048576:
        return 4294967295
    if units == 0 or units > 128 or modes == 0 or modes > 1024:
        return 4294967295
    if work < 1024 or work > 1048576 or output < 128 or output > 1048576:
        return 4294967295
    if pool < 64 or pool > 1048576 or literals < 3 or literals > (pool - 16) >> 4:
        return 4294967295
    head = 72 + units * 8 + modes * 16
    if head > length(s):
        return 4294967295
    at = 72 + units * 8
    i = 0
    while i < modes:
        if uint(s, at + i * 16, 8) != i + 1 or uint(s, at + i * 16 + 8, 8) > 4:
            return 4294967295
        i = i + 1
    size = head + policy + pool_image
    i = 0
    while i < units:
        n = uint(s, 72 + i * 8, 8)
        if n == 0 or n > 1048576 or size > {LIMIT} - n:
            return 4294967295
        size = size + n
        i = i + 1
    if length(s) != size:
        return 4294967295
    meta = 64 + (units + 1) * 16 + modes * 16
    final = {len(prefix)} + meta + size - head
    if final > {LIMIT} or final > length(o):
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8]
        source+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    start=len(prefix)
    source+=f'''    write(o, 96, final, 8)
    write(o, 104, final, 8)
    write(o, {holes['policy_hole']}, {start}+meta-{holes['policy_hole']+4}, 4)
    write(o, {holes['metadata_hole']}, {start-176}, 4)
    write(o, {holes['metadata_size_hole']}, meta, 4)
    write(o, {start}, {META_MAGIC}, 8)
    write(o, {start+8}, units, 8)
    write(o, {start+16}, work, 8)
    write(o, {start+24}, output, 8)
    write(o, {start+32}, pool, 8)
    write(o, {start+40}, literals, 8)
    write(o, {start+48}, modes, 8)
    write(o, {start+56}, 0, 8)
    position = {start} + meta + policy
    write(o, {start+64}, position - 176, 8)
    write(o, {start+72}, pool_image, 8)
    position = position + pool_image
    i = 0
    while i < units:
        n = uint(s, 72 + i * 8, 8)
        write(o, {start+80} + i * 16, position - 176, 8)
        write(o, {start+88} + i * 16, n, 8)
        position = position + n
        i = i + 1
    copy_bytes(s, o, 72 + units * 8, {start+64} + (units + 1) * 16, modes * 16)
    copy_bytes(s, o, head, {start} + meta, size - head)
    return final
'''
    return source+HELPERS


def main():
    for name,source in (('continuation_policy',policy_source()),('continuation_packer',packer_source()),('continuation_inprocess_packer',packer_source(in_process=True))):
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
        path.write_text(render_assembly(document(source,name)))
        print(path.name,path.stat().st_size)


if __name__=='__main__':main()
