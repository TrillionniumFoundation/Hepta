"""Prepare complete independent HIA VM packets for cold export references.

The supplied projection is generated from full Core by the independent native
source/projector root. This owner normalizes actual caller argument words and
adds original execution budgets and complete external borrowed-buffer snapshots.
It never accepts target code or expected return values.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
KINDS=('void','unit','bool','u8','u16','u32','u64','usize','i8','i16','i32','i64','isize')
SOURCE=r'''
def prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 80 or uint(s,0) != INPUT_MAGIC:
        return 4294967295
    mode = uint(s,8)
    projection = uint(s,16)
    arguments = uint(s,24)
    snapshot = uint(s,32)
    steps = uint(s,40)
    depth = uint(s,48)
    heap = uint(s,56)
    failure = uint(s,64)
    if mode > 2 or projection < 72 or projection > 33554432 or arguments > 524288 or snapshot > 33554432:
        return 4294967295
    if mode != 2 and arguments > 16:
        return 4294967295
    if steps == 0 or steps > 10000000 or depth == 0 or depth > 256 or heap > 1073741824 or failure > 10000000 or uint(s,72) != 0:
        return 4294967295
    if length(s) != 80 + arguments * 16 + projection + snapshot:
        return 4294967295
    base = 80 + arguments * 16
    if uint(s,base) != PROJECT_MAGIC:
        return 4294967295
    registers = uint(s,base+8)
    bounce = uint(s,base+16)
    end = uint(s,base+24)
    returns = uint(s,base+32)
    if registers == 0 or bounce == 0 or registers + bounce > 524288 or arguments > registers:
        return 4294967295
    if end < 72 or (end & 7) != 0 or returns > bounce or projection != end + returns * 8:
        return 4294967295
    if uint(s,base+40) > 1 or uint(s,base+48) != 0 or uint(s,base+56) != 0:
        return 4294967295
    size = end + arguments * 8 + 16
    if mode == 0:
        if snapshot != 0:
            return 4294967295
    elif mode == 1:
        if arguments != 3 or snapshot > 1048576:
            return 4294967295
        if uint(s,80) != 14 or uint(s,96) != 15 or uint(s,112) != 15:
            return 4294967295
        if uint(s,88) != 0 or uint(s,104) != 0 or uint(s,120) != 0:
            return 4294967295
        size = size + 80 + snapshot
    external = 0
    if mode == 2:
        total = 0
        i = 0
        while i < arguments:
            kind = uint(s,80+i*16)
            if kind == 14 or kind == 15:
                extent = uint(s,88+i*16)
                if extent > snapshot-total:
                    return 4294967295
                total = total + extent
                external = external + 1
            elif kind < 2 or kind > 12:
                return 4294967295
            i = i + 1
        if total != snapshot:
            return 4294967295
        if external != 0:
            size = size + 8 + external*24 + snapshot
    if size > 33554432:
        return 4294967295
    if length(o) < size:
        return 4294967294
    i = 0
    while i < arguments:
        kind = uint(s,80+i*16)
        if mode == 0 and (kind < 2 or kind > 12):
            return 4294967295
        i = i + 1
    write(o,0,PROGRAM_MAGIC)
    write(o,8,steps)
    write(o,16,depth)
    write(o,24,registers)
    write(o,32,bounce)
    write(o,40,end)
    write(o,48,arguments)
    write(o,56,returns)
    copy(s,o,base+64,64,end-64)
    i = 0
    while i < arguments:
        value = 0
        kind = uint(s,80+i*16)
        if mode == 0 or (mode == 2 and kind < 14):
            value = normalized(kind,uint(s,88+i*16))
        write(o,end+i*8,value)
        i = i + 1
    tail = end + arguments * 8
    write(o,tail,heap)
    write(o,tail+8,failure)
    if mode == 1:
        write(o,tail+16,3)
        write(o,tail+24,0)
        write(o,tail+32,0)
        write(o,tail+40,0)
        write(o,tail+48,1)
        write(o,tail+56,1)
        write(o,tail+64,snapshot)
        write(o,tail+72,2)
        write(o,tail+80,1)
        write(o,tail+88,0)
        copy(s,o,base+projection,tail+96,snapshot)
    if mode == 2 and external != 0:
        write(o,tail+16,external)
        cursor = tail+24
        i = 0
        while i < arguments:
            kind = uint(s,80+i*16)
            if kind == 14 or kind == 15:
                write(o,cursor,i)
                write(o,cursor+8,kind-14)
                write(o,cursor+16,uint(s,88+i*16))
                cursor = cursor + 24
            i = i + 1
        copy(s,o,base+projection,cursor,snapshot)
    return size

def normalized(kind:u64,value:u64) -> u64:
    bits = 64
    if kind == 2:
        bits = 1
    if kind == 3 or kind == 8:
        bits = 8
    if kind == 4 or kind == 9:
        bits = 16
    if kind == 5 or kind == 10:
        bits = 32
    if bits == 64:
        return value
    mask = (1 << bits) - 1
    value = value & mask
    if kind >= 8 and (value & (1 << (bits-1))) != 0:
        value = value | (18446744073709551615 ^ mask)
    return value

def uint(s:readbuf,at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s,at+i) << (i*8))
        i = i + 1
    return value

def write(o:mutbuf,at:u64,value:u64) -> u64:
    i = 0
    while i < 8:
        store(o,at+i,(value >> (i*8)) & 255)
        i = i + 1
    return 0

def copy(s:readbuf,o:mutbuf,at:u64,to:u64,size:u64) -> u64:
    i = 0
    while i < size:
        store(o,to+i,byte(s,at+i))
        i = i + 1
    return 0
'''
def main():
    source=SOURCE
    for key,value in [('INPUT_MAGIC',b'HIAEVP01'),('PROJECT_MAGIC',b'HIAERW02'),('PROGRAM_MAGIC',b'HIARPG02')]:source=source.replace(key,str(int.from_bytes(value,'little')))
    p=ROOT/'examples/hia_bootstrap/cold_export_reference_prepare.hepta';p.write_text(render_assembly(document(source,'cold_export_reference_prepare')));print(p.name,p.stat().st_size)
    from tools.generate_hia_native_filter import document as filter_document
    p=ROOT/'examples/hia_bootstrap/cold_export_reference_filter_packer.hepta'
    p.write_text(render_assembly(filter_document(wire_bytes=33554432+8192,output_bytes=33554432,workspace_bytes=1048576,magic=int.from_bytes(b'HIAVMP01','little'),module='cold_export_reference_filter_packer')))
    print(p.name,p.stat().st_size)
if __name__=='__main__':main()
