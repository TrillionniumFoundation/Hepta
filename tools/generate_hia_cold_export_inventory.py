"""Exact ELF64 inventory assertions used by the frozen scalar export gate.

This finite ELF64 facade mirrors object_structure/object_symbols and the original
closed seven-import ABI. The wanted public names are source-authority inputs;
no target symbol table supplies the expectation.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
IMPORTS=('abort','calloc','malloc','free','memset','memcpy','memmove')
SOURCE=r'''
def inventory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 32 or number(s,0,8) != INPUT_MAGIC or length(w) < 2048 or length(o) < 8:
        return 4294967295
    size = number(s,8,8)
    count = number(s,16,8)
    table = number(s,24,8)
    if size < 64 or size > 67108864 or count == 0 or count > 128 or table != count * 136:
        return 4294967295
    base = 32 + table
    if length(s) != base + size:
        return 4294967295
    i = 0
    while i < count:
        name = 32 + i * 136
        width = number(s,name,8)
        if width == 0 or width > 128:
            return 4294967295
        j = 0
        while j < 128:
            value = byte(s,name+8+j)
            if j < width:
                if value == 0 or value > 127:
                    return 4294967295
            elif value != 0:
                return 4294967295
            j = j + 1
        j = 0
        while j < i:
            prior = 32 + j * 136
            if number(s,prior,8) == width and equal(s,prior+8,name+8,width) != 0:
                return 4294967295
            j = j + 1
        store(w,i,0)
        i = i + 1
    write(w,1024,0)
    if number(s,base,4) != 1179403647 or number(s,base+4,2) != 258 or number(s,base+16,2) != 1 or number(s,base+18,2) != 62 or number(s,base+52,2) != 64:
        return 4294967295
    sections = number(s,base+40,8)
    section_count = number(s,base+60,2)
    if number(s,base+58,2) != 64 or section_count == 0 or section_count > 4096 or sections < 64 or bounded(size,sections,section_count*64) == 0:
        return 4294967295
    i = 0
    while i < section_count:
        row = base + sections + i*64
        kind = number(s,row+4,4)
        extent = number(s,row+32,8)
        if kind == 0:
            if i != 0 or extent != 0:
                return 4294967295
        elif kind != 8 and extent != 0:
            offset = number(s,row+24,8)
            if offset < 64 or bounded(size,offset,extent) == 0:
                return 4294967295
        i = i + 1
    observed = 0
    i = 0
    while i < section_count:
        row = base + sections + i*64
        if number(s,row+4,4) == 2:
            observed = 1
            link = number(s,row+40,4)
            if link >= section_count or number(s,row+56,8) != 24:
                return 4294967295
            strings = base + sections + link*64
            if number(s,strings+4,4) != 3:
                return 4294967295
            names = number(s,strings+24,8)
            names_size = number(s,strings+32,8)
            if bounded(size,names,names_size) == 0:
                return 4294967295
            cursor = number(s,row+24,8)
            extent = number(s,row+32,8)
            if extent != 0 and bounded(size,cursor,extent) == 0:
                return 4294967295
            end = cursor + extent
            while cursor < end:
                if end - cursor < 24:
                    return 4294967295
                if symbol(s,w,base,cursor,sections,section_count,names,names_size,count) == 0:
                    return 4294967295
                cursor = cursor + 24
        i = i + 1
    if observed == 0:
        return 4294967295
    i = 0
    while i < count:
        if byte(w,i) != 1:
            return 4294967295
        i = i + 1
    write(o,0,1)
    return 8

def symbol(s:readbuf,w:mutbuf,base:u64,cursor:u64,sections:u64,section_count:u64,names:u64,names_size:u64,count:u64) -> u64:
    row = base + cursor
    name = number(s,row,4)
    if name == 0:
        return 1
    info = byte(s,row+4)
    binding = info >> 4
    kind = info & 15
    if binding > 2:
        return 0
    if binding == 0:
        return 1
    if name >= names_size:
        return 0
    width = 0
    while name + width < names_size and byte(s,base+names+name+width) != 0:
        if byte(s,base+names+name+width) > 127:
            return 0
        width = width + 1
    if name + width == names_size:
        return 0
    if width == 0:
        return 1
    start = base + names + name
    section = number(s,row+6,2)
    wanted = expected(s,start,width,count)
    imported = import_code(s,start,width)
    if section == 0:
        if imported == 0:
            return 0
        if wanted != 18446744073709551615 and byte(w,wanted) != 0:
            return 0
        write(w,1024,number_mut(w,1024) | imported)
        return 1
    if kind != 2 or binding != 1 or section >= section_count:
        return 0
    if imported != 0 and (number_mut(w,1024) & imported) != 0:
        return 0
    if wanted == 18446744073709551615 or byte(w,wanted) != 0:
        return 0
    body = base + sections + section*64
    total = number(s,body+32,8)
    at = number(s,row+8,8)
    width = number(s,row+16,8)
    if number(s,body+4,4) != 1 or (number(s,body+8,8) & 6) != 6 or width == 0 or at >= total or width > total-at:
        return 0
    store(w,wanted,1)
    return 1

def expected(s:readbuf,start:u64,width:u64,count:u64) -> u64:
    i = 0
    while i < count:
        at = 32 + i*136
        if number(s,at,8) == width and equal(s,at+8,start,width) != 0:
            return i
        i = i + 1
    return 18446744073709551615

def bounded(size:u64,at:u64,width:u64) -> u64:
    if at > size:
        return 0
    if width > size-at:
        return 0
    return 1

def equal(s:readbuf,a:u64,b:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(s,b+i):
            return 0
        i = i + 1
    return 1

def number(s:readbuf,at:u64,n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(s,at+i) << (i*8))
        i = i + 1
    return value

def number_mut(s:mutbuf,at:u64) -> u64:
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
'''
def source_program():
    source=SOURCE.replace('INPUT_MAGIC',str(int.from_bytes(b'HIAEXI01','little')))
    source+='\ndef import_code(s:readbuf,at:u64,n:u64) -> u64:\n'
    for index,name in enumerate(IMPORTS):
        raw=name.encode();source+=f'    if n == {len(raw)} and number(s,at,{len(raw)}) == {int.from_bytes(raw,"little")}:\n        return {1<<index}\n'
    return source+'    return 0\n'
def main():
    p=ROOT/'examples/hia_bootstrap/cold_export_inventory.hepta';p.write_text(render_assembly(document(source_program(),'cold_export_inventory')));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
