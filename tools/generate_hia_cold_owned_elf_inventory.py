"""Native exact inspect_owned_object gate, preserving every original predicate."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_cold_export_inventory import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]

def source_program():
    names=b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0'
    source='''def inspect(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    size = length(s)
    if size < 64 or size > 67108864:
        return 4294967295
    if number(s,0,8) != 282584257676671 or number(s,8,8) != 0 or number(s,16,8) != 4299030529:
        return 4294967295
    if number(s,24,8) != 0 or number(s,32,8) != 0 or number(s,48,8) != 274877906944 or number(s,56,8) != 1125929975808000:
        return 4294967295
    h = number(s,40,8)
    if h < 64 or h > size or size-h != 448 or (h & 7) != 0:
        return 4294967295
    i = 0
    while i < 64:
        if byte(s,h+i) != 0:
            return 4294967295
        i = i+1
    i = 1
    while i < 7:
        row = h+i*64
        at = number(s,row+24,8)
        extent = number(s,row+32,8)
        if number(s,row+16,8) != 0 or at < 64 or at > h or extent > h-at:
            return 4294967295
        i = i+1
    text_size = number(s,h+96,8)
    sym = number(s,h+152,8)
    strings = number(s,h+216,8)
    names = number(s,h+280,8)
    stack = number(s,h+344,8)
    rela = number(s,h+408,8)
    rela_size = number(s,h+416,8)
@ROWS@
    if text_size < 5 or sym != ((64+text_size+7) & 18446744073709551608) or strings != sym+120 or names != strings+16 or stack != names+60:
        return 4294967295
    if rela != ((names+60+7) & 18446744073709551608) or h != rela+rela_size or rela_size < 24 or rela_size > 288000:
        return 4294967295
@NAMES@
    remainder = rela_size
    while remainder >= 24:
        remainder = remainder-24
    if remainder != 0:
        return 4294967295
    if number(s,strings,8) != STRING0 or number(s,strings+8,8) != STRING1:
        return 4294967295
    if number(s,sym,8) != 0 or number(s,sym+8,8) != 0 or number(s,sym+16,8) != 0:
        return 4294967295
    if number(s,sym+24,8) != 281487861612544 or number(s,sym+32,8) != 0 or number(s,sym+40,8) != 0:
        return 4294967295
    if number(s,sym+48,8) != 281552286121985 or number(s,sym+56,8) != 0 or number(s,sym+64,8) == 0 or number(s,sym+64,8) > text_size:
        return 4294967295
    if number(s,sym+72,8) != IMPORT0 or number(s,sym+80,8) != 0 or number(s,sym+88,8) != 0:
        return 4294967295
    if number(s,sym+96,8) != IMPORT1 or number(s,sym+104,8) != 0 or number(s,sym+112,8) != 0:
        return 4294967295
    at = rela
    last = 0
    while at < h:
        place = number(s,at,8)
        symbol = number(s,at+12,4)
        if place < 4 or place > text_size-4 or (at != rela and place <= last+4) or number(s,at+8,4) != 4 or (symbol != 3 and symbol != 4) or number(s,at+16,8) != 18446744073709551612:
            return 4294967295
        if number(s,64+place-1,5) != 232:
            return 4294967295
        last = place
        at = at+24
    if length(o) < text_size:
        return 4294967294
    i = 0
    while i < text_size:
        store(o,i,byte(s,64+i))
        i = i+1
    return text_size
'''
    rows=[(1,1,6,None,0,0,16,0),(7,2,0,120,3,2,8,24),(15,3,0,16,0,0,1,0),(23,3,0,60,0,0,1,0),(33,1,0,0,0,0,1,0),(49,4,0,None,2,1,8,24)]
    checks=[]
    for i,(name,kind,flags,size,link,info,align,entry) in enumerate(rows,1):
        fields=[(0,4,name),(4,4,kind),(8,8,flags),(40,4,link),(44,4,info),(48,8,align),(56,8,entry)]
        if size is not None:fields.append((32,8,size))
        if i==1:fields.append((24,8,64))
        for off,width,value in fields:checks.append(f'    if number(s,h+{i*64+off},{width}) != {value}:\n        return 4294967295')
    source=source.replace('@ROWS@','\n'.join(checks));checks=[]
    for at in range(0,len(names),8):
        raw=names[at:at+8];checks.append(f'    if number(s,names+{at},{len(raw)}) != {int.from_bytes(raw,"little")}:\n        return 4294967295')
    source=source.replace('@NAMES@','\n'.join(checks))
    strings=b'\0f0\0calloc\0free\0'
    for key,value in {'STRING0':int.from_bytes(strings[:8],'little'),'STRING1':int.from_bytes(strings[8:],'little'),'IMPORT0':int.from_bytes(struct.pack('<IBBH',4,18,0,0),'little'),'IMPORT1':int.from_bytes(struct.pack('<IBBH',11,18,0,0),'little')}.items():source=source.replace(key,str(value))
    helper=HELPERS[HELPERS.index('\ndef number('):HELPERS.index('\ndef number_mut(')]
    return source+helper

def main():
    p=ROOT/'examples/hia_bootstrap/cold_owned_elf_inventory.hepta';p.write_text(render_assembly(document(source_program(),'cold_owned_elf_inventory')));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
