"""HIA shared linker for the source compiler's named-export object layout.

The object-layout reader accepts both source compiler layouts: the closed
six-section f0 object and the seven-section named-export object. The latter
declares imported functions with STT_FUNC. Its seven-import list, relocation
checks, dynsym/hash/PLT/GOT emission and hardening retain the general linker.
The original general-emitter source and product are unchanged.
"""
from pathlib import Path
import re,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_shared_linker import source_program as shared_source,document
ROOT=Path(__file__).resolve().parents[1]
def six_layout():
    names=b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'
    source='''
def object_layout(s:readbuf,w:mutbuf) -> u64:
    if length(s) >= 64 and uint(s,56,8) == SIX_HEADER:
        return object_layout_six(s,w)
    return object_layout_seven(s,w)

def object_layout_six(s:readbuf,w:mutbuf) -> u64:
    size = length(s)
    if size < 448 or size > 67108864:
        return 0
    if uint(s,0,8) != 282584257676671 or uint(s,8,8) != 0 or uint(s,16,8) != 4299030529:
        return 0
    if uint(s,24,8) != 0 or uint(s,32,8) != 0 or uint(s,48,8) != 274877906944 or uint(s,56,8) != SIX_HEADER:
        return 0
    h = uint(s,40,8)
    if h < 64 or h != size-384 or (h & 7) != 0:
        return 0
    i = 0
    while i < 64:
        if byte(s,h+i) != 0:
            return 0
        i = i+1
    i = 1
    while i < 6:
        at = h+i*64
        offset = uint(s,at+24,8)
        extent = uint(s,at+32,8)
        if uint(s,at+16,8) != 0 or offset < 64 or within(h,offset,extent) == 0:
            return 0
        i = i+1
    text_size = uint(s,h+96,8)
    sym = uint(s,h+152,8)
    strings = uint(s,h+216,8)
    shstrings = uint(s,h+280,8)
    stack = uint(s,h+344,8)
    if text_size == 0 or sym != aligned(64+text_size,8) or strings != sym+72 or shstrings != strings+4 or stack != shstrings+49:
        return 0
@ROW_CHECKS@
@NAME_CHECKS@
    if uint(s,sym,8) != 0 or uint(s,sym+8,8) != 0 or uint(s,sym+16,8) != 0:
        return 0
    if uint(s,sym+24,8) != 281487861612544 or uint(s,sym+32,8) != 0 or uint(s,sym+40,8) != 0:
        return 0
    if uint(s,sym+48,8) != 281552286121985 or uint(s,sym+56,8) != 0 or uint(s,sym+64,8) == 0 or uint(s,sym+64,8) > text_size or uint(s,strings,4) != 3171840:
        return 0
    put(w,0,64)
    put(w,8,text_size)
    put(w,16,h)
    put(w,24,0)
    put(w,32,sym)
    put(w,40,3)
    put(w,48,2)
    put(w,56,strings)
    put(w,64,4)
    return 1
'''
    source=source.replace('SIX_HEADER',str(int.from_bytes(struct.pack('<4H',0,64,6,4),'little')))
    # Each checked row reproduces inspect_selfhost_object's fixed tuple; only
    # offsets and text extent are read above, independently of any target code.
    rows=[(1,1,6,None,0,0,16,0),(7,2,0,72,3,2,8,24),(15,3,0,4,0,0,1,0),(23,3,0,49,0,0,1,0),(33,1,0,0,0,0,1,0)]
    checks=[]
    for i,(name,kind,flags,size,link,info,align,entry) in enumerate(rows,1):
        fields=[(0,4,name),(4,4,kind),(8,8,flags),(40,4,link),(44,4,info),(48,8,align),(56,8,entry)]
        if size is not None:fields.append((32,8,size))
        if i==1:fields.append((24,8,64))
        for off,width,value in fields:
            checks.append(f'    if uint(s,h+{i*64+off},{width}) != {value}:\n        return 0')
    source=source.replace('@ROW_CHECKS@','\n'.join(checks))
    checks=[]
    for at in range(0,len(names),8):
        data=names[at:at+8]
        checks.append(f'    if uint(s,shstrings+{at},{len(data)}) != {int.from_bytes(data,"little")}:\n        return 0')
    return source.replace('@NAME_CHECKS@','\n'.join(checks))
def source_program():
    source=shared_source();begin=source.index('\ndef object_layout(');end=source.index('\ndef symbols(',begin);old=source[begin:end]
    # Original layout: null,text,rela,sym,str,shstr,stack. The source compiler
    # emits null,text,sym,str,shstr,stack,rela with identical ELF semantics.
    mapping={132:388,136:392,168:424,184:440,152:408,160:416,
             196:132,200:136,232:168,248:184,216:152,224:160,236:172,
             260:196,264:200,280:216,288:224}
    changed=re.sub(r'h \+ ([0-9]+)',lambda m:'h + '+str(mapping.get(int(m[1]),int(m[1]))),old)
    changed=changed.replace('1407404952518656','1125929975808000')
    changed=changed.replace('uint(s, h + 424, 8) != 4294967299','uint(s, h + 424, 8) != 4294967298')
    changed=changed.replace('uint(s, h + 168, 4) != 4','uint(s, h + 168, 4) != 3')
    changed=changed.replace('sym < rela + rela_size','sym < text + text_size')
    changed=changed.replace('if strings < sym + sym_size or strings_size == 0 or within(h, strings, strings_size) == 0 or byte(s, strings) != 0:', 'if strings < sym + sym_size or strings_size == 0 or within(h, strings, strings_size) == 0 or byte(s, strings) != 0 or rela < strings + strings_size:')
    assert changed!=old and source.count(old)==1
    changed=changed.replace('def object_layout(', 'def object_layout_seven(')
    return (source[:begin]+six_layout()+changed+source[end:]).replace('if tag != 16 or value != 0 or extent != 0:', 'if tag != 18 or value != 0 or extent != 0:')
def main():
    p=ROOT/'examples/hia_bootstrap/cold_export_linker.hepta';p.write_text(render_assembly(document(source_program(),'cold_export_linker')));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
