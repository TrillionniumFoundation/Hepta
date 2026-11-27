"""Native public BG capsule with fixed autonomous reaper roles."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
from tools import generate_hia_background_optimizer_native_bundle_packer as original
ROOT=Path(__file__).resolve().parents[1]
ROLES=('public','manager','thread')
OBJECT_MASK=7
MAGIC=int.from_bytes(b'HIABGRP1','little')
HEADER=40
IMPORTS=original.IMPORTS
EXPORTS=(('hia_background_native_public',0),('hia_background_native_objects',512),('hia_background_native_finalizer',528),('hia_background_native_reaper_manager',544))
BRIDGE=bytearray(560)
for _at in (0,512,528,544):BRIDGE[_at]=233
BRIDGE=bytes(BRIDGE)
ELF_HEADER=original.ELF_HEADER
INSPECT=original.INSPECT.replace('while i<61:','while i<3:')
inspect_object=original.inspect_object
MANAGER_HOLES={'thread_entry': 374, 'thread_trampoline': 711, 'old_finalizer': 763}
TRAMPOLINE=672

def fixed_metadata():
    strings=bytearray(b'\0');pos={}
    for name in [n for n,_ in EXPORTS]+list(IMPORTS):
        pos[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    for n,at in EXPORTS:symbols.append(struct.pack('<IBBHQQ',pos[n],18,0,1,at,5))
    for n in IMPORTS:symbols.append(struct.pack('<IBBHQQ',pos[n],16,0,0,0,0))
    rows=[bytes(64)]
    for name,kind,flags,link,info,align,extent in [
      ('.text',1,6,0,0,16,0),('.rela.text',4,0,3,1,8,24),('.symtab',2,0,4,2,8,24),
      ('.strtab',3,0,0,0,1,0),('.shstrtab',3,0,0,0,1,0),('.note.GNU-stack',1,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,0,link,info,align,extent))
    return b''.join(symbols),bytes(strings),b''.join(rows)

def reference_object(parts):
    if len(parts)!=3 or any(not p or len(p)>4194304 for p in parts):raise ValueError('original leaf bound')
    unpacked=[inspect_object(p)for p in parts];bodies=[b for b,r in unpacked]
    if len(bodies[0])<544:raise ValueError('original public exports')
    for name,hole in MANAGER_HOLES.items():
        prefix=b'\xe8'if name=='old_finalizer'else b'\x48\x8d\x15'if name=='thread_trampoline'else b'\x48\x8d\x05'
        if bodies[1][hole-len(prefix):hole]!=prefix or bodies[1][hole:hole+4]!=bytes(4):raise ValueError('fixed native hole')
    if len(bodies[2])<=TRAMPOLINE:raise ValueError('fixed native trampoline')
    out=bytearray(ELF_HEADER+BRIDGE);starts=[]
    for body in bodies:
        out.extend(bytes((-len(out))%16));starts.append(len(out));out.extend(body)
    textn=len(out)-64
    if textn>16777216:raise ValueError('original text bound')
    for off,target in zip((0,512,528,544),(starts[0],starts[0]+512,starts[1],starts[1])):
        struct.pack_into('<i',out,64+off+1,target-64-off-5)
    for name,hole in MANAGER_HOLES.items():
        target=starts[0]+528 if name=='old_finalizer'else starts[2]+(TRAMPOLINE if name=='thread_trampoline'else 0)
        at=starts[1]+hole;struct.pack_into('<i',out,at,target-at-4)
    out.extend(bytes((-len(out))%8));relat=len(out)
    for start,(_,rels)in zip(starts,unpacked):
        for off,name in rels:out.extend(struct.pack('<QQq',start-64+off,((6+IMPORTS.index(name))<<32)|4,-4))
    symbols,strings,sections=fixed_metadata();symat=len(out);out.extend(symbols);strat=len(out);out.extend(strings)
    namesat=len(out);out.extend(base.SECTIONS);noteat=len(out);out.extend(bytes((-len(out))%8));sh=len(out);out.extend(sections)
    struct.pack_into('<Q',out,40,sh)
    for i,off,n in [(1,64,textn),(2,relat,symat-relat),(3,symat,len(symbols)),(4,strat,len(strings)),(5,namesat,len(base.SECTIONS)),(6,noteat,0)]:
        struct.pack_into('<QQ',out,sh+64*i+24,off,n)
    return bytes(out)

def source_program():
    symbols,strings,sections=fixed_metadata();functions=[];calls={}
    for name,raw in [('prefix',ELF_HEADER+BRIDGE),('symbols',symbols),('strings',strings),('names',base.SECTIONS),('sections',sections)]:
        calls[name],fn=base.emitters('bg_bundle_'+name,raw);functions.append(fn)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<8192:
        return 4294967294
    if length(s)<{HEADER} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=3:
        return 4294967295
    at={HEADER}
    i=0
    rels=0
    while i<3:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304 or at>length(s) or n>length(s)-at:
            return 4294967295
        write(w,i*8,at,8)
        write(w,512+i*8,at,8)
        write(w,1024+i*8,n,8)
        write(w,2560+i*8,0,8)
        if (({OBJECT_MASK}>>i)&1)!=0:
            if inspect(s,w,i,at,n)==0:
                return 4294967295
            rels=rels+get(w,2560+i*8)
        at=at+n
        i=i+1
    if at!=length(s):
        return 4294967295
    if fixed_holes(s,w)==0:
        return 4294967295
    at={64+len(BRIDGE)}
    i=0
    while i<3:
        at=(at+15)&18446744073709551600
        write(w,1536+i*8,at,8)
        at=at+get(w,1024+i*8)
        i=i+1
    if at-64>16777216:
        return 4294967295
    write(w,4608,at,8)
    at=(at+7)&18446744073709551608
    write(w,4616,at,8)
    at=at+rels*24
    write(w,4624,at,8)
    at=at+{len(symbols)}
    write(w,4632,at,8)
    at=at+{len(strings)}
    write(w,4640,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,4648,at,8)
    at=(at+7)&18446744073709551608
    write(w,4656,at,8)
    if length(o)<at+448:
        return 4294967294
    write(w,4664,at+448,8)
    i=0
    while i<at+448:
        store(o,i,0)
        i=i+1
'''
    for name,at in [('prefix','0'),('symbols','get(w,4624)'),('strings','get(w,4632)'),('names','get(w,4640)'),('sections','get(w,4656)')]:
        for fn in calls[name]:source+=f'    {fn}(o,{at})\n'
    source+='''    sh=get(w,4656)
    write(o,40,sh,8)
    write(o,sh+88,64,8)
    write(o,sh+96,get(w,4608)-64,8)
    write(o,sh+152,get(w,4616),8)
    write(o,sh+160,get(w,4624)-get(w,4616),8)
    write(o,sh+216,get(w,4624),8)
'''
    source+=f'''    write(o,sh+224,{len(symbols)},8)
    write(o,sh+280,get(w,4632),8)
    write(o,sh+288,{len(strings)},8)
    write(o,sh+344,get(w,4640),8)
    write(o,sh+352,{len(base.SECTIONS)},8)
    write(o,sh+408,get(w,4648),8)
    i=0
    while i<3:
        copy(s,o,get(w,512+i*8),get(w,1536+i*8),get(w,1024+i*8))
        i=i+1
'''
    targets=['get(w,1536)','get(w,1536)+512','get(w,1544)','get(w,1544)']
    for (_,off),target in zip(EXPORTS,targets):source+=f'    write(o,{64+off+1},{target}-{64+off+5},4)\n'
    for name,hole in MANAGER_HOLES.items():
        target='get(w,1536)+528'if name=='old_finalizer'else 'get(w,1552)'+('+'+str(TRAMPOLINE)if name=='thread_trampoline'else '')
        source+=f'    write(o,get(w,1544)+{hole},{target}-get(w,1544)-{hole+4},4)\n'
    source+='''    emit_relocations(s,o,w)
    return get(w,4664)

def fixed_holes(s:readbuf,w:mutbuf) -> u64:
'''
    source+='    if get(w,1024)<544:\n        return 0\n'
    for name,hole in MANAGER_HOLES.items():
        n=1 if name=='old_finalizer'else 3
        expected=232 if n==1 else (1412424 if name=='thread_trampoline'else 363848)
        source+=f'    if get(w,1032)<{hole+4} or uint(s,get(w,520)+{hole-n},{n})!={expected} or uint(s,get(w,520)+{hole},4)!=0:\n        return 0\n'
    source+=f'    if get(w,1040)<{TRAMPOLINE+1}:\n        return 0\n'
    source+='    return 1\n'
    source+=INSPECT
    # All section metadata is fixed; only offsets and sizes are input dependent.
    source+='\ndef section_shape(s:readbuf,at:u64,index:u64) -> u64:\n'
    for i,(name,kind,flags,link,info,align,extent)in enumerate([
      ('.text',1,6,0,0,16,0),('.rela.text',4,0,3,1,8,24),('.symtab',2,0,4,2,8,24),
      ('.strtab',3,0,0,0,1,0),('.shstrtab',3,0,0,0,1,0),('.note.GNU-stack',1,0,0,0,1,0)],1):
        source+=f'''    if index=={i}:
        if uint(s,at,8)!={base.SECTIONS.index(name.encode()+bytes([0]))+(kind<<32)} or uint(s,at+8,8)!={flags} or uint(s,at+16,8)!=0:
            return 0
        if uint(s,at+40,8)!={link+(info<<32)} or uint(s,at+48,8)!={align} or uint(s,at+56,8)!={extent}:
            return 0
        return 1
'''
    source+='    return 0\n\ndef section_names(s:readbuf,at:u64) -> u64:\n'
    for i in range(0,len(base.SECTIONS),8):
        b=base.SECTIONS[i:i+8];source+=f'    if uint(s,at+{i},{len(b)})!={int.from_bytes(b,"little")}:\n        return 0\n'
    source+='    return 1\n\ndef import_name(s:readbuf,at:u64,n:u64) -> u64:\n'
    for i,name in enumerate(IMPORTS,1):
        raw=name.encode()+b'\0';condition=' and '.join(f'uint(s,at+{j},{len(raw[j:j+8])})=={int.from_bytes(raw[j:j+8],"little")}'for j in range(0,len(raw),8))
        source+=f'    if n>={len(raw)} and {condition}:\n        return {i}\n'
    source+='    return 0\n'
    source=source.replace('SECTION_NAMES_N',str(len(base.SECTIONS)))
    return source+'\n'+'\n'.join(functions)+base.HELPERS

def main():
    name='background_optimizer_native_reaper_public_packer'
    d=document(source_program(),name);p=ROOT/'examples/hia_bootstrap'/(name+'.hepta')
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
