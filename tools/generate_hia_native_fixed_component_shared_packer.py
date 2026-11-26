"""Thin native component loader; two fixed parent roles are resolved by native fusion.

The same mechanics and admission policy as HIANLCP1 are retained. Neither a
caller-provided pointer nor dynamic symbol lookup chooses the two parent roles.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_native_fixed_component_packer as full
ROOT=Path(__file__).resolve().parents[1]
ROLES=('loader','catalog','stable')
MAGIC=int.from_bytes(b'HIANLCP2','little')
IMPORTS=full.IMPORTS+('hia_root_sha256_stream','hia_root_native_mapping')
BRIDGE=full.BRIDGE
HOLES={name:full.HOLES[name]for name in ROLES}
RELOCATIONS=full.RELOCATIONS+tuple((at,'hia_root_sha256_stream')for at in full.HOLES['sha'])+tuple((at,'hia_root_native_mapping')for at in full.HOLES['mapping'])
SHARED_PINS={
 'hia_root_sha256_stream':dict(bytes=33264,sha256='d18077e7a13f00859e61101cf487ae579def62df2f5288066dfbb305ae386bfc'),
 'hia_root_native_mapping':dict(bytes=80848,sha256='39b2175453bda3f81ce233c5fe31290e22e0d6f83b69fd57c46d396a6cf895f3')}
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in('hia_native_fixed_component_loader',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_native_fixed_component_loader'],18,0,1,0,len(full.OUTER))]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in[
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(full.common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',full.common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def source_program():
    values=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,fixed_parts=fixed_parts)
    old={name:getattr(full.generic,name)for name in values}
    try:
        for name,value in values.items():setattr(full.generic,name,value)
        source=full.generic.source_program()
    finally:
        for name,value in old.items():setattr(full.generic,name,value)
    for a,b in[('length(s)<48','length(s)<40'),('uint(s,8,8)!=4','uint(s,8,8)!=3'),('total=48','total=40'),
                ('while count<4:','while count<3:'),('at=48','at=40'),('while i<4:','while i<3:'),('if i!=3:','if i!=2:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(parts):
    if len(parts)!=3 or any(not x or len(x)>4194304 for x in parts):raise ValueError('three bounded fixed native policies required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,part in zip(ROLES,parts):
        raw.extend(bytes((-len(raw))%16))
        for at in HOLES[name]:struct.pack_into('<i',raw,64+at,len(raw)-64-at-4)
        raw.extend(part)
    size=len(raw)-64
    if size>16777216:raise ValueError('original 16 MiB text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in[relas,symbols,strings,full.common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
    for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
    return bytes(raw)
def main():
    tree=document(source_program(),'native_fixed_component_shared_packer')
    p=ROOT/'examples/hia_bootstrap/native_fixed_component_shared_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
