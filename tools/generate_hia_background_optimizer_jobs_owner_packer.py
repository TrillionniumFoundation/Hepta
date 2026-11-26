"""Native one-policy Jobs owner capsule with the original mechanical boundary."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_background_jobs_packer as original
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=original.BRIDGE
HOLES=original.HOLES
RELOCATIONS=original.RELOCATIONS
EXPORT_SIZE=original.EXPORT_SIZE
ROLES=('policy',)
MAGIC=int.from_bytes(b'HIABJMP1','little')
def fixed_parts():
    strings=b'\0hia_background_optimizer_jobs_owner\0malloc\0free\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0)for name in('malloc','free')])
    relas=b''.join(struct.pack('<QQq',off,((3+('malloc','free').index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
      ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
      ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
      ('.shstrtab',3,0,len(original.base.base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',original.base.base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,strings,b''.join(rows)
def apply(fn,*args):
    changed=dict(BRIDGE=BRIDGE,HOLES=HOLES,RELOCATIONS=RELOCATIONS,EXPORT_SIZE=EXPORT_SIZE,ROLES=ROLES,MAGIC=MAGIC,fixed_parts=fixed_parts)
    saved={k:getattr(original,k)for k in changed}
    try:
        for k,v in changed.items():setattr(original,k,v)
        return fn(*args)
    finally:
        for k,v in saved.items():setattr(original,k,v)
def source_program():return apply(original.source_program)
def reference_object(flats):return apply(original.reference_object,flats)
def main():
    d=document(source_program(),'background_optimizer_jobs_owner_packer')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_jobs_owner_packer.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
