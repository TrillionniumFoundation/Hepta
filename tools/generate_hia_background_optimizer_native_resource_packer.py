"""Fixed native packers for managed BG capsules; no runtime host assembly."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
CONFIG = {'resource': {'bridge': 'e9000000000000000000000000000000535541544155415641574881ecc80000004989fc4989f74989d54889cd4d89c64c89cb4981ff800000000f85160100004881fd000010000f82090100004881fb000200000f85fc0000004d85e40f84f30000004d85ed0f84ea0000004d85f60f84e10000004c89e04c01f80f82d50000004c89ea4801ea0f82c90000004c89f14801d90f82bd0000004939d473094939c50f82af0000004939d673094939cd0f82a10000004939cc73094939c60f829300000049c78580000000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0746983f8107568498db5001000004889e7b918000000fcf348a54889e7bec00000004c89ea4889e94d89f04989d9e8e6feffff898424c00000004c89ee498dbd00040000b910000000fcf348a549c78580000000010000008b8424c000000049898588000000e97cffffff31c0eb05b8fdffffff4881c4c8000000415f415e415d415c5d5bc3', 'holes': {'owner': 1, 'finalizer': 225}, 'roles': ['owner', 'finalizer'], 'magic': 'HIABGRP3', 'export': 'hia_background_native_objects', 'exports': [('hia_background_native_objects', 0), ('hia_background_native_finalizer', 16)], 'relocations': [(954, 'malloc'), (968, 'free')]}}
def fixed_parts(name):
    cfg=CONFIG[name];bridge=bytes.fromhex(cfg["bridge"]);imports=tuple(dict.fromkeys(n for _,n in cfg["relocations"]))
    exports=cfg["exports"];names=tuple(n for n,_ in exports)+imports;strings=bytearray(b"\0");positions={}
    for n in names:positions[n]=len(strings);strings.extend(n.encode()+b"\0")
    symbols=[bytes(24),struct.pack("<IBBHQQ",0,3,0,1,0,0)]
    for n,at in exports:symbols.append(struct.pack("<IBBHQQ",positions[n],18,0,1,at,len(bridge)-at))
    indexes={}
    for n in imports:indexes[n]=len(symbols);symbols.append(struct.pack("<IBBHQQ",positions[n],16,0,0,0,0))
    relas=b"".join(struct.pack("<QQq",off,(indexes[n]<<32)|4,-4)for off,n in cfg["relocations"])
    symbols=b"".join(symbols);strings=bytes(strings)
    header=struct.pack("<16sHHIQQQIHHHHHH",b"\x7fELF\x02\x01\x01"+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for n,kind,flags,size,link,info,align,extent in [
      (".text",1,6,0,0,0,16,0),(".rela.text",4,0,len(relas),3,1,8,24),
      (".symtab",2,0,len(symbols),4,2,8,24),(".strtab",3,0,len(strings),0,0,1,0),
      (".shstrtab",3,0,len(base.SECTIONS),0,0,1,0),(".note.GNU-stack",1,0,0,0,0,1,0)]:
        rows.append(struct.pack("<IIQQQQIIQQ",base.SECTIONS.index(n.encode()+b"\0"),kind,flags,0,0,size,link,info,align,extent))
    return header+bridge,relas,symbols,strings,b"".join(rows)
def source_program(name):
    cfg=CONFIG[name];n=len(cfg["roles"]);assert 0<n<=4
    changes=dict(BRIDGE=bytes.fromhex(cfg["bridge"]),HOLES=cfg["holes"],ROLES=tuple(cfg["roles"]),
      MAGIC=int.from_bytes(cfg["magic"].encode(),"little"),fixed_parts=lambda:fixed_parts(name))
    old={k:getattr(base,k)for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        source=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for old,new in [("length(s)<48",f"length(s)<{16+8*n}"),("uint(s,8,8)!=4",f"uint(s,8,8)!={n}"),
      ("total=48",f"total={16+8*n}"),("while count<4:",f"while count<{n}:"),("at=48",f"at={16+8*n}"),
      ("while i<4:",f"while i<{n}:"),("if i!=3:",f"if i!={n-1}:")]:
        assert old in source,old;source=source.replace(old,new)
    return source
def reference_object(name,flats):
    cfg=CONFIG[name]
    if len(flats)!=len(cfg["roles"])or any(not f or len(f)>4194304 for f in flats):raise ValueError("bounded native roles required")
    prefix,relas,symbols,strings,sections=fixed_parts(name);raw=bytearray(prefix)
    for role,flat in zip(cfg["roles"],flats):
        raw.extend(bytes((-len(raw))%16));off=cfg["holes"][role]
        struct.pack_into("<i",raw,64+off,len(raw)-64-off-4);raw.extend(flat)
    if len(raw)-64>16777216:raise ValueError("original 16 MiB text bound")
    textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
    for b in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(b)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into("<Q",raw,40,sh);struct.pack_into("<QQ",raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into("<Q",raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    for name in CONFIG:
        module="background_optimizer_native_resource_packer"
        d=document(source_program(name),module);p=ROOT/"examples/hia_bootstrap"/(module+".hepta");p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
