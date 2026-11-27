"""Native one-policy reaper capsules; fixed platform seams only."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
CONFIG = {'thread': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd002000000f820e0100004881fb000200000f85010100004d85e40f84f80000004d85ed0f84ef0000004d85f60f84e600000049f7c6070000000f85d90000004c89e04c01f80f82cd0000004c89ea4801ea0f82c10000004c89f14801d90f82b50000004939d473094939c50f82a70000004939cc73094939c60f82990000004939cd73094939d60f828b00000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849701000083f80a74dc83f801746683f8020f84d900000083f8030f84f300000083f8060f840701000083f8070f840901000083f8080f840d01000083f809743f83f80f741383f8110f8431010000b8fdffffffe9430100004d89b500040000488d05aafeffff4989850804000031c0e91b01000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c247800750b498b45000f05e9b00000004c89d14d8b5d0041ffd389c0e99f00000049817d00400100000f8550ffffff498d9640010000418b4508418b4d10f00fb10aeb7c49817d00400100000f852dffffff498d9640010000418b45088702eb5f498b7d00e800000000eb54498b7d00e80000000031c0eb47498b45004883f8030f87f8feffff498b7508480334c4498b45104883f8030f87e2feffff498b7d1848033cc4498b4d20fcf3a431c0eb10498bbea800000031f6e800000000eb0049898588000000e94afeffff4881c488000000415f415e415d415c5d5bc30f1f004883ec084989f8488d9700100000488dbf00040000be80000000b900000c0041b900020000e836fdffff31c04883c408c3', 'holes': {'policy': 232}, 'roles': ['policy'], 'magic': 'HIABRTP1', 'export': 'hia_background_native_reaper_thread', 'exports': [('hia_background_native_reaper_thread', 0), ('hia_background_native_reaper_trampoline', 672)], 'relocations': [(549, 'malloc'), (560, 'free'), (633, 'pthread_join')]}, 'manager': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd004000000f82240100004881fb000200000f85170100004d85e40f840e0100004d85ed0f84050100004d85f60f84fc00000049f7c6070000000f85ef0000004c89e04c01f80f82e30000004c89ea4801ea0f82d70000004c89f14801d90f82cb0000004939d473094939c50f82bd0000004939cc73094939c60f82af0000004939cd73094939d60f82a100000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846902000083f80a74dc83f8010f848600000083f8020f84f900000083f8030f841601000083f8060f842d01000083f8070f843201000083f8080f843901000083f809745f83f80f742583f80b0f846001000083f8100f848701000083f8110f8460010000b8fdffffffe9ff0100004d89b500040000488d0594feffff49898508040000488d05000000004989851004000031c0e9c901000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c247800750b498b45000f05e95e0100004c89d14d8b5d0041ffd389c0e94d01000049817d00b00000000f8542ffffff498d96b0000000418b4508418b4d10f00fb10ae92701000049817d00b00000000f851cffffff498d96b0000000418b45088702e907010000498b7d00e800000000e9f9000000498b7d00e80000000031c0e9e9000000498b45004883f8030f87defeffff498b7508480334c4498b45104883f8030f87c8feffff498b7d1848033cc4498b4d20fcf3a431c0e9af000000498b7d00498b4d0831c0fcf3aae99d000000498b8de0000000488db9a800000031f6488d1500000000e800000000eb7f4881ec904000004c89ee4889e7b900080000fcf348a54c89e74c89fe4c89ea4889e94d89f04989d9e800000000898424804000004c89ee488dbc2400400000b910000000fcf348a54889e64c89efb900080000fcf348a5488db42400400000498dbd00200000b910000000fcf348a58b8424804000004881c490400000eb0049898588000000e978fdffff4881c488000000415f415e415d415c5d5bc3', 'holes': {'policy': 232}, 'roles': ['policy'], 'magic': 'HIABRMP1', 'export': 'hia_background_native_reaper_manager', 'exports': [('hia_background_native_reaper_manager', 0)], 'relocations': [(591, 'malloc'), (605, 'free'), (716, 'pthread_create')]}}
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
        module="background_optimizer_native_reaper_"+name+"_packer"
        d=document(source_program(name),module);p=ROOT/"examples/hia_bootstrap"/(module+".hepta");p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
