"""Fixed native packers for managed BG capsules; no runtime host assembly."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
CONFIG = {'construct': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd00000c000f82ae0000004881fb000020000f85a10000004d85e40f84980000004d85ed0f848f0000004d85f60f84860000004c89e04c01f8727e4c89ea4801ea72764c89f14801d9726e4939d473054939c572644939cc73054939c6725a4939cd73054939d6725049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849b00000083f80a74dc83f809740f83f8107459b8fdffffffe9820000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c24484d8b5d0041ffd389c0eb27498dbd00100000be10000000498d9500f00000b9800000004d89f04989d9e80000000089c0eb0049898588000000e946ffffff4881c488000000415f415e415d415c5d5bc3', 'holes': {'policy': 195, 'bind': 342}, 'roles': ('policy', 'bind'), 'magic': 'HIABGIP1', 'export': 'hia_background_native_object_construct', 'relocations': []}, 'retire': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd00000c000f82a10000004881fb000020000f85940000004d85e40f848b0000004d85ed0f84820000004d85f6747d4c89e04c01f872754c89ea4801ea726d4c89f14801d972654939d473054939c5725b4939cc73054939c672514939cd73054939d6724749c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0746c83f80a74e083f8097407b8fdffffffeb5b4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c24484d8b5d0041ffd389c0eb0049898588000000e979ffffff4881c488000000415f415e415d415c5d5bc3', 'holes': {'policy': 191}, 'roles': ('policy',), 'magic': 'HIABGTP1', 'export': 'hia_background_native_object_retire', 'relocations': []}, 'methods': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd00000c000f82a10000004881fb000020000f85940000004d85e40f848b0000004d85ed0f84820000004d85f6747d4c89e04c01f872754c89ea4801ea726d4c89f14801d972654939d473054939c5725b4939cc73054939c672514939cd73054939d6724749c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0746c83f80a74e083f8097407b8fdffffffeb5b4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c24484d8b5d0041ffd389c0eb0049898588000000e979ffffff4881c488000000415f415e415d415c5d5bc3', 'holes': {'policy': 191}, 'roles': ('policy',), 'magic': 'HIABGMP1', 'export': 'hia_background_native_object_methods', 'relocations': []}, 'owner': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000010000f822d0100004881fb000200000f85200100004d85e40f84170100004d85ed0f840e0100004d85f60f840501000049f7c6070000000f85f80000004c89e04c01f80f82ec0000004c89ea4801ea0f82e00000004c89f14801d90f82d40000004939d473094939c50f82c60000004939cc73094939c60f82b80000004939cd73094939d60f82aa00000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f844202000083f80a74dc83f8010f848100000083f8020f84f400000083f8030f841101000083f8060f842801000083f8070f842d01000083f8080f843401000083f809745a83f80f742e83f80b0f845b01000083f8100f846101000083f8110f848001000083f8120f84a5010000b8fdffffffe9cf0100004d89b500040000488d058bfeffff4989850804000031c0e9a701000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c247800750b498b45000f05e93c0100004c89d14d8b5d0041ffd389c0e92b01000049817d00b00000000f8550ffffff498d96b0000000418b4508418b4d10f00fb10ae90501000049817d00b00000000f852affffff498d96b0000000418b45088702e9e5000000498b7d00e800000000e9d7000000498b7d00e80000000031c0e9c7000000498b45004883f8030f87ecfeffff498b7508480334c4498b45104883f8030f87d6feffff498b7d1848033cc4498b4d20fcf3a431c0e98d000000498b7d00498b4d0831c0fcf3aaeb7e4c89e74c89fe498d9500800000b900000c004d8b85e000000041b900002000e80000000089c0eb56498dbd00100000be10000000498d9500800000b900000c004d8b85e000000041b900002000e80000000089c0eb284c89e74c89fe498d9500800000b900000c004d8b85e000000041b900002000e80000000089c0eb0049898588000000e99ffdffff4881c488000000415f415e415d415c5d5bc3', 'holes': {'policy': 232, 'construct': 716, 'retire': 762, 'methods': 802}, 'roles': ('policy', 'construct', 'retire', 'methods'), 'magic': 'HIABGOP2', 'export': 'hia_background_native_objects', 'relocations': [(586, 'malloc'), (600, 'free')]}}
def fixed_parts(name):
    cfg=CONFIG[name];bridge=bytes.fromhex(cfg["bridge"]);imports=tuple(dict.fromkeys(n for _,n in cfg["relocations"]))
    names=(cfg["export"],*imports);strings=bytearray(b"\0");positions={}
    for n in names:positions[n]=len(strings);strings.extend(n.encode()+b"\0")
    symbols=[bytes(24),struct.pack("<IBBHQQ",0,3,0,1,0,0),struct.pack("<IBBHQQ",positions[names[0]],18,0,1,0,len(bridge))]
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
        module="background_optimizer_native_object_"+name+"_packer"
        d=document(source_program(name),module);p=ROOT/"examples/hia_bootstrap"/(module+".hepta");p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
