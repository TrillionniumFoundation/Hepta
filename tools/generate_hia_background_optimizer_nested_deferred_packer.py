"""Native one-policy packers for explicit deferred nested BG variants."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_future_packer as base
ROOT=Path(__file__).resolve().parents[1]
MODELS={'structure': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82de0000004881fb800000000f82d10000004d85e40f84c80000004d85ed0f84bf0000004d85f60f84b60000004c89e04c01f80f82aa0000004c89ea4801ea0f829e0000004c89f14801d90f82920000004939d473094939c50f82840000004939cc73054939c6727a4939cd73054939d6727049c785000100000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f841c01000083f80a74dc83f801742f83f804743583f8060f84a900000083f8070f84ab00000083f8080f84af00000083f8097415b8fdffffffe9e300000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb6f4c89d14d8b5d0041ffd389c0eb61498b45004839e80f8373ffffff4c01e8eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8748ffffff498b7508480334c4498b45104883f8030f8732ffffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898508010000e9c5feffff4881c488000000415f415e415d415c5d5bc3', 'symbol': 'hia_background_value_structure_deferred', 'holes': {'policy': 211}, 'relocations': ((421, 'malloc'), (432, 'free')), 'magic': 'HIABTDP1'}, 'transport': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000002000f82e20000004881fb000100000f82d50000004d85e40f84cc0000004d85ed0f84c30000004d85f60f84ba0000004c89e04c01f80f82ae0000004c89ea4801ea0f82a20000004c89f14801d90f82960000004939d473094939c50f82880000004939cc73054939c6727e4939cd73054939d6727449c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f842001000083f80a74dc83f801743383f8040f84a000000083f8060f84a900000083f8070f84ab00000083f8080f84af00000083f8097415b8fdffffffe9e300000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb6f4c89d14d8b5d0041ffd389c0eb61498b45004839e80f8373ffffff4c01e8eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8748ffffff498b7508480334c4498b45104883f8030f8732ffffff498b7d1848033cc4498b4d20fcf3a431c0eb00498985c0010000e9c1feffff4881c488000000415f415e415d415c5d5bc3', 'symbol': 'hia_background_value_transport_deferred', 'holes': {'policy': 211}, 'relocations': ((425, 'malloc'), (436, 'free')), 'magic': 'HIABIDP1'}, 'freeze': {'bridge': '535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000004000f82e20000004881fb000800000f82d50000004d85e40f84cc0000004d85ed0f84c30000004d85f60f84ba0000004c89e04c01f80f82ae0000004c89ea4801ea0f82a20000004c89f14801d90f82960000004939d473094939c50f82880000004939cc73054939c6727e4939cd73054939d6727449c785000100000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f842001000083f80a74dc83f801743383f8040f84a000000083f8060f84a900000083f8070f84ab00000083f8080f84af00000083f8097415b8fdffffffe9e300000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb6f4c89d14d8b5d0041ffd389c0eb61498b45004839e80f8373ffffff4c01e8eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8748ffffff498b7508480334c4498b45104883f8030f8732ffffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898550020000e9c1feffff4881c488000000415f415e415d415c5d5bc3', 'symbol': 'hia_background_value_freeze_deferred', 'holes': {'policy': 211}, 'relocations': ((425, 'malloc'), (436, 'free')), 'magic': 'HIABFDP1'}}
def fixed_parts(kind):
    item=MODELS[kind];bridge=bytes.fromhex(item["bridge"])
    strings=b"\0"+item["symbol"].encode()+b"\0malloc\0free\0"
    symbols=b"".join([bytes(24),struct.pack("<IBBHQQ",0,3,0,1,0,0),
        struct.pack("<IBBHQQ",1,18,0,1,0,len(bridge))]+[
        struct.pack("<IBBHQQ",strings.index(name.encode()+b"\0"),16,0,0,0,0)
        for name in ("malloc","free")])
    relas=b"".join(struct.pack("<QQq",off,((3+("malloc","free").index(name))<<32)|4,-4)
                    for off,name in item["relocations"])
    header=struct.pack("<16sHHIQQQIHHHHHH",b"\x7fELF\x02\x01\x01"+bytes(9),
        1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,typ,flags,size,link,info,align,extent in [
        (".text",1,6,0,0,0,16,0),(".rela.text",4,0,len(relas),3,1,8,24),
        (".symtab",2,0,len(symbols),4,2,8,24),(".strtab",3,0,len(strings),0,0,1,0),
        (".shstrtab",3,0,len(base.base.SECTIONS),0,0,1,0),
        (".note.GNU-stack",1,0,0,0,0,1,0)]:
        rows.append(struct.pack("<IIQQQQIIQQ",base.base.SECTIONS.index(name.encode()+b"\0"),
                    typ,flags,0,0,size,link,info,align,extent))
    return header+bridge,relas,symbols,strings,b"".join(rows)
def apply(kind,function,*args):
    item=MODELS[kind];bridge=bytes.fromhex(item["bridge"])
    changes={"BRIDGE":bridge,"RELOCATIONS":item["relocations"],
      "HOLES":item["holes"],"EXPORT_SIZE":len(bridge),"ROLES":("policy",),
      "MAGIC":int.from_bytes(item["magic"].encode(),"little"),
      "fixed_parts":lambda:fixed_parts(kind)}
    old={k:getattr(base,k)for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        return function(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def source_program(kind):return apply(kind,base.source_program)
def reference_object(kind,parts):return apply(kind,base.reference_object,parts)
def main():
    for kind in MODELS:
        name="background_optimizer_value_"+kind+"_deferred_packer"
        d=document(source_program(kind),name)
        p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
        print(name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),flush=True)
if __name__=="__main__":main()
