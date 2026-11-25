"""Explicit nine-role Future cleanup capsule; the old eight-role packer stays unchanged."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('4c8d150000000041bb00000100eb3a4c8d150000000041bb00800000eb2b4c8d150000000041bb00400000eb1c4c8d150000000041bb00400000eb0d4c8d150000000041bb00100000535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4c895424784c39dd0f82bd0100004881fb000100000f82b00100004d85ed0f84a70100004d85f60f849e0100004c89e84801e80f829201000048894424584c89f04801d80f828101000048894424604c3b74245873094c39e80f876c0100004c89e04c01f80f82600100004d85ff74294d85e40f84520100004c3b64245873094c39e80f87420100004c3b64246073094c39f00f8732010000488d050507000049894640488d050000000049894648488d05f304000049894650488d05d3feffff49894658488d056a03000049894660488d05e603000049894668488d05c1feffff49898698000000488d0549040000498986a0000000488d05b4feffff498986a8000000488d05b5feffff498986b0000000488d0500000000498986b8000000488d05a8feffff498986c0000000488d05fa010000498986c800000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9ff54247885c00f84a101000083f80a74dd83f801744e83f8020f84ca00000083f8030f84e900000083f8040f84ff00000083f8050f840801000083f8060f841101000083f8070f841301000083f8080f841701000083f8097418b8fdffffffe94901000048c784248000000000000000eb0c48c7842480000000010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c24484883bc248000000000750b498b45000f05e9c90000004c89d14d8b5d0041ffd389c0e9b8000000498b55004883fa20740a4883fa2c0f855dffffff4c01f2418b4508418b4d10f00fb10ae990000000498b55004883fa20740a4883fa2c0f8535ffffff4c01f2418b45088702eb71498b45004839e80f831dffffff4c01e8eb5f498b45004839d80f830bffffff4c01f0eb4d498b7d00e8c5060000eb42498b7d00e81707000031c0eb35498b45004883f8030f87e0feffff498b7508480334c4498b45104883f8030f87cafeffff498b7d1848033cc4498b4d20fcf3a431c0498985c0010000e941feffff4881c4a8000000415f415e415d415c5d5bc3535541544155415641574883ec284989fc4989f74989d54889cd4d89c64c89cb4981ffc00000000f85c50000004881fd800000000f82b80000004881fb000100000f82ab0000004d85e40f84a20000004d85ed0f84990000004d85f60f84900000004c89e84801e80f8284000000488904244c89f04801d8727848894424084c3b342473054c39e877684c89e04c01f872604c3b242473054c39e877554c3b64240873054c39f077494881ec008000004c89e74c89fe4889e2b9008000004d89f04989d94c8d150000000041bb00800000e8d7fbffff85c0750f4889e64c89efb910000000fcf348a54881c400800000eb05b8fdffffff4883c428415f415e415d415c5d5bc3534889f34889f8488dbb0002000031d2b9180000004889174883c708ffc975f548ba48494150464330314889930002000048c783080200000100000048899b1002000048898318020000488dbb00020000bec0000000488d9300040000b9008000004c8b83b800000041b900010000e8f9faffff85c075088b83180400005bc3b8020000005bc3534889fb488dbb0002000031c0b918000000fcf348ab48b848494150464330314889830002000048c783080200000200000048899b10020000488dbb00020000bec0000000488d9300040000b9008000004c8b83b800000041b900010000e883faffff85c0751148399b4004000075084889dfe8bb04000031c05bc3534881ec402000004889f34989fa4889e731c0b908000000fcf348ab48b848494142464e3032488904244c895424084889e7be40000000488d542440b9002000004989d841b900010000e80000000085c0750f48837c2448007507488b442460eb05b8020000004881c4402000005bc3535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd004000000f82930000004881fb000100000f828600000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846c01000083f80a74dc83f801744583f8020f84b800000083f8030f84cc00000083f8040f84da00000083f8060f84e300000083f8070f84e500000083f8080f84e900000083f8097415b8fdffffffe91d01000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c247800750b498b45000f05e9a60000004c89d14d8b5d0041ffd389c0e99500000049837d00200f856fffffff498d5620418b4508418b4d10f00fb10aeb7849837d00200f8552ffffff498d5620418b45088702eb61498b45004839e80f8339ffffff4c01e8eb4f498b7d00e852020000eb44498b7d00e8a402000031c0eb37498b45004883f8030f870effffff498b7508480334c4498b45104883f8030f87f8feffff498b7d1848033cc4498b4d20fcf3a431c0eb00498985c0010000e975feffff4881c488000000415f415e415d415c5d5bc3535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000200000f829000000049c745400000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846a01000083f80a74dc83f801745283f8020f849800000083f8030f84b900000083f8040f84d500000083f8050f84e400000083f8060f84f300000083f8070f84f600000083f8080f84fa00000083f8090f8401010000b8fdffffffe9120100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9b3000000498b55004881fa8000000074094881fa8400000075914c01f2418b4508418b4d10f00fb10ae989000000498b55004881fa80000000740d4881fa840000000f8563ffffff4c01f2418b45088702eb64498b7500498dbd00010000b908000000fcf348a531c0eb4c498b7d00498db500010000b908000000fcf348a531c0eb34bf40000000e84c000000eb28498b7d00e89e00000031c0eb1b4d8b5d004c89f7498b750841ffd3eb0b4d8b5d00498b7d0841ffd3498985c0010000e977feffff418b45084881c488000000415f415e415d415c5d5bc3534889fb4889fe4883c620724c31ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff732649ba4849414e4b414c314c8910488d4b20488948084889581048f7d3488958184883c0205bc331c05bc34885ff744a40f6c70f75454883ff20723f4883ef2048b84849414e4b414c31483907752c488b7708488b57104889d148f7d148394f1875184883c22072124839f2750db80b0000000f054885c07501c30f0b')
ROLES=('owner','carrier','timeout','log','cell','kernel','value','notify','cleanup')
FIXUPS=(('owner', 3), ('carrier', 18), ('timeout', 33), ('log', 48), ('log', 63), ('value', 275), ('notify', 386), ('cleanup', 1123), ('notify', 1520), ('cell', 1671), ('kernel', 2163))
EXPORT_SIZE=2734
def fixed_parts():
 strings=b'\0hia_background_optimizer_future_public\0'
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)])
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [
  ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,0,3,1,8,24),
  ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
  ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,b'',symbols,strings,b''.join(rows)
def reference_object(flats):
 if len(flats)!=9 or any(not x or len(x)>4194304 for x in flats):raise ValueError('nine actual bounded HIA roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 offsets_by_role={}
 for role,flat in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16));offsets_by_role[role]=len(raw);raw.extend(flat)
 for role,hole in FIXUPS:struct.pack_into('<i',raw,64+hole,offsets_by_role[role]-64-hole-4)
 if len(raw)-64>16777216:raise ValueError('preserved text domain')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
 return bytes(raw)
def reference_flat(flats):
 obj=reference_object(flats);sh=struct.unpack_from('<Q',obj,40)[0];n=struct.unpack_from('<Q',obj,sh+96)[0];return obj[64:64+n]
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts();functions=[];calls={}
 for name,raw in [('prefix',prefix),('tail',relas+symbols+strings+base.SECTIONS),('sections',sections),('flat_bridge',BRIDGE)]:
  calls[name],src=base.emitters(name,raw);functions.append(src)
 source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<96 or uint(s,0,8)!={int.from_bytes(b'HIABFPP3','little')} or uint(s,8,8)!=9:
        return 4294967295
    if uint(s,88,8)>1:
        return 4294967295
    total=96
    i=0
    while i<9:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,160)-64>16777216:
        return 4294967295
    if uint(s,88,8)==1:
        return pack_flat(s,o,w)
    n=get(w,216)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,168)'),('sections','get(w,208)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,208)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,160)-64,8)
    write(o,sections+152,get(w,168),8)
    write(o,sections+216,get(w,176),8)
    write(o,sections+280,get(w,184),8)
    write(o,sections+344,get(w,192),8)
    write(o,sections+408,get(w,200),8)
'''
 for role,hole in FIXUPS:source+=f'    write(o,{64+hole},get(w,{80+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=96
    i=0
    while i<9:
        copy(s,o,at,get(w,80+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,216)

def layout(w:mutbuf) -> u64:
'''
 source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
 source+='''    i=0
    while i<9:
        write(w,80+i*8,at,8)
        at=at+get(w,i*8)
        if i!=8:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,160,at,8)
    at=(at+7)&18446744073709551608
    write(w,168,at,8)
    write(w,176,at,8)
'''
 source+=f'''    at=at+{len(symbols)}
    write(w,184,at,8)
    at=at+{len(strings)}
    write(w,192,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,200,at,8)
    at=(at+7)&18446744073709551608
    write(w,208,at,8)
    write(w,216,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def pack_flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,160)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_bridge']:source+=f'    {fn}(o,0)\n'
 for role,hole in FIXUPS:source+=f'    write(o,{hole},get(w,{80+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=96
    i=0
    while i<9:
        copy(s,o,at,get(w,80+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'background_optimizer_future_public_cleanup_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_cleanup_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
