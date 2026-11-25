"""Independent mechanical provenance and native pack/link qualification."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,subprocess
from tools.qualify_hia_multiversion_components import Image
from tools.generate_hia_multiversion_image_packer import reference_object,ROLES,BRIDGE,HOLES,RELOCATIONS,EXPORT_SIZE
ROOT=Path(__file__).resolve().parents[1]
def sha(x):return hashlib.sha256(x).hexdigest()
def observed(directory):
    out=directory/'mechanical-source-reference.o'
    subprocess.run(['as','--64','--fatal-warnings','-o',str(out),str(ROOT/'tools/hia_multiversion_image_bridge.S')],check=True,capture_output=True)
    raw=out.read_bytes();h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);rows=[struct.unpack_from('<IIQQQQIIQQ',raw,h[6]+i*64) for i in range(h[12])]
    r=rows[h[13]];ns=raw[r[4]:r[4]+r[5]]
    def name(data,at):return data[at:data.index(0,at)].decode()
    named={name(ns,r[0]):r for r in rows};tx=named['.text'];sy=named['.symtab'];st=rows[sy[6]];strings=raw[st[4]:st[4]+st[5]]
    symbols=[struct.unpack_from('<IBBHQQ',raw,sy[4]+i) for i in range(0,sy[5],24)];values={name(strings,r[0]):r for r in symbols};relocs=[]
    for row in rows:
        if row[1]==4 and rows[row[7]]==tx:
            for at in range(row[4],row[4]+row[5],24):
                off,info,add=struct.unpack_from('<QQq',raw,at);assert info&0xffffffff==4 and add==-4;relocs.append((off,name(strings,symbols[info>>32][0])))
    actual=(raw[tx[4]:tx[4]+tx[5]],{k:values[k+'_hole'][4] for k in ROLES},tuple(relocs),values['hia_mv_image'][5])
    assert actual==(BRIDGE,HOLES,RELOCATIONS,EXPORT_SIZE)
    return sha(raw)
def call(image,packet,capacity,work=1048576,fill=165):
    o=ctypes.create_string_buffer(capacity);w=ctypes.create_string_buffer(work);ctypes.memset(o,fill,capacity)
    rc=image(packet,o,w)
    return rc,o.raw
def qualify(directory):
    packer=Image(directory/'multiversion_image_packer.flat');linker=Image(directory/'multiversion_shared_linker.flat')
    source_sha=observed(directory)
    flats=[(directory/(r+'.flat')).read_bytes() for r in ('multiversion_image','sha256_stream','safe_core_elf_inventory','native_mapping')]
    packet=struct.pack('<8s5Q',b'HIAMVPK1',4,*map(len,flats))+b''.join(flats)
    expected=reference_object(flats);rc,out=call(packer,packet,len(expected));assert rc==len(expected) and out==expected
    (directory/'image-component.o').write_bytes(out)
    rc,linked=call(linker,out,len(expected)+16384);assert rc<len(linked);linked=linked[:rc]
    (directory/'image-component.so').write_bytes(linked)
    lib=ctypes.CDLL(str(directory/'image-component.so'));assert lib.hia_mv_image
    rows=[{'case':'actual-four-roles','object_bytes':len(out),'object_sha256':sha(out),'image_bytes':len(linked),'image_sha256':sha(linked)}]
    # New private packet refusal is transactional, before any output is emitted.
    variants=[('magic',b'BADMAGIC'+packet[8:]),('tail',packet+b'\0'),('truncated',packet[:-1]),('short',packet[:47])]
    for at in [8,16,24,32,40]:
        for value in ([0,3,5,2**64-1] if at==8 else [0,4194305,2**64-1]):
            v=bytearray(packet);struct.pack_into('<Q',v,at,value);variants.append((f'word-{at}-{value}',bytes(v)))
    for name,data in variants:
        result,output=call(packer,data,len(expected));assert result>=0xfffffff0 and output==b'\xa5'*len(output),name
        rows.append({'case':name,'refused':True})
    for cap in [0,63,len(expected)-1]:
        result,output=call(packer,packet,cap);assert result==0xfffffffe and output==b'\xa5'*len(output)
        rows.append({'case':f'output-{cap}','refused':True})
    # Exact framing and original general ELF rejection checks remain live.
    for name,data in [('elf-tail',expected+b'\0'),('elf-truncated',expected[:-1]),('elf-magic',b'BAD!'+expected[4:])]:
        result,output=call(linker,data,len(expected)+16384);assert result>=0xfffffff0 and output==b'\xa5'*len(output),name
        rows.append({'case':name,'refused':True})
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',expected)
    sections=[struct.unpack_from('<IIQQQQIIQQ',expected,h[6]+i*64) for i in range(7)]
    v=bytearray(expected);struct.pack_into('<Q',v,h[6]+6*64+8,4)
    result,output=call(linker,bytes(v),len(expected)+16384)
    assert result==len(linked) and output[:result]==linked
    rows.append({'case':'input-stack-flags-canonicalized','same_noexec_output':True})
    for name,mutation in [
        ('import-unknown',lambda v:v.__setitem__(slice(sections[4][4]+14,sections[4][4]+20),b'malloc')),
        ('rela-kind',lambda v:struct.pack_into('<I',v,sections[2][4]+8,1)),
        ('call-displacement',lambda v:v.__setitem__(64+RELOCATIONS[0][0],1)),
        ('duplicate-export',lambda v:struct.pack_into('<Q',v,sections[3][4]+2*24+16,0))]:
        v=bytearray(expected);mutation(v);result,output=call(linker,bytes(v),len(expected)+16384)
        assert result>=0xfffffff0 and output==b'\xa5'*len(output),name
        rows.append({'case':name,'refused':True})
    report={'schema':'hepta.hia.multiversion-image-native-packaging.v1','passed':len(rows),'failed':0,
        'runtime_packaging_native':True,'whole_native_runtime':False,
        'mechanical_source_sha256':sha((ROOT/'tools/hia_multiversion_image_bridge.S').read_bytes()),
        'mechanical_reference_object_sha256':source_sha,
        'packet_sha256':sha(packet),'image_sha256':sha(linked),
        'source_sha256':{x:sha((ROOT/'examples/hia_bootstrap'/(x+'.hepta')).read_bytes()) for x in ['multiversion_image_packer','multiversion_shared_linker']},
        'cases':rows}
    (directory/'packaging-qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('MV_IMAGE_PACKAGING_PASS',len(rows),len(linked),sha(linked),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',required=True,type=Path);a=p.parse_args();qualify(a.directory)
if __name__=='__main__':main()
