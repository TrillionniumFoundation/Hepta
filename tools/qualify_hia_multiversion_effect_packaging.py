"""Native MV effect packers: exact .S provenance, frames, bounds, ELF linking."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib,json,struct,subprocess
from tools.qualify_hia_multiversion_components import Image
ROOT=Path(__file__).resolve().parents[1]
def sha(x):return hashlib.sha256(x).hexdigest()
def mechanical(m,name,d):
    out=d/(name+'-mechanical.o');source=ROOT/'tools'/('hia_multiversion_'+name+'_bridge.S')
    subprocess.run(['as','--64','--fatal-warnings','-o',str(out),str(source)],check=True,capture_output=True)
    raw=out.read_bytes();h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);rows=[struct.unpack_from('<IIQQQQIIQQ',raw,h[6]+i*64) for i in range(h[12])]
    sh=rows[h[13]];ns=raw[sh[4]:sh[4]+sh[5]]
    def string(data,at):return data[at:data.index(0,at)].decode()
    named={string(ns,r[0]):r for r in rows};tx=named['.text'];sy=named['.symtab'];st=rows[sy[6]];strings=raw[st[4]:st[4]+st[5]]
    symbols=[struct.unpack_from('<IBBHQQ',raw,sy[4]+i) for i in range(0,sy[5],24)];values={string(strings,r[0]):r for r in symbols}
    relas=[]
    for r in rows:
        if r[1]==4 and rows[r[7]]==tx:
            for at in range(r[4],r[4]+r[5],24):
                off,info,add=struct.unpack_from('<QQq',raw,at);assert info&0xffffffff==4 and add==-4
                relas.append((off,string(strings,symbols[info>>32][0])))
    actual=(raw[tx[4]:tx[4]+tx[5]],{k:values[k+'_hole'][4] for k in m.ROLES},tuple(relas),values['hia_mv_'+('retire' if name=='retirement' else name)][5])
    assert actual==(m.BRIDGE,m.HOLES,getattr(m,'RELOCATIONS',()),m.EXPORT_SIZE),(name,'mechanical provenance')
    return {'source_sha256':sha(source.read_bytes()),'object_sha256':sha(raw),'bridge_bytes':len(m.BRIDGE),'bridge_sha256':sha(m.BRIDGE)}
def call(image,packet,capacity):
    o=ctypes.create_string_buffer(capacity);w=ctypes.create_string_buffer(1048576);ctypes.memset(o,0xa5,capacity)
    rc=image(packet,o,w);return rc,o.raw
def qualify(name,d,linkerpath):
    m=importlib.import_module('tools.generate_hia_multiversion_'+name+'_packer')
    packer=Image(d/('multiversion_'+name+'_packer.flat'));linker=Image(linkerpath)
    if name=='retirement':roles=['multiversion_retirement','retirement_state'];magic=b'HIAMVRP1';product='retirement'
    elif name=='future':roles=['multiversion_future'];magic=b'HIAMVFP1';product='future'
    elif name=='prepare_process':roles=['multiversion_prepare_process'];magic=b'HIAMVXP1';product='process'
    else:roles=['multiversion_probe_owner','multiversion_probes','evaluate_reference_wire','scalar_reference'];magic=b'HIAMVPP1';product='probe'
    parts=[(d/(r+'.flat')).read_bytes() for r in roles]
    def packet(xs):return struct.pack('<8s'+'Q'*(len(xs)+1),magic,len(xs),*map(len,xs))+b''.join(xs)
    source=packet(parts);expected=m.reference_object(parts);rc,out=call(packer,source,len(expected));assert rc==len(expected) and out==expected
    rc,linked=call(linker,out,len(out)+16384);assert rc<len(linked);linked=linked[:rc]
    assert linked==(d/(product+'-component.so')).read_bytes()
    rows=[{'case':'all-actual-roles','object_sha256':sha(out),'image_sha256':sha(linked)}]
    variants=[('magic',b'BADMAGIC'+source[8:]),('tail',source+b'\0'),('truncated',source[:-1]),('short-header',source[:8*(len(parts)+2)-1])]
    for at in range(8,8*(len(parts)+2),8):
        for value in ([0,len(parts)-1,len(parts)+1,2**64-1] if at==8 else [0,4194305,2**64-1]):
            p=bytearray(source);struct.pack_into('<Q',p,at,value);variants.append((f'field-{at}-{value}',bytes(p)))
    for label,raw in variants:
        rc,out=call(packer,raw,len(expected));assert rc>=0xfffffff0 and out==b'\xa5'*len(out),(name,label,rc)
        rows.append({'case':label,'refused_transactionally':True})
    for size in [0,63,len(expected)-1]:
        rc,out=call(packer,source,size);assert rc==0xfffffffe and out==b'\xa5'*len(out),(name,size,rc)
        rows.append({'case':'output-'+str(size),'refused_transactionally':True})
    long=[parts[0]+bytes(4194304-len(parts[0]))]+parts[1:];want=m.reference_object(long)
    rc,out=call(packer,packet(long),len(want));assert rc==len(want) and out==want
    rows.append({'case':'exact-four-MiB-role','bytes':len(out)})
    if name=='probe':
        large=[bytes(4194304)]*4;rc,out=call(packer,packet(large),len(expected));assert rc>=0xfffffff0 and out==b'\xa5'*len(out)
        rows.append({'case':'all-role-text-overflow','refused_transactionally':True})
    report={'schema':'hepta.hia.multiversion-effect-native-packaging.v1','component':name,'passed':len(rows),'failed':0,'production_packaging_uses_hia_only':True,'whole_native_runtime':False,'mechanical':mechanical(m,name,d),'actual_roles':{r:sha(p) for r,p in zip(roles,parts)},'image_sha256':sha(linked),'cases':rows}
    (d/'packaging-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_EFFECT_PACK_PASS',name,len(rows),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--name',required=True,choices=['retirement','probe','future','prepare_process']);p.add_argument('--directory',type=Path,required=True);p.add_argument('--linker',type=Path,required=True);a=p.parse_args();qualify(a.name,a.directory,a.linker)
if __name__=='__main__':main()
