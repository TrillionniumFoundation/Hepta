"""Exact mechanical sources and native packaging of the nine-role intake."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct,subprocess
from tools.qualify_hia_multiversion_components import Image
from tools import generate_hia_multiversion_prepare_intake_packer as m
from tools import generate_hia_multiversion_prepare_process_packer as p
from tools import generate_hia_multiversion_intake_packer as i
ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    a=argparse.ArgumentParser();a.add_argument('--directory',type=Path,required=True);a=a.parse_args();D=a.directory;mechanical=[]
    for name,expected,holes in [('prepare_intake',m.OUTER,m.OUTER_HOLES),('prepare_process',p.BRIDGE,p.HOLES),('intake',i.BRIDGE,i.HOLES)]:
        source=ROOT/'tools'/('hia_multiversion_'+name+'_bridge.S');obj=D/(name+'-provenance.o');binary=D/(name+'-provenance.bin')
        subprocess.run(['/usr/bin/as','--64','--fatal-warnings','-o',str(obj),str(source)],check=True,capture_output=True)
        subprocess.run(['/usr/bin/objcopy','-O','binary','--only-section=.text',str(obj),str(binary)],check=True,capture_output=True)
        assert binary.read_bytes()==expected
        names={}
        for line in subprocess.check_output(['/usr/bin/nm','-an',str(obj)],text=True).splitlines():
            row=line.split()
            if len(row)==3 and row[2].endswith('_hole'):names[row[2][:-5]]=int(row[0],16)
        assert names==holes,(name,names,holes)
        mechanical.append({'source':str(source.relative_to(ROOT)),'source_sha256':sha(source.read_bytes()),'bytes':len(expected),'actual_bytes_sha256':sha(expected),'holes':holes})
    roles=['multiversion_prepare_intake','multiversion_prepare_process','multiversion_intake','core_admission','json_canonical','native_scalar_proof_hash','multiversion_profile','scalar_profile','multiversion_abi']
    parts=[(D/(name+'.flat')).read_bytes() for name in roles];packer=Image(D/'multiversion_prepare_intake_packer.flat');linker=Image(D/'elf_shared_linker.flat')
    def packet(xs):return struct.pack('<8s10Q',b'HIAMVNK1',9,*map(len,xs))+b''.join(xs)
    def call(data,size,work=1048576):
        out=C.create_string_buffer(size);C.memset(out,0xa5,size);w=C.create_string_buffer(work);rc=packer(data,out,w);return rc,out.raw
    data=packet(parts);expected=m.reference_object(parts);rc,out=call(data,len(expected));assert rc==len(expected) and out==expected
    linked=C.create_string_buffer(len(expected)+16384);w=C.create_string_buffer(1<<20);n=linker(out,linked,w);assert linked.raw[:n]==(D/'prepare-intake-component.so').read_bytes()
    rows=[{'case':'actual-nine-role-ET_REL-and-linked-image','object_sha256':sha(out),'image_sha256':sha(linked.raw[:n])}]
    variants=[('magic',b'INVALID!'+data[8:]),('truncated',data[:-1]),('tail',data+b' '),('short-header',data[:87])]
    for at in range(8,88,8):
        for v in ([0,8,10,2**64-1] if at==8 else [0,4194305,2**64-1]):
            x=bytearray(data);struct.pack_into('<Q',x,at,v);variants.append(('field-'+str(at)+'-'+str(v),bytes(x)))
    for label,raw in variants:
        rc,out=call(raw,len(expected));assert rc>=0xfffffff0 and out==b'\xa5'*len(out),(label,rc);rows.append({'case':label,'transactional_refusal':True})
    for n in [0,63,len(expected)-1]:
        rc,out=call(data,n);assert rc==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'output-'+str(n),'transactional_refusal':True})
    rc,out=call(data,len(expected),327);assert rc==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'workspace-327','transactional_refusal':True})
    long=[parts[0]+bytes(4194304-len(parts[0]))]+parts[1:];want=m.reference_object(long);rc,out=call(packet(long),len(want));assert rc==len(want) and out==want;rows.append({'case':'exact-four-MiB-policy','bytes':len(out)})
    huge=[bytes(4194304)]*9;rc,out=call(packet(huge),len(expected));assert rc>=0xfffffff0 and out==b'\xa5'*len(out);rows.append({'case':'original-sixteen-MiB-text-limit','transactional_refusal':True})
    report={'schema':'hepta.hia.multiversion-prepare-intake.packaging.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'mechanical':mechanical,'actual_roles':{name:sha(raw) for name,raw in zip(roles,parts)},'image_sha256':sha((D/'prepare-intake-component.so').read_bytes()),'cases':rows}
    (D/'packaging-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PREPARE_INTAKE_PACK_PASS',len(rows),flush=True)
if __name__=='__main__':main()
