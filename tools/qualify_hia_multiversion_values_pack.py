"""Native two-role packaging and independently assembled mechanical provenance."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct,subprocess
from tools.qualify_hia_multiversion_components import Image
from tools import generate_hia_multiversion_values_packer as m
ROOT=Path(__file__).resolve().parents[1]
sha=lambda x:hashlib.sha256(x).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
    parts=[(D/'multiversion_values.flat').read_bytes(),(D/'unsigned_decimal_values.flat').read_bytes()]
    packet=lambda xs:struct.pack('<8s'+str(len(xs)+1)+'Q',b'HIAMVUP1',len(xs),*map(len,xs))+b''.join(xs)
    pack=Image(D/'multiversion_values_packer.flat');base=packet(parts);expect=m.reference_object(parts)
    def call(raw,cap=None,workcap=128):
        if cap is None:cap=len(expect)
        out=C.create_string_buffer(max(1,cap));C.memset(out,0xa5,len(out));work=C.create_string_buffer(max(workcap,1));source=C.create_string_buffer(raw,len(raw) or 1)
        n=pack.entry(source,len(raw),out,cap,work,workcap);assert source.raw==(raw or b'\0')
        return n,out.raw[:cap]
    rows=[]
    n,out=call(base);assert n==len(expect) and out==expect;rows.append({'case':'actual-native-object','bytes':n,'sha256':sha(out)})
    report=json.loads((D/'build.json').read_text());link=Image(report['linker']['path']);out=C.create_string_buffer(len(expect)+65536);w=C.create_string_buffer(1<<20);n=link(expect,out,w);assert sha(out.raw[:n])==report['image_sha256'];rows.append({'case':'actual-native-shared-link','sha256':sha(out.raw[:n])})
    source=ROOT/'tools/hia_multiversion_values_bridge.S';obj=D/'independent-mechanical.o';binary=D/'independent-mechanical.bin'
    subprocess.run(['as','--64','--fatal-warnings','-o',str(obj),str(source)],check=True,capture_output=True);subprocess.run(['objcopy','-O','binary','--only-section=.text',str(obj),str(binary)],check=True,capture_output=True)
    assert binary.read_bytes()==m.BRIDGE
    holes={}
    for line in subprocess.check_output(['nm','-an',str(obj)],text=True).splitlines():
        xs=line.split()
        if len(xs)==3 and xs[2].endswith('_hole'):holes[xs[2][:-5]]=int(xs[0],16)
    assert holes==m.HOLES
    rows.append({'case':'actual-independent-mechanical-capsule','bytes':len(m.BRIDGE),'sha256':sha(m.BRIDGE),'source_sha256':sha(source.read_bytes()),'holes':holes})
    variants=[('magic',b'INVALID!'+base[8:]),('short-header',base[:31]),('short-body',base[:-1]),('tail',base+b'x')]
    for at,values in [(8,[0,1,3,2**64-1]),(16,[0,4194305,2**64-1]),(24,[0,4194305,2**64-1])]:
        for value in values:
            raw=bytearray(base);struct.pack_into('<Q',raw,at,value);variants.append((str(at)+'-'+str(value),bytes(raw)))
    for name,raw in variants:
        n,out=call(raw);assert n==0xffffffff and out==b'\xa5'*len(out),(name,n);rows.append({'case':'reject-'+name,'status':n,'transactional_output':True})
    for cap in (0,63,len(expect)-1):
        n,out=call(base,cap);assert n==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'short-output-'+str(cap),'status':n})
    n,out=call(base,workcap=127);assert n==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'short-workspace','status':n})
    for label,xs in [('policy-four-MiB',[parts[0]+bytes(4194304-len(parts[0])),parts[1]]),('values-four-MiB',[parts[0],parts[1]+bytes(4194304-len(parts[1]))]),('both-four-MiB',[bytes(4194304),bytes(4194304)])]:
        expected=m.reference_object(xs);n,out=call(packet(xs),len(expected));assert n==len(expected) and out==expected;rows.append({'case':label,'bytes':n,'sha256':sha(out)})
    record={'schema':'hepta.hia.multiversion-values-packaging.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'packer':pack.pin,'cases':rows}
    (D/'packaging-qualification.json').write_text(json.dumps(record,indent=2)+'\n');print('VALUE_PACK_PASS',len(rows),flush=True)
if __name__=='__main__':main()
