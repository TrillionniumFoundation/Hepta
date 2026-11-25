"""Full original finite vectors through actual HIA VM and loaded native C ABI."""
from pathlib import Path
import argparse,copy,ctypes,hashlib,json,os,struct
from tools.qualify_hia_multiversion_image import Fixture
from tools.qualify_hia_multiversion_call import decode_abi,function,document
from tools.qualify_hia_multiversion_components import get,put,sha
from hepta import hia_multiversion as original
from hepta.hia_program import verify_program
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
ROOT=Path(__file__).resolve().parents[1]
ARGS=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64]
class Probe:
    def __init__(self,d,image_dir,retirement_dir):
        self.d=d;self.artifacts=B/'native-multiversion-call-v5'
        self.f=Fixture(image_dir,B/'native-multiversion-components-v5',self.artifacts,self.artifacts)
        self.lib=ctypes.CDLL(str(d/'probe-component.so'));self.run=self.lib.hia_mv_probe;self.run.argtypes=ARGS;self.run.restype=ctypes.c_uint32
        self.retlib=ctypes.CDLL(str(retirement_dir/'retirement-component.so'));self.ret=self.retlib.hia_mv_retire;self.ret.argtypes=ARGS;self.ret.restype=ctypes.c_uint32
        self.out=ctypes.create_string_buffer(128);self.rout=ctypes.create_string_buffer(768);self.rows=[]
    def loaded(self,name,data,abi):
        self.path=self.d/(name+'.target.so');self.path.write_bytes(data)
        ctypes.memset(self.f.work,0,8192)
        path=os.fsencode(self.path);packet=struct.pack('<8sQQQ',b'HIAMVI01',len(path),len(abi),len(data))+hashlib.sha256(data).digest()+path+abi
        s=ctypes.create_string_buffer(packet);rc=self.f.entry(s,len(packet),self.f.out,512,self.f.work,len(self.f.work));assert rc==0,(name,rc)
        self.abi=abi
    def retire(self):
        packet=struct.pack('<8sQQ',b'HIAMVRT1',1,7);s=ctypes.create_string_buffer(packet)
        rc=self.ret(s,len(packet),self.rout,768,self.f.work,len(self.f.work))
        assert rc==0 and get(self.rout,24)&8 and not self.path.exists(),(rc,get(self.rout,24))
    def probe(self,name,raw,want,expected_calls=None):
        s=ctypes.create_string_buffer(raw);ctypes.memset(self.out,0xa5,128)
        rc=self.run(s,len(raw),self.out,128,self.f.work,len(self.f.work));receipt=self.out.raw
        assert s.raw==raw+b'\0'
        assert rc==want and receipt[:8]==b'HIAMVPR1' and get(self.out,8)==want,(name,rc,struct.unpack('<16Q',receipt))
        if expected_calls is not None:assert get(self.out,56)==expected_calls,(name,get(self.out,56),expected_calls)
        row={'case':name,'status':rc,'export_index':get(self.out,16),'vector_index':get(self.out,24),'actual_native_calls':get(self.out,56),'vm_steps':get(self.out,64),'expected_word':get(self.out,32),'actual_word':get(self.out,40),'source_sha256':sha(raw),'receipt_sha256':sha(receipt)}
        (self.d/(name+'.response')).write_bytes(receipt);self.rows.append(row);print('MV_PROBE_PASS',name,rc,get(self.out,56),get(self.out,64),flush=True)
        return row
    def qualify(self):
        total=0;firstoff=None
        for name in ['all-types','arity-0-15','arity-16','mixed-16','proved-total-ops','long-names']:
            raw=(self.artifacts/(name+'.core.json')).read_bytes();data=(self.artifacts/(name+'.so')).read_bytes();program=verify_program(raw)
            abi=self.f.make_abi(raw,total=name=='proved-total-ops')
            sigs=original._reference_scalar_profile(program,program.as_dict(),prove_total=name=='proved-total-ops')
            expected=sum(len(original._probe_vectors(x)) for x in sigs);before=set(os.listdir('/proc/self/fd'))
            self.loaded(name,data,abi)
            if name=='all-types':firstoff=get(self.f.out,384)
            try:self.probe(name,raw,0,expected);total+=expected
            finally:self.retire()
            assert set(os.listdir('/proc/self/fd'))==before
        # A valid, same-domain ELF that computes a wrong result must be rejected by
        # the live VM, even though its own actual SHA and mapping are valid.
        raw=(self.artifacts/'all-types.core.json').read_bytes();data=bytearray((self.artifacts/'all-types.so').read_bytes());abi=self.f.make_abi(raw)
        data[firstoff:firstoff+3]=b'\x31\xc0\xc3'
        self.loaded('wrong-native-bool',bytes(data),abi)
        try:self.probe('wrong-native-bool',raw,7)
        finally:self.retire()
        # The same holder is never released by a probe; preparation owns cleanup.
        raw=(self.artifacts/'all-types.core.json').read_bytes();data=(self.artifacts/'all-types.so').read_bytes();abi=self.f.make_abi(raw)
        self.loaded('probe-refusals',data,abi)
        try:
            invalid=bytearray(raw);invalid[0]=ord('!')
            self.probe('invalid-core',bytes(invalid),3)
            value=json.loads(raw)
            value['functions'][0]['name']='absent_function'
            self.probe('missing-core-function',json.dumps(value,separators=(',',':'),sort_keys=True).encode(),3)
            # Reset ordinary owner state, then reject a deliberately absent address.
            address=get(self.f.work,2048);put(self.f.work,2048,0)
            self.probe('absent-address',raw,6,0);put(self.f.work,2048,address)
            put(self.f.work,24,os.getpid()+1);self.probe('wrong-process',raw,1,0);put(self.f.work,24,os.getpid())
        finally:self.retire()
        return total
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',required=True,type=Path);p.add_argument('--image-directory',required=True,type=Path);p.add_argument('--retirement-directory',required=True,type=Path);a=p.parse_args()
    q=Probe(a.directory,a.image_directory,a.retirement_directory);total=q.qualify()
    report={'schema':'hepta.hia.multiversion-full-native-probes.v1','whole_native_runtime':False,'passed':len(q.rows),'failed':0,'full_original_vectors':total,'actual_native_calls':sum(x['actual_native_calls'] for x in q.rows),'scope':'actual HIA complete-Core projection, actual independent HIA scalar VM per vector, actual sealed loaded C ABI, same holder native retirement','image_sha256':sha((a.directory/'probe-component.so').read_bytes()),'retirement_sha256':sha((a.retirement_directory/'retirement-component.so').read_bytes()),'actual_sources':{x:sha((ROOT/x).read_bytes()) for x in ['examples/hia_bootstrap/multiversion_probe_owner.hepta','examples/hia_bootstrap/multiversion_probes.hepta','examples/hia_bootstrap/evaluate_reference_wire.hepta','examples/hia_bootstrap/scalar_reference.hepta','tools/hia_multiversion_probe_bridge.S']},'original_sources':{x:sha((ROOT/x).read_bytes()) for x in ['hepta/hia_multiversion.py','hepta/hia_scalar_reference_wire.py','hepta/hia_program_runtime.py']},'cases':q.rows}
    (a.directory/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_FULL_PROBE_PASS',len(q.rows),total,flush=True)
if __name__=='__main__':main()
