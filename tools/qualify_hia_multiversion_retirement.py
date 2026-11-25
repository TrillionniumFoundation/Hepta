"""Fresh original/native same-holder retirement qualification."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,struct,_ctypes
from tools.qualify_hia_multiversion_image import Fixture
from tools.qualify_hia_multiversion_components import get
from hepta.hia_native_retirement import _ReferencePathIdentityPin,_ReferenceNativeRetirement
from hepta import hia_multiversion as original
STATUS=('not_acquired','open','unknown','closed')
DISK=('not_attempted','absent','blocked_by_uncertain_native_release','refused_unowned','removed','error',None)
OBS=('pending','absent','owned_present','replaced','unbound','recreated_after_release','error')
NONE=(1<<64)-1
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
def original_summary(owner):
    r=owner.snapshot();p=r['artifact_identity_pin'];native=r['native']
    return {'native_attempted':r['native_attempted'],'native_succeeded':r['native_release_succeeded'],'complete':r['complete'],
      'library':native.get('library',{}).get('status'),'fd':native.get('fd',{}).get('status'),
      'disk':r['disk'].get('status'),'disk_before':r['disk'].get('before',{}).get('status'),'disk_attempts':r['disk_attempts'],
      'pin':{k:p[k] for k in ('acquisition_attempted','identity_bound','identity_fd_held','path_released','close_attempted','release_succeeded')},
      'pin_close':p['close']['status']}
def native_summary(out):
    flags=get(out,24);v=struct.unpack('<64Q',out.raw[128:640]);attempt=bool(v[22])
    return {'native_attempted':attempt,'native_succeeded':bool(flags&4),'complete':bool(flags&8),
      'library':STATUS[v[23]] if attempt else None,'fd':STATUS[v[24]] if attempt else None,
      'disk':DISK[v[29]],'disk_before':OBS[v[32]] if v[28] else None,'disk_attempts':v[28],
      'pin':{'acquisition_attempted':bool(v[4]),'identity_bound':bool(v[7]),'identity_fd_held':bool(flags&2),
        'path_released':bool(v[10]),'close_attempted':bool(v[11]),'release_succeeded':bool(flags&1)},
      'pin_close':STATUS[v[12]]}
class Pair:
    def __init__(self,directory,image_dir):
        self.d=directory;self.d.mkdir()
        A=B/'native-multiversion-call-v5'
        self.f=Fixture(image_dir,B/'native-multiversion-components-v5',A,A)
        self.abi=self.f.make_abi((A/'all-types.core.json').read_bytes());self.data=(A/'all-types.so').read_bytes()
        self.retlib=ctypes.CDLL(str(directory.parent/'retirement-component.so'));self.ret=self.retlib.hia_mv_retire
        self.ret.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64];self.ret.restype=ctypes.c_uint32
        self.out=ctypes.create_string_buffer(768);self.rows=[]
        self.native_path=self.d/'native.so';self.original_path=self.d/'original.so'
    def load(self,mode='loaded'):
        ctypes.memset(self.f.work,0,8192)
        for p in [self.native_path,self.original_path]:
            if mode!='missing':p.write_bytes(self.data)
        native_data=self.data
        digest=hashlib.sha256(native_data).digest()
        if mode=='hash-refusal':digest=bytes(32)
        path=os.fsencode(self.native_path)
        packet=struct.pack('<8sQQQ',b'HIAMVI01',len(path),len(self.abi),len(native_data))+digest+path+self.abi
        source=ctypes.create_string_buffer(packet);rc=self.f.entry(source,len(packet),self.f.out,512,self.f.work,len(self.f.work))
        assert rc==0 if mode=='loaded' else rc!=0
        pin=_ReferencePathIdentityPin(self.original_path)
        inode=None;fd=None;library=None
        if mode!='missing':
            info=self.original_path.lstat();inode=(info.st_dev,info.st_ino);pin.acquire(inode)
        if mode=='loaded':
            fd=original._sealed_fd(self.data);library=ctypes.CDLL('/proc/self/fd/'+str(fd),mode=os.RTLD_LOCAL|os.RTLD_NOW)
        self.reference=_ReferenceNativeRetirement(7,'qualification',self.original_path,inode,library,{},fd,pin)
        self.generation=7
    def call(self,op=1):
        raw=struct.pack('<8sQQ',b'HIAMVRT1',op,self.generation);s=ctypes.create_string_buffer(raw)
        rc=self.ret(s,len(raw),self.out,768,self.f.work,len(self.f.work))
        assert rc==0,(rc,get(self.out,64),get(self.f.work,4096),get(self.f.work,4176),get(self.f.work,6*1048576+9000+8))
        actual=native_summary(self.out)
        if op==1:self.reference.attempt()
        expected=original_summary(self.reference)
        assert actual==expected,(actual,expected,struct.unpack('<64Q',self.out.raw[128:640]))
        if actual['native_attempted']:assert bytes(self.f.work[2048:2176])==bytes(128)
        self.rows.append({'operation':op,'snapshot':actual})
        return actual
    def mutate(self,kind):
        for p in [self.native_path,self.original_path]:
            if kind=='absent':p.unlink()
            elif kind=='replace':
                p.rename(p.with_suffix('.held'));p.write_bytes(b'replacement')
            elif kind=='symlink':
                p.rename(p.with_suffix('.held'));p.symlink_to(p.with_suffix('.held'))
            elif kind=='recreate':p.write_bytes(b'recreated')
            else:raise ValueError(kind)
    def finish_external(self):
        # Only teardown of the isolated test process/remaining known-open pins.
        # Product retirement never receives a new close right from this helper.
        ref=self.reference
        if ref.identity_pin.fd is not None and not ref.identity_pin.close_attempted:os.close(ref.identity_pin.fd)
        if get(self.f.work,32)!=NONE and get(self.f.work,120)==0:os.close(get(self.f.work,32))
        assert get(self.f.work,56)==0 and get(self.f.work,48)==NONE
def qualify(directory,image_dir):
    rows=[]
    for mode in ['loaded','hash-refusal','missing']:
        for scenario in ['normal','absent','replace','symlink']:
            if mode=='missing' and scenario!='normal':continue
            pair=Pair(directory/(mode+'-'+scenario),image_dir);pair.load(mode)
            pair.call(2)
            if scenario!='normal':pair.mutate(scenario)
            pair.call()
            pair.call()
            if not pair.native_path.exists():
                pair.mutate('recreate');last=pair.call();assert pair.native_path.read_bytes()==b'recreated'
            pair.finish_external();rows.append({'case':mode+'-'+scenario,'snapshots':pair.rows})
            print('RETIRE_PAIR_PASS',mode,scenario,flush=True)
    report={'schema':'hepta.hia.multiversion-retirement-effects.v1','whole_native':False,'passed':len(rows),'failed':0,'cases':rows,
      'image_sha256':hashlib.sha256((directory/'retirement-component.so').read_bytes()).hexdigest()}
    (directory/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_RETIRE_PASS',len(rows),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--image-directory',type=Path,required=True);a=p.parse_args();qualify(a.directory,a.image_directory)
if __name__=='__main__':main()
