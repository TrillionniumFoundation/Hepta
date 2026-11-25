"""Original/native generation-image custody qualification, development only."""
from pathlib import Path
import argparse,copy,ctypes,fcntl,hashlib,json,os,stat,struct,_ctypes
from tools.qualify_hia_multiversion_components import Image,put,get,sha
from tools.qualify_hia_multiversion_call import decode_abi
from hepta import hia_multiversion as original
from hepta.hia_program import verify_program,execute_program
from hepta.elf_shared_abi import inspect_owned_shared_elf
from hepta.hia_native_retirement import _ReferencePathIdentityPin
from hepta.native_mapping_identity import verify_loaded_symbols
ROOT=Path(__file__).resolve().parents[1];NONE=(1<<64)-1
class Fixture:
    def __init__(self,directory,components,call_directory,artifacts):
        self.d=directory;self.artifacts=artifacts
        self.image=ctypes.CDLL(str(directory/'image-component.so'))
        self.entry=self.image.hia_mv_image
        self.entry.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64];self.entry.restype=ctypes.c_uint32
        self.profile=Image(components/'multiversion_profile.flat');self.policy=Image(components/'scalar_profile.flat');self.abi=Image(call_directory/'multiversion_abi.flat')
        self.work=ctypes.create_string_buffer(160<<20);self.out=ctypes.create_string_buffer(512)
        self.rows=[];self.cases=0;self.native_calls=0
    def make_abi(self,raw,total=False):
        w=ctypes.create_string_buffer(32<<20);o=ctypes.create_string_buffer(8<<20);put(o,0,int(total));put(o,8,1);put(o,16,0)
        rc=self.profile(raw,o,w);assert rc<len(o);facts=o.raw[:rc]
        decision=ctypes.create_string_buffer(144);sw=ctypes.create_string_buffer(8192);assert self.policy(facts,decision,sw)==0
        ctypes.memmove(sw,decision,144);out=ctypes.create_string_buffer(16+320*16);rc=self.abi(facts,out,sw);assert rc<=len(out)
        return out.raw[:rc]
    def reference(self,path,abi,size,digest):
        pin=_ReferencePathIdentityPin(Path(os.fsdecode(path)));fd=None;lib=None;functions={}
        try:
            published=os.lstat(path);inode=(published.st_dev,published.st_ino) if stat.S_ISREG(published.st_mode) else None
            pin.acquire(inode)
            data,inode=original._read_artifact(Path(os.fsdecode(path)))
            if inode!=pin.inode or len(data)!=size or hashlib.sha256(data).digest()!=digest:raise ValueError('actual build binding changed')
            signatures=decode_abi(abi);inspect_owned_shared_elf(data,tuple(x[1] for x in signatures))
            fd=original._sealed_fd(data);lib=ctypes.CDLL('/proc/self/fd/'+str(fd),mode=os.RTLD_LOCAL|os.RTLD_NOW)
            for _,name,types,result in signatures:
                fn=getattr(lib,name);fn.argtypes=[original._CTYPES[t] for t in types];fn.restype=original._CTYPES[result];functions[name]=fn
            verify_loaded_symbols(fd,functions)
            return True
        except (OSError,ValueError,RuntimeError) as e:return False
        finally:
            functions.clear()
            if lib is not None:
                for name,value in list(vars(lib).items()):
                    if isinstance(value,ctypes._CFuncPtr):delattr(lib,name)
                _ctypes.dlclose(lib._handle)
            if fd is not None:os.close(fd)
            pin._close_once()
    def run(self,label,path,abi,expected=None,hash_override=None,size_override=None,program=None,frame_override=None):
        path=os.fsencode(path);data=Path(os.fsdecode(path)).read_bytes() if os.path.isfile(path) and not os.path.islink(path) and os.stat(path).st_size<=64<<20 else b''
        size=len(data) if size_override is None else size_override
        digest=hashlib.sha256(data).digest() if hash_override is None else hash_override
        packet=struct.pack('<8sQQQ',b'HIAMVI01',len(path),len(abi),size)+digest+path+abi
        if frame_override is not None:packet=frame_override(packet)
        wanted=self.reference(path,abi,size,digest) if expected is None else expected
        before=set(os.listdir('/proc/self/fd'))
        ctypes.memset(self.work,0,8192);ctypes.memset(self.out,0xa5,512);source=ctypes.create_string_buffer(packet)
        rc=self.entry(source,len(packet),self.out,512,self.work,len(self.work));receipt=self.out.raw
        assert source.raw==packet+b'\0'
        owned=receipt[:8]==b'HIAMVIR1'
        functions={}
        try:
            assert (rc==0)==wanted,(label,rc,get(self.work,0),wanted)
            if wanted:
                assert owned and get(self.out,8)==0
                pinfd,fd,handle=get(self.out,24),get(self.out,32),get(self.out,40)
                assert get(self.out,112)==1 and get(self.out,128)==0 and get(self.out,144)==os.getpid()
                actual=os.fstat(pinfd);pathstat=os.stat(path)
                assert (actual.st_dev,actual.st_ino)==(pathstat.st_dev,pathstat.st_ino)==(get(self.out,96),get(self.out,104))
                assert fcntl.fcntl(fd,1034)==15 and os.pread(fd,size+1,0)==data
                assert receipt[64:96]==digest
                for i,(_,name,types,result) in enumerate(decode_abi(abi)):
                    fn=ctypes.CFUNCTYPE(original._CTYPES[result],*[original._CTYPES[t] for t in types])(get(self.out,256+i*8));functions[name]=fn
                    if program is not None:
                        signature=original.ScalarABI(name,types,result);vectors=original._probe_vectors(signature)
                        for values in [vectors[0],vectors[-1]]:
                            expected_value=execute_program(program,name,list(values),max_steps=4224)['result']
                            value=fn(*values);assert type(value) is type(expected_value) and value==expected_value
                            self.native_calls+=1
                mapping=verify_loaded_symbols(fd,functions)
                for i,(_,name,_,_) in enumerate(decode_abi(abi)):
                    assert mapping['symbols'][name]['file_offset']==get(self.out,384+i*8),(name,mapping['symbols'][name],get(self.out,384+i*8))
                assert get(self.work,40)==NONE,'transient descriptor remains owned'
            row={'case':label,'accepted':rc==0,'rc':rc,'phase':get(self.work,0),'receipt_sha256':sha(receipt),'actual_expected_sha256':digest.hex(),'raw_errno':get(self.out,16) if owned else None}
            (self.d/(label+'.response')).write_bytes(receipt);self.rows.append(row);self.cases+=1
        finally:
            functions.clear()
            if owned:
                handle=get(self.out,40);fd=get(self.out,32);pinfd=get(self.out,24)
                if handle:_ctypes.dlclose(handle)
                if fd!=NONE:os.close(fd)
                if pinfd!=NONE and get(self.out,128)==0:os.close(pinfd)
            after=set(os.listdir('/proc/self/fd'));assert after==before,(label,'fd custody',before,after)
    def qualify(self):
        abi=None
        for label in ['all-types','arity-0-15','arity-16','mixed-16','proved-total-ops','long-names']:
            raw=(self.artifacts/(label+'.core.json')).read_bytes();program=verify_program(raw)
            abi=self.make_abi(raw,total=label=='proved-total-ops')
            source=self.artifacts/(label+'.so');target=self.d/(label+'.target.so');target.write_bytes(source.read_bytes())
            self.run(label,target,abi,program=program)
        raw=(self.artifacts/'all-types.core.json').read_bytes();abi=self.make_abi(raw);data=(self.artifacts/'all-types.so').read_bytes()
        target=self.d/'negative-source.so';target.write_bytes(data)
        self.run('wrong-digest',target,abi,hash_override=bytes(32))
        self.run('wrong-size',target,abi,size_override=len(data)+1)
        bad=bytearray(abi);bad[16+32]=ord('X');self.run('wrong-export',target,bytes(bad))
        malformed=self.d/'bad-elf.so';malformed.write_bytes(b'BAD!'+data[4:]);self.run('bad-elf',malformed,abi)
        small=self.d/'small.so';small.write_bytes(bytes(63));self.run('too-small',small,abi,size_override=64)
        large=self.d/'too-large.so'
        with large.open('wb') as f:f.truncate((64<<20)+1)
        self.run('too-large',large,abi,expected=False,size_override=64<<20)
        missing=self.d/'missing.so';self.run('missing',missing,abi,expected=False,size_override=len(data))
        link=self.d/'symlink.so';link.symlink_to(target);self.run('symlink',link,abi,expected=False,size_override=len(data))
        directory=self.d/'directory.so';directory.mkdir();self.run('directory',directory,abi,expected=False,size_override=len(data))
        fifo=self.d/'fifo.so';os.mkfifo(fifo);self.run('fifo',fifo,abi,expected=False,size_override=len(data))
        weird=os.fsencode(self.d)+b'/raw-\xff\n.so'
        with open(weird,'wb') as f:f.write(data)
        self.run('raw-path-bytes',weird,abi,program=verify_program(raw))
        for label,mutation in [('truncated-frame',lambda p:p[:-1]),('trailing-frame',lambda p:p+b'\0'),('wrong-frame-magic',lambda p:b'BADMAGIC'+p[8:]),('path-nul',lambda p:p[:64]+b'\0'+p[65:]),('short-abi',lambda p:p[:16]+struct.pack('<Q',8)+p[24:])]:
            self.run(label,target,abi,expected=False,frame_override=mutation)
        return self.rows
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--components',type=Path,required=True);p.add_argument('--call-directory',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args()
    f=Fixture(a.directory,a.components,a.call_directory,a.artifacts);rows=f.qualify()
    report={'schema':'hepta.hia.multiversion-image-qualification.v1','scope':'real native HIA capture/seal/ELF/load/mapping and original-helper comparison; preparation proof/retirement/public owner still separate','whole_native':False,'production_packer_complete':False,'passed':len(rows),'failed':0,'actual_loaded_native_vm_calls':f.native_calls,'image_sha256':sha((a.directory/'image-component.so').read_bytes()),'components':json.loads((a.directory/'build.json').read_text()),'original_sources':{r:sha((ROOT/r).read_bytes()) for r in ['hepta/hia_multiversion.py','hepta/hia_native_retirement.py','hepta/native_mapping_identity.py','hepta/elf_shared_abi.py']},'cases':rows}
    (a.directory/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_IMAGE_PASS',len(rows),f.native_calls,flush=True)
if __name__=='__main__':main()
