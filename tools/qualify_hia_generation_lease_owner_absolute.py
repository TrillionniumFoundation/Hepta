"""Actual fixed native lexical Path.absolute, Unicode and custody gates."""
from pathlib import Path
import argparse,ctypes as C,errno,fcntl,hashlib,itertools,json,mmap,os,shutil,struct
from tools import qualify_hia_generation_lease_owner_bound as fault
from tools import generate_hia_generation_lease_owner_absolute_packer as packer
MAGIC=int.from_bytes(b'HIAGPAQ1','little')
NORM_MAGIC=int.from_bytes(b'HIAGPAN1','little')
REPLY=int.from_bytes(b'HIAGPAR1','little')
NONE=(1<<64)-1
BAD=4294967293
WORK=200704
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def u64(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def fdset():
    found=set()
    for text in os.listdir('/proc/self/fd'):
        try:os.fstat(int(text));found.add(int(text))
        except OSError:pass
    return found
def request(value,normalized=False):
    body=value.encode('utf-8','surrogatepass')
    return struct.pack('<4Q',NORM_MAGIC if normalized else MAGIC,0,len(body),0)+body
def abort_request():return struct.pack('<4Q',MAGIC,1,0,0)
class Image:
    def __init__(self,path):
        self.lib=C.CDLL(str(path),mode=os.RTLD_NOW|os.RTLD_LOCAL)
        self.entry=self.lib.hia_generation_lease_owner_absolute
        self.entry.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64]
        self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value
class Operation:
    def __init__(self,image):
        self.image=image
        self.work=mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        self.output=mmap.mmap(-1,128,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
    def address(self):return C.addressof(C.c_char.from_buffer(self.work))
    def call(self,data):
        buf=C.create_string_buffer(data)
        rc=int(self.image.entry(C.addressof(buf),len(data),C.addressof(C.c_char.from_buffer(self.output)),128,self.address(),WORK))
        raw=bytes(self.output)
        return rc,raw
    def finish(self):
        assert u64(self.work,0)==97
        assert all(u64(self.work,256+i*8)==NONE for i in range(6))
        self.work.close();self.output.close()
    def close_unused(self):
        self.work.close();self.output.close()
def successful(image,value,normalized=False):
    initial=fdset();op=Operation(image)
    rc,reply=op.call(request(value,normalized))
    assert rc==0 and u64(reply,0)==REPLY and u64(reply,8)==0 and u64(reply,56)==0,(repr(value),rc,list(struct.unpack('<16Q',reply)))
    fd=u64(reply,32);n=u64(reply,40)
    assert fd!=NONE and fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and u64(reply,48)==15
    assert os.fstat(fd).st_size==n and fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
    actual=os.pread(fd,n+1,0)
    expected=(os.path.abspath(value) if normalized else str(Path(value).absolute())).encode('utf-8','surrogatepass')
    assert actual==expected,(repr(value),repr(actual),repr(expected))
    os.close(fd);op.finish();assert fdset()==initial
    return actual

def wire_controls(image):
    initial=fdset();op=Operation(image);op.output[:]=bytes([165])*128
    # First invalid call permits only the fixed bridge's actual self capture.
    rc,raw=op.call(bytes(1));assert rc==BAD and raw==bytes([165])*128
    expected=bytearray(WORK);struct.pack_into('<Q',expected,16,op.address())
    assert op.work[:]==expected
    stable=bytes(op.work)
    samples=[b'',bytes(31),struct.pack('<4Q',MAGIC,2,0,0),abort_request(),
             struct.pack('<4Q',MAGIC,0,1,0),struct.pack('<4Q',MAGIC,0,0,1),
             struct.pack('<4Q',int.from_bytes(b'HIAPTH01','little'),0,0,0)]
    for body in [b'\x80',b'\xc0\x80',b'\xc1\xbf',b'\xe0\x80\x80',b'\xf0\x80\x80\x80',
                 b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xf0\x90\x80',b'\xc2']:
        samples.append(struct.pack('<4Q',MAGIC,0,len(body),0)+body)
    for data in samples:
        rc,raw=op.call(data);assert rc==BAD and raw==bytes([165])*128 and bytes(op.work)==stable
    # Mechanical span rejection precedes every policy write.
    buf=C.create_string_buffer(request('x'))
    for on,wn in [(127,WORK),(128,WORK-1)]:
        rc=image.entry(C.addressof(buf),len(request('x')),C.addressof(C.c_char.from_buffer(op.output)),on,op.address(),wn)
        assert rc==BAD and bytes(op.output)==bytes([165])*128 and bytes(op.work)==stable
    op.close_unused();assert fdset()==initial
    return dict(passed=True,private_wire_controls=len(samples)+3,no_write=True)

def lexical_and_unicode(image):
    cases=['','.','..','/','//','///','////','a','a/.','a/..','a/../b','a//./b///../c',
           './a','../a','//a','//a//..//b','///a/../b','a/../../..','/../../..','//../../..',
           'a\x00b','\x00','a/./\x00/..','quote"\\\n\t',
           '\U0001f600/\u4e2d\u6587','\ud800','\udfff','\udc80','\udcff','\ud800\udc00',
           'x/\ud800\udc00/y','\udc80/./\udcff/../z']
    for a,b in itertools.product(['.','..','a','','//'],repeat=2):
        cases.extend([a+'/'+b,'//'+a+'/'+b,'///'+a+'/'+b])
    for value in cases:successful(image,value)
    for value in ['x'*131073,('part/..//.'*17000),('x\ud800\udc00\U0001f600/'*12000)]:
        successful(image,value)
    return dict(passed=True,cases=len(cases)+3,preserved_dotdot=True,preserved_two_slash_root=True,
                adjacent_surrogates_not_combined=True,large_inputs_without_input_path_syscalls=True)

def actual_filesystems(image,out):
    original=os.open('.',os.O_RDONLY|os.O_DIRECTORY)
    root=out/'paths';root.mkdir()
    cases=0
    try:
        os.chdir(root)
        Path('real').mkdir();Path('link').symlink_to('real',target_is_directory=True)
        for value in ['link/..','link/../missing','link/.','//unresolved/../name']:
            actual=successful(image,value);cases+=1
            if value=='link/..':assert actual.endswith(b'/link/..')
        os.mkdir(b'invalid-\xff-\xed\xa0\x80')
        os.chdir(b'invalid-\xff-\xed\xa0\x80')
        for value in ['','..','next\ud800','a/../b']:successful(image,value);cases+=1
        os.fchdir(original);os.chdir(root)
        Path('long').mkdir();os.chdir('long')
        for i in range(24):
            segment=str(i)+'-'+'p'*190
            os.mkdir(segment);os.chdir(segment)
        assert len(os.getcwdb())>4096
        for value in ['','..','../..','name/../tail','\ud800/\udc80']:
            successful(image,value);cases+=1
        os.fchdir(original);os.chdir(root)
        Path('deleted').mkdir();os.chdir('deleted');os.rmdir(root/'deleted')
        initial=fdset();op=Operation(image)
        rc,reply=op.call(request('child'))
        try:Path('child').absolute()
        except FileNotFoundError as e:expected_errno=e.errno
        else:raise AssertionError('deleted cwd oracle unexpectedly succeeded')
        assert rc==0 and u64(reply,8)==4 and u64(reply,16)==(-expected_errno)&NONE and u64(reply,56)==0
        op.finish();assert fdset()==initial;cases+=1
    finally:
        os.fchdir(original);os.close(original)
        shutil.rmtree(root)
    return dict(passed=True,cases=cases,actual_symlink_not_resolved=True,actual_invalid_fs_bytes=True,
                actual_cwd_over_4096=True,actual_deleted_cwd_error=True)

def real_syscall_failures(image):
    rows=[];initial=fdset()
    for nr,name,value in [(39,'pid','x'),(319,'memfd','x'),(79,'getcwd','x'),
                          (18,'pwrite','/x'),(72,'seals','/x'),(5,'fstat','/x')]:
        op=Operation(image)
        def work():
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),nr,errno.EACCES)
            return op.call(request(value))
        rc,reply=fault.thread_result(work)
        assert rc==0 and u64(reply,0)==REPLY and u64(reply,8)!=0 and u64(reply,16)==(-errno.EACCES)&NONE
        assert u64(reply,32)==NONE and u64(reply,56)==0
        rows.append(dict(syscall=nr,name=name,status=u64(reply,8),errno=errno.EACCES))
        op.finish();assert fdset()==initial
    return dict(passed=True,actual_kernel_seccomp_errors=rows)

def real_pending_custody(image):
    initial=fdset();op=Operation(image)
    def work():
        fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),436,errno.EACCES)
        return op.call(request('relative/../value'))
    rc,reply=fault.thread_result(work)
    assert rc==0 and u64(reply,8)==4 and u64(reply,56)==1 and u64(reply,32)==NONE
    held=[u64(op.work,256+i*8) for i in range(6) if u64(op.work,256+i*8)!=NONE]
    assert len(held)==3 and u64(op.work,0)==98
    for fd in held:os.fstat(fd)
    # A bytewise context copy has no authority to consume the original FDs.
    copied=Operation(image);copied.work[:]=op.work[:];copied.output[:]=bytes([165])*128
    rc,raw=copied.call(abort_request())
    assert rc==BAD and raw==bytes([165])*128
    for fd in held:os.fstat(fd)
    copied.close_unused()
    # A fork inherits descriptors but cannot operate its parent's captured PID.
    stable=bytes(op.work);readfd,writefd=os.pipe()
    child=os.fork()
    if child==0:
        try:
            os.close(readfd)
            rc,raw=op.call(abort_request())
            live=all(os.fstat(fd).st_mode for fd in held)
            os.write(writefd,json.dumps(dict(rc=rc,live=bool(live))).encode())
            os._exit(0)
        except BaseException:os._exit(91)
    os.close(writefd);child_reply=os.read(readfd,4096);os.close(readfd)
    _,status=os.waitpid(child,0);assert status==0
    data=json.loads(child_reply);assert data==dict(rc=BAD,live=True)
    assert bytes(op.work)==stable
    # The original context retries only its held private FDs after the rejecting
    # thread has exited; it does not repeat input parsing or path acquisition.
    rc,raw=op.call(abort_request())
    assert rc==0 and u64(raw,8)==0 and u64(raw,56)==0 and u64(raw,32)==NONE
    for fd in held:
        try:os.fstat(fd)
        except OSError as e:assert e.errno==errno.EBADF
        else:raise AssertionError('native abort failed to release held descriptor')
    op.finish();assert fdset()==initial
    return dict(passed=True,actual_cleanup_denial=True,retained_fds=len(held),
                copied_context_refused=True,fork_refused=True,real_retry_released_all=True)


def posix_abspath_profile(image,out):
    cases=['','.','..','../..','a/..','a/../b','a/../../b','a//b/../../c',
           '/..','/../..','/a/../b','/a/b/../../../x','//a/b/../../..',
           '///a/../b','//','///','////','//a/../b','../a/../../c',
           'a/./../b//./c','/a/../..','\u4e2d\u6587/../\U0001f600','\\ud800/../x',
           'x/\\ud800\\udc00/../../z','a\\x00b/../tail','\\udc80/../\\udcff',
           'a'*131073+'/../tail',('a/../'*25000)+'tail']
    for a,b in itertools.product(['.','..','a','','//'],repeat=2):
        cases.extend([a+'/'+b,'//'+a+'/'+b])
    for value in cases:successful(image,value,True)
    original=os.open('.',os.O_RDONLY|os.O_DIRECTORY);root=out/'normpaths';root.mkdir()
    filesystem=0
    try:
        os.chdir(root);Path('real').mkdir();Path('link').symlink_to('real',target_is_directory=True)
        for value in ['link/..','link/../missing','/unresolved/../name']:
            successful(image,value,True);filesystem+=1
        os.mkdir(b'invalid-\\xff-\\xed\\xa0\\x80');os.chdir(b'invalid-\\xff-\\xed\\xa0\\x80')
        for value in ['..','../tail','a/../../b']:
            successful(image,value,True);filesystem+=1
        os.fchdir(original);os.chdir(root);Path('long').mkdir();os.chdir('long')
        for i in range(24):
            segment=str(i)+'-'+'p'*190;os.mkdir(segment);os.chdir(segment)
        assert len(os.getcwdb())>4096
        for value in ['..','../..','../../../x','part/../../tail','\\ud800/../end']:
            successful(image,value,True);filesystem+=1
    finally:
        os.fchdir(original);os.close(original);shutil.rmtree(root)
    initial=fdset();op=Operation(image)
    def denied():
        fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),77,errno.EACCES)
        return op.call(request('/part/../tail',True))
    rc,reply=fault.thread_result(denied)
    assert rc==0 and u64(reply,8)==4 and u64(reply,16)==(-errno.EACCES)&NONE
    assert u64(reply,32)==NONE and u64(reply,56)==0
    op.finish();assert fdset()==initial
    return dict(passed=True,cases=len(cases),filesystem_cases=filesystem,
                collapses_dotdot_as_actual_posixpath=True,original_path_absolute_profile_retained=True,
                native_ftruncate_failure_errno=errno.EACCES)



def actual_close_fallback(image):
    before=fdset()
    def fallback():
        fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),436,errno.ENOSYS)
        successful(image,'relative/../literal')
        successful(image,'relative/../normalized',True)
        return dict(lexical_and_normalized_passed=True,actual_close_syscall=True)
    row=fault.thread_result(fallback)
    assert fdset()==before
    reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(reader);op=Operation(image)
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),436,errno.ENOSYS)
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),3,errno.EIO)
            rc,reply=op.call(request('relative/../literal'))
            assert rc==0 and u64(reply,8)!=0 and u64(reply,56)==1 and u64(reply,72)!=0
            assert u64(reply,16)==(-errno.EIO)&NONE and u64(reply,88)==(-errno.EIO)&NONE
            assert u64(reply,32)==NONE and u64(op.work,0)==98
            stable=bytes(op.work);stable_out=bytes(op.output);held=fdset()
            rc,again=op.call(abort_request())
            assert rc==BAD and bytes(op.work)==stable and bytes(op.output)==stable_out
            assert fdset()==held
            os.write(writer,json.dumps(dict(unknown_fd_mask=u64(reply,72),pending=True,
                abort_refused_without_writes=True,no_unknown_fd_retry=True)).encode())
            os._exit(0)
        except BaseException as error:
            os.write(writer,json.dumps(dict(error=repr(error))).encode());os._exit(94)
    os.close(writer);payload=os.read(reader,16384);os.close(reader)
    _,status=os.waitpid(pid,0);unknown=json.loads(payload);assert status==0,unknown
    assert fdset()==before
    return dict(passed=True,actual_close_range_enosys=True,normal_fallback=row,
                actual_close_eio_quarantine=unknown,process_exit_releases_quarantined_custody=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    build=json.loads((args.image.parent/'build.json').read_bytes())
    assert pin(args.image.read_bytes())==build['product']
    image=Image(args.image)
    rows={}
    for name,fn in [('wire',lambda:wire_controls(image)),('lexical-unicode',lambda:lexical_and_unicode(image)),
                    ('filesystem',lambda:actual_filesystems(image,args.output)),
                    ('syscall-failures',lambda:real_syscall_failures(image)),
                    ('pending-custody',lambda:real_pending_custody(image)),
                    ('posix-abspath-profile',lambda:posix_abspath_profile(image,args.output)),
                    ('actual-close-fallback',lambda:actual_close_fallback(image))]:
        row=fn();rows[name]=row;(args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
        print('NATIVE_ABSOLUTE_CASE',name,flush=True)
    report=dict(schema='hepta.hia.owner-lexical-absolute.qualification.v2',passed=True,
                product=pin(args.image.read_bytes()),build=pin((args.image.parent/'build.json').read_bytes()),
                cases=rows,actual_fixed_native_bridge=True,no_python_role_dispatch=True,
                public_path_constructor_qualified=False,tempfile_gettempdir_qualified=False,
                whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(rows))),flush=True)
if __name__=='__main__':main()
