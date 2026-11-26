"""Real native gettempdir ordering, cache, concurrency and retirement gates."""
from pathlib import Path
import argparse,contextlib,ctypes as C,errno,fcntl,hashlib,json,mmap,os,queue,select,shutil,struct,tempfile,threading,time
from concurrent.futures import ThreadPoolExecutor
from tools import qualify_hia_generation_lease_owner_bound as fault
from tools import generate_hia_generation_lease_owner_tempdir_packer as packer
from tools import qualify_hia_native_seccomp_notify as notify
MAGIC=int.from_bytes(b'HIAGTDQ1','little')
REPLY=int.from_bytes(b'HIAGTDR1','little')
NONE=(1<<64)-1
BAD=4294967293
WORK=204800
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def u64(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def fdset():
    result=set()
    for name in os.listdir('/proc/self/fd'):
        try:os.fstat(int(name));result.add(int(name))
        except OSError:pass
    return result
def request(op=0):return struct.pack('<4Q',MAGIC,op,0,0)
class Image:
    def __init__(self,path):
        self.path=path
        self.library=C.CDLL(str(path),mode=os.RTLD_NOW|os.RTLD_LOCAL)
        self.entry=self.library.hia_generation_lease_owner_tempdir
        self.entry.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64]
        self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value
class Context:
    def __init__(self,image):
        self.image=image
        self.work=mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
    def address(self):return C.addressof(C.c_char.from_buffer(self.work))
    def call(self,op=0,data=None):
        data=request(op)if data is None else data
        source=C.create_string_buffer(data)
        output=C.create_string_buffer(bytes([165])*128)
        rc=int(self.image.entry(C.addressof(source),len(data),C.addressof(output),128,self.address(),WORK))
        raw=output.raw[:128]
        return rc,raw
    def get(self):
        rc,raw=self.call()
        assert rc==0 and u64(raw,0)==REPLY and u64(raw,8)==0 and u64(raw,56)==0,(rc,list(struct.unpack('<16Q',raw)),list(struct.unpack('<64Q',self.work[:512])))
        fd,n=u64(raw,32),u64(raw,40)
        assert fd!=NONE and u64(raw,48)==15 and u64(raw,64)==1 and u64(raw,80)==1
        try:
            assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15
            assert fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
            assert os.fstat(fd).st_size==n
            body=os.pread(fd,n+1,0)
            return body.decode('utf-8','surrogatepass')
        finally:os.close(fd)
    def retry(self):
        rc,raw=self.call(2)
        assert rc==0 and u64(raw,8)==0 and u64(raw,56)==0 and u64(raw,32)==NONE,(rc,list(struct.unpack('<16Q',raw)))
    def retire(self):
        rc,raw=self.call(1)
        assert rc==0 and u64(raw,0)==REPLY and u64(raw,8)==0 and u64(raw,56)==0 and u64(raw,72)==1,(rc,list(struct.unpack('<16Q',raw)))
        assert u64(self.work,32)==3 and u64(self.work,24)==0
        assert u64(self.work,40)==NONE and u64(self.work,96)==NONE and u64(self.work,112)==NONE
        assert u64(self.work,104)==0 and u64(self.work,432)==0 and u64(self.work,512)==NONE
        assert all(u64(self.work,i)==0 for i in [192,216,240,288,320,336])
        rc,again=self.call(1);assert rc==0 and u64(again,8)==0 and u64(again,72)==1
        self.work.close()
@contextlib.contextmanager
def environment(values):
    names=[b'TMPDIR',b'TEMP',b'TMP']
    saved={key:os.environb.get(key)for key in names}
    try:
        for key in names:
            os.environb.pop(key,None)
        for key,value in values.items():
            key=key.encode()if isinstance(key,str)else key
            value=os.fsencode(value)if isinstance(value,str)else value
            os.environb[key]=value
        yield
    finally:
        for key in names:
            os.environb.pop(key,None)
            if saved[key]is not None:os.environb[key]=saved[key]

def basic(image,out):
    before=fdset();root=out/'ordered';root.mkdir()
    for name in ['first','second','third']: (root/name).mkdir()
    (root/'file').write_text('not a directory')
    scenarios=[
      dict(TMPDIR=str(root/'first'),TEMP=str(root/'second'),TMP=str(root/'third')),
      dict(TMPDIR=str(root/'missing'),TEMP=str(root/'second'),TMP=str(root/'third')),
      dict(TMPDIR=str(root/'file'),TEMP='',TMP=str(root/'third')),
      dict(TMPDIR='',TEMP='',TMP=''),
      {},
      dict(TMPDIR='//'+str(root/'first').lstrip('/')),
      dict(TMPDIR=str(root/'first')+'/../second'),
      dict(TMPDIR=str(root/'missing'/'..'/'third')),
      dict(TMPDIR='/'+'x'*131073,TEMP=str(root/'second')),
    ]
    rows=[]
    for values in scenarios:
        with environment(values):
            expected=tempfile._get_default_tempdir()
            context=Context(image);actual=context.get()
            assert actual==expected,(values,repr(actual),repr(expected))
            context.retire();rows.append(dict(value=actual,expected=expected))
    assert all(not list((root/name).iterdir())for name in ['first','second','third'])
    assert fdset()==before
    return dict(passed=True,cases=len(rows),actual_oracle='tempfile._get_default_tempdir',rows=rows)

def relative_and_unicode(image,out):
    before=fdset();original=os.open('.',os.O_RDONLY|os.O_DIRECTORY);root=out/'unicode';root.mkdir()
    rows=[]
    try:
        os.chdir(root);Path('one').mkdir();Path('two').mkdir()
        invalid=b'invalid-\\xff-\\xed\\xa0\\x80'
        os.mkdir(invalid)
        for value in ['one','one/../two','./one//./',invalid,'missing/../two','.','./']:
            with environment({b'TMPDIR':value}):
                expected=tempfile._get_default_tempdir()
                context=Context(image);actual=context.get();assert actual==expected,(repr(value),repr(actual),repr(expected))
                context.retire();rows.append(dict(input=repr(value),actual=repr(actual)))
        os.chdir(invalid)
        with environment(dict(TMPDIR='..')):
            expected=tempfile._get_default_tempdir();context=Context(image)
            assert context.get()==expected;context.retire();rows.append(dict(invalid_cwd=True))
        os.fchdir(original);os.chdir(root);Path('long').mkdir();os.chdir('long')
        for i in range(24):
            part=str(i)+'-'+'p'*190;os.mkdir(part);os.chdir(part)
        assert len(os.getcwdb())>4096
        with environment(dict(TMPDIR='.',TEMP=str(root/'two'))):
            expected=tempfile._get_default_tempdir();context=Context(image)
            actual=context.get();assert actual==expected,(repr(actual),repr(expected));context.retire();rows.append(dict(long_actual_cwd=True,value=actual))
    finally:
        os.fchdir(original);os.close(original)
    assert fdset()==before
    return dict(passed=True,cases=len(rows),rows=rows,actual_surrogateescape_and_posix_abspath=True)

def cache_and_concurrency(image,out):
    before=fdset();root=out/'cache';root.mkdir()
    first=root/'first';second=root/'second';first.mkdir();second.mkdir()
    with environment(dict(TMPDIR=str(first))):
        context=Context(image)
        with ThreadPoolExecutor(max_workers=8)as pool:
            values=list(pool.map(lambda _:context.get(),range(32)))
        assert values==[str(first)]*32 and not list(first.iterdir())
        held=u64(context.work,40);os.fstat(held);first.rmdir()
        with environment(dict(TMPDIR=str(second))):
            def unchanged():
                fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),257,errno.EACCES)
                fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),318,errno.EACCES)
                return context.get()
            assert fault.thread_result(unchanged)==str(first)
            assert context.get()==str(first)
        context.retire()
        try:os.fstat(held)
        except OSError as e:assert e.errno==errno.EBADF
        else:raise AssertionError('cache descriptor not retired')
    assert fdset()==before
    return dict(passed=True,threads=8,calls=32,live_cache_survives_environment_and_directory_change=True,
                cached_get_needs_no_open_or_random=True,actual_cache_fd_retired=True)

def wire_and_identity(image,out):
    before=fdset();context=Context(image);original=bytes(context.work)
    samples=[b'',bytes(31),request()+b'x',struct.pack('<4Q',MAGIC,3,0,0),struct.pack('<4Q',MAGIC,0,1,0),
             struct.pack('<4Q',MAGIC,0,0,1),struct.pack('<4Q',int.from_bytes(b'HIAGPAQ1','little'),0,0,0)]
    for data in samples:
        rc,raw=context.call(data=data);assert rc==BAD and raw==bytes([165])*128 and bytes(context.work)==original
    root=out/'identity';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        assert context.get()==str(root)
        stable=bytes(context.work)
        copied=Context(image);copied.work[:]=stable
        rc,raw=copied.call(1);assert rc==BAD and raw==bytes([165])*128 and bytes(copied.work)==stable
        copied.work.close()
        reader,writer=os.pipe();pid=os.fork()
        if pid==0:
            try:
                os.close(reader);rc,raw=context.call(1)
                os.write(writer,json.dumps(dict(rc=rc,unchanged=bytes(context.work)==stable)).encode());os._exit(0)
            except BaseException:os._exit(91)
        os.close(writer);child=json.loads(os.read(reader,4096));os.close(reader)
        _,status=os.waitpid(pid,0);assert status==0 and child==dict(rc=BAD,unchanged=True)
        assert bytes(context.work)==stable
        context.retire()
    assert fdset()==before
    return dict(passed=True,private_wire_no_write_cases=len(samples),copied_context_refused_without_writes=True,
                fork_refused_without_writes=True)

def real_failures(image,out):
    before=fdset();root=out/'failures';root.mkdir()
    rows=[]
    for nr,name in [(39,'getpid'),(9,'mmap'),(318,'getrandom')]:
        with environment(dict(TMPDIR=str(root))):
            context=Context(image)
            def denied():
                fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),nr,errno.EACCES)
                return context.call()
            rc,raw=fault.thread_result(denied)
            assert rc==0 and u64(raw,0)==REPLY and u64(raw,8)!=0 and u64(raw,56)==0 and u64(raw,32)==NONE
            assert u64(raw,16)==(-errno.EACCES)&NONE
            assert context.get()==str(root);context.retire()
            assert not list(root.iterdir()) and fdset()==before
            rows.append(dict(syscall=nr,name=name,errno=errno.EACCES,recovered=True))
    with environment({}):
        context=Context(image)
        def all_open_denied():
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),257,errno.EACCES)
            return context.call()
        rc,raw=fault.thread_result(all_open_denied)
        assert rc==0 and u64(raw,8)==8 and u64(raw,16)==(-errno.ENOENT)&NONE
        assert u64(raw,96)==7 and u64(raw,56)==0 and u64(raw,32)==NONE
        context.retire();rows.append(dict(all_candidates_failed=True,errno=errno.ENOENT))
    assert fdset()==before
    return dict(passed=True,cases=rows,actual_kernel_errors=True)

def pending_cleanup(image,out):
    before=fdset();rows=[]
    for nr,name in [(436,'probe-close'),(87,'probe-unlink'),(11,'mapping-retirement'),(5,'probe-identity')]:
        root=out/('pending-'+name);root.mkdir()
        with environment(dict(TMPDIR=str(root))):
            context=Context(image)
            def denied():
                fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),nr,errno.EIO)
                return context.call()
            rc,raw=fault.thread_result(denied)
            assert rc==0 and u64(raw,8)==11 and u64(raw,56)==1 and u64(raw,80)==1 and u64(raw,32)==NONE
            assert u64(raw,16)==(-errno.EIO)&NONE and u64(context.work,32)==2
            mapped={at:u64(context.work,at)for at in [192,216,240,288,320,336]if u64(context.work,at)}
            assert mapped
            if nr==5:
                held=u64(context.work,96);assert held!=NONE and os.fstat(held).st_size==0
                assert u64(context.work,464)==0 and len(list(root.iterdir()))==1
            elif nr==436:
                held=u64(context.work,96);assert held!=NONE and os.fstat(held).st_size==4
                assert len(list(root.iterdir()))==1
            elif nr==87:
                assert u64(context.work,96)==NONE and u64(context.work,104)==1
                assert len(list(root.iterdir()))==1
            stable=bytes(context.work)
            blocked_rc,blocked=context.call()
            assert blocked_rc==0 and u64(blocked,8)==11 and u64(blocked,56)==1
            assert bytes(context.work)==stable
            copied=Context(image);copied.work[:]=stable
            bad,untouched=copied.call(2);assert bad==BAD and untouched==bytes([165])*128 and bytes(copied.work)==stable
            copied.work.close()
            context.retry();assert not list(root.iterdir())
            assert all(u64(context.work,at)==0 for at in mapped)
            assert context.get()==str(root)
            context.retire();assert fdset()==before
            rows.append(dict(syscall=nr,name=name,retained_mappings=len(mapped),actual_retry=True))
    root=out/'pending-cache-retirement';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        context=Context(image);assert context.get()==str(root);held=u64(context.work,40)
        def denied_cache():
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),436,errno.EIO)
            return context.call(1)
        rc,raw=fault.thread_result(denied_cache)
        assert rc==0 and u64(raw,8)==11 and u64(raw,56)==1 and u64(raw,72)==0
        assert u64(context.work,40)==held;os.fstat(held)
        context.retire();assert fdset()==before
        rows.append(dict(cache_close_retained_until_true_retirement=True))
    return dict(passed=True,cases=rows,known_custody_not_retried_as_new_creation=True)


def actual_codec(image,out):
    raw=C.string_at(image.address+packer.HOLES['codec'],4)
    address=image.address+packer.HOLES['codec']+4+struct.unpack('<i',raw)[0]
    compiled=(image.path.parent/'generation_lease_owner_tempdir_codec.flat').read_bytes()
    assert C.string_at(address,len(compiled))==compiled
    entry=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(address)
    magic=int.from_bytes(b'HIAGTCQ1','little');reply=int.from_bytes(b'HIAGTCR1','little')
    def convert(mode,body):
        header=bytearray(128);struct.pack_into('<3Q',header,0,magic,mode,len(body))
        data=bytes(header)+body;source=C.create_string_buffer(data)
        output=C.create_string_buffer(128+3*len(body));work=C.create_string_buffer(32)
        rc=int(entry(source,len(data),output,len(output),work,32))
        raw=output.raw
        assert rc==0 and u64(raw,0)==reply
        return u64(raw,8),raw[128:128+u64(raw,16)]
    samples=[bytes([i])for i in range(256)]
    samples.extend([bytes([a,b])for a in [0,127,128,191,192,194,223,224,237,239,240,244,255]for b in range(256)])
    samples.extend([bytes(range(256))*512,b'normal/quoted"\\\\path',b'\\xed\\xa0\\x80',b'\\xf4\\x90\\x80\\x80'])
    for body in samples:
        status,encoded=convert(0,body);assert status==0
        expected=body.decode('utf-8','surrogateescape').encode('utf-8','surrogatepass')
        assert encoded==expected,(body[:32],encoded[:32],expected[:32])
        status,decoded=convert(1,encoded);assert status==0 and decoded==body
    rejected=0
    for value in range(0xd800,0xe000):
        text=chr(value)
        status,encoded=convert(1,text.encode('utf-8','surrogatepass'))
        if 0xdc80<=value<=0xdcff:assert status==0 and encoded==text.encode('utf-8','surrogateescape')
        else:assert status==2 and encoded==b'';rejected+=1
    return dict(passed=True,roundtrips=len(samples),surrogate_values=2048,rejected_non_fs_surrogates=rejected,
                actual_embedded_native_codec=True,all_filesystem_bytes_preserved=True)

def replaced_pending_path(image,out):
    before=fdset();root=out/'replacement';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        context=Context(image)
        def denied():
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),87,errno.EIO)
            return context.call()
        rc,raw=fault.thread_result(denied)
        assert rc==0 and u64(raw,8)==11 and u64(raw,56)==1 and u64(context.work,104)==1
        names=list(root.iterdir());assert len(names)==1
        old=names[0];saved=root/'moved-owned-file';old.rename(saved)
        old.write_bytes(b'foreign replacement must survive')
        before_inode=os.stat(old).st_ino
        assert before_inode!=u64(context.work,456)
        context.retry()
        assert os.stat(old).st_ino==before_inode and old.read_bytes()==b'foreign replacement must survive'
        context.retire()
        old.unlink();saved.unlink()
        assert not list(root.iterdir())
    assert fdset()==before
    return dict(passed=True,actual_unlink_eio=True,actual_inode_replacement=True,
                native_retry_preserved_foreign_replacement=True,held_native_resources_retired=True)

def actual_mutex_failure(image,out):
    before=fdset();root=out/'mutex';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        context=Context(image);published=queue.Queue();finished=threading.Event();result={}
        def worker():
            try:
                listener=notify.install(image.address,image.address+len(packer.BRIDGE),318)
                published.put(listener);result['value']=context.get()
            except BaseException as error:result['error']=repr(error)
            finally:finished.set()
        thread=threading.Thread(target=worker);thread.start()
        listener=published.get(timeout=20);pending=None;events=0
        try:
            ready,_,_=select.select([listener],[],[],20);assert ready and not finished.is_set()
            pending=notify.receive(listener);events+=1
            assert pending.data.nr==318 and pending.data.args[0]==context.address()+1536 and pending.data.args[1]==64
            assert u64(context.work,24)==1 and u64(context.work,32)==1
            captured_cwd=u64(context.work,512)
            assert captured_cwd!=NONE and fcntl.fcntl(captured_cwd,fcntl.F_GET_SEALS)==15
            assert os.pread(captured_cwd,u64(context.work,520),0)==os.getcwd().encode('utf-8','surrogatepass')
            stable=bytes(context.work)
            def contender():
                fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),202,errno.EACCES)
                return context.call()
            rc,raw=fault.thread_result(contender)
            assert rc==0 and u64(raw,8)==4 and u64(raw,16)==(-errno.EACCES)&NONE and u64(raw,56)==0
            assert bytes(context.work)==stable
            notify.continue_syscall(listener,pending);pending=None
            deadline=time.monotonic()+20
            while not finished.is_set():
                assert time.monotonic()<deadline
                ready,_,_=select.select([listener],[],[],0.1)
                if ready and not finished.is_set():
                    event=notify.receive(listener);events+=1
                    assert event.data.nr==318
                    notify.continue_syscall(listener,event)
            thread.join(1);assert not thread.is_alive()
            assert result==dict(value=str(root)),result
        finally:
            if pending is not None:notify.continue_syscall(listener,pending)
            thread.join(20);os.close(listener)
        assert context.get()==str(root);context.retire()
    assert fdset()==before
    return dict(passed=True,actual_getrandom_notifications=events,mutex_observed_held=True,
                cwd_snapshot_captured_before_first_probe=True,
                actual_competing_futex_eacces_preserved_context=True,real_kernel_continue_and_retirement=True)



def native_text_size(image):
    raw=(image.path.parent/'component.o').read_bytes()
    sh=struct.unpack_from('<Q',raw,40)[0]
    size=struct.unpack_from('<Q',raw,sh+64+32)[0]
    assert size>len(packer.BRIDGE) and size<16777216
    return size

def actual_close_fallback(image,out):
    before=fdset();root=out/'close-fallback';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        context=Context(image)
        def fallback():
            fault.deny_fixed_syscall(image.address,image.address+native_text_size(image),436,errno.ENOSYS)
            first=context.get();second=context.get()
            assert first==second==str(root)
            context.retire()
            return dict(actual_close_syscall=True,cached_result_preserved=True,retired=True)
        row=fault.thread_result(fallback)
        assert not list(root.iterdir())
    assert fdset()==before
    return dict(passed=True,actual_close_range_enosys=True,all_embedded_roles_filtered=True,**row)

def actual_unknown_close(image,out):
    before=fdset();rows=[]
    for child_failure in (True,False):
        root=out/('unknown-absolute-close' if child_failure else 'unknown-probe-close');root.mkdir()
        with environment(dict(TMPDIR=str(root))):
            reader,writer=os.pipe();pid=os.fork()
            if pid==0:
                try:
                    os.close(reader);context=Context(image)
                    extent=native_text_size(image) if child_failure else len(packer.BRIDGE)
                    fault.deny_fixed_syscall(image.address,image.address+extent,436,errno.ENOSYS)
                    fault.deny_fixed_syscall(image.address,image.address+extent,3,errno.EIO)
                    rc,raw=context.call()
                    assert rc==0 and u64(raw,8)==11 and u64(raw,56)==1 and u64(raw,80)==0
                    assert u64(raw,72)==0 and u64(raw,32)==NONE and u64(context.work,32)==4
                    stable=bytes(context.work);held=fdset()
                    assert held
                    if child_failure:
                        assert u64(context.work,4096+400)!=0
                    else:
                        assert u64(context.work,560)==96
                        assert u64(raw,16)==(-errno.EIO)&NONE
                        owned=u64(context.work,96)
                        assert owned!=NONE and os.fstat(owned).st_size==4
                    for op in (0,1,2):
                        rc,again=context.call(op)
                        assert rc==0 and u64(again,8)==11 and u64(again,56)==1
                        assert u64(again,80)==0 and u64(again,72)==0 and u64(again,32)==NONE
                        assert bytes(context.work)==stable and fdset()==held
                    row=dict(child_absolute=child_failure,actual_close_range_enosys=True,actual_close_eio=True,
                             ownership_unknown=True,all_public_retry_and_retire_refused=True,
                             no_fd_reuse_retry=True,quarantine_preserved_until_process_exit=True)
                    os.write(writer,json.dumps(row).encode());os._exit(0)
                except BaseException as error:
                    os.write(writer,json.dumps(dict(error=repr(error))).encode());os._exit(93)
            os.close(writer);payload=os.read(reader,16384);os.close(reader)
            _,status=os.waitpid(pid,0);row=json.loads(payload)
            assert status==0,row
            rows.append(row)
            # The product kept unknown custody. Process exit, not a false native
            # ACK, releases its FDs; remove only the test's private probe fixture.
            for path in root.iterdir():path.unlink()
            assert not list(root.iterdir())
        assert fdset()==before
    return dict(passed=True,cases=rows)

def actual_delivered_fd_on_unlock_error(image,out):
    before=fdset();root=out/'delivered-fd-unlock-error';root.mkdir()
    with environment(dict(TMPDIR=str(root))):
        context=Context(image)
        def denied():
            fault.deny_fixed_syscall(image.address,image.address+len(packer.BRIDGE),202,errno.EACCES)
            return context.call()
        rc,raw=fault.thread_result(denied)
        assert rc==0 and u64(raw,8)==11 and u64(raw,16)==(-errno.EACCES)&NONE and u64(raw,24)==901
        assert u64(raw,56)==0 and u64(raw,80)==1 and u64(raw,72)==0 and u64(context.work,24)==0
        fd,n=u64(raw,32),u64(raw,40)
        assert fd!=NONE and u64(raw,48)==15
        try:
            assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and os.fstat(fd).st_size==n
            assert os.pread(fd,n+1,0)==str(root).encode('utf-8','surrogatepass')
        finally:os.close(fd)
        assert context.get()==str(root);context.retire()
        assert not list(root.iterdir())
    assert fdset()==before
    return dict(passed=True,actual_futex_wake_eacces=True,already_published_fd_delivered=True,
                actual_seals_and_path_verified=True,caller_drop_then_native_cache_retirement=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    build=json.loads((args.image.parent/'build.json').read_bytes())
    assert pin(args.image.read_bytes())==build['product']
    image=Image(args.image);rows={}
    for name,fn in [('ordered',basic),('relative-unicode',relative_and_unicode),('cache-concurrency',cache_and_concurrency),
                    ('wire-identity',wire_and_identity),('real-failures',real_failures),('pending-cleanup',pending_cleanup),
                    ('actual-codec',actual_codec),('replaced-pending-path',replaced_pending_path),('actual-mutex-failure',actual_mutex_failure),
                    ('actual-close-fallback',actual_close_fallback),('actual-unknown-close',actual_unknown_close),
                    ('delivered-fd-unlock-error',actual_delivered_fd_on_unlock_error)]:
        print('TEMPDIR_CASE_BEGIN',name,flush=True)
        row=fn(image,args.output);rows[name]=row
        (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
        print('TEMPDIR_CASE_PASS',name,flush=True)
    report=dict(schema='hepta.hia.owner-tempdir.qualification.v1',passed=True,cases=rows,
                product=pin(args.image.read_bytes()),build=pin((args.image.parent/'build.json').read_bytes()),
                actual_fixed_native_bridge=True,no_python_role_dispatch=True,
                live_environment_and_real_probes=True,public_constructor_qualified=False,whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(rows))),flush=True)
if __name__=='__main__':main()
