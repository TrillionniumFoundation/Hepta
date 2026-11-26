"""Real native recursive directory cleanup: identity, retry and custody gates."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,os,queue,select,struct,threading
from tools import generate_hia_native_owned_directory_cleanup_packer as spec
from tools import qualify_hia_generation_lease_owner as owner_qa
from tools import qualify_hia_generation_lease_owner_bound as fault
from tools import qualify_hia_generation_lease_owner_tempdir as tq
from tools import qualify_hia_native_seccomp_notify as notify
Q=int.from_bytes(b'HIARMTQ1','little');R=int.from_bytes(b'HIARMTR1','little')
BAD=4294967293;NONE=(1<<64)-1
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def u64(b,at):return struct.unpack_from('<Q',b,at)[0]
def req(op,root=0,parent=0,leaf=b''):
    return struct.pack('<16Q',Q,op,root,parent,len(leaf),*([0]*11))+leaf
def decode(b):
    names=('status','error','phase','known','pending','retired','root_removed','fds','maps','visited','removed','depth','cleanup_error')
    return {name:u64(b,8+8*i)for i,name in enumerate(names)}
class Native:
    def __init__(self,path):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_native_owned_directory_cleanup
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value;self.context=C.create_string_buffer(4096);self.calls=0
    def raw(self,data,context=None):
        source=C.create_string_buffer(data);output=C.create_string_buffer(bytes([165])*128)
        w=self.context if context is None else context
        rc=int(self.entry(source,len(data),output,128,w,4096));self.calls+=1
        assert source.raw==data+b'\0' and output.raw[128:]==b'\0'
        return rc,output.raw[:128]
    def call(self,op,root=0,parent=0,leaf=b''):
        rc,raw=self.raw(req(op,root,parent,leaf))
        assert rc==0 and u64(raw,0)==R and raw[112:]==bytes(16),(rc,raw.hex())
        return decode(raw)
    def deny(self,op,nr,err,root=0,parent=0,leaf=b''):
        def work():
            fault.deny_fixed_syscall(self.address,self.address+len(spec.BRIDGE),nr,err)
            return self.call(op,root,parent,leaf)
        return fault.thread_result(work)
def done(row,removed=True):
    assert row['status']==0 and row['known']==1 and row['pending']==0 and row['retired']==1,row
    assert row['fds']==0 and row['maps']==0 and row['depth']==0,row
    assert row['root_removed']==int(removed),row
def held(row):
    assert row['status']==11 and row['known']==1 and row['pending']==1 and row['retired']==0,row
    assert row['fds']+row['maps']>0,row
class Tree:
    def __init__(self,out,name):
        self.parent=out/name;self.parent.mkdir();self.path=self.parent/'work';self.path.mkdir()
        self.parentfd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        self.rootfd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    def close(self):
        os.fstat(self.rootfd);os.fstat(self.parentfd);os.close(self.rootfd);os.close(self.parentfd)
    def start(self,n):return n.call(0,self.rootfd,self.parentfd,b'work')
def file_at(fd,name,body=b'data'):
    f=os.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC,0o600,dir_fd=fd)
    try:assert os.write(f,body)==len(body)
    finally:os.close(f)
def mixed(path,out):
    before=tq.fdset();t=Tree(out,'mixed');outside=t.parent/'outside';outside.mkdir();(outside/'marker').write_bytes(b'preserve')
    (t.path/'a').mkdir();(t.path/'a'/'b').mkdir();(t.path/'a'/'b'/'file').write_bytes(b'nested')
    (t.path/'empty').mkdir();file_at(t.rootfd,b'raw-\xff-\xed\xa0\x80',b'raw')
    os.mkfifo(t.path/'fifo');os.symlink('../outside',t.path/'external');os.symlink('loop',t.path/'loop')
    n=Native(path);row=t.start(n);done(row)
    assert not t.path.exists() and (outside/'marker').read_bytes()==b'preserve'
    again=n.call(1);done(again);assert again['removed']==row['removed']
    t.close();assert tq.fdset()==before
    return dict(passed=True,actual=row,symlink_target_preserved=True,invalid_fs_bytes=True,repeat_retired_ack=True)
def deep(path,out):
    before=tq.fdset();t=Tree(out,'deep');cur=os.dup(t.rootfd);parts=[]
    try:
        for i in range(160):
            leaf=('level%03d_'%i+'x'*35).encode();parts.append(leaf)
            os.mkdir(leaf,dir_fd=cur);nextfd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=cur)
            os.close(cur);cur=nextfd
        file_at(cur,b'end',b'past PATH_MAX')
    finally:os.close(cur)
    assert sum(map(len,parts))+len(parts)>4096
    n=Native(path);row=t.start(n);done(row);assert not t.path.exists()
    t.close();assert tq.fdset()==before
    return dict(passed=True,directory_levels=160,total_relative_path_bytes=sum(map(len,parts))+len(parts),actual=row)
def borrowed_offset(path,out):
    before=tq.fdset();t=Tree(out,'borrowed-offset')
    for i in range(40):file_at(t.rootfd,('entry%03d'%i).encode())
    libc=C.CDLL(None,use_errno=True);libc.syscall.restype=C.c_long
    buf=C.create_string_buffer(4096);assert libc.syscall(217,t.rootfd,buf,4096)>0
    offset=os.lseek(t.rootfd,0,os.SEEK_CUR);assert offset>0
    n=Native(path);row=t.start(n);done(row);assert os.lseek(t.rootfd,0,os.SEEK_CUR)==offset
    t.close();assert tq.fdset()==before
    return dict(passed=True,actual_caller_directory_offset_unchanged=offset,actual=row)
def identity(path,out):
    before=tq.fdset();rows=[]
    for symlink in (False,True):
        t=Tree(out,'identity-'+str(int(symlink)));(t.path/'keep').write_bytes(b'kept')
        if symlink:os.symlink('work',t.parent/'other')
        else:(t.parent/'other').mkdir()
        n=Native(path);r=n.call(0,t.rootfd,t.parentfd,b'other')
        assert r['status']==4 and r['known']==1 and r['retired']==1 and r['pending']==0 and r['root_removed']==0,r
        assert r['fds']==r['maps']==0 and (t.path/'keep').read_bytes()==b'kept'
        real=Native(path);done(t.start(real));t.close();rows.append(r)
    assert tq.fdset()==before
    return dict(passed=True,wrong_root_and_symlink_leaf_refused=rows)
def guards(path,out):
    before=tq.fdset();t=Tree(out,'guards');n=Native(path)
    bad=[b'',bytes(127),req(3),req(0,t.rootfd,t.parentfd,b''),req(0,t.rootfd,t.parentfd,b'.'),
         req(0,t.rootfd,t.parentfd,b'..'),req(0,t.rootfd,t.parentfd,b'a/b'),req(0,t.rootfd,t.parentfd,b'a\0b'),
         req(1,1),req(2)+b'x']
    for data in bad:
        previous=bytes(n.context);rc,raw=n.raw(data)
        assert rc==BAD and raw==bytes([165])*128 and bytes(n.context)==previous,(data,rc,raw.hex())
    r=n.deny(0,217,errno.EIO,t.rootfd,t.parentfd,b'work');held(r)
    stable=bytes(n.context);copy=C.create_string_buffer(stable)
    rc,raw=n.raw(req(1),copy)
    assert rc==BAD and raw==bytes([165])*128 and copy.raw[:4096]==stable and bytes(n.context)==stable
    source=C.create_string_buffer(req(1));rc=n.entry(source,128,n.context,128,n.context,4096)
    assert rc==BAD and bytes(n.context)==stable
    reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(reader);rc,raw=n.raw(req(1))
            os.write(writer,json.dumps(dict(rc=rc,context_unchanged=bytes(n.context)==stable,output_unchanged=raw==bytes([165])*128)).encode());os._exit(0)
        except BaseException:os._exit(91)
    os.close(writer);child=json.loads(os.read(reader,16384));os.close(reader);_,status=os.waitpid(pid,0)
    assert status==0 and child==dict(rc=BAD,context_unchanged=True,output_unchanged=True)
    done(n.call(1));t.close();assert tq.fdset()==before
    return dict(passed=True,wire_cases=len(bad),copy_no_write=True,overlap_no_write=True,fork_no_write=True)
def initial_failures(path,out):
    before=tq.fdset();rows=[]
    for name,nr,err in [('dup',72,errno.EIO),('map',9,errno.ENOMEM),('stat',5,errno.EIO),
                        ('identity',262,errno.EIO),('fresh-walk-open',257,errno.EIO)]:
        t=Tree(out,'initial-'+name);(t.path/'keep').write_bytes(b'untouched');n=Native(path)
        r=n.deny(0,nr,err,t.rootfd,t.parentfd,b'work')
        assert r['status']==4 and r['error']==(1<<64)-err and r['retired']==1 and r['known']==1,r
        assert r['root_removed']==r['fds']==r['maps']==r['pending']==0 and (t.path/'keep').exists()
        clean=Native(path);done(t.start(clean));t.close();rows.append(dict(name=name,syscall=nr,actual=r))
        assert tq.fdset()==before
    return dict(passed=True,cases=rows,borrowed_originals_remain_open=True)
def pending_failures(path,out):
    before=tq.fdset();rows=[]
    for name,nr,err in [('getdents',217,errno.EIO),('child-open',257,errno.EACCES),('unlink',263,errno.EIO),
                        ('close-range',436,errno.EIO),('munmap',11,errno.EIO),('frame-allocation',9,errno.ENOMEM)]:
        t=Tree(out,'pending-'+name);(t.path/'child').mkdir();(t.path/'child'/'file').write_bytes(b'data');n=Native(path)
        if name in ('child-open','frame-allocation'):
            held(n.deny(0,217,errno.EIO,t.rootfd,t.parentfd,b'work'))
            r=n.deny(1,nr,err)
        else:r=n.deny(0,nr,err,t.rootfd,t.parentfd,b'work')
        held(r);assert r['error']==(1<<64)-err,r
        os.fstat(t.rootfd);os.fstat(t.parentfd)
        final=n.call(1);done(final);assert not t.path.exists()
        t.close();assert tq.fdset()==before
        rows.append(dict(name=name,syscall=nr,actual_failure=r,actual_retry=final))
    return dict(passed=True,cases=rows,actual_other_thread_retry=True)
def abort_only(path,out):
    before=tq.fdset();t=Tree(out,'abort-only');(t.path/'keep').write_bytes(b'remainder');n=Native(path)
    held(n.deny(0,263,errno.EIO,t.rootfd,t.parentfd,b'work'))
    r=n.call(2)
    assert r['retired']==1 and r['pending']==0 and r['known']==1 and r['root_removed']==0 and r['fds']==r['maps']==0,r
    assert (t.path/'keep').read_bytes()==b'remainder'
    done(Native(path).call(0,t.rootfd,t.parentfd,b'work'));t.close();assert tq.fdset()==before
    return dict(passed=True,actual_abort=r,remaining_tree_not_deleted=True)
def close_fallback(path,out):
    before=tq.fdset();t=Tree(out,'close-fallback');(t.path/'child').mkdir();(t.path/'child'/'f').write_bytes(b'data');n=Native(path)
    r=n.deny(0,436,errno.ENOSYS,t.rootfd,t.parentfd,b'work');done(r);t.close();assert tq.fdset()==before
    return dict(passed=True,actual_kernel_enosys_then_real_close=True,actual=r)
def unknown_close(path,out):
    before=tq.fdset();t=Tree(out,'unknown-close');reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(reader);n=Native(path)
            fault.deny_fixed_syscall(n.address,n.address+len(spec.BRIDGE),436,errno.ENOSYS)
            fault.deny_fixed_syscall(n.address,n.address+len(spec.BRIDGE),3,errno.EIO)
            r=t.start(n);assert r['known']==0 and r['pending']==1 and r['retired']==0 and r['root_removed']==1,r
            stable=bytes(n.context)
            for op in (1,2):
                refused=n.call(op);assert refused['known']==0 and refused['pending']==1 and refused['retired']==0
                assert bytes(n.context)==stable
            os.write(writer,json.dumps(dict(passed=True,actual=r,native_retirement_claimed=False,unknown_retry_refused=True)).encode());os._exit(0)
        except BaseException:
            import traceback;traceback.print_exc();os._exit(91)
    os.close(writer);raw=os.read(reader,16384);os.close(reader);_,status=os.waitpid(pid,0)
    assert status==0,(status,raw);result=json.loads(raw);assert not t.path.exists();t.close();assert tq.fdset()==before
    result['kernel_process_exit_released_test_only_custody']=True
    return result
def notified(n,nr,fn,controller):
    listeners=queue.Queue();result=queue.Queue();ended=threading.Event()
    def work():
        try:
            listener=notify.install(n.address,n.address+len(spec.BRIDGE),nr);listeners.put(listener)
            result.put((True,fn()))
        except BaseException as e:result.put((False,e))
        finally:ended.set()
    thread=threading.Thread(target=work);thread.start();listener=listeners.get(timeout=10);count=0
    try:
        while not ended.is_set():
            ready,_,_=select.select([listener],[],[],10)
            if ended.is_set():break
            assert ready,'native notification did not arrive'
            event=notify.receive(listener);count+=1
            assert event.data.nr==nr and n.address<=event.data.ip<n.address+len(spec.BRIDGE)
            controller(count,event);notify.continue_syscall(listener,event)
        thread.join(10);assert not thread.is_alive()
        ok,value=result.get_nowait()
        if not ok:raise value
        return value,count
    finally:os.close(listener)
def replaced_root(path,out):
    before=tq.fdset();t=Tree(out,'replaced-root');n=Native(path)
    def controller(count,event):
        if count==2:
            assert event.data.args[0]==u64(n.context,56)
            os.rename(t.path,t.parent/'moved');t.path.mkdir();(t.path/'foreign').write_bytes(b'preserve')
    r,count=notified(n,262,lambda:t.start(n),controller);held(r)
    assert count==2 and r['error']==(1<<64)-errno.ESTALE and r['root_removed']==0,r
    retired=n.call(2);assert retired['retired']==1 and retired['root_removed']==0 and retired['fds']==retired['maps']==0,retired
    assert (t.path/'foreign').read_bytes()==b'preserve'
    cleanup=Native(path);done(cleanup.call(0,t.rootfd,t.parentfd,b'moved'))
    t.close();assert tq.fdset()==before
    return dict(passed=True,notifications=count,actual_identity_race=r,actual_resource_only_retirement=retired,foreign_inode_preserved=True)
def rescan(path,out):
    before=tq.fdset();t=Tree(out,'rescan');n=Native(path)
    def controller(count,event):
        assert count==1 and event.data.args[2]==512
        file_at(t.rootfd,b'late-file',b'appeared after EOF')
    r,count=notified(n,263,lambda:t.start(n),controller);held(r)
    assert r['error']==(1<<64)-errno.ENOTEMPTY and u64(n.context,40)==190,r
    failed_seek=n.deny(1,8,errno.EIO);held(failed_seek);assert failed_seek['phase']==191
    final=n.call(1);done(final);assert not t.path.exists();t.close();assert tq.fdset()==before
    return dict(passed=True,notifications=count,actual_enotempty=r,actual_rewind_failure=failed_seek,actual_native_rescan=final)
def contention(path,out):
    before=tq.fdset();t=Tree(out,'contention');(t.path/'x').write_bytes(b'data');n=Native(path);checked=[]
    def controller(count,event):
        if not checked:
            assert u64(n.context,24)==1
            stable=bytes(n.context)
            r=n.deny(1,202,errno.EACCES)
            assert r['status']==4 and r['error']==(1<<64)-errno.EACCES and r['retired']==0,r
            assert bytes(n.context)==stable
            checked.append(r)
    final,count=notified(n,217,lambda:t.start(n),controller);done(final);assert checked
    t.close();assert tq.fdset()==before
    return dict(passed=True,notifications=count,actual_held_mutex_wait_failure=checked[0],context_unchanged_by_contender=True,actual_completion=final)
def std_fds(path,out):
    before=tq.fdset();t=Tree(out,'standard-fds');(t.path/'f').write_bytes(b'data');reader,writer=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(reader);os.dup2(t.rootfd,0);os.dup2(t.parentfd,1);os.close(2)
            n=Native(path);r=n.call(0,0,1,b'work');done(r);os.fstat(0);os.fstat(1)
            os.write(writer,json.dumps(dict(passed=True,actual=r,borrowed_fd_zero_and_one_preserved=True)).encode());os._exit(0)
        except BaseException:os._exit(91)
    os.close(writer);raw=os.read(reader,16384);os.close(reader);_,status=os.waitpid(pid,0)
    assert status==0,(status,raw);result=json.loads(raw);t.close();assert tq.fdset()==before
    return result
def packer_domain(path,out):
    flat=(path.parent/'native_owned_directory_cleanup_packer.flat').read_bytes()
    policy=(path.parent/'native_owned_directory_cleanup.flat').read_bytes()
    valid=struct.pack('<3Q',spec.MAGIC,1,len(policy))+policy
    assert owner_qa.old.run_packer(flat,valid)==spec.reference_object([policy])
    image=owner_qa.old.Image(flat);cases=[]
    invalid=[b'',bytes(23),struct.pack('<3Q',0,1,len(policy))+policy,
             struct.pack('<3Q',spec.MAGIC,0,len(policy))+policy,
             struct.pack('<3Q',spec.MAGIC,2,len(policy))+policy,
             struct.pack('<3Q',spec.MAGIC,1,0),
             struct.pack('<3Q',spec.MAGIC,1,4194305)+bytes(4194305),
             struct.pack('<3Q',spec.MAGIC,1,NONE),valid[:-1],valid+b'x']
    for data in invalid:
        source=C.create_string_buffer(data)
        with owner_qa.mmap.mmap(-1,1<<20)as output,owner_qa.mmap.mmap(-1,1<<20)as work:
            rc=int(image.entry(source,len(data),owner_qa.address(output),len(output),owner_qa.address(work),len(work)))
            assert rc==0 or rc>=len(output),(len(data),rc)
            cases.append(dict(input_bytes=len(data),actual_rc=rc))
    return dict(passed=True,valid_native_pack_matches_independent_object=True,invalid=cases)
CASES={'packer-domain':packer_domain,'mixed':mixed,'deep':deep,'borrowed-offset':borrowed_offset,'identity':identity,'guards':guards,
       'initial-failures':initial_failures,'pending-failures':pending_failures,'abort-only':abort_only,
       'close-fallback':close_fallback,'unknown-close':unknown_close,'replaced-root':replaced_root,
       'rescan':rescan,'contention':contention,'standard-fds':std_fds}
def main():
    p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cases',default=','.join(CASES));args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    build=json.loads((args.product.parent/'build.json').read_bytes());assert pin(args.product.read_bytes())==build['product']
    rows={}
    for name in args.cases.split(','):
        print('RMTREE_CASE_BEGIN',name,flush=True);row=CASES[name](args.product,args.output);rows[name]=row
        (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n');print('RMTREE_CASE_PASS',name,flush=True)
    report=dict(schema='hepta.hia.owned-directory-cleanup.qualification.v1',passed=True,complete=set(rows)==set(CASES),
                product=pin(args.product.read_bytes()),build=pin((args.product.parent/'build.json').read_bytes()),cases=rows,
                host_callbacks=False,host_context_prefix_writes=False,native_syscall_results_patched=False,
                whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(rows),complete=report['complete'])),flush=True)
if __name__=='__main__':main()
