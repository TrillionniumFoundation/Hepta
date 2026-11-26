"""Actual inode-bound permission recovery compared with TemporaryDirectory.

This development gate never changes native context, lock words or replies.
Faults are kernel seccomp decisions at the real fixed bridge syscall IP.
"""
from pathlib import Path
import argparse,ctypes as C,errno,json,os,stat,tempfile
from tools import qualify_hia_native_owned_directory_cleanup as q
from tools import qualify_hia_generation_lease_owner_bound as fault

def mode(path):return stat.S_IMODE(os.stat(path).st_mode)
def row_error(row,number):
    q.held(row);assert row['error']==(1<<64)-number,row
def actual_permission_fd(n):
    fd=q.u64(n.context,416);assert fd!=q.NONE and fd<=2147483647
    return fd,os.fstat(fd)
def fd_closed(fd):
    try:os.fstat(fd)
    except OSError as e:assert e.errno==errno.EBADF
    else:raise AssertionError(('native permission FD still open',fd))
def child_zero(t):
    child=t.path/'child';child.mkdir();(child/'payload').write_bytes(b'owned')
    os.chmod(child/'payload',0);os.chmod(child,0)
    return child
def build_fixture(t,kind):
    outside=t.parent/'outside';outside.write_bytes(b'preserve');os.chmod(outside,0o600)
    if kind=='root-zero':
        child_zero(t);os.chmod(t.path,0)
    elif kind=='child-zero':
        child_zero(t)
    elif kind=='hardlink-mode':
        os.link(outside,t.path/'hardlink');os.chmod(outside,0o400);os.chmod(t.path,0o500)
    elif kind=='symlink-mode':
        os.symlink('../outside',t.path/'external');os.chmod(t.path,0o500)
    else:raise AssertionError(kind)
    return outside
def oracle_pair(product,out,kind):
    before=q.tq.fdset();results=[]
    for native in (False,True):
        t=q.Tree(out,kind+('-native' if native else '-python'));outside=build_fixture(t,kind)
        if native:
            n=q.Native(product);row=t.start(n);q.done(row)
        else:
            tempfile.TemporaryDirectory._rmtree(str(t.path));row={'python_removed':True}
        assert not t.path.exists() and outside.read_bytes()==b'preserve'
        result={'native':native,'outside_mode':mode(outside),'actual':row}
        if kind=='hardlink-mode':assert mode(outside)==0o700,result
        else:assert mode(outside)==0o600,result
        t.close();results.append(result)
    assert results[0]['outside_mode']==results[1]['outside_mode']
    assert q.tq.fdset()==before
    return dict(passed=True,kind=kind,actual_python_oracle=True,results=results)
def root_zero(product,out):return oracle_pair(product,out,'root-zero')
def child_mode(product,out):return oracle_pair(product,out,'child-zero')
def hardlink_mode(product,out):return oracle_pair(product,out,'hardlink-mode')
def symlink_mode(product,out):return oracle_pair(product,out,'symlink-mode')
def deep_permissions(product,out):
    before=q.tq.fdset();t=q.Tree(out,'deep-permissions');current=os.dup(t.rootfd);chain=[];total=0
    try:
        for i in range(112):
            leaf=('mode%03d_'%i+'x'*35).encode();os.mkdir(leaf,dir_fd=current)
            nextfd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=current)
            chain.append(current);current=nextfd;total+=len(leaf)+1
        q.file_at(current,b'end',b'actual depth beyond PATH_MAX')
        os.fchmod(current,0)
        for fd in reversed(chain):os.fchmod(fd,0)
    finally:
        os.close(current)
        for fd in chain:os.close(fd)
    assert total>4096
    n=q.Native(product);row=t.start(n);q.done(row);t.close();assert q.tq.fdset()==before
    return dict(passed=True,levels=112,total_relative_bytes=total,actual=row)
def fchmod_failure(product,out):
    before=q.tq.fdset();t=q.Tree(out,'fchmod-failure');(t.path/'keep').write_bytes(b'keep');os.chmod(t.path,0)
    n=q.Native(product);row=n.deny(0,91,errno.EIO,t.rootfd,t.parentfd,b'work');row_error(row,errno.EIO)
    assert row['phase']==701 and q.u64(n.context,40)==700 and stat.S_IMODE(os.fstat(t.rootfd).st_mode)==0,row
    final=n.call(1);q.done(final);t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_kernel_fchmod_eio=row,actual_other_thread_retry=final)
def fchmodat2_failure(product,out):
    before=q.tq.fdset();t=q.Tree(out,'fchmodat2-failure');child=child_zero(t);n=q.Native(product)
    row=n.deny(0,452,errno.EIO,t.rootfd,t.parentfd,b'work');row_error(row,errno.EIO)
    fd,identity=actual_permission_fd(n)
    assert row['phase']==709 and q.u64(n.context,40)==708 and stat.S_IMODE(identity.st_mode)==0,row
    assert (identity.st_dev,identity.st_ino)==(os.stat(child).st_dev,os.stat(child).st_ino)
    final=n.call(1);q.done(final);fd_closed(fd);t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_kernel_fchmodat2_eio=row,retained_fd=fd,identity=[identity.st_dev,identity.st_ino],actual_retry=final)
def deny_both(n,fn,first,second):
    def work():
        for nr,err in (first,second):fault.deny_fixed_syscall(n.address,n.address+len(q.spec.BRIDGE),nr,err)
        return fn()
    return fault.thread_result(work)
def fallback(product,out):
    before=q.tq.fdset();t=q.Tree(out,'fd-path-fallback');child_zero(t);n=q.Native(product)
    row=n.deny(0,452,errno.ENOSYS,t.rootfd,t.parentfd,b'work');q.done(row)
    t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_enosys_then_fd_bound_proc_chmod=True,actual=row)
def fallback_failure(product,out):
    before=q.tq.fdset();t=q.Tree(out,'fd-path-failure');child=child_zero(t);n=q.Native(product)
    row=deny_both(n,lambda:t.start(n),(452,errno.ENOSYS),(90,errno.EIO));row_error(row,errno.EIO)
    fd,identity=actual_permission_fd(n)
    assert row['phase']==713 and q.u64(n.context,40)==712 and stat.S_IMODE(identity.st_mode)==0,row
    assert C.string_at(C.addressof(n.context)+1600)==b'/proc/self/fd/'+str(fd).encode()
    final=n.call(1);q.done(final);fd_closed(fd);t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_enosys_and_chmod_eio=row,retained_fd=fd,actual_retry=final)
def close_permission_fd(product,out):
    before=q.tq.fdset();t=q.Tree(out,'permission-close-failure');child_zero(t);n=q.Native(product)
    row=n.deny(0,436,errno.EIO,t.rootfd,t.parentfd,b'work');row_error(row,errno.EIO)
    fd,identity=actual_permission_fd(n)
    assert row['phase']==950 and q.u64(n.context,368)==5 and q.u64(n.context,360)==714,row
    assert stat.S_IMODE(identity.st_mode)==0o700
    final=n.call(1);q.done(final);fd_closed(fd);t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_close_range_eio=row,owned_permission_fd=fd,actual_retry=final)
def abort_permission_fd(product,out):
    before=q.tq.fdset();t=q.Tree(out,'permission-abort');child=child_zero(t);n=q.Native(product)
    row=n.deny(0,452,errno.EIO,t.rootfd,t.parentfd,b'work');row_error(row,errno.EIO);fd,_=actual_permission_fd(n)
    final=n.call(2)
    assert final['known']==1 and final['pending']==0 and final['retired']==1 and final['root_removed']==0,final
    assert final['fds']==final['maps']==final['depth']==0 and mode(child)==0,final
    fd_closed(fd)
    tempfile.TemporaryDirectory._rmtree(str(t.path));t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_failure=row,actual_resource_only_retirement=final,remaining_tree_removed_only_by_test_fixture=True)
def raced_chmod(product,out,use_fallback):
    before=q.tq.fdset();t=q.Tree(out,'race-'+('fallback' if use_fallback else 'fchmodat2'));child=child_zero(t)
    outside=t.parent/'outside';outside.write_bytes(b'outside');os.chmod(outside,0o600);n=q.Native(product);identities=[]
    def work():
        if use_fallback:fault.deny_fixed_syscall(n.address,n.address+len(q.spec.BRIDGE),452,errno.ENOSYS)
        return t.start(n)
    def controller(count,event):
        assert count==1
        fd,held=actual_permission_fd(n)
        if use_fallback:assert C.string_at(event.data.args[0])==b'/proc/self/fd/'+str(fd).encode()
        else:assert event.data.args[0]==fd
        os.rename(child,t.path/'moved')
        os.symlink('../outside',child)
        identities.append([held.st_dev,held.st_ino])
    row,count=q.notified(n,90 if use_fallback else 452,work,controller)
    row_error(row,errno.ENOTEMPTY);assert count==1
    assert mode(outside)==0o600 and outside.read_bytes()==b'outside'
    assert mode(t.path/'moved')==0o700 and identities==[[os.stat(t.path/'moved').st_dev,os.stat(t.path/'moved').st_ino]]
    assert not child.exists() and not child.is_symlink()
    final=n.call(1);q.done(final);t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_notifications=count,held_inode_chmod=True,outside_target_unchanged=True,actual_late_rename_rescan=row,actual_retry=final)
def race_fchmodat2(product,out):return raced_chmod(product,out,False)
def race_fallback(product,out):return raced_chmod(product,out,True)
def raced_capture(product,out):
    before=q.tq.fdset();t=q.Tree(out,'capture-race');child=child_zero(t)
    outside=t.parent/'outside';outside.write_bytes(b'outside');os.chmod(outside,0o600);n=q.Native(product);captured=[]
    def controller(count,event):
        if event.data.args[2]==2752512:
            assert not captured
            os.rename(child,t.path/'moved');os.link(outside,child);captured.append(True)
    row,count=q.notified(n,257,lambda:t.start(n),controller);row_error(row,errno.ESTALE)
    assert captured==[True] and q.u64(n.context,416)==q.NONE and row['phase']==714,row
    assert mode(outside)==0o600 and mode(t.path/'moved')==0
    final=n.call(2);assert final['retired']==1 and final['pending']==0 and final['known']==1 and final['root_removed']==0,final
    assert final['fds']==final['maps']==0
    tempfile.TemporaryDirectory._rmtree(str(t.path));assert mode(outside)==0o600
    t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_notifications=count,captured_inode_mismatch_rejected=row,no_foreign_chmod=True,actual_retirement=final)
def wrong_identity_mode(product,out):
    before=q.tq.fdset();t=q.Tree(out,'wrong-identity-mode');(t.path/'keep').write_bytes(b'preserved');os.chmod(t.path,0)
    (t.parent/'other').mkdir();n=q.Native(product);row=n.call(0,t.rootfd,t.parentfd,b'other')
    assert row['status']==4 and row['error']==(1<<64)-errno.ESTALE and row['retired']==1 and row['known']==1,row
    assert row['root_removed']==row['fds']==row['maps']==0 and stat.S_IMODE(os.fstat(t.rootfd).st_mode)==0
    actual=q.Native(product);q.done(t.start(actual));t.close();assert q.tq.fdset()==before
    return dict(passed=True,actual_wrong_identity=row,unverified_root_not_chmodded=True)
def external_parent(product,out):
    before=q.tq.fdset();rows=[]
    for native in (False,True):
        t=q.Tree(out,'external-parent-'+str(int(native)));(t.path/'file').write_bytes(b'data');os.chmod(t.parent,0o500)
        if native:
            n=q.Native(product);row=t.start(n);row_error(row,errno.EACCES)
            assert row['root_removed']==0 and row['retired']==0,row
        else:
            try:tempfile.TemporaryDirectory._rmtree(str(t.path))
            except PermissionError as e:row={'python_errno':e.errno}
            else:raise AssertionError('Python unexpectedly removed root from unwritable external parent')
        assert stat.S_IMODE(os.fstat(t.parentfd).st_mode)==0o500
        os.fchmod(t.parentfd,0o700)
        if native:final=n.call(1);q.done(final);row={'failure':row,'retry':final}
        else:tempfile.TemporaryDirectory._rmtree(str(t.path))
        t.close();rows.append(row)
    assert q.tq.fdset()==before
    return dict(passed=True,actual_python_oracle=True,external_parent_mode_never_changed=True,results=rows)

CASES={'root-zero':root_zero,'child-zero':child_mode,'hardlink-mode':hardlink_mode,'symlink-mode':symlink_mode,
       'deep-permissions':deep_permissions,'fchmod-failure':fchmod_failure,'fchmodat2-failure':fchmodat2_failure,
       'fd-path-fallback':fallback,'fd-path-failure':fallback_failure,'permission-close-failure':close_permission_fd,
       'permission-abort':abort_permission_fd,'fchmodat2-race':race_fchmodat2,'fd-path-race':race_fallback,
       'capture-identity-race':raced_capture,'wrong-identity-mode':wrong_identity_mode,'external-parent':external_parent}
def main():
    p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cases',default=','.join(CASES));args=p.parse_args()
    assert os.geteuid()!=0,'Permission denial gates require the actual unprivileged service account'
    args.output.mkdir(parents=True,exist_ok=False)
    build=json.loads((args.product.parent/'build.json').read_bytes());assert q.pin(args.product.read_bytes())==build['product']
    rows={}
    for name in args.cases.split(','):
        print('RMTREE_PERMISSION_BEGIN',name,flush=True);row=CASES[name](args.product,args.output);rows[name]=row
        (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n');print('RMTREE_PERMISSION_PASS',name,flush=True)
    report=dict(schema='hepta.hia.owned-directory-permissions.qualification.v1',passed=True,complete=set(rows)==set(CASES),
                product=q.pin(args.product.read_bytes()),build=q.pin((args.product.parent/'build.json').read_bytes()),cases=rows,
                actual_uid=os.geteuid(),host_callbacks=False,host_context_prefix_writes=False,native_syscall_results_patched=False,
                whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(rows),complete=report['complete'])),flush=True)
if __name__=='__main__':main()
