"""Qualify the exact Store path adapter under real ENOSYS seccomp filtering.

The bounded fallback is for the original HIA owners' admitted path shapes:
a no-link parent directory, or one child component under a held parent FD.
Other openat2 errors must return without attempting an openat fallback.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,errno,fcntl,json,mmap,os,stat,struct,subprocess,sys
from tempfile import TemporaryDirectory

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
ADAPTERS=('hia_agent_store_init_syscalls.S','hia_agent_store_syscalls.S')

def seccomp(error,forbid_openat):
    class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    instructions=[(0x20,0,0,0),(0x15,0,1,437),(0x06,0,0,0x50000|error)]
    if forbid_openat:instructions += [(0x15,0,1,257),(0x06,0,0,0x80000000)]
    instructions += [(0x06,0,0,0x7fff0000)]
    filters=(Filter*len(instructions))(*(Filter(*row) for row in instructions))
    program=Program(len(instructions),filters)
    libc=ctypes.CDLL(None,use_errno=True);libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    assert libc.prctl(38,1,0,0,0)==0,ctypes.get_errno()
    assert libc.prctl(22,2,ctypes.addressof(program),0,0)==0,ctypes.get_errno()

def fd_set():
    result=[]
    for fd in range(256):
        try:fcntl.fcntl(fd,fcntl.F_GETFD)
        except OSError as e:
            if e.errno!=errno.EBADF:raise
        else:result.append(fd)
    return result

def child(path,error,fixture):
    raw=path.read_bytes()
    code=mmap.mmap(-1,len(raw)+3,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    code.write(bytes.fromhex('4989ca')+raw) # System V fourth argument -> syscall R10.
    function=ctypes.CFUNCTYPE(ctypes.c_long,ctypes.c_long,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_ulong)(ctypes.addressof(ctypes.c_char.from_buffer(code)))
    base=fixture;target=base/'a/b/root';anchor=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    held=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    rows=[]
    def invoke(name,directory,value,flags=0xb0000,mode=0,resolve=6):
        before=fd_set()
        how=ctypes.create_string_buffer(struct.pack('<3Q',flags,mode,resolve))
        got=function(directory,os.fsencode(value),ctypes.addressof(how),24)
        row={'case':name,'result':got if got<0 else 0}
        if got>=0:
            st=os.fstat(got);row.update(device=st.st_dev,inode=st.st_ino,mode=stat.S_IMODE(st.st_mode),kind=stat.S_IFMT(st.st_mode),uid=st.st_uid,cloexec=fcntl.fcntl(got,fcntl.F_GETFD),flags=fcntl.fcntl(got,fcntl.F_GETFL))
            assert row['cloexec']==1
            os.close(got)
        assert fd_set()==before,(name,'descriptor leak')
        rows.append(row)
    if error not in [0,38]:
        seccomp(error,True)
        invoke('original-error-no-fallback',-100,target)
        assert rows[-1]['result']==-error
        print(json.dumps({'error':error,'cases':rows}),flush=True)
        return
    if error:seccomp(error,False)
    invoke('absolute-parent',-100,target)
    invoke('relative-parent',anchor,'a/b/root')
    invoke('relative-current-directory',-100,'a/b/root')
    invoke('dot-parent',anchor,'a/./b/root')
    invoke('repeated-separator',anchor,'a//b///root/')
    invoke('root-directory',-100,'/')
    invoke('intermediate-symlink',anchor,'a/link/root')
    invoke('final-directory-symlink',anchor,'a/b/root-link')
    invoke('regular-parent-refused',anchor,'a/b/file')
    invoke('missing-parent',anchor,'a/b/missing')
    invoke('invalid-directory-fd',-1,'a/b/root')
    invoke('long-component',anchor,'a/'+'x'*256)
    invoke('long-path',anchor,'x'*4096)
    invoke('held-regular-child',held,'value',0xa0000,0,14)
    invoke('held-directory-child',held,'directory',0xb0000,0,14)
    invoke('held-implied-directory',held,'directory',0x90000,0,14)
    invoke('held-implied-directory-link',held,'directory-link',0x90000,0,14)
    invoke('held-exclusive-create-new',held,'exclusive-'+str(error),0x800c2,0o600,14)
    invoke('held-exclusive-create-existing-link',held,'value-link',0x800c2,0o600,14)
    invoke('held-leaf-symlink',held,'value-link',0xa0000,0,14)
    invoke('held-directory-symlink',held,'directory-link',0xb0000,0,14)
    invoke('held-absolute-refused',held,str(target/'value'),0xa0000,0,14)
    invoke('held-dotdot-refused',held,'../file',0xa0000,0,14)
    invoke('held-create-new',held,'new-'+str(error),0xa00c2,0o600,14)
    invoke('held-create-existing-link',held,'value-link',0xa00c2,0o600,14)
    invoke('invalid-flag-bits',held,'value',0xa0010,0,14)
    invoke('invalid-create-mode',held,'mode-invalid',0xa00c2,0o10000,14)
    if error:
        invoke('parent-dotdot-fails-closed',anchor,'a/b/../b/root')
        invoke('multi-child-fails-closed',held,'directory/value',0xa0000,0,14)
        invoke('dot-child-fails-closed',held,'.',0xb0000,0,14)
        invoke('unsupported-resolve-fails-closed',held,'value',0xa0000,0,2)
        invoke('missing-nofollow-fails-closed',held,'value',0x80000,0,14)
        for row in rows[-5:]:assert row['result']<0,row
    os.close(anchor);os.close(held)
    print(json.dumps({'error':error,'cases':rows}),flush=True)

def rename_race(path, directory, case):
    """Stop the actual adapter at openat entry/exit, then exchange a pathname.

    The qualifier does not edit the adapter. PTRACE_GET_SYSCALL_INFO distinguishes
    entry and exit stops; the filesystem change occurs while the child is stopped.
    The ENOSYS result comes from the same real seccomp filter as the other gates.
    """
    import signal,time
    class Registers(ctypes.Structure):
        _fields_=[(x,ctypes.c_ulonglong) for x in
          ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx',
           'rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base',
           'ds','es','fs','gs')]
    libc=ctypes.CDLL(None,use_errno=True)
    libc.ptrace.argtypes=[ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p]
    libc.ptrace.restype=ctypes.c_long
    def ptrace(command,pid,addr=0,data=0):
        ctypes.set_errno(0)
        got=libc.ptrace(command,pid,addr,data)
        error=ctypes.get_errno()
        if got==-1 and error:raise OSError(error,os.strerror(error))
        return got
    fixture=directory/case;target=fixture/'a/b/root';target.mkdir(mode=0o700,parents=True)
    outside=fixture/'outside/b/root';outside.mkdir(mode=0o700,parents=True)
    for base,value in [(target,b'held-original'),(outside,b'outside-denied')]:
        (base/'value').write_bytes(value)
    held=case.startswith('held-')
    anchor=os.open(target if held else fixture,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    wanted=(target/'value' if held else target).stat()
    forbidden=(outside/'value' if held else outside).stat()
    original=(wanted.st_dev,wanted.st_ino);other=(forbidden.st_dev,forbidden.st_ino)
    assert original!=other
    raw=path.read_bytes()
    memory=mmap.mmap(-1,len(raw)+3,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    memory.write(bytes.fromhex('4989ca')+raw)
    function=ctypes.CFUNCTYPE(ctypes.c_long,ctypes.c_long,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_ulong)(ctypes.addressof(ctypes.c_char.from_buffer(memory)))
    how=ctypes.create_string_buffer(struct.pack('<3Q',0xa0000 if held else 0xb0000,0,14 if held else 6))
    argument=b'value' if held else b'a/b/root'
    reader,writer=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(reader)
        try:
            seccomp(38,False)
            ptrace(0,0)
            os.kill(os.getpid(),signal.SIGSTOP)
            got=function(anchor,argument,ctypes.addressof(how),24)
            row={'result':got if got<0 else 0}
            if got>=0:
                st=os.fstat(got);row.update(device=st.st_dev,inode=st.st_ino,mode=stat.S_IMODE(st.st_mode))
                if held:row['bytes_hex']=os.read(got,64).hex()
                os.close(got)
            os.write(writer,json.dumps(row).encode());os._exit(0)
        except BaseException as exc:
            os.write(writer,json.dumps({'error':repr(exc)}).encode());os._exit(1)
    os.close(writer)
    changed=False;pending=False;mutation=None
    phase='exit' if case.endswith('-after') else 'entry'
    watch=b'value' if held else (b'root' if case.startswith('final-') else b'a')
    expected_error=-40 if case in ('intermediate-before','held-leaf-before') else (-20 if case=='final-before' else None)
    def string_at(address):
        out=bytearray()
        for offset in range(0,256,8):
            word=ptrace(2,pid,address+offset)
            chunk=ctypes.c_ulonglong(word).value.to_bytes(8,'little')
            if b'\0' in chunk:return bytes(out)+chunk.split(b'\0',1)[0]
            out+=chunk
        raise AssertionError('bounded component did not terminate')
    def exchange():
        nonlocal changed,mutation
        if case.startswith('intermediate-'):
            old=fixture/'a';saved=fixture/'saved-a';replacement=fixture/'outside'
        elif case.startswith('final-') or case.startswith('held-parent-'):
            old=target;saved=target.with_name('saved-root');replacement=outside
        else:
            old=target/'value';saved=target/'saved-value';replacement=outside/'value'
        before=old.lstat();old.rename(saved);old.symlink_to(replacement)
        assert saved.stat().st_ino==before.st_ino and old.is_symlink()
        mutation={'phase':phase,'component':watch.decode(),'original_path':str(old),
                  'held_inode':before.st_ino,'replacement_symlink':str(replacement)}
        changed=True
    try:
        _,status=os.waitpid(pid,0);assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP
        ptrace(0x4200,pid,0,1|0x100000) # TRACESYSGOOD and EXITKILL.
        deadline=time.monotonic()+15
        while True:
            ptrace(24,pid,0,0) # PTRACE_SYSCALL.
            while True:
                ended,status=os.waitpid(pid,os.WNOHANG)
                if ended:break
                assert time.monotonic()<deadline,'ptrace race qualifier timed out'
                time.sleep(.001)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):break
            assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==(signal.SIGTRAP|0x80),status
            regs=Registers();ptrace(12,pid,0,ctypes.addressof(regs))
            info=ctypes.create_string_buffer(128);ptrace(0x420e,pid,128,ctypes.addressof(info))
            operation=info.raw[0]
            if operation==1:
                pending=False
                if regs.orig_rax==257 and not changed and string_at(regs.rsi)==watch:
                    pending=True
                    if phase=='entry':exchange()
            elif operation==2 and pending:
                if phase=='exit':
                    assert ctypes.c_longlong(regs.rax).value>=0,regs.rax
                    exchange()
                pending=False
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,status
        observation=json.loads(os.read(reader,4096));assert 'error' not in observation,observation
        assert changed,'the requested production syscall boundary was not observed'
        if expected_error is not None:assert observation['result']==expected_error,observation
        else:
            assert observation['result']==0 and (observation['device'],observation['inode'])==original,observation
            assert (observation['device'],observation['inode'])!=other
            if held:assert bytes.fromhex(observation['bytes_hex'])==b'held-original'
        return {'case':case,'mutation':mutation,'observation':observation,
                'original_identity':original,'outside_identity':other,'status':'passed'}
    except BaseException:
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:os.waitpid(pid,0)
        except ChildProcessError:pass
        raise
    finally:
        os.close(reader);os.close(anchor);memory.close()


def main():
    if len(sys.argv)==5 and sys.argv[1]=='--child':
        child(Path(sys.argv[2]),int(sys.argv[3]),Path(sys.argv[4]));return
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();D=a.output.absolute();D.mkdir(mode=0o700)
    from tools.build_hia_agent_batch_commit import assemble_adapter
    report={'schema':'hia.store-path-transport-qualification.v1','status':'running','scope':'exact emitted native adapter instructions with actual kernel seccomp; independent real systemd/Worker gate remains required','adapters':{},'runs':[]}
    def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    codes=[]
    for name in ADAPTERS:
        work=D/name;work.mkdir();source=(ROOT/'tools'/name).read_bytes()
        raw,symbols,_=assemble_adapter(work,name,source)
        helper=raw[symbols['hia_open_nofollow']:symbols['hia_open_nofollow_end']]
        code=work/'helper.bin';code.write_bytes(helper);codes.append(code)
        report['adapters'][name]={'source_sha256':sha256(source).hexdigest(),'adapter_sha256':sha256(raw).hexdigest(),'helper_sha256':sha256(helper).hexdigest(),'helper_bytes':len(helper)}
    assert codes[0].read_bytes()==codes[1].read_bytes()
    fixture=D/'filesystem';target=fixture/'a/b/root';target.mkdir(mode=0o700,parents=True)
    (fixture/'a/b/file').write_bytes(b'regular')
    (fixture/'a/link').symlink_to('b')
    (fixture/'a/b/root-link').symlink_to('root')
    (target/'value').write_bytes(b'controlled child')
    (target/'value-link').symlink_to('value')
    (target/'directory').mkdir(mode=0o700)
    (target/'directory/value').write_bytes(b'nested')
    (target/'directory-link').symlink_to('directory')
    save()
    try:
        for error in [0,38,1,13,22,40]:
            command=[sys.executable,'-B',str(Path(__file__).resolve()),'--child',str(codes[0]),str(error),str(fixture)]
            result=subprocess.run(command,cwd=fixture,capture_output=True,timeout=20)
            (D/('errno-'+str(error)+'.stdout')).write_bytes(result.stdout)
            (D/('errno-'+str(error)+'.stderr')).write_bytes(result.stderr)
            assert result.returncode==0 and not result.stderr,(error,result.returncode,result.stderr)
            row=json.loads(result.stdout);report['runs'].append(row);save()
        kernel,fallback=report['runs'][:2]
        expected={x['case']:x for x in kernel['cases']}
        for row in fallback['cases']:
            if row['case'] not in expected:continue
            other=expected[row['case']]
            keys=['result'] if row['result']<0 else ['result','mode','kind','uid','cloexec','flags']
            if row['case'] not in ('held-create-new','held-exclusive-create-new') and row['result']==0:keys+=['device','inode']
            assert all(row[k]==other[k] for k in keys),(row,other)
        report['rename_races']=[]
        for case in ('intermediate-before','intermediate-after','final-before','final-after','held-parent-before','held-leaf-before'):
            report['rename_races'].append(rename_race(codes[0],D/'rename-races',case));save()
        report.update(status='passed',case_count=sum(len(r['cases']) for r in report['runs'])+len(report['rename_races']),
            no_fallback_for_non_ENOSYS=[r['error'] for r in report['runs'][2:]],
            root_and_component_refusals_preserved=True)
        save();print(json.dumps({'status':'passed','cases':report['case_count'],'output':str(D)}),flush=True)
    except BaseException:
        import traceback
        report['status']='failed';report['failure']=traceback.format_exc();save();raise
if __name__=='__main__':main()
