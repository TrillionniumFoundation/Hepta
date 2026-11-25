"""Actual sealed-process transport qualification; external child is QA only."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,fcntl,struct,subprocess,time,threading,signal,errno,concurrent.futures
MAX=64<<20;NONE=(1<<64)-1
QA_CHILD_SOURCE='#define _GNU_SOURCE\n#include <unistd.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <signal.h>\n#include <errno.h>\n#include <time.h>\n#include <fcntl.h>\n#include <stdio.h>\n#include <string.h>\n#include <sys/wait.h>\nstatic int all(int fd,const void *v,size_t n){const unsigned char *p=v;while(n){ssize_t z=write(fd,p,n);if(z<0&&errno==EINTR)continue;if(z<=0)return 1;p+=z;n-=(size_t)z;}return 0;}\nstatic void pattern(int fd,uint64_t n,int tiny){unsigned char b[65536];uint64_t pos=0;while(pos<n){size_t k=(n-pos>sizeof b)?sizeof b:(size_t)(n-pos);if(tiny&&k>7)k=7;for(size_t i=0;i<k;i++)b[i]=(unsigned char)((pos+i)%251);if(all(fd,b,k))_exit(91);pos+=k;}}\nint main(int argc,char **argv){uint64_t h[4]={0};size_t at=0;while(at<32){ssize_t n=read(0,(char*)h+at,32-at);if(n<0&&errno==EINTR)continue;if(n<=0)return 92;at+=(size_t)n;}\n if(h[0]==0){char b[65536];for(;;){ssize_t n=read(0,b,sizeof b);if(n<0&&errno==EINTR)continue;if(n<0)return 93;if(!n)return 0;if(all(1,b,n))return 94;}}\n if(h[0]==1||h[0]==8){pattern(1,h[1],h[0]==8);pattern(2,h[2],h[0]==8);return (int)h[3];}\n if(h[0]==2){struct timespec t={(time_t)(h[1]/1000),(long)((h[1]%1000)*1000000)};while(nanosleep(&t,&t)<0&&errno==EINTR){}return (int)h[2];}\n if(h[0]==3){raise((int)h[1]);return 95;}\n if(h[0]==4){for(int i=0;i<argc;i++){all(1,argv[i],strlen(argv[i]));all(1,"\\0",1);}extern char **environ;for(char **e=environ;*e;e++){all(2,*e,strlen(*e));all(2,"\\0",1);}return 0;}\n if(h[0]==5){close(1);close(2);for(;;)pause();}\n if(h[0]==6||h[0]==7){pid_t child=fork();if(child<0)return 96;if(!child){for(;;)pause();}uint64_t ids[2]={(uint64_t)getpid(),(uint64_t)child};all(1,ids,sizeof ids);if(argc==2){int fd=open(argv[1],O_CREAT|O_EXCL|O_WRONLY,0600);if(fd<0)return 97;all(fd,ids,sizeof ids);close(fd);}if(h[0]==7)return 0;for(;;)pause();}\n return 98;\n}\n\n'
def prepare_fixture(directory):
    directory.mkdir(parents=True,exist_ok=True)
    source=directory/'child-fixture.c'
    if source.exists():assert source.read_text()==QA_CHILD_SOURCE
    else:source.write_text(QA_CHILD_SOURCE)
    if not (directory/'child-fixture').exists():
        subprocess.run(['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra',str(source),'-o',str(directory/'child-fixture')],check=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def sealed(raw,mode=0o500,seal=15):
    fd=os.memfd_create('mv-prepare-qa',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
    os.write(fd,raw);os.fchmod(fd,mode)
    if seal:fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seal)
    return fd
class Process:
    def __init__(self,path):
        self.lib=C.CDLL(str(path));self.f=self.lib.hia_mv_prepare_process;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
    def run(self,fd,data,*,role=1,path=b'',outcap=MAX,errcap=MAX,budget=5,cancel=None,deadline=None):
        end=time.monotonic_ns()+int(budget*1e9) if deadline is None else deadline
        packet=struct.pack('<8s15Q',b'HIAMVPS1',role,fd,end,len(data),outcap,errcap,len(path),0 if cancel is None else C.addressof(cancel),*([0]*7))+data+path
        s=C.create_string_buffer(packet);o=C.create_string_buffer(b'O'*128);w=C.create_string_buffer(20<<20)
        started=time.monotonic_ns();rc=self.f(s,len(packet),o,128,w,len(w));wall=time.monotonic_ns()-started
        assert s.raw==packet+b'\0'
        h=struct.unpack_from('<8s15Q',o.raw);assert h[0]==b'HIAMVPO1' and rc==h[1] and h[15]==0,(rc,h)
        assert h[11]>=h[10]
        if h[10]:assert h[11]-h[10]<=wall+100_000_000
        if rc==0:assert h[10]>0
        streams=[]
        if rc==0:
            assert h[12:15]==(1,7,15),h
            for fd,n in zip(h[6:8],h[8:10]):
                assert fd>=3 and fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and os.fstat(fd).st_size==n
                assert os.fstat(fd).st_nlink==0 and os.fstat(fd).st_mode&0o777==0o600
                try:os.pwrite(fd,b'x',0)
                except OSError as e:assert e.errno==errno.EPERM
                else:raise AssertionError('unsealed captured stream')
                streams.append(os.pread(fd,n,0));assert len(streams[-1])==n;os.close(fd)
        else:
            assert h[6:8]==(NONE,NONE),h
        if h[2]:
            try:r=os.waitpid(h[2],os.WNOHANG)
            except ChildProcessError:r=None
            assert r is None,('owned child not reaped',r,h)
        return {'status':rc,'reply':[h[0].decode(),*h[1:]],'wall_ns':wall,'stdout':streams[0] if streams else b'','stderr':streams[1] if streams else b''}
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--prepare-fixture',action='store_true');p.add_argument('--normalizer',type=Path);p.add_argument('--proof',type=Path);p.add_argument('--builder',type=Path);a=p.parse_args();D=a.directory
    if a.prepare_fixture:prepare_fixture(D);return
    proc=Process(D/'process-component.so');image=(D/'child-fixture').read_bytes();fd=sealed(image);rows=[]
    def record(label,result):
        row={k:v for k,v in result.items() if k not in ('stdout','stderr')};row.update(case=label,stdout_bytes=len(result['stdout']),stderr_bytes=len(result['stderr']),stdout_sha256=sha(result['stdout']),stderr_sha256=sha(result['stderr']));rows.append(row);print('PROCESS_CASE_PASS',label,result['status'],flush=True)
    def paired(label,data,**options):
        baseline=set(os.listdir('/proc/self/fd'))
        role=options.get('role',1);path=options.get('path',b'')
        argv=[['','hia-admit-agent-json','hia-native-scalar-proof','hia-build-shared','hia-verify-core-json'][role]]
        if role==3:argv.append(os.fsdecode(path))
        old=subprocess.run(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),input=data,capture_output=True,env={'PATH':''},timeout=15)
        r=proc.run(fd,data,**options);assert r['status']==0,(label,r)
        status=r['reply'][3];newcode=os.waitstatus_to_exitcode(status)
        assert (newcode,r['stdout'],r['stderr'])==(old.returncode,old.stdout,old.stderr),(label,newcode,old.returncode,len(r['stdout']),len(old.stdout))
        assert set(os.listdir('/proc/self/fd'))==baseline,(label,'FD leak')
        record(label,r)
    for role in (1,2,3,4):
        paired('fixed-argv-'+str(role),struct.pack('<4Q',4,0,0,0),role=role,path=os.fsencode(str(D/'not-created-target')) if role==3 else b'')
    for n in (0,1,7,31,4095,4096,4097,65535,65536,65537,1<<20):
        paired('stdin-capture-'+str(n),struct.pack('<4Q',0,0,0,0)+bytes(range(256))*(n//256)+bytes(range(n%256)))
    for n in (0,1,7,4095,65535,65536,65537,1<<20,MAX):
        paired('both-streams-'+str(n),struct.pack('<4Q',1,n,n,0))
    paired('tiny-real-pipe-writes',struct.pack('<4Q',8,2048,1031,0))
    paired('nonzero-exit',struct.pack('<4Q',1,91,63,37))
    for sig in (signal.SIGTERM,signal.SIGABRT,signal.SIGKILL):
        paired('signal-'+str(int(sig)),struct.pack('<4Q',3,sig,0,0))
    for which in ('stdout','stderr'):
        data=struct.pack('<4Q',1,65 if which=='stdout' else 0,65 if which=='stderr' else 0,0)
        r=proc.run(fd,data,outcap=64,errcap=64);assert r['status']==4 and r['reply'][12]==1,r;record(which+'-cap-plus-one',r)
    for label,data in [('sleep',struct.pack('<4Q',2,10000,0,0)),('closed-streams-live-child',struct.pack('<4Q',5,0,0,0))]:
        r=proc.run(fd,data,budget=.1);assert r['status']==1 and r['reply'][12]==1 and r['wall_ns']<1_000_000_000,r;record('deadline-'+label,r)
    r=proc.run(fd,struct.pack('<4Q',0,0,0,0),deadline=time.monotonic_ns()-1);assert r['status']==1 and r['reply'][2]==0,r;record('expired-before-launch',r)
    cancel=C.c_uint64(1);r=proc.run(fd,struct.pack('<4Q',2,1000,0,0),cancel=cancel);assert r['status']==2 and r['reply'][2]==0;record('cancel-before-launch',r)
    cancel=C.c_uint64(0)
    def later():time.sleep(.06);cancel.value=1
    t=threading.Thread(target=later);t.start();r=proc.run(fd,struct.pack('<4Q',2,1000,0,0),cancel=cancel);t.join()
    assert r['status']==2 and r['reply'][12]==1 and r['wall_ns']<1_000_000_000,r;record('cancel-during-running',r)
    for mode in (6,7):
        path=D/('group-'+str(mode)+'.pids')
        r=proc.run(fd,struct.pack('<4Q',mode,0,0,0),role=3,path=os.fsencode(path),budget=.12)
        assert r['status']==1 and r['reply'][12]==1,r
        parent,descendant=struct.unpack('<2Q',path.read_bytes());assert parent==r['reply'][2]
        try:state=Path('/proc/'+str(descendant)+'/stat').read_text().split(') ')[1].split()[0]
        except (FileNotFoundError,ProcessLookupError):state=None
        assert state in (None,'Z'),(parent,descendant,state)
        record('deadline-group-'+str(mode),r)
    for label,body,mode,seal in [('unsealed',image,0o500,0),('nonexec',image,0o600,15),('bad-ELF',b'not an executable',0o500,15),('empty',b'',0o500,15)]:
        bad=sealed(body,mode,seal);r=proc.run(bad,struct.pack('<4Q',0,0,0,0));os.close(bad)
        assert r['status']==(5 if label in ('nonexec','bad-ELF') else 3),(label,r)
        record(label,r)
    # Real full product roles, compared to the same ordinary native executables.
    A=D.parent.parent/'native-release-closeout-20261124T0740Z'
    depot=A/'native-final-v21-round13/bootstrap-depot/f4dde135441d9a4f18608a417c85c39c35b9004208df1eebdabe6379c040c2ee'
    import sys;sys.path.insert(0,str(a.source))
    from tests.test_hia_scalar_profile_native import basic
    from tests.test_hia_program_composite import scalar_task_program
    raw=json.dumps(basic(),separators=(',',':')).encode()
    normal=sealed((a.normalizer or depot/'hia-nominal-constructor').read_bytes())
    for label,data in [('primitive',raw),('composite',json.dumps(scalar_task_program(),separators=(',',':')).encode()),('refusal',raw[:-1])]:
        old=subprocess.run(['hia-admit-agent-json'],executable='/proc/self/fd/'+str(normal),pass_fds=(normal,),input=data,capture_output=True,env={'PATH':''},timeout=5)
        r=proc.run(normal,data,outcap=16777280,errcap=65536)
        assert r['status']==0 and (os.waitstatus_to_exitcode(r['reply'][3]),r['stdout'],r['stderr'])==(old.returncode,old.stdout,old.stderr)
        record('actual-normalizer-'+label,r)
    for label,data in [('primitive',raw),('refusal',raw[:-1])]:
        old=subprocess.run(['hia-verify-core-json'],executable='/proc/self/fd/'+str(normal),pass_fds=(normal,),input=data,capture_output=True,env={'PATH':''},timeout=5)
        r=proc.run(normal,data,role=4,outcap=16777280,errcap=65536)
        assert r['status']==0 and (os.waitstatus_to_exitcode(r['reply'][3]),r['stdout'],r['stderr'])==(old.returncode,old.stdout,old.stderr)
        record('actual-normalizer-diagnostic-'+label,r)
    os.close(normal)
    proof=a.proof or A/'native-scalar-proof-engine-v7/hia-native-scalar-proof'
    pf=sealed(proof.read_bytes());name=b'f';request=struct.pack('<8s7Q',b'HIAMVP01',1,2000,len(name),len(raw),0,0,0)+name+raw
    r=proc.run(pf,request,role=2,outcap=8<<20,errcap=65536);assert r['status']==0 and r['reply'][3]==0 and r['stdout'][:8]==b'HIAMVR01',r
    assert json.loads(r['stdout'][64:])['structural_verification'] is True
    record('actual-primitive-proof',r);os.close(pf)
    builder=sealed((a.builder or depot/'hia-build-object').read_bytes());path=D/'actual-build.so'
    r=proc.run(builder,raw,role=3,path=os.fsencode(path),outcap=8<<20,errcap=8<<20,budget=15)
    assert r['status']==0 and r['reply'][3]==0 and path.read_bytes()[:4]==b'\x7fELF',r
    record('actual-build-shared',r);os.close(builder)
    # Separate workspaces must not share PID, pipe, offset, or cancellation state.
    def thread_case(index):
        data=struct.pack('<4Q',1,10000+index,777+index,index)
        return index,proc.run(fd,data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for index,r in pool.map(thread_case,range(8)):
            assert r['status']==0 and os.waitstatus_to_exitcode(r['reply'][3])==index
            assert len(r['stdout'])==10000+index and len(r['stderr'])==777+index
            record('concurrent-'+str(index),r)
    os.close(fd)
    report={'schema':'hepta.hia.multiversion-prepare-process.qualification.v1','passed':len(rows),'failed':0,'whole_native_runtime':False,'scope':'actual sealed fixed-role process capture with bounded streams, absolute deadline, cancellation, direct-child reaping and same process-group termination','image_sha256':sha((D/'process-component.so').read_bytes()),'qa_child_sha256':sha(image),'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PROCESS_QUALIFICATION_PASS',len(rows),flush=True)
if __name__=='__main__':main()

