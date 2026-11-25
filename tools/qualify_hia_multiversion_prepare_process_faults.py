"""Actual transport syscall fault and short-write controls, without product edits."""
from pathlib import Path
import argparse,os,sys,json,hashlib,errno
from tools.hia_multiversion_process_ptrace_qa import trace
from tools.generate_hia_multiversion_prepare_process_packer import BRIDGE
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--source',type=Path,required=True);a=p.parse_args();D=a.directory;Q=D/'faults-v2';Q.mkdir(mode=0o700,exist_ok=False)
    env={**os.environ,'PYTHONPATH':str(a.source),'PYTHONDONTWRITEBYTECODE':'1'};rows=[];at=BRIDGE.index(bytes.fromhex('0f05'));assert BRIDGE.find(bytes.fromhex('0f05'),at+2)==-1
    def run(label,**kw):
        target=Q/(label+'.json')
        r=trace([sys.executable,'-B','-m','tools.hia_multiversion_prepare_process_fault_worker',str(D),str(target),'short'],env,str(Q/(label+'.stderr')),syscall_offset=at,**kw)
        (Q/(label+'.trace.json')).write_text(json.dumps(r,indent=2)+'\n')
        assert r['returncode']==0 and target.exists(),(label,r['returncode'],(Q/(label+'.stderr')).read_text()[-4000:])
        return json.loads(target.read_text()),r
    base,t=run('baseline');assert base['status']==0 and t['events'];record={'case':'baseline','outcome':0};rows.append(record)
    specs=[]
    def add(label,phase,nr,error,want,ordinal=1,retval=None):specs.append((label,phase,nr,error,want,ordinal,retval))
    for label,phase,nr in [('dup',3,72),('role-seals',4,72),('role-stat',5,5),('input-memfd',7,319),('seek',10,8),('stdout-mode',15,91),('stderr-mode',18,91),('fork',25,57)]:
        add(label+'-EIO',phase,nr,errno.EIO,3)
    add('bad-role-seals',4,72,None,3,retval=0)
    for i in (1,2,3):add('pipe-'+str(i)+'-EMFILE',20,293,errno.EMFILE,3,i)
    for label,phase in [('input',11),('stdout',150),('stderr',152)]:add(label+'-seal-EIO',phase,72,errno.EIO,3)
    for label,phase in [('input',9),('capture',102)]:
        add(label+'-write-EINTR',phase,1,errno.EINTR,0)
        add(label+'-write-EIO',phase,1,errno.EIO,3)
        add(label+'-write-zero',phase,1,None,3,retval=0)
    for label,phase,nr in [('read',101,0),('waitid',103,247),('wait4',120,61),('poll',104,7)]:
        add(label+'-EINTR',phase,nr,errno.EINTR,0)
        add(label+'-EIO',phase,nr,errno.EIO,3)
    for phase in (1,200):add('clock-'+str(phase)+'-EIO',phase,228,errno.EIO,3)
    for label,phase,nr,error,want,ordinal,retval in specs:
        r,t=run(label,phase=phase,number=nr,ordinal=ordinal,error=error,retval=retval)
        assert len(t['injected'])==1,(label,'not exactly once',t['injected'])
        assert r['status']==want,(label,r,want)
        rows.append({'case':label,'phase':phase,'syscall':nr,'ordinal':ordinal,'error':error,'retval':retval,'outcome':r['status'],'owned_child_reaped':r['reply'][12],'actual_injected':t['injected'][0]})
        print('PROCESS_FAULT_PASS',label,want,flush=True)
    for n in (1,7,97,4096):
        r,t=run('real-short-write-'+str(n),short_write=n)
        assert r['status']==0 and t['injected']
        assert all(0<item['result']<=n for item in t['injected']),('not an actual partial write',n)
        rows.append({'case':'real-short-write-'+str(n),'outcome':0,'actual_short_calls':len(t['injected']),'source_and_output_exact':True})
        print('PROCESS_SHORT_PASS',n,len(t['injected']),flush=True)
    report={'schema':'hepta.hia.multiversion-prepare-process.faults.v2','passed':len(rows),'failed':0,'whole_native_runtime':False,'product_image_sha256':hashlib.sha256((D/'process-component.so').read_bytes()).hexdigest(),'method':'external ptrace at the actual unchanged native adapter syscall PC and HIA continuation phase; short writes execute the real syscall with reduced count, preserving actual bytes and actual returned count','cases':rows}
    (D/'fault-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PROCESS_FAULTS_PASS',len(rows),flush=True)
if __name__=='__main__':main()

