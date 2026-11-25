"""Real syscall faults, uncertain close and fd-number reuse against old owner."""
from pathlib import Path
import sys,subprocess,json,re,hashlib,os
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';PY='/home/qian-qi/hia-unified-env-20261120/bin/python'
def run(D,image,work,name,mode,inject=None):
    trace=work/(name+'.trace');out=work/(name+'.json')
    args=['/usr/bin/strace','-qq','-e','trace=close,unlink,unlinkat,newfstatat,fstat,write','-o',str(trace)]
    if inject:args+=['-e','inject='+inject]
    r=subprocess.run(args+[PY,'-m','tools.qualify_hia_multiversion_retirement_fault_child',str(D),str(image),mode,work.name+"-"+name,str(out)],cwd=V,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},capture_output=True,timeout=45)
    (work/(name+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,(name,r.returncode,r.stderr)
    return json.loads(out.read_text()),trace.read_text()
def counts(trace):
    seen={};selected={};inside=False
    for line in trace.splitlines():
        m=re.match(r'([a-zA-Z_0-9]+)\(',line)
        if not m:continue
        call=m.group(1);seen[call]=seen.get(call,0)+1
        if 'RETIRE_BEGIN' in line:inside=True;continue
        if 'RETIRE_RETRY' in line:inside=False
        if not inside:continue
        kind=None
        if call=='close':kind='memfd-close' if 'memfd-close' not in selected else 'pin-close'
        elif call in ('unlink','unlinkat'):kind='unlink'
        elif call=='newfstatat' and 'AT_SYMLINK_NOFOLLOW' in line:kind='path-stat'
        elif call=='fstat' or (call=='newfstatat' and 'AT_EMPTY_PATH' in line):kind='pin-stat'
        if kind is not None and kind not in selected:selected[kind]=(call,seen[call],line)
    return selected
def main():
    D=Path(sys.argv[1]);image=Path(sys.argv[2]);work=Path(sys.argv[3]);work.mkdir()
    baseline={};pairs=[]
    for mode in ['original','native']:
        row,trace=run(D,image,work,'baseline-'+mode,mode);baseline[mode]=counts(trace);print(mode,baseline[mode],flush=True)
    for kind in ['memfd-close','pin-close','unlink','path-stat','pin-stat']:
        assert kind in baseline['original'] and kind in baseline['native'],kind
        for error in ['EIO','EINTR']:
            rows=[]
            for mode in ['original','native']:
                call,n,_=baseline[mode][kind];name=kind+'-'+error+'-'+mode
                row,_=run(D,image,work,name,mode,call+':error='+error+':when='+str(n));rows.append(row)
            assert rows[0]==rows[1],(kind,error,rows)
            if kind.endswith('close'):assert rows[0]['reused_fd_survived']==1
            pairs.append({'case':kind+'-'+error,'snapshots':rows[0]});print('RETIRE_FAULT_PASS',kind,error,flush=True)
    report={'schema':'hepta.hia.multiversion-retirement-faults.v1','passed_pairs':len(pairs),'failed':0,'image_sha256':hashlib.sha256((D/'retirement-component.so').read_bytes()).hexdigest(),'cases':pairs}
    (work/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_RETIRE_OS_PASS',len(pairs),flush=True)
if __name__=='__main__':main()
