"""Actual kernel-error qualification of the native generation loader."""
from pathlib import Path
import sys,subprocess,json,re,hashlib
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
V=B/'native-multiversion-source';PY='/home/qian-qi/hia-unified-env-20261120/bin/python'
def run(D,work,name,mode,inject=None):
    trace=work/(name+'.trace');result=work/(name+'.json')
    args=['/usr/bin/strace','-qq','-e','trace=fcntl,write,pread64,memfd_create','-o',str(trace)]
    if inject:args+=['-e','inject='+inject]
    args += [PY,'-m','tools.qualify_hia_multiversion_image_fault_child',str(D),mode,str(B/'native-multiversion-call-v5/all-types.so'),str(result)]
    r=subprocess.run(args,cwd=V,capture_output=True,timeout=45)
    (work/(name+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,(name,r.returncode,r.stderr)
    row=json.loads(result.read_text());assert row['fd_balanced']
    return row,trace.read_text()
def counts(trace):
    seen={};rows=[];inside=False
    for line in trace.splitlines():
        m=re.match(r'([a-zA-Z_0-9]+)\(',line)
        if not m:continue
        syscall=m.group(1);seen[syscall]=seen.get(syscall,0)+1
        if 'IMAGE_BEGIN' in line:inside=True;continue
        if 'IMAGE_END' in line:inside=False
        if inside and syscall=='fcntl':
            kind='add' if 'F_ADD_SEALS' in line else 'get' if 'F_GET_SEALS' in line else 'other'
            rows.append((syscall,seen[syscall],kind,line))
    return rows
def main():
    D=Path(sys.argv[1]);work=Path(sys.argv[2]);work.mkdir()
    baseline={};rows=[]
    for mode in ['original','native']:
        result,trace=run(D,work,'baseline-'+mode,mode);assert result['accepted']
        baseline[mode]=counts(trace);print(mode,baseline[mode],flush=True)
    assert [x[2] for x in baseline['original']]==[x[2] for x in baseline['native']]==['add','get','get','get']
    for index,kind in enumerate(['add','get-seal','get-before-maps','get-after-maps']):
        for error,want in [('EPERM',False),('EIO',False),('EINTR',True)]:
            pair=[]
            for mode in ['original','native']:
                when=baseline[mode][index][1]
                name=f'{kind}-{error}-{mode}'
                result,_=run(D,work,name,mode,'fcntl:error='+error+':when='+str(when))
                assert result['accepted']==want,(name,result,want)
                pair.append(result)
            rows.append({'case':kind+'-'+error,'original':pair[0],'native':pair[1]})
            print('FAULT_PAIR_PASS',kind,error,flush=True)
    report={'schema':'hepta.hia.multiversion-image-actual-syscall-qualification.v1','scope':'actual fcntl failures and EINTR retry at all seal/mapping checks, original/native paired','passed_pairs':len(rows),'failed':0,'image_sha256':hashlib.sha256((D/'image-component.so').read_bytes()).hexdigest(),'cases':rows}
    (work/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('MV_IMAGE_OS_PASS',len(rows),flush=True)
if __name__=='__main__':main()
