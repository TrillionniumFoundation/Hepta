"""Bind the actual interpreter, immutable foreign bytes and exact 4b checkout."""
import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time
import traceback

BASE = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE = '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
PARENT = '5f7f95367e8e395863801487e969d286b9091110'

def identity(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode): raise ValueError('ordinary input required')
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha': sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
            'mode': '100755' if mode & 0o111 else '100644'}

def files(root):
    return {p.relative_to(root).as_posix(): identity(p) for p in sorted(root.rglob('*'))
            if p.is_file() and '.git' not in p.relative_to(root).parts and '__pycache__' not in p.parts}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    here=Path(__file__).resolve().parent;out=args.output.absolute();out.mkdir(mode=0o700,exist_ok=False)
    before=None;inputs=files(here);start=time.perf_counter_ns()
    report={'schema':'hia.proof-fixed-foreign.actual314-driver.v1','python':sys.version,
            'source_head':BASE,'source_tree':TREE,'native_entries':0,'proof_policy_calls':0,
            'scope':'FIXED_INTERPRETER_PRIMITIVES_ONLY','current_cold':False,'whole_native':False}
    def git(*values):
        return subprocess.check_output(['git',*values],cwd=root,timeout=30)
    try:
        assert sys.implementation.name=='cpython' and sys.version_info[:3]==(3,14,4)
        release=platform.freedesktop_os_release()
        assert platform.system()=='Linux' and platform.machine()=='x86_64'
        assert release.get('ID')=='ubuntu' and release.get('VERSION_ID')=='24.04'
        assert (git('rev-parse','HEAD').decode().strip(),git('rev-parse','HEAD^{tree}').decode().strip(),
                git('rev-parse','HEAD^').decode().strip())==(BASE,TREE,PARENT)
        assert not git('status','--porcelain=v1','--untracked-files=all')
        before=files(root);assert len(before)==3153
        tracked={}
        for row in git('ls-tree','-r','-z','--full-tree','HEAD').split(b'\0'):
            if not row:continue
            header,name=row.split(b'\t',1);mode,kind,blob=header.decode().split()
            assert kind=='blob';tracked[name.decode()]={'mode':mode,'git_blob_sha':blob}
        assert set(tracked)==set(before)
        assert all(all(before[name][key]==value for key,value in row.items()) for name,row in tracked.items())
        (out/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
        (out/'inputs-before.json').write_text(json.dumps(inputs,sort_keys=True,indent=2)+'\n')
        argv=[sys.executable,'-B',str(here/'probe_fixed_proof.py'),'--candidate',str(here/'hia_proof_contract_foreign_frozen.py'),
              '--source',str(root),'--output',str(out/'probe'),'--expected-version','3.14.4']
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
        begin=time.perf_counter_ns()
        try:
            with (out/'probe.stdout.log').open('xb') as stdout,(out/'probe.stderr.log').open('xb') as stderr:
                result=subprocess.run(argv,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=60)
            report['terminal']={'argv':argv,'returncode':result.returncode,'timed_out':False,'timeout_seconds':60,
                                'elapsed_ns':time.perf_counter_ns()-begin}
        except subprocess.TimeoutExpired:
            report['terminal']={'argv':argv,'returncode':None,'timed_out':True,'timeout_seconds':60,
                                'elapsed_ns':time.perf_counter_ns()-begin}
            raise
        report['probe']=json.loads((out/'probe/REPORT.json').read_bytes())
        report['status']='PASS' if result.returncode==0 and report['probe']['status']=='PASS' else 'FAIL'
    except BaseException:
        report.update(status='FAIL',traceback=traceback.format_exc())
    finally:
        if before is not None:
            after=files(root)
            report['complete_source_unchanged']=after==before
            (out/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
            if after!=before:report['status']='FAIL'
        report['inputs_unchanged']=files(here)==inputs
        if not report['inputs_unchanged']:report['status']='FAIL'
        report['elapsed_ns']=time.perf_counter_ns()-start
        (out/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps({key:report.get(key) for key in ('status','complete_source_unchanged','inputs_unchanged','elapsed_ns')}))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
