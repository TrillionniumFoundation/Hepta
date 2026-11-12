"""Four new lifecycle observations on unchanged R3; no compile or suite replay."""
from __future__ import annotations
import argparse,hashlib,json,os,signal,subprocess,sys,time,traceback
from pathlib import Path
from run_byte_abi_development import BASE,TREE,CORE_PACKET,BYTE_PACKET,digest,decode,git,snapshot,apply,encoded

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    source,inputs,output=a.source.resolve(),a.input.resolve(),a.output.resolve();output.mkdir(mode=0o700)
    r={'schema':'hia.native-byte-abi.call-ci.v1','scope':'FOUR_ADDITIONAL_ACTUAL_CALL_LIFETIME_OBSERVATIONS','status':'HOLD','base':BASE,'base_tree':TREE,'python':sys.version,'no_compilation':True,'original_23_and_29_not_replayed':True,'current_cold':False,'whole_qualified':False,'product_changes':[]};expected=None;authority={};started=time.monotonic()
    try:
        if sys.version_info[:3]!=(3,14,4) or sys.implementation.name!='cpython':raise ValueError('actual CPython3.14.4 required')
        authority={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs.iterdir() if x.is_file()}
        if git(source,'rev-parse','HEAD').decode().strip()!=BASE or git(source,'rev-parse','HEAD^{tree}').decode().strip()!=TREE or git(source,'status','--porcelain'):raise ValueError('exact clean4b source required')
        base=json.loads(decode(inputs/'base-map.zlib.json'));assert len(base)==3153
        entries={}
        for row in git(source,'ls-tree','-r','-z','HEAD').split(b'\0'):
            if not row:continue
            header,name=row.split(b'\t',1);mode,typ,sha=header.decode().split();assert typ=='blob';entries[name.decode()]=(mode,sha)
        assert entries=={n:(v['mode'],v['blob']) for n,v in base.items()}
        r['source_before']=snapshot(source,base)
        assert digest((inputs/'core-r3-source.json').read_bytes())==CORE_PACKET
        core=json.loads(decode(inputs/'core-r3-source.json',legacy=True));raw=decode(inputs/'byte-source-r3.zlib.json');assert digest(raw)==BYTE_PACKET;byte=json.loads(raw)
        assert len(core['files'])==27 and len(byte['files'])==16
        expected=dict(base);apply(source,expected,core['files'],core=True);apply(source,expected,byte['files']);assert len(expected)==3178
        r['source_after_overlay']=snapshot(source,expected)
        packet=json.loads((inputs/'image.zlib.json').read_bytes());image=decode(inputs/'image.zlib.json');assert digest(image)=='50070ab0cb820898d8c304a325f64f96e4606e6cea76a457480275ac5aa2b552'
        manifest=packet['manifest_utf8'].encode();assert digest(manifest)==packet['manifest_sha256'];record=json.loads(manifest)
        assert record['image_path']=='native-byte-abi.image.bin' and record['image_sha256']==digest(image) and record['source_sha256']==digest((source/'examples/hia_bootstrap/native_byte_abi.hiaasm').read_bytes())
        m=output/'development-manifest.json';m.write_bytes(manifest);im=output/record['image_path'];im.write_bytes(image)
        r['image']={k:v for k,v in packet.items() if k not in ('data','manifest_utf8')}
        env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_')};env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(source))
        argv=[sys.executable,'-B',str(inputs/'probe_byte_call_lifetime.py'),'--source',str(source),'--manifest',str(m),'--output',str(output/'OBSERVATIONS.json')]
        t=time.monotonic();child=subprocess.Popen(argv,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);timed_out=False
        try:out,err=child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(child.pid,signal.SIGKILL);out,err=child.communicate(timeout=30)
        (output/'probe.stdout').write_bytes(out);(output/'probe.stderr').write_bytes(err)
        r['process']={'argv':argv,'returncode':child.returncode,'timed_out':timed_out,'timeout_seconds':60,'seconds':time.monotonic()-t,'stdout_bytes':len(out),'stdout_sha256':digest(out),'stderr_bytes':len(err),'stderr_sha256':digest(err)}
        if (output/'OBSERVATIONS.json').exists():r['observations']=json.loads((output/'OBSERVATIONS.json').read_bytes())
        if child.returncode==0 and not timed_out and r.get('observations',{}).get('matched')==4:r['status']='PASS'
        if m.read_bytes()!=manifest or im.read_bytes()!=image:raise ValueError('actual image/manifest changed')
    except BaseException as error:r['failure']={'type':type(error).__name__,'text':str(error),'traceback':traceback.format_exc()}
    finally:
        try:
            if expected is not None:r['source_after']=snapshot(source,expected);r['source_stable']=True
            if authority!={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs.iterdir() if x.is_file()}:raise ValueError('harness inputs changed')
        except BaseException as error:r['custody_failure']={'type':type(error).__name__,'text':str(error),'traceback':traceback.format_exc()};r['status']='HOLD'
        r['seconds']=time.monotonic()-started;(output/'RESULT.json').write_bytes(encoded(r))
        print(json.dumps({k:v for k,v in r.items() if k not in ('source_before','source_after_overlay','source_after')},indent=2))
    return 0 if r['status']=='PASS' and 'failure' not in r else 1
if __name__=='__main__':raise SystemExit(main())
