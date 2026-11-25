"""Every positive original probe signature through actual HIA build/load/VM/native."""
from pathlib import Path
import argparse,copy,hashlib,json,os,random,subprocess,sys,time
from tools.qualify_hia_multiversion_probe_owner import Probe
from tools.qualify_hia_multiversion_call import function,document
from tools.generate_hia_multiversion_abi import TYPES
from hepta.hia_multiversion import ScalarABI,_probe_vectors
from hepta.hia_program import verify_program
def sha(x):return hashlib.sha256(x).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',required=True,type=Path);p.add_argument('--components',required=True,type=Path);p.add_argument('--image-directory',required=True,type=Path);p.add_argument('--retirement-directory',required=True,type=Path);p.add_argument('--builder',required=True,type=Path);a=p.parse_args()
    D=a.directory;D.mkdir()
    # The production component is immutable; only the external QA output is new.
    os.symlink(a.components/'probe-component.so',D/'probe-component.so')
    q=Probe(D,a.image_directory,a.retirement_directory)
    inputs=[([typ]*n,typ+'-'+str(n),typ) for typ in TYPES for n in range(17)]
    rng=random.Random(0x4d565052)
    for i in range(96):
        types=[rng.choice(TYPES) for _ in range(rng.randrange(17))]
        inputs.append((types,'mixed-'+str(i),TYPES[i%len(TYPES)]))
    programs=[];total=0;rows=[];start=time.monotonic_ns()
    for first in range(0,len(inputs),16):
        group=inputs[first:first+16];functions=[];vectors=0;signatures=[]
        for i,(types,label,result0) in enumerate(group,first):
            selected=i%len(types) if types else 0;result=types[selected] if types else result0
            name='signature_'+str(i).zfill(4)
            functions.append(function(name,types,result=result,selected=selected))
            count=len(_probe_vectors(ScalarABI(name,tuple(types),result)));vectors+=count
            signatures.append({'case':label,'function':name,'parameters':types,'result':result,'selected':selected,'vectors':count})
        label='batch-'+str(first//16).zfill(2)
        program=verify_program(document(functions));raw=json.dumps(program.as_dict(),sort_keys=True,separators=(',',':')).encode()
        (D/(label+'.core.json')).write_bytes(raw);artifact=D/(label+'.built.so')
        before=time.monotonic_ns();r=subprocess.run(['hia-build-shared',str(artifact)],executable=str(a.builder),input=raw,env={'PATH':''},capture_output=True,timeout=60)
        (D/(label+'.build.stdout')).write_bytes(r.stdout);(D/(label+'.build.stderr')).write_bytes(r.stderr)
        assert r.returncode==0,(label,r.returncode,r.stderr[-4000:])
        abi=q.f.make_abi(raw);data=artifact.read_bytes();fds=set(os.listdir('/proc/self/fd'))
        q.loaded(label,data,abi)
        try:row=q.probe(label,raw,0,vectors)
        finally:q.retire()
        assert set(os.listdir('/proc/self/fd'))==fds
        row.update({'build_report_sha256':sha(r.stdout),'actual_image_sha256':sha(data),'elapsed_ns':time.monotonic_ns()-before,'signatures':signatures});rows.append(row);total+=vectors
    assert len(inputs)==283 and total==16547
    report={'schema':'hepta.hia.multiversion-all-signature-native-probes.v1','whole_native_runtime':False,'positive_signatures':len(inputs),'actual_builds':len(rows),'actual_native_calls':total,'actual_vm_calls':total,'vm_max_steps':4224,'vm_max_depth':256,'passed':len(rows),'failed':0,'elapsed_ns':time.monotonic_ns()-start,'native_builder':{'path':str(a.builder),'sha256':sha(a.builder.read_bytes())},'probe_image_sha256':sha((D/'probe-component.so').read_bytes()),'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_ALL_SIGNATURES_PASS',len(inputs),len(rows),total,flush=True)
if __name__=='__main__':main()
