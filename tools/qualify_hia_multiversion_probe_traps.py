"""Trap/budget failures in the live HIA probe path, before unsafe native calls."""
from pathlib import Path
import argparse,copy,json,os,struct,subprocess
from tools.qualify_hia_multiversion_probe_owner import Probe
from tools.qualify_hia_multiversion_call import function,document
from tools.qualify_hia_multiversion_components import get,sha
from hepta import hia_multiversion as original
from hepta.hia_program import verify_program,execute_program
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--components',type=Path,required=True);p.add_argument('--image-directory',type=Path,required=True);p.add_argument('--retirement-directory',type=Path,required=True);p.add_argument('--builder',type=Path,required=True);a=p.parse_args()
    D=a.directory;D.mkdir();os.symlink(a.components/'probe-component.so',D/'probe-component.so');q=Probe(D,a.image_directory,a.retirement_directory)
    cases=[]
    for name,typ,op,const,status,code in [('overflow','u8','int.add.checked',1,1,'overflow'),('division-zero','u8','int.div.checked',0,2,'division_by_zero'),('signed-min-div','i8','int.div.checked',-1,3,'overflow'),('shift-width','u8','int.shl.checked',8,4,'overflow')]:
        fn=function('probe',[typ],operation=op);fn['blocks'][0]['ops'][0]['attrs']['value']=const;cases.append((name,fn,status,code))
    for code,status in [('user',7),('overflow',8),('division_by_zero',9),('bounds',10),('allocation',11)]:
        fn=function('probe',['u64']);fn['effects']=['trap'];fn['blocks'][0]['term']={'op':'trap','code':code};cases.append(('explicit-'+code,fn,status,code))
    fn=function('probe',['u64']);fn['effects']=['trap'];fn['blocks'][0]['term']={'op':'jump','target':'loop','args':['x0']};fn['blocks'].append({'id':'loop','params':[{'name':'y','type':'u64'}],'ops':[],'term':{'op':'jump','target':'loop','args':['y']}});cases.append(('step-budget',fn,5,'step'))
    fn=function('probe',['u64']);fn['effects']=['trap'];fn['blocks'][0]['ops']=[{'op':'call','args':['x0'],'out':[{'name':'r','type':'u64'}],'attrs':{'function':'probe'}}];fn['blocks'][0]['term']={'op':'ret','values':['r']};cases.append(('call-budget',fn,6,'depth'))
    rows=[]
    for name,fn,status,code in cases:
        program=verify_program(document([fn]));raw=json.dumps(program.as_dict(),separators=(',',':'),sort_keys=True).encode();(D/(name+'.core.json')).write_bytes(raw)
        safe=verify_program(document([function('probe',[p['type'] for p in fn['params']],result=fn['returns'][0])]))
        safe_raw=json.dumps(safe.as_dict(),separators=(',',':'),sort_keys=True).encode();abi=q.f.make_abi(safe_raw)
        signature=original.ScalarABI('probe',tuple(p['type'] for p in fn['params']),fn['returns'][0]);vectors=original._probe_vectors(signature)
        successes=0;error=None
        for vector in vectors:
            try:execute_program(program,'probe',list(vector),max_steps=4224,max_call_depth=256);successes+=1
            except Exception as exc:error={'class':type(exc).__name__,'text':str(exc),'code':getattr(exc,'code',None)};break
        assert error is not None,(name,'old VM unexpectedly normal')
        if code not in str(error).lower():
            assert code=='depth' and 'call' in str(error).lower(),(name,error)
        output=D/(name+'.built.so');r=subprocess.run(['hia-build-shared',str(output)],executable=str(a.builder),input=raw,env={'PATH':''},capture_output=True,timeout=60)
        (D/(name+'.build.stdout')).write_bytes(r.stdout);(D/(name+'.build.stderr')).write_bytes(r.stderr);assert r.returncode==0,(name,r.returncode,r.stderr[-4000:])
        before=set(os.listdir('/proc/self/fd'));q.loaded(name,output.read_bytes(),abi)
        try:
            row=q.probe(name,raw,5,successes);observed=get(q.f.work,(3<<20)+8);assert observed==status,(name,observed,status)
            row.update({'old_vm_exception':error,'actual_vm_status':observed,'unsafe_vector_never_called_natively':True})
        finally:q.retire()
        assert set(os.listdir('/proc/self/fd'))==before;rows.append(row)
    report={'schema':'hepta.hia.multiversion-native-probe-traps.v1','scope':'fault defence at private preparation probe stage; public profile/totality rejects these inputs earlier','whole_native_runtime':False,'passed':len(rows),'failed':0,'vm_steps':4224,'vm_depth':256,'image_sha256':sha((D/'probe-component.so').read_bytes()),'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('MV_PROBE_TRAPS_PASS',len(rows),flush=True)
if __name__=='__main__':main()
