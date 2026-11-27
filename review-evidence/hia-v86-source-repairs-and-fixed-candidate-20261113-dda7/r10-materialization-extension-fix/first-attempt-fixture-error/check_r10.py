"""Bounded harness controls only; no product imports, generators, or tests."""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import traceback

ROOT=Path(__file__).resolve().parent
HARNESS=Path('/workspace/scratch/dda74a4fae35/recovered-v85/harness/tools')
OLD=Path('/workspace/scratch/dda74a4fae35/v85-backend-source-repair-r1/originals/before-materialization-fragment.hepta')
NEW=Path('/workspace/scratch/dda74a4fae35/v85-backend-source-repair-r1/source/tools/hia_program_normalization_materialize.hepta')

def identity(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def functions(raw):
    result={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.FunctionDef):result[node.name]=ast.dump(node,include_attributes=False)
        elif isinstance(node,ast.ClassDef):
            for method in node.body:
                if isinstance(method,ast.FunctionDef):result[node.name+'.'+method.name]=ast.dump(method,include_attributes=False)
    return result

def main():
    r8=(HARNESS/'materialize_candidate_r9.py').read_bytes()
    r9=(HARNESS/'materialize_candidate_r10.py').read_bytes()
    original=OLD.read_bytes();complete=NEW.read_bytes()
    assert identity(r8)['blob']=='dd141887690ced77704e7ba2f6ac482edca97f02'
    assert identity(r9)['blob']=='03249a2c928055f5451a3ab8bbfbccf47eee8a91'
    assert identity(original)['blob']=='544235f7f1364b0956657888547465d527d62d9e'
    assert identity(complete)['blob']=='684d9cebab563fb2d7ca0e4aae8f0deac28397be'
    assert complete[:len(original)]==original
    before,after=functions(r8),functions(r9)
    changed=[name for name in before if name in after and before[name]!=after[name]]
    assert changed==['check_materialization_extension'],changed
    assert not set(after)-set(before)
    assert not set(before)-set(after)
    tree=ast.parse(r9)
    definitions=[n for n in tree.body if isinstance(n,ast.FunctionDef)
                 and n.name in {'check','sha','oid','check_materialization_extension'}]
    assert len(definitions)==4
    namespace={'hashlib':hashlib}
    exec(compile(ast.Module(body=definitions,type_ignores=[]),str(HARNESS/'materialize_candidate_r10.py'),'exec'),namespace)
    admit=namespace['check_materialization_extension']
    pin={'path':'tools/hia_program_normalization_materialize.hiaasm',
         'target':'tools/hia_program_normalization_materialize.hepta','mode':'100644',
         'action':'retained-prefix-complete-program','blob':'544235f7f1364b0956657888547465d527d62d9e',
         'prefix_bytes':41578,'prefix_sha256':'eb56e6922b6b47524ef7005bb15d886221e34deaa46794b7805ab819c6473008',
         'target_bytes':58467,'target_blob':'684d9cebab563fb2d7ca0e4aae8f0deac28397be',
         'target_sha256':'ca2b5dd0560cc27cb4b5c684978d8a9a62402d79d5f91c2515eb9f3168898e24',
         'semantic_equivalence_claim':False}
    observations=[]
    def observe(label,pin_value,old_value,path,expected):
        started=time.monotonic()
        try:
            value=admit(pin_value,old_value,path)
            row={'case':label,'outcome':'accepted','value':value}
        except BaseException as error:
            row={'case':label,'outcome':'rejected','error_type':type(error).__name__,
                 'error':str(error),'traceback':traceback.format_exc()}
        row.update(expected=expected,wall_seconds=time.monotonic()-started,
                   matches_expected=row['outcome']==expected)
        observations.append(row)
    with tempfile.TemporaryDirectory(prefix='r9-controls-',dir=ROOT) as directory:
        base=Path(directory);ordinary=base/'ordinary.hepta';ordinary.write_bytes(complete);ordinary.chmod(0o644)
        observe('actual_original_and_complete_file',pin,original,ordinary,'accepted')
        changed_prefix=bytes([original[0]^1])+original[1:]
        observe('changed_original_prefix',pin,changed_prefix,ordinary,'rejected')
        for name,raw in [('changed_target_prefix',bytes([complete[0]^1])+complete[1:]),
                         ('changed_target_closure',complete[:-1]+bytes([complete[-1]^1])),
                         ('truncated_target',complete[:-1])]:
            path=base/(name+'.hepta');path.write_bytes(raw)
            observe(name,pin,original,path,'rejected')
        for key,value in [('path','tools/other.hiaasm'),('target','tools/other.hepta'),
                          ('mode','100755'),('action','relocate-exact-bytes'),
                          ('prefix_bytes',41578.0),('target_bytes',True),
                          ('blob','0'*40),('prefix_sha256','0'*64),
                          ('target_blob','0'*40),('target_sha256','0'*64)]:
            altered=dict(pin);altered[key]=value
            observe('changed_pin_'+key,altered,original,ordinary,'rejected')
        link=base/'link.hepta';link.symlink_to(ordinary)
        observe('symlink_target',pin,original,link,'rejected')
        folder=base/'directory.hepta';folder.mkdir()
        observe('directory_target',pin,original,folder,'rejected')
        fifo=base/'fifo.hepta';os.mkfifo(fifo)
        observe('fifo_target',pin,original,fifo,'rejected')
        observe('missing_target',pin,original,base/'absent.hepta','rejected')
        executable=base/'executable.hepta';executable.write_bytes(complete);executable.chmod(0o755)
        observe('physical_target_mode_0755_with_pin_100644',pin,original,executable,'rejected')
    assert (HARNESS/'materialize_candidate_r10.py').read_bytes()==r9
    assert (HARNESS/'materialize_candidate_r9.py').read_bytes()==r8
    assert OLD.read_bytes()==original and NEW.read_bytes()==complete
    report={'schema':'hepta.r10-materialization-extension-controls.v1',
            'status':'PASS' if all(row['matches_expected'] for row in observations) else 'COUNTEREXAMPLE',
            'scope':'Actual new harness helper only; no product import or generator/test/native execution',
            'baseline_r9':identity(r8),'candidate_r10':identity(r9),'original_fragment':identity(original),'new_complete_input':identity(complete),
            'changed_function_asts':changed,'added_function_asts':sorted(set(after)-set(before)),
            'all_other_function_asts_unchanged':True,'source_gate_gates_unchanged':True,
            'observations':observations,'controls':len(observations),
            'matching_controls':sum(row['matches_expected'] for row in observations),
            'all_four_input_files_unchanged':True,'product_executed':False,'qualification':False}
    (ROOT/'REPORT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='observations'},indent=2))
    print(json.dumps([row for row in observations if not row['matches_expected']],indent=2))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
