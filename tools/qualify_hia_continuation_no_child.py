"""Two unchanged original no-child compiler scripts through four HIA schedulers.

Only setup selects native owners. Original inner caller bodies still prohibit
LLVM and process launching; this is not the full original module test suite.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
FAMILIES=('core-lowering','core-emitter','byte-wrapper','machine-object')
PREFIX='''from pathlib import Path
import hashlib,importlib,importlib.abc,inspect,json,os,sys
from unittest.mock import patch
sys.path.insert(0,SITE_PATH)
class NoAuthoring(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if (fullname.startswith('tools.') and fullname!='tools.hia_core_reference') or 'generate_hia_' in fullname:raise AssertionError('runtime authoring import '+fullname)
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_program_native as backend,hia_native_byte_abi as byte_abi,hia_machine_elf as elf
from hepta.hia_core_lowering_native import LoweringSession
from hepta.hia_native_continuation_inprocess import InProcessContinuation
owners={};counts={};controls=[];original_run=InProcessContinuation.run
for family,namespace in [('core-lowering',backend),('core-emitter',backend),('byte-wrapper',byte_abi),('machine-object',elf)]:
 name=family.replace('-','_');selection=importlib.import_module('hepta.hia_'+name+'_selection')
 path=MANIFESTS[family];os.environ[selection.SELECTOR]=path
 owner=getattr(selection,'installed_'+name)(path,vars(namespace))
 assert isinstance(owner._continuation,InProcessContinuation)
 owners[id(owner)]=family;counts[family]=dict(invocations=0,calls=0,handoffs=0)
 controls.append(owner)
def run(engine,session):
 result=original_run(engine,session)
 family=owners.get(id(session.owner))
 if family is not None:
  row=counts[family];row['invocations']+=1;row['calls']+=session.native_observation[3];row['handoffs']+=session.native_observation[4]
 return result
InProcessContinuation.run=run
def forbidden(*args,**kwargs):raise AssertionError('retained Python scheduler/control entered')
for name in ('run','step','handoff'):setattr(LoweringSession,name,forbidden)
for base in (backend._Function,backend._Emitter):
 for name,method in tuple(vars(base).items()):
  if inspect.isfunction(method)and name!='__new__':setattr(base,name,forbidden)
for name in ('_reference_normalize_exports','_reference_emit_wrapper'):setattr(byte_abi,name,forbidden)
for name in ('_reference_name','_reference_exact_int','_reference_write_elf_object'):setattr(elf,name,forbidden)
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report',type=Path)
    parser.add_argument('--development-bundles',type=Path)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    if bool(args.cold_report)==bool(args.development_bundles):parser.error('exactly one matching cold or explicit development bundle map required')
    from tools.hia_selfhost_contract import file_digests
    from tests.test_hia_program_native import minimal_document
    from tests.test_hia_native_byte_abi import byte_program
    before=file_digests(ROOT);args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    if args.cold_report:
        from tools.build_hia_native_continuation import build
        cold=json.loads(args.cold_report.read_bytes());nested=json.loads(Path(cold['nested_report']).read_bytes())
        compiler=Path(nested['generations'][-1]['produced_image'])
        manifests={kind:str(build(args.evidence/kind,compiler,args.cold_report,in_process=True,kind=kind)) for kind in FAMILIES}
        scope='MATCHING_SOURCE_COLD_TWO_ORIGINAL_INNER_SCRIPTS_NOT_FULL_MODULES'
    else:
        manifests=json.loads(args.development_bundles.read_bytes());scope='EXPLICIT_OLDER_COMPILER_DEVELOPMENT_TWO_ORIGINAL_INNER_SCRIPTS_NOT_FULL_MODULES'
    if type(manifests) is not dict or set(manifests)!=set(FAMILIES):raise ValueError('exact four-family manifest map required')
    bundle_pins={}
    for name,path in manifests.items():
        if type(path) is not str or not Path(path).is_absolute():raise ValueError('absolute native scheduling manifest required')
        for p in sorted(Path(path).parent.rglob('*')):
            if p.is_file():bundle_pins[str(p)]=sha256(p.read_bytes()).hexdigest()
    rows=[]
    for module,method,document in (
            ('test_hia_program_native','test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch',minimal_document()),
            ('test_hia_native_byte_abi','test_direct_byte_object_emission_needs_no_llvm_or_subprocess',byte_program())):
        source=ROOT/'tests'/(module+'.py');raw=source.read_bytes();tree=ast.parse(raw)
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==method)
        assignment=next(n for n in node.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='script' for t in n.targets))
        original=ast.literal_eval(assignment.value)
        directory=args.evidence/module;directory.mkdir(mode=0o700)
        (directory/'original-script.py').open('x').write(original)
        prefix=PREFIX.replace('SITE_PATH',repr(str(ROOT.resolve()))).replace('MANIFESTS',repr(manifests))
        suffix='\nassert all(v["invocations"]>0 and v["calls"]>0 for v in counts.values()),counts\nassert not any(n.startswith("tools.") and n!="tools.hia_core_reference" for n in sys.modules)\nprint("NATIVE_NO_CHILD_COUNTS",json.dumps(counts,sort_keys=True))\n'
        child=directory/'captured-caller.py';child.open('x').write(prefix+'\n'+original+suffix)
        env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k not in ('PYTHONPATH','PYTHONHOME')};env.update(PATH='',PYTHONDONTWRITEBYTECODE='1')
        started=time.monotonic()
        result=subprocess.run([sys.executable,'-B','-I','-S',str(child),json.dumps(document),str(directory/'output.o')],cwd=directory,env=env,capture_output=True,timeout=20,start_new_session=True)
        (directory/'stdout.log').open('xb').write(result.stdout);(directory/'stderr.log').open('xb').write(result.stderr)
        row=dict(module=module,method=method,original_script_sha256=sha256(original.encode()).hexdigest(),original_test_source_sha256=sha256(raw).hexdigest(),returncode=result.returncode,seconds=time.monotonic()-started)
        if result.returncode==0:
            lines=[line for line in result.stdout.decode().splitlines() if line.startswith('NATIVE_NO_CHILD_COUNTS ')]
            if len(lines)!=1:raise ValueError('one exact native no-child observation required')
            counts=json.loads(lines[0].split(' ',1)[1])
            if type(counts) is not dict or set(counts)!=set(FAMILIES):raise ValueError('native no-child family observation differs')
            row['native_counts']=counts
        rows.append(row)
        if result.returncode:break
    stable=file_digests(ROOT)==before and all(sha256(Path(path).read_bytes()).hexdigest()==pin for path,pin in bundle_pins.items())
    combined={family:{field:sum(row.get('native_counts',{}).get(family,{}).get(field,0) for row in rows) for field in ('invocations','calls','handoffs')} for family in FAMILIES}
    covered=all(all(type(value) is int and value>0 for value in counts.values()) for counts in combined.values())
    passed=len(rows)==2 and all(r['returncode']==0 for r in rows) and stable and covered
    report=dict(status='PASS' if passed else 'FAIL',scope=scope,rows=rows,combined_native_counts=combined,actual_internal_handoffs_covered_by_both_original_scripts=covered,original_bodies_unchanged=True,source_and_bundle_unchanged=stable,
        source_pins=before,bundle_pins=bundle_pins,retained_controls_and_host_run_step_handoff_forbidden=True,runtime_authoring_and_child_launch_forbidden=True,original_CLI_shim_only_allowed_tool='tools.hia_core_reference',external_objects_still_hosted=True,whole_native_delivery_qualified=False)
    (args.evidence/'report.json').open('x').write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','scope','source_and_bundle_unchanged')}))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
