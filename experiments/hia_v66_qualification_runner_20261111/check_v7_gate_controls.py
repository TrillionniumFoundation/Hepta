"""Controller delta/receipt injection controls, never product qualification."""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace


def assignment(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id==name for t in node.targets))


def function(tree,name):
    return next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name)


def wire_controls(tree, runner, output):
    """Call the actual controller gate with explicitly synthetic child receipts."""
    modules=ast.literal_eval(assignment(tree,'JSON_WIRE_CALLER_MODULES').value)
    names=ast.literal_eval(assignment(tree,'JSON_WIRE_CALLER_SOURCES').value)
    tools=ast.literal_eval(assignment(tree,'JSON_WIRE_AGENT_TOOLS').value)
    loaded=[name+'.Example.test_control' for name in modules]
    sources={name:sha256(name.encode()).hexdigest() for name in names}
    image_bytes=b'JSON wire controller fixture, not executable'
    image_sha=sha256(image_bytes).hexdigest()
    manifest={'schema':'hepta.hia.json-wire-native.v1',
              'source_sha256':sources['examples/hia_bootstrap/json_wire.hiaasm'],
              'image_path':'json-wire.image.bin','image_sha256':image_sha,'compiler_sha256':'7'*64}
    profile={'schema':'hepta.hia.ordinary-json-wire-product-profile.v1',
             'selector':'HEPTA_HIA_JSON_WIRE_MANIFEST','entire_python_call_domain_replaced':False}
    normal={'schema':'hepta.hia.json-wire-selected-callers.v1','status':'PASS',
        'scope':'MATCHING_SOURCE_COLD_SELECTED_CALLERS','loaded_test_ids':loaded,
        'chosen_test_ids':loaded[:],'executed_test_ids':loaded[:],
        'tests_loaded':len(loaded),'tests_chosen':len(loaded),'tests_run':len(loaded),
        'failures':[],'errors':[],'skipped':[],'expected_failures':[],'unexpected_successes':[],
        'explicit_development_exclusions':{},'retained_owner_forbidden':True,
        'host_encoder_forbidden_inside_native_owner':True,'retained_owner_entries':[],
        'host_encoder_entries':[],'ordinary_wire_calls':20,'actual_native_step_returns':{'0':9,'1':11},
        'source_manifest_image_stable':True,'subprocesses_inherit_selector':True,
        'matching_cold_source_closure_stable':True,
        'all_eleven_agent_tools_entered_selected_wire':True,
        'agent_tools_with_native_wire':dict.fromkeys(tools,1),'source_sha256':sources,
        'manifest':manifest,'image_sha256':image_sha,'ordinary_entry_profile':profile,
        'evidence_dir_retained':True}
    cases=[('normal',None,None)]
    for key,value in (
        ('schema','wrong'),('scope','DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'),
        ('chosen_test_ids',loaded[:-1]),('executed_test_ids',loaded[::-1]),
        ('tests_loaded',len(loaded)+1),('tests_chosen',float(len(loaded))),
        ('explicit_development_exclusions',{loaded[0]:'controller fault'}),
        ('retained_owner_forbidden',False),('host_encoder_forbidden_inside_native_owner',False),
        ('retained_owner_entries',['entered']),('host_encoder_entries',['entered']),
        ('ordinary_wire_calls',0),('ordinary_wire_calls',True),('actual_native_step_returns',{}),
        ('actual_native_step_returns',{'0':0}),('all_eleven_agent_tools_entered_selected_wire',False),
        ('agent_tools_with_native_wire',{name:1 for name in tools[:-1]}),
        ('source_manifest_image_stable',False),('subprocesses_inherit_selector',False),
        ('matching_cold_source_closure_stable',False),
        ('source_sha256',{}),('image_sha256','8'*64),('evidence_dir_retained',False)):
        cases.append((key+'-'+str(len(cases)),key,value))
    for key in ('errors','failures','skipped','expected_failures','unexpected_successes'):
        cases.append((key,key,['observed anomaly']))
    cases.extend((name,None,None) for name in (
        'duplicate-IDs','foreign-ID','compiler-drift','nonzero-child','cold-mutated',
        'wrong-image','missing-build','build-cold-sha','build-source-sha','profile-drift',
        'evidence-path','manifest-path','malformed-report'))
    code=compile(ast.Module(body=[function(tree,'selected_json_wire_callers')],type_ignores=[]),str(runner),'exec')
    results=[]
    for name,key,replacement in cases:
        directory=output/('wire-'+name);directory.mkdir()
        cold=directory/'cold.json';cold.write_text(json.dumps({'generation_sha256':['7'*64]*3}))
        value=deepcopy(normal)
        if key is not None:value[key]=replacement
        if name in ('duplicate-IDs','foreign-ID'):
            value['loaded_test_ids'][1]=value['loaded_test_ids'][0] if name=='duplicate-IDs' else 'tests.unrelated.Control.test_other'
            value['chosen_test_ids']=value['loaded_test_ids'][:]
            value['executed_test_ids']=value['loaded_test_ids'][:]
        if name=='compiler-drift':value['manifest']['compiler_sha256']='8'*64
        steps=[]
        def run(step,command):
            assert step=='json-wire-selected-callers'
            evidence=directory/'json-wire-selected-callers-evidence'
            assert command[:7]==['tools/qualify_hia_json_wire_native_callers.py',
                '--cold-report',str(cold),'--output',str(directory/'json-wire-selected-callers.json'),
                '--evidence-dir',str(evidence)]
            assert command[7:]==[item for module in modules for item in ('--module',module)]
            assert all(arg not in command for arg in ('--development','--manifest','--exclude'))
            build=evidence/'wire';build.mkdir(parents=True)
            value['evidence_dir']=str(evidence.resolve())
            value['manifest_path']=str((build/'manifest.json').resolve())
            if name=='evidence-path':value['evidence_dir']=str(directory/'unrelated')
            if name=='manifest-path':value['manifest_path']=str(directory/'unrelated.json')
            (build/'manifest.json').write_text(json.dumps(value['manifest']))
            (build/'json-wire.image.bin').write_bytes(image_bytes+b'changed' if name=='wrong-image' else image_bytes)
            receipt={'schema':'hepta.hia.json-wire-build.v1','scope':'MATCHING_SOURCE_COLD_BUILD',
                'manifest':value['manifest'],'source_manifest':sources,
                'cold_report_sha256':sha256(cold.read_bytes()).hexdigest(),
                'ordinary_entry_profile':profile,
                'native_compile_receipt':{'status':'returned','abi_status':0,'source_unchanged':True,
                    'produced_sha256':image_sha,'produced_bytes':len(image_bytes),
                    'input_sha256':manifest['source_sha256'],'artifact_sha256':'7'*64,
                    'forbidden_compiler_modules_loaded':[]}}
            if name=='build-cold-sha':receipt['cold_report_sha256']='8'*64
            if name=='build-source-sha':receipt['source_manifest']={}
            if name=='profile-drift':receipt['ordinary_entry_profile']={}
            if name!='missing-build':(build/'build.json').write_text(json.dumps(receipt))
            (directory/'json-wire-selected-callers.json').write_text(
                'not JSON' if name=='malformed-report' else json.dumps(value))
            if name=='cold-mutated':cold.write_text('{"changed":true}')
            steps.append({'name':step,'passed':name!='nonzero-child'})
            return name!='nonzero-child'
        env={'Path':Path,'json':json,'sha256':sha256,'re':re,'out':directory,'cold':cold,
             'run':run,'JSON_WIRE_CALLER_MODULES':modules,'JSON_WIRE_CALLER_SOURCES':names,
             'JSON_WIRE_AGENT_TOOLS':tools,'sources':sources,'cold_sources':sources,'steps':steps,
             'file_record':lambda p:{'path':str(p),'sha256':sha256(p.read_bytes()).hexdigest()}}
        exec(code,env)
        actual=env['selected_json_wire_callers']()
        expected=name=='normal'
        assert actual['passed'] is expected,(name,actual)
        assert steps[-1]['passed'] is expected
        results.append({'case':name,'expected_pass':expected,'outcome':actual})
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    runner=Path(__file__).with_name('run_hia_qualification_v7.py')
    original=Path(__file__).with_name('run_hia_qualification_v6_original.py')
    raw=runner.read_bytes();old_raw=original.read_bytes()
    assert sha256(old_raw).hexdigest()=='565537d5eb7b5e49662b21e531eed50affb13924d0cdd1584608ffb9f59339eb'
    tree=ast.parse(raw);old=ast.parse(old_raw)
    preserved={}
    for name in ('suite','selected_journal_callers','_pinned_state','file_record'):
        observed=ast.dump(function(tree,name),include_attributes=False)
        expected=ast.dump(function(old,name),include_attributes=False)
        assert observed==expected,name
        preserved[name]=sha256(observed.encode()).hexdigest()
    old_groups=ast.literal_eval(assignment(old,'groups').value)
    groups=ast.literal_eval(assignment(tree,'groups').value)
    assert all(groups.get(k)==v for k,v in old_groups.items())
    extra={'json-wire':['tests.test_hia_json_wire_native'],
           'ordinary-wire-entry':['tests.test_hia_json_wire_entry'],
           'worker-report':['tests.test_hia_worker_report_native'],
           'machine-plan':['tests.test_hia_machine_plan_native'],
           'linked-observer':['tests.test_hia_selfhost_linked_observer']}
    assert {k:v for k,v in groups.items() if k not in old_groups}==extra
    old_dev=ast.literal_eval(assignment(old,'development_selectors').value)
    new_dev=ast.literal_eval(assignment(tree,'development_selectors').value)
    assert new_dev[:len(old_dev)]==old_dev
    assert new_dev[len(old_dev):]==tuple('HEPTA_HIA_'+x+'_DEVELOPMENT_MANIFEST'
                                       for x in ('JSON_WIRE','WORKER_REPORT','MACHINE_PLAN'))
    cold_loop=lambda t:next(n for n in t.body if isinstance(n,ast.For)
        and isinstance(n.iter,ast.Tuple) and any(isinstance(c,ast.Constant) and c.value=='AGENT_STDIO' for c in n.iter.elts))
    previous=ast.literal_eval(cold_loop(old).iter);current=ast.literal_eval(cold_loop(tree).iter)
    assert current==previous+('JSON_WIRE','WORKER_REPORT','MACHINE_PLAN')
    # Cold command and outer workflow timeout remain the exact original AST.
    assert ast.dump(assignment(tree,'cold_completed'),include_attributes=False)==ast.dump(assignment(old,'cold_completed'),include_attributes=False)
    assert ast.literal_eval(assignment(tree,'reproduce_code').value)==ast.literal_eval(assignment(old,'reproduce_code').value)
    helper_hashes={}
    for name,expected in {
        'workflow_process.py':'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80',
        'qualification_prerequisites.py':'352e537de1ca6962d6d8bafa6ac9dea61c83f0d30c5d9c75bce50088fefadead',
        'guardian.py':'d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
        'process_owner_impl.py':'36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    }.items():
        helper_hashes[name]=sha256(runner.with_name(name).read_bytes()).hexdigest()
        assert helper_hashes[name]==expected,name
    modules=ast.literal_eval(assignment(tree,'MACHINE_PLAN_CALLER_MODULES').value)
    loaded=[module+'.Example.test_'+str(n) for module in modules for n in range(11)]
    sources={'hepta/example.py':'1'*64,'tools/example.py':'2'*64,
             'tests/example.py':'3'*64,'examples/hia_bootstrap/machine_plan.hiaasm':'4'*64,
             'README.md':'5'*64}
    snapshot={k:v for k,v in sources.items() if k!='README.md'}
    image_bytes=b'controller fixture, deliberately not executable'
    image_sha=sha256(image_bytes).hexdigest()
    manifest={'schema':'hepta.hia.machine-plan-native.v1','source_sha256':'4'*64,
              'image_path':'machine-plan.image.bin','image_sha256':image_sha,'compiler_sha256':'7'*64}
    normal={'schema':'hepta.hia.machine-plan-selected-callers.v1','status':'PASS',
        'scope':'MATCHING_SOURCE_COLD_SELECTED_CALLERS','loaded_test_ids':loaded,'executed_test_ids':loaded[:],
        'tests_loaded':44,'tests_run':44,'failures':[],'errors':[],'skipped':[],
        'expected_failures':[],'unexpected_successes':[],'retained_plan_owners_forbidden':True,
        'subprocesses_inherit_selector':True,'source_and_manifest_unchanged':True,
        'native_stage_entries':{'1':5,'2':3},'source_before_sha256':snapshot,
        'source_after_sha256':snapshot.copy(),'manifest':manifest,'image_sha256':image_sha,
        'actual_cold_build_retained':True}
    cases=[]
    def case(name, change=None, *, completed=True,cold_change=False,raw_text=None):
        value=deepcopy(normal)
        if change:change(value)
        cases.append((name,value,completed,cold_change,raw_text))
    case('normal')
    for key,value in (
        ('schema','wrong'),('status','FAIL'),('scope','DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'),
        ('loaded_test_ids',[]),('executed_test_ids',loaded[::-1]),('tests_run',43),('tests_loaded',44.0),
        ('retained_plan_owners_forbidden',False),('subprocesses_inherit_selector',False),
        ('source_and_manifest_unchanged',False),('native_stage_entries',{}),
        ('native_stage_entries',{'1':0}),('native_stage_entries',{'1':True}),
        ('source_before_sha256',{}),('source_after_sha256',{}),('image_sha256','8'*64)):
        case(key+'-'+str(len(cases)),lambda row,k=key,v=value:row.__setitem__(k,v))
    for key in ('errors','failures','skipped','expected_failures','unexpected_successes'):
        case(key,lambda row,k=key:row.__setitem__(k,['actual anomaly marker']))
    def duplicate(row):
        row['loaded_test_ids'][1]=row['loaded_test_ids'][0];row['executed_test_ids']=row['loaded_test_ids'][:]
    case('duplicate-IDs',duplicate)
    def foreign(row):
        row['loaded_test_ids'][0]='tests.foreign.Example.test';row['executed_test_ids']=row['loaded_test_ids'][:]
    case('foreign-ID',foreign)
    def missing_module(row):
        row['loaded_test_ids']=[modules[0]+'.Example.test_'+str(i) for i in range(44)]
        row['executed_test_ids']=row['loaded_test_ids'][:]
    case('missing-module',missing_module)
    for key,value in (('schema','wrong'),('source_sha256','8'*64),('image_sha256','8'*64),
                      ('compiler_sha256','8'*64),('image_path','../escape'),('image_path','..')):
        case('manifest-'+key+'-'+str(len(cases)),lambda row,k=key,v=value:row['manifest'].__setitem__(k,v))
    case('nonzero-child',completed=False)
    case('cold-mutated',cold_change=True)
    case('malformed-report',raw_text='not JSON')
    case('nonobject-report',raw_text='[]')
    for fault in ('missing-image','wrong-image','manifest-changed','build-cold-sha',
                  'build-source-sha','retention-flag','evidence-path'):
        case(fault)
    compiled=compile(ast.Module(body=[function(tree,'selected_machine_plan_callers')],type_ignores=[]),str(runner),'exec')
    observations=[]
    for name,value,completed,cold_change,raw_text in cases:
        directory=args.output/name;directory.mkdir()
        cold=directory/'cold.json';cold.write_text(json.dumps({'generation_sha256':['7'*64]*3}))
        steps=[]
        def run(step,command):
            assert step=='machine-plan-selected-callers'
            assert command[:5]==['tools/qualify_hia_machine_plan_native_callers.py','--cold-report',str(cold),'--output',str(directory/'machine-plan-selected-callers.json')]
            evidence=directory/'machine-plan-selected-callers-evidence'
            assert command[5:7]==['--evidence-dir',str(evidence)]
            assert command[7:]==[item for module in modules for item in ('--module',module)]
            assert '--development' not in command and '--manifest' not in command
            build=evidence/'build';build.mkdir(parents=True)
            value['caller_build_evidence_directory']=str(evidence.resolve())
            if name=='retention-flag':value['actual_cold_build_retained']=False
            if name=='evidence-path':value['caller_build_evidence_directory']=str(directory/'unrelated')
            (build/'manifest.json').write_text(json.dumps(manifest if name=='manifest-changed' else value['manifest']))
            if name=='manifest-changed':(build/'manifest.json').write_text('{}')
            (build/'machine-plan.image.bin').write_bytes(image_bytes+b'changed' if name=='wrong-image' else image_bytes)
            if name=='missing-image':(build/'machine-plan.image.bin').unlink()
            build_value={'schema':'hepta.hia.machine-plan-build.v1','status':'NATIVE_CANDIDATE_BUILT',
                'manifest':value['manifest'],'cold_report_sha256':sha256(cold.read_bytes()).hexdigest(),
                'source_manifest':snapshot,'native_compile_receipt':{'status':'returned','abi_status':0,
                    'source_unchanged':True,'produced_sha256':image_sha,'produced_bytes':len(image_bytes),
                    'input_sha256':'4'*64,'artifact_sha256':'7'*64,'forbidden_compiler_modules_loaded':[]}}
            if name=='build-cold-sha':build_value['cold_report_sha256']='8'*64
            if name=='build-source-sha':build_value['source_manifest']={}
            (build/'build.json').write_text(json.dumps(build_value))
            (directory/'machine-plan-selected-callers.json').write_text(raw_text if raw_text is not None else json.dumps(value))
            if cold_change:cold.write_text('{"changed":true}')
            steps.append({'name':step,'passed':completed})
            return completed
        env={'Path':Path,'json':json,'sha256':sha256,'re':re,'out':directory,'cold':cold,'run':run,
             'MACHINE_PLAN_CALLER_MODULES':modules,'source_before':{'files':sources},'sources':sources,
             'cold_sources':snapshot,
             'steps':steps,'file_record':lambda p:{'path':str(p),'sha256':sha256(p.read_bytes()).hexdigest()}}
        exec(compiled,env)
        actual=env['selected_machine_plan_callers']()
        expected=name=='normal'
        assert actual['passed'] is expected,(name,actual)
        assert steps[-1]['passed'] is expected
        observations.append({'case':name,'expected_pass':expected,'outcome':actual})
    # Execute the actual final conjunction and status assignments, then refuse
    # each new missing/failing mandatory result without running product code.
    final_names=('mandatory_gates','all_passed','full_outcome','full_qualified','status')
    final=compile(ast.Module(body=[assignment(tree,n) for n in final_names],type_ignores=[]),str(runner),'exec')
    final_results=[]
    for fault in ('normal','json-wire','ordinary-wire-entry','worker-report','machine-plan','linked-observer','machine-callers','wire-callers'):
        results={n:{'passed':True} for n in ('json-preflight','agent-journal','composite-types','json-wire','ordinary-wire-entry','worker-report','machine-plan','linked-observer','full-retained-regression')}
        if fault in results:results[fault]['passed']=False
        env={'prerequisite_admission':{'status':'CURRENT_SOURCE_PREREQUISITES_ADMITTED_NOT_TEST_PASS'},
             'prerequisites_preserved':True,'suite_outcomes':results,'caller_outcome':{'passed':True},
             'machine_plan_caller_outcome':{'passed':fault!='machine-callers'},'ok':True,
             'json_wire_caller_outcome':{'passed':fault!='wire-callers'},
             'preserved':True,'harness_preserved':True,'a':SimpleNamespace(full=True)}
        exec(final,env)
        assert env['status']==('FULL_RETAINED_PASS' if fault=='normal' else 'HOLD'),fault
        final_results.append({'case':fault,'status':env['status']})
    # Exercise the actual run() adapter with an explicitly injected supervisor;
    # it transports no product code. Each step must have four distinct fresh
    # fixture locations and retain the source-bound cold selector.
    step_root=args.output/'step-environments';step_root.mkdir()
    observed_environments=[]
    def supervisor(command,**options):
        assert options['seconds']==1800
        observed_environments.append(dict(options['env']))
        options['stdout_path'].write_bytes(b'controller transport fixture\n')
        options['stderr_path'].write_bytes(b'')
        result={'status':'WORKFLOW_STEP_COMPLETED','returncode':0,'timed_out':False,
                'cleanup':{'complete':True}}
        options['receipt_path'].write_text(json.dumps(result))
        return result
    env={'Path':Path,'json':json,'sha256':sha256,'sys':sys,'time':time,'out':step_root,'root':step_root,
         'environment':{'HEPTA_HIA_JSON_WIRE_COLD_REPORT':str(step_root/'cold.json')},
         'steps':[],'run_workflow_step':supervisor}
    exec(compile(ast.Module(body=[function(tree,'run')],type_ignores=[]),str(runner),'exec'),env)
    for name in ('step-one','step-two'):
        assert env['run'](name,['-c','pass']) is True
    selected=[]
    for index,observed in enumerate(observed_environments):
        assert observed['HEPTA_HIA_JSON_WIRE_COLD_REPORT']==str(step_root/'cold.json')
        for owner,stem in (('JSON_WIRE','json-wire'),('JSON_WIRE_ENTRY','json-wire-entry'),('WORKER_REPORT','worker-report'),('MACHINE_PLAN','machine-plan')):
            key='HEPTA_HIA_'+owner+'_FIXTURE_EVIDENCE'
            expected=step_root/(('step-one' if index==0 else 'step-two')+'-'+stem+'-fixtures')
            assert observed[key]==str(expected)
            assert env['steps'][index]['new_owner_fixture_evidence'][owner]==str(expected)
            selected.append(str(expected))
    assert len(set(selected))==8
    wire_results=wire_controls(tree,runner,args.output)
    assert runner.read_bytes()==raw and original.read_bytes()==old_raw
    receipt={'schema':'hia.v7-controller-receipt-and-delta-controls.v1','status':'CONTROLLER_CONTROLS_PASS',
        'runner_sha256':sha256(raw).hexdigest(),'original_runner_sha256':sha256(old_raw).hexdigest(),
        'preserved_function_AST_sha256':preserved,'old_groups_preserved':old_groups,
        'added_complete_groups':extra,'unchanged_helpers':helper_hashes,
        'machine_caller_receipt_controls':observations,'final_conjunction_controls':final_results,
        'wire_caller_receipt_controls':wire_results,
        'per_step_fixture_environments':observed_environments,
        'product_or_cold_qualification_claimed':False}
    (args.output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'receipt_controls':len(observations),
                      'wire_receipt_controls':len(wire_results),
                      'final_conjunction_controls':len(final_results),'runner_sha256':receipt['runner_sha256']},sort_keys=True))


if __name__=='__main__':
    main()
