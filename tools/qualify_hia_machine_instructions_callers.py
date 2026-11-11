"""Exercise all 41 HIA instruction controls and unchanged original 51 callers."""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from tools.qualify_hia_machine_state_callers import (
    ORIGINAL_MODULES,flatten,strict_pass,source_pins,copy_manifest,
    _require,cold_accounting_context,capture_native_group,record_native_return,finish_native_accounting)
COMPONENT_MODULES=('tests.test_hia_machine_instructions_native',)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report',type=Path)
    selection.add_argument('--development-bundle',type=Path)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    directory=args.evidence.resolve()
    directory.mkdir(parents=True,exist_ok=False)
    from hepta import hia_machine_x64 as reference
    from hepta.hia_machine_encoding_native import (
        SELECTOR as ENCODING_SELECTOR,COMMANDS,NativeEncodedCode,NativeMachineEncoding,
        installed_machine_encoding)
    from hepta.hia_machine_state_native import (
        SELECTOR as STATE_SELECTOR,MODES as STATE_MODES,NativeMachineState,installed_machine_state)
    from hepta.hia_machine_instructions_native import (
        SELECTOR,MODES,NativeMachineInstructions,installed_machine_instructions)
    before=source_pins()
    report={'schema':'hepta.hia.machine-instructions-selected-callers.v1','status':'STARTED',
        'scope':'MATCHING_SOURCE_COLD_SELECTED_CALLERS' if args.cold_report else 'EXPLICIT_DEVELOPMENT_ONLY',
        'source_before':before,'groups':[],'retained_owner_entries':[],
        'default_or_whole_stack_claimed':False,'python':sys.version,
        'guarded_original_caller_denominator':51,'component_denominator':12,
        'all_original_methods_unchanged':True}
    started=time.monotonic()
    instruction_entries,state_entries,encoding_entries,per_test=Counter(),Counter(),Counter(),Counter()
    active_test=['outside-test']
    active_group=['outside-group']
    group_bindings,normal_returns,image_identity_changes={},{},[]
    cold_context=None
    original_run,original_state,original_encode=(
        NativeMachineInstructions.run,NativeMachineState.run,NativeMachineEncoding.encode)
    def tracked_run(owner,receiver,mode,*arguments):
        image_before=getattr(owner,'image_sha256',None)
        if hasattr(owner,'image_sha256'):
            instruction_entries[MODES[mode-1]]+=1
            per_test[active_test[0]]+=1
        value=original_run(owner,receiver,mode,*arguments)
        record_native_return(normal_returns,image_identity_changes,active_group[0],
            'instructions',owner,image_before,MODES[mode-1])
        return value
    def tracked_state(owner,receiver,mode,*arguments):
        image_before=getattr(owner,'image_sha256',None)
        if hasattr(owner,'image_sha256'):
            state_entries[STATE_MODES[mode-1]]+=1
        value=original_state(owner,receiver,mode,*arguments)
        record_native_return(normal_returns,image_identity_changes,active_group[0],
            'state',owner,image_before,STATE_MODES[mode-1])
        return value
    def tracked_encode(owner,command,**values):
        image_before=getattr(owner,'image_sha256',None)
        if hasattr(owner,'image_sha256'):encoding_entries[command]+=1
        value=original_encode(owner,command,**values)
        record_native_return(normal_returns,image_identity_changes,active_group[0],
            'encoding',owner,image_before,command)
        return value
    def forbidden(name):
        def fail(*arguments,**keywords):
            report['retained_owner_entries'].append(name)
            raise AssertionError('retained instruction owner entered: '+name)
        return fail
    inputs=[]
    try:
        cold_context=cold_accounting_context(args.cold_report)
        if args.cold_report:
            from tools.build_hia_machine_instructions import build
            from tools.build_hia_machine_state import build as build_state
            from tools.build_hia_machine_encoding import build as build_encoding
            outer=json.loads(args.cold_report.read_bytes())
            nested=json.loads(Path(outer['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            manifest=build(directory/'instructions',compiler,args.cold_report)
            state_manifest=build_state(directory/'state',compiler,args.cold_report)
            encoding_manifest=build_encoding(directory/'encoding',compiler,args.cold_report)
        else:
            raw=args.development_bundle.read_bytes()
            bundle=json.loads(raw)
            manifest=copy_manifest(Path(bundle['instructions_manifest']).resolve(strict=True),directory/'instructions')
            state_manifest=copy_manifest(Path(bundle['state_manifest']).resolve(strict=True),directory/'state')
            encoding_manifest=copy_manifest(Path(bundle['encoding_manifest']).resolve(strict=True),directory/'encoding')
            (directory/'original-development-bundle.json').write_bytes(raw)
            report['original_development_bundle_sha256']=sha256(raw).hexdigest()
        native=installed_machine_instructions(str(manifest))
        state=installed_machine_state(str(state_manifest))
        encoding=installed_machine_encoding(str(encoding_manifest))
        for path in (manifest,state_manifest,encoding_manifest):
            raw=path.read_bytes();value=json.loads(raw)
            image=path.parent/value['image_path']
            inputs.extend([(path,raw),(image,image.read_bytes())])
        bundle=directory/'bundle.json'
        bundle.write_text(json.dumps({'instructions_manifest':str(manifest),
            'state_manifest':str(state_manifest),'encoding_manifest':str(encoding_manifest)},
            sort_keys=True,indent=2)+'\n')
        inputs.append((bundle,bundle.read_bytes()))
        report.update(instructions_manifest=str(manifest),state_manifest=str(state_manifest),
            encoding_manifest=str(encoding_manifest),instructions_image_sha256=native.image_sha256,
            state_image_sha256=state.image_sha256,encoding_image_sha256=encoding.image_sha256,
            input_bindings=[{'path':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for path,raw in inputs])
        with patch.object(NativeMachineInstructions,'run',tracked_run),patch.object(NativeMachineState,'run',tracked_state),patch.object(NativeMachineEncoding,'encode',tracked_encode):
            for label,modules,expected_count,guard in (
                ('component',COMPONENT_MODULES,12,False),
                ('original-callers',ORIGINAL_MODULES,51,True)):
                active_group[0]=label
                loader=unittest.TestLoader()
                suite=loader.loadTestsFromNames(modules)
                loaded=[test.id() for test in flatten(suite)]
                executed=[]
                class Result(unittest.TextTestResult):
                    def startTest(self,test):
                        active_test[0]=test.id();executed.append(test.id());super().startTest(test)
                row={'label':label,'modules':list(modules),'expected_methods':expected_count,
                    'loaded_ids':loaded,'loader_errors':list(loader.errors)}
                report['groups'].append(row)
                if loader.errors or len(loaded)!=expected_count or len(set(loaded))!=len(loaded):
                    raise AssertionError('complete unchanged method denominator did not load')
                with ExitStack() as guards:
                    if guard:
                        capture_native_group(group_bindings,label,{'instructions':manifest,
                            'state':state_manifest,'encoding':encoding_manifest},cold_context,before)
                        guards.enter_context(patch.dict(os.environ,{
                            SELECTOR:str(manifest),STATE_SELECTOR:str(state_manifest),
                            ENCODING_SELECTOR:str(encoding_manifest)}))
                        for name,member in reference.Code.__dict__.items():
                            if inspect.isfunction(member) and name!='__new__':
                                guards.enter_context(patch.object(reference.Code,name,forbidden('Code.'+name)))
                        guards.enter_context(patch.object(reference.Code,'offset',property(forbidden('Code.offset'))))
                        for name in ('_reg','_condition','_disp32'):
                            if hasattr(reference,name):
                                guards.enter_context(patch.object(reference,name,forbidden(name)))
                        for name,member in NativeEncodedCode.__dict__.items():
                            if inspect.isfunction(member) and name!='_bytes':
                                guards.enter_context(patch.object(NativeEncodedCode,name,forbidden('NativeEncodedCode.'+name)))
                    else:
                        guards.enter_context(patch.dict(os.environ,{
                            SELECTOR:'',STATE_SELECTOR:'',ENCODING_SELECTOR:'',
                            'HEPTA_HIA_MACHINE_INSTRUCTIONS_COLD_REPORT':str(args.cold_report.resolve()) if args.cold_report else '',
                            'HEPTA_HIA_MACHINE_INSTRUCTIONS_DEVELOPMENT_BUNDLE':'' if args.cold_report else str(bundle),
                            'HEPTA_HIA_MACHINE_INSTRUCTIONS_FIXTURE_EVIDENCE':str(directory/'component-fixture')}))
                        component=sys.modules[COMPONENT_MODULES[0]].MachineInstructionsNativeTests
                        original_setup=component.setUpClass
                        def setup(cls):
                            original_setup()
                            _require(cls.scope==('MATCHING_SOURCE_COLD_BUILD' if args.cold_report
                                                else 'EXPLICIT_DEVELOPMENT_ONLY'),
                                     'native instruction component selected the wrong scope')
                            capture_native_group(group_bindings,label,{'instructions':cls.manifest,
                                'state':cls.state_manifest,'encoding':cls.encoding_manifest},cold_context,before)
                        guards.enter_context(patch.object(component,'setUpClass',classmethod(setup)))
                    at=time.monotonic()
                    with (directory/(label+'.unittest.log')).open('x') as stream:
                        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
                    row['seconds']=time.monotonic()-at
                row['executed_ids'],row['tests_run']=executed,result.testsRun
                for key in ('failures','errors','skipped','expectedFailures'):
                    row[key]=[[test.id(),detail] for test,detail in getattr(result,key)]
                row['unexpectedSuccesses']=[test.id() for test in result.unexpectedSuccesses]
                row['strict_pass']=strict_pass(result,loaded,executed)
                if not row['strict_pass']:raise AssertionError('selected caller group failed: '+label)
        if (report['retained_owner_entries'] or set(instruction_entries)!=set(MODES)
            or set(state_entries)!=set(STATE_MODES) or set(encoding_entries)!=set(COMMANDS)):
            raise AssertionError('complete 41 instruction, 6 state and 37 byte ownership was not observed')
        report['status']='PASS'
    except BaseException:
        report['status']='FAIL';report['exception']=traceback.format_exc()
    report['native_instruction_control_entries']=dict(instruction_entries)
    report['native_state_entries']=dict(state_entries)
    report['native_byte_command_entries']=dict(encoding_entries)
    report['per_test_native_instruction_entries']=dict(per_test)
    finish_native_accounting(report,group_bindings,normal_returns,image_identity_changes,
        {'instructions':MODES,'state':STATE_MODES,'encoding':COMMANDS},cold_context,
        args.cold_report,before,inputs)
    report['seconds']=time.monotonic()-started
    (directory/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('schema','scope','status','source_stable','manifest_images_bundle_stable','seconds')}|
        {'groups':[{'label':row['label'],'tests_run':row.get('tests_run'),'strict_pass':row.get('strict_pass')} for row in report['groups']],
        'exception':report.get('exception')}))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
