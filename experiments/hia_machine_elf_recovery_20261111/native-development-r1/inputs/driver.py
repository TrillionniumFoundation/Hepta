"""Single new reconstructed ELF development attempt under an external owner.

The unchanged original native child limits and each original test budget are
independent of the new controller's 300-second overall ownership deadline.
"""
from __future__ import annotations
from pathlib import Path
import json
import os
import stat
import sys
import time
import traceback
from common import (ROOT,SOURCE,COMPILER,PYTHON,PYTHON_SHA,COMPILER_SHA,GENERATED,
                    checked_config,create,environment,load_exact,natural_guardian,
                    read_json,require,stable_file,wire)

config=checked_config(ROOT/'control'/'config.json')
workflow=load_exact('elf_native_original_workflow',ROOT/'control'/'workflow_process.py',
                   'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80')
env=environment()
fixed=ROOT/'fixed-build'
baseline=ROOT/'baseline-build'
env['HEPTA_HIA_MACHINE_ELF_MANIFEST']=str(fixed/'manifest.json')
report={'schema':'hepta.hia.machine-elf.reconstructed-development.v1',
        'status':'HOLD','scope':'RECONSTRUCTED_COMPONENT_DEVELOPMENT_NOT_FULL_QUALIFICATION',
        'source_authoring_commit':'1b120342aa467ebab91180d102ea338d5b136c2a',
        'key':config['key'],'root':str(ROOT),'source':str(SOURCE),
        'commands':[],'checks':{},'scope_boundaries':{
            'cold_qualification_executed':False,'matching_current_cold':False,
            'whole_native_delivery_qualified':False,'whole_writer_qualified':False,
            'historical_55_51_results_inherited':False,'full_foreign_timsort_schedule_closed':False,
            'installed_wheel_executed':False,'full_64mib_65536_runtime_boundaries_closed':False,
            'private_step_precondition_lifetime_closed':False},
        'budgets':{'external_controller_seconds':300,'compiler_child_wall_seconds':20,
                   'compiler_child_cpu_seconds':10,'reconstructed_55_seconds':20,
                   'original_51_seconds':180,'foreign_phase_controls_seconds':20}}
started=time.monotonic()
inputs_before=None
source_before=None
failure=None
build_pins={}
save_count=0

def save():
    global save_count
    save_count+=1
    path=ROOT/('report-update-'+str(save_count)+'.json')
    create(path,wire(report))
    os.replace(path,ROOT/'report.json')

def observed_inputs():
    return {path:stable_file(path,pin['sha256'],resolve=pin.get('resolve',False),
                           executable=pin.get('executable',False))[0]
            for path,pin in config['readonly_inputs'].items()}

def full_source(name):
    observation,_=read_json(Path(config['source_inventory']['path']),
                            config['source_inventory']['sha256'])
    require(observation['root']==str(SOURCE) and len(observation['files'])==3928,
            'actual authoring source inventory differs')
    expected=observation['files']
    actual=set()
    for current,directories,files in os.walk(SOURCE,followlinks=False):
        if Path(current)==SOURCE:
            require('.git' in directories,'existing complete independent Git source required')
            directories.remove('.git')
        for directory in directories:
            require(stat.S_ISDIR((Path(current)/directory).lstat().st_mode),
                    'source symlink or special directory refused')
        actual.update((Path(current)/item).relative_to(SOURCE).as_posix() for item in files)
    require(actual==set(expected),'complete physical source denominator differs')
    result={}
    for relative,old in sorted(expected.items()):
        info,_=stable_file(SOURCE/relative,old['sha256'])
        mode='100755' if (SOURCE/relative).stat().st_mode & stat.S_IXUSR else '100644'
        info={**info,'mode':mode}
        require(info==old,'source bytes/mode/identity changed from actual authoring: '+relative)
        result[relative]=info
    receipt=create(ROOT/name,wire({'root':str(SOURCE),'files':result}))
    return result,receipt

def build_binding(directory,variant):
    value,record=read_json(directory/'build.json')
    require(value['status']=='NATIVE_DEVELOPMENT_IMAGE_BUILT'
            and value['variant']==variant and value['compiler_sha256']==COMPILER_SHA,
            'actual native build identity differs')
    source_pin=stable_file(directory/'source.hiaasm',value['actual_source']['sha256'])[0]
    image_pin=stable_file(directory/'machine-elf.image.bin',value['image']['sha256'])[0]
    manifest,manifest_pin=read_json(directory/'manifest.json',value['manifest_file']['sha256'])
    receipt=value['native_compile_receipt']
    require(manifest==value['manifest'] and manifest['source_sha256']==source_pin['sha256']
            and manifest['image_sha256']==image_pin['sha256']
            and receipt['input_sha256']==source_pin['sha256']
            and receipt['produced_sha256']==image_pin['sha256']
            and receipt['artifact_sha256']==COMPILER_SHA,
            'actual B3/source/image/manifest binding differs')
    return {'record':record,'source':source_pin,'image':image_pin,'manifest':manifest_pin}

def step(label,script,arguments,seconds):
    record=workflow.run_workflow_step(
        [str(PYTHON),'-B',str(ROOT/'control'/script),*map(str,arguments)],
        cwd=SOURCE,env=env,stdout_path=ROOT/(label+'.stdout'),
        stderr_path=ROOT/(label+'.stderr'),receipt_path=ROOT/(label+'.process.json'),
        seconds=seconds)
    report['commands'].append(record)
    save()
    require(record['status']=='WORKFLOW_STEP_COMPLETED' and record['returncode']==0
            and record['timed_out'] is False and record['cleanup']['complete'] is True
            and record['cleanup']['signalled']==[] and record['cleanup']['errors']==[],
            label+' did not complete naturally')

try:
    require(sys.version_info[:3]==(3,14,4),'exact Python version differs')
    inputs_before=observed_inputs()
    report['readonly_inputs_before']=inputs_before
    previous,_=read_json('/home/qian-qi/he26elfrecoverr1/report.json',
        'f23e363b9ee9eb0be46edff9e46668bf26e079a1e816b84dccb5e46176646aa4')
    guard,_=read_json('/home/qian-qi/he26elfrecoverr1/guard/guardian.json',
        '1bd56484a7d79e3649b8da6f6ea4bf9a35c15ae41b34ca7da8ff30af73281ee1')
    require(previous['status']=='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
            and all(previous['check_results'].values()) and natural_guardian(guard),
            'actual source authoring admission failed')
    source_before,source_pin=full_source('source-before.json')
    report['source_before']=source_pin
    for relative,pin in config['product_sources'].items():
        stable_file(SOURCE/relative,pin['sha256'])
    step('build-fixed','compile.py',['--compiler',COMPILER,'--output',fixed],40)
    value,_=read_json(fixed/'build.json')
    require(value['status']=='NATIVE_DEVELOPMENT_IMAGE_BUILT'
            and value['variant']=='filter_key_fixed','fixed compile report refused')
    build_pins['fixed']=build_binding(fixed,'filter_key_fixed')
    report['development_builds_before']=dict(build_pins)
    report['checks']['fixed_actual_native_compile']=True
    step('reconstructed-55','controls55.py',[
        '--manifest',fixed/'manifest.json','--inputs',ROOT/'control'/'cases55.json',
        '--oracle',ROOT/'control'/'oracle.py.txt','--report',ROOT/'reconstructed-55.json'],20)
    value,_=read_json(ROOT/'reconstructed-55.json')
    require(value['status']=='PASS' and value['loaded']==55 and value['executed']==55
            and value['loaded_case_ids']==value['executed_case_ids']
            and value['retained_owner_calls']==[],'new 55 result conjunction failed')
    report['checks']['reconstructed_new_55']=True
    step('original-51','original51.py',[
        '--manifest',fixed/'manifest.json','--inventory',ROOT/'control'/'original51.json',
        '--oracle',ROOT/'control'/'oracle.py.txt','--output',ROOT/'original-51'],180)
    value,_=read_json(ROOT/'original-51'/'report.json')
    require(value['status']=='PASS' and value['tests_loaded']==51 and value['tests_run']==51
            and value['loaded_test_ids']==value['executed_test_ids']
            and all(x==0 for x in value['anomaly_counts'].values())
            and value['retained_owner_calls']==[]
            and value['complete_return_object']['pass'] is True
            and value['fresh_selected_child']['returncode']==0,
            'actual original 51 and metadata conjunction failed')
    report['checks']['original_51_and_full_metadata']=True
    step('build-baseline','compile.py',[
        '--compiler',COMPILER,'--output',baseline,
        '--generator',ROOT/'control'/'generator-before.py.txt',
        '--generator-sha256','8bcda88d89db86c43d970e052e77cfcf5a98ef1b063356f6aad9c75b490ec87e'],40)
    value,_=read_json(baseline/'build.json')
    require(value['status']=='NATIVE_DEVELOPMENT_IMAGE_BUILT'
            and value['variant']=='before_filter_key_fix','baseline actual compile failed')
    build_pins['baseline']=build_binding(baseline,'before_filter_key_fix')
    report['development_builds_before']=dict(build_pins)
    report['checks']['baseline_actual_native_compile']=True
    step('foreign-phase','foreign_phase.py',[
        '--manifest',fixed/'manifest.json','--baseline-build',baseline,
        '--oracle',ROOT/'control'/'oracle.py.txt','--report',ROOT/'foreign-phase.json'],20)
    value,_=read_json(ROOT/'foreign-phase.json')
    require(value['status']=='PASS' and value['loaded']==4 and value['executed']==4
            and value['loaded_case_ids']==value['executed_case_ids']
            and all(row['pass'] for row in value['cases']),
            'actual before/after foreign phase conjunction failed')
    report['checks']['four_original_counterexamples_and_fixed_observations']=True
    report['status']='COMPONENT_DEVELOPMENT_PASS_PENDING_EXTERNAL_GUARDIAN'
except BaseException as exc:
    failure=exc
    report['failure']={'type':type(exc).__name__,'text':str(exc),'traceback':traceback.format_exc()}
finally:
    try:
        if build_pins:
            actual={}
            for label in build_pins:
                directory=fixed if label=='fixed' else baseline
                variant='filter_key_fixed' if label=='fixed' else 'before_filter_key_fix'
                actual[label]=build_binding(directory,variant)
            report['development_builds_after']=actual
            require(actual==build_pins,'created native build artifacts changed')
            report['development_builds_stable']=True
        if inputs_before is not None:
            after=observed_inputs()
            report['readonly_inputs_after']=after
            require(inputs_before==after,'readonly inputs changed')
        if source_before is not None:
            after,pin=full_source('source-after.json')
            report['source_after']=pin
            require(source_before==after,'full actual source changed')
            report['source_stable']=True
    except BaseException as exc:
        report['final_source_failure']={'type':type(exc).__name__,'text':str(exc),
                                        'traceback':traceback.format_exc()}
        report['status']='HOLD'
        if failure is None:
            failure=exc
    report['seconds']=time.monotonic()-started
    if failure is not None:
        report['status']='HOLD'
    save()
    print(json.dumps({'stage':'reconstructed_elf_development','status':report['status'],
                      'checks':report['checks'],'seconds':report['seconds']}),flush=True)
if failure is not None:
    raise failure
