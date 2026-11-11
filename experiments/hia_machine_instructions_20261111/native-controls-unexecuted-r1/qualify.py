"""Run one unchanged 12+51 qualification under the original 180 second owner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from development_common import command, digest, natural_owner, path_bytes, save, snapshot

root=Path(sys.argv[1]).resolve(strict=True)
request=json.loads((root/'request.json').read_bytes())
source=Path(request['candidate_source']).resolve(strict=True)
preparation=Path('/home/qian-qi/he26instructions-native-prepare-r1')
phase=request['phase']
started=time.monotonic()
report={'schema':'hia.machine-instructions-owned-caller-worker.v1','status':'STARTED',
    'scope':'EXPLICIT_DEVELOPMENT_ONLY','phase':phase,'python':sys.version,
    'executable':sys.executable,'product_candidate_commit':request['candidate_commit'],
    'product_candidate_tree':request['candidate_tree'],'matching_current_cold':False,
    'default_or_whole_native_claimed':False,'component_denominator':12,
    'unchanged_original_caller_denominator':51}
before=inputs_before=None
try:
    expected_roots={'state':'/home/qian-qi/he26instructions-state-qualification-r1',
        'instructions':'/home/qian-qi/he26instructions-instruction-qualification-r1'}
    if phase not in expected_roots or str(root)!=expected_roots[phase] or source!=preparation/'source':
        raise ValueError('fixed phase root differs')
    binary=Path(sys.executable).resolve()
    if digest(binary.read_bytes())!=request['python_binary_sha256']:
        raise ValueError('actual Python binary differs')
    prepare_raw=(preparation/'control.json').read_bytes()
    if digest(prepare_raw)!=request['preparation_control_sha256']:
        raise ValueError('actual preparation control differs')
    prepare=json.loads(prepare_raw)
    if (prepare['status']!='PASS' or not natural_owner(prepare['lifecycle'])
        or prepare['lifecycle']['returncode']!=0
        or prepare['inner_status']!='EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED'):
        raise ValueError('actual development preparation was not completed')
    inputs_before=[]
    for row in request['input_bindings']:
        actual,raw=path_bytes(Path(row['path']))
        if actual!=row:
            raise ValueError('development bundle input differs '+row['path'])
        inputs_before.append(actual)
    report['input_bindings_before']=inputs_before
    subprocess.run(['git','diff','--cached','--quiet',request['candidate_tree'],'--'],cwd=source,check=True)
    head=command(['git','rev-parse','HEAD'],source)
    if head!='608157e52b0b94e0d294f6b99c4e809869f183aa':
        raise ValueError('actual materialization HEAD differs')
    report['actual_checkout_HEAD']=head
    report['actual_index_matches_tree']=request['candidate_tree']
    before=snapshot(source)
    if len(before)!=3941:
        raise ValueError('full candidate leaf denominator differs')
    save(root,'candidate-source-before.json',before)
    module='tools.qualify_hia_machine_'+('state' if phase=='state' else 'instructions')+'_callers'
    evidence=root/'evidence'
    argv=[sys.executable,'-B','-m',module,'--development-bundle',str(preparation/'bundle.json'),
        '--evidence',str(evidence)]
    at=time.monotonic()
    result=subprocess.run(argv,cwd=source,capture_output=True)
    (root/'qualifier.stdout').write_bytes(result.stdout)
    (root/'qualifier.stderr').write_bytes(result.stderr)
    report['actual_command']={'argv':argv,'cwd':str(source),'returncode':result.returncode,
        'seconds':time.monotonic()-at,'stdout_sha256':digest(result.stdout),
        'stderr_sha256':digest(result.stderr)}
    path=evidence/'report.json'
    raw=path.read_bytes()
    selected=json.loads(raw)
    report['selected_report']={'path':str(path),'bytes':len(raw),'sha256':digest(raw)}
    expected_groups=[('component',['tests.test_hia_machine_'+phase+'_native'],
        request['component_ids']),('original-callers',request['original_modules'],request['original_ids'])]
    if len(selected['groups'])!=2:
        raise AssertionError('original complete groups did not run')
    for group,(label,modules,ids) in zip(selected['groups'],expected_groups):
        if (group['label']!=label or group['modules']!=modules
            or group['loaded_ids']!=ids or group['executed_ids']!=ids
            or group['tests_run']!=len(ids) or group['strict_pass'] is not True
            or group['loader_errors'] or len(ids)!=len(set(ids))
            or any(group[k] for k in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses'))):
            raise AssertionError('complete fixed original method identity/results differ: '+label)
    if (result.returncode or selected['status']!='PASS'
        or selected['scope']!='EXPLICIT_DEVELOPMENT_ONLY'
        or selected['source_stable'] is not True
        or selected['manifest_images_bundle_stable'] is not True
        or selected['retained_owner_entries']):
        raise AssertionError('component/caller source or owner qualification failed')
    report['groups']=[{k:group[k] for k in ('label','modules','expected_methods',
        'loaded_ids','executed_ids','tests_run','strict_pass','seconds',
        'failures','errors','skipped','expectedFailures','unexpectedSuccesses')}
        for group in selected['groups']]
    report['old_owner_entries']=selected['retained_owner_entries']
    report['native_entries']={k:v for k,v in selected.items() if k.startswith('native_') and k.endswith('_entries')}
    report['status']='EXPLICIT_DEVELOPMENT_12_PLUS_51_PASS'
except BaseException:
    report['status']='HOLD'
    report['exception']=traceback.format_exc()
finally:
    try:
        if before is not None:
            after=snapshot(source)
            save(root,'candidate-source-after.json',after)
            report['full_source_stable']=after==before
            if not report['full_source_stable']:
                report['status']='HOLD'
        if inputs_before is not None:
            inputs_after=[path_bytes(Path(row['path']))[0] for row in request['input_bindings']]
            report['input_bindings_after']=inputs_after
            report['all_original_inputs_stable']=inputs_after==inputs_before
            if not report['all_original_inputs_stable']:
                report['status']='HOLD'
    except BaseException:
        report['status']='HOLD'
        report['final_identity_error']=traceback.format_exc()
    report['seconds']=time.monotonic()-started
    save(root,'report.json',report)
    print(json.dumps({key:report.get(key) for key in ('status','scope','phase','seconds',
        'full_source_stable','all_original_inputs_stable','exception')},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='EXPLICIT_DEVELOPMENT_12_PLUS_51_PASS' else 1)
