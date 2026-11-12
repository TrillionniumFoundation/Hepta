"""Independent readback of retained bytes from the one actual Core r3 run.

Does not import product/controller code, execute a compiler, or reconstruct remote
filesystem observations. Original remote identity arrays are compared as integers;
their bytes are joined to the fully CRC/hash-checked downloaded artifact.
"""
from pathlib import Path, PurePosixPath
from collections import Counter
import hashlib, json, zipfile, time

HERE = Path(__file__).resolve().parent
ARCH = Path('/tmp/hia-core116-r3-artifact-43175231100')
MEMBERS = ARCH / 'members'
PREFIX = 'hia-core-emitter-native-development-r3'
ROOT = MEMBERS / PREFIX
CONTROL = Path('/workspace/scratch/e26ed3e2edcf/core/native116-metadata-r3')
checks = []
def require(value, label):
    if not value:
        raise AssertionError(label)
    checks.append(label)
def raw(relative):
    return (ROOT / relative).read_bytes()
def doc(relative):
    return json.loads(raw(relative))
def sha(data):
    return hashlib.sha256(data).hexdigest()
def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
def pin(data):
    return {'bytes':len(data), 'sha256':sha(data), 'git_blob_sha1':blob(data)}
def git_tree(rows):
    top={}
    for row in rows:
        node=top
        parts=row['path'].split('/')
        for part in parts[:-1]:
            node=node.setdefault(part,{})
        assert parts[-1] not in node
        node[parts[-1]]=row
    def digest(node):
        entries=[]
        for name,value in node.items():
            if 'path' in value:
                mode=value['mode']; identity=value['git_blob_sha1']; sortname=name
            else:
                mode='40000'; identity=digest(value); sortname=name+'/'
            entries.append((sortname.encode(), mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(identity)))
        data=b''.join(value for _,value in sorted(entries))
        return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
    return digest(top)

started=time.monotonic()
policy=json.loads((CONTROL/'policy.json').read_bytes())
context=doc('context.json')
remote_root=context['root']
source_root=context['source']
require(context['run_id']==43175231100 and context['run_attempt']==1, 'exact actual operation')
require(context['workflow_commit']=='6c0cf12e0c59a75cf4c1df84287a23840e38548f'
        and context['actual_control_commit']=='4b17b155ecd72c27e8300ffd778b837ce491cfdb', 'exact A/B controls')
require(context['candidate']==policy['candidate']=={'commit':'946f3fd08b63846305d3cbf920b61ceed1e696f0',
        'tree':'f3e2b8e3b638c830d2c8d4977e0972af32fee5bc','leaves':4030}, 'exact pure development candidate')
require(sha((CONTROL/'policy.json').read_bytes())==context['policy_sha256'], 'original frozen policy hash')
provider=json.loads((HERE/'provider-run-terminal.json').read_bytes())
require(provider['id']==43175231100 and provider['head_sha']==context['workflow_commit']
        and provider['event']=='create' and provider['run_attempt']==1 and provider['conclusion']=='success', 'provider terminal exact success')

initial=doc('initial-source.json')
derived=doc('preparation/derived-source.json')
source_after=doc('preparation/source-after.json')
complete_after=doc('complete-source-after.json')
remote_rows={r['path']:r for r in derived['rows']}
tree=json.loads((HERE/'candidate-tree.json').read_bytes())
git_rows={r['path']:r for r in tree['tree'] if r['type']=='blob'}
require(tree['truncated'] is False and tree['sha']==policy['candidate']['tree'] and len(git_rows)==4030, 'actual canonical full leaf tree')
require(len(initial['rows'])==len(derived['rows'])==4030 and len(remote_rows)==4030, 'full source denominator')
require(all(git_rows[r['path']]['sha']==r['git_blob_sha1'] and git_rows[r['path']]['mode']==r['mode']
        and git_rows[r['path']]['size']==r['bytes'] for r in initial['rows']), 'all initial leaves join canonical path mode size Git blob')
require(git_tree(initial['rows'])==initial['actual_worktree_tree']==policy['candidate']['tree'], 'initial full tree recomputed')
require(git_tree(derived['rows'])==derived['actual_worktree_tree']=='985446a932b63bb7f7a6384793c5ee82d7183a6e', 'actual derived full tree recomputed')
require(initial['metadata']==derived['metadata'] and initial['metadata']['actual_head']==policy['candidate']['commit']
        and initial['metadata']['actual_index_tree']==policy['candidate']['tree'], 'real HEAD/index remain original candidate')
require(initial['physical']==derived['physical'] and initial['physical']['file_count']==4030
        and initial['physical']['files']==sorted(git_rows)
        and initial['physical']['excluded_only']==['.git']
        and initial['physical']['ignored_and_untracked_extras_rejected'] is True, 'full original physical source inventory recorded')
require(derived==source_after==complete_after, 'derived source equals all actual later snapshots')
changes=[{'path':old['path'],'before':old,'after':new}
         for old,new in zip(initial['rows'],derived['rows']) if old!=new]
require([x['path'] for x in changes]==['docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'], 'only two authorized generated JSON changes')
prep=doc('preparation/report.json')
acceptance=doc('PREPARATION-ACCEPTANCE.json')
final=doc('FINAL.json')
callers=doc('callers/report.json')
require(prep['derived_source_delta']==changes and prep['derived_worktree_tree']==derived['actual_worktree_tree'], 'actual derivation receipt matches exact changes')
require(doc('preparation/source-before.json')==initial, 'preparation before equals initial')
for change in changes:
    name=PurePosixPath(change['path']).name
    body=raw('preparation/derived/'+name)
    require(pin(body)=={k:change['after'][k] for k in pin(body)}
            and body==raw('preparation/final-'+name), 'derived raw retained '+name)
require(all(x['returncode']==0 for x in prep['derived_commands']) and len(prep['derived_commands'])==3, 'actual derivation three commands succeeded')

checked_pins=set()
def evidence_path(path):
    if path.startswith(remote_root+'/'):
        return ROOT/path[len(remote_root)+1:]
    return None
def check_pin(record):
    path=record['path']; target=evidence_path(path)
    if target is None:
        require(path.startswith(source_root+'/'), 'unmapped retained original is source')
        row=remote_rows[path[len(source_root)+1:]]
        require(all(record[k]==row[k] for k in ('bytes','sha256','git_blob_sha1')), 'source original matches derived leaf '+path)
        return None
    body=target.read_bytes()
    require(pin(body)=={k:record[k] for k in pin(body)}, 'actual artifact bytes join retained pin '+path)
    checked_pins.add(path)
    if 'identity' in record:
        identity=record['identity']
        require(len(identity)==9 and all(type(x) is int for x in identity) and identity[6]==len(body)
                and (identity[2]&0o7777)==record['posix_mode'], 'lossless remote identity metadata '+path)
    return body

owners={}
for phase in ['preparation','tests']:
    setup=doc(phase+'-setup.json')
    guard=doc(phase+'-guard/guardian.json')
    request=doc(phase+'-guard/request.json')
    require(guard['command']==setup['command']==request['command'] and guard['cwd']==setup['cwd']==remote_root, phase+' exact command/cwd')
    require(guard['external_controller_seconds']==setup['controller_seconds']==request['controller_seconds']==180
            and setup['cleanup_seconds']==3, phase+' original 180/3')
    require(sha(raw(phase+'-guard/request.json'))==setup['guardian_config_sha256'], phase+' exact request hash')
    require(guard['source_identities_before']==guard['source_identities_after']==setup['source_identities']
            and guard['input_identity_preserved'] is True, phase+' complete remote input identities stable')
    require(guard['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED' and guard['qualification'] is None
            and guard['cold_180_second_gate_modified'] is False, phase+' guardian natural success')
    life=guard['lifecycle']; cleanup=life['cleanup']
    require(life['qualification_seconds']==180 and life['cleanup_seconds']==3
            and life['status']=='OWNED_PROCESS_COMPLETED' and life['returncode']==0
            and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
            and life['event_overflow'] is False and life['interrupted_signals']==[]
            and life.get('owner_error') is None, phase+' lifecycle success without timeout or error')
    require(cleanup['complete'] is True and cleanup['leader_reaped'] is True
            and cleanup['observed_echild'] is True and cleanup['deadline_exceeded'] is False
            and cleanup['errors']==[] and cleanup['remaining_direct_children']==[], phase+' kernel cleanup ECHILD')
    require([e['kind'] for e in life['events']]==['qualification_started','owned_child_observed',
            'qualification_exit_observed','owned_child_reaped'], phase+' four natural events and no kill')
    for name in ['child.stdout.log','child.stderr.log']:
        path=remote_root+'/'+phase+'-guard/'+name
        require(guard['logs'][path]==sha(raw(phase+'-guard/'+name)), phase+' actual original log '+name)
    for path,digest in setup['additional_original_bindings'].items():
        require(evidence_path(path) is not None and sha(evidence_path(path).read_bytes())==digest, phase+' actual additional binding '+path)
    owners[phase]={'owner_seconds':(life['events'][2]['monotonic_ns']-life['events'][0]['monotonic_ns'])/1e9,
                   'input_count':len(setup['source_identities']),'additional_original_count':len(setup['additional_original_bindings']),
                   'guardian_original':pin(raw(phase+'-guard/guardian.json')),'cleanup':cleanup}

require(prep['status']=='DEVELOPMENT_B0_B1_B2_39_BUILT' and prep['compile_child_wall_seconds']==20
        and prep['compile_child_CPU_seconds']==10 and prep['original_compile_capacity_bytes']==1048576, 'unchanged bootstrap and unit compile limits')
require(all(prep[name] is False for name in ['generated_HIA_sources_recreated','cold_qualified','old_compiler_image_reused',
        'B3_or_mutation_qualified','complete_116_tests_executed','whole_native_claimed','original_limits_changed',
        'production_activated','desktop_interpreter_identity_claimed','derived_tree_has_published_commit']), 'preparation scope remains development')
require(doc('preparation/bootstrap/B0.receipt.json')==prep['B0'] and prep['B0']['seed_only'] is True, 'actual B0 original receipt')
for value in prep['B0_originals'].values():
    check_pin(value)
require(raw('preparation/bootstrap/B1.image.bin')==raw('preparation/bootstrap/B2.image.bin')
        and prep['B1_equals_B2'] is True, 'new B1 equals new B2 actual bytes')
compiler_sha=sha(raw('preparation/bootstrap/B2.image.bin'))
require(compiler_sha=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8', 'actual new compiler SHA recorded')
names=policy['unit_names']
require(len(names)==39 and names[0]=='core_lowering_pool'
        and [x['name'] for x in prep['unit_receipts']]==names, 'all 39 actual native units in original order')
records=prep['compile_originals']
require([x['stage'] for x in records]==['B1','B2',*names], 'all 41 compile original groups')
suffixes=['.receipt.json','.stdout.log','.stderr.log','.request.json','.input.bin','.output.bin']
extension={'case','input_sha256','input_bytes','artifact_sha256','format','runner_sha256','wall_elapsed_ns','produced_image','produced_bytes','produced_sha256'}
limits={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,'stack_bytes':8<<20,'output_capacity':1048576,'workspace_bytes':1048576}
unit_by_name={x['name']:x for x in prep['unit_receipts']}
compile_rows=[]
for index,record in enumerate(records):
    label=record['stage']; files=record['files']
    require(len(files)==6 and all(x['path'].endswith(label+suffix) for x,suffix in zip(files,suffixes)), 'six fixed compile originals '+label)
    bodies={suffix:check_pin(value) for suffix,value in zip(suffixes,files)}
    receipt=json.loads(bodies['.receipt.json'])
    expected=prep[label] if index<2 else unit_by_name[label]['native_compile_receipt']
    require(receipt==expected and json.loads(bodies['.stdout.log'])=={k:v for k,v in receipt.items() if k not in extension}, 'receipt equals actual child stdout plus producer fields '+label)
    require(receipt['status']=='returned' and receipt['abi_status']==0 and receipt['source_unchanged'] is True
            and receipt['forbidden_compiler_modules_loaded']==[] and receipt['limits']==limits
            and receipt['runner_sha256']==remote_rows['tools/hia_selfhost_child.py']['sha256']
            and receipt['wall_elapsed_ns']<=20*10**9, 'actual child status and fixed limits '+label)
    require(sha(bodies['.input.bin'])==receipt['input_sha256']==receipt['source_sha256']
            and len(bodies['.input.bin'])==receipt['input_bytes']
            and len(bodies['.output.bin'])==1048576
            and sha(bodies['.output.bin'])==receipt['output_sha256'], 'actual input/output '+label)
    image=evidence_path(receipt['produced_image']).read_bytes()
    require(len(image)==receipt['core_u32']==receipt['produced_bytes'] and sha(image)==receipt['produced_sha256']
            and image==bodies['.output.bin'][:len(image)], 'actual image equals returned prefix '+label)
    request=json.loads(bodies['.request.json'])
    require(request['capacity']==request['workspace_size']==1048576 and request['workspace_fill']==0
            and request['format']==receipt['format'] and request['source']==files[4]['path']
            and request['output']==files[5]['path'] and request['source_sha256']==sha(bodies['.input.bin'])
            and request['image_sha256']==receipt['artifact_sha256']==sha(evidence_path(request['image']).read_bytes()), 'exact compile request artifact and input '+label)
    if index>=2:
        wanted=policy['original_generated_assets']['sources']['examples/hia_bootstrap/'+label+'.hiaasm']
        require(pin(bodies['.input.bin'])=={k:wanted[k] for k in pin(bodies['.input.bin'])}
                and request['image_sha256']==compiler_sha, 'actual original generated source admitted '+label)
    compile_rows.append({'stage':label,'image':pin(image),'wall_elapsed_ns':receipt['wall_elapsed_ns']})

def check_bundle(relative):
    manifest=doc(relative+'/manifest.json')
    require(manifest=={'schema':'hepta.hia.core-lowering-native.v2','abi_sha256':policy['original_generated_assets']['abi_sha256'],
        'compiler_sha256':compiler_sha,'unit_manifests':{n:n+'/manifest.json' for n in names}}, 'exact bundle '+relative)
    images=[];sources={};bindings=[{'path':remote_root+'/'+relative+'/manifest.json','bytes':len(raw(relative+'/manifest.json')),'sha256':sha(raw(relative+'/manifest.json'))}]
    for n in manifest['unit_manifests']:
        unit=doc(relative+'/'+n+'/manifest.json')
        require(set(unit)=={'schema','source_sha256','image_path','image_sha256','compiler_sha256'}
                and unit['schema']=='hepta.hia.core-lowering-unit-native.v2'
                and unit['compiler_sha256']==compiler_sha and PurePosixPath(unit['image_path']).name==unit['image_path'], 'unit schema '+relative+'/'+n)
        source='examples/hia_bootstrap/'+n+'.hiaasm'
        image=raw(relative+'/'+n+'/'+unit['image_path'])
        require(unit['source_sha256']==policy['original_generated_assets']['sources'][source]['sha256']
                and sha(image)==unit['image_sha256'] and 0<len(image)<=1048576, 'unit actual source/image '+relative+'/'+n)
        sources[n]=unit['source_sha256']
        for suffix in ['manifest.json',unit['image_path']]:
            path=relative+'/'+n+'/'+suffix;body=raw(path)
            bindings.append({'path':remote_root+'/'+path,'bytes':len(body),'sha256':sha(body)})
    images=[doc(relative+'/'+n+'/manifest.json')['image_sha256'] for n in names]
    return manifest,images,sources,bindings
_,prepared_images,_,_=check_bundle('preparation/bundle')
manifest,images,sources,bindings=check_bundle('callers/build')
require(images==prepared_images and len(bindings)==79, 'actual caller bundle equals all prepared 39 images')
build=doc('preparation/bundle/build.json')
require(build['units']==prep['unit_receipts'] and build['source_manifest']==prep['development_source_manifest']
        and build['actual_unit_count']==build['expected_unit_count']==39 and build['cold_qualified'] is False, 'actual build receipt joins preparation')
require(all(remote_rows[name]['sha256']==digest for name,digest in build['source_manifest'].items()), 'full 794 source manifest joins derived canonical rows')
require(acceptance['actual_preparation']['report']==prep and acceptance['actual_preparation']['compile_originals']==records, 'acceptance retains all preparation and compile originals')
for record in prep['build_files']:
    check_pin(record)
require(len(prep['build_files'])==80, 'all 80 build originals')

require(callers['schema']=='hepta.hia.core-lowering-selected-callers.v2' and callers['status']=='PASS'
        and callers['scope']=='EXPLICIT_DEVELOPMENT_ONLY' and callers['development_group'] is None
        and callers['complete_three_groups_executed'] is True and callers['complete_three_groups_required_for_qualification'] is True
        and callers['retained_owner_entries']==[] and callers['hosted_primitive_kinds']==19
        and callers['public_control_mode_count']==33 and callers['abi_control_mode_count']==36, 'actual default complete116 and honest hosted scope')
require(callers['source_before']==callers['source_after']==build['source_manifest'], 'caller source before/after full794 binding')
all_ids=[];groups=[]
for group in callers['groups']:
    expected=policy['test_groups'][group['label']]
    require(group['loaded_ids']==group['executed_ids']==group['frozen_original_ids']==expected['ids']
            and group['tests_run']==group['expected_methods']==expected['count']
            and group['modules']==expected['modules'] and group['strict_pass'] is True, 'exact group IDs '+group['label'])
    require(all(group[k]==[] for k in ['errors','failures','skipped','expectedFailures','unexpectedSuccesses','loader_errors']), 'all group anomalies zero '+group['label'])
    all_ids.extend(group['executed_ids']); groups.append({'label':group['label'],'count':group['tests_run'],'seconds':group['seconds'],
                                                       'unittest_log':pin(raw('callers/'+group['label']+'.unittest.log'))})
require(len(all_ids)==len(set(all_ids))==116 and [g['count'] for g in groups]==[15,51,50], 'complete unique116 once in original order')
require(callers['input_bindings']==bindings and callers['complete_image_sha256']==images, 'report complete actual input bindings')
for role in ['caller','component']:
    observed=callers['bundle_observations'][role]
    require(observed['input_bindings_before']==observed['input_bindings_after']==bindings
            and observed['unit_image_sha256']==images and observed['unit_names']==names
            and observed['source_sha256']==sources and observed['stable'] is True, 'full bundle observation '+role)
abi=json.loads(check_pin(prep['abi_original']))
require(sha(raw('preparation/hia_core_lowering_abi.json'))==policy['original_generated_assets']['abi_sha256'], 'actual ABI original')
modes=abi['modes']; private={'_native_globals','_native_generator_0','_native_generator_1'}
totals=Counter();per_group=Counter();witnessed=set();component_private=set();component_yield=set();seen=set()
for row in callers['native_step_returns']:
    key=(row['group'],row['mode'],row['unit_index'],row['status'])
    require(key not in seen and row['group'] in policy['test_groups'] and row['mode'] in modes
            and type(row['count']) is int and row['count']>0 and type(row['status']) is int and row['status'] in range(4)
            and type(row['unit_index']) is int and 0<=row['unit_index']<38
            and row['bundle_image_index']==row['unit_index']+1
            and row['unit_name']==names[row['bundle_image_index']]
            and row['image_sha256']==images[row['bundle_image_index']]
            and row['mode_number']==modes[row['mode']]['number']
            and row['abi_sha256']==callers['abi_sha256']
            and row['bundle_sha256']==sha(raw('callers/build/manifest.json')), 'actual native step row '+str(len(seen)))
    seen.add(key);totals[str(row['status'])]+=row['count'];per_group[row['group']]+=row['count'];witnessed.add(row['mode'])
    if row['group']=='component' and row['mode'] in private: component_private.add(row['mode'])
    if row['group']=='component' and row['status']==3: component_yield.add(row['mode'])
require(len(modes)==36 and len(set(modes)-private)==33 and witnessed==set(modes)
        and component_private==private and {'_native_generator_0','_native_generator_1'}<=component_yield
        and dict(totals)==callers['actual_native_step_statuses']
        and set(totals)=={'0','1','2','3'}, 'all36 actual modes including component globals and two actual lazy yields')
require(callers['native_step_ledger_schema']=='hepta.hia.core-lowering-native-step-returns.v2'
        and callers['group_bundle_roles']=={'component':'component','original-core':'caller','original-machine':'caller'}
        and callers['native_mode_entries_are_attempts'] is True, 'actual v2 ledger semantics preserved')
case='callers/component-fixture/installed-control'
expected=doc(case+'/expected.json'); installed=doc(case+'/report.json'); processes=doc(case+'/processes.json')
require(len(processes)==3 and all(r['returncode']==0 for r in processes) and processes[2]['argv'][1:4]==['-I','-S','-B'], 'three actual wheel and isolated child processes')
for process,label in zip(processes,['wheel-build','wheel-install','installed-execution']):
    for stream in ['stdout','stderr']:
        require(sha(raw(case+'/'+label+'.'+stream))==process[stream+'_sha256'], 'actual installed process stream '+label+'/'+stream)
require(json.loads(raw(case+'/installed-execution.stdout'))==installed and installed['status']=='INSTALLED_CORE_LOWERING_PASS'
        and installed['units']==39 and installed['image_sha256']==images and installed['source_sha256']==sources
        and installed['actual_native_steps']>0 and all(installed[k] is True for k in ['empty_PATH','isolated_without_site','authoring_forbidden','retained_lowering_forbidden']), 'actual installed native execution')
for name,digest in expected['python'].items():
    require(sha(raw(case+'/installed/'+name))==digest==remote_rows[name]['sha256'], 'installed Python source '+name)
for name,digest in expected['resources'].items():
    require(sha(raw(case+'/installed/hepta/_data/'+name))==digest==remote_rows[name]['sha256'], 'installed resource '+name)
require(installed['python_files']==len(expected['python'])==168 and installed['resource_files']==len(expected['resources'])==102, 'complete installed resource and Python counts')
wheels=list((ROOT/case/'wheels').glob('*.whl'))
require(len(wheels)==1,'one actual wheel retained')
with zipfile.ZipFile(wheels[0]) as z:
    require(z.testzip() is None,'actual wheel complete CRC')
require(final['status']=='DEVELOPMENT_CORE_EMITTER_COMPLETE_116_PASS'
        and final['complete_native_callers']['unique_test_ids']==all_ids
        and final['complete_native_callers']['actual_step_totals']==dict(totals)
        and final['complete_native_callers']['group_actual_step_totals']==dict(per_group), 'final joins actual independent116 and steps')
require(all(final[k] is False for k in ['cold_qualified','matching_source_cold_qualification_claimed',
        'old_compiler_or_product_results_inherited','original_limits_changed','preparation_plus_tests_claimed_as_one_cold_180',
        'production_activated','split_development_groups_accepted','whole_native_claimed']), 'final does not expand scope')
result={'schema':'hia.core116.independent-original-readback.v1','status':'PASS','run_id':43175231100,
        'artifact_id':13923748174,'candidate':policy['candidate'],'actual_derived_tree':derived['actual_worktree_tree'],
        'checks':len(checks),'source_leaves':4030,'derived_delta_paths':[x['path'] for x in changes],
        'source_manifest_count':len(build['source_manifest']),'compile_stages':len(compile_rows),'unit_count':39,
        'complete_test_ids':all_ids,'groups':groups,'owners':owners,'preparation_seconds':prep['seconds'],
        'complete_default116_seconds':callers['seconds'],'step_matrix_rows':len(seen),'actual_step_totals':dict(totals),
        'actual_step_count':sum(totals.values()),'per_group_steps':dict(per_group),'public_modes':sorted(set(modes)-private),
        'component_private_modes':sorted(component_private),'component_yield_modes':sorted(component_yield),
        'installed_actual_steps':installed['actual_native_steps'],'installed_python_files':168,'installed_resources':102,
        'checked_retained_pin_paths':len(checked_pins),'hosted_primitive_kinds':19,'cold_qualified':False,'whole_native_claimed':False,
        'remote_identity_scope':'Original integer identities compared and joined to bytes; remote filesystem syscalls not reexecuted.',
        'artifact_original':json.loads((ARCH/'DOWNLOAD.json').read_bytes()),'artifact_complete_crc':json.loads((ARCH/'ARTIFACT-READBACK.json').read_bytes())['status'],
        'seconds':time.monotonic()-started}
(HERE/'INDEPENDENT-READBACK.json').write_text(json.dumps(result,indent=2)+'\n')
(HERE/'INDEPENDENT-CHECKS.json').write_text(json.dumps(checks,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['complete_test_ids','public_modes','owners']},sort_keys=True))

