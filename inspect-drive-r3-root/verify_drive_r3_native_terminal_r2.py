"""Root full actual R3 Native17/VM12 terminal readback; no product call."""
import ast,collections,hashlib,json,os,stat,struct,sys,time,zlib
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35')
D=Path('/tmp/hia-root-v141-dda7')
A=Path('/tmp/hia-inspect-drive-source18-r3-dda7')
E=Path('/dev/shm/hia-inspect-drive-r3-dda7/native-vm-attempt-r1')
O=E.parent/'native-vm-outer-r1'
helper=(R/'v95-audit-mount-r1/v140-progress/verify_source18_proposal.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='c932413d529442b855043d13afb3e4d6aefa0973'
ns={}
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'[Root read-only definitions]','exec'),ns)
read,obj,tree=ns['read'],ns['obj'],ns['tree']
def pinbytes(b):return dict(bytes=len(b),mode='100644',sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
def pin(p):return read(p)[1]
started=time.monotonic_ns()
assert sys.version_info[:3]==(3,14,4)
p=obj(A/'NATIVE-PLAN.json');launch=obj(A/'NATIVE-LAUNCH.json');r=obj(E/'RESULT.json');outer=obj(O/'OUTER.json')
assert pin(E/'RESULT.json')['git_blob']=='7db4dbd26a798aecd3ae22a599c42be20d21414b'
assert pin(A/'NATIVE-PLAN.json')['git_blob']=='9cb9a6a75238a000a3a723841b478db4424b441d'
assert r['status']=='DEVELOPMENT_NATIVE_VM_PASS' and r['phase']=='native-vm' and r['owner_launch_attempts']==10
assert r['complete_source_guard_pass'] and r['source_tree']==p['source']['tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96' and r['source_files']==3188
assert r['plan_pin']==pin(A/'NATIVE-PLAN.json') and r['actual_source_predecessor']==obj(p['source_predecessor']['path'])
assert r['runtime']==p['runtime'] and not r['matching_current_cold'] and not r['whole_cli_native'] and not r['CLI_op10_connected']
assert not r['original3_or_CLI43_executed'] and r['historical_results_not_inherited']
assert r['generation_result_pin']==p['inputs']['generation_result']['pin']
assert outer['returncode']==0 and outer['status']=='OUTER_EXIT_ZERO' and not outer['automatic_retry']
assert outer['argv']==launch['argv'] and outer['cwd']==launch['cwd'] and outer['launch_git']==pin(A/'NATIVE-LAUNCH.json')['git_blob']
assert outer['qualification_seconds_per_owner']==180 and outer['cleanup_seconds_per_owner']==3
assert outer['output_filesystem']==p['evidence_authority'] and outer['entry_available_bytes']>=1073741824
assert outer['allowed_maximum_counts']==dict(Native=17,VM=12,compile=1,owners=10)
assert outer['elapsed_ns']==730344006312
outer_files={}
for path in O.iterdir():
    assert path.is_file() and not path.is_symlink()
    outer_files[path.name]=pin(path)
assert set(outer_files)=={'OUTER.json','STARTED.json','PROCESS.json','stdout.bin','stderr.bin'}
for k in ('outer_stdout','outer_stderr'):
    row=outer[k];assert row['path']==str(O/launch[k]) and all(outer_files[launch[k]][f]==row[f] for f in ('bytes','sha256'))
evidence_names=set()
for row in r['evidence']:
    _,got,st=read(row['path'])
    assert got==row['pin'] and st['mode']==row['posix_mode'],row['path']
    evidence_names.add(row['path'])
assert len(evidence_names)==len(r['evidence'])==61495
current=set()
for directory,dirs,files in os.walk(E,followlinks=False):
    for name in dirs:assert stat.S_ISDIR((Path(directory)/name).lstat().st_mode)
    current.update(str(Path(directory)/name) for name in files)
assert current==evidence_names|{str(E/'RESULT.json')}
order=['build-inspect']+p['native_group_order']+p['vm_group_order']
assert [x['label'] for x in r['stages']]==order
captures={role:obj(p['inputs'][role+'_final']['path']) for role in ('base','predecessor','source')}
inodes={}
for role,capture in captures.items():
    root=Path(p[role]['path']);assert not capture['errors'] and tree(capture['files'])==p[role]['tree']
    seen=set();inodes[role]=set()
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
        for name in files:seen.add((Path(folder)/name).relative_to(root).as_posix())
    assert seen==set(capture['files'])
    for name,expected in capture['files'].items():
        _,got,st=read(root/name);assert got==expected and st==capture['stat'][name],role+'/'+name
        inodes[role].add((st['device'],st['inode']))
        if role=='source':assert st['nlink']==1
assert len(inodes['source'])==3188 and inodes['source'].isdisjoint(inodes['base']|inodes['predecessor'])
for key in ('executable','library'):
    row=p['runtime'][key];_,got,st=read(row['path'])
    assert got['bytes']==row['bytes'] and got['sha256']==row['sha256']
    for k in ('device','inode','mode','mtime_ns','ctime_ns'):assert st[k]==row[k]
guards=list(E.glob('GUARD-*.json'));assert len(guards)==22
for path in guards:
    g=obj(path);assert g['all_bytes_and_seven_stat_fields']
    for role in captures:
        row=g[role];assert pin(row['path'])==row['pin'] and obj(row['path'])==captures[role]
rows=[];native_ids=[];vm_ids=[];journals=[];all_native=[];faults={};decoded={};descriptors={}
cross_by_nonce=collections.defaultdict(list)
def buffer(directory,b):
    assert b['file']==b['sha256']+'.zlib'
    path=Path(directory)/b['file'];key=str(path)
    expected={k:b[k] for k in ('bytes','mode','sha256','git_blob')}
    if key in descriptors:assert descriptors[key]==expected
    else:
        data=zlib.decompress(read(path)[0]);assert pinbytes(data)==expected
        descriptors[key]=expected;decoded[key]=data
    return decoded[key]
for index,stage in enumerate(r['stages']):
    label=stage['label'];directory=Path(stage['directory'])
    assert directory==E/('%02d-%s'%(index+1,label))
    child=obj(directory/'RESULT.json');request=obj(directory/'REQUEST.json');command=obj(directory/'COMMAND.json')
    owner=obj(directory/'OWNER.json');returned=obj(directory/'OWNER-RETURNED.json');oreq=obj(directory/'OWNER.json.request.json')
    assert stage['source_guard_pass'] and stage['status']==child['status']=='PASS'
    assert child['request_pin']==pin(directory/'REQUEST.json') and stage['child_result_pin']==pin(directory/'RESULT.json')
    assert child['source_unchanged'] and child['compiler_unchanged'] and child['source_before_tree']==child['source_after_tree']==p['source']['tree']
    assert request['group']==label and request['source']==p['source']['path'] and request['runtime_context']==p['runtime']
    assert command['argv']==oreq['command'] and command['cwd']==oreq['cwd']==p['source']['path'] and command['environment']==oreq['env']==command['supervisor_environment']
    for x in (command,owner,oreq):assert x['qualification_seconds']==180 and x['cleanup_seconds']==3
    assert returned==stage['owner_returned'] and returned['receipt_sha256']==pin(directory/'OWNER.json')['sha256'] and returned['supervisor_returncode']==0
    assert {k:v for k,v in returned.items() if k not in ('receipt_sha256','supervisor_returncode')}==owner
    assert owner['request_sha256']==pin(directory/'OWNER.json.request.json')['sha256']
    assert owner['returncode']==0 and owner['status']=='OWNED_PROCESS_COMPLETED'
    assert not owner['timed_out'] and owner['exit_observed_before_deadline'] and not owner['event_overflow'] and not owner['interrupted_signals']
    clean=owner['cleanup'];assert clean['complete'] and clean['observed_echild'] and clean['leader_reaped'] and not clean['deadline_exceeded'] and not clean['errors'] and not clean['remaining_direct_children'] and clean['elapsed_ns']<=3000000000
    row=dict(label=label,child=pin(directory/'RESULT.json'),owner=pin(directory/'OWNER.json'),cleanup_ns=clean['elapsed_ns'],final_ECHILD=True,historical_descendant_inventory_complete=owner['historical_descendant_inventory_complete'])
    if index==0:
        build=child['build'];assert build==stage['build'] and build['status']=='BUILT_AND_READ_BACK' and build['compile_seconds']==20 and build['capacity']==1048576
        assert build['complete_source_map_pin']==p['inputs']['source_map']['pin'] and not build['matching_current_cold']
        for b in build['observation_bindings']:
            _,got,st=read(b['path']);assert got['bytes']==b['bytes'] and got['sha256']==b['sha256'] and st['mode']==b['mode']
        manifest=obj(build['manifest']);assert pin(build['manifest'])=={k:v for k,v in build['manifest_binding'].items() if k!='path'}
        image=Path(build['manifest']).parent/manifest['image_path']
        assert pin(image)==build['image'] and build['image']['bytes']==120231 and build['image']['sha256']=='1458c7d482dda1370854ae32036d4d27ac1daff333454b639cdd956e97007cd1'
        assert manifest['image_sha256']==build['image']['sha256']
        for name,sha in manifest['host_sources'].items():assert captures['source']['files']['hepta/'+name]['sha256']==sha
        row['image']=build['image'];row['compiler_workspace_fully_observed']=False
    else:
        tests=obj(directory/'TESTS.json');assert tests==child['tests']==stage['tests'] and tests['status']=='PASS'
        for k in ('declared_ids','loaded_ids','started_ids','stopped_ids'):assert tests[k]==p['groups'][label]['ids']
        assert tests['tests_run']==len(tests['declared_ids']) and tests['events']==[[event,n] for n in tests['declared_ids'] for event in ('start','stop')]
        for k in ('failures','errors','skipped','expected_failures','unexpected_successes','loader_errors'):assert not tests[k]
        row.update(tests=pin(directory/'TESTS.json'),methods=tests['tests_run'],events=len(tests['events']))
        if label in p['native_group_order']:
            native_ids.extend(tests['started_ids'])
            machine=directory/'controls/machine';journal_path=machine/'INDEX.json';j=obj(journal_path)
            assert j['schema']=='hepta.hia.inspect-full-machine-frames.v1'
            assert j['started_calls']==j['complete_calls']==len(j['frames']) and j['all_source_unchanged']
            unique=set();full_bytes=0
            for fi,f in enumerate(j['frames']):
                assert f['index']==fi and f['returned'] and f['source_unchanged'] and f['image_sha256']==build['image']['sha256']
                afterpath=machine/'frames'/('%08d-AFTER.json'%fi)
                assert f==obj(afterpath)
                before=obj(machine/'frames'/('%08d-BEFORE.json'%fi));assert before['returned'] is False
                for key,value in before.items():
                    if key!='returned':assert f[key]==value
                for key in ('source_before','output_before','workspace_before','source_after','output_after','workspace_after'):
                    b=f[key];data=buffer(machine/'buffers',b)
                    if b['file'] not in unique:unique.add(b['file']);full_bytes+=len(data)
                assert buffer(machine/'buffers',f['source_before'])==buffer(machine/'buffers',f['source_after'])
                if label=='inspect-native-provider-protocol' and f['case']=='cross-frame-and-repeated-claim':
                    head=struct.unpack_from('<6Q',buffer(machine/'buffers',f['workspace_before']))
                    assert head[0]==f['command'];cross_by_nonce[head[1]].append([fi,head[0],f['result']])
                all_native.append(dict(journal=str(journal_path),frame=f,after_path=str(afterpath),buffers=str(machine/'buffers')))
            assert {x.name for x in (machine/'buffers').iterdir()}==unique
            journals.append(dict(label=label,index=pin(journal_path),complete_calls=len(j['frames']),complete_buffers=len(unique),decoded_bytes=full_bytes))
            fault_path=directory/'controls/INJECTED-RETURN.json'
            if fault_path.exists():
                fault=obj(fault_path);assert len(fault['injected'])==1 and fault['quarantined_until_child_exit'] and all(x['refused'] for x in fault['replay'])
                target=fault['target'];assert target not in faults
                injected=fault['injected'][0];f=j['frames'][injected['frame_index']]
                assert f['command']==injected['command'] and f['result']==injected['actual_result']
                faults[target]=dict(frame=f,journal=str(journal_path),raw=pin(fault_path))
        else:vm_ids.extend(tests['started_ids'])
    rows.append(row)
assert len(native_ids)==17 and len(vm_ids)==12 and len(all_native)==13586
assert set(cross_by_nonce)=={3,4}
for n in (3,4):
    assert any(command==2 and result==4 for _,command,result in cross_by_nonce[n])
    assert cross_by_nonce[n][-1][1:]==[1,5]
assert set(faults)=={'claim','effect-ack','terminal-ack','retirement-ack'}
catalog=obj(E/'NATIVE-VM-CATALOG.json')
keys=('signature-start','inspection-start','dict-update-claim','dict-update-ack','normal-terminal','exception-terminal','retirement-start','retirement-ack','lost-claim','lost-effect-ack','lost-terminal-ack','lost-retirement-ack')
assert catalog['schema']=='hepta.hia.inspect-native-frame-vm-catalog.v1' and catalog['selection_order']==list(keys)
assert catalog['all_native_frames']==len(all_native) and not catalog['all_native_frames_claimed_vm_equal']
assert catalog['image_sha256']==build['image']['sha256']
assert (catalog['max_steps_per_frame'],catalog['max_heap_bytes'],catalog['max_call_depth'])==(10000000,8388608,128)
predicates={
 'signature-start':lambda f:f['command']==0 and f['case']=='signature-eager-False-False:selected',
 'inspection-start':lambda f:f['command']==0 and f['case'].startswith('real-schema-') and f['case'].endswith(':selected'),
 'dict-update-claim':lambda f:f['command']==2 and f['issued_raw']==[0,253] and f['result']==4,
 'dict-update-ack':lambda f:f['command']==1 and f['issued_raw']==[0,253],
 'normal-terminal':lambda f:f['command']==1 and f['result']==0,
 'exception-terminal':lambda f:f['command']==1 and f['result']==3,
 'retirement-start':lambda f:f['command']==4,
 'retirement-ack':lambda f:f['command']==1 and f['result']==5}
for row in catalog['input_bindings']:assert pin(row['path'])=={k:row[k] for k in ('bytes','mode','sha256','git_blob')}
for key,selected in catalog['selected_frames'].items():
    assert pin(selected['journal'])==selected['journal_pin'] and pin(selected['after_path'])==selected['after_pin']
    assert obj(selected['after_path'])==selected['frame']
    if key in predicates:
        wanted=next(x for x in all_native if predicates[key](x['frame']))
        assert all(selected[k]==wanted[k] for k in wanted)
    else:
        wanted=faults[key.removeprefix('lost-')]
        assert selected['frame']==wanted['frame'] and selected['journal']==wanted['journal']
vm_rows=[];seen_keys=[]
for stage in r['stages'][-2:]:
    directory=Path(stage['directory'])/'controls';report=obj(directory/'REPORT.json')
    assert report['schema']=='hepta.hia.inspect-full-buffer-vm-observations.v1' and not report['all_native_frames_replayed'] and not report['matching_current_cold']
    assert report['source']==captures['source']['files']['examples/hia_bootstrap/inspect_program.hepta']
    assert (report['max_steps_per_frame'],report['max_heap_bytes'],report['max_call_depth'])==(10000000,8388608,128)
    assert len(report['observations'])==len(stage['tests']['started_ids'])
    used=set()
    for v in report['observations']:
        key=v['key'];selected=catalog['selected_frames'][key];native=selected['frame'];seen_keys.append(key)
        assert obj(directory/(key+'.json'))==v and v['status']=='PASS' and v['source_unchanged'] and v['exact_native_buffers']
        assert v['native_case']==native['case'] and v['native_frame_index']==native['index'] and type(v['vm_result']) is int and v['vm_result']==v['native_result']==native['result']
        assert 0<v['steps']<=10000000
        for side in ('before','after'):
            for region in ('source','output','workspace'):
                actual=buffer(directory/'buffers',v[side][region]);expected=buffer(selected['buffers'],native[region+'_'+side])
                assert actual==expected
                used.add(v[side][region]['file'])
        vm_rows.append(dict(key=key,steps=v['steps'],native_result=v['native_result'],actual_complete_six_buffers_equal=True,record=pin(directory/(key+'.json'))))
    assert {x.name for x in (directory/'buffers').iterdir()}==used
assert seen_keys==list(keys)
report=dict(schema='hepta.root-drive-r3-native17-vm12-full-terminal.v1',status='PASS_ALL_ACTUAL_NATIVE17_VM12_FULL_RAW_AND_CURRENT_THREE_TREES',actual_session=5079,result=pin(E/'RESULT.json'),outer=pin(O/'OUTER.json'),plan=pin(A/'NATIVE-PLAN.json'),source_tree=p['source']['tree'],source_files=3188,base_files=3187,predecessor_files=3188,stages=rows,compile_pass=1,Native_methods=17,Native_events=34,VM_methods=12,VM_events=24,full_evidence_files=61495,full_evidence_bytes=sum(x['pin']['bytes'] for x in r['evidence']),complete_attempt_and_outer_pathsets=True,outer_files=outer_files,all_current_three_trees_bytes_modes_seven_stats=True,source_guards=22,all10_owners_original180_plus3_ECHILD=True,complete_native_calls=13586,journals=journals,complete_unique_buffers=len(decoded),decoded_bytes=sum(len(x) for x in decoded.values()),all_actual_native_and_VM_six_buffers_full_readback=True,selected_VM_catalog=pin(E/'NATIVE-VM-CATALOG.json'),vm_observations=vm_rows,only12_selected_frames_VM_replayed=True,cross_frame_nonce3_final=cross_by_nonce[3][-1],cross_frame_nonce4_final=cross_by_nonce[4][-1],cross_frame_nonce4_actual_claim_and_ACK_now_present=True,lost_actual_return_faults={k:v['raw'] for k,v in faults.items()},lost_return_quarantines_preserved=True,ECHILD_does_not_prove_all_frames_retired=True,all_frames_retired=False,original_earlier_failure_preserved=True,outer_elapsed_ns=outer['elapsed_ns'],catalog_preparation_included_in_outer_not_an_owner_budget=True,automatic_retry=False,matching_current_cold=False,CLI_op10_connected=False,whole_native=False,production_legacy_retired=False,products_by_this_reader=0,elapsed_ns=time.monotonic_ns()-started)
path=D/'ROOT-DRIVE-R3-NATIVE-VM-TERMINAL.json'
with path.open('x') as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(status=report['status'],report=str(path),pin=pin(path),complete_native_calls=13586,VM_methods=12,evidence_files=61495,unique_buffers=len(decoded),decoded_bytes=report['decoded_bytes'],elapsed_ns=report['elapsed_ns']),sort_keys=True))
