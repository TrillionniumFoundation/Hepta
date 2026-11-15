"""Explicit development codec controls; no default or durable Store admission."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

AUTHOR=Path(__file__).absolute().parent
GENERATION_AUTHOR=Path('/workspace/hia-store-codecs-generation-author-r1-20261115-dda7')
sys.path.insert(0,str(GENERATION_AUTHOR/'controls'))
import generation_support as G
SCHEMA='hepta.hia.store-codecs-qualification.v1'
OUTPUT=Path('/home/agent/hia-store-codecs-qualification-r2-20261115-dda7')

def require(ok,text):
    if not ok:raise AssertionError(text)

def fixed(row):return G.checked(row)
def read(path):return G.decode(fixed(G.capture(Path(path))))
def write(path,value):G.publish(Path(path),value)
def raw_pin(raw):return {k:v for k,v in G.pin(raw).items() if k!='mode'}

def load(path,sha):
    require(Path(path)==AUTHOR/'PLAN.json','one exact qualification author plan required')
    row=G.capture(Path(path));raw=fixed(row);require(G.pin(raw)['sha256']==sha,'complete author plan identity differs')
    value=G.decode(raw)
    require(value['schema']==SCHEMA+'.plan' and value['state']=='AUTHORING_ONLY_ROOT_EXECUTION_REQUIRED'
        and value['scope']==str(OUTPUT) and value['limits']==G.LIMITS and value['storage_floor']==G.MINIMUM_FREE
        and value['automatic_retry'] is False and value['default_activated'] is False
        and value['durability_qualified'] is False and value['whole'] is False,'fixed development boundary differs')
    require(set(p.name for p in AUTHOR.iterdir())==set(value['author_pathset']),'complete frozen author pathset changed')
    generation=G.decode(fixed(value['generation_plan']));G.shape(generation)
    require(generation['source']==value['source'] and generation['runtime']==value['runtime'],'exact source/runtime lineage differs')
    require(Path(sys.executable).absolute()==Path(value['runtime']['launch_executable'])
        and sys.version_info[:3]==(3,14,4) and sys.flags.isolated and sys.flags.dont_write_bytecode,
        'actual fixed3.14.4 -I -B launch required')
    return row,value,generation

def immutable(plan):
    G.guard_directories(plan['author_ancestors'])
    G.guard_directories(plan['output_ancestors'])
    for row in plan['controls'].values():fixed(row)
    for row in plan['inputs'].values():fixed(row)
    for row in plan['generation_files']:fixed(row)
    for row in plan['terminal_files']:fixed(row)
    fixed(plan['compiler'])
    proof=G.decode(fixed(plan['inputs']['generation_terminal_result']))
    require(proof['status']=='PASS_COMPLETE_STORE_CODECS_GENERATION_TERMINAL_READBACK_ONLY'
        and proof['actual_generation_calls']==proof['actual_original_owners']==6 and proof['terminal_errors']==[]
        and proof['products']==proof['project_imports']==proof['new_owners']==0,'actual complete generation readback required')
    parent=G.decode(fixed(plan['inputs']['generation_result']))
    for name in ('head','catalog'):
        require(parent['first_outputs'][name]['asset']==plan['components'][name]['asset'],'exact actual generated asset binding differs')
        require(proof['actual_components'][name]['asset']==plan['components'][name]['asset']['pin'],'independent actual generation proof differs')
    return dict(controls=len(plan['controls']),inputs=len(plan['inputs']),generation_files=len(plan['generation_files']),
        terminal_files=len(plan['terminal_files']),compiler=plan['compiler']['pin'])

def guard(plan,generation,runtime_guard=None):
    fixed_inputs=immutable(plan);domains=G.full_guard(generation,runtime_guard)
    return dict(fixed_inputs=fixed_inputs,domains=domains)

def equal(a,b):
    require(a['fixed_inputs']==b['fixed_inputs'],'frozen qualification inputs changed')
    G.equal_guard(a['domains'],b['domains'])

def prior_readback(inventories):
    """Exact complete ordered prior inventories; every payload is reread fresh."""
    rows=[];paths=set()
    for descriptor in inventories:
        raw=fixed(descriptor)
        require(len(raw)<=4*1024*1024,'original bounded metadata shard exceeded')
        value=G.decode(raw)
        require(value['schema']==SCHEMA+'.prior-artifacts' and type(value['rows']) is list
            and value['rows'],'complete nonempty prior-artifact shard required')
        for row in value['rows']:
            require(row['path'] not in paths,'duplicate prior artifact path')
            paths.add(row['path']);fixed(row);rows.append(row)
    return rows

def publish_artifacts(directory,rows):
    """Full rows, contiguous order, 4MiB shards; no payload or identity omitted."""
    destination=directory/'PRIOR-ARTIFACTS';destination.mkdir(mode=0o700)
    groups=[];group=[];used=1024
    for row in rows:
        encoded=G.encoded(row)
        extent=len(encoded)+4*encoded.count(b'\n')+2
        require(extent+1024<=4*1024*1024,'one metadata record exceeds original shard bound')
        if used+extent>4*1024*1024:
            require(group,'one metadata record exceeds original shard bound')
            groups.append(group);group=[];used=1024
        group.append(row);used+=extent
    if group:groups.append(group)
    result=[]
    for i,group in enumerate(groups):
        value=dict(schema=SCHEMA+'.prior-artifacts',rows=group)
        require(len(G.encoded(value))<=4*1024*1024,'complete encoded metadata shard exceeded bound')
        path=destination/('%04d.json'%i);write(path,value)
        result.append(G.capture(path))
    require(prior_readback(result)==rows,'complete prior artifact roundtrip differs')
    return result

def load_oracle(plan,component):
    row=plan['components'][component]['oracle'];raw=fixed(row)
    name='_hia_store_'+component+'_oracle'
    spec=importlib.util.spec_from_file_location(name,row['path']);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(Path(module.__file__).absolute()==Path(row['path']) and fixed(row)==raw,'development oracle identity changed')
    return module

def image_guard(plan,build):
    require(build['component'] in ('head','catalog') and build['compiler']==plan['compiler']
        and build['source']==plan['components'][build['component']]['asset'],'actual compile/source binding differs')
    raw=fixed(build['image']);require(0<len(raw)<=1048576,'unchanged image capacity required')
    for row in build['files']:fixed(row)
    return raw

def compile_component(plan,component,folder):
    sys.path.insert(0,plan['source'])
    from tools.qualify_hia_selfhost import compile_stage
    from tools.hia_cli_discovery_custody import admit_compilation
    from tools import qualify_hia_selfhost as compile_module
    require(compile_module.NATIVE_OBSERVER is None and compile_module.NATIVE_LINKED_OBSERVER is None,
        'original disposable compiler transport required')
    source=fixed(plan['components'][component]['asset']);compiler_before=fixed(plan['compiler'])
    label='store-'+component
    image,returned=compile_stage(folder,label,Path(plan['compiler']['path']),source)
    actual,descriptors=admit_compilation(folder,label,Path(plan['compiler']['path']),source,image)
    require(actual==returned and fixed(plan['compiler'])==compiler_before,'real compiler receipt or compiler changed')
    require(returned['limits']=={'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,
        'output_capacity':1048576,'stack_bytes':8388608,'workspace_bytes':1048576},'original compiler limits differ')
    value=dict(component=component,source=plan['components'][component]['asset'],compiler=plan['compiler'],
        image=G.capture(image),receipt=returned,files=[G.capture(Path(r['path'])) for r in descriptors if Path(r['path'])!=Path(plan['compiler']['path'])],
        compile_calls=1,current_cold=False,default=False,whole=False,durability=False)
    write(folder/'BUILD.json',value)
    return value

def buffer(row,root):
    require(set(row)=={'path','bytes','sha256','git_blob'} and Path(row['path']).is_relative_to(root),'full physical buffer reference differs')
    descriptor=G.capture(Path(row['path']));raw=fixed(descriptor)
    require(raw_pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')},'full captured buffer bytes differ')
    return raw

def frames(folder,plan,component,build):
    index=read(folder/'frames/INDEX.json');root=folder/'frames'
    require(index['schema']=='hepta.hia.store-codecs.full-native-vm-pairs.v1'
        and index['source_sha256']==plan['components'][component]['asset']['pin']['sha256']
        and index['image']==raw_pin(fixed(build['image'])) and index['mapping_closed'] is True
        and index['cleanup_error'] is None and index['all_complete'] is True and index['limits']=={
        'max_steps':10000000,'max_heap_bytes':8388608,'max_call_depth':128},'real full Native/VM index incomplete')
    require(index['actual_native_attempts']==index['actual_vm_attempts']==len(index['calls'])>0,'one actual Native/VM per frame required')
    seen=[]
    for ordinal,row in enumerate(index['calls']):
        directory=Path(row['source_before']['path']).parent
        require(directory.parent.parent==root and directory.parent.name==row['case']
            and read(directory/'AFTER.json')==row,'actual complete per-call AFTER/index relation differs')
        before_record=read(directory/'BEFORE.json');native_record=read(directory/'NATIVE-AFTER.json')
        require(set(before_record)<=set(row) and set(native_record)<=set(row)
            and before_record['native_attempts']==before_record['vm_attempts']==0
            and before_record['returned'] is before_record['complete'] is False
            and native_record['native_attempts']==1 and native_record['vm_attempts']==0
            and native_record['returned'] is True and native_record['complete'] is False,
            'original pre-call and Native-return stage observations differ')
        for key,value in before_record.items():
            if key not in ('native_attempts','vm_attempts','returned','complete'):
                require(row[key]==value,'pre-call recorded identity changed')
        for key,value in native_record.items():
            if key not in ('vm_attempts','complete'):
                require(row[key]==value,'Native-return recorded identity changed')
        require(row['index']==ordinal and row['native_attempts']==row['vm_attempts']==1 and row['complete'] is True
            and row['returned'] is True and row['vm_values']==[row['native_result_u64']]
            and row['native_observation_errors']==row['vm_observation_errors']==[] and row['all_three_complete_buffers_equal'] is True
            and 0<row['vm_steps']<=10000000 and all(row['vm_owners_active']) and all(row['vm_views_active'])
            and row['vm_view_mutable']==[False,True,True] and len(set(row['vm_owner_ids']))==3,'actual returned pair/limits/owners differ')
        ranges=row['physical_ranges'];require(len(ranges)==3,'three actual Native physical ranges required')
        sorted_ranges=sorted((x['begin'],x['end']) for x in ranges)
        require(all(a[1]<=b[0] for a,b in zip(sorted_ranges,sorted_ranges[1:])), 'Native physical ranges overlap')
        if row['case'] not in seen:seen.append(row['case'])
        for i,(name,tag) in enumerate(zip(('source','output','workspace'),(0x6d,0x93,0xc5))):
            before=buffer(row[name+'_before'],root);after=buffer(row[name+'_after'],root);vm=buffer(row[name+'_vm_after'],root)
            physical_before=buffer(row[name+'_physical_before'],root);physical_after=buffer(row[name+'_physical_after'],root)
            require(len(physical_before)==len(physical_after)==len(before)+128 and len(after)==len(before)
                and physical_before[64:-64]==before and physical_after[64:-64]==after and after==vm
                and physical_before[:64]==physical_after[:64]==bytes([tag])*64
                and physical_before[-64:]==physical_after[-64:]==bytes([tag^255])*64
                and ranges[i]['payload']==ranges[i]['begin']+64 and ranges[i]['extent']==len(before)
                and ranges[i]['end']==ranges[i]['begin']+len(before)+128
                and row[name+'_canaries_unchanged'] is True,'complete physical canaries/logical Native/VM bytes differ')
            if name=='source':require(before==after,'readbuf source was modified')
    require(seen==index['cases'],'all declared case observations required in order')
    return dict(cases=index['cases'],calls=len(index['calls']),complete_native_vm_pairs=True,
        physical_buffers_per_call=6,logical_before_after_buffers_per_call=6,vm_after_buffers_per_call=3,
        max_vm_steps=max(r['vm_steps'] for r in index['calls']),limits=index['limits'])
